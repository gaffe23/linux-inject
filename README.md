# linux-inject
**Tool for injecting a shared library into a currently running process on Linux**

* Provides the Linux equivalent of using `CreateRemoteThread()` on Windows to inject a DLL into a running process

* Performs injection using `ptrace()` rather than `LD_PRELOAD`, since the target process is already running at the time of injection

* Supports x86, x86_64, and ARM

* Does not require the target process to have been built with `-ldl` flag, because it loads the shared library using `__libc_dlopen_mode()` from libc rather than `dlopen()` from libdl

## Caveat about `ptrace()`

* On many Linux distributions, the kernel is configured by default to prevent any process from calling `ptrace()` on another process that it did not create (e.g. via `fork()`).

* This is a security feature meant to prevent exactly the kind of mischief that this tool causes.

* You can temporarily disable it until the next reboot using the following command:

        echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

## Compiling

* arm:

        make arm

* x86:

        make x86

* x86_64:

        make x86_64

## Usage

    ./inject [process-name] [library-to-inject]

## Sample

* In one terminal, start up the sample target app, which simply outputs "sleeping..." each second:

        ./sample-target

* In another terminal, inject sample-library.so into the target app:

        ./inject sample-target sample-library.so

*  The output should look something like this:

 * First terminal:

            $ ./sample-target
            sleeping...
            sleeping...
            I just got loaded at 0x7f37d5cc6000
            sleeping...
            sleeping...

 * Second terminal:

            $ ./inject sample-target sample-library.so
            found process "sample-target" with pid 31490
            library "sample-library.so" successfully injected
	    $

* If the injection fails, make sure your machine is configured to allow processes to `ptrace()` other processes that they did not create. See the "Caveat about `ptrace()`" section above.

* If the injection was successful, the app will display a message showing the address where the sample shared library was loaded, which you can verify by checking `/proc/[pid]/maps`:

	$ cat /proc/$(pgrep sample-target)/maps
	[...]
	7f37d5cc6000-7f37d5cc7000 r-xp 00000000 ca:01 267321                     /home/ubuntu/linux-inject/sample-library.so
	7f37d5cc7000-7f37d5ec6000 ---p 00001000 ca:01 267321                     /home/ubuntu/linux-inject/sample-library.so
	7f37d5ec6000-7f37d5ec7000 r--p 00000000 ca:01 267321                     /home/ubuntu/linux-inject/sample-library.so
	7f37d5ec7000-7f37d5ec8000 rw-p 00001000 ca:01 267321                     /home/ubuntu/linux-inject/sample-library.so
	[...]

* From looking at the first column, you can see that the base address of sample-library.so is 0x7f37d5cc6000, which matches the output given by the app after the injection.

* You could also verify this by attaching `gdb` to the target app after doing the injection and then running `info sharedlibrary` to see what shared libraries the process currently has loaded:

	$ gdb -p $(pgrep sample-target)
	[...]
	(gdb) info sharedlibrary
	From                To                  Syms Read   Shared Object Library
	0x00007f37d628ded0  0x00007f37d628e9ce  Yes         /lib/x86_64-linux-gnu/libdl.so.2
	0x00007f37d5ee74a0  0x00007f37d602c583  Yes         /lib/x86_64-linux-gnu/libc.so.6
	0x00007f37d6491ae0  0x00007f37d64ac4e0  Yes         /lib64/ld-linux-x86-64.so.2
	0x00007f37d5cc6670  0x00007f37d5cc67b9  Yes         /home/ubuntu/linux-inject/sample-library.so
	(gdb)


## TODOs / Known Issues

* It doesn't yet support specifying a target process by its PID, which is basic functionality that definitely needs to be added.

* The ARM version currently only works if the target process is executing in ARM mode at the time of injection. In the future, it should be able to support injecting into processes that are executing in either ARM or Thumb mode, by detecting the current mode and switching it if needed. After the injection, it should return the processor to whatever mode it was in before (which will require it to keep track of what mode it was in originally).

* The target process occasionally raises a `SIGTRAP` signal that is not caught by the injector, which causes the target process to core dump. I have a feeling this is a race condition between the target hitting the `SIGTRAP` and the injector trying to `ptrace()` the target again. If this is the case, it would mean that target hits the `SIGTRAP` too quickly sometimes, and it could likely be fixed by just adding a slight delay to slow down the target's execution.

* I need to try running this on a bunch of different Linux setups and fix any hiccups that might arise.

* Make the inline assembly sections more concise, if possible.

* Eliminate the need for inline assembly, if possible.

* Refactor/clean up the code that calculates function offsets; it calls `dlopen()` more times than necessary and should probably be put into a separate function.
