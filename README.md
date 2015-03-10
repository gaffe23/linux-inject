# linux-inject
**Tool for injecting a shared library into a currently running process on Linux**

* Provides the Linux equivalent of using `CreateRemoteThread()` on Windows to inject a DLL into a running process

* Performs injection using `ptrace()` rather than `LD_PRELOAD`, since the target process is already running at the time of injection

* Supports x86, x86_64, and ARM

* Does not require the target process to have been built with `-ldl` flag, because it loads the shared library using `__libc_dlopen_mode()` from libc rather than `dlopen()` from libdl

## Caveat about `ptrace()`

* On many Linux distributions, the kernel is configured by default to prevent any process from calling `ptrace()` on another process that it did not create (e.g. via `fork()`).

* This is a security feature meant to prevent exactly the kind of mischief that this tool causes.

* You can temporarily disable it (until the next reboot) using the following command:

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

        ./target

* In another terminal, inject library.so into the target app:

        ./inject target ./library.so

*  The output should look something like this:

 * First terminal:

            $ ./target
            sleeping...
            sleeping...
            I just got loaded at 0x7f622fac5000
            sleeping...
            sleeping...

 * Second terminal:

            $ ./inject target ./library.so
            found process "target" with pid 31490
            library "./library.so" successfully injected

* If the injection fails, make sure your machine is configured to allow processes to `ptrace()` other processes that they did not create. See the "Caveat about `ptrace()`" section above.

* If the injection was successful, the target app will display a message showing the address where the shared library was loaded, which you can verify by checking `/proc/[pid]/maps`:

        $ cat /proc/31490/maps
        00400000-00401000 r-xp 00000000 ca:01 263080                             /home/gaffe/linux-inject/target
        00600000-00601000 r--p 00000000 ca:01 263080                             /home/gaffe/linux-inject/target
        00601000-00602000 rw-p 00001000 ca:01 263080                             /home/gaffe/linux-inject/target
        02205000-02226000 rw-p 00000000 00:00 0                                  [heap]
        7f622fac5000-7f622fac6000 r-xp 00000000 ca:01 267208                     /home/gaffe/linux-inject/library.so
        7f622fac6000-7f622fcc5000 ---p 00001000 ca:01 267208                     /home/gaffe/linux-inject/library.so
        7f622fcc5000-7f622fcc6000 r--p 00000000 ca:01 267208                     /home/gaffe/linux-inject/library.so
        7f622fcc6000-7f622fcc7000 rw-p 00001000 ca:01 267208                     /home/gaffe/linux-inject/library.so
        [...]

* From looking at the first column, you can see that the base address of library.so is 0x7f622fac5000, which matches the output given by the target app.

* You could also verify this by attaching `gdb` to the target app after the injection and running `info sharedlibrary` to see what shared libraries the process currently has loaded.

## TODOs / Known Issues

* It doesn't yet support specifying a target process by its PID, which is basic functionality that ought to be added.

* The ARM version currently only works if the target process is executing in ARM mode at the time of injection. In the future, it should be able to support injecting into processes that are executing in either ARM or Thumb mode, by detecting the current mode and switching it if needed. After the injection, it should return the processor to whatever mode it was in before (which will require it to keep track of what mode it was in originally).

* The target process occasionally raises a `SIGTRAP` signal that is not caught by the injector, which causes the target process to core dump. I have a feeling this is a race condition between the target hitting the `SIGTRAP` and the injector trying to `ptrace()` the target again. If this is the case, it would mean that target hits the `SIGTRAP` too quickly sometimes, and it could likely be fixed by just adding a slight delay to slow down the target's execution.

* I need to try running this on a bunch of different Linux setups and fix any hiccups that might arise.

* Make the inline assembly sections more concise, if possible.

* Eliminate the need for inline assembly, if possible.

* Refactor/clean up the code that calculates function offsets; it calls `dlopen()` more times than necessary and should probably be put into a separate function.
