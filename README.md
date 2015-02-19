# linux-inject
**Tool for injecting a shared library into a currently running process on Linux.**

`linux-inject` is intended to provide the Linux equivalent of using `CreateRemoteThread()` on Windows to inject a DLL into a running process. It supports x86, x86_64, and ARM.

## Caveats

* Normally the OS will only search for shared libraries in the standard library paths, so it's necessary to either prepend `./` to the name of the shared library to inject or to just supply the full path to it.

* On many Linux distributions, the kernel is configured to prevent a process from calling `ptrace()` on any process that it did not create. This feature can be disabled temporarily (until the next reboot) using the following command:

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

* The target app will display a message showing the address where the shared library was loaded (which you can verify by checking `/proc/[pid]/maps`). The output should look something like this:

 * First terminal:

            $ ./target
            sleeping...
            sleeping...
            I just got loaded at 0x7f568d86a000
            sleeping...
            sleeping...

 * Second terminal:

            $ ./inject target ./library.so
            found process "target" with pid 7547
            library "./library.so" successfully injected

## TODOs / Known Issues

* The ARM version currently only works if the target process is executing in ARM mode at the time of injection. In the future, it should be able to support injecting into processes that are executing in either ARM or Thumb mode by detecting the current mode and switching it if needed.

* The target occasionally raises a `SIGTRAP` signal that is not caught by the injector, which causes the target process to core dump.

* The injector really should `malloc()` the amount of memory required based on the actual length of the library path. As it stands, it just allocates 32 bytes of memory and assumes that will be enough to hold the path, which is a bit silly.

* Factor out duplicated code, such as `findProcessByName` and the `ptrace_*` functions. Will need to add some arch-specific `#define`s for the `ptrace_*` functions, because x86 and x86_64 use `struct user_regs_struct`, and ARM uses `struct user_regs`.

* Make the inline assembly sections more concise, if possible.

* Eliminate the need for inline assembly, if possible.

* Add a function that will automatically determine the full path to the specified shared library, so that the user doesn't have to prepend `./` to a library in the current directory.

* Try running this on a bunch of different Linux setups and fix any hiccups that might arise.
