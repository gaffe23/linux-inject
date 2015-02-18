# linux-inject
**Tool for injecting a shared library into a currently running process on Linux.**

`linux-inject` is intended to provide the Linux equivalent of using `CreateRemoteThread()` on Windows to inject a DLL into a running process.

## Caveats

* Normally the OS will only search for shared libraries in the standard library paths, so it's necessary to either prepend `./` to the name of the shared library to inject or to just supply the full path to it.

* On many Linux distributions, the kernel is configured to prevent a process from calling `ptrace()` on any process that it did not create. This feature can be disabled temporarily (until the next reboot) using the following command:

        echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

* Currently only runs on x64. x86 and ARM support coming soon.

* Currently has an issue where the target occasionally hits an `int 3` instruction that is not caught by the injector, which causes the target process to crash.

## Compiling
* arm:

        make arm

* x86_64:

        make x86_64

## Usage
    ./inject [process-name] [library-to-inject]

## Sample
* In one terminal, start up the sample target app:

        ./target

* In another terminal, inject library.so into the target app:

        ./inject target ./library.so

* The output should look something like this:
 * First terminal:

            $ ./target
            sleeping...
            I just got loaded at 0x00007f568d86a000

 * Second terminal:

            $ ./inject target ./library.so
            found process "target" with pid 7547
            library "./library.so" successfully injected
