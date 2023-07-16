## Installing dependencies

Required are:
- rust >= 1.56
- cargo
- cargo-bpf
- LLVM 13

The installation of other dependencies listed in `Cargo.toml` are handled by Rust's package manager cargo when building the project.
At the time of writing, the Rust version needs to be at least 1.56. Check [here](https://github.com/foniod/redbpf#valid-combinations-of-rust-and-llvm-versions) to determine valid combinations of Rust and LLVM.

### Installing Rust and cargo
If the repositories of your distribution do not provide a version of Rust >= 1.56 yet, use the following commands to install the latest version of Rust directly.

```bash
curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf -o "rustup.sh"
chmod +x rustup.sh
./rustup.sh
```
This will also install cargo. Using `./rustup.sh -y` disables the confirmation prompt.

In order to use the `cargo` command in the same shell session, reload it using `source $HOME/.cargo/env`.

### Installing LLVM 13
LLVM 13 is a dependency of cargo-bpf. Follow the instructions [here](https://github.com/foniod/redbpf#install) to install LLVM depending on your distribution, as they are kept up-to-date.

### Installing cargo-bpf
Once LLVM 13 is installed, install cargo-bpf by running the following commands. For platforms other than Ubuntu/Debian, the prefix should be `llvm-config --prefix`.
```bash
PREFIX=$(llvm-config-13 --prefix)
LLVM_SYS_130_PREFIX="$PREFIX" cargo install cargo-bpf --no-default-features --features=llvm13,command-line
```
This will allow to use the `cargo bpf` subcommand.

Note that if the installation does not work, changes to RedBPF might have been made and [installation instructions](https://github.com/foniod/redbpf#install) or related [issues](https://github.com/foniod/redbpf/issues) may provide further information.

## Building the program

The program consists of a kernel and userspace part. The userspace part is the root of the repository, the kernel part is located in the directory `kernel_probes/`. Note that building the program requires `sudo`.

The kernel part needs to be built first. To do this, run:
```bash
cd kernel_probes/
sudo cargo bpf build --target-dir=../target
```
Then, return to the root of the project using `cd ..` and build the userspace part:
```bash
sudo cargo build
```

## Running the program
To run the program with default values and a single matching thread, run the program with `sudo cargo run`.

Additional arguments can be supplied with `sudo cargo run -- <args>`. To view all available options, run `sudo cargo run -- -h`.

When running the program at higher traffic rates, the size of the `PerfMap` which passes kernel events to the userspace program might need to be increased. This cannot be done with command line arguments and has to be determined at compile time. Open the following file:
```bash
kernel_probes/src/queue_xmit/main.rs
```
At the top of the file, the buffer size is specified:
```rust
// Buffer accessible by our userspace program.
#[map]
static mut KERNEL_EVENTS: PerfMap<XmitEvent> = PerfMap::with_max_entries(2048);
```
Change `2048` to the desired size and rebuild the program.


### Comments
On Debian it appears if you do not require root rights to build the program.
To run it (e.g. if `sudo cargo run`) does not work, one can use `sudo ./taget/debug/matcher -- <args>` to execute the matcher as superuser (required for matching)
