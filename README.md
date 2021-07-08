# SNAP2EXE

`SNAP2EXE` aims to generate an ELF executable from a run-time snapshot of a process so that user can continue that process from where it was snapshoted by simply executing the genereated executable. We call such an executable as a **snapshot executable**.

We provide a library and a binary tool:
- The library mainly contains two interfaces:
    - `snap2exe(pid, save_dir)`: snapshot the process at run-time by `pid` and generate a snapshot executable to the `save_dir`.
    - `s2e_checkpoint(cond, save_dir, policy)`: a process can call it to snapshot itself to generate a snapshot executable when `cond` is true.
- The binary tool `snap2exe` encapsulates the `snap2exe(pid, save_dir)` interface, which attaches to a process at run-time by `pid` and snapshot it to an executable.

The snapshot executable generated by the library and the tool will continue to execute from where it was snapshoted.

## Build

Just use `make`, and the binary `snap2exe` and the library `libsnap2exe.a` will be output to the `./build` directory.

## Usage

```
snap2exe <pid> <save_dir>
    <pid>: the process to snapshot.
    <save_dir>: the directory to save snapshot executables.
```

## Demo

An example using the `s2e_checkpoint()` interface:

```bash
$ make
$ make test
$ ./test-ckpt
$ ./snapshots/test-ckpt/<id>/cont
```

An example using the `snap2exe` tool:

```bash
$ make
$ make test
$ ./test-tool &
$ ./build/snap2exe $! snapshots/test-tool  # need sudo
$ cd snapshots/test-tool/<id>
$ chmod a+x cont && ./cont  # need sudo
```

## Limits

- Can be only used on `x86_64-linux`.
- Cannot recover kernel states execpt opened regular files.
