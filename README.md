# SNAP2EXE

`snap2exe` recovers an ELF executable from a core dump so that you can continue a process from where it was core dumped by simply executing this executable.

## Build

Just use `make`, and the binary `snap2exe` will be output to the `./build` directory.

## Demo

```bash
$ gcc example.c -o example
$ ./example &
$ ./dump.sh $!  # need root
$ ./build/snap2exe core.$! example-cont
$ ./example-cont
```

## Limits

- Can be only used on `x86_64-linux`.
- Cannot recover kernel states such as file descriptors.