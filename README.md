# lsmtrace

Trace all lsm hooks touched by executable

## Requirements

Your kernel must have been compiled with the follwing options:
BPF_SYSCALL
BPF_LSM
DEBUG_INFO
DEBUG_INFO_BTF

## Compilation

```shell
$ git submodule update --init --recursive    # check out libbpf
$ cd src
$ make
$ sudo ./lmstrace [process] -s [syscall]
```

