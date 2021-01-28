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
```

## Run

```shell
$ sudo ./lsmtrace /usr/bin/ls -a /home$ cd src

Attaching hooks, don`t rush..

-> FUNCTION_CALL: -> file_alloc_security( struct file *file )
     file,f_mode = 0
     file,f_path.dentry,d_flags = 0
     file,f_path.dentry,d_name.name = 
-> FUNCTION_CALL: -> inode_permission( struct inode *inode, int mask )
-> FUNCTION_CALL: -> inode_permission( struct inode *inode, int mask )
...
```


