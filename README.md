# lsmtrace

Trace all lsm hooks touched by executable

## Requirements

Your kernel must have been compiled with the follwing options:
* BPF_SYSCALL
* BPF_LSM
* DEBUG_INFO
* DEBUG_INFO_BTF

## Compilation

```shell
$ git submodule update --init --recursive    # check out libbpf
$ cd src
$ make
```

## Run

```shell
$ sudo ./lsmtrace /usr/bin/ls -a /home  

Attaching hooks, don`t rush..

-> HOOK_CALL: -> cred_getsecid( const struct cred *c, u32 *secid )
-> HOOK_CALL: -> file_permission( struct file *file, int mask )
     file,f_mode = 32797
     file,f_path.dentry,d_flags = 64
     file,f_path.dentry,d_name.name = ls
     file,f_path.dentry,d_inode,i_ino = 3670696
...
```


