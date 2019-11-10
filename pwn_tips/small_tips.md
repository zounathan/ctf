Small Tips
=
* glibc中的`environ`可以获取栈地址
* 修改`global_max_fast`，增大/减小fastbin的最大size
* `__malloc_hook`前有libc地址，可以伪造为size为`0x70`的fastbin
* glibc几个关键特性时间点
  * 2.26之后有Tcache
  * 2.24之后有vtable检查
