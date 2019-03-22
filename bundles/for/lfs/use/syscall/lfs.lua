local lfs = assert(require "syscall" and require "syscall.lfs")
require"package".loaded.lfs = lfs
return lfs
