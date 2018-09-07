do --{{
local sources, priorities = {}, {};assert(not sources["syscall.linux.netfilter"],"module already exists")sources["syscall.linux.netfilter"]=([===[-- <pack syscall.linux.netfilter> --
-- module for netfilter code
-- will cover iptables, ip6tables, ebtables, arptables eventually
-- even less documentation than for netlink but it does not look too bad...

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local nf = {} -- exports

local ffi = require "ffi"
local bit = require "syscall.bit"
local S = require "syscall"
local helpers = require "syscall.helpers"
local c = S.c
local types = S.types
local t, pt, s = types.t, types.pt, types.s

function nf.socket(family)
  return S.socket(family, "raw", "raw")
end

local level = {
  [c.AF.INET] = c.IPPROTO.IP,
  [c.AF.INET6] = c.IPPROTO.IPV6,
}

function nf.version(family)
  family = family or c.AF.INET
  local sock, err = nf.socket(family)
  if not sock then return nil, err end
  local rev = t.xt_get_revision()
  local max, err = sock:getsockopt(level[family], c.IPT_SO_GET.REVISION_TARGET, rev, s.xt_get_revision);
  local ok, cerr = sock:close()
  if not ok then return nil, cerr end
  if not max then return nil, err end
  return max
end

return nf

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.mips.ffi"],"module already exists")sources["syscall.linux.mips.ffi"]=([===[-- <pack syscall.linux.mips.ffi> --
-- MIPS specific definitions

-- sigset_t size is set from _NSIG here

return {
  nsig = [[
static const int _NSIG = 128;
]],
  ucontext = [[
typedef struct sigaltstack {
  void *ss_sp;
  size_t ss_size;
  int ss_flags;
} stack_t;
typedef struct {
  unsigned __mc1[2];
  unsigned long long __mc2[65];
  unsigned __mc3[5];
  unsigned long long __mc4[2];
  unsigned __mc5[6];
} mcontext_t;
typedef struct __ucontext {
  unsigned long uc_flags;
  struct __ucontext *uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  sigset_t uc_sigmask;
  unsigned long uc_regspace[128];
} ucontext_t;
]],
sigaction = [[
struct k_sigaction {
  unsigned int    sa_flags;
  void (*sa_handler)(int);
  sigset_t        sa_mask;
};
]],
siginfo = [[
/* note renamed members of struct to match other architectures */
typedef struct siginfo {
  int si_signo;
  int si_code;
  int si_errno;
  int __pad0[SI_MAX_SIZE / sizeof(int) - SI_PAD_SIZE - 3];

  union {
    int _pad[SI_PAD_SIZE];

    struct {
      pid_t si_pid;
      uid_t si_uid;
    } kill;

    struct {
      timer_t si_tid;
      int si_overrun;
      char _pad[sizeof(uid_t) - sizeof(int)];
      sigval_t si_sigval;
      int _sys_private;
    } timer;

    struct {
      pid_t si_pid;
      uid_t si_uid;
      sigval_t si_sigval;
    } rt;

    struct {
      pid_t si_pid;
      uid_t si_uid;
      int si_status;
      clock_t si_utime;
      clock_t si_stime;
    } sigchld;

    struct {
      pid_t si_pid;
      clock_t si_utime;
      int si_status;
      clock_t si_stime;
    } irix_sigchld;

    struct {
      void *si_addr;
      short si_addr_lsb;
    } sigfault;

    struct {
      long si_band;
      int si_fd;
    } sigpoll;

    struct {
      void *si_call_addr;
      int si_syscall;
      unsigned int si_arch;
    } sigsys;
  } _sifields;
} siginfo_t;
]],
  -- note this is struct stat64
  stat = [[
struct stat {
  unsigned long   st_dev;
  unsigned long   __st_pad0[3];
  unsigned long long      st_ino;
  mode_t          st_mode;
  nlink_t         st_nlink;
  uid_t           st_uid;
  gid_t           st_gid;
  unsigned long   st_rdev;
  unsigned long   __st_pad1[3];
  long long       st_size;
  time_t          st_atime;
  unsigned long   st_atime_nsec;
  time_t          st_mtime;
  unsigned long   st_mtime_nsec;
  time_t          st_ctime;
  unsigned long   st_ctime_nsec;
  unsigned long   st_blksize;
  unsigned long   __st_pad2;
  long long       st_blocks;
  long __st_padding4[14];
};
]],
  statfs = [[
struct statfs64 {
  uint32_t   f_type;
  uint32_t   f_bsize;
  uint32_t   f_frsize;
  uint32_t   __pad;
  uint64_t   f_blocks;
  uint64_t   f_bfree;
  uint64_t   f_files;
  uint64_t   f_ffree;
  uint64_t   f_bavail;
  kernel_fsid_t f_fsid;
  uint32_t   f_namelen;
  uint32_t   f_flags;
  uint32_t   f_spare[5];
};
]],
  nsig = [[
static const int _NSIG = 128;
]],
  termios = [[
struct termios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[23];
};
]],
}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.x64.ffi"],"module already exists")sources["syscall.linux.x64.ffi"]=([===[-- <pack syscall.linux.x64.ffi> --
-- x64 specific definitions

return {
  epoll = [[
struct epoll_event {
  uint32_t events;
  epoll_data_t data;
}  __attribute__ ((packed));
]],
  ucontext = [[
typedef long long greg_t, gregset_t[23];
typedef struct _fpstate {
  unsigned short cwd, swd, ftw, fop;
  unsigned long long rip, rdp;
  unsigned mxcsr, mxcr_mask;
  struct {
    unsigned short significand[4], exponent, padding[3];
  } _st[8];
  struct {
    unsigned element[4];
  } _xmm[16];
  unsigned padding[24];
} *fpregset_t;
typedef struct {
  gregset_t gregs;
  fpregset_t fpregs;
  unsigned long long __reserved1[8];
} mcontext_t;
typedef struct __ucontext {
  unsigned long uc_flags;
  struct __ucontext *uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  sigset_t uc_sigmask;
  unsigned long __fpregs_mem[64];
} ucontext_t;
]],
  stat = [[
struct stat {
  unsigned long   st_dev;
  unsigned long   st_ino;
  unsigned long   st_nlink;
  unsigned int    st_mode;
  unsigned int    st_uid;
  unsigned int    st_gid;
  unsigned int    __pad0;
  unsigned long   st_rdev;
  long            st_size;
  long            st_blksize;
  long            st_blocks;
  unsigned long   st_atime;
  unsigned long   st_atime_nsec;
  unsigned long   st_mtime;
  unsigned long   st_mtime_nsec;
  unsigned long   st_ctime;
  unsigned long   st_ctime_nsec;
  long            __unused[3];
};
]],
}


]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.util"],"module already exists")sources["syscall.util"]=([===[-- <pack syscall.util> --
-- generic utils not specific to any OS

-- these are generally equivalent to things that are in man(1) or man(3)
-- these can be made more modular as number increases

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local function init(S)

local h = require "syscall.helpers"
local htonl = h.htonl

local ffi = require "ffi"
local bit = require "syscall.bit"

local abi, types, c = S.abi, S.types, S.c
local t, pt, s = types.t, types.pt, types.s

local mt, meth = {}, {}

local util = require("syscall." .. abi.os .. ".util").init(S)

mt.dir = {
  __tostring = function(t)
    if #t == 0 then return "" end
    table.sort(t)
    return table.concat(t, "\n") .. "\n"
    end
}

function util.dirtable(name, nodots) -- return table of directory entries, remove . and .. if nodots true
  local d = {}
  local size = 4096
  local buf = t.buffer(size)
  local iter, err = util.ls(name, buf, size)
  if not iter then return nil, err end
  for f in iter do
    if not (nodots and (f == "." or f == "..")) then d[#d + 1] = f end
  end
  return setmetatable(d, mt.dir)
end

-- this returns an iterator over multiple calls to getdents TODO add nodots?
-- note how errors work, getdents will throw as called multiple times, but normally should not fail if open succeeds
-- getdents can fail eg on nfs though.
function util.ls(name, buf, size)
  size = size or 4096
  buf = buf or t.buffer(size)
  if not name then name = "." end
  local fd, err = S.open(name, "directory, rdonly")
  if err then return nil, err end
  local di
  return function()
    local d, first
    repeat
      if not di then
        local err
        di, err = fd:getdents(buf, size)
        if not di then
          fd:close()
          error(err)
        end
        first = true
      end
      d = di()
      if not d then di = nil end
      if not d and first then return nil end
    until d
    return d.name, d
  end
end

-- recursive rm TODO use ls iterator, which also returns type
local function rmhelper(file, prefix)
  local name
  if prefix then name = prefix .. "/" .. file else name = file end
  local st, err = S.lstat(name)
  if not st then return nil, err end
  if st.isdir then
    local files, err = util.dirtable(name, true)
    if not files then return nil, err end
    for _, f in pairs(files) do
      local ok, err = rmhelper(f, name)
      if not ok then return nil, err end
    end
    local ok, err = S.rmdir(name)
    if not ok then return nil, err end
  else
    local ok, err = S.unlink(name)
    if not ok then return nil, err end
  end
  return true
end

function util.rm(...)
  for _, f in ipairs{...} do
    local ok, err = rmhelper(f)
    if not ok then return nil, err end
  end
  return true
end

-- TODO warning broken
function util.cp(source, dest, mode) -- TODO make much more functional, less broken, esp fix mode! and size issue!!
  local contents, err = util.readfile(source)
  if not contents then return nil, err end
  local ok, err = util.writefile(dest, contents, mode)
  if not ok then return nil, err end
  return true
end

function util.touch(file)
  local fd, err = S.open(file, "wronly,creat,noctty,nonblock", "0666")
  if not fd then return nil, err end
  local fd2, err = S.dup(fd)
  if not fd2 then
    fd2:close()
    return nil, err
  end
  fd:close()
  local ok, err = S.futimes(fd2)
  fd2:close()
  if not ok then return nil, err end
  return true
end

function util.createfile(file) -- touch without timestamp adjustment
  local fd, err = S.open(file, "wronly,creat,noctty,nonblock", "0666")
  if not fd then return nil, err end
  local ok, err = fd:close()
  if not ok then return nil, err end
  return true
end

function util.mapfile(name) -- generally better to use, but no good for sysfs etc
  local fd, err = S.open(name, "rdonly")
  if not fd then return nil, err end
  local st, err = S.fstat(fd)
  if not st then return nil, err end
  local size = st.size
  local m, err = S.mmap(nil, size, "read", "shared", fd, 0)
  if not m then return nil, err end
  local str = ffi.string(m, size)
  local ok, err = S.munmap(m, size)
  if not ok then return nil, err end
  local ok, err = fd:close()
  if not ok then return nil, err end
  return str
end

-- TODO fix short reads, but mainly used for sysfs, proc
function util.readfile(name, buffer, length)
  local fd, err = S.open(name, "rdonly")
  if not fd then return nil, err end
  local r, err = S.read(fd, buffer, length or 4096)
  if not r then return nil, err end
  local ok, err = fd:close()
  if not ok then return nil, err end
  return r
end

-- write string to named file; silently ignore short writes TODO fix
function util.writefile(name, str, mode, flags)
  local fd, err
  if mode then fd, err = S.creat(name, mode) else fd, err = S.open(name, flags or "wronly") end
  if not fd then return nil, err end
  local n, err = S.write(fd, str)
  if not n then return nil, err end
  local ok, err = fd:close()
  if not ok then return nil, err end
  return true
end

mt.ps = {
  __tostring = function(ps)
    local s = {}
    for i = 1, #ps do
      s[#s + 1] = tostring(ps[i])
    end
    return table.concat(s, '\n')
  end
}

-- note that Linux and NetBSD have /proc but FreeBSD does not usually have it mounted, although it is an option
function util.ps()
  local ls, err = util.dirtable("/proc")
  if not ls then return nil, err end
  local ps = {}
  for i = 1, #ls do
    if not string.match(ls[i], '[^%d]') then
      local p = util.proc(tonumber(ls[i]))
      if p then ps[#ps + 1] = p end
    end
  end
  table.sort(ps, function(a, b) return a.pid < b.pid end)
  return setmetatable(ps, mt.ps)
end

mt.proc = {
  __index = function(p, k)
    local name = p.dir .. k
    local st, err = S.lstat(name)
    if not st then return nil, err end
    if st.isreg then
      local fd, err = S.open(p.dir .. k, "rdonly")
      if not fd then return nil, err end
      local ret, err = S.read(fd) -- read defaults to 4k, sufficient?
      if not ret then return nil, err end
      S.close(fd)
      return ret -- TODO many could usefully do with some parsing
    end
    if st.islnk then
      local ret, err = S.readlink(name)
      if not ret then return nil, err end
      return ret
    end
    -- TODO directories
  end,
  __tostring = function(p) -- TODO decide what to print
    local c = p.cmdline
    if c then
      if #c == 0 then
        local comm = p.comm
        if comm and #comm > 0 then
          c = '[' .. comm:sub(1, -2) .. ']'
        end
      end
      return p.pid .. '  ' .. c
    end
  end
}

function util.proc(pid)
  if not pid then pid = S.getpid() end
  return setmetatable({pid = pid, dir = "/proc/" .. pid .. "/"}, mt.proc)
end

-- receive cmsg, extended helper on recvmsg, fairly incomplete at present
function util.recvcmsg(fd, msg, flags)
  if not msg then
    local buf1 = t.buffer(1) -- assume user wants to receive single byte to get cmsg
    local io = t.iovecs{{buf1, 1}}
    local bufsize = 1024 -- sane default, build your own structure otherwise
    local buf = t.buffer(bufsize)
    msg = t.msghdr{iov = io, msg_control = buf, msg_controllen = bufsize}
  end
  local count, err = S.recvmsg(fd, msg, flags)
  if not count then return nil, err end
  local ret = {count = count, iovec = msg.msg_iov} -- thats the basic return value, and the iovec
  for mc, cmsg in msg:cmsgs() do
    local pid, uid, gid = cmsg:credentials()
    if pid then
      ret.pid = pid
      ret.uid = uid
      ret.gid = gid
    end
    local fd_array = {}
    for fd in cmsg:fds() do
      fd_array[#fd_array + 1] = fd
    end
    ret.fd = fd_array
  end
  return ret
end

function util.sendfds(fd, ...)
  local buf1 = t.buffer(1) -- need to send one byte
  local io = t.iovecs{{buf1, 1}}
  local cmsg = t.cmsghdr("socket", "rights", {...})
  local msg = t.msghdr{iov = io, control = cmsg}
  return S.sendmsg(fd, msg, 0)
end

-- generic inet name to ip, also with netmask support
-- TODO convert to a type? either way should not really be in util, probably helpers
-- better as a type that returns inet, mask
function util.inet_name(src, netmask)
  local addr
  if not netmask then
    local a, b = src:find("/", 1, true)
    if a then
      netmask = tonumber(src:sub(b + 1))
      src = src:sub(1, a - 1)
    end
  end
  if src:find(":", 1, true) then -- ipv6
    addr = t.in6_addr(src)
    if not addr then return nil end
    if not netmask then netmask = 128 end
  else
    addr = t.in_addr(src)
    if not addr then return nil end
    if not netmask then netmask = 32 end
  end
  return addr, netmask
end

local function lastslash(name)
  local ls
  local i = 0
  while true do 
    i = string.find(name, "/", i + 1)
    if not i then return ls end
    ls = i
  end
end

local function deltrailslash(name)
  while name:sub(#name) == "/" do
    name = string.sub(name, 1, #name - 1)
  end
  return name
end

function util.basename(name)
  if name == "" then return "." end
  name = deltrailslash(name)
  if name == "" then return "/" end -- was / or // etc
  local ls = lastslash(name)
  if not ls then return name end
  return string.sub(name, ls + 1)
end

function util.dirname(name)
  if name == "" then return "." end
  name = deltrailslash(name)
  if name == "" then return "/" end -- was / or // etc
  local ls = lastslash(name)
  if not ls then return "." end
  name = string.sub(name, 1, ls - 1)
  name = deltrailslash(name)
  if name == "" then return "/" end -- was / or // etc
  return name
end

return util

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.x86.ffi"],"module already exists")sources["syscall.linux.x86.ffi"]=([===[-- <pack syscall.linux.x86.ffi> --
-- x86 specific definitions

return {
  ucontext = [[
typedef int greg_t, gregset_t[19];
typedef struct _fpstate {
  unsigned long cw, sw, tag, ipoff, cssel, dataoff, datasel;
  struct {
    unsigned short significand[4], exponent;
  } _st[8];
  unsigned long status;
} *fpregset_t;
typedef struct {
  gregset_t gregs;
  fpregset_t fpregs;
  unsigned long oldmask, cr2;
} mcontext_t;
typedef struct __ucontext {
  unsigned long uc_flags;
  struct __ucontext *uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  sigset_t uc_sigmask;
  unsigned long __fpregs_mem[28];
} ucontext_t;
]],
  stat = [[
struct stat {
  unsigned long long      st_dev;
  unsigned char   __pad0[4];
  unsigned long   __st_ino;
  unsigned int    st_mode;
  unsigned int    st_nlink;
  unsigned long   st_uid;
  unsigned long   st_gid;
  unsigned long long      st_rdev;
  unsigned char   __pad3[4];
  long long       st_size;
  unsigned long   st_blksize;
  unsigned long long      st_blocks;
  unsigned long   st_atime;
  unsigned long   st_atime_nsec;
  unsigned long   st_mtime;
  unsigned int    st_mtime_nsec;
  unsigned long   st_ctime;
  unsigned long   st_ctime_nsec;
  unsigned long long      st_ino;
};
]],
  statfs = [[
typedef long statfs_word;
struct statfs64 {
  statfs_word f_type;
  statfs_word f_bsize;
  uint64_t f_blocks;
  uint64_t f_bfree;
  uint64_t f_bavail;
  uint64_t f_files;
  uint64_t f_ffree;
  kernel_fsid_t f_fsid;
  statfs_word f_namelen;
  statfs_word f_frsize;
  statfs_word f_flags;
  statfs_word f_spare[4];
} __attribute__((packed,aligned(4)));
]],
}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.constants"],"module already exists")sources["syscall.linux.constants"]=([===[-- <pack syscall.linux.constants> --
-- tables of constants

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local abi = require "syscall.abi"

local bit = require "syscall.bit"

local tobit = bit.tobit

local arch = require("syscall.linux." .. abi.arch .. ".constants") -- architecture specific code

local h = require "syscall.helpers"

local octal, multiflags, charflags, swapflags, strflag, atflag, modeflags
  = h.octal, h.multiflags, h.charflags, h.swapflags, h.strflag, h.atflag, h.modeflags

local function addarch(tb, a, default)
  local add = a or default
  for k, v in pairs(add) do tb[k] = v end
end

local c = {}

c.errornames = require "syscall.linux.errors"

c.REG = arch.REG

-- TODO only define one of these
c.STD = strflag {
  IN_FILENO = 0,
  OUT_FILENO = 1,
  ERR_FILENO = 2,
  IN = 0,
  OUT = 1,
  ERR = 2,
}

-- sizes
c.PATH_MAX = 4096

-- open, fcntl TODO not setting largefile if matches exactly in upper case, potentially confusing
c.O = multiflags(arch.O or {
  RDONLY    = octal('0000'),
  WRONLY    = octal('0001'),
  RDWR      = octal('0002'),
  ACCMODE   = octal('0003'),
  CREAT     = octal('0100'),
  EXCL      = octal('0200'),
  NOCTTY    = octal('0400'),
  TRUNC     = octal('01000'),
  APPEND    = octal('02000'),
  NONBLOCK  = octal('04000'),
  DSYNC     = octal('010000'),
  ASYNC     = octal('020000'),
  DIRECT    = octal('040000'),
  DIRECTORY = octal('0200000'),
  NOFOLLOW  = octal('0400000'),
  NOATIME   = octal('01000000'),
  CLOEXEC   = octal('02000000'),
  SYNC      = octal('04010000'),
})

c.O.FSYNC     = c.O.SYNC
c.O.RSYNC     = c.O.SYNC
c.O.NDELAY    = c.O.NONBLOCK

if not c.O.LARGEFILE then -- also can be arch dependent
  if abi.abi32 then c.O.LARGEFILE = octal('0100000') else c.O.LARGEFILE = 0 end
end

-- just for pipe2
c.OPIPE = multiflags {
  NONBLOCK  = c.O.NONBLOCK,
  CLOEXEC   = c.O.CLOEXEC,
  DIRECT    = c.O.DIRECT,
}

-- for mq_attr NONBLOCK only flag allowed
c.OMQATTR = multiflags {
  NONBLOCK = c.O.NONBLOCK,
}

-- modes and file types. note renamed second set from S_ to MODE_ but duplicated in S for stat
c.S_I = modeflags {
  FMT   = octal('0170000'),
  FSOCK = octal('0140000'),
  FLNK  = octal('0120000'),
  FREG  = octal('0100000'),
  FBLK  = octal('0060000'),
  FDIR  = octal('0040000'),
  FCHR  = octal('0020000'),
  FIFO  = octal('0010000'),
  SUID  = octal('0004000'),
  SGID  = octal('0002000'),
  SVTX  = octal('0001000'),
  RWXU  = octal('00700'),
  RUSR  = octal('00400'),
  WUSR  = octal('00200'),
  XUSR  = octal('00100'),
  RWXG  = octal('00070'),
  RGRP  = octal('00040'),
  WGRP  = octal('00020'),
  XGRP  = octal('00010'),
  RWXO  = octal('00007'),
  ROTH  = octal('00004'),
  WOTH  = octal('00002'),
  XOTH  = octal('00001'),
}

c.MODE = modeflags {
  SUID = octal('04000'),
  SGID = octal('02000'),
  SVTX = octal('01000'),
  RWXU = octal('00700'),
  RUSR = octal('00400'),
  WUSR = octal('00200'),
  XUSR = octal('00100'),
  RWXG = octal('00070'),
  RGRP = octal('00040'),
  WGRP = octal('00020'),
  XGRP = octal('00010'),
  RWXO = octal('00007'),
  ROTH = octal('00004'),
  WOTH = octal('00002'),
  XOTH = octal('00001'),
}

-- access
c.OK = charflags {
  R = 4,
  W = 2,
  X = 1,
  F = 0,
}

-- fcntl
c.F = strflag(arch.F or {
  DUPFD       = 0,
  GETFD       = 1,
  SETFD       = 2,
  GETFL       = 3,
  SETFL       = 4,
  GETLK       = 5,
  SETLK       = 6,
  SETLKW      = 7,
  SETOWN      = 8,
  GETOWN      = 9,
  SETSIG      = 10,
  GETSIG      = 11,
  GETLK64     = 12,
  SETLK64     = 13,
  SETLKW64    = 14,
  SETOWN_EX   = 15,
  GETOWN_EX   = 16,
  SETLEASE    = 1024,
  GETLEASE    = 1025,
  NOTIFY      = 1026,
  CANCELLK    = 1029,
  DUPFD_CLOEXEC = 1030,
  SETPIPE_SZ  = 1031,
  GETPIPE_SZ  = 1032,
  ADD_SEALS   = 1033,
  GET_SEALS   = 1034,
})

-- messy
if abi.abi64 then
  c.F.GETLK64   = c.F.GETLK
  c.F.SETLK64   = c.F.SETLK
  c.F.SETLKW64  = c.F.SETLKW
else
  c.F.GETLK     = c.F.GETLK64
  c.F.SETLK     = c.F.SETLK64
  c.F.SETLKW    = c.F.SETLKW64
end

c.FD = multiflags {
  CLOEXEC = 1,
}

-- note changed from F_ to FCNTL_LOCK
c.FCNTL_LOCK = strflag {
  RDLCK = 0,
  WRLCK = 1,
  UNLCK = 2,
}

-- lockf, changed from F_ to LOCKF_
c.LOCKF = strflag {
  ULOCK = 0,
  LOCK  = 1,
  TLOCK = 2,
  TEST  = 3,
}

-- for flock (2)
c.LOCK = multiflags {
  SH        = 1,
  EX        = 2,
  NB        = 4,
  UN        = 8,
  MAND      = 32,
  READ      = 64,
  WRITE     = 128,
  RW        = 192,
}

-- for memfd
c.F_SEAL = multiflags {
  SEAL     = 0x0001,
  SHRINK   = 0x0002,
  GROW     = 0x0004,
  WRITE    = 0x0008,
}

--mmap
c.PROT = multiflags {
  NONE  = 0x0,
  READ  = 0x1,
  WRITE = 0x2,
  EXEC  = 0x4,
  GROWSDOWN = 0x01000000,
  GROWSUP   = 0x02000000,
}

addarch(c.PROT, arch.PROT, {})

-- Sharing types
c.MAP = multiflags(arch.MAP or {
  FILE       = 0,
  SHARED     = 0x01,
  PRIVATE    = 0x02,
  TYPE       = 0x0f,
  FIXED      = 0x10,
  ANONYMOUS  = 0x20,
  GROWSDOWN  = 0x00100,
  DENYWRITE  = 0x00800,
  EXECUTABLE = 0x01000,
  LOCKED     = 0x02000,
  NORESERVE  = 0x04000,
  POPULATE   = 0x08000,
  NONBLOCK   = 0x10000,
  STACK      = 0x20000,
  HUGETLB    = 0x40000,
})

if abi.abi64 then c.MAP["32BIT"] = 0x40 end

c.MAP.ANON       = c.MAP.ANONYMOUS

-- flags for `mlockall'.
c.MCL = strflag (arch.MCL or {
  CURRENT    = 1,
  FUTURE     = 2,
})

-- flags for `mremap'.
c.MREMAP = multiflags {
  MAYMOVE = 1,
  FIXED   = 2,
}

-- madvise advice parameter
c.MADV = strflag {
  NORMAL      = 0,
  RANDOM      = 1,
  SEQUENTIAL  = 2,
  WILLNEED    = 3,
  DONTNEED    = 4,
  REMOVE      = 9,
  DONTFORK    = 10,
  DOFORK      = 11,
  MERGEABLE   = 12,
  UNMERGEABLE = 13,
  HUGEPAGE    = 14,
  NOHUGEPAGE  = 15,
  HWPOISON    = 100,
}

-- posix fadvise
c.POSIX_FADV = strflag {
  NORMAL       = 0,
  RANDOM       = 1,
  SEQUENTIAL   = 2,
  WILLNEED     = 3,
  DONTNEED     = 4,
  NOREUSE      = 5,
}

-- fallocate
c.FALLOC_FL = strflag {
  KEEP_SIZE  = 0x01,
  PUNCH_HOLE = 0x02,
}

-- getpriority, setpriority flags
c.PRIO = strflag {
  PROCESS = 0,
  PGRP = 1,
  USER = 2,
}

-- lseek
c.SEEK = strflag {
  SET = 0,
  CUR = 1,
  END = 2,
  DATA = 3,
  HOLE = 4,
}

-- exit
c.EXIT = strflag {
  SUCCESS = 0,
  FAILURE = 1,
}

-- sigaction, note renamed SIGACT from SIG_
c.SIGACT = strflag {
  ERR = -1,
  DFL =  0,
  IGN =  1,
  HOLD = 2,
}

c.SIGEV = strflag {
  SIGNAL    = 0,
  NONE      = 1,
  THREAD    = 2,
  THREAD_ID = 4,
}

c.SIG = strflag(arch.SIG or {
  HUP = 1,
  INT = 2,
  QUIT = 3,
  ILL = 4,
  TRAP = 5,
  ABRT = 6,
  BUS = 7,
  FPE = 8,
  KILL = 9,
  USR1 = 10,
  SEGV = 11,
  USR2 = 12,
  PIPE = 13,
  ALRM = 14,
  TERM = 15,
  STKFLT = 16,
  CHLD = 17,
  CONT = 18,
  STOP = 19,
  TSTP = 20,
  TTIN = 21,
  TTOU = 22,
  URG  = 23,
  XCPU = 24,
  XFSZ = 25,
  VTALRM = 26,
  PROF = 27,
  WINCH = 28,
  IO = 29,
  PWR = 30,
  SYS = 31,
})

c.SIG.IOT = c.SIG.ABRT
--c.SIG.UNUSED     = 31 -- TODO this looks arch dependent
c.SIG.CLD        = c.SIG.CHLD
c.SIG.POLL       = c.SIG.IO

-- sigprocmask note renaming of SIG to SIGPM
c.SIGPM = strflag(arch.SIGPM or {
  BLOCK     = 0,
  UNBLOCK   = 1,
  SETMASK   = 2,
})

-- signalfd
c.SFD = multiflags(arch.SFD or {
  CLOEXEC  = octal('02000000'),
  NONBLOCK = octal('04000'),
})

-- sockets note mix of single and multiple flags TODO code to handle temporarily using multi which is kind of ok
c.SOCK = multiflags(arch.SOCK or {
  STREAM    = 1,
  DGRAM     = 2,
  RAW       = 3,
  RDM       = 4,
  SEQPACKET = 5,
  DCCP      = 6,
  PACKET    = 10,

  CLOEXEC  = octal('02000000'),
  NONBLOCK = octal('04000'),
})

-- misc socket constants
c.SCM = strflag {
  RIGHTS = 0x01,
  CREDENTIALS = 0x02,
}

-- setsockopt
c.SOL = strflag {
  IP         = 0,
  IPV6       = 41,
  ICMPV6     = 58,
  RAW        = 255,
  DECNET     = 261,
  X25        = 262,
  PACKET     = 263,
  ATM        = 264,
  AAL        = 265,
  IRDA       = 266,
}

if arch.SOLSOCKET then c.SOL.SOCKET = arch.SOLSOCKET else c.SOL.SOCKET = 1 end

c.SO = strflag(arch.SO or {
  DEBUG       = 1,
  REUSEADDR   = 2,
  TYPE        = 3,
  ERROR       = 4,
  DONTROUTE   = 5,
  BROADCAST   = 6,
  SNDBUF      = 7,
  RCVBUF      = 8,
  KEEPALIVE   = 9,
  OOBINLINE   = 10,
  NO_CHECK    = 11,
  PRIORITY    = 12,
  LINGER      = 13,
  BSDCOMPAT   = 14,
  REUSEPORT   = 15, -- new, may not be defined yet
  PASSCRED    = 16,
  PEERCRED    = 17,
  RCVLOWAT    = 18,
  SNDLOWAT    = 19,
  RCVTIMEO    = 20,
  SNDTIMEO    = 21,
  SECURITY_AUTHENTICATION = 22,
  SECURITY_ENCRYPTION_TRANSPORT = 23,
  SECURITY_ENCRYPTION_NETWORK = 24,
  BINDTODEVICE       = 25,
  ATTACH_FILTER      = 26,
  DETACH_FILTER      = 27,
  PEERNAME           = 28,
  TIMESTAMP          = 29,
  ACCEPTCONN         = 30,
  PEERSEC            = 31,
  SNDBUFFORCE        = 32,
  RCVBUFFORCE        = 33,
  PASSSEC            = 34,
  TIMESTAMPNS        = 35,
  MARK               = 36,
  TIMESTAMPING       = 37,
  PROTOCOL           = 38,
  DOMAIN             = 39,
  RXQ_OVFL           = 40,
  WIFI_STATUS        = 41,
  PEEK_OFF           = 42,
  NOFCS              = 43,
  LOCK_FILTER        = 44,
  SELECT_ERR_QUEUE   = 45,
  BUSY_POLL          = 46,
  MAX_PACING_RATE    = 47,
  BPF_EXTENSIONS     = 48,
  INCOMING_CPU       = 49,
  ATTACH_BPF         = 50,
  ATTACH_REUSEPORT_CBPF = 51,
  ATTACH_REUSEPORT_EBPF = 52,
})

c.SO.GET_FILTER = c.SO.ATTACH_FILTER
c.SO.DETACH_BPF = c.SO.DETACH_FILTER

-- Maximum queue length specifiable by listen.
c.SOMAXCONN = 128

-- shutdown
c.SHUT = strflag {
  RD   = 0,
  WR   = 1,
  RDWR = 2,
}

-- waitpid 3rd arg
c.W = multiflags {
  NOHANG       = 1,
  UNTRACED     = 2,
  EXITED       = 4,
  CONTINUED    = 8,
  NOWAIT       = 0x01000000,
  NOTHREAD     = 0x20000000, -- __WNOTHREAD
  ALL          = 0x40000000, -- __WALL
  CLONE        = 0x80000000, -- __WCLONE
}

c.W.STOPPED      = c.W.UNTRACED

-- waitid
c.P = strflag{
  ALL  = 0,
  PID  = 1,
  PGID = 2,
}

-- struct siginfo, eg waitid
c.SI = strflag(arch.SI or {
  ASYNCNL = -60,
  TKILL = -6,
  SIGIO = -5,
  ASYNCIO = -4,
  MESGQ = -3,
  TIMER = -2,
  QUEUE = -1,
  USER = 0,
  KERNEL = 0x80,
})

-- note renamed ILL to SIGILL etc as POLL clashes

c.SIGILL = strflag {
  ILLOPC = 1,
  ILLOPN = 2,
  ILLADR = 3,
  ILLTRP = 4,
  PRVOPC = 5,
  PRVREG = 6,
  COPROC = 7,
  BADSTK = 8,
}

c.SIGFPE = strflag {
  INTDIV = 1,
  INTOVF = 2,
  FLTDIV = 3,
  FLTOVF = 4,
  FLTUND = 5,
  FLTRES = 6,
  FLTINV = 7,
  FLTSUB = 8,
}

c.SIGSEGV = strflag {
  MAPERR = 1,
  ACCERR = 2,
}

c.SIGBUS = strflag {
  ADRALN = 1,
  ADRERR = 2,
  OBJERR = 3,
}

c.SIGTRAP = strflag {
  BRKPT = 1,
  TRACE = 2,
}

c.SIGCLD = strflag {
  EXITED    = 1,
  KILLED    = 2,
  DUMPED    = 3,
  TRAPPED   = 4,
  STOPPED   = 5,
  CONTINUED = 6,
}

c.SIGPOLL = strflag {
  IN  = 1,
  OUT = 2,
  MSG = 3,
  ERR = 4,
  PRI = 5,
  HUP = 6,
}

-- sigaction -- note not cast to (void *)(int) as we do not know type here
c.SA = multiflags(arch.SA or {
  NOCLDSTOP = 0x00000001,
  NOCLDWAIT = 0x00000002,
  SIGINFO   = 0x00000004,
  ONSTACK   = 0x08000000,
  RESTART   = 0x10000000,
  NODEFER   = 0x40000000,
  RESETHAND = 0x80000000,
  RESTORER  = 0x04000000,
})

c.SA.NOMASK    = c.SA.NODEFER
c.SA.ONESHOT   = c.SA.RESETHAND

-- timers
c.ITIMER = strflag {
  REAL    = 0,
  VIRTUAL = 1,
  PROF    = 2,
}

-- clocks
c.CLOCK = strflag {
  REALTIME           = 0,
  MONOTONIC          = 1,
  PROCESS_CPUTIME_ID = 2,
  THREAD_CPUTIME_ID  = 3,
  MONOTONIC_RAW      = 4,
  REALTIME_COARSE    = 5,
  MONOTONIC_COARSE   = 6,
}

c.TIMER = strflag {
  ABSTIME = 1,
}

-- adjtimex
c.ADJ = multiflags {
  OFFSET             = 0x0001,
  FREQUENCY          = 0x0002,
  MAXERROR           = 0x0004,
  ESTERROR           = 0x0008,
  STATUS             = 0x0010,
  TIMECONST          = 0x0020,
  TAI                = 0x0080,
  MICRO              = 0x1000,
  NANO               = 0x2000,
  TICK               = 0x4000,
  OFFSET_SINGLESHOT  = 0x8001,
  OFFSET_SS_READ     = 0xa001,
}

c.STA = multiflags {
  PLL         = 0x0001,
  PPSFREQ     = 0x0002,
  PPSTIME     = 0x0004,
  FLL         = 0x0008,
  INS         = 0x0010,
  DEL         = 0x0020,
  UNSYNC      = 0x0040,
  FREQHOLD    = 0x0080,
  PPSSIGNAL   = 0x0100,
  PPSJITTER   = 0x0200,
  PPSWANDER   = 0x0400,
  PPSERROR    = 0x0800,
  CLOCKERR    = 0x1000,
  NANO        = 0x2000,
  MODE        = 0x4000,
  CLK         = 0x8000,
}

-- return values for adjtimex
c.TIME = strflag {
  OK         = 0,
  INS        = 1,
  DEL        = 2,
  OOP        = 3,
  WAIT       = 4,
  ERROR      = 5,
}

c.TIME.BAD        = c.TIME.ERROR

-- xattr; defined as multi as 0 is default, even though both flags makes no sense
c.XATTR = multiflags {
  CREATE  = 1,
  REPLACE = 2,
}

-- utime
c.UTIME = strflag {
  NOW  = bit.lshift(1, 30) - 1,
  OMIT = bit.lshift(1, 30) - 2,
}

c.AT_FDCWD = atflag {
  FDCWD = -100,
}

-- not all combinations valid
c.AT = multiflags {
  SYMLINK_NOFOLLOW = 0x100,
  REMOVEDIR        = 0x200,
  EACCESS          = 0x200,
  SYMLINK_FOLLOW   = 0x400,
  NO_AUTOMOUNT     = 0x800,
  EMPTY_PATH       = 0x1000,
}

-- send, recv etc
c.MSG = multiflags {
  OOB             = 0x01,
  PEEK            = 0x02,
  DONTROUTE       = 0x04,
  CTRUNC          = 0x08,
  PROXY           = 0x10,
  TRUNC           = 0x20,
  DONTWAIT        = 0x40,
  EOR             = 0x80,
  WAITALL         = 0x100,
  FIN             = 0x200,
  SYN             = 0x400,
  CONFIRM         = 0x800,
  RST             = 0x1000,
  ERRQUEUE        = 0x2000,
  NOSIGNAL        = 0x4000,
  MORE            = 0x8000,
  WAITFORONE      = 0x10000,
  CMSG_CLOEXEC    = 0x40000000,
}

c.MSG.TRYHARD         = c.MSG.DONTROUTE

-- rlimit
c.RLIMIT = strflag(arch.RLIMIT or {
  CPU        = 0,
  FSIZE      = 1,
  DATA       = 2,
  STACK      = 3,
  CORE       = 4,
  RSS        = 5,
  NPROC      = 6,
  NOFILE     = 7,
  MEMLOCK    = 8,
  AS         = 9,
  LOCKS      = 10,
  SIGPENDING = 11,
  MSGQUEUE   = 12,
  NICE       = 13,
  RTPRIO     = 14,
  RTTIME     = 15,
})

c.RLIMIT.OFILE = c.RLIMIT.NOFILE

c.RLIM = strflag {
  INFINITY = h.uint64_max,
}

-- timerfd
c.TFD = multiflags(arch.TFD or {
  CLOEXEC  = octal("02000000"),
  NONBLOCK = octal("04000"),
})

c.TFD_TIMER = strflag {
  ABSTIME = 1,
  CANCEL_ON_SET = 2,
}

-- poll
c.POLL = multiflags(arch.POLL or {
  IN          = 0x001,
  PRI         = 0x002,
  OUT         = 0x004,
  ERR         = 0x008,
  HUP         = 0x010,
  NVAL        = 0x020,
  RDNORM      = 0x040,
  RDBAND      = 0x080,
  WRNORM      = 0x100,
  WRBAND      = 0x200,
  MSG         = 0x400,
  REMOVE      = 0x1000,
  RDHUP       = 0x2000,
})

-- epoll renamed from EPOLL_ to EPOLLCREATE
c.EPOLLCREATE = multiflags {
  CLOEXEC = octal("02000000"),
  NONBLOCK = octal("04000"),
}

c.EPOLL = multiflags {
  IN  = 0x001,
  PRI = 0x002,
  OUT = 0x004,
  RDNORM = 0x040,
  RDBAND = 0x080,
  WRNORM = 0x100,
  WRBAND = 0x200,
  MSG = 0x400,
  ERR = 0x008,
  HUP = 0x010,
  RDHUP = 0x2000,
  ONESHOT = bit.lshift(1, 30),
  ET = bit.lshift(1, 30) * 2, -- 2^31 but making sure no sign issue
}

c.EPOLL_CTL = strflag {
  ADD = 1,
  DEL = 2,
  MOD = 3,
}

-- splice etc
c.SPLICE_F = multiflags {
  MOVE         = 1,
  NONBLOCK     = 2,
  MORE         = 4,
  GIFT         = 8,
}

-- aio - see /usr/include/linux/aio_abi.h
c.IOCB_CMD = strflag {
  PREAD   = 0,
  PWRITE  = 1,
  FSYNC   = 2,
  FDSYNC  = 3,
-- PREADX = 4,
-- POLL   = 5,
  NOOP    = 6,
  PREADV  = 7,
  PWRITEV = 8,
}

c.IOCB_FLAG = strflag {
  RESFD = 1,
}

-- file types in directory
c.DT = strflag {
  UNKNOWN = 0,
  FIFO = 1,
  CHR = 2,
  DIR = 4,
  BLK = 6,
  REG = 8,
  LNK = 10,
  SOCK = 12,
  WHT = 14,
}

-- sync file range
c.SYNC_FILE_RANGE = multiflags {
  WAIT_BEFORE = 1,
  WRITE       = 2,
  WAIT_AFTER  = 4,
}

-- netlink
c.NETLINK = strflag {
  ROUTE         = 0,
  UNUSED        = 1,
  USERSOCK      = 2,
  FIREWALL      = 3,
  INET_DIAG     = 4,
  NFLOG         = 5,
  XFRM          = 6,
  SELINUX       = 7,
  ISCSI         = 8,
  AUDIT         = 9,
  FIB_LOOKUP    = 10,
  CONNECTOR     = 11,
  NETFILTER     = 12,
  IP6_FW        = 13,
  DNRTMSG       = 14,
  KOBJECT_UEVENT= 15,
  GENERIC       = 16,
  SCSITRANSPORT = 18,
  ECRYPTFS      = 19,
}

-- see man netlink(7) for details. Note us of flags by context
c.NLM_F = multiflags {
  REQUEST = 1,
  MULTI   = 2,
  ACK     = 4,
  ECHO    = 8,
-- for GET
  ROOT    = 0x100,
  MATCH   = 0x200,
  ATOMIC  = 0x400,
-- for NEW
  REPLACE = 0x100,
  EXCL    = 0x200,
  CREATE  = 0x400,
  APPEND  = 0x800,
}

c.NLM_F.DUMP = bit.bor(c.NLM_F.ROOT, c.NLM_F.MATCH)

-- generic types. These are part of same sequence as RTM
c.NLMSG = strflag{
  NOOP     = 0x1,
  ERROR    = 0x2,
  DONE     = 0x3,
  OVERRUN  = 0x4,
}

-- routing
c.RTM = strflag {
  NEWLINK     = 16,
  DELLINK     = 17,
  GETLINK     = 18,
  SETLINK     = 19,
  NEWADDR     = 20,
  DELADDR     = 21,
  GETADDR     = 22,
  NEWROUTE    = 24,
  DELROUTE    = 25,
  GETROUTE    = 26,
  NEWNEIGH    = 28,
  DELNEIGH    = 29,
  GETNEIGH    = 30,
  NEWRULE     = 32,
  DELRULE     = 33,
  GETRULE     = 34,
  NEWQDISC    = 36,
  DELQDISC    = 37,
  GETQDISC    = 38,
  NEWTCLASS   = 40,
  DELTCLASS   = 41,
  GETTCLASS   = 42,
  NEWTFILTER  = 44,
  DELTFILTER  = 45,
  GETTFILTER  = 46,
  NEWACTION   = 48,
  DELACTION   = 49,
  GETACTION   = 50,
  NEWPREFIX   = 52,
  GETMULTICAST = 58,
  GETANYCAST  = 62,
  NEWNEIGHTBL = 64,
  GETNEIGHTBL = 66,
  SETNEIGHTBL = 67,
  NEWNDUSEROPT = 68,
  NEWADDRLABEL = 72,
  DELADDRLABEL = 73,
  GETADDRLABEL = 74,
  GETDCB = 78,
  SETDCB = 79,
}

-- linux/if_linc.h
c.IFLA = strflag {
  UNSPEC    = 0,
  ADDRESS   = 1,
  BROADCAST = 2,
  IFNAME    = 3,
  MTU       = 4,
  LINK      = 5,
  QDISC     = 6,
  STATS     = 7,
  COST      = 8,
  PRIORITY  = 9,
  MASTER    = 10,
  WIRELESS  = 11,
  PROTINFO  = 12,
  TXQLEN    = 13,
  MAP       = 14,
  WEIGHT    = 15,
  OPERSTATE = 16,
  LINKMODE  = 17,
  LINKINFO  = 18,
  NET_NS_PID= 19,
  IFALIAS   = 20,
  NUM_VF    = 21,
  VFINFO_LIST = 22,
  STATS64   = 23,
  VF_PORTS  = 24,
  PORT_SELF = 25,
  AF_SPEC   = 26,
  GROUP     = 27,
  NET_NS_FD = 28,
}

c.IFLA_INET = strflag {
  UNSPEC = 0,
  CONF   = 1,
}

c.IFLA_INET6 = strflag {
  UNSPEC = 0,
  FLAGS  = 1,
  CONF   = 2,
  STATS  = 3,
  MCAST  = 4,
  CACHEINFO  = 5,
  ICMP6STATS = 6,
}

c.IFLA_INFO = strflag {
  UNSPEC = 0,
  KIND   = 1,
  DATA   = 2,
  XSTATS = 3,
}

c.IFLA_VLAN = strflag {
  UNSPEC = 0,
  ID     = 1,
  FLAGS  = 2,
  EGRESS_QOS  = 3,
  INGRESS_QOS = 4,
}

c.IFLA_VLAN_QOS = strflag {
  UNSPEC  = 0,
  MAPPING = 1,
}

c.IFLA_MACVLAN = strflag {
  UNSPEC = 0,
  MODE   = 1,
}

c.MACVLAN_MODE = multiflags {
  PRIVATE = 1,
  VEPA    = 2,
  BRIDGE  = 4,
  PASSTHRU = 8,
}

c.IFLA_VF_INFO = strflag {
  UNSPEC = 0,
  INFO   = 1, -- note renamed IFLA_VF_INFO to IFLA_VF_INFO.INFO
}

c.IFLA_VF = strflag {
  UNSPEC   = 0,
  MAC      = 1,
  VLAN     = 2,
  TX_RATE  = 3,
  SPOOFCHK = 4,
}

c.IFLA_VF_PORT = strflag {
  UNSPEC = 0,
  PORT   = 1, -- note renamed from IFLA_VF_PORT to IFLA_VF_PORT.PORT?
}

c.IFLA_PORT = strflag {
  UNSPEC    = 0,
  VF        = 1,
  PROFILE   = 2,
  VSI_TYPE  = 3,
  INSTANCE_UUID = 4,
  HOST_UUID = 5,
  REQUEST   = 6,
  RESPONSE  = 7,
}

c.VETH_INFO = strflag {
  UNSPEC = 0,
  PEER   = 1,
}

c.PORT = strflag {
  PROFILE_MAX      =  40,
  UUID_MAX         =  16,
  SELF_VF          =  -1,
}

c.PORT_REQUEST = strflag {
  PREASSOCIATE    = 0,
  PREASSOCIATE_RR = 1,
  ASSOCIATE       = 2,
  DISASSOCIATE    = 3,
}

c.PORT_VDP_RESPONSE = strflag {
  SUCCESS = 0,
  INVALID_FORMAT = 1,
  INSUFFICIENT_RESOURCES = 2,
  UNUSED_VTID = 3,
  VTID_VIOLATION = 4,
  VTID_VERSION_VIOALTION = 5, -- seems to be misspelled in headers TODO fix
  OUT_OF_SYNC = 6,
}

c.PORT_PROFILE_RESPONSE = strflag {
  SUCCESS = 0x100,
  INPROGRESS = 0x101,
  INVALID = 0x102,
  BADSTATE = 0x103,
  INSUFFICIENT_RESOURCES = 0x104,
  ERROR = 0x105,
}

-- from if_addr.h interface address types and flags
c.IFA = strflag {
  UNSPEC    = 0,
  ADDRESS   = 1,
  LOCAL     = 2,
  LABEL     = 3,
  BROADCAST = 4,
  ANYCAST   = 5,
  CACHEINFO = 6,
  MULTICAST = 7,
}

c.IFA_F = multiflags {
  SECONDARY   = 0x01,
  NODAD       = 0x02,
  OPTIMISTIC  = 0x04,
  DADFAILED   = 0x08,
  HOMEADDRESS = 0x10,
  DEPRECATED  = 0x20,
  TENTATIVE   = 0x40,
  PERMANENT   = 0x80,
}

c.IFA_F.TEMPORARY   = c.IFA_F.SECONDARY

-- routing
c.RTN = strflag {
  UNSPEC      = 0,
  UNICAST     = 1,
  LOCAL       = 2,
  BROADCAST   = 3,
  ANYCAST     = 4,
  MULTICAST   = 5,
  BLACKHOLE   = 6,
  UNREACHABLE = 7,
  PROHIBIT    = 8,
  THROW       = 9,
  NAT         = 10,
  XRESOLVE    = 11,
}

c.RTPROT = strflag {
  UNSPEC   = 0,
  REDIRECT = 1,
  KERNEL   = 2,
  BOOT     = 3,
  STATIC   = 4,
  GATED    = 8,
  RA       = 9,
  MRT      = 10,
  ZEBRA    = 11,
  BIRD     = 12,
  DNROUTED = 13,
  XORP     = 14,
  NTK      = 15,
  DHCP     = 16,
}

c.RT_SCOPE = strflag {
  UNIVERSE = 0,
  SITE = 200,
  LINK = 253,
  HOST = 254,
  NOWHERE = 255,
}

c.RTM_F = multiflags {
  NOTIFY          = 0x100,
  CLONED          = 0x200,
  EQUALIZE        = 0x400,
  PREFIX          = 0x800,
}

c.RT_TABLE = strflag {
  UNSPEC  = 0,
  COMPAT  = 252,
  DEFAULT = 253,
  MAIN    = 254,
  LOCAL   = 255,
  MAX     = 0xFFFFFFFF,
}

c.RTA = strflag {
  UNSPEC = 0,
  DST = 1,
  SRC = 2,
  IIF = 3,
  OIF = 4,
  GATEWAY = 5,
  PRIORITY = 6,
  PREFSRC = 7,
  METRICS = 8,
  MULTIPATH = 9,
  PROTOINFO = 10,
  FLOW = 11,
  CACHEINFO = 12,
  SESSION = 13,
  MP_ALGO = 14,
  TABLE = 15,
  MARK = 16,
  MFC_STATS = 17,
  VIA = 18,
  NEWDST = 19,
  PREF = 20,
}

-- route flags
c.RTF = multiflags {
  UP          = 0x0001,
  GATEWAY     = 0x0002,
  HOST        = 0x0004,
  REINSTATE   = 0x0008,
  DYNAMIC     = 0x0010,
  MODIFIED    = 0x0020,
  MTU         = 0x0040,
  WINDOW      = 0x0080,
  IRTT        = 0x0100,
  REJECT      = 0x0200,
-- ipv6 route flags
  DEFAULT     = 0x00010000,
  ALLONLINK   = 0x00020000,
  ADDRCONF    = 0x00040000,
  PREFIX_RT   = 0x00080000,
  ANYCAST     = 0x00100000,
  NONEXTHOP   = 0x00200000,
  EXPIRES     = 0x00400000,
  ROUTEINFO   = 0x00800000,
  CACHE       = 0x01000000,
  FLOW        = 0x02000000,
  POLICY      = 0x04000000,
  LOCAL       = 0x80000000,
}

c.RTF.MSS         = c.RTF.MTU

--#define RTF_PREF(pref)  ((pref) << 27)
--#define RTF_PREF_MASK   0x18000000

-- interface flags
c.IFF = multiflags {
  UP         = 0x1,
  BROADCAST  = 0x2,
  DEBUG      = 0x4,
  LOOPBACK   = 0x8,
  POINTOPOINT= 0x10,
  NOTRAILERS = 0x20,
  RUNNING    = 0x40,
  NOARP      = 0x80,
  PROMISC    = 0x100,
  ALLMULTI   = 0x200,
  MASTER     = 0x400,
  SLAVE      = 0x800,
  MULTICAST  = 0x1000,
  PORTSEL    = 0x2000,
  AUTOMEDIA  = 0x4000,
  DYNAMIC    = 0x8000,
  LOWER_UP   = 0x10000,
  DORMANT    = 0x20000,
  ECHO       = 0x40000,
}

c.IFF.ALL        = 0xffffffff
c.IFF.NONE       = bit.bnot(0x7ffff) -- this is a bit of a fudge as zero should work, but does not for historical reasons see net/core/rtnetlinc.c

c.IFF.VOLATILE = c.IFF.LOOPBACK + c.IFF.POINTOPOINT + c.IFF.BROADCAST + c.IFF.ECHO +
                 c.IFF.MASTER + c.IFF.SLAVE + c.IFF.RUNNING + c.IFF.LOWER_UP + c.IFF.DORMANT

-- netlink multicast groups
-- legacy names, which are masks.
c.RTMGRP = multiflags {
  LINK            = 1,
  NOTIFY          = 2,
  NEIGH           = 4,
  TC              = 8,
  IPV4_IFADDR     = 0x10,
  IPV4_MROUTE     = 0x20,
  IPV4_ROUTE      = 0x40,
  IPV4_RULE       = 0x80,
  IPV6_IFADDR     = 0x100,
  IPV6_MROUTE     = 0x200,
  IPV6_ROUTE      = 0x400,
  IPV6_IFINFO     = 0x800,
--DECNET_IFADDR   = 0x1000,
--DECNET_ROUTE    = 0x4000,
  IPV6_PREFIX     = 0x20000,
}

-- rtnetlink multicast groups (bit numbers not masks)
c.RTNLGRP = strflag {
  NONE = 0,
  LINK = 1,
  NOTIFY = 2,
  NEIGH = 3,
  TC = 4,
  IPV4_IFADDR = 5,
  IPV4_MROUTE = 6,
  IPV4_ROUTE = 7,
  IPV4_RULE = 8,
  IPV6_IFADDR = 9,
  IPV6_MROUTE = 10,
  IPV6_ROUTE = 11,
  IPV6_IFINFO = 12,
-- DECNET_IFADDR = 13,
  NOP2 = 14,
-- DECNET_ROUTE = 15,
-- DECNET_RULE = 16,
  NOP4 = 17,
  IPV6_PREFIX = 18,
  IPV6_RULE = 19,
  ND_USEROPT = 20,
  PHONET_IFADDR = 21,
  PHONET_ROUTE = 22,
  DCB = 23,
}

-- netlink neighbours (arp)
c.NDA = strflag {
  UNSPEC = 0,
  DST = 1,
  LLADDR = 2,
  CACHEINFO = 3,
  PROBES = 4,
}

c.NTF = multiflags {
  USE        = 0x01,
  PROXY      = 0x08,
  ROUTER     = 0x80,
  SELF       = 0x02,
  MASTER     = 0x04,
}

c.NUD = multiflags {
  INCOMPLETE = 0x01,
  REACHABLE  = 0x02,
  STALE      = 0x04,
  DELAY      = 0x08,
  PROBE      = 0x10,
  FAILED     = 0x20,
  NOARP      = 0x40,
  PERMANENT  = 0x80,
  NONE       = 0x00,
}

c.NDTPA = strflag {
  UNSPEC = 0,
  IFINDEX = 1,
  REFCNT = 2,
  REACHABLE_TIME = 3,
  BASE_REACHABLE_TIME = 4,
  RETRANS_TIME = 5,
  GC_STALETIME = 6,
  DELAY_PROBE_TIME = 7,
  QUEUE_LEN = 8,
  APP_PROBES = 9,
  UCAST_PROBES = 10,
  MCAST_PROBES = 11,
  ANYCAST_DELAY = 12,
  PROXY_DELAY = 13,
  PROXY_QLEN = 14,
  LOCKTIME = 15,
  QUEUE_LENBYTES = 16,
}

c.NDTA = strflag {
  UNSPEC = 0,
  NAME = 1,
  THRESH1 = 2,
  THRESH2 = 3,
  THRESH3 = 4,
  CONFIG = 5,
  PARMS = 6,
  STATS = 7,
  GC_INTERVAL = 8,
}

-- address families
c.AF = strflag {
  UNSPEC     = 0,
  LOCAL      = 1,
  INET       = 2,
  AX25       = 3,
  IPX        = 4,
  APPLETALK  = 5,
  NETROM     = 6,
  BRIDGE     = 7,
  ATMPVC     = 8,
  X25        = 9,
  INET6      = 10,
  ROSE       = 11,
  DECNET     = 12,
  NETBEUI    = 13,
  SECURITY   = 14,
  KEY        = 15,
  NETLINK    = 16,
  PACKET     = 17,
  ASH        = 18,
  ECONET     = 19,
  ATMSVC     = 20,
  RDS        = 21,
  SNA        = 22,
  IRDA       = 23,
  PPPOX      = 24,
  WANPIPE    = 25,
  LLC        = 26,
  CAN        = 29,
  TIPC       = 30,
  BLUETOOTH  = 31,
  IUCV       = 32,
  RXRPC      = 33,
  ISDN       = 34,
  PHONET     = 35,
  IEEE802154 = 36,
  CAIF       = 37,
  ALG        = 38,
  NFC        = 39,
}

c.AF.UNIX       = c.AF.LOCAL
c.AF.FILE       = c.AF.LOCAL
c.AF.ROUTE      = c.AF.NETLINK

-- arp types, which are also interface types for ifi_type
c.ARPHRD = strflag {
  NETROM   = 0,
  ETHER    = 1,
  EETHER   = 2,
  AX25     = 3,
  PRONET   = 4,
  CHAOS    = 5,
  IEEE802  = 6,
  ARCNET   = 7,
  APPLETLK = 8,
  DLCI     = 15,
  ATM      = 19,
  METRICOM = 23,
  IEEE1394 = 24,
  EUI64    = 27,
  INFINIBAND = 32,
  SLIP     = 256,
  CSLIP    = 257,
  SLIP6    = 258,
  CSLIP6   = 259,
  RSRVD    = 260,
  ADAPT    = 264,
  ROSE     = 270,
  X25      = 271,
  HWX25    = 272,
  CAN      = 280,
  PPP      = 512,
  CISCO    = 513,
  LAPB     = 516,
  DDCMP    = 517,
  RAWHDLC  = 518,
  TUNNEL   = 768,
  TUNNEL6  = 769,
  FRAD     = 770,
  SKIP     = 771,
  LOOPBACK = 772,
  LOCALTLK = 773,
  FDDI     = 774,
  BIF      = 775,
  SIT      = 776,
  IPDDP    = 777,
  IPGRE    = 778,
  PIMREG   = 779,
  HIPPI    = 780,
  ASH      = 781,
  ECONET   = 782,
  IRDA     = 783,
  FCPP     = 784,
  FCAL     = 785,
  FCPL     = 786,
  FCFABRIC = 787,
  IEEE802_TR = 800,
  IEEE80211 = 801,
  IEEE80211_PRISM = 802,
  IEEE80211_RADIOTAP = 803,
  IEEE802154         = 804,
  PHONET   = 820,
  PHONET_PIPE = 821,
  CAIF     = 822,
  VOID     = 0xFFFF,
  NONE     = 0xFFFE,
}

c.ARPHRD.HDLC     = c.ARPHRD.CISCO

-- IP
c.IPPROTO = strflag {
  IP = 0,
  ICMP = 1,
  IGMP = 2,
  IPIP = 4,
  TCP = 6,
  EGP = 8,
  PUP = 12,
  UDP = 17,
  IDP = 22,
  TP = 29,
  DCCP = 33,
  IPV6 = 41,
  ROUTING = 43,
  FRAGMENT = 44,
  RSVP = 46,
  GRE = 47,
  ESP = 50,
  AH = 51,
  ICMPV6 = 58,
  NONE = 59,
  DSTOPTS = 60,
  MTP = 92,
  ENCAP = 98,
  PIM = 103,
  COMP = 108,
  SCTP = 132,
  UDPLITE = 136,
  RAW = 255,
}

c.IP = strflag {
  TOS          = 1,
  TTL          = 2,
  HDRINCL      = 3,
  OPTIONS      = 4,
  ROUTER_ALERT = 5,
  RECVOPTS     = 6,
  RETOPTS      = 7,
  PKTINFO      = 8,
  PKTOPTIONS   = 9,
  MTU_DISCOVER = 10,
  RECVERR      = 11,
  RECVTTL      = 12,
  RECVTOS      = 13,
  MTU          = 14,
  FREEBIND     = 15,
  IPSEC_POLICY = 16,
  XFRM_POLICY  = 17,
  PASSSEC      = 18,
  TRANSPARENT  = 19,
  ORIGDSTADDR  = 20,
  MINTTL       = 21,
  NODEFRAG     = 22,
  MULTICAST_IF                 = 32,
  MULTICAST_TTL                = 33,
  MULTICAST_LOOP               = 34,
  ADD_MEMBERSHIP               = 35,
  DROP_MEMBERSHIP              = 36,
  UNBLOCK_SOURCE               = 37,
  BLOCK_SOURCE                 = 38,
  ADD_SOURCE_MEMBERSHIP        = 39,
  DROP_SOURCE_MEMBERSHIP       = 40,
  MSFILTER                     = 41,

  MULTICAST_ALL                = 49, 
  UNICAST_IF                   = 50,
}

c.ETH_P = strflag {
  LOOP      = 0x0060,
  PUP       = 0x0200,
  PUPAT     = 0x0201,
  IP        = 0x0800,
  X25       = 0x0805,
  ARP       = 0x0806,
  BPQ       = 0x08FF,
  IEEEPUP   = 0x0a00,
  IEEEPUPAT = 0x0a01,
  DEC       = 0x6000,
  DNA_DL    = 0x6001,
  DNA_RC    = 0x6002,
  DNA_RT    = 0x6003,
  LAT       = 0x6004,
  DIAG      = 0x6005,
  CUST      = 0x6006,
  SCA       = 0x6007,
  TEB       = 0x6558,
  RARP      = 0x8035,
  ATALK     = 0x809B,
  AARP      = 0x80F3,
  ["8021Q"] = 0x8100,
  IPX       = 0x8137,
  IPV6      = 0x86DD,
  PAUSE     = 0x8808,
  SLOW      = 0x8809,
  WCCP      = 0x883E,
  PPP_DISC  = 0x8863,
  PPP_SES   = 0x8864,
  MPLS_UC   = 0x8847,
  MPLS_MC   = 0x8848,
  ATMMPOA   = 0x884c,
  LINK_CTL  = 0x886c,
  ATMFATE   = 0x8884,
  PAE       = 0x888E,
  AOE       = 0x88A2,
  ["8021AD"]= 0x88A8,
  ["802_EX1"]= 0x88B5,
  TIPC      = 0x88CA,
  ["8021AH"]= 0x88E7,
  ["1588"]  = 0x88F7,
  FCOE      = 0x8906,
  TDLS      = 0x890D,
  FIP       = 0x8914,
  QINQ1     = 0x9100,
  QINQ2     = 0x9200,
  QINQ3     = 0x9300,
  EDSA      = 0xDADA,
  AF_IUCV   = 0xFBFB,
  ["802_3"] = 0x0001,
  AX25      = 0x0002,
  ALL       = 0x0003,
  ["802_2"] = 0x0004,
  SNAP      = 0x0005,
  DDCMP     = 0x0006,
  WAN_PPP   = 0x0007,
  PPP_MP    = 0x0008,
  LOCALTALK = 0x0009,
  CAN       = 0x000C,
  PPPTALK   = 0x0010,
  TR_802_2  = 0x0011,
  MOBITEX   = 0x0015,
  CONTROL   = 0x0016,
  IRDA      = 0x0017,
  ECONET    = 0x0018,
  HDLC      = 0x0019,
  ARCNET    = 0x001A,
  DSA       = 0x001B,
  TRAILER   = 0x001C,
  PHONET    = 0x00F5,
  IEEE802154= 0x00F6,
  CAIF      = 0x00F7,
}

c.ETHERTYPE = strflag {
  PUP          = 0x0200,
  SPRITE       = 0x0500,
  IP           = 0x0800,
  ARP          = 0x0806,
  REVARP       = 0x8035,
  AT           = 0x809B,
  AARP         = 0x80F3,
  VLAN         = 0x8100,
  IPX          = 0x8137,
  IPV6         = 0x86dd,
  LOOPBACK     = 0x9000,
  TRAIL        = 0x1000,
}

-- eventfd
c.EFD = multiflags {
  SEMAPHORE = 1,
  CLOEXEC = c.O.CLOEXEC,
  NONBLOCK = c.O.NONBLOCK,
}

-- mount
c.MS = multiflags {
  RDONLY = 1,
  NOSUID = 2,
  NODEV = 4,
  NOEXEC = 8,
  SYNCHRONOUS = 16,
  REMOUNT = 32,
  MANDLOCK = 64,
  DIRSYNC = 128,
  NOATIME = 1024,
  NODIRATIME = 2048,
  BIND = 4096,
  MOVE = 8192,
  REC = 16384,
  SILENT = 32768,
  POSIXACL = bit.lshift(1, 16),
  UNBINDABLE = bit.lshift(1, 17),
  PRIVATE = bit.lshift(1, 18),
  SLAVE = bit.lshift(1, 19),
  SHARED = bit.lshift(1, 20),
  RELATIME = bit.lshift(1, 21),
  KERNMOUNT = bit.lshift(1, 22),
  I_VERSION = bit.lshift(1, 23),
  STRICTATIME = bit.lshift(1, 24),
  ACTIVE = bit.lshift(1, 30),
  NOUSER = bit.lshift(1, 31),
}

-- fake flags
c.MS.RO = c.MS.RDONLY -- allow use of "ro" as flag as that is what /proc/mounts uses
c.MS.RW = 0           -- allow use of "rw" as flag as appears in /proc/mounts
c.MS.SECLABEL = 0     -- appears in /proc/mounts in some distros, ignore

-- flags to `msync'. - note was MS_ renamed to MSYNC_
c.MSYNC = multiflags {
  ASYNC       = 1,
  INVALIDATE  = 2,
  SYNC        = 4,
}

-- one table for umount as it uses MNT_ and UMOUNT_ options
c.UMOUNT = multiflags {
  FORCE    = 1,
  DETACH   = 2,
  EXPIRE   = 4,
  NOFOLLOW = 8,
}

-- reboot
c.LINUX_REBOOT_CMD = strflag {
  RESTART      =  0x01234567,
  HALT         =  0xCDEF0123,
  CAD_ON       =  0x89ABCDEF,
  CAD_OFF      =  0x00000000,
  POWER_OFF    =  0x4321FEDC,
  RESTART2     =  0xA1B2C3D4,
  SW_SUSPEND   =  0xD000FCE2,
  KEXEC        =  0x45584543,
}

-- clone
c.CLONE = multiflags {
  VM      = 0x00000100,
  FS      = 0x00000200,
  FILES   = 0x00000400,
  SIGHAND = 0x00000800,
  PTRACE  = 0x00002000,
  VFORK   = 0x00004000,
  PARENT  = 0x00008000,
  THREAD  = 0x00010000,
  NEWNS   = 0x00020000,
  SYSVSEM = 0x00040000,
  SETTLS  = 0x00080000,
  PARENT_SETTID  = 0x00100000,
  CHILD_CLEARTID = 0x00200000,
  DETACHED = 0x00400000,
  UNTRACED = 0x00800000,
  CHILD_SETTID = 0x01000000,
  NEWUTS   = 0x04000000,
  NEWIPC   = 0x08000000,
  NEWUSER  = 0x10000000,
  NEWPID   = 0x20000000,
  NEWNET   = 0x40000000,
  IO       = 0x80000000,
}

-- inotify
-- flags note rename from IN_ to IN_INIT
c.IN_INIT = multiflags(arch.IN_INIT or {
  CLOEXEC = octal("02000000"),
  NONBLOCK = octal("04000"),
})

-- events
c.IN = multiflags {
  ACCESS        = 0x00000001,
  MODIFY        = 0x00000002,
  ATTRIB        = 0x00000004,
  CLOSE_WRITE   = 0x00000008,
  CLOSE_NOWRITE = 0x00000010,
  OPEN          = 0x00000020,
  MOVED_FROM    = 0x00000040,
  MOVED_TO      = 0x00000080,
  CREATE        = 0x00000100,
  DELETE        = 0x00000200,
  DELETE_SELF   = 0x00000400,
  MOVE_SELF     = 0x00000800,
  UNMOUNT       = 0x00002000,
  Q_OVERFLOW    = 0x00004000,
  IGNORED       = 0x00008000,

  ONLYDIR       = 0x01000000,
  DONT_FOLLOW   = 0x02000000,
  EXCL_UNLINK   = 0x04000000,
  MASK_ADD      = 0x20000000,
  ISDIR         = 0x40000000,
  ONESHOT       = 0x80000000,
}

c.IN.CLOSE         = c.IN.CLOSE_WRITE + c.IN.CLOSE_NOWRITE
c.IN.MOVE          = c.IN.MOVED_FROM + c.IN.MOVED_TO

c.IN.ALL_EVENTS    = c.IN.ACCESS + c.IN.MODIFY + c.IN.ATTRIB + c.IN.CLOSE_WRITE
                       + c.IN.CLOSE_NOWRITE + c.IN.OPEN + c.IN.MOVED_FROM
                       + c.IN.MOVED_TO + c.IN.CREATE + c.IN.DELETE
                       + c.IN.DELETE_SELF + c.IN.MOVE_SELF

--prctl
c.PR = strflag {
  SET_PDEATHSIG = 1,
  GET_PDEATHSIG = 2,
  GET_DUMPABLE  = 3,
  SET_DUMPABLE  = 4,
  GET_UNALIGN   = 5,
  SET_UNALIGN   = 6,
  GET_KEEPCAPS  = 7,
  SET_KEEPCAPS  = 8,
  GET_FPEMU     = 9,
  SET_FPEMU     = 10,
  GET_FPEXC     = 11,
  SET_FPEXC     = 12,
  GET_TIMING    = 13,
  SET_TIMING    = 14,
  SET_NAME      = 15,
  GET_NAME      = 16,
  GET_ENDIAN    = 19,
  SET_ENDIAN    = 20,
  GET_SECCOMP   = 21,
  SET_SECCOMP   = 22,
  CAPBSET_READ  = 23,
  CAPBSET_DROP  = 24,
  GET_TSC       = 25,
  SET_TSC       = 26,
  GET_SECUREBITS= 27,
  SET_SECUREBITS= 28,
  SET_TIMERSLACK= 29,
  GET_TIMERSLACK= 30,
  TASK_PERF_EVENTS_DISABLE=31,
  TASK_PERF_EVENTS_ENABLE=32,
  MCE_KILL      = 33,
  MCE_KILL_GET  = 34,
  SET_NO_NEW_PRIVS = 38,
  GET_NO_NEW_PRIVS = 39,
  GET_TID_ADDRESS = 40,
}

-- for PR get/set unalign
c.PR_UNALIGN = strflag {
  NOPRINT   = 1,
  SIGBUS    = 2,
}

-- for PR fpemu
c.PR_FPEMU = strflag {
  NOPRINT     = 1,
  SIGFPE      = 2,
}

-- for PR fpexc -- TODO should be a combo of stringflag and flags
c.PR_FP_EXC = multiflags {
  SW_ENABLE  = 0x80,
  DIV        = 0x010000,
  OVF        = 0x020000,
  UND        = 0x040000,
  RES        = 0x080000,
  INV        = 0x100000,
  DISABLED   = 0,
  NONRECOV   = 1,
  ASYNC      = 2,
  PRECISE    = 3,
}

-- PR get set timing
c.PR_TIMING = strflag {
  STATISTICAL= 0,
  TIMESTAMP  = 1,
}

-- PR set endian
c.PR_ENDIAN = strflag {
  BIG         = 0,
  LITTLE      = 1,
  PPC_LITTLE  = 2,
}

-- PR TSC
c.PR_TSC = strflag {
  ENABLE         = 1,
  SIGSEGV        = 2,
}

-- somewhat confusing as there are some in PR too.
c.PR_MCE_KILL = strflag {
  CLEAR     = 0,
  SET       = 1,
}

-- note rename, this is extra option see prctl code
c.PR_MCE_KILL_OPT = strflag {
  LATE         = 0,
  EARLY        = 1,
  DEFAULT      = 2,
}

c.LINUX_CAPABILITY_VERSION = {0x19980330, 0x20071026, 0x20080522}
c.LINUX_CAPABILITY_U32S = {1, 2, 2}

-- capabilities NB these are bit shifts
c.CAP = strflag {
  CHOWN = 0,
  DAC_OVERRIDE = 1,
  DAC_READ_SEARCH = 2,
  FOWNER = 3,
  FSETID = 4,
  KILL = 5,
  SETGID = 6,
  SETUID = 7,
  SETPCAP = 8,
  LINUX_IMMUTABLE = 9,
  NET_BIND_SERVICE = 10,
  NET_BROADCAST = 11,
  NET_ADMIN = 12,
  NET_RAW = 13,
  IPC_LOCK = 14,
  IPC_OWNER = 15,
  SYS_MODULE = 16,
  SYS_RAWIO = 17,
  SYS_CHROOT = 18,
  SYS_PTRACE = 19,
  SYS_PACCT = 20,
  SYS_ADMIN = 21,
  SYS_BOOT = 22,
  SYS_NICE = 23,
  SYS_RESOURCE = 24,
  SYS_TIME = 25,
  SYS_TTY_CONFIG = 26,
  MKNOD = 27,
  LEASE = 28,
  AUDIT_WRITE = 29,
  AUDIT_CONTROL = 30,
  SETFCAP = 31,
  MAC_OVERRIDE = 32,
  MAC_ADMIN = 33,
  SYSLOG = 34,
  WAKE_ALARM = 35,
}

-- capabilities as stored on file system in xattr
c.VFS_CAP = strflag {
  REVISION_MASK   = 0xFF000000,
  REVISION_SHIFT  = 24,
  REVISION_1      = 0x01000000,
  U32_1           = 1,
  REVISION_2      = 0x02000000,
  U32_2           = 2,
}

c.VFS_CAP.FLAGS_MASK = bit.bnot(c.VFS_CAP.REVISION_MASK)
c.VFS_CAP.U32      = c.VFS_CAP.U32_2
c.VFS_CAP.REVISION = c.VFS_CAP.REVISION_2

c.VFS_CAP_FLAGS = strflag {
  EFFECTIVE = 0x000001,
}

c.XATTR_CAPS = strflag {
  SZ_1 = 4 * (1 + 2 * c.VFS_CAP.U32_1),
  SZ_2 = 4 * (1 + 2 * c.VFS_CAP.U32_2),
}

c.XATTR_CAPS.SZ = c.XATTR_CAPS.SZ_2

-- new SECCOMP modes, now there is filter as well as strict
c.SECCOMP_MODE = strflag {
  DISABLED = 0,
  STRICT   = 1,
  FILTER   = 2,
}

c.SECCOMP_RET = multiflags {
  KILL      = 0x00000000,
  TRAP      = 0x00030000,
  ERRNO     = 0x00050000,
  TRACE     = 0x7ff00000,
  ALLOW     = 0x7fff0000,

  ACTION    = 0x7fff0000, -- mask
  DATA      = 0x0000ffff, -- mask
}

-- Elf machine flags
c.EM = strflag {
  NONE        = 0,
  M32         = 1,
  SPARC       = 2,
  ["386"]     = 3,
  ["68K"]     = 4,
  ["88K"]     = 5,
  ["860"]     = 7,
  MIPS        = 8,
  MIPS_RS3_LE = 10,
  MIPS_RS4_BE = 10,
  PARISC      = 15,
  SPARC32PLUS = 18,
  PPC         = 20,
  PPC64       = 21,
  S390        = 22,
  SPU         = 23,
  ARM         = 40,
  SH          = 42,
  SPARCV9     = 43,
  H8_300      = 46,
  IA_64       = 50,
  X86_64      = 62,
  CRIS        = 76,
  V850        = 87,
  M32R        = 88,
  MN10300     = 89,
  BLACKFIN    = 106,
  TI_C6000    = 140,
  AARCH64     = 183,
  FRV         = 0x5441,
  AVR32       = 0x18ad,
  ALPHA       = 0x9026,
  CYGNUS_V850 = 0x9080,
  CYGNUS_M32R = 0x9041,
  S390_OLD    = 0xA390,
  CYGNUS_MN10300 = 0xbeef,
}

-- audit flags (lots missing from linux/audit.h)

-- I don't think we need to export these
local __AUDIT_ARCH_64BIT = 0x80000000
local __AUDIT_ARCH_LE    = 0x40000000

c.AUDIT_ARCH = strflag {
  AARCH64 = c.EM.AARCH64 + __AUDIT_ARCH_64BIT + __AUDIT_ARCH_LE,
  ALPHA = c.EM.ALPHA + __AUDIT_ARCH_64BIT + __AUDIT_ARCH_LE,
  ARM = c.EM.ARM + __AUDIT_ARCH_LE,
  ARMEB = c.EM.ARM,
  CRIS = c.EM.CRIS + __AUDIT_ARCH_LE,
  FRV = c.EM.FRV,
  H8300 = c.EM.H8_300,
  I386 = c.EM["386"] + __AUDIT_ARCH_LE,
  IA64 = c.EM.IA_64 + __AUDIT_ARCH_64BIT + __AUDIT_ARCH_LE,
  M32R = c.EM.M32R,
  M68K = c.EM["68K"],
  MIPS = c.EM.MIPS,
  MIPSEL = c.EM.MIPS + __AUDIT_ARCH_LE,
  MIPS64 = c.EM.MIPS + __AUDIT_ARCH_64BIT,
  MIPSEL64 = c.EM.MIPS + __AUDIT_ARCH_64BIT + __AUDIT_ARCH_LE,
  PARISC = c.EM.PARISC,
  PARISC64 = c.EM.PARISC + __AUDIT_ARCH_64BIT,
  PPC = c.EM.PPC,
  PPC64 = c.EM.PPC64 + __AUDIT_ARCH_64BIT,
  S390 = c.EM.S390,
  S390X = c.EM.S390 + __AUDIT_ARCH_64BIT,
  SH = c.EM.SH,
  SHEL = c.EM.SH + __AUDIT_ARCH_LE,
  SH64 = c.EM.SH + __AUDIT_ARCH_64BIT,
  SHEL64 =c.EM.SH + __AUDIT_ARCH_64BIT + __AUDIT_ARCH_LE,
  SPARC =c.EM.SPARC,
  SPARC64 =c.EM.SPARCV9 + __AUDIT_ARCH_64BIT,
  X86_64 = c.EM.X86_64 + __AUDIT_ARCH_64BIT + __AUDIT_ARCH_LE,
}

-- BPF socket filter
c.BPF = multiflags {
-- class
  LD         = 0x00,
  LDX        = 0x01,
  ST         = 0x02,
  STX        = 0x03,
  ALU        = 0x04,
  ALU64      = 0x07,
  JMP        = 0x05,
  RET        = 0x06,
  MISC       = 0x07,
-- size
  W          = 0x00,
  H          = 0x08,
  B          = 0x10,
  DW         = 0x18,
-- mode
  IMM        = 0x00,
  ABS        = 0x20,
  IND        = 0x40,
  MEM        = 0x60,
  LEN        = 0x80,
  MSH        = 0xa0,
-- op
  ADD        = 0x00,
  SUB        = 0x10,
  MUL        = 0x20,
  DIV        = 0x30,
  OR         = 0x40,
  AND        = 0x50,
  LSH        = 0x60,
  RSH        = 0x70,
  ARSH       = 0xc0,
  NEG        = 0x80,
  MOD        = 0x90,
  XOR        = 0xa0,
  MOV        = 0xb0,
  XADD       = 0xc0,
  END        = 0xd0,
  JA         = 0x00,
  JEQ        = 0x10,
  JGT        = 0x20,
  JGE        = 0x30,
  JSET       = 0x40,
  JNE        = 0x50,
  JSGT       = 0x60,
  JSGE       = 0x70,
  CALL       = 0x80,
  EXIT       = 0x90,
-- src
  K          = 0x00,
  X          = 0x08,
-- rval
  A          = 0x10,
-- miscop
  TAX        = 0x00,
  TXA        = 0x80,
  TO_LE      = 0x00,
  TO_BE      = 0x08,
-- flags
  ANY        = 0,
  NOEXIST    = 1,
  EXIST      = 2,
}

-- BPF map type
c.BPF_MAP = strflag {
  UNSPEC           = 0,
  HASH             = 1,
  ARRAY            = 2,
  PROG_ARRAY       = 3,
  PERF_EVENT_ARRAY = 4,
  PERCPU_HASH      = 5,
  PERCPU_ARRAY     = 6,
  STACK_TRACE      = 7,
  CGROUP_ARRAY     = 8,
}

-- BPF syscall commands
c.BPF_CMD = strflag {
  MAP_CREATE       = 0,
  MAP_LOOKUP_ELEM  = 1,
  MAP_UPDATE_ELEM  = 2,
  MAP_DELETE_ELEM  = 3,
  MAP_GET_NEXT_KEY = 4,
  PROG_LOAD        = 5,
  OBJ_PIN          = 6,
  OBJ_GET          = 7,
}

-- BPF program types
c.BPF_PROG = strflag {
  UNSPEC        = 0,
  SOCKET_FILTER = 1,
  KPROBE        = 2,
  SCHED_CLS     = 3,
  SCHED_ACT     = 4,
  TRACEPOINT    = 5,
  XDP           = 6,
}

-- Linux performance monitoring
-- perf_event_attr.type
c.PERF_TYPE = strflag {
  HARDWARE   = 0,
  SOFTWARE   = 1,
  TRACEPOINT = 2,
  HW_CACHE   = 3,
  RAW        = 4,
  BREAKPOINT = 5,
}

-- perf_event_attr.event_id
c.PERF_COUNT = strflag {
  -- Generalized performance event event_id types
  HW_CPU_CYCLES                = 0,
  HW_INSTRUCTIONS              = 1,
  HW_CACHE_REFERENCES          = 2,
  HW_CACHE_MISSES              = 3,
  HW_BRANCH_INSTRUCTIONS       = 4,
  HW_BRANCH_MISSES             = 5,
  HW_BUS_CYCLES                = 6,
  HW_STALLED_CYCLES_FRONTEND   = 7,
  HW_STALLED_CYCLES_BACKEND    = 8,
  HW_REF_CPU_CYCLES            = 9,
  -- Generalized hardware cache events
  HW_CACHE_L1D                 = 0,
  HW_CACHE_L1I                 = 1,
  HW_CACHE_LL                  = 2,
  HW_CACHE_DTLB                = 3,
  HW_CACHE_ITLB                = 4,
  HW_CACHE_BPU                 = 5,
  HW_CACHE_NODE                = 6,
  HW_CACHE_OP_READ             = 0,
  HW_CACHE_OP_WRITE            = 1,
  HW_CACHE_OP_PREFETCH         = 2,
  HW_CACHE_RESULT_ACCESS       = 0,
  HW_CACHE_RESULT_MISS         = 1,
  -- Special "software" events provided by the kernel
  SW_CPU_CLOCK                 = 0,
  SW_TASK_CLOCK                = 1,
  SW_PAGE_FAULTS               = 2,
  SW_CONTEXT_SWITCHES          = 3,
  SW_CPU_MIGRATIONS            = 4,
  SW_PAGE_FAULTS_MIN           = 5,
  SW_PAGE_FAULTS_MAJ           = 6,
  SW_ALIGNMENT_FAULTS          = 7,
  SW_EMULATION_FAULTS          = 8,
  SW_DUMMY                     = 9,
  SW_BPF_OUTPUT                = 10,
}

-- Bits that can be set in perf_event_attr.sample_type to request information
c.PERF_SAMPLE = multiflags {
  IP                          = bit.lshift(1, 0),
  TID                         = bit.lshift(1, 1),
  TIME                        = bit.lshift(1, 2),
  ADDR                        = bit.lshift(1, 3),
  READ                        = bit.lshift(1, 4),
  CALLCHAIN                   = bit.lshift(1, 5),
  ID                          = bit.lshift(1, 6),
  CPU                         = bit.lshift(1, 7),
  PERIOD                      = bit.lshift(1, 8),
  STREAM_ID                   = bit.lshift(1, 9),
  RAW                         = bit.lshift(1, 10),
  BRANCH_STACK                = bit.lshift(1, 11),
  REGS_USER                   = bit.lshift(1, 12),
  STACK_USER                  = bit.lshift(1, 13),
  WEIGHT                      = bit.lshift(1, 14),
  DATA_SRC                    = bit.lshift(1, 15),
  IDENTIFIER                  = bit.lshift(1, 16),
  TRANSACTION                 = bit.lshift(1, 17),
  REGS_INTR                   = bit.lshift(1, 18),
}

-- values to program into perf_event_attr.branch_sample_type when PERF_SAMPLE_BRANCH is set
c.PERF_SAMPLE_BRANCH = multiflags {
  USER_SHIFT           = 0,
  KERNEL_SHIFT         = 1,
  HV_SHIFT             = 2,
  ANY_SHIFT            = 3,
  ANY_CALL_SHIFT       = 4,
  ANY_RETURN_SHIFT     = 5,
  IND_CALL_SHIFT       = 6,
  ABORT_TX_SHIFT       = 7,
  IN_TX_SHIFT          = 8,
  NO_TX_SHIFT          = 9,
  COND_SHIFT           = 10,
  CALL_STACK_SHIFT     = 11,
  IND_JUMP_SHIFT       = 12,
  CALL_SHIFT           = 13,
  NO_FLAGS_SHIFT       = 14,
  NO_CYCLES_SHIFT      = 15,
}
c.PERF_SAMPLE_BRANCH.USER          = bit.lshift(1, c.PERF_SAMPLE_BRANCH.USER_SHIFT)
c.PERF_SAMPLE_BRANCH.KERNEL        = bit.lshift(1, c.PERF_SAMPLE_BRANCH.KERNEL_SHIFT)
c.PERF_SAMPLE_BRANCH.HV            = bit.lshift(1, c.PERF_SAMPLE_BRANCH.HV_SHIFT)
c.PERF_SAMPLE_BRANCH.ANY           = bit.lshift(1, c.PERF_SAMPLE_BRANCH.ANY_SHIFT)
c.PERF_SAMPLE_BRANCH.ANY_CALL      = bit.lshift(1, c.PERF_SAMPLE_BRANCH.ANY_CALL_SHIFT)
c.PERF_SAMPLE_BRANCH.ANY_RETURN    = bit.lshift(1, c.PERF_SAMPLE_BRANCH.ANY_RETURN_SHIFT)
c.PERF_SAMPLE_BRANCH.IND_CALL      = bit.lshift(1, c.PERF_SAMPLE_BRANCH.IND_CALL_SHIFT)
c.PERF_SAMPLE_BRANCH.ABORT_TX      = bit.lshift(1, c.PERF_SAMPLE_BRANCH.ABORT_TX_SHIFT)
c.PERF_SAMPLE_BRANCH.IN_TX         = bit.lshift(1, c.PERF_SAMPLE_BRANCH.IN_TX_SHIFT)
c.PERF_SAMPLE_BRANCH.NO_TX         = bit.lshift(1, c.PERF_SAMPLE_BRANCH.NO_TX_SHIFT)
c.PERF_SAMPLE_BRANCH.COND          = bit.lshift(1, c.PERF_SAMPLE_BRANCH.COND_SHIFT)
c.PERF_SAMPLE_BRANCH.CALL_STACK    = bit.lshift(1, c.PERF_SAMPLE_BRANCH.CALL_STACK_SHIFT)
c.PERF_SAMPLE_BRANCH.IND_JUMP      = bit.lshift(1, c.PERF_SAMPLE_BRANCH.IND_JUMP_SHIFT)
c.PERF_SAMPLE_BRANCH.CALL          = bit.lshift(1, c.PERF_SAMPLE_BRANCH.CALL_SHIFT)
c.PERF_SAMPLE_BRANCH.NO_FLAGS      = bit.lshift(1, c.PERF_SAMPLE_BRANCH.NO_FLAGS_SHIFT)
c.PERF_SAMPLE_BRANCH.NO_CYCLES     = bit.lshift(1, c.PERF_SAMPLE_BRANCH.NO_CYCLES_SHIFT)

-- Flags for perf_attr.read_format
c.PERF_READ_FORMAT = multiflags {
  TOTAL_TIME_ENABLED = bit.lshift(1, 0),
  TOTAL_TIME_RUNNING = bit.lshift(1, 1),
  ID                 = bit.lshift(1, 2),
  GROUP              = bit.lshift(1, 3),
}

-- Flags for perf_event_open
c.PERF_FLAG = multiflags {
  FD_NO_GROUP    = bit.lshift(1, 0),
  FD_OUTPUT      = bit.lshift(1, 1),
  PID_CGROUP     = bit.lshift(1, 2),
  FD_CLOEXEC     = bit.lshift(1, 3),
}


-- If perf_event_attr.sample_id_all is set then all event types will
-- have the sample_type selected fields related to where/when
-- (identity) an event took place (TID, TIME, ID, STREAM_ID, CPU, IDENTIFIER)
c.PERF_RECORD = strflag {
  MMAP           = 1,
  LOST           = 2,
  COMM           = 3,
  EXIT           = 4,
  THROTTLE       = 5,
  UNTHROTTLE     = 6,
  FORK           = 7,
  READ           = 8,
  SAMPLE         = 9,
  MMAP2          = 10,
  AUX            = 11,
  ITRACE_START   = 12,
  LOST_SAMPLES   = 13,
  SWITCH         = 14,
  SWITCH_CPU_WIDE= 15,
}

-- termios - c_cc characters
c.CC = strflag(arch.CC or {
  VINTR    = 0,
  VQUIT    = 1,
  VERASE   = 2,
  VKILL    = 3,
  VEOF     = 4,
  VTIME    = 5,
  VMIN     = 6,
  VSWTC    = 7,
  VSTART   = 8,
  VSTOP    = 9,
  VSUSP    = 10,
  VEOL     = 11,
  VREPRINT = 12,
  VDISCARD = 13,
  VWERASE  = 14,
  VLNEXT   = 15,
  VEOL2    = 16,
})

-- termios - c_iflag bits
c.IFLAG = multiflags(arch.IFLAG or {
  IGNBRK  = octal('0000001'),
  BRKINT  = octal('0000002'),
  IGNPAR  = octal('0000004'),
  PARMRK  = octal('0000010'),
  INPCK   = octal('0000020'),
  ISTRIP  = octal('0000040'),
  INLCR   = octal('0000100'),
  IGNCR   = octal('0000200'),
  ICRNL   = octal('0000400'),
  IUCLC   = octal('0001000'),
  IXON    = octal('0002000'),
  IXANY   = octal('0004000'),
  IXOFF   = octal('0010000'),
  IMAXBEL = octal('0020000'),
  IUTF8   = octal('0040000'),
})

-- termios - c_oflag bits
c.OFLAG = multiflags(arch.OFLAG or {
  OPOST  = octal('0000001'),
  OLCUC  = octal('0000002'),
  ONLCR  = octal('0000004'),
  OCRNL  = octal('0000010'),
  ONOCR  = octal('0000020'),
  ONLRET = octal('0000040'),
  OFILL  = octal('0000100'),
  OFDEL  = octal('0000200'),
  NLDLY  = octal('0000400'),
  NL0    = octal('0000000'),
  NL1    = octal('0000400'),
  CRDLY  = octal('0003000'),
  CR0    = octal('0000000'),
  CR1    = octal('0001000'),
  CR2    = octal('0002000'),
  CR3    = octal('0003000'),
  TABDLY = octal('0014000'),
  TAB0   = octal('0000000'),
  TAB1   = octal('0004000'),
  TAB2   = octal('0010000'),
  TAB3   = octal('0014000'),
  BSDLY  = octal('0020000'),
  BS0    = octal('0000000'),
  BS1    = octal('0020000'),
  FFDLY  = octal('0100000'),
  FF0    = octal('0000000'),
  FF1    = octal('0100000'),
  VTDLY  = octal('0040000'),
  VT0    = octal('0000000'),
  VT1    = octal('0040000'),
  XTABS  = octal('0014000'),
})

-- using string keys as sparse array uses a lot of memory
c.B = setmetatable(arch.B or {
  ['0'] = octal('0000000'),
  ['50'] = octal('0000001'),
  ['75'] = octal('0000002'),
  ['110'] = octal('0000003'),
  ['134'] = octal('0000004'),
  ['150'] = octal('0000005'),
  ['200'] = octal('0000006'),
  ['300'] = octal('0000007'),
  ['600'] = octal('0000010'),
  ['1200'] = octal('0000011'),
  ['1800'] = octal('0000012'),
  ['2400'] = octal('0000013'),
  ['4800'] = octal('0000014'),
  ['9600'] = octal('0000015'),
  ['19200'] = octal('0000016'),
  ['38400'] = octal('0000017'),
  ['57600'] = octal('0010001'),
  ['115200'] = octal('0010002'),
  ['230400'] = octal('0010003'),
  ['460800'] = octal('0010004'),
  ['500000'] = octal('0010005'),
  ['576000'] = octal('0010006'),
  ['921600'] = octal('0010007'),
  ['1000000'] = octal('0010010'),
  ['1152000'] = octal('0010011'),
  ['1500000'] = octal('0010012'),
  ['2000000'] = octal('0010013'),
  ['2500000'] = octal('0010014'),
  ['3000000'] = octal('0010015'),
  ['3500000'] = octal('0010016'),
  ['4000000'] = octal('0010017'),
}, {
  __index = function(b, k)
    return b[tostring(k)]
  end,
})

--[[
c.__MAX_BAUD = c.B4000000
c.EXTA       = c.B19200
c.EXTB       = c.B38400
]]

-- TODO clean up how to handle these (used for custom speeds)
c.CBAUD      = arch.CBAUD or octal('0010017')
c.CBAUDEX    = arch.CBAUDEX or octal('0010000')
c.CIBAUD     = arch.CIBAUD or octal('002003600000') -- input baud rate (not used)

c.CMSPAR     = octal('010000000000') -- mark or space (stick) parity
c.CRTSCTS    = octal('020000000000') -- flow control

-- termios - c_cflag bits
c.CFLAG = multiflags(arch.CFLAG or {
  CSIZE      = octal('0000060'),
  CS5        = octal('0000000'),
  CS6        = octal('0000020'),
  CS7        = octal('0000040'),
  CS8        = octal('0000060'),
  CSTOPB     = octal('0000100'),
  CREAD      = octal('0000200'),
  PARENB     = octal('0000400'),
  PARODD     = octal('0001000'),
  HUPCL      = octal('0002000'),
  CLOCAL     = octal('0004000'),
})

-- termios - c_lflag bits
c.LFLAG = multiflags(arch.LFLAG or {
  ISIG    = octal('0000001'),
  ICANON  = octal('0000002'),
  XCASE   = octal('0000004'),
  ECHO    = octal('0000010'),
  ECHOE   = octal('0000020'),
  ECHOK   = octal('0000040'),
  ECHONL  = octal('0000100'),
  NOFLSH  = octal('0000200'),
  TOSTOP  = octal('0000400'),
  ECHOCTL = octal('0001000'),
  ECHOPRT = octal('0002000'),
  ECHOKE  = octal('0004000'),
  FLUSHO  = octal('0010000'),
  PENDIN  = octal('0040000'),
  IEXTEN  = octal('0100000'),
  EXTPROC = octal('0200000'),
})

-- termios - tcflow() and TCXONC use these. renamed from TC to TCFLOW
c.TCFLOW = strflag {
  OOFF = 0,
  OON  = 1,
  IOFF = 2,
  ION  = 3,
}

-- termios - tcflush() and TCFLSH use these. renamed from TC to TCFLUSH
c.TCFLUSH = strflag {
  IFLUSH  = 0,
  OFLUSH  = 1,
  IOFLUSH = 2,
}

-- termios - tcsetattr uses these
c.TCSA = strflag {
  NOW   = 0,
  DRAIN = 1,
  FLUSH = 2,
}

-- TIOCM
c.TIOCM = multiflags(arch.TIOCM or {
  LE  = 0x001,
  DTR = 0x002,
  RTS = 0x004,
  ST  = 0x008,
  SR  = 0x010,
  CTS = 0x020,
  CAR = 0x040,
  RNG = 0x080,
  DSR = 0x100,
})

c.TIOCM.CD  = c.TIOCM.CAR
c.TIOCM.RI  = c.TIOCM.RNG

-- sysfs values
c.SYSFS_BRIDGE_ATTR        = "bridge"
c.SYSFS_BRIDGE_FDB         = "brforward"
c.SYSFS_BRIDGE_PORT_SUBDIR = "brif"
c.SYSFS_BRIDGE_PORT_ATTR   = "brport"
c.SYSFS_BRIDGE_PORT_LINK   = "bridge"

-- sizes -- TODO in tables?
c.HOST_NAME_MAX = 64
c.IFNAMSIZ      = 16
c.IFHWADDRLEN   = 6

-- input subsystem. TODO split into another file as a lot of them
c.INPUT_PROP = strflag {
  POINTER              = 0x00,
  DIRECT               = 0x01,
  BUTTONPAD            = 0x02,
  SEMI_MT              = 0x03,
}

c.EV = strflag {
  SYN                  = 0x00,
  KEY                  = 0x01,
  REL                  = 0x02,
  ABS                  = 0x03,
  MSC                  = 0x04,
  SW                   = 0x05,
  LED                  = 0x11,
  SND                  = 0x12,
  REP                  = 0x14,
  FF                   = 0x15,
  PWR                  = 0x16,
  FF_STATUS    	       = 0x17,
  MAX                  = 0x1f,
}

c.SYN = strflag {
  REPORT              = 0,
  CONFIG              = 1,
  MT_REPORT   	      = 2,
  DROPPED             = 3,
}

-- TODO odd namespacing issue with KEY and BTN, not sure best resolution, maybe have KEYBTN table with both
c.KEY = strflag {
  RESERVED            = 0,
  ESC                 = 1,
  ["1"]               = 2,
  ["2"]               = 3,
  ["3"]               = 4,
  ["4"]               = 5,
  ["5"]               = 6,
  ["6"]               = 7,
  ["7"]               = 8,
  ["8"]               = 9,
  ["9"]               = 10,
  ["0"]               = 11,
  MINUS               = 12,
  EQUAL               = 13,
  BACKSPACE           = 14,
  TAB                 = 15,
  Q                   = 16,
  W                   = 17,
  E                   = 18,
  R                   = 19,
  T                   = 20,
  Y                   = 21,
  U                   = 22,
  I                   = 23,
  O                   = 24,
  P                   = 25,
  LEFTBRACE           = 26,
  RIGHTBRACE          = 27,
  ENTER               = 28,
  LEFTCTRL            = 29,
  A                   = 30,
  S                   = 31,
  D                   = 32,
  F                   = 33,
  G                   = 34,
  H                   = 35,
  J                   = 36,
  K                   = 37,
  L                   = 38,
  SEMICOLON           = 39,
  APOSTROPHE          = 40,
  GRAVE               = 41,
  LEFTSHIFT           = 42,
  BACKSLASH           = 43,
  Z                   = 44,
  X                   = 45,
  C                   = 46,
  V                   = 47,
  B                   = 48,
  N                   = 49,
  M                   = 50,
  COMMA               = 51,
  DOT                 = 52,
  SLASH               = 53,
  RIGHTSHIFT          = 54,
  KPASTERISK          = 55,
  LEFTALT             = 56,
  SPACE               = 57,
  CAPSLOCK            = 58,
  F1                  = 59,
  F2                  = 60,
  F3                  = 61,
  F4                  = 62,
  F5                  = 63,
  F6                  = 64,
  F7                  = 65,
  F8                  = 66,
  F9                  = 67,
  F10                 = 68,
  NUMLOCK             = 69,
  SCROLLLOCK          = 70,
  KP7                 = 71,
  KP8                 = 72,
  KP9                 = 73,
  KPMINUS             = 74,
  KP4                 = 75,
  KP5                 = 76,
  KP6                 = 77,
  KPPLUS              = 78,
  KP1                 = 79,
  KP2                 = 80,
  KP3                 = 81,
  KP0                 = 82,
  KPDOT               = 83,
  ZENKAKUHANKAKU      = 85,
  ["102ND"]           = 86,
  F11                 = 87,
  F12                 = 88,
  RO                  = 89,
  KATAKANA            = 90,
  HIRAGANA            = 91,
  HENKAN              = 92,
  KATAKANAHIRAGANA    = 93,
  MUHENKAN            = 94,
  KPJPCOMMA           = 95,
  KPENTER             = 96,
  RIGHTCTRL           = 97,
  KPSLASH             = 98,
  SYSRQ               = 99,
  RIGHTALT            = 100,
  LINEFEED            = 101,
  HOME                = 102,
  UP                  = 103,
  PAGEUP              = 104,
  LEFT                = 105,
  RIGHT               = 106,
  END                 = 107,
  DOWN                = 108,
  PAGEDOWN            = 109,
  INSERT              = 110,
  DELETE              = 111,
  MACRO               = 112,
  MUTE                = 113,
  VOLUMEDOWN          = 114,
  VOLUMEUP            = 115,
  POWER               = 116,
  KPEQUAL             = 117,
  KPPLUSMINUS         = 118,
  PAUSE               = 119,
  SCALE               = 120,
  KPCOMMA             = 121,
  HANGEUL             = 122,
  HANJA               = 123,
  YEN                 = 124,
  LEFTMETA            = 125,
  RIGHTMETA           = 126,
  COMPOSE             = 127,
  STOP                = 128,
  AGAIN               = 129,
  PROPS               = 130,
  UNDO                = 131,
  FRONT               = 132,
  COPY                = 133,
  OPEN                = 134,
  PASTE               = 135,
  FIND                = 136,
  CUT                 = 137,
  HELP                = 138,
  MENU                = 139,
  CALC                = 140,
  SETUP               = 141,
  SLEEP               = 142,
  WAKEUP              = 143,
  FILE                = 144,
  SENDFILE            = 145,
  DELETEFILE          = 146,
  XFER                = 147,
  PROG1               = 148,
  PROG2               = 149,
  WWW                 = 150,
  MSDOS               = 151,
  COFFEE              = 152,
  DIRECTION           = 153,
  CYCLEWINDOWS        = 154,
  MAIL                = 155,
  BOOKMARKS           = 156,
  COMPUTER            = 157,
  BACK                = 158,
  FORWARD             = 159,
  CLOSECD             = 160,
  EJECTCD             = 161,
  EJECTCLOSECD        = 162,
  NEXTSONG            = 163,
  PLAYPAUSE           = 164,
  PREVIOUSSONG        = 165,
  STOPCD              = 166,
  RECORD              = 167,
  REWIND              = 168,
  PHONE               = 169,
  ISO                 = 170,
  CONFIG              = 171,
  HOMEPAGE            = 172,
  REFRESH             = 173,
  EXIT                = 174,
  MOVE                = 175,
  EDIT                = 176,
  SCROLLUP            = 177,
  SCROLLDOWN          = 178,
  KPLEFTPAREN         = 179,
  KPRIGHTPAREN        = 180,
  NEW                 = 181,
  REDO                = 182,
  F13                 = 183,
  F14                 = 184,
  F15                 = 185,
  F16                 = 186,
  F17                 = 187,
  F18                 = 188,
  F19                 = 189,
  F20                 = 190,
  F21                 = 191,
  F22                 = 192,
  F23                 = 193,
  F24                 = 194,
  PLAYCD              = 200,
  PAUSECD             = 201,
  PROG3               = 202,
  PROG4               = 203,
  DASHBOARD           = 204,
  SUSPEND             = 205,
  CLOSE               = 206,
  PLAY                = 207,
  FASTFORWARD         = 208,
  BASSBOOST           = 209,
  PRINT               = 210,
  HP                  = 211,
  CAMERA              = 212,
  SOUND               = 213,
  QUESTION            = 214,
  EMAIL               = 215,
  CHAT                = 216,
  SEARCH              = 217,
  CONNECT             = 218,
  FINANCE             = 219,
  SPORT               = 220,
  SHOP                = 221,
  ALTERASE            = 222,
  CANCEL              = 223,
  BRIGHTNESSDOWN      = 224,
  BRIGHTNESSUP        = 225,
  MEDIA               = 226,
  SWITCHVIDEOMODE     = 227,
  KBDILLUMTOGGLE      = 228,
  KBDILLUMDOWN        = 229,
  KBDILLUMUP          = 230,
  SEND                = 231,
  REPLY               = 232,
  FORWARDMAIL         = 233,
  SAVE                = 234,
  DOCUMENTS           = 235,
  BATTERY             = 236,
  BLUETOOTH           = 237,
  WLAN                = 238,
  UWB                 = 239,
  UNKNOWN             = 240,
  VIDEO_NEXT          = 241,
  VIDEO_PREV          = 242,
  BRIGHTNESS_CYCLE    = 243,
  BRIGHTNESS_ZERO     = 244,
  DISPLAY_OFF         = 245,
  WIMAX               = 246,
  RFKILL              = 247,
  MICMUTE             = 248,
-- BTN values go in here
  OK                  = 0x160,
  SELECT              = 0x161,
  GOTO                = 0x162,
  CLEAR               = 0x163,
  POWER2              = 0x164,
  OPTION              = 0x165,
  INFO                = 0x166,
  TIME                = 0x167,
  VENDOR              = 0x168,
  ARCHIVE             = 0x169,
  PROGRAM             = 0x16a,
  CHANNEL             = 0x16b,
  FAVORITES           = 0x16c,
  EPG                 = 0x16d,
  PVR                 = 0x16e,
  MHP                 = 0x16f,
  LANGUAGE            = 0x170,
  TITLE               = 0x171,
  SUBTITLE            = 0x172,
  ANGLE               = 0x173,
  ZOOM                = 0x174,
  MODE                = 0x175,
  KEYBOARD            = 0x176,
  SCREEN              = 0x177,
  PC                  = 0x178,
  TV                  = 0x179,
  TV2                 = 0x17a,
  VCR                 = 0x17b,
  VCR2                = 0x17c,
  SAT                 = 0x17d,
  SAT2                = 0x17e,
  CD                  = 0x17f,
  TAPE                = 0x180,
  RADIO               = 0x181,
  TUNER               = 0x182,
  PLAYER              = 0x183,
  TEXT                = 0x184,
  DVD                 = 0x185,
  AUX                 = 0x186,
  MP3                 = 0x187,
  AUDIO               = 0x188,
  VIDEO               = 0x189,
  DIRECTORY           = 0x18a,
  LIST                = 0x18b,
  MEMO                = 0x18c,
  CALENDAR            = 0x18d,
  RED                 = 0x18e,
  GREEN               = 0x18f,
  YELLOW              = 0x190,
  BLUE                = 0x191,
  CHANNELUP           = 0x192,
  CHANNELDOWN         = 0x193,
  FIRST               = 0x194,
  LAST                = 0x195,
  AB                  = 0x196,
  NEXT                = 0x197,
  RESTART             = 0x198,
  SLOW                = 0x199,
  SHUFFLE             = 0x19a,
  BREAK               = 0x19b,
  PREVIOUS            = 0x19c,
  DIGITS              = 0x19d,
  TEEN                = 0x19e,
  TWEN                = 0x19f,
  VIDEOPHONE          = 0x1a0,
  GAMES               = 0x1a1,
  ZOOMIN              = 0x1a2,
  ZOOMOUT             = 0x1a3,
  ZOOMRESET           = 0x1a4,
  WORDPROCESSOR       = 0x1a5,
  EDITOR              = 0x1a6,
  SPREADSHEET         = 0x1a7,
  GRAPHICSEDITOR      = 0x1a8,
  PRESENTATION        = 0x1a9,
  DATABASE            = 0x1aa,
  NEWS                = 0x1ab,
  VOICEMAIL           = 0x1ac,
  ADDRESSBOOK         = 0x1ad,
  MESSENGER           = 0x1ae,
  DISPLAYTOGGLE       = 0x1af,
  SPELLCHECK          = 0x1b0,
  LOGOFF              = 0x1b1,
  DOLLAR              = 0x1b2,
  EURO                = 0x1b3,
  FRAMEBACK           = 0x1b4,
  FRAMEFORWARD        = 0x1b5,
  CONTEXT_MENU        = 0x1b6,
  MEDIA_REPEAT        = 0x1b7,
  ["10CHANNELSUP"]    = 0x1b8,
  ["10CHANNELSDOWN"]  = 0x1b9,
  IMAGES              = 0x1ba,
  DEL_EOL             = 0x1c0,
  DEL_EOS             = 0x1c1,
  INS_LINE            = 0x1c2,
  DEL_LINE            = 0x1c3,
  FN                  = 0x1d0,
  FN_ESC              = 0x1d1,
  FN_F1               = 0x1d2,
  FN_F2               = 0x1d3,
  FN_F3               = 0x1d4,
  FN_F4               = 0x1d5,
  FN_F5               = 0x1d6,
  FN_F6               = 0x1d7,
  FN_F7               = 0x1d8,
  FN_F8               = 0x1d9,
  FN_F9               = 0x1da,
  FN_F10              = 0x1db,
  FN_F11              = 0x1dc,
  FN_F12              = 0x1dd,
  FN_1                = 0x1de,
  FN_2                = 0x1df,
  FN_D                = 0x1e0,
  FN_E                = 0x1e1,
  FN_F                = 0x1e2,
  FN_S                = 0x1e3,
  FN_B                = 0x1e4,
  BRL_DOT1            = 0x1f1,
  BRL_DOT2            = 0x1f2,
  BRL_DOT3            = 0x1f3,
  BRL_DOT4            = 0x1f4,
  BRL_DOT5            = 0x1f5,
  BRL_DOT6            = 0x1f6,
  BRL_DOT7            = 0x1f7,
  BRL_DOT8            = 0x1f8,
  BRL_DOT9            = 0x1f9,
  BRL_DOT10           = 0x1fa,
  NUMERIC_0           = 0x200,
  NUMERIC_1           = 0x201,
  NUMERIC_2           = 0x202,
  NUMERIC_3           = 0x203,
  NUMERIC_4           = 0x204,
  NUMERIC_5           = 0x205,
  NUMERIC_6           = 0x206,
  NUMERIC_7           = 0x207,
  NUMERIC_8           = 0x208,
  NUMERIC_9           = 0x209,
  NUMERIC_STAR        = 0x20a,
  NUMERIC_POUND       = 0x20b,
  CAMERA_FOCUS        = 0x210,
  WPS_BUTTON          = 0x211,
  TOUCHPAD_TOGGLE     = 0x212,
  TOUCHPAD_ON         = 0x213,
  TOUCHPAD_OFF        = 0x214,
  CAMERA_ZOOMIN       = 0x215,
  CAMERA_ZOOMOUT      = 0x216,
  CAMERA_UP           = 0x217,
  CAMERA_DOWN         = 0x218,
  CAMERA_LEFT         = 0x219,
  CAMERA_RIGHT        = 0x21a,
}

c.KEY.SCREENLOCK = c.KEY.COFFEE
c.KEY.HANGUEL    = c.KEY.HANGEUL

c.BTN = strflag {
  MISC                = 0x100,
  ["0"]               = 0x100,
  ["1"]               = 0x101,
  ["2"]               = 0x102,
  ["3"]               = 0x103,
  ["4"]               = 0x104,
  ["5"]               = 0x105,
  ["6"]               = 0x106,
  ["7"]               = 0x107,
  ["8"]               = 0x108,
  ["9"]               = 0x109,
  MOUSE               = 0x110,
  LEFT                = 0x110,
  RIGHT               = 0x111,
  MIDDLE              = 0x112,
  SIDE                = 0x113,
  EXTRA               = 0x114,
  FORWARD             = 0x115,
  BACK                = 0x116,
  TASK                = 0x117,
  JOYSTICK            = 0x120,
  TRIGGER             = 0x120,
  THUMB               = 0x121,
  THUMB2              = 0x122,
  TOP                 = 0x123,
  TOP2                = 0x124,
  PINKIE              = 0x125,
  BASE                = 0x126,
  BASE2               = 0x127,
  BASE3               = 0x128,
  BASE4               = 0x129,
  BASE5               = 0x12a,
  BASE6               = 0x12b,
  DEAD                = 0x12f,
  GAMEPAD             = 0x130,
  A                   = 0x130,
  B                   = 0x131,
  C                   = 0x132,
  X                   = 0x133,
  Y                   = 0x134,
  Z                   = 0x135,
  TL                  = 0x136,
  TR                  = 0x137,
  TL2                 = 0x138,
  TR2                 = 0x139,
  SELECT              = 0x13a,
  START               = 0x13b,
  MODE                = 0x13c,
  THUMBL              = 0x13d,
  THUMBR              = 0x13e,
  DIGI                = 0x140,
  TOOL_PEN            = 0x140,
  TOOL_RUBBER         = 0x141,
  TOOL_BRUSH          = 0x142,
  TOOL_PENCIL         = 0x143,
  TOOL_AIRBRUSH       = 0x144,
  TOOL_FINGER         = 0x145,
  TOOL_MOUSE          = 0x146,
  TOOL_LENS           = 0x147,
  TOOL_QUINTTAP       = 0x148,
  TOUCH               = 0x14a,
  STYLUS              = 0x14b,
  STYLUS2             = 0x14c,
  TOOL_DOUBLETAP      = 0x14d,
  TOOL_TRIPLETAP      = 0x14e,
  TOOL_QUADTAP        = 0x14f,
  WHEEL               = 0x150,
  GEAR_DOWN           = 0x150,
  GEAR_UP             = 0x151,

  TRIGGER_HAPPY               = 0x2c0,
  TRIGGER_HAPPY1              = 0x2c0,
  TRIGGER_HAPPY2              = 0x2c1,
  TRIGGER_HAPPY3              = 0x2c2,
  TRIGGER_HAPPY4              = 0x2c3,
  TRIGGER_HAPPY5              = 0x2c4,
  TRIGGER_HAPPY6              = 0x2c5,
  TRIGGER_HAPPY7              = 0x2c6,
  TRIGGER_HAPPY8              = 0x2c7,
  TRIGGER_HAPPY9              = 0x2c8,
  TRIGGER_HAPPY10             = 0x2c9,
  TRIGGER_HAPPY11             = 0x2ca,
  TRIGGER_HAPPY12             = 0x2cb,
  TRIGGER_HAPPY13             = 0x2cc,
  TRIGGER_HAPPY14             = 0x2cd,
  TRIGGER_HAPPY15             = 0x2ce,
  TRIGGER_HAPPY16             = 0x2cf,
  TRIGGER_HAPPY17             = 0x2d0,
  TRIGGER_HAPPY18             = 0x2d1,
  TRIGGER_HAPPY19             = 0x2d2,
  TRIGGER_HAPPY20             = 0x2d3,
  TRIGGER_HAPPY21             = 0x2d4,
  TRIGGER_HAPPY22             = 0x2d5,
  TRIGGER_HAPPY23             = 0x2d6,
  TRIGGER_HAPPY24             = 0x2d7,
  TRIGGER_HAPPY25             = 0x2d8,
  TRIGGER_HAPPY26             = 0x2d9,
  TRIGGER_HAPPY27             = 0x2da,
  TRIGGER_HAPPY28             = 0x2db,
  TRIGGER_HAPPY29             = 0x2dc,
  TRIGGER_HAPPY30             = 0x2dd,
  TRIGGER_HAPPY31             = 0x2de,
  TRIGGER_HAPPY32             = 0x2df,
  TRIGGER_HAPPY33             = 0x2e0,
  TRIGGER_HAPPY34             = 0x2e1,
  TRIGGER_HAPPY35             = 0x2e2,
  TRIGGER_HAPPY36             = 0x2e3,
  TRIGGER_HAPPY37             = 0x2e4,
  TRIGGER_HAPPY38             = 0x2e5,
  TRIGGER_HAPPY39             = 0x2e6,
  TRIGGER_HAPPY40             = 0x2e7,
}

c.REL = strflag {
  X                   = 0x00,
  Y                   = 0x01,
  Z                   = 0x02,
  RX                  = 0x03,
  RY                  = 0x04,
  RZ                  = 0x05,
  HWHEEL              = 0x06,
  DIAL                = 0x07,
  WHEEL               = 0x08,
  MISC                = 0x09,
  MAX                 = 0x0f,
}

c.ABS = strflag {
  X                   = 0x00,
  Y                   = 0x01,
  Z                   = 0x02,
  RX                  = 0x03,
  RY                  = 0x04,
  RZ                  = 0x05,
  THROTTLE            = 0x06,
  RUDDER              = 0x07,
  WHEEL               = 0x08,
  GAS                 = 0x09,
  BRAKE               = 0x0a,
  HAT0X               = 0x10,
  HAT0Y               = 0x11,
  HAT1X               = 0x12,
  HAT1Y               = 0x13,
  HAT2X               = 0x14,
  HAT2Y               = 0x15,
  HAT3X               = 0x16,
  HAT3Y               = 0x17,
  PRESSURE            = 0x18,
  DISTANCE            = 0x19,
  TILT_X              = 0x1a,
  TILT_Y              = 0x1b,
  TOOL_WIDTH          = 0x1c,
  VOLUME              = 0x20,
  MISC                = 0x28,
  MT_SLOT             = 0x2f,
  MT_TOUCH_MAJOR      = 0x30,
  MT_TOUCH_MINOR      = 0x31,
  MT_WIDTH_MAJOR      = 0x32,
  MT_WIDTH_MINOR      = 0x33,
  MT_ORIENTATION      = 0x34,
  MT_POSITION_X       = 0x35,
  MT_POSITION_Y       = 0x36,
  MT_TOOL_TYPE        = 0x37,
  MT_BLOB_ID          = 0x38,
  MT_TRACKING_ID      = 0x39,
  MT_PRESSURE         = 0x3a,
  MT_DISTANCE         = 0x3b,
  MAX                 = 0x3f,
}

c.MSC = strflag {
  SERIAL              = 0x00,
  PULSELED            = 0x01,
  GESTURE             = 0x02,
  RAW                 = 0x03,
  SCAN                = 0x04,
  MAX                 = 0x07,
}

c.LED = strflag {
  NUML                = 0x00,
  CAPSL               = 0x01,
  SCROLLL             = 0x02,
  COMPOSE             = 0x03,
  KANA                = 0x04,
  SLEEP               = 0x05,
  SUSPEND             = 0x06,
  MUTE                = 0x07,
  MISC                = 0x08,
  MAIL                = 0x09,
  CHARGING            = 0x0a,
  MAX                 = 0x0f,
}

c.REP = strflag {
  DELAY               = 0x00,
  PERIOD              = 0x01,
  MAX                 = 0x01,
}

c.SND = strflag {
  CLICK               = 0x00,
  BELL                = 0x01,
  TONE                = 0x02,
  MAX                 = 0x07,
}

c.ID = strflag {
  BUS                  = 0,
  VENDOR               = 1,
  PRODUCT              = 2,
  VERSION              = 3,
}

c.BUS = strflag {
  PCI                 = 0x01,
  ISAPNP              = 0x02,
  USB                 = 0x03,
  HIL                 = 0x04,
  BLUETOOTH           = 0x05,
  VIRTUAL             = 0x06,
  ISA                 = 0x10,
  I8042               = 0x11,
  XTKBD               = 0x12,
  RS232               = 0x13,
  GAMEPORT            = 0x14,
  PARPORT             = 0x15,
  AMIGA               = 0x16,
  ADB                 = 0x17,
  I2C                 = 0x18,
  HOST                = 0x19,
  GSC                 = 0x1A,
  ATARI               = 0x1B,
  SPI                 = 0x1C,
}

c.MT_TOOL = strflag {
  FINGER  = 0,
  PEN     = 1,
  MAX     = 1,
}

c.FF_STATUS = strflag {
  STOPPED       = 0x00,
  PLAYING       = 0x01,
  MAX           = 0x01,
}

-- TODO note these are split into different categories eg EFFECT, WAVEFORM unclear how best to handle (FF_STATUS too?)
c.FF = strflag {
-- EFFECT
  RUMBLE       = 0x50,
  PERIODIC     = 0x51,
  CONSTANT     = 0x52,
  SPRING       = 0x53,
  FRICTION     = 0x54,
  DAMPER       = 0x55,
  INERTIA      = 0x56,
  RAMP         = 0x57,
-- WAVEFORM
  SQUARE       = 0x58,
  TRIANGLE     = 0x59,
  SINE         = 0x5a,
  SAW_UP       = 0x5b,
  SAW_DOWN     = 0x5c,
  CUSTOM       = 0x5d,
-- dev props
  GAIN         = 0x60,
  AUTOCENTER   = 0x61,
}

-- errors
c.E = strflag(arch.E or {
  PERM          =  1,
  NOENT         =  2,
  SRCH          =  3,
  INTR          =  4,
  IO            =  5,
  NXIO          =  6,
  ["2BIG"]      =  7,
  NOEXEC        =  8,
  BADF          =  9,
  CHILD         = 10,
  AGAIN         = 11,
  NOMEM         = 12,
  ACCES         = 13,
  FAULT         = 14,
  NOTBLK        = 15,
  BUSY          = 16,
  EXIST         = 17,
  XDEV          = 18,
  NODEV         = 19,
  NOTDIR        = 20,
  ISDIR         = 21,
  INVAL         = 22,
  NFILE         = 23,
  MFILE         = 24,
  NOTTY         = 25,
  TXTBSY        = 26,
  FBIG          = 27,
  NOSPC         = 28,
  SPIPE         = 29,
  ROFS          = 30,
  MLINK         = 31,
  PIPE          = 32,
  DOM           = 33,
  RANGE         = 34,
  DEADLK        = 35,
  NAMETOOLONG   = 36,
  NOLCK         = 37,
  NOSYS         = 38,
  NOTEMPTY      = 39,
  LOOP          = 40,
  NOMSG         = 42,
  IDRM          = 43,
  CHRNG         = 44,
  L2NSYNC       = 45,
  L3HLT         = 46,
  L3RST         = 47,
  LNRNG         = 48,
  UNATCH        = 49,
  NOCSI         = 50,
  L2HLT         = 51,
  BADE          = 52,
  BADR          = 53,
  XFULL         = 54,
  NOANO         = 55,
  BADRQC        = 56,
  BADSLT        = 57,
  BFONT         = 59,
  NOSTR         = 60,
  NODATA        = 61,
  TIME          = 62,
  NOSR          = 63,
  NONET         = 64,
  NOPKG         = 65,
  REMOTE        = 66,
  NOLINK        = 67,
  ADV           = 68,
  SRMNT         = 69,
  COMM          = 70,
  PROTO         = 71,
  MULTIHOP      = 72,
  DOTDOT        = 73,
  BADMSG        = 74,
  OVERFLOW      = 75,
  NOTUNIQ       = 76,
  BADFD         = 77,
  REMCHG        = 78,
  LIBACC        = 79,
  LIBBAD        = 80,
  LIBSCN        = 81,
  LIBMAX        = 82,
  LIBEXEC       = 83,
  ILSEQ         = 84,
  RESTART       = 85,
  STRPIPE       = 86,
  USERS         = 87,
  NOTSOCK       = 88,
  DESTADDRREQ   = 89,
  MSGSIZE       = 90,
  PROTOTYPE     = 91,
  NOPROTOOPT    = 92,
  PROTONOSUPPORT= 93,
  SOCKTNOSUPPORT= 94,
  OPNOTSUPP     = 95,
  PFNOSUPPORT   = 96,
  AFNOSUPPORT   = 97,
  ADDRINUSE     = 98,
  ADDRNOTAVAIL  = 99,
  NETDOWN       = 100,
  NETUNREACH    = 101,
  NETRESET      = 102,
  CONNABORTED   = 103,
  CONNRESET     = 104,
  NOBUFS        = 105,
  ISCONN        = 106,
  NOTCONN       = 107,
  SHUTDOWN      = 108,
  TOOMANYREFS   = 109,
  TIMEDOUT      = 110,
  CONNREFUSED   = 111,
  HOSTDOWN      = 112,
  HOSTUNREACH   = 113,
  ALREADY       = 114,
  INPROGRESS    = 115,
  STALE         = 116,
  UCLEAN        = 117,
  NOTNAM        = 118,
  NAVAIL        = 119,
  ISNAM         = 120,
  REMOTEIO      = 121,
  DQUOT         = 122,
  NOMEDIUM      = 123,
  MEDIUMTYPE    = 124,
  CANCELED      = 125,
  NOKEY         = 126,
  KEYEXPIRED    = 127,
  KEYREVOKED    = 128,
  KEYREJECTED   = 129,
  OWNERDEAD     = 130,
  NOTRECOVERABLE= 131,
  RFKILL        = 132,
})

-- ppc only redefines DEADLOCK, mips redefines all
if arch.EDEADLOCK then c.E.DEADLOCK = arch.EDEADLOCK end

-- alternate names
c.EALIAS = {
  WOULDBLOCK    = c.E.AGAIN,
  NOATTR        = c.E.NODATA,
  NOTSUP        = c.E.OPNOTSUPP,
}
-- for most architectures this is an alias, but not ppc, mips
if not c.E.DEADLOCK then c.EALIAS.DEADLOCK = c.E.DEADLK end

c.SWAP_FLAG = swapflags {
  PREFER       = 0x8000,
  PRIO_MASK    = 0x7fff,
  PRIO_SHIFT   = 0,
  DISCARD      = 0x10000,
}

--c.FUTEX = 

-- iptables/xtables

c.NF = strflag {
  DROP = 0,
  ACCEPT = 1,
  STOLEN = 2,
  QUEUE = 3,
  REPEAT = 4,
  STOP = 5,
}

-- misc values, just gathered in a table as better namespacing
c.XT = strflag {
  FUNCTION_MAXNAMELEN  = 30,
  EXTENSION_MAXNAMELEN = 29,
  TABLE_MAXNAMELEN     = 32,
}

local IPT_BASE_CTL = 64

c.IPT_SO_SET = strflag {
  REPLACE      = IPT_BASE_CTL,
  ADD_COUNTERS = IPT_BASE_CTL + 1,
}

c.IPT_SO_GET = strflag {
  INFO                 = IPT_BASE_CTL,
  ENTRIES              = IPT_BASE_CTL + 1,
  REVISION_MATCH       = IPT_BASE_CTL + 2,
  REVISION_TARGET      = IPT_BASE_CTL + 3,
}

c.SCHED = multiflags {
  NORMAL           = 0,
  OTHER            = 0,
  FIFO             = 1,
  RR               = 2,
  BATCH            = 3,
  -- ISO
  IDLE             = 5,
  RESET_ON_FORK    = 0x40000000, -- TODO only this flag can be ORed
}

c.TUN_READQ = strflag {
  SIZE = 500,
}

c.TUN = multiflags {
  TUN_DEV    = 0x0001, 
  TAP_DEV    = 0x0002,
  TYPE_MASK  = 0x000f,
  FASYNC     = 0x0010,
  NOCHECKSUM = 0x0020,
  NO_PI      = 0x0040,
  ONE_QUEUE  = 0x0080,
  PERSIST    = 0x0100,
  VNET_HDR   = 0x0200,
  TAP_MQ     = 0x0400,
}

-- note that these are IFF_ but that is a duplicated prefix so using this.
-- These are valid options for struct ifreq flags, while the other IFF_ are for ifinfo
c.IFREQ = multiflags {
-- for tun tap interfaces
  TUN          = 0x0001,
  TAP          = 0x0002,
  NO_PI        = 0x1000,
  ONE_QUEUE    = 0x2000,
  VNET_HDR     = 0x4000,
  TUN_EXCL     = 0x8000,
  MULTI_QUEUE  = 0x0100,
  ATTACH_QUEUE = 0x0200,
  DETACH_QUEUE = 0x0400,
-- for bridge interfaces
  SLAVE_NEEDARP = 0x40,
  ISATAP        = 0x80,
  MASTER_ARPMON = 0x100,
  WAN_HDLC      = 0x200,
  XMIT_DST_RELEASE = 0x400,
  DONT_BRIDGE   = 0x800,
  DISABLE_NETPOLL  = 0x1000,
  MACVLAN_PORT     = 0x2000,
  BRIDGE_PORT   = 0x4000,
  OVS_DATAPATH     = 0x8000,
  TX_SKB_SHARING   = 0x10000,
  UNICAST_FLT   = 0x20000,
}

c.TUN_F = multiflags {
  CSUM     = 0x01,
  TSO4     = 0x02,
  TSO6     = 0x04,
  TSO_ECN  = 0x08,
  UFO      = 0x10,
}

c.TUN_PKT = strflag {
  STRIP = 0x0001,
}

c.TUN_FLT = strflag {
  ALLMULTI = 0x0001,
}

c.PC = strflag {
  LINK_MAX          =  0,
  MAX_CANON         =  1,
  MAX_INPUT         =  2,
  NAME_MAX          =  3,
  PATH_MAX          =  4,
  PIPE_BUF          =  5,
  CHOWN_RESTRICTED  =  6,
  NO_TRUNC          =  7,
  VDISABLE          =  8,
  SYNC_IO           =  9,
  ASYNC_IO          = 10,
  PRIO_IO           = 11,
  SOCK_MAXBUF       = 12,
  FILESIZEBITS      = 13,
  REC_INCR_XFER_SIZE= 14,
  REC_MAX_XFER_SIZE = 15,
  REC_MIN_XFER_SIZE = 16,
  REC_XFER_ALIGN    = 17,
  ALLOC_SIZE_MIN    = 18,
  SYMLINK_MAX       = 19,
  ["2_SYMLINKS"]    = 20,
}

c.RUSAGE = strflag {
  SELF     =  0,
  CHILDREN = -1,
  BOTH     = -2,
  THREAD   =  1,
}

-- waitpid and wait4 pid
c.WAIT = strflag {
  ANY      = -1,
  MYPGRP   = 0,
}

-- virtio functions
c.VIRTIO = strflag {
  PCI_HOST_FEATURES       = 0,
  PCI_GUEST_FEATURES      = 4,
  PCI_QUEUE_PFN           = 8,
  PCI_QUEUE_NUM           = 12,
  PCI_QUEUE_SEL           = 14,
  PCI_QUEUE_NOTIFY        = 16,
  PCI_STATUS              = 18,
  PCI_ISR                 = 19,
  PCI_ISR_CONFIG          = 0x2,
  MSI_CONFIG_VECTOR       = 20,
  MSI_QUEUE_VECTOR        = 22,
  MSI_NO_VECTOR           = 0xffff,
  PCI_ABI_VERSION         = 0,
  PCI_QUEUE_ADDR_SHIFT    = 12,
  PCI_VRING_ALIGN         = 4096,
  -- TODO VIRTIO_PCI_CONFIG_OFF(msix_enabled)     ((msix_enabled) ? 24 : 20)
}

-- from linux/pci_regs.h
c.PCI = strflag {
  VENDOR_ID          = 0x00,
  DEVICE_ID          = 0x02,
  COMMAND            = 0x04,
  STATUS             = 0x06,
  CLASS_REVISION     = 0x08,
  REVISION_ID        = 0x08,
  CLASS_PROG         = 0x09,
  CLASS_DEVICE       = 0x0a,
  CACHE_LINE_SIZE    = 0x0c,
  LATENCY_TIMER      = 0x0d,
  HEADER_TYPE        = 0x0e,
  CACHE_LINE_SIZE    = 0x0c,
  LATENCY_TIMER      = 0x0d,
  HEADER_TYPE        = 0x0e,
  BIST               = 0x0f,
  BASE_ADDRESS_0     = 0x10,
  BASE_ADDRESS_1     = 0x14,
  BASE_ADDRESS_2     = 0x18,
  BASE_ADDRESS_3     = 0x1c,
  BASE_ADDRESS_4     = 0x20,
  BASE_ADDRESS_5     = 0x24,
-- Header type 0 (Normal)
  CARDBUS_CIS        = 0x28,
  SUBSYSTEM_VENDOR_ID= 0x2c,
  SUBSYSTEM_ID       = 0x2e,
  ROM_ADDRESS        = 0x30,
  CAPABILITY_LIST    = 0x34,
  INTERRUPT_LINE     = 0x3c,
  INTERRUPT_PIN      = 0x3d,
  MIN_GNT            = 0x3e,
  MAX_LAT            = 0x3f,
-- Header type 1 (PCI-to-PCI bridges)
  PRIMARY_BUS        = 0x18,
  SECONDARY_BUS      = 0x19,
  SUBORDINATE_BUS    = 0x1a,
  SEC_LATENCY_TIMER  = 0x1b,
  IO_BASE            = 0x1c,
  IO_LIMIT           = 0x1d,
  SEC_STATUS         = 0x1e,
  MEMORY_BASE        = 0x20,
  MEMORY_LIMIT       = 0x22,
  PREF_MEMORY_BASE   = 0x24,
  PREF_MEMORY_LIMIT  = 0x26,
  PREF_BASE_UPPER32  = 0x28,
  PREF_LIMIT_UPPER32 = 0x2c,
  IO_BASE_UPPER16    = 0x30,
  IO_LIMIT_UPPER16   = 0x32,
  ROM_ADDRESS1       = 0x38,
  BRIDGE_CONTROL     = 0x3e,
-- Header type 2 (CardBus bridges)
  CB_CAPABILITY_LIST = 0x14,
  CB_SEC_STATUS      = 0x16,
  CB_PRIMARY_BUS     = 0x18,
  CB_CARD_BUS        = 0x19,
  CB_SUBORDINATE_BUS = 0x1a,
  CB_LATENCY_TIMER   = 0x1b,
  CB_MEMORY_BASE_0   = 0x1c,
  CB_MEMORY_LIMIT_0  = 0x20,
  CB_MEMORY_BASE_1   = 0x24,
  CB_MEMORY_LIMIT_1  = 0x28,
  CB_IO_BASE_0       = 0x2c,
  CB_IO_BASE_0_HI    = 0x2e,
  CB_IO_LIMIT_0      = 0x30,
  CB_IO_LIMIT_0_HI   = 0x32,
  CB_IO_BASE_1       = 0x34,
  CB_IO_BASE_1_HI    = 0x36,
  CB_IO_LIMIT_1      = 0x38,
  CB_IO_LIMIT_1_HI   = 0x3a,
  CB_BRIDGE_CONTROL  = 0x3e,
  CB_SUBSYSTEM_VENDOR_ID = 0x40,
  CB_SUBSYSTEM_ID        = 0x42,
  CB_LEGACY_MODE_BASE    = 0x44,
}

-- unclear how best to group these, maybe just put everything in PCI and let app fix it
c.PCI_BASE_ADDRESS = strflag {
  SPACE         = 0x01,
  SPACE_IO      = 0x01,
  SPACE_MEMORY  = 0x00,
  MEM_TYPE_MASK = 0x06,
  MEM_TYPE_32   = 0x00,
  MEM_TYPE_1M   = 0x02,
  MEM_TYPE_64   = 0x04,
  MEM_PREFETCH  = 0x08,
  --MEM_MASK      (~0x0fUL)
  --IO_MASK       (~0x03UL)
}

c.TCP = strflag {
  NODELAY            = 1,
  MAXSEG             = 2,
  CORK               = 3,
  KEEPIDLE           = 4,
  KEEPINTVL          = 5,
  KEEPCNT            = 6,
  SYNCNT             = 7,
  LINGER2            = 8,
  DEFER_ACCEPT       = 9,
  WINDOW_CLAMP       = 10,
  INFO               = 11,
  QUICKACK           = 12,
  CONGESTION         = 13,
  MD5SIG             = 14,
  THIN_LINEAR_TIMEOUTS= 16,
  THIN_DUPACK        = 17,
  USER_TIMEOUT       = 18,
  REPAIR             = 19,
  REPAIR_QUEUE       = 20,
  QUEUE_SEQ          = 21,
  REPAIR_OPTIONS     = 22,
  FASTOPEN           = 23,
  TIMESTAMP          = 24,
}

-- ipv6 sockopts
c.IPV6 = strflag {
  ADDRFORM          = 1,
  ["2292PKTINFO"]   = 2,
  ["2292HOPOPTS"]   = 3,
  ["2292DSTOPTS"]   = 4,
  ["2292RTHDR"]     = 5,
  ["2292PKTOPTIONS"]= 6,
  CHECKSUM          = 7,
  ["2292HOPLIMIT"]  = 8,
  NEXTHOP           = 9,
  AUTHHDR           = 10,
  FLOWINFO          = 11,
  UNICAST_HOPS      = 16,
  MULTICAST_IF      = 17,
  MULTICAST_HOPS    = 18,
  MULTICAST_LOOP    = 19,
  ADD_MEMBERSHIP    = 20,
  DROP_MEMBERSHIP   = 21,
  ROUTER_ALERT      = 22,
  MTU_DISCOVER      = 23,
  MTU               = 24,
  RECVERR           = 25,
  V6ONLY            = 26,
  JOIN_ANYCAST      = 27,
  LEAVE_ANYCAST     = 28,
}

-- need to use tobit to make sure within int range
c.LINUX_REBOOT = strflag {
  MAGIC1    = tobit(0xfee1dead),
  MAGIC2    = tobit(672274793),
  MAGIC2A   = tobit(85072278),
  MAGIC2B   = tobit(369367448),
  MAGIC2C   = tobit(537993216),
}

c.GRND = multiflags {
  NONBLOCK = 0x0001,
  RANDOM   = 0x0002,
}

c.MFD = multiflags {
  CLOEXEC            = 0x0001,
  ALLOW_SEALING      = 0x0002,
}

return c

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.syscalls"],"module already exists")sources["syscall.syscalls"]=([===[-- <pack syscall.syscalls> --
-- choose correct syscalls for OS, plus shared calls
-- note that where functions are identical if present but may be missing they can also go here
-- note that OS specific calls are loaded at the end so they may override generic calls here

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local abi = require "syscall.abi"
local ffi = require "ffi"
local bit = require "syscall.bit"

local h = require "syscall.helpers"
local err64 = h.err64
local errpointer = h.errpointer
local getfd, istype, mktype, reviter = h.getfd, h.istype, h.mktype, h.reviter

local function init(C, c, types)

-- this could be an arguments, fcntl syscall is a function of this
local fcntl = require("syscall." .. abi.os .. ".fcntl").init(types)

local errno = ffi.errno

local t, pt, s = types.t, types.pt, types.s

local S = {}

local function getdev(dev)
  if type(dev) == "table" then return t.device(dev).dev end
  if ffi.istype(t.device, dev) then dev = dev.dev end
  return dev
end

-- return helpers.

-- 64 bit return helpers. Only use for lseek in fact; we use tonumber but remove if you need files over 56 bits long
-- TODO only luaffi needs the cast as wont compare to number; hopefully fixed in future with 5.3 or a later luaffi.
local function ret64(ret, err)
  if ret == err64 then return nil, t.error(err or errno()) end
  return tonumber(ret)
end

local function retnum(ret, err) -- return Lua number where double precision ok, eg file ops etc
  ret = tonumber(ret)
  if ret == -1 then return nil, t.error(err or errno()) end
  return ret
end

local function retfd(ret, err)
  if ret == -1 then return nil, t.error(err or errno()) end
  return t.fd(ret)
end

-- used for no return value, return true for use of assert
local function retbool(ret, err)
  if ret == -1 then return nil, t.error(err or errno()) end
  return true
end

-- used for pointer returns, -1 is failure
local function retptr(ret, err)
  if ret == errpointer then return nil, t.error(err or errno()) end
  return ret
end

-- generic iterator; this counts down to 0 so need no closure
local function retiter(ret, err, array)
  ret = tonumber(ret)
  if ret == -1 then return nil, t.error(err or errno()) end
  return reviter, array, ret
end

-- generic system calls
function S.close(fd)
  if fd == getfd(fd) then -- fd number
    return retbool(C.close(getfd(fd)))
  else                    -- fd object: avoid mulitple close
    return fd:close()
  end
end
function S.chdir(path) return retbool(C.chdir(path)) end
function S.fchdir(fd) return retbool(C.fchdir(getfd(fd))) end
function S.fchmod(fd, mode) return retbool(C.fchmod(getfd(fd), c.MODE[mode])) end
function S.fchown(fd, owner, group) return retbool(C.fchown(getfd(fd), owner or -1, group or -1)) end
function S.lchown(path, owner, group) return retbool(C.lchown(path, owner or -1, group or -1)) end
function S.chroot(path) return retbool(C.chroot(path)) end
function S.umask(mask) return C.umask(c.MODE[mask]) end
function S.sync() C.sync() end
function S.flock(fd, operation) return retbool(C.flock(getfd(fd), c.LOCK[operation])) end
-- TODO read should have consistent return type but then will differ from other calls.
function S.read(fd, buf, count)
  if buf then return retnum(C.read(getfd(fd), buf, count or #buf or 4096)) end -- user supplied a buffer, standard usage
  count = count or 4096
  buf = t.buffer(count)
  local ret, err = tonumber(C.read(getfd(fd), buf, count))
  if ret == -1 then return nil, t.error(err or errno()) end
  return ffi.string(buf, ret) -- user gets a string back, can get length from #string
end
function S.readv(fd, iov)
  iov = mktype(t.iovecs, iov)
  return retnum(C.readv(getfd(fd), iov.iov, #iov))
end
function S.write(fd, buf, count) return retnum(C.write(getfd(fd), buf, count or #buf)) end
function S.writev(fd, iov)
  iov = mktype(t.iovecs, iov)
  return retnum(C.writev(getfd(fd), iov.iov, #iov))
end
function S.pread(fd, buf, count, offset) return retnum(C.pread(getfd(fd), buf, count, offset)) end
function S.pwrite(fd, buf, count, offset) return retnum(C.pwrite(getfd(fd), buf, count or #buf, offset)) end
if C.preadv and C.pwritev then -- these are missing in eg OSX
  function S.preadv(fd, iov, offset)
    iov = mktype(t.iovecs, iov)
    return retnum(C.preadv(getfd(fd), iov.iov, #iov, offset))
  end
  function S.pwritev(fd, iov, offset)
    iov = mktype(t.iovecs, iov)
    return retnum(C.pwritev(getfd(fd), iov.iov, #iov, offset))
  end
end
function S.lseek(fd, offset, whence)
  return ret64(C.lseek(getfd(fd), offset or 0, c.SEEK[whence or c.SEEK.SET]))
end
if C.readlink then
  function S.readlink(path, buffer, size)
    size = size or c.PATH_MAX
    buffer = buffer or t.buffer(size)
    local ret, err = tonumber(C.readlink(path, buffer, size))
    if ret == -1 then return nil, t.error(err or errno()) end
    return ffi.string(buffer, ret)
  end
else
  function S.readlink(path, buffer, size)
    size = size or c.PATH_MAX
    buffer = buffer or t.buffer(size)
    local ret, err = tonumber(C.readlinkat(c.AT_FDCWD.FDCWD, path, buffer, size))
    if ret == -1 then return nil, t.error(err or errno()) end
    return ffi.string(buffer, ret)
  end
end
function S.fsync(fd) return retbool(C.fsync(getfd(fd))) end
if C.stat then
  function S.stat(path, buf)
    if not buf then buf = t.stat() end
    local ret = C.stat(path, buf)
    if ret == -1 then return nil, t.error() end
    return buf
  end
else
  function S.stat(path, buf)
    if not buf then buf = t.stat() end
    local ret = C.fstatat(c.AT_FDCWD.FDCWD, path, buf, 0)
    if ret == -1 then return nil, t.error() end
    return buf
  end
end
if C.lstat then
  function S.lstat(path, buf)
    if not buf then buf = t.stat() end
    local ret, err = C.lstat(path, buf)
    if ret == -1 then return nil, t.error(err or errno()) end
    return buf
  end
else
  function S.lstat(path, buf)
    if not buf then buf = t.stat() end
    local ret, err = C.fstatat(c.AT_FDCWD.FDCWD, path, buf, c.AT.SYMLINK_NOFOLLOW)
    if ret == -1 then return nil, t.error(err or errno()) end
    return buf
  end
end
function S.fstat(fd, buf)
  if not buf then buf = t.stat() end
  local ret, err = C.fstat(getfd(fd), buf)
  if ret == -1 then return nil, t.error(err or errno()) end
  return buf
end
function S.truncate(path, length) return retbool(C.truncate(path, length)) end
function S.ftruncate(fd, length) return retbool(C.ftruncate(getfd(fd), length)) end

-- recent Linux does not have open, rmdir, unlink etc any more as syscalls
if C.open then
  function S.open(pathname, flags, mode) return retfd(C.open(pathname, c.O[flags], c.MODE[mode])) end
else
  function S.open(pathname, flags, mode) return retfd(C.openat(c.AT_FDCWD.FDCWD, pathname, c.O[flags], c.MODE[mode])) end
end
if C.rmdir then
  function S.rmdir(path) return retbool(C.rmdir(path)) end
else
  function S.rmdir(path) return retbool(C.unlinkat(c.AT_FDCWD.FDCWD, path, c.AT.REMOVEDIR)) end
end
if C.unlink then
  function S.unlink(pathname) return retbool(C.unlink(pathname)) end
else
  function S.unlink(path) return retbool(C.unlinkat(c.AT_FDCWD.FDCWD, path, 0)) end
end
if C.chmod then
  function S.chmod(path, mode) return retbool(C.chmod(path, c.MODE[mode])) end
else
  function S.chmod(path, mode) return retbool(C.fchmodat(c.AT_FDCWD.FDCWD, path, c.MODE[mode], 0)) end
end
if C.access then
  function S.access(pathname, mode) return retbool(C.access(pathname, c.OK[mode])) end
else
  function S.access(pathname, mode) return retbool(C.faccessat(c.AT_FDCWD.FDCWD, pathname, c.OK[mode], 0)) end
end
if C.chown then
  function S.chown(path, owner, group) return retbool(C.chown(path, owner or -1, group or -1)) end
else
  function S.chown(path, owner, group) return retbool(C.fchownat(c.AT_FDCWD.FDCWD, path, owner or -1, group or -1, 0)) end
end
if C.mkdir then
  function S.mkdir(path, mode) return retbool(C.mkdir(path, c.MODE[mode])) end
else
  function S.mkdir(path, mode) return retbool(C.mkdirat(c.AT_FDCWD.FDCWD, path, c.MODE[mode])) end
end
if C.symlink then
  function S.symlink(oldpath, newpath) return retbool(C.symlink(oldpath, newpath)) end
else
  function S.symlink(oldpath, newpath) return retbool(C.symlinkat(oldpath, c.AT_FDCWD.FDCWD, newpath)) end
end
if C.link then
  function S.link(oldpath, newpath) return retbool(C.link(oldpath, newpath)) end
else
  function S.link(oldpath, newpath) return retbool(C.linkat(c.AT_FDCWD.FDCWD, oldpath, c.AT_FDCWD.FDCWD, newpath, 0)) end
end
if C.rename then
  function S.rename(oldpath, newpath) return retbool(C.rename(oldpath, newpath)) end
else
  function S.rename(oldpath, newpath) return retbool(C.renameat(c.AT_FDCWD.FDCWD, oldpath, c.AT_FDCWD.FDCWD, newpath)) end
end
if C.mknod then
  function S.mknod(pathname, mode, dev) return retbool(C.mknod(pathname, c.S_I[mode], getdev(dev) or 0)) end
else
  function S.mknod(pathname, mode, dev) return retbool(C.mknodat(c.AT_FDCWD.FDCWD, pathname, c.S_I[mode], getdev(dev) or 0)) end
end

local function sproto(domain, protocol) -- helper function to lookup protocol type depending on domain TODO table?
  protocol = protocol or 0
  if domain == c.AF.NETLINK then return c.NETLINK[protocol] end
  return c.IPPROTO[protocol]
end

function S.socket(domain, stype, protocol)
  domain = c.AF[domain]
  return retfd(C.socket(domain, c.SOCK[stype], sproto(domain, protocol)))
end
function S.socketpair(domain, stype, protocol, sv2)
  domain = c.AF[domain]
  sv2 = sv2 or t.int2()
  local ret, err = C.socketpair(domain, c.SOCK[stype], sproto(domain, protocol), sv2)
  if ret == -1 then return nil, t.error(err or errno()) end
  return true, nil, t.fd(sv2[0]), t.fd(sv2[1])
end

function S.dup(oldfd) return retfd(C.dup(getfd(oldfd))) end
if C.dup2 then function S.dup2(oldfd, newfd) return retfd(C.dup2(getfd(oldfd), getfd(newfd))) end end
if C.dup3 then function S.dup3(oldfd, newfd, flags) return retfd(C.dup3(getfd(oldfd), getfd(newfd), flags or 0)) end end

function S.sendto(fd, buf, count, flags, addr, addrlen)
  if not addr then addrlen = 0 end
  local saddr = pt.sockaddr(addr)
  return retnum(C.sendto(getfd(fd), buf, count or #buf, c.MSG[flags], saddr, addrlen or #addr))
end
function S.recvfrom(fd, buf, count, flags, addr, addrlen)
  local saddr
  if addr == false then
    addr = nil
    addrlen = nil
  else
    if addr then
      addrlen = addrlen or #addr
    else
      addr = t.sockaddr_storage()
      addrlen = addrlen or s.sockaddr_storage
    end
    if type(addrlen) == "number" then addrlen = t.socklen1(addrlen) end
    saddr = pt.sockaddr(addr)
  end
  local ret, err = C.recvfrom(getfd(fd), buf, count or #buf, c.MSG[flags], saddr, addrlen) -- TODO addrlen 0 here???
  ret = tonumber(ret)
  if ret == -1 then return nil, t.error(err or errno()) end
  if addr then return ret, nil, t.sa(addr, addrlen[0]) else return ret end
end
function S.sendmsg(fd, msg, flags)
  if not msg then -- send a single byte message, eg enough to send credentials
    local buf1 = t.buffer(1)
    local io = t.iovecs{{buf1, 1}}
    msg = t.msghdr{msg_iov = io.iov, msg_iovlen = #io}
  end
  return retnum(C.sendmsg(getfd(fd), msg, c.MSG[flags]))
end
function S.recvmsg(fd, msg, flags) return retnum(C.recvmsg(getfd(fd), msg, c.MSG[flags])) end

-- TODO better handling of msgvec, create one structure/table
if C.sendmmsg then
  function S.sendmmsg(fd, msgvec, flags)
    msgvec = mktype(t.mmsghdrs, msgvec)
    return retbool(C.sendmmsg(getfd(fd), msgvec.msg, msgvec.count, c.MSG[flags]))
  end
end
if C.recvmmsg then
  function S.recvmmsg(fd, msgvec, flags, timeout)
    if timeout then timeout = mktype(t.timespec, timeout) end
    msgvec = mktype(t.mmsghdrs, msgvec)
    return retbool(C.recvmmsg(getfd(fd), msgvec.msg, msgvec.count, c.MSG[flags], timeout))
  end
end

-- TODO {get,set}sockopt may need better type handling see new unfinished sockopt file, plus not always c.SO[]
function S.setsockopt(fd, level, optname, optval, optlen)
   -- allocate buffer for user, from Lua type if know how, int and bool so far
  if not optlen and type(optval) == 'boolean' then optval = h.booltoc(optval) end
  if not optlen and type(optval) == 'number' then
    optval = t.int1(optval)
    optlen = s.int
  end
  return retbool(C.setsockopt(getfd(fd), c.SOL[level], c.SO[optname], optval, optlen))
end
function S.getsockopt(fd, level, optname, optval, optlen)
  if not optval then optval, optlen = t.int1(), s.int end
  optlen = optlen or #optval
  local len = t.socklen1(optlen)
  local ret, err = C.getsockopt(getfd(fd), c.SOL[level], c.SO[optname], optval, len)
  if ret == -1 then return nil, t.error(err or errno()) end
  if len[0] ~= optlen then error("incorrect optlen for getsockopt: set " .. optlen .. " got " .. len[0]) end
  return optval[0] -- TODO will not work if struct, eg see netfilter
end
function S.bind(sockfd, addr, addrlen)
  local saddr = pt.sockaddr(addr)
  return retbool(C.bind(getfd(sockfd), saddr, addrlen or #addr))
end
function S.listen(sockfd, backlog) return retbool(C.listen(getfd(sockfd), backlog or c.SOMAXCONN)) end
function S.connect(sockfd, addr, addrlen)
  local saddr = pt.sockaddr(addr)
  return retbool(C.connect(getfd(sockfd), saddr, addrlen or #addr))
end
function S.accept(sockfd, addr, addrlen)
  local saddr = pt.sockaddr(addr)
  if addr then addrlen = addrlen or t.socklen1() end
  return retfd(C.accept(getfd(sockfd), saddr, addrlen))
end
function S.getsockname(sockfd, addr, addrlen)
  addr = addr or t.sockaddr_storage()
  addrlen = addrlen or t.socklen1(#addr)
  local saddr = pt.sockaddr(addr)
  local ret, err = C.getsockname(getfd(sockfd), saddr, addrlen)
  if ret == -1 then return nil, t.error(err or errno()) end
  return t.sa(addr, addrlen[0])
end
function S.getpeername(sockfd, addr, addrlen)
  addr = addr or t.sockaddr_storage()
  addrlen = addrlen or t.socklen1(#addr)
  local saddr = pt.sockaddr(addr)
  local ret, err = C.getpeername(getfd(sockfd), saddr, addrlen)
  if ret == -1 then return nil, t.error(err or errno()) end
  return t.sa(addr, addrlen[0])
end
function S.shutdown(sockfd, how) return retbool(C.shutdown(getfd(sockfd), c.SHUT[how])) end
if C.poll then
  function S.poll(fds, timeout) return retnum(C.poll(fds.pfd, #fds, timeout or -1)) end
end
-- TODO rework fdset interface, see issue #71
-- fdset handlers
local function mkfdset(fds, nfds) -- should probably check fd is within range (1024), or just expand structure size
  local set = t.fdset()
  for i, v in ipairs(fds) do
    local fd = tonumber(getfd(v))
    if fd + 1 > nfds then nfds = fd + 1 end
    local fdelt = bit.rshift(fd, 5) -- always 32 bits
    set.fds_bits[fdelt] = bit.bor(set.fds_bits[fdelt], bit.lshift(1, fd % 32)) -- always 32 bit words
  end
  return set, nfds
end

local function fdisset(fds, set)
  local f = {}
  for i, v in ipairs(fds) do
    local fd = tonumber(getfd(v))
    local fdelt = bit.rshift(fd, 5) -- always 32 bits
    if bit.band(set.fds_bits[fdelt], bit.lshift(1, fd % 32)) ~= 0 then table.insert(f, v) end -- careful not to duplicate fd objects
  end
  return f
end

-- TODO convert to metatype. Problem is how to deal with nfds
if C.select then
function S.select(sel, timeout) -- note same structure as returned
  local r, w, e
  local nfds = 0
  if timeout then timeout = mktype(t.timeval, timeout) end
  r, nfds = mkfdset(sel.readfds or {}, nfds or 0)
  w, nfds = mkfdset(sel.writefds or {}, nfds)
  e, nfds = mkfdset(sel.exceptfds or {}, nfds)
  local ret, err = C.select(nfds, r, w, e, timeout)
  if ret == -1 then return nil, t.error(err or errno()) end
  return {readfds = fdisset(sel.readfds or {}, r), writefds = fdisset(sel.writefds or {}, w),
          exceptfds = fdisset(sel.exceptfds or {}, e), count = tonumber(ret)}
end
else
  function S.select(sel, timeout)
    if timeout then timeout = mktype(t.timespec, timeout / 1000) end
    return S.pselect(sel, timeout)
  end
end

-- TODO note that in Linux syscall modifies timeout, which is non standard, like ppoll
function S.pselect(sel, timeout, set) -- note same structure as returned
  local r, w, e
  local nfds = 0
  if timeout then timeout = mktype(t.timespec, timeout) end
  if set then set = mktype(t.sigset, set) end
  r, nfds = mkfdset(sel.readfds or {}, nfds or 0)
  w, nfds = mkfdset(sel.writefds or {}, nfds)
  e, nfds = mkfdset(sel.exceptfds or {}, nfds)
  local ret, err = C.pselect(nfds, r, w, e, timeout, set)
  if ret == -1 then return nil, t.error(err or errno()) end
  return {readfds = fdisset(sel.readfds or {}, r), writefds = fdisset(sel.writefds or {}, w),
          exceptfds = fdisset(sel.exceptfds or {}, e), count = tonumber(ret)}
end

function S.getuid() return C.getuid() end
function S.geteuid() return C.geteuid() end
function S.getpid() return C.getpid() end
function S.getppid() return C.getppid() end
function S.getgid() return C.getgid() end
function S.getegid() return C.getegid() end
function S.setuid(uid) return retbool(C.setuid(uid)) end
function S.setgid(gid) return retbool(C.setgid(gid)) end
function S.seteuid(uid) return retbool(C.seteuid(uid)) end
function S.setegid(gid) return retbool(C.setegid(gid)) end
function S.getsid(pid) return retnum(C.getsid(pid or 0)) end
function S.setsid() return retnum(C.setsid()) end
function S.setpgid(pid, pgid) return retbool(C.setpgid(pid or 0, pgid or 0)) end
function S.getpgid(pid) return retnum(C.getpgid(pid or 0)) end
if C.getpgrp then
  function S.getpgrp() return retnum(C.getpgrp()) end
else
  function S.getpgrp() return retnum(C.getpgid(0)) end
end
function S.getgroups()
  local size = C.getgroups(0, nil) -- note for BSD could use NGROUPS_MAX instead
  if size == -1 then return nil, t.error() end
  local groups = t.groups(size)
  local ret = C.getgroups(size, groups.list)
  if ret == -1 then return nil, t.error() end
  return groups
end
function S.setgroups(groups)
  if type(groups) == "table" then groups = t.groups(groups) end
  return retbool(C.setgroups(groups.count, groups.list))
end

function S.sigprocmask(how, set, oldset)
  oldset = oldset or t.sigset()
  if not set then how = c.SIGPM.SETMASK end -- value does not matter if set nil, just returns old set
  local ret, err = C.sigprocmask(c.SIGPM[how], t.sigset(set), oldset)
  if ret == -1 then return nil, t.error(err or errno()) end
  return oldset
end
function S.sigpending()
  local set = t.sigset()
  local ret, err = C.sigpending(set)
  if ret == -1 then return nil, t.error(err or errno()) end
 return set
end
function S.sigsuspend(mask) return retbool(C.sigsuspend(t.sigset(mask))) end
function S.kill(pid, sig) return retbool(C.kill(pid, c.SIG[sig])) end

-- _exit is the real exit syscall, or whatever is suitable if overridden in c.lua; libc.lua may override
function S.exit(status) C._exit(c.EXIT[status or 0]) end

function S.fcntl(fd, cmd, arg)
  cmd = c.F[cmd]
  if fcntl.commands[cmd] then arg = fcntl.commands[cmd](arg) end
  local ret, err = C.fcntl(getfd(fd), cmd, pt.void(arg or 0))
  if ret == -1 then return nil, t.error(err or errno()) end
  if fcntl.ret[cmd] then return fcntl.ret[cmd](ret, arg) end
  return true
end

-- TODO return metatype that has length and can gc?
function S.mmap(addr, length, prot, flags, fd, offset)
  return retptr(C.mmap(addr, length, c.PROT[prot], c.MAP[flags], getfd(fd or -1), offset or 0))
end
function S.munmap(addr, length)
  return retbool(C.munmap(addr, length))
end
function S.msync(addr, length, flags) return retbool(C.msync(addr, length, c.MSYNC[flags])) end
function S.mlock(addr, len) return retbool(C.mlock(addr, len)) end
function S.munlock(addr, len) return retbool(C.munlock(addr, len)) end
function S.munlockall() return retbool(C.munlockall()) end
function S.madvise(addr, length, advice) return retbool(C.madvise(addr, length, c.MADV[advice])) end

function S.ioctl(d, request, argp)
  local read, singleton = false, false
  local name = request
  if type(name) == "string" then
    request = c.IOCTL[name]
  end
  if type(request) == "table" then
    local write = request.write
    local tp = request.type
    read = request.read
    singleton = request.singleton
    request = request.number
    if type(argp) ~= "string" and type(argp) ~= "cdata" and type ~= "userdata" then
      if write then
        if not argp then error("no argument supplied for ioctl " .. name) end
        argp = mktype(tp, argp)
      end
      if read then
        argp = argp or tp()
      end
    end
  else -- some sane defaults if no info
    if type(request) == "table" then request = request.number end
    if type(argp) == "string" then argp = pt.char(argp) end
    if type(argp) == "number" then argp = t.int1(argp) end
  end
  local ret, err = C.ioctl(getfd(d), request, argp)
  if ret == -1 then return nil, t.error(err or errno()) end
  if read and singleton then return argp[0] end
  if read then return argp end
  return true -- will need override for few linux ones that return numbers
end

if C.pipe then
  function S.pipe(fd2)
    fd2 = fd2 or t.int2()
    local ret, err = C.pipe(fd2)
    if ret == -1 then return nil, t.error(err or errno()) end
    return true, nil, t.fd(fd2[0]), t.fd(fd2[1])
  end
else
  function S.pipe(fd2)
    fd2 = fd2 or t.int2()
    local ret, err = C.pipe2(fd2, 0)
    if ret == -1 then return nil, t.error(err or errno()) end
    return true, nil, t.fd(fd2[0]), t.fd(fd2[1])
  end
end

if C.gettimeofday then
  function S.gettimeofday(tv)
    tv = tv or t.timeval() -- note it is faster to pass your own tv if you call a lot
    local ret, err = C.gettimeofday(tv, nil)
    if ret == -1 then return nil, t.error(err or errno()) end
    return tv
  end
end

if C.settimeofday then
  function S.settimeofday(tv) return retbool(C.settimeofday(tv, nil)) end
end

function S.getrusage(who, ru)
  ru = ru or t.rusage()
  local ret, err = C.getrusage(c.RUSAGE[who], ru)
  if ret == -1 then return nil, t.error(err or errno()) end
  return ru
end

if C.fork then
  function S.fork() return retnum(C.fork()) end
else
  function S.fork() return retnum(C.clone(c.SIG.CHLD, 0)) end
end

function S.execve(filename, argv, envp)
  local cargv = t.string_array(#argv + 1, argv or {})
  cargv[#argv] = nil -- LuaJIT does not zero rest of a VLA
  local cenvp = t.string_array(#envp + 1, envp or {})
  cenvp[#envp] = nil
  return retbool(C.execve(filename, cargv, cenvp))
end

-- man page says obsolete for Linux, but implemented and useful for compatibility
function S.wait4(pid, options, ru, status) -- note order of arguments changed as rarely supply status (as waitpid)
  if ru == false then ru = nil else ru = ru or t.rusage() end -- false means no allocation
  status = status or t.int1()
  local ret, err = C.wait4(c.WAIT[pid], status, c.W[options], ru)
  if ret == -1 then return nil, t.error(err or errno()) end
  return ret, nil, t.waitstatus(status[0]), ru
end

if C.waitpid then
  function S.waitpid(pid, options, status) -- note order of arguments changed as rarely supply status
    status = status or t.int1()
    local ret, err = C.waitpid(c.WAIT[pid], status, c.W[options])
    if ret == -1 then return nil, t.error(err or errno()) end
    return ret, nil, t.waitstatus(status[0])
  end
end

if S.waitid then
  function S.waitid(idtype, id, options, infop) -- note order of args, as usually dont supply infop
    if not infop then infop = t.siginfo() end
    local ret, err = C.waitid(c.P[idtype], id or 0, infop, c.W[options])
    if ret == -1 then return nil, t.error(err or errno()) end
    return infop
  end
end

function S.setpriority(which, who, prio) return retbool(C.setpriority(c.PRIO[which], who or 0, prio)) end
-- Linux overrides getpriority as it offsets return values so that they are not negative
function S.getpriority(which, who)
  errno(0)
  local ret, err = C.getpriority(c.PRIO[which], who or 0)
  if ret == -1 and (err or errno()) ~= 0 then return nil, t.error(err or errno()) end
  return ret
end

-- these may not always exist, but where they do they have the same interface
if C.creat then
  function S.creat(pathname, mode) return retfd(C.creat(pathname, c.MODE[mode])) end
end
if C.pipe2 then
  function S.pipe2(flags, fd2)
    fd2 = fd2 or t.int2()
    local ret, err = C.pipe2(fd2, c.OPIPE[flags])
    if ret == -1 then return nil, t.error(err or errno()) end
    return true, nil, t.fd(fd2[0]), t.fd(fd2[1])
  end
end
if C.mlockall then
  function S.mlockall(flags) return retbool(C.mlockall(c.MCL[flags])) end
end
if C.linkat then
  function S.linkat(olddirfd, oldpath, newdirfd, newpath, flags)
    return retbool(C.linkat(c.AT_FDCWD[olddirfd], oldpath, c.AT_FDCWD[newdirfd], newpath, c.AT[flags]))
  end
end
if C.symlinkat then
  function S.symlinkat(oldpath, newdirfd, newpath) return retbool(C.symlinkat(oldpath, c.AT_FDCWD[newdirfd], newpath)) end
end
if C.unlinkat then
  function S.unlinkat(dirfd, path, flags) return retbool(C.unlinkat(c.AT_FDCWD[dirfd], path, c.AT[flags])) end
end
if C.renameat then
  function S.renameat(olddirfd, oldpath, newdirfd, newpath)
    return retbool(C.renameat(c.AT_FDCWD[olddirfd], oldpath, c.AT_FDCWD[newdirfd], newpath))
  end
end
if C.mkdirat then
  function S.mkdirat(fd, path, mode) return retbool(C.mkdirat(c.AT_FDCWD[fd], path, c.MODE[mode])) end
end
if C.fchownat then
  function S.fchownat(dirfd, path, owner, group, flags)
    return retbool(C.fchownat(c.AT_FDCWD[dirfd], path, owner or -1, group or -1, c.AT[flags]))
  end
end
if C.faccessat then
  function S.faccessat(dirfd, pathname, mode, flags)
    return retbool(C.faccessat(c.AT_FDCWD[dirfd], pathname, c.OK[mode], c.AT[flags]))
  end
end
if C.readlinkat then
  function S.readlinkat(dirfd, path, buffer, size)
    size = size or c.PATH_MAX
    buffer = buffer or t.buffer(size)
    local ret, err = C.readlinkat(c.AT_FDCWD[dirfd], path, buffer, size)
    ret = tonumber(ret)
    if ret == -1 then return nil, t.error(err or errno()) end
    return ffi.string(buffer, ret)
  end
end
if C.mknodat then
  function S.mknodat(fd, pathname, mode, dev)
    return retbool(C.mknodat(c.AT_FDCWD[fd], pathname, c.S_I[mode], getdev(dev) or 0))
  end
end
if C.utimensat then
  function S.utimensat(dirfd, path, ts, flags)
    if ts then ts = t.timespec2(ts) end -- TODO use mktype?
    return retbool(C.utimensat(c.AT_FDCWD[dirfd], path, ts, c.AT[flags]))
  end
end
if C.fstatat then
  function S.fstatat(fd, path, buf, flags)
    if not buf then buf = t.stat() end
    local ret, err = C.fstatat(c.AT_FDCWD[fd], path, buf, c.AT[flags])
    if ret == -1 then return nil, t.error(err or errno()) end
    return buf
  end
end
if C.fchmodat then
  function S.fchmodat(dirfd, pathname, mode, flags)
    return retbool(C.fchmodat(c.AT_FDCWD[dirfd], pathname, c.MODE[mode], c.AT[flags]))
  end
end
if C.openat then
  function S.openat(dirfd, pathname, flags, mode)
    return retfd(C.openat(c.AT_FDCWD[dirfd], pathname, c.O[flags], c.MODE[mode]))
  end
end

if C.fchroot then
  function S.fchroot(fd) return retbool(C.fchroot(getfd(fd))) end
end
if C.lchmod then
  function S.lchmod(path, mode) return retbool(C.lchmod(path, c.MODE[mode])) end
end

if C.fdatasync then
  function S.fdatasync(fd) return retbool(C.fdatasync(getfd(fd))) end
end
-- Linux does not have mkfifo syscalls, emulated
if C.mkfifo then
  function S.mkfifo(pathname, mode) return retbool(C.mkfifo(pathname, c.S_I[mode])) end
end
if C.mkfifoat then
  function S.mkfifoat(dirfd, pathname, mode) return retbool(C.mkfifoat(c.AT_FDCWD[dirfd], pathname, c.S_I[mode])) end
end
if C.utimes then
  function S.utimes(filename, ts)
    if ts then ts = t.timeval2(ts) end
    return retbool(C.utimes(filename, ts))
  end
end
if C.lutimes then
  function S.lutimes(filename, ts)
    if ts then ts = t.timeval2(ts) end
    return retbool(C.lutimes(filename, ts))
  end
end
if C.futimes then
  function S.futimes(fd, ts)
    if ts then ts = t.timeval2(ts) end
    return retbool(C.futimes(getfd(fd), ts))
  end
end

if C.getdents then
  function S.getdents(fd, buf, size)
    size = size or 4096 -- may have to be equal to at least block size of fs
    buf = buf or t.buffer(size)
    local ret, err = C.getdents(getfd(fd), buf, size)
    if ret == -1 then return nil, t.error(err or errno()) end
    return t.dirents(buf, ret)
  end
end
if C.futimens then
  function S.futimens(fd, ts)
    if ts then ts = t.timespec2(ts) end
    return retbool(C.futimens(getfd(fd), ts))
  end
end
if C.accept4 then
  function S.accept4(sockfd, addr, addrlen, flags)
    local saddr = pt.sockaddr(addr)
    if addr then addrlen = addrlen or t.socklen1() end
    return retfd(C.accept4(getfd(sockfd), saddr, addrlen, c.SOCK[flags]))
  end
end
if C.sigaction then
  function S.sigaction(signum, handler, oldact)
    if type(handler) == "string" or type(handler) == "function" then
      handler = {handler = handler, mask = "", flags = 0} -- simple case like signal
    end
    if handler then handler = mktype(t.sigaction, handler) end
    return retbool(C.sigaction(c.SIG[signum], handler, oldact))
  end
end
if C.getitimer then
  function S.getitimer(which, value)
    value = value or t.itimerval()
    local ret, err = C.getitimer(c.ITIMER[which], value)
    if ret == -1 then return nil, t.error(err or errno()) end
    return value
  end
end
if C.setitimer then
  function S.setitimer(which, it, oldtime)
    oldtime = oldtime or t.itimerval()
    local ret, err = C.setitimer(c.ITIMER[which], mktype(t.itimerval, it), oldtime)
    if ret == -1 then return nil, t.error(err or errno()) end
    return oldtime
  end
end
if C.clock_getres then
  function S.clock_getres(clk_id, ts)
    ts = ts or t.timespec()
    local ret, err = C.clock_getres(c.CLOCK[clk_id], ts)
    if ret == -1 then return nil, t.error(err or errno()) end
    return ts
  end
end
if C.clock_gettime then
  function S.clock_gettime(clk_id, ts)
    ts = ts or t.timespec()
    local ret, err = C.clock_gettime(c.CLOCK[clk_id], ts)
    if ret == -1 then return nil, t.error(err or errno()) end
    return ts
  end
end
if C.clock_settime then
  function S.clock_settime(clk_id, ts)
    ts = mktype(t.timespec, ts)
    return retbool(C.clock_settime(c.CLOCK[clk_id], ts))
  end
end
if C.clock_nanosleep then
  function S.clock_nanosleep(clk_id, flags, req, rem)
    rem = rem or t.timespec()
    local ret, err = C.clock_nanosleep(c.CLOCK[clk_id], c.TIMER[flags or 0], mktype(t.timespec, req), rem)
    if ret == -1 then
      if (err or errno()) == c.E.INTR then return true, nil, rem else return nil, t.error(err or errno()) end
    end
    return true -- no time remaining
  end
end

if C.timer_create then
  function S.timer_create(clk_id, sigev, timerid)
    timerid = timerid or t.timer()
    if sigev then sigev = mktype(t.sigevent, sigev) end
    local ret, err = C.timer_create(c.CLOCK[clk_id], sigev, timerid:gettimerp())
    if ret == -1 then return nil, t.error(err or errno()) end
    return timerid
  end
  function S.timer_delete(timerid) return retbool(C.timer_delete(timerid:gettimer())) end
  function S.timer_settime(timerid, flags, new_value, old_value)
    if old_value ~= false then old_value = old_value or t.itimerspec() else old_value = nil end
    new_value = mktype(t.itimerspec, new_value)
    local ret, err = C.timer_settime(timerid:gettimer(), c.TIMER[flags], new_value, old_value)
    if ret == -1 then return nil, t.error(err or errno()) end
    return true, nil, old_value
  end
  function S.timer_gettime(timerid, curr_value)
    curr_value = curr_value or t.itimerspec()
    local ret, err = C.timer_gettime(timerid:gettimer(), curr_value)
    if ret == -1 then return nil, t.error(err or errno()) end
    return curr_value
  end
  function S.timer_getoverrun(timerid) return retnum(C.timer_getoverrun(timerid:gettimer())) end
end

-- legacy in many OSs, implemented using recvfrom, sendto
if C.send then
  function S.send(fd, buf, count, flags) return retnum(C.send(getfd(fd), buf, count, c.MSG[flags])) end
end
if C.recv then
  function S.recv(fd, buf, count, flags) return retnum(C.recv(getfd(fd), buf, count, c.MSG[flags], false)) end
end

-- TODO not sure about this interface, maybe return rem as extra parameter see #103
if C.nanosleep then
  function S.nanosleep(req, rem)
    rem = rem or t.timespec()
    local ret, err = C.nanosleep(mktype(t.timespec, req), rem)
    if ret == -1 then
      if (err or errno()) == c.E.INTR then return true, nil, rem else return nil, t.error(err or errno()) end
    end
    return true -- no time remaining
  end
end

-- getpagesize might be a syscall, or in libc, or may not exist
if C.getpagesize then
  function S.getpagesize() return retnum(C.getpagesize()) end
end

if C.syncfs then
  function S.syncfs(fd) return retbool(C.syncfs(getfd(fd))) end
end

-- although the pty functions are not syscalls, we include here, like eg shm functions, as easier to provide as methods on fds
-- Freebsd has a syscall, other OSs use /dev/ptmx
if C.posix_openpt then
  function S.posix_openpt(flags) return retfd(C.posix_openpt(c.O[flags])) end
else
  function S.posix_openpt(flags) return S.open("/dev/ptmx", flags) end
end
S.openpt = S.posix_openpt

function S.isatty(fd)
  local tc, err = S.tcgetattr(fd)
  if tc then return true else return nil, err end
end

if c.IOCTL.TIOCGSID then -- OpenBSD only has in legacy ioctls
  function S.tcgetsid(fd) return S.ioctl(fd, "TIOCGSID") end
end

-- now call OS specific for non-generic calls
local hh = {
  ret64 = ret64, retnum = retnum, retfd = retfd, retbool = retbool, retptr = retptr, retiter = retiter
}

if (abi.rump and abi.types == "netbsd") or (not abi.rump and abi.bsd) then
  S = require("syscall.bsd.syscalls")(S, hh, c, C, types)
end
S = require("syscall." .. abi.os .. ".syscalls")(S, hh, c, C, types)

return S

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.arm64.nr"],"module already exists")sources["syscall.linux.arm64.nr"]=([===[-- <pack syscall.linux.arm64.nr> --
-- arm64 syscall numbers are the new architecture defaults
-- so we could reuse this file for other architectures
-- note that there are some name differences for new 32 bit architectures

local nr = {
  SYS = {
  io_setup = 0,
  io_destroy = 1,
  io_submit = 2,
  io_cancel = 3,
  io_getevents = 4,
  setxattr = 5,
  lsetxattr = 6,
  fsetxattr = 7,
  getxattr = 8,
  lgetxattr = 9,
  fgetxattr = 10,
  listxattr = 11,
  llistxattr = 12,
  flistxattr = 13,
  removexattr = 14,
  lremovexattr = 15,
  fremovexattr = 16,
  getcwd = 17,
  lookup_dcookie = 18,
  eventfd2 = 19,
  epoll_create1 = 20,
  epoll_ctl = 21,
  epoll_pwait = 22,
  dup = 23,
  dup3 = 24,
  fcntl = 25,
  inotify_init1 = 26,
  inotify_add_watch = 27,
  inotify_rm_watch = 28,
  ioctl = 29,
  ioprio_set = 30,
  ioprio_get = 31,
  flock = 32,
  mknodat = 33,
  mkdirat = 34,
  unlinkat = 35,
  symlinkat = 36,
  linkat = 37,
  renameat = 38,
  umount2 = 39,
  mount = 40,
  pivot_root = 41,
  nfsservctl = 42,
  statfs = 43,
  fstatfs = 44,
  truncate = 45,
  ftruncate = 46,
  fallocate = 47,
  faccessat = 48,
  chdir = 49,
  fchdir = 50,
  chroot = 51,
  fchmod = 52,
  fchmodat = 53,
  fchownat = 54,
  fchown = 55,
  openat = 56,
  close = 57,
  vhangup = 58,
  pipe2 = 59,
  quotactl = 60,
  getdents64 = 61,
  lseek = 62,
  read = 63,
  write = 64,
  readv = 65,
  writev = 66,
  pread64 = 67,
  pwrite64 = 68,
  preadv = 69,
  pwritev = 70,
  sendfile = 71,
  pselect6 = 72,
  ppoll = 73,
  signalfd4 = 74,
  vmsplice = 75,
  splice = 76,
  tee = 77,
  readlinkat = 78,
  fstatat = 79,
  fstat = 80,
  sync = 81,
  fsync = 82,
  fdatasync = 83,
  sync_file_range = 84,
  timerfd_create = 85,
  timerfd_settime = 86,
  timerfd_gettime = 87,
  utimensat = 88,
  acct = 89,
  capget = 90,
  capset = 91,
  personality = 92,
  exit = 93,
  exit_group = 94,
  waitid = 95,
  set_tid_address = 96,
  unshare = 97,
  futex = 98,
  set_robust_list = 99,
  get_robust_list = 100,
  nanosleep = 101,
  getitimer = 102,
  setitimer = 103,
  kexec_load = 104,
  init_module = 105,
  delete_module = 106,
  timer_create = 107,
  timer_gettime = 108,
  timer_getoverrun = 109,
  timer_settime = 110,
  timer_delete = 111,
  clock_settime = 112,
  clock_gettime = 113,
  clock_getres = 114,
  clock_nanosleep = 115,
  syslog = 116,
  ptrace = 117,
  sched_setparam = 118,
  sched_setscheduler = 119,
  sched_getscheduler = 120,
  sched_getparam = 121,
  sched_setaffinity = 122,
  sched_getaffinity = 123,
  sched_yield = 124,
  sched_get_priority_max = 125,
  sched_get_priority_min = 126,
  sched_rr_get_interval = 127,
  restart_syscall = 128,
  kill = 129,
  tkill = 130,
  tgkill = 131,
  sigaltstack = 132,
  rt_sigsuspend = 133,
  rt_sigaction = 134,
  rt_sigprocmask = 135,
  rt_sigpending = 136,
  rt_sigtimedwait = 137,
  rt_sigqueueinfo = 138,
  rt_sigreturn = 139,
  setpriority = 140,
  getpriority = 141,
  reboot = 142,
  setregid = 143,
  setgid = 144,
  setreuid = 145,
  setuid = 146,
  setresuid = 147,
  getresuid = 148,
  setresgid = 149,
  getresgid = 150,
  setfsuid = 151,
  setfsgid = 152,
  times = 153,
  setpgid = 154,
  getpgid = 155,
  getsid = 156,
  setsid = 157,
  getgroups = 158,
  setgroups = 159,
  uname = 160,
  sethostname = 161,
  setdomainname = 162,
  getrlimit = 163,
  setrlimit = 164,
  getrusage = 165,
  umask = 166,
  prctl = 167,
  getcpu = 168,
  gettimeofday = 169,
  settimeofday = 170,
  adjtimex = 171,
  getpid = 172,
  getppid = 173,
  getuid = 174,
  geteuid = 175,
  getgid = 176,
  getegid = 177,
  gettid = 178,
  sysinfo = 179,
  mq_open = 180,
  mq_unlink = 181,
  mq_timedsend = 182,
  mq_timedreceive = 183,
  mq_notify = 184,
  mq_getsetattr = 185,
  msgget = 186,
  msgctl = 187,
  msgrcv = 188,
  msgsnd = 189,
  semget = 190,
  semctl = 191,
  semtimedop = 192,
  semop = 193,
  shmget = 194,
  shmctl = 195,
  shmat = 196,
  shmdt = 197,
  socket = 198,
  socketpair = 199,
  bind = 200,
  listen = 201,
  accept = 202,
  connect = 203,
  getsockname = 204,
  getpeername = 205,
  sendto = 206,
  recvfrom = 207,
  setsockopt = 208,
  getsockopt = 209,
  shutdown = 210,
  sendmsg = 211,
  recvmsg = 212,
  readahead = 213,
  brk = 214,
  munmap = 215,
  mremap = 216,
  add_key = 217,
  request_key = 218,
  keyctl = 219,
  clone = 220,
  execve = 221,
  mmap = 222,
  fadvise64 = 223,
  swapon = 224,
  swapoff = 225,
  mprotect = 226,
  msync = 227,
  mlock = 228,
  munlock = 229,
  mlockall = 230,
  munlockall = 231,
  mincore = 232,
  madvise = 233,
  remap_file_pages = 234,
  mbind = 235,
  get_mempolicy = 236,
  set_mempolicy = 237,
  migrate_pages = 238,
  move_pages = 239,
  rt_tgsigqueueinfo = 240,
  perf_event_open = 241,
  accept4 = 242,
  recvmmsg = 243,
  wait4 = 260,
  prlimit64 = 261,
  fanotify_init = 262,
  fanotify_mark = 263,
  name_to_handle_at = 264,
  open_by_handle_at = 265,
  clock_adjtime = 266,
  syncfs = 267,
  setns = 268,
  sendmmsg = 269,
  process_vm_readv = 270,
  process_vm_writev = 271,
  kcmp = 272,
  finit_module = 273,
  sched_setattr = 274,
  sched_getattr = 275,
  renameat2 = 276,
  seccomp = 277,
  getrandom = 278,
  memfd_create = 279,
  bpf = 280,
  execveat = 281,
}
}

return nr

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.compat"],"module already exists")sources["syscall.compat"]=([===[-- <pack syscall.compat> --
-- Compatibility wrappers to add more commonality between different systems, plus define common functions from man(3)

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local function init(S) 

local abi, types, c = S.abi, S.types, S.c
local t, pt, s = types.t, types.pt, types.s

local ffi = require "ffi"

local h = require "syscall.helpers"

local istype, mktype, getfd = h.istype, h.mktype, h.getfd

if not S.creat then
  function S.creat(pathname, mode) return S.open(pathname, "CREAT,WRONLY,TRUNC", mode) end
end

function S.nice(inc)
  local prio = S.getpriority("process", 0) -- this cannot fail with these args.
  local ok, err = S.setpriority("process", 0, prio + inc)
  if not ok then return nil, err end
  return S.getpriority("process", 0)
end

-- deprecated in NetBSD and not in some archs for Linux, implement with recvfrom/sendto
function S.recv(fd, buf, count, flags) return S.recvfrom(fd, buf, count, flags, nil, nil) end
function S.send(fd, buf, count, flags) return S.sendto(fd, buf, count, flags, nil, nil) end

-- not a syscall in many systems, defined in terms of sigaction
local sigret = {}
for k, v in pairs(c.SIGACT) do if k ~= "ERR" then sigret[v] = k end end

if S.sigaction then
  function S.signal(signum, handler) -- defined in terms of sigaction, see portability notes in Linux man page
    local oldact = t.sigaction()
    local ok, err = S.sigaction(signum, handler, oldact)
    if not ok then return nil, err end
    local num = tonumber(t.intptr(oldact.handler))
    local ret = sigret[num]
    if ret then return ret end -- return eg "IGN", "DFL" not a function pointer
    return oldact.handler
  end
end

if not S.pause and S.sigsuspend then -- NetBSD and OSX deprecate pause
  function S.pause() return S.sigsuspend(t.sigset()) end
end

if not S.alarm and S.setitimer then -- usually implemented via itimer, although Linux provides alarm as syscall
  function S.alarm(sec)
    local oldit, err = S.setitimer(c.ITIMER.REAL, {0, sec})
    if not oldit then return nil, err end -- alarm not supposed to return errors but hey
    return oldit.value.sec
  end
end

-- non standard names
if not S.umount then S.umount = S.unmount end
if not S.unmount then S.unmount = S.umount end

if S.getdirentries and not S.getdents then -- eg OSX has extra arg
  function S.getdents(fd, buf, len)
    return S.getdirentries(fd, buf, len, nil)
  end
end

-- TODO we should allow utimbuf and also table of times really; this is the very old 1s precision version, NB Linux has syscall
if not S.utime then
  function S.utime(path, actime, modtime)
    local tv
    modtime = modtime or actime
    if actime and modtime then tv = {actime, modtime} end
    return S.utimes(path, tv)
  end
end

-- not a syscall in Linux
if S.utimensat and not S.futimens then
  function S.futimens(fd, times)
    return S.utimensat(fd, nil, times, 0)
  end
end

-- some linux arhcitectures eg ARM do not have a time syscall
if not S.time then
  function S.time(t)
    local tv = S.gettimeofday()
    if t then t[0] = tv.sec end
    return tv.sec
  end
end

-- the utimes, futimes, lutimes are legacy, but OSX/FreeBSD do not support the nanosecond versions
-- we support the legacy versions but do not fake the more precise ones
S.futimes = S.futimes or S.futimens
if S.utimensat and not S.lutimes then
  function S.lutimes(filename, times)
    return S.utimensat("FDCWD", filename, times, "SYMLINK_NOFOLLOW")
  end
end
if S.utimensat and not S.utimes then
  function S.utimes(filename, times)
    return S.utimensat("FDCWD", filename, times, 0)
  end
end

if not S.wait then
  function S.wait(status) return S.waitpid(-1, 0, status) end
end

S.wait3 = function(options, rusage, status) return S.wait4(-1, options, rusage, status) end

if not S.waitpid and S.wait4 then
  S.waitpid = function(pid, options, status) return S.wait4(pid, options, false, status) end
end

if S.wait4 and not S.wait then
  S.wait = function(status) return S.wait4(-1, 0, false, status) end
end

if not S.nanosleep then
  function S.nanosleep(req, rem)
    S.select({}, req)
    if rem then rem.sec, rem.nsec = 0, 0 end -- cannot tell how much time left, could be interrupted by a signal.
    return true
  end
end

-- common libc function
if not S.sleep and S.nanosleep then
  function S.sleep(sec)
    local ok, err, rem = S.nanosleep(sec)
    if not ok then return nil, err end
    if rem then return tonumber(rem.tv_sec) end
    return 0
  end
end

return S

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.methods"],"module already exists")sources["syscall.methods"]=([===[-- <pack syscall.methods> --
-- this creates types with methods
-- cannot do this in types as the functions have not been defined yet (as they depend on types)
-- well we could, by passing in the empty table for S, but this is more modular

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local function init(S)

local abi = S.abi

local c = S.c
local types = S.types
local t, s, pt = types.t, types.s, types.pt

local bit = require "syscall.bit"

local ffi = require "ffi"

local h = require "syscall.helpers"

local getfd, istype, mktype = h.getfd, h.istype, h.mktype

local function metatype(tp, mt)
  if abi.rumpfn then tp = abi.rumpfn(tp) end
  return ffi.metatype(tp, mt)
end

-- easier interfaces to some functions that are in common use TODO new fcntl code should make easier
local function nonblock(fd)
  local fl, err = S.fcntl(fd, c.F.GETFL)
  if not fl then return nil, err end
  fl, err = S.fcntl(fd, c.F.SETFL, c.O(fl, "nonblock"))
  if not fl then return nil, err end
  return true
end

local function block(fd)
  local fl, err = S.fcntl(fd, c.F.GETFL)
  if not fl then return nil, err end
  fl, err = S.fcntl(fd, c.F.SETFL, c.O(fl, "~nonblock"))
  if not fl then return nil, err end
  return true
end

local function tell(fd) return S.lseek(fd, 0, c.SEEK.CUR) end

-- somewhat confusing now we have flock too. I think this comes from nixio.
local function lockf(fd, cmd, len)
  cmd = c.LOCKF[cmd]
  if cmd == c.LOCKF.LOCK then
    return S.fcntl(fd, c.F.SETLKW, {l_type = c.FCNTL_LOCK.WRLCK, l_whence = c.SEEK.CUR, l_start = 0, l_len = len})
  elseif cmd == c.LOCKF.TLOCK then
    return S.fcntl(fd, c.F.SETLK, {l_type = c.FCNTL_LOCK.WRLCK, l_whence = c.SEEK.CUR, l_start = 0, l_len = len})
  elseif cmd == c.LOCKF.ULOCK then
    return S.fcntl(fd, c.F.SETLK, {l_type = c.FCNTL_LOCK.UNLCK, l_whence = c.SEEK.CUR, l_start = 0, l_len = len})
  elseif cmd == c.LOCKF.TEST then
    local ret, err = S.fcntl(fd, c.F.GETLK, {l_type = c.FCNTL_LOCK.WRLCK, l_whence = c.SEEK.CUR, l_start = 0, l_len = len})
    if not ret then return nil, err end
    return ret.l_type == c.FCNTL_LOCK.UNLCK
  end
end

-- methods on an fd
-- note could split, so a socket does not have methods only appropriate for a file; sometimes you do not know what type an fd is
local fdmethods = {'dup', 'dup2', 'dup3', 'read', 'write', 'pread', 'pwrite',
                   'lseek', 'fchdir', 'fsync', 'fdatasync', 'fstat', 'fcntl', 'fchmod',
                   'bind', 'listen', 'connect', 'accept', 'getsockname', 'getpeername',
                   'send', 'sendto', 'recv', 'recvfrom', 'readv', 'writev', 'sendmsg',
                   'recvmsg', 'setsockopt', 'epoll_ctl', 'epoll_wait', 'sendfile', 'getdents',
                   'ftruncate', 'shutdown', 'getsockopt',
                   'inotify_add_watch', 'inotify_rm_watch', 'inotify_read', 'flistxattr',
                   'fsetxattr', 'fgetxattr', 'fremovexattr', 'fxattr', 'splice', 'vmsplice', 'tee',
                   'timerfd_gettime', 'timerfd_settime',
                   'fadvise', 'fallocate', 'posix_fallocate', 'readahead',
                   'sync_file_range', 'fstatfs', 'futimens', 'futimes',
                   'fstatat', 'unlinkat', 'mkdirat', 'mknodat', 'faccessat', 'fchmodat', 'fchown',
                   'fchownat', 'readlinkat', 'setns', 'openat', 'accept4',
                   'preadv', 'pwritev', 'epoll_pwait', 'ioctl', 'flock', 'fpathconf',
                   'grantpt', 'unlockpt', 'ptsname', 'tcgetattr', 'tcsetattr', 'isatty',
                   'tcsendbreak', 'tcdrain', 'tcflush', 'tcflow', 'tcgetsid',
                   'sendmmsg', 'recvmmsg', 'syncfs',
                   'fchflags', 'fchroot', 'fsync_range', 'kevent', 'paccept', 'fktrace', -- bsd only
                   'pdgetpid', 'pdkill' -- freebsd only
                   }
local fmeth = {}
for _, v in ipairs(fdmethods) do fmeth[v] = S[v] end

-- defined above
fmeth.block = block
fmeth.nonblock = nonblock
fmeth.tell = tell
fmeth.lockf = lockf

-- fd not first argument
fmeth.mmap = function(fd, addr, length, prot, flags, offset) return S.mmap(addr, length, prot, flags, fd, offset) end
if S.bindat then fmeth.bindat = function(s, dirfd, addr, addrlen) return S.bindat(dirfd, s, addr, addrlen) end end
if S.connectat then fmeth.connectat = function(s, dirfd, addr, addrlen) return S.connectat(dirfd, s, addr, addrlen) end end

-- allow calling without leading f
fmeth.stat = S.fstat
fmeth.chdir = S.fchdir
fmeth.sync = S.fsync
fmeth.datasync = S.fdatasync
fmeth.chmod = S.fchmod
fmeth.setxattr = S.fsetxattr
fmeth.getxattr = S.gsetxattr
fmeth.truncate = S.ftruncate
fmeth.statfs = S.fstatfs
fmeth.utimens = S.futimens
fmeth.utimes = S.futimes
fmeth.seek = S.lseek
fmeth.chown = S.fchown
fmeth.lock = S.flock
fmeth.pathconf = S.fpathconf
-- netbsd only
fmeth.chflags = S.fchflags
fmeth.chroot = S.fchroot
fmeth.sync_range = S.fsync_range
fmeth.ktrace = S.fktrace
-- no point having fd in name - bsd only
fmeth.extattr_get = S.extattr_get_fd
fmeth.extattr_set = S.extattr_set_fd
fmeth.extattr_delete = S.extattr_delete_fd
fmeth.extattr_list = S.extattr_list_fd

local function nogc(d) return ffi.gc(d, nil) end

fmeth.nogc = nogc

-- sequence number used by netlink messages
fmeth.seq = function(fd)
  fd.sequence = fd.sequence + 1
  return fd.sequence
end

-- TODO note this is not very friendly to user, as will just get EBADF from all calls
function fmeth.close(fd)
  local fileno = getfd(fd)
  if fileno == -1 then return true end -- already closed
  local ok, err = S.close(fileno)
  fd.filenum = -1 -- make sure cannot accidentally close this fd object again
  return ok, err
end

fmeth.getfd = function(fd) return fd.filenum end

t.fd = metatype("struct {int filenum; int sequence;}", {
  __index = fmeth,
  __gc = fmeth.close,
  __new = function(tp, i)
    return istype(tp, i) or ffi.new(tp, i or -1)
  end,
})

S.stdin = t.fd(c.STD.IN):nogc()
S.stdout = t.fd(c.STD.OUT):nogc()
S.stderr = t.fd(c.STD.ERR):nogc()

if S.mq_open then -- TODO better test. TODO support in BSD
local mqmeth = {
  close = fmeth.close,
  nogc = nogc,
  getfd = function(fd) return fd.filenum end,
  getattr = function(mqd, attr)
    attr = attr or t.mq_attr()
    local ok, err = S.mq_getsetattr(mqd, nil, attr)
    if not ok then return nil, err end
    return attr
  end,
  setattr = function(mqd, attr)
    if type(attr) == "number" or type(attr) == "string" then attr = {flags = attr} end -- only flags can be set so allow this
    attr = mktype(t.mq_attr, attr)
    return S.mq_getsetattr(mqd, attr, nil)
  end,
  timedsend = S.mq_timedsend,
  send = function(mqd, msg_ptr, msg_len, msg_prio) return S.mq_timedsend(mqd, msg_ptr, msg_len, msg_prio) end,
  timedreceive = S.mq_timedreceive,
  receive = function(mqd, msg_ptr, msg_len, msg_prio) return S.mq_timedreceive(mqd, msg_ptr, msg_len, msg_prio) end,
}

t.mqd = metatype("struct {mqd_t filenum;}", {
  __index = mqmeth,
  __gc = mqmeth.close,
  __new = function(tp, i)
    return istype(tp, i) or ffi.new(tp, i or -1)
  end,
})
end

-- TODO deal with delete twice issue with delete and gc
t.timer = metatype("struct {timer_t timerid[1];}", {
  __index = {
    gettimerp = function(self) return self.timerid end,
    gettimer = function(self) return self.timerid[0] end,
    settime = S.timer_settime,
    gettime = S.timer_gettime,
    delete = S.timer_delete,
    getoverrun = S.timer_getoverrun,
  },
--__gc = S.timer_delete,
})

if abi.os == "linux" then
  -- Linux performance monitoring reader
  t.perf_reader = metatype("struct {int fd; char *map; size_t map_pages; }", {
    __new = function (ct, fd)
      if not fd then return ffi.new(ct) end
      if istype(t.fd, fd) then fd = fd:nogc():getfd() end
      return ffi.new(ct, fd)
    end,
    __len = function(t) return ffi.sizeof(t) end,
    __gc = function (t) t:close() end,
    __index = {
      close = function(t)
        t:munmap()
        if t.fd > 0 then S.close(t.fd) end
      end,
      munmap = function (t)
        if t.map_pages > 0 then
          S.munmap(t.map, (t.map_pages + 1) * S.getpagesize())
          t.map_pages = 0
        end
      end,
      -- read(2) interface, see `perf_attr.read_format`
      -- @return u64 or an array of u64
      read = function (t, len)
        local rvals = ffi.new('uint64_t [4]')
        local nb, err = S.read(t.fd, rvals, len or ffi.sizeof(rvals))
        if not nb then return nil, err end
        return nb == 8 and rvals[0] or rvals
      end,
      -- mmap(2) interface, see sampling interface (`perf_attr.sample_type` and `perf_attr.mmap`)
      -- first page is metadata page, the others are sample_type dependent
      mmap = function (t, pages)
        t:munmap()
        pages = pages or 8
        local map, err = S.mmap(nil, (pages + 1) * S.getpagesize(), "read, write", "shared", t.fd, 0)
        if not map then return nil, err end
        t.map = map
        t.map_pages = pages
        return pages
      end,
      meta = function (t)
        return t.map_pages > 0 and ffi.cast("struct perf_event_mmap_page *", t.map) or nil
      end,
      -- next() function for __ipairs returning (len, event) pairs
      -- it only retires read events when current event length is passed
      next = function (t, curlen)
        local buffer_size = S.getpagesize() * t.map_pages
        local base = t.map + S.getpagesize()
        local meta = t:meta()
        -- Retire last read event or start iterating
        if curlen then
          meta.data_tail = meta.data_tail + curlen
        end
        -- End of ring buffer, yield
        -- TODO: <insert memory barrier here>
        if meta.data_head == meta.data_tail then
          return
        end
        local e = pt.perf_event_header(base + (meta.data_tail % buffer_size))
        local e_end = base + (meta.data_tail + e.size) % buffer_size;
        -- If the perf event wraps around the ring, we need to make a contiguous copy
        if ffi.cast("uintptr_t", e_end) < ffi.cast("uintptr_t", e) then
          local tmp_e = ffi.new("char [?]", e.size)
          local len = (base + buffer_size) - ffi.cast('char *', e)
          ffi.copy(tmp_e, e, len)
          ffi.copy(tmp_e + len, base, e.size - len)
          e = ffi.cast(ffi.typeof(e), tmp_e)
        end
        return e.size, e
      end,
      -- Various ioctl() wrappers
      ioctl = function(t, cmd, val) return S.ioctl(t.fd, cmd, val or 0) end,
      start = function(t) return t:ioctl("PERF_EVENT_IOC_ENABLE") end,
      stop = function(t) return t:ioctl("PERF_EVENT_IOC_DISABLE") end,
      refresh = function(t) return t:ioctl("PERF_EVENT_IOC_REFRESH") end,
      reset = function(t) return t:ioctl("PERF_EVENT_IOC_RESET") end,
      setfilter = function(t, val) return t:ioctl("PERF_EVENT_IOC_SET_FILTER", val) end,
      setbpf = function(t, fd) return t:ioctl("PERF_EVENT_IOC_SET_BPF", pt.void(fd)) end,
    },
    __ipairs = function(t) return t.next, t, nil end
  })
end

-- TODO reinstate this, more like fd is, hence changes to destroy
--[[
t.aio_context = metatype("struct {aio_context_t ctx;}", {
  __index = {destroy = S.io_destroy, submit = S.io_submit, getevents = S.io_getevents, cancel = S.io_cancel, nogc = nogc},
  __gc = S.io_destroy
})
]]

return S

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.arm64.constants"],"module already exists")sources["syscall.linux.arm64.constants"]=([===[-- <pack syscall.linux.arm64.constants> --
-- arm64 specific constants

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local abi = require "syscall.abi"

local octal = function (s) return tonumber(s, 8) end 

local arch = {}

arch.O = {
  RDONLY    = octal('0000'),
  WRONLY    = octal('0001'),
  RDWR      = octal('0002'),
  ACCMODE   = octal('0003'),
  CREAT     = octal('0100'),
  EXCL      = octal('0200'),
  NOCTTY    = octal('0400'),
  TRUNC     = octal('01000'),
  APPEND    = octal('02000'),
  NONBLOCK  = octal('04000'),
  DSYNC     = octal('010000'),
  ASYNC     = octal('020000'),
  DIRECTORY = octal('040000'),
  NOFOLLOW  = octal('0100000'),
  DIRECT    = octal('0200000'),
  LARGEFILE = octal('0400000'),
  NOATIME   = octal('01000000'),
  CLOEXEC   = octal('02000000'),
  SYNC      = octal('04010000'),
}

return arch
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.types"],"module already exists")sources["syscall.types"]=([===[-- <pack syscall.types> --
-- choose correct types for OS

-- these are either simple ffi types or ffi metatypes for the kernel types
-- plus some Lua metatables for types that cannot be sensibly done as Lua types eg arrays, integers

-- note that some types will be overridden, eg default fd type will have metamethods added

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string, math = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string, math

local function init(c, ostypes, bsdtypes)

local abi = require "syscall.abi"

local ffi = require "ffi"
local bit = require "syscall.bit"

local h = require "syscall.helpers"

local ptt, reviter, mktype, istype, lenfn, lenmt, getfd, newfn
  = h.ptt, h.reviter, h.mktype, h.istype, h.lenfn, h.lenmt, h.getfd, h.newfn
local addtype, addtype_var, addtype_fn, addraw2 = h.addtype, h.addtype_var, h.addtype_fn, h.addraw2
local ntohl, ntohl, ntohs, htons = h.ntohl, h.ntohl, h.ntohs, h.htons
local split, trim, strflag = h.split, h.trim, h.strflag
local align = h.align

local types = {t = {}, pt = {}, s = {}, ctypes = {}}

local t, pt, s, ctypes = types.t, types.pt, types.s, types.ctypes

local sharedtypes = require "syscall.shared.types"

for k, v in pairs(sharedtypes.t) do t[k] = v end
for k, v in pairs(sharedtypes.pt) do pt[k] = v end
for k, v in pairs(sharedtypes.s) do s[k] = v end
for k, v in pairs(sharedtypes.ctypes) do ctypes[k] = v end

local mt = {} -- metatables

-- generic types

local voidp = ffi.typeof("void *")

function pt.void(x)
  return ffi.cast(voidp, x)
end

local addtypes = {
  size = "size_t",
  ssize = "ssize_t",
  mode = "mode_t",
  dev = "dev_t",
  off = "off_t",
  uid = "uid_t",
  gid = "gid_t",
  pid = "pid_t",
  in_port = "in_port_t",
  sa_family = "sa_family_t",
  socklen = "socklen_t",
  id = "id_t",
  daddr = "daddr_t",
  time = "time_t",
  clock = "clock_t",
  nlink = "nlink_t",
  ino = "ino_t",
  nfds = "nfds_t",
}

-- note we cannot add any metatable, as may be declared in os and rump, so not even lenmt added
for k, v in pairs(addtypes) do addtype(types, k, v) end

t.socklen1 = ffi.typeof("socklen_t[1]")
t.off1 = ffi.typeof("off_t[1]")
t.uid1 = ffi.typeof("uid_t[1]")
t.gid1 = ffi.typeof("gid_t[1]")

local errsyms = {} -- reverse lookup by number
local errnames = {} -- lookup error message by number
for k, v in pairs(c.E) do
  errsyms[v] = k
  errnames[v] = assert(c.errornames[k], "missing error name " .. k)
end

for k, v in pairs(c.EALIAS or {}) do
  c.E[k] = v
end
c.EALIAS = nil

mt.error = {
  __tostring = function(e) return errnames[e.errno] end,
  __index = function(e, k)
    if k == 'sym' then return errsyms[e.errno] end
    if k == 'lsym' then return errsyms[e.errno]:lower() end
    if c.E[k] then return c.E[k] == e.errno end
    error("invalid error " .. k)
  end,
  __new = function(tp, errno)
    if not errno then errno = ffi.errno() end
    return ffi.new(tp, errno)
  end,
}

t.error = ffi.metatype("struct {int errno;}", mt.error)

mt.timeval = {
  index = {
    time = function(tv) return tonumber(tv.tv_sec) + tonumber(tv.tv_usec) / 1000000 end,
    sec = function(tv) return tonumber(tv.tv_sec) end,
    usec = function(tv) return tonumber(tv.tv_usec) end,
  },
  newindex = {
    time = function(tv, v)
      local i, f = math.modf(v)
      tv.tv_sec, tv.tv_usec = i, math.floor(f * 1000000)
    end,
    sec = function(tv, v) tv.tv_sec = v end,
    usec = function(tv, v) tv.tv_usec = v end,
  },
  __new = function(tp, v)
    if not v then v = {0, 0} end
    if istype(t.timespec, v) then v = {v.tv_sec, math.floor(v.tv_nsec / 1000)} end
    if type(v) == "table" then
      if v.tv_nsec then -- compat with timespec
        v.tv_usec = math.floor(v.tv_nsec / 1000)
        v.tv_nsec = 0
      end
    end
    if type(v) ~= "number" then return ffi.new(tp, v) end
    local ts = ffi.new(tp)
    ts.time = v
    return ts
  end,
  __tostring = function(tv) return tostring(tv.time) end,
}

addtype(types, "timeval", "struct timeval", mt.timeval)

mt.timespec = {
  index = {
    time = function(tv) return tonumber(tv.tv_sec) + tonumber(tv.tv_nsec) / 1000000000 end,
    sec = function(tv) return tonumber(tv.tv_sec) end,
    nsec = function(tv) return tonumber(tv.tv_nsec) end,
  },
  newindex = {
    time = function(tv, v)
      local i, f = math.modf(v)
      tv.tv_sec, tv.tv_nsec = i, math.floor(f * 1000000000)
    end,
    sec = function(tv, v) tv.tv_sec = v end,
    nsec = function(tv, v) tv.tv_nsec = v end,
  },
  __new = function(tp, v)
    if not v then v = {0, 0} end
    if istype(t.timeval, v) then v = {v.tv_sec, v.tv_usec * 1000} end
    if type(v) == "table" then
      if v.tv_usec then -- compat with timespec TODO add to methods, and use standard new allocation function?
        v.tv_nsec = v.tv_usec * 1000
        v.tv_usec = 0
      end
    end
    if type(v) ~= "number" then return ffi.new(tp, v) end
    local ts = ffi.new(tp)
    ts.time = v
    return ts
  end,
  __tostring = function(tv) return tostring(tv.time) end,
}

addtype(types, "timespec", "struct timespec", mt.timespec)

-- array so cannot just add metamethods
addraw2(types, "timeval2_raw", "struct timeval")
t.timeval2 = function(tv1, tv2)
  if ffi.istype(t.timeval2_raw, tv1) then return tv1 end
  if type(tv1) == "table" then tv1, tv2 = tv1[1], tv1[2] end
  local tv = t.timeval2_raw()
  if tv1 then tv[0] = t.timeval(tv1) end
  if tv2 then tv[1] = t.timeval(tv2) end
  return tv
end

-- array so cannot just add metamethods
addraw2(types, "timespec2_raw", "struct timespec")
t.timespec2 = function(ts1, ts2)
  if ffi.istype(t.timespec2_raw, ts1) then return ts1 end
  if type(ts1) == "table" then ts1, ts2 = ts1[1], ts1[2] end
  local ts = t.timespec2_raw()
  if ts1 then if type(ts1) == 'string' then ts[0].tv_nsec = c.UTIME[ts1] else ts[0] = t.timespec(ts1) end end
  if ts2 then if type(ts2) == 'string' then ts[1].tv_nsec = c.UTIME[ts2] else ts[1] = t.timespec(ts2) end end
  return ts
end

mt.groups = {
  __index = function(g, k)
    return g.list[k - 1]
  end,
  __newindex = function(g, k, v)
    g.list[k - 1] = v
  end,
  __new = function(tp, gs)
    if type(gs) == 'number' then return ffi.new(tp, gs, gs) end
    return ffi.new(tp, #gs, #gs, gs)
  end,
  __len = function(g) return g.count end,
}

addtype_var(types, "groups", "struct {int count; gid_t list[?];}", mt.groups)

-- signal set handlers
local function sigismember(set, sig)
  local d = bit.rshift(sig - 1, 5) -- always 32 bits
  return bit.band(set.sig[d], bit.lshift(1, (sig - 1) % 32)) ~= 0
end

local function sigemptyset(set)
  for i = 0, s.sigset / 4 - 1 do
    if set.sig[i] ~= 0 then return false end
  end
  return true
end

local function sigaddset(set, sig)
  set = t.sigset(set)
  local d = bit.rshift(sig - 1, 5)
  set.sig[d] = bit.bor(set.sig[d], bit.lshift(1, (sig - 1) % 32))
  return set
end

local function sigdelset(set, sig)
  set = t.sigset(set)
  local d = bit.rshift(sig - 1, 5)
  set.sig[d] = bit.band(set.sig[d], bit.bnot(bit.lshift(1, (sig - 1) % 32)))
  return set
end

local function sigaddsets(set, sigs) -- allow multiple
  if type(sigs) ~= "string" then return sigaddset(set, sigs) end
  set = t.sigset(set)
  local a = split(",", sigs)
  for i, v in ipairs(a) do
    local s = trim(v)
    local sig = c.SIG[s]
    if not sig then error("invalid signal: " .. v) end -- don't use this format if you don't want exceptions, better than silent ignore
    sigaddset(set, sig)
  end
  return set
end

local function sigdelsets(set, sigs) -- allow multiple
  if type(sigs) ~= "string" then return sigdelset(set, sigs) end
  set = t.sigset(set)
  local a = split(",", sigs)
  for i, v in ipairs(a) do
    local s = trim(v)
    local sig = c.SIG[s]
    if not sig then error("invalid signal: " .. v) end -- don't use this format if you don't want exceptions, better than silent ignore
    sigdelset(set, sig)
  end
  return set
end

mt.sigset = {
  __index = function(set, k)
    if k == 'add' then return sigaddsets end
    if k == 'del' then return sigdelsets end
    if k == 'isemptyset' then return sigemptyset(set) end
    local sig = c.SIG[k]
    if sig then return sigismember(set, sig) end
    error("invalid index " .. k)
  end,
  __new = function(tp, str)
    if ffi.istype(tp, str) then return str end
    if not str then return ffi.new(tp) end
    local f = ffi.new(tp)
    local a = split(",", str)
    for i, v in ipairs(a) do
      local st = trim(v)
      local sig = c.SIG[st]
      if not sig then error("invalid signal: " .. v) end -- don't use this format if you don't want exceptions, better than silent ignore
      local d = bit.rshift(sig - 1, 5) -- always 32 bits
      f.sig[d] = bit.bor(f.sig[d], bit.lshift(1, (sig - 1) % 32))
    end
    return f
  end,
}

addtype(types, "sigset", "sigset_t", mt.sigset)

mt.sigval = {
  index = {
    int = function(self) return self.sival_int end,
    ptr = function(self) return self.sival_ptr end,
  },
  newindex = {
    int = function(self, v) self.sival_int = v end,
    ptr = function(self, v) self.sival_ptr = v end,
  },
  __new = function(tp, v)
    if not v or type(v) == "table" then return newfn(tp, v) end
    local siv = ffi.new(tp)
    if type(v) == "number" then siv.int = v else siv.ptr = v end
    return siv
  end,
}

addtype(types, "sigval", "union sigval", mt.sigval) -- not always called sigval_t

-- cmsg functions, try to hide some of this nasty stuff from the user
local cmsgtype = "struct cmsghdr"
if abi.rumpfn then cmsgtype = abi.rumpfn(cmsgtype) end
local cmsg_hdrsize = ffi.sizeof(ffi.typeof(cmsgtype), 0)
local voidalign = ffi.alignof(ffi.typeof("void *"))
local function cmsg_align(len) return align(len, voidalign) end -- TODO double check this is correct for all OSs
local cmsg_ahdr = cmsg_align(cmsg_hdrsize)
--local function cmsg_space(len) return cmsg_ahdr + cmsg_align(len) end
local function cmsg_len(len) return cmsg_ahdr + len end

-- TODO move this to sockopt file, like set/getsockopt as very similar mapping
local typemap = {
  [c.SOL.SOCKET] = c.SCM,
}

-- TODO add the othes here, they differ by OS
if c.SOL.IP then typemap[c.SOL.IP] = c.IP end

mt.cmsghdr = {
  __index = {
    len = function(self) return tonumber(self.cmsg_len) end,
    data = function(self) return self.cmsg_data end,
    datalen = function(self) return self:len() - cmsg_ahdr end,
    hdrsize = function(self) return cmsg_hdrsize end, -- constant, but better to have it here
    align = function(self) return cmsg_align(self:len()) end,
    fds = function(self)
      if self.cmsg_level == c.SOL.SOCKET and self.cmsg_type == c.SCM.RIGHTS then
        local fda = pt.int(self:data())
        local fdc = bit.rshift(self:datalen(), 2) -- shift by int size
        local i = 0
        return function()
          if i < fdc then
            local fd = t.fd(fda[i])
            i = i + 1
            return fd
          end
        end
      else
        return function() end
      end
    end,
    credentials = function(self) -- TODO Linux only, NetBSD uses SCM_CREDS
      if self.cmsg_level == c.SOL.SOCKET and self.cmsg_type == c.SCM.CREDENTIALS then
        local cred = pt.ucred(self:data())
        return cred.pid, cred.uid, cred.gid
      else
        return nil, "cmsg does not contain credentials"
      end
    end,
    setdata = function(self, data, datalen)
      ffi.copy(self:data(), data, datalen or #data)
    end,
    setfd = function(self, fd) -- single fd
      local int = pt.int(self:data())
      int[0] = getfd(fd)
    end,
    setfds = function(self, fds) -- general case, note does not check size
      if type(fds) == "number" or fds.getfd then return self:setfd(fds) end
      local int = pt.int(self:data())
      local off = 0
      for _, v in ipairs(fds) do
        int[off] = getfd(v)
        off = off + 1
      end
    end,
  },
  __new = function (tp, level, scm, data, data_size)
    if not data then data_size = data_size or 0 end
    level = c.SOL[level]
    if typemap[level] then scm = typemap[level][scm] end
    if level == c.SOL.SOCKET and scm == c.SCM.RIGHTS then
      if type(data) == "number" then -- slightly odd but useful interfaces for fds - TODO document
        data_size = data * s.int
        data = nil
      elseif type(data) == "table" then data_size = #data * s.int end
    end
    data_size = data_size or #data
    local self = ffi.new(tp, data_size, {
      cmsg_len = cmsg_len(data_size),
      cmsg_level = level,
      cmsg_type = scm,
    })
    if data and (level == c.SOL.SOCKET and scm == c.SCM.RIGHTS) then
      self:setfds(data)
    elseif data then
      self:setdata(data, data_size)
    end
    return self
  end,
}

addtype_var(types, "cmsghdr", "struct cmsghdr", mt.cmsghdr)

-- msg_control is a bunch of cmsg structs, but these are all different lengths, as they have variable size arrays

-- these functions also take and return a raw char pointer to msg_control, to make life easier, as well as the cast cmsg
local function cmsg_firsthdr(msg)
  local mc = msg.msg_control
  local cmsg = pt.cmsghdr(mc)
  if tonumber(msg.msg_controllen) < cmsg:hdrsize() then return nil end -- hdrsize is a constant, so does not matter if invalid struct
  return mc, cmsg
end

local function cmsg_nxthdr(msg, buf, cmsg)
  if tonumber(cmsg.cmsg_len) < cmsg:hdrsize() then return nil end -- invalid cmsg
  buf = pt.char(buf)
  local msg_control = pt.char(msg.msg_control)
  buf = buf + cmsg:align() -- find next cmsg
  if buf + cmsg:hdrsize() > msg_control + msg.msg_controllen then return nil end -- header would not fit
  cmsg = pt.cmsghdr(buf)
  if buf + cmsg:align() > msg_control + msg.msg_controllen then return nil end -- whole cmsg would not fit
  return buf, cmsg
end

local function cmsg_iter(msg, last_msg_control)
  local msg_control
  if last_msg_control == nil then -- First iteration
    msg_control = pt.char(msg.msg_control)
  else
    local last_cmsg = pt.cmsghdr(last_msg_control)
    msg_control = last_msg_control + last_cmsg:align() -- find next cmsg
  end
  local end_offset = pt.char(msg.msg_control) + msg.msg_controllen
  local cmsg = pt.cmsghdr(msg_control)
  if msg_control + cmsg:hdrsize() > end_offset then return nil end -- header would not fit
  if msg_control + cmsg:align() > end_offset then return nil end -- whole cmsg would not fit
  return msg_control, cmsg
end
local function cmsg_headers(msg)
  return cmsg_iter, msg, nil
end

mt.msghdr = {
  __index = {
    cmsg_firsthdr = cmsg_firsthdr,
    cmsg_nxthdr = cmsg_nxthdr,
    cmsgs = cmsg_headers,
    -- TODO add iov
  },
  newindex = {
    name = function(m, n)
      m.msg_name, m.msg_namelen = n, #n
    end,
    iov = function(m, io)
      if ffi.istype(t.iovec, io) then -- single iovec
        m.msg_iov, m.msg_iovlen = io, 1
      else -- iovecs
        m.msg_iov, m.msg_iovlen = io.iov, #io
      end
    end,
    control = function(m, buf)
      if buf then m.msg_control, m.msg_controllen = buf, #buf else m.msg_control, m.msg_controllen = nil, 0 end
    end,
  },
  __new = newfn,
}

addtype(types, "msghdr", "struct msghdr", mt.msghdr)

mt.pollfd = {
  index = {
    getfd = function(pfd) return pfd.fd end,
  }
}

for k, v in pairs(c.POLL) do mt.pollfd.index[k] = function(pfd) return bit.band(pfd.revents, v) ~= 0 end end

addtype(types, "pollfd", "struct pollfd", mt.pollfd)

mt.pollfds = {
  __len = function(p) return p.count end,
  __new = function(tp, ps)
    if type(ps) == 'number' then return ffi.new(tp, ps, ps) end
    local count = #ps
    local fds = ffi.new(tp, count, count)
    for n = 1, count do -- TODO ideally we use ipairs on both arrays/tables
      fds.pfd[n - 1].fd = ps[n].fd:getfd()
      fds.pfd[n - 1].events = c.POLL[ps[n].events]
      fds.pfd[n - 1].revents = 0
    end
    return fds
  end,
  __ipairs = function(p) return reviter, p.pfd, p.count end
}

addtype_var(types, "pollfds", "struct {int count; struct pollfd pfd[?];}", mt.pollfds)

mt.rusage = {
  index = {
    utime    = function(ru) return ru.ru_utime end,
    stime    = function(ru) return ru.ru_stime end,
    maxrss   = function(ru) return tonumber(ru.ru_maxrss) end,
    ixrss    = function(ru) return tonumber(ru.ru_ixrss) end,
    idrss    = function(ru) return tonumber(ru.ru_idrss) end,
    isrss    = function(ru) return tonumber(ru.ru_isrss) end,
    minflt   = function(ru) return tonumber(ru.ru_minflt) end,
    majflt   = function(ru) return tonumber(ru.ru_majflt) end,
    nswap    = function(ru) return tonumber(ru.ru_nswap) end,
    inblock  = function(ru) return tonumber(ru.ru_inblock) end,
    oublock  = function(ru) return tonumber(ru.ru_oublock) end,
    msgsnd   = function(ru) return tonumber(ru.ru_msgsnd) end,
    msgrcv   = function(ru) return tonumber(ru.ru_msgrcv) end,
    nsignals = function(ru) return tonumber(ru.ru_nsignals) end,
    nvcsw    = function(ru) return tonumber(ru.ru_nvcsw) end,
    nivcsw   = function(ru) return tonumber(ru.ru_nivcsw) end,
  },
  print = {"utime", "stime", "maxrss", "ixrss", "idrss", "isrss", "minflt", "majflt", "nswap",
           "inblock", "oublock", "msgsnd", "msgrcv", "nsignals", "nvcsw", "nivcsw"},
}

addtype(types, "rusage", "struct rusage", mt.rusage)

local function itnormal(v)
  if not v then v = {{0, 0}, {0, 0}} end
  if v.interval then
    v.it_interval = v.interval
    v.interval = nil
  end
  if v.value then
    v.it_value = v.value
    v.value = nil
  end
  if not v.it_interval then
    v.it_interval = v[1]
    v[1] = nil
  end
  if not v.it_value then
    v.it_value = v[2]
    v[2] = nil
  end
  return v
end

mt.itimerspec = {
  index = {
    interval = function(it) return it.it_interval end,
    value = function(it) return it.it_value end,
  },
  __new = function(tp, v)
    v = itnormal(v)
    v.it_interval = istype(t.timespec, v.it_interval) or t.timespec(v.it_interval)
    v.it_value = istype(t.timespec, v.it_value) or t.timespec(v.it_value)
    return ffi.new(tp, v)
  end,
}

addtype(types, "itimerspec", "struct itimerspec", mt.itimerspec)

mt.itimerval = {
  index = {
    interval = function(it) return it.it_interval end,
    value = function(it) return it.it_value end,
  },
  __new = function(tp, v)
    v = itnormal(v)
    v.it_interval = istype(t.timeval, v.it_interval) or t.timeval(v.it_interval)
    v.it_value = istype(t.timeval, v.it_value) or t.timeval(v.it_value)
    return ffi.new(tp, v)
  end,
}

addtype(types, "itimerval", "struct itimerval", mt.itimerval)

mt.macaddr = {
  __tostring = function(m)
    local hex = {}
    for i = 1, 6 do
      hex[i] = string.format("%02x", m.mac_addr[i - 1])
    end
    return table.concat(hex, ":")
  end,
  __new = function(tp, str)
    local mac = ffi.new(tp)
    if str then
      for i = 1, 6 do
        local n = tonumber(str:sub(i * 3 - 2, i * 3 - 1), 16) -- TODO more checks on syntax
        mac.mac_addr[i - 1] = n
      end
    end
    return mac
  end,
}

addtype(types, "macaddr", "struct {uint8_t mac_addr[6];}", mt.macaddr)

-- include OS specific types
types = ostypes.init(types)
if bsdtypes then types = bsdtypes.init(c, types) end

-- define dents type if dirent is defined
if t.dirent then
  t.dirents = function(buf, size) -- buf should be char*
    local d, i = nil, 0
    return function() -- TODO work out if possible to make stateless
      if size > 0 and not d then
        d = pt.dirent(buf)
        i = i + d.d_reclen
        return d
      end
      while i < size do
        d = pt.dirent(pt.char(d) + d.d_reclen)
        i = i + d.d_reclen
        if d.ino ~= 0 then return d end -- some systems use ino = 0 for deleted files before removed eg OSX; it is never valid
      end
      return nil
    end
  end
end

return types

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.libc"],"module already exists")sources["syscall.libc"]=([===[-- <pack syscall.libc> --
-- things that are libc only, not syscalls
-- this file will not be included if not running with libc eg for rump

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local function init(S)

local c = S.c
local types = S.types
local t, s, pt = types.t, types.s, types.pt

local ffi = require "ffi"

local h = require "syscall.helpers"

local zeropointer = pt.void(0)

local function retbool(ret)
  if ret == -1 then return nil, t.error() end
  return true
end

-- if getcwd not defined, fall back to libc implementation (currently osx, freebsd)
-- freebsd implementation fairly complex
if not S.getcwd then
ffi.cdef [[
char *getcwd(char *buf, size_t size);
]]
  function S.getcwd(buf, size)
    size = size or c.PATH_MAX
    buf = buf or t.buffer(size)
    local ret = ffi.C.getcwd(buf, size)
    if ret == zeropointer then return nil, t.error() end
    return ffi.string(buf)
  end
end

-- in NetBSD, OSX exit defined in libc, no _exit syscall available
if not S.exit then
  function S.exit(status) return retbool(ffi.C.exit(c.EXIT[status or 0])) end
end

if not S._exit then
  S._exit = S.exit -- provide syscall exit if possible
end

ffi.cdef [[
int __cxa_atexit(void (*func) (void *), void * arg, void * dso_handle);
]]

local function inlibc(k) return ffi.C[k] end

if pcall(inlibc, "exit") and pcall(inlibc, "__cxa_atexit") then
  function S.exit(status) return retbool(ffi.C.exit(c.EXIT[status or 0])) end -- use libc exit instead
  function S.atexit(f) return retbool(ffi.C.__cxa_atexit(f, nil, nil)) end
end

--[[ -- need more types defined
int uname(struct utsname *buf);
time_t time(time_t *t);
]]

--[[
int gethostname(char *name, size_t namelen);
int sethostname(const char *name, size_t len);
int getdomainname(char *name, size_t namelen);
int setdomainname(const char *name, size_t len);
--]]

-- environment
ffi.cdef [[
// environment
extern char **environ;

int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
int clearenv(void);
char *getenv(const char *name);
]]

function S.environ() -- return whole environment as table
  local environ = ffi.C.environ
  if not environ then return nil end
  local r = {}
  local i = 0
  while environ[i] ~= zeropointer do
    local e = ffi.string(environ[i])
    local eq = e:find('=')
    if eq then
      r[e:sub(1, eq - 1)] = e:sub(eq + 1)
    end
    i = i + 1
  end
  return r
end

function S.getenv(name)
  return S.environ()[name]
end
function S.unsetenv(name) return retbool(ffi.C.unsetenv(name)) end
function S.setenv(name, value, overwrite)
  overwrite = h.booltoc(overwrite) -- allows nil as false/0
  return retbool(ffi.C.setenv(name, value, overwrite))
end
function S.clearenv() return retbool(ffi.C.clearenv()) end

S.errno = ffi.errno

return S

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.bit"],"module already exists")sources["syscall.bit"]=([===[-- <pack syscall.bit> --
-- abstract different bit libraries in different lua versions

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

-- TODO add 64 bit operations here

local ffi = require "ffi"

local abi = require "syscall.abi"

local ok, bit

ok, bit = pcall(require, "bit")

if not ok then
  ok, bit = pcall(require, "bit32")

  local int32 = ffi.typeof("int32_t")

  if not ok then error("no suitable bit library found") end

  -- fixups to make compatible with luajit
  bit.tobit = function(x) return tonumber(int32(x)) end
  bit.bswap = function(x)
    return bit.bor(bit.lshift(bit.extract(x, 0, 8), 24),
                     bit.lshift(bit.extract(x, 8, 8), 16),
                     bit.lshift(bit.extract(x, 16, 8), 8),
                                bit.extract(x, 24, 8))
    end
end

-- 64 to 32 bit conversions via unions TODO use meth not object? tidy up
local mt
if abi.le then
mt = {
  __index = {
    to32 = function(u) return u.i32[1], u.i32[0] end,
    from32 = function(u, a, b) u.i32[1], u.i32[0] = a, b end,
  }
}
else
mt = {
  __index = {
    to32 = function(u) return u.i32[0], u.i32[1] end,
    from32 = function(u, a, b) u.i32[0], u.i32[1] = a, b end,
  }
}
end

mt.__new = function(tp, x)
  local n = ffi.new(tp)
  n.i64 = x or 0
  return n
end

local i6432 = ffi.metatype("union {int64_t i64; int32_t i32[2];}", mt)
local u6432 = ffi.metatype("union {uint64_t i64; uint32_t i32[2];}", mt)

bit.i6432 = function(x) return i6432(x):to32() end
bit.u6432 = function(x) return u6432(x):to32() end

-- initial 64 bit ops. TODO for luajit 2.1 these are not needed, as accepts 64 bit cdata
function bit.bor64(a, b, ...)
  local aa, bb, cc = i6432(a), i6432(b), i6432()
  cc.i32[0], cc.i32[1] = bit.bor(aa.i32[0], bb.i32[0]), bit.bor(aa.i32[1], bb.i32[1])
  if select('#', ...) > 0 then return bit.bor64(cc.i64, ...) end
  return cc.i64
end

function bit.band64(a, b, ...)
  local aa, bb, cc = i6432(a), i6432(b), i6432()
  cc.i32[0], cc.i32[1] = bit.band(aa.i32[0], bb.i32[0]), bit.band(aa.i32[1], bb.i32[1])
  if select('#', ...) > 0 then return bit.band64(cc.i64, ...) end
  return cc.i64
end

function bit.lshift64(a, n)
  if n == 0 then return a end
  local aa, bb = i6432(a), i6432(0)
  local ah, al = aa:to32()
  local bl, bh = 0, 0
  if n < 32 then
    bh, bl = bit.lshift(ah, n), bit.lshift(al, n)
    bh = bit.bor(bh, bit.rshift(al, 32 - n))
  else
    bh, bl = bit.lshift(al, n - 32), 0
  end
  bb:from32(bh, bl)
  return bb.i64
end

function bit.rshift64(a, n)
  if n == 0 then return a end
  local aa, bb = i6432(a), i6432(0)
  local ah, al = aa:to32()
  local bl, bh = 0, 0
  if n < 32 then
    bh, bl = bit.rshift(ah, n), bit.rshift(al, n)
    bl = bit.bor(bl, bit.lshift(ah, 32 - n))
  else
    bh, bl = 0, bit.rshift(ah, n - 32)
  end
  bb:from32(bh, bl)
  return bb.i64
end

return bit
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.arm.nr"],"module already exists")sources["syscall.linux.arm.nr"]=([===[-- <pack syscall.linux.arm.nr> --
-- arm syscall numbers

-- eabi only

local nr = {
  zeropad = true,
  SYS = {
  restart_syscall  = 0,
  exit             = 1,
  fork             = 2,
  read             = 3,
  write            = 4,
  open             = 5,
  close            = 6,
  creat            = 8,
  link             = 9,
  unlink           = 10,
  execve           = 11,
  chdir      	   = 12,
  mknod            = 14,
  chmod            = 15,
  lchown           = 16,
  lseek            = 19,
  getpid           = 20,
  mount            = 21,
  setuid           = 23,
  getuid           = 24,
  ptrace           = 26,
  pause            = 29,
  access           = 33,
  nice             = 34,
  sync             = 36,
  kill             = 37,
  rename           = 38,
  mkdir            = 39,
  rmdir            = 40,
  dup              = 41,
  pipe             = 42,
  times            = 43,
  brk              = 45,
  setgid           = 46,
  getgid           = 47,
  geteuid          = 49,
  getegid          = 50,
  acct             = 51,
  umount2          = 52,
  ioctl            = 54,
  fcntl            = 55,
  setpgid          = 57,
  umask            = 60,
  chroot           = 61,
  ustat            = 62,
  dup2             = 63,
  getppid          = 64,
  getpgrp          = 65,
  setsid           = 66,
  sigaction        = 67,
  setreuid         = 70,
  setregid         = 71,
  sigsuspend       = 72,
  sigpending       = 73,
  sethostname      = 74,
  setrlimit        = 75,
  getrusage        = 77,
  gettimeofday     = 78,
  settimeofday     = 79,
  getgroups        = 80,
  setgroups        = 81,
  symlink          = 83,
  readlink         = 85,
  uselib           = 86,
  swapon           = 87,
  reboot           = 88,
  munmap           = 91,
  truncate         = 92,
  ftruncate        = 93,
  fchmod           = 94,
  fchown           = 95,
  getpriority      = 96,
  setpriority      = 97,
  statfs           = 99,
  fstatfs          = 100,
  syslog           = 103,
  setitimer        = 104,
  getitimer        = 105,
  stat             = 106,
  lstat            = 107,
  fstat            = 108,
  vhangup          = 111,
  wait4            = 114,
  swapoff          = 115,
  sysinfo          = 116,
  fsync            = 118,
  sigreturn        = 119,
  clone            = 120,
  setdomainname    = 121,
  uname            = 122,
  adjtimex         = 124,
  mprotect         = 125,
  sigprocmask      = 126,
  init_module      = 128,
  delete_module    = 129,
  quotactl         = 131,
  getpgid          = 132,
  fchdir           = 133,
  bdflush          = 134,
  sysfs            = 135,
  personality      = 136,
  setfsuid         = 138,
  setfsgid         = 139,
  _llseek          = 140,
  getdents         = 141,
  _newselect       = 142,
  flock            = 143,
  msync            = 144,
  readv            = 145,
  writev           = 146,
  getsid           = 147,
  fdatasync        = 148,
  _sysctl          = 149,
  mlock            = 150,
  munlock          = 151,
  mlockall         = 152,
  munlockall       = 153,
  sched_setparam   = 154,
  sched_getparam   = 155,
  sched_setscheduler = 156,
  sched_getscheduler = 157,
  sched_yield      = 158,
  sched_get_priority_max = 159,
  sched_get_priority_min = 160,
  sched_rr_get_interval  = 161,
  nanosleep        = 162,
  mremap           = 163,
  setresuid        = 164,
  getresuid        = 165,
  poll             = 168,
  nfsservctl       = 169,
  setresgid        = 170,
  getresgid        = 171,
  prctl            = 172,
  rt_sigreturn     = 173,
  rt_sigaction     = 174,
  rt_sigprocmask   = 175,
  rt_sigpending    = 176,
  rt_sigtimedwait  = 177,
  rt_sigqueueinfo  = 178,
  rt_sigsuspend    = 179,
  pread64          = 180,
  pwrite64         = 181,
  chown            = 182,
  getcwd           = 183,
  capget           = 184,
  capset           = 185,
  sigaltstack      = 186,
  sendfile         = 187,
  vfork            = 190,
  ugetrlimit       = 191,
  mmap2            = 192,
  truncate64       = 193,
  ftruncate64      = 194,
  stat64           = 195,
  lstat64          = 196,
  fstat64          = 197,
  lchown32         = 198,
  getuid32         = 199,
  getgid32         = 200,
  geteuid32        = 201,
  getegid32        = 202,
  setreuid32       = 203,
  setregid32       = 204,
  getgroups32      = 205,
  setgroups32      = 206,
  fchown32         = 207,
  setresuid32      = 208,
  getresuid32      = 209,
  setresgid32      = 210,
  getresgid32      = 211,
  chown32          = 212,
  setuid32         = 213,
  setgid32         = 214,
  setfsuid32       = 215,
  setfsgid32       = 216,
  getdents64       = 217,
  pivot_root       = 218,
  mincore          = 219,
  madvise          = 220,
  fcntl64          = 221,
  gettid           = 224,
  readahead        = 225,
  setxattr         = 226,
  lsetxattr        = 227,
  fsetxattr        = 228,
  getxattr         = 229,
  lgetxattr        = 230,
  fgetxattr        = 231,
  listxattr        = 232,
  llistxattr       = 233,
  flistxattr       = 234,
  removexattr      = 235,
  lremovexattr     = 236,
  fremovexattr     = 237,
  tkill            = 238,
  sendfile64       = 239,
  futex            = 240,
  sched_setaffinity= 241,
  sched_getaffinity= 242,
  io_setup         = 243,
  io_destroy       = 244,
  io_getevents     = 245,
  io_submit        = 246,
  io_cancel        = 247,
  exit_group       = 248,
  lookup_dcookie   = 249,
  epoll_create     = 250,
  epoll_ctl        = 251,
  epoll_wait       = 252,
  remap_file_pages = 253,
  set_tid_address  = 256,
  timer_create     = 257,
  timer_settime    = 258,
  timer_gettime    = 259,
  timer_getoverrun = 260,
  timer_delete     = 261,
  clock_settime    = 262,
  clock_gettime    = 263,
  clock_getres     = 264,
  clock_nanosleep  = 265,
  statfs64         = 266,
  fstatfs64        = 267,
  tgkill           = 268,
  utimes           = 269,
  fadvise64_64     = 270,
  pciconfig_iobase = 271,
  pciconfig_read   = 272,
  pciconfig_write  = 273,
  mq_open          = 274,
  mq_unlink        = 275,
  mq_timedsend     = 276,
  mq_timedreceive  = 277,
  mq_notify        = 278,
  mq_getsetattr    = 279,
  waitid           = 280,
  socket           = 281,
  bind             = 282,
  connect          = 283,
  listen           = 284,
  accept           = 285,
  getsockname      = 286,
  getpeername      = 287,
  socketpair       = 288,
  send             = 289,
  sendto           = 290,
  recv             = 291,
  recvfrom         = 292,
  shutdown         = 293,
  setsockopt       = 294,
  getsockopt       = 295,
  sendmsg          = 296,
  recvmsg          = 297,
  semop            = 298,
  semget           = 299,
  semctl           = 300,
  msgsnd           = 301,
  msgrcv           = 302,
  msgget           = 303,
  msgctl           = 304,
  shmat            = 305,
  shmdt            = 306,
  shmget           = 307,
  shmctl           = 308,
  add_key          = 309,
  request_key      = 310,
  keyctl           = 311,
  semtimedop       = 312,
  vserver          = 313,
  ioprio_set       = 314,
  ioprio_get       = 315,
  inotify_init     = 316,
  inotify_add_watch= 317,
  inotify_rm_watch = 318,
  mbind            = 319,
  get_mempolicy    = 320,
  set_mempolicy    = 321,
  openat           = 322,
  mkdirat          = 323,
  mknodat          = 324,
  fchownat         = 325,
  futimesat        = 326,
  fstatat64        = 327,
  unlinkat         = 328,
  renameat         = 329,
  linkat           = 330,
  symlinkat        = 331,
  readlinkat       = 332,
  fchmodat         = 333,
  faccessat        = 334,
  pselect6         = 335,
  ppoll            = 336,
  unshare          = 337,
  set_robust_list  = 338,
  get_robust_list  = 339,
  splice           = 340,
  sync_file_range2 = 341,
  tee              = 342,
  vmsplice         = 343,
  move_pages       = 344,
  getcpu           = 345,
  epoll_pwait      = 346,
  kexec_load       = 347,
  utimensat        = 348,
  signalfd         = 349,
  timerfd_create   = 350,
  eventfd          = 351,
  fallocate        = 352,
  timerfd_settime  = 353,
  timerfd_gettime  = 354,
  signalfd4        = 355,
  eventfd2         = 356,
  epoll_create1    = 357,
  dup3             = 358,
  pipe2            = 359,
  inotify_init1    = 360,
  preadv           = 361,
  pwritev          = 362,
  rt_tgsigqueueinfo= 363,
  perf_event_open  = 364,
  recvmmsg         = 365,
  accept4          = 366,
  fanotify_init    = 367,
  fanotify_mark    = 368,
  prlimit64        = 369,
  name_to_handle_at= 370,
  open_by_handle_at= 371,
  clock_adjtime    = 372,
  syncfs           = 373,
  sendmmsg         = 374,
  setns            = 375,
  process_vm_readv = 376,
  process_vm_writev= 377,
  kcmp             = 378,
  finit_module     = 379,
  sched_setattr    = 380,
  sched_getattr    = 381,
  renameat2        = 382,
  seccomp          = 383,
  getrandom        = 384,
  memfd_create     = 385,
  bpf              = 386,
}
}

return nr

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.nl"],"module already exists")sources["syscall.linux.nl"]=([===[-- <pack syscall.linux.nl> --
-- modularize netlink code as it is large and standalone

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local function init(S)

local nl = {} -- exports

local ffi = require "ffi"
local bit = require "syscall.bit"

local h = require "syscall.helpers"

local util = S.util

local types = S.types
local c = S.c

local htonl = h.htonl
local align = h.align

local t, pt, s = types.t, types.pt, types.s

local adtt = {
  [c.AF.INET] = t.in_addr,
  [c.AF.INET6] = t.in6_addr,
}

local function addrtype(af)
  local tp = adtt[tonumber(af)]
  if not tp then error("bad address family") end
  return tp()
end

local function mktype(tp, x) if ffi.istype(tp, x) then return x else return tp(x) end end

local mt = {} -- metatables
local meth = {}

-- similar functions for netlink messages
local function nlmsg_align(len) return align(len, 4) end
local nlmsg_hdrlen = nlmsg_align(s.nlmsghdr)
local function nlmsg_length(len) return len + nlmsg_hdrlen end
local function nlmsg_ok(msg, len)
  return len >= nlmsg_hdrlen and msg.nlmsg_len >= nlmsg_hdrlen and msg.nlmsg_len <= len
end
local function nlmsg_next(msg, buf, len)
  local inc = nlmsg_align(msg.nlmsg_len)
  return pt.nlmsghdr(buf + inc), buf + inc, len - inc
end

local rta_align = nlmsg_align -- also 4 byte align
local function rta_length(len) return len + rta_align(s.rtattr) end
local function rta_ok(msg, len)
  return len >= s.rtattr and msg.rta_len >= s.rtattr and msg.rta_len <= len
end
local function rta_next(msg, buf, len)
  local inc = rta_align(msg.rta_len)
  return pt.rtattr(buf + inc), buf + inc, len - inc
end

local addrlenmap = { -- map interface type to length of hardware address TODO are these always same?
  [c.ARPHRD.ETHER] = 6,
  [c.ARPHRD.EETHER] = 6,
  [c.ARPHRD.LOOPBACK] = 6,
}

local ifla_decode = {
  [c.IFLA.IFNAME] = function(ir, buf, len)
    ir.name = ffi.string(buf)
  end,
  [c.IFLA.ADDRESS] = function(ir, buf, len)
    local addrlen = addrlenmap[ir.type]
    if (addrlen) then
      ir.addrlen = addrlen
      ir.macaddr = t.macaddr()
      ffi.copy(ir.macaddr, buf, addrlen)
    end
  end,
  [c.IFLA.BROADCAST] = function(ir, buf, len)
    local addrlen = addrlenmap[ir.type] -- TODO always same
    if (addrlen) then
      ir.broadcast = t.macaddr()
      ffi.copy(ir.broadcast, buf, addrlen)
    end
  end,
  [c.IFLA.MTU] = function(ir, buf, len)
    local u = pt.uint(buf)
    ir.mtu = tonumber(u[0])
  end,
  [c.IFLA.LINK] = function(ir, buf, len)
    local i = pt.int(buf)
    ir.link = tonumber(i[0])
  end,
  [c.IFLA.QDISC] = function(ir, buf, len)
    ir.qdisc = ffi.string(buf)
  end,
  [c.IFLA.STATS] = function(ir, buf, len)
    ir.stats = t.rtnl_link_stats() -- despite man page, this is what kernel uses. So only get 32 bit stats here.
    ffi.copy(ir.stats, buf, s.rtnl_link_stats)
  end
}

local ifa_decode = {
  [c.IFA.ADDRESS] = function(ir, buf, len)
    ir.addr = addrtype(ir.family)
    ffi.copy(ir.addr, buf, ffi.sizeof(ir.addr))
  end,
  [c.IFA.LOCAL] = function(ir, buf, len)
    ir.loc = addrtype(ir.family)
    ffi.copy(ir.loc, buf, ffi.sizeof(ir.loc))
  end,
  [c.IFA.BROADCAST] = function(ir, buf, len)
    ir.broadcast = addrtype(ir.family)
    ffi.copy(ir.broadcast, buf, ffi.sizeof(ir.broadcast))
  end,
  [c.IFA.LABEL] = function(ir, buf, len)
    ir.label = ffi.string(buf)
  end,
  [c.IFA.ANYCAST] = function(ir, buf, len)
    ir.anycast = addrtype(ir.family)
    ffi.copy(ir.anycast, buf, ffi.sizeof(ir.anycast))
  end,
  [c.IFA.CACHEINFO] = function(ir, buf, len)
    ir.cacheinfo = t.ifa_cacheinfo()
    ffi.copy(ir.cacheinfo, buf, ffi.sizeof(t.ifa_cacheinfo))
  end,
}

local rta_decode = {
  [c.RTA.DST] = function(ir, buf, len)
    ir.dst = addrtype(ir.family)
    ffi.copy(ir.dst, buf, ffi.sizeof(ir.dst))
  end,
  [c.RTA.SRC] = function(ir, buf, len)
    ir.src = addrtype(ir.family)
    ffi.copy(ir.src, buf, ffi.sizeof(ir.src))
  end,
  [c.RTA.IIF] = function(ir, buf, len)
    local i = pt.int(buf)
    ir.iif = tonumber(i[0])
  end,
  [c.RTA.OIF] = function(ir, buf, len)
    local i = pt.int(buf)
    ir.oif = tonumber(i[0])
  end,
  [c.RTA.GATEWAY] = function(ir, buf, len)
    ir.gateway = addrtype(ir.family)
    ffi.copy(ir.gateway, buf, ffi.sizeof(ir.gateway))
  end,
  [c.RTA.PRIORITY] = function(ir, buf, len)
    local i = pt.int(buf)
    ir.priority = tonumber(i[0])
  end,
  [c.RTA.PREFSRC] = function(ir, buf, len)
    local i = pt.uint32(buf)
    ir.prefsrc = tonumber(i[0])
  end,
  [c.RTA.METRICS] = function(ir, buf, len)
    local i = pt.int(buf)
    ir.metrics = tonumber(i[0])
  end,
  [c.RTA.TABLE] = function(ir, buf, len)
    local i = pt.uint32(buf)
    ir.table = tonumber(i[0])
  end,
  [c.RTA.CACHEINFO] = function(ir, buf, len)
    ir.cacheinfo = t.rta_cacheinfo()
    ffi.copy(ir.cacheinfo, buf, s.rta_cacheinfo)
  end,
  [c.RTA.PREF] = function(ir, buf, len)
    local i = pt.uint8(buf)
    ir.pref = tonumber(i[0])
  end,
  -- TODO some missing
}

local nda_decode = {
  [c.NDA.DST] = function(ir, buf, len)
    ir.dst = addrtype(ir.family)
    ffi.copy(ir.dst, buf, ffi.sizeof(ir.dst))
  end,
  [c.NDA.LLADDR] = function(ir, buf, len)
    ir.lladdr = t.macaddr()
    ffi.copy(ir.lladdr, buf, s.macaddr)
  end,
  [c.NDA.CACHEINFO] = function(ir, buf, len)
     ir.cacheinfo = t.nda_cacheinfo()
     ffi.copy(ir.cacheinfo, buf, s.nda_cacheinfo)
  end,
  [c.NDA.PROBES] = function(ir, buf, len)
     -- TODO what is this? 4 bytes
  end,
}

local ifflist = {}
for k, _ in pairs(c.IFF) do ifflist[#ifflist + 1] = k end

mt.iff = {
  __tostring = function(f)
    local s = {}
    for _, k in pairs(ifflist) do if bit.band(f.flags, c.IFF[k]) ~= 0 then s[#s + 1] = k end end
    return table.concat(s, ' ')
  end,
  __index = function(f, k)
    if c.IFF[k] then return bit.band(f.flags, c.IFF[k]) ~= 0 end
  end
}

nl.encapnames = {
  [c.ARPHRD.ETHER] = "Ethernet",
  [c.ARPHRD.LOOPBACK] = "Local Loopback",
}

meth.iflinks = {
  fn = {
    refresh = function(i)
      local j, err = nl.interfaces()
      if not j then return nil, err end
      for k, _ in pairs(i) do i[k] = nil end
      for k, v in pairs(j) do i[k] = v end
      return i
    end,
  },
}

mt.iflinks = {
  __index = function(i, k)
    if meth.iflinks.fn[k] then return meth.iflinks.fn[k] end
  end,
  __tostring = function(is)
    local s = {}
    for _, v in ipairs(is) do
      s[#s + 1] = tostring(v)
    end
    return table.concat(s, '\n')
  end
}

meth.iflink = {
  index = {
    family = function(i) return tonumber(i.ifinfo.ifi_family) end,
    type = function(i) return tonumber(i.ifinfo.ifi_type) end,
    typename = function(i)
      local n = nl.encapnames[i.type]
      return n or 'unknown ' .. i.type
    end,
    index = function(i) return tonumber(i.ifinfo.ifi_index) end,
    flags = function(i) return setmetatable({flags = tonumber(i.ifinfo.ifi_flags)}, mt.iff) end,
    change = function(i) return tonumber(i.ifinfo.ifi_change) end,
  },
  fn = {
    setflags = function(i, flags, change)
      local ok, err = nl.newlink(i, 0, flags, change or c.IFF.ALL)
      if not ok then return nil, err end
      return i:refresh()
    end,
    up = function(i) return i:setflags("up", "up") end,
    down = function(i) return i:setflags("", "up") end,
    setmtu = function(i, mtu)
      local ok, err = nl.newlink(i.index, 0, 0, 0, "mtu", mtu)
      if not ok then return nil, err end
      return i:refresh()
    end,
    setmac = function(i, mac)
      local ok, err = nl.newlink(i.index, 0, 0, 0, "address", mac)
      if not ok then return nil, err end
      return i:refresh()
    end,
    address = function(i, address, netmask) -- add address
      if type(address) == "string" then address, netmask = util.inet_name(address, netmask) end
      if not address then return nil end
      local ok, err
      if ffi.istype(t.in6_addr, address) then
        ok, err = nl.newaddr(i.index, c.AF.INET6, netmask, "permanent", "local", address)
      else
        local broadcast = address:get_mask_bcast(netmask).broadcast
        ok, err = nl.newaddr(i.index, c.AF.INET, netmask, "permanent", "local", address, "broadcast", broadcast)
      end
      if not ok then return nil, err end
      return i:refresh()
    end,
    deladdress = function(i, address, netmask)
      if type(address) == "string" then address, netmask = util.inet_name(address, netmask) end
      if not address then return nil end
      local af
      if ffi.istype(t.in6_addr, address) then af = c.AF.INET6 else af = c.AF.INET end
      local ok, err = nl.deladdr(i.index, af, netmask, "local", address)
      if not ok then return nil, err end
      return i:refresh()
    end,
    delete = function(i)
      local ok, err = nl.dellink(i.index)
      if not ok then return nil, err end
      return true     
    end,
    move_ns = function(i, ns) -- TODO also support file descriptor form as well as pid
      local ok, err = nl.newlink(i.index, 0, 0, 0, "net_ns_pid", ns)
      if not ok then return nil, err end
      return true -- no longer here so cannot refresh
    end,
    rename = function(i, name)
      local ok, err = nl.newlink(i.index, 0, 0, 0, "ifname", name)
      if not ok then return nil, err end
      i.name = name -- refresh not working otherwise as done by name TODO fix so by index
      return i:refresh()
    end,
    refresh = function(i)
      local j, err = nl.interface(i.name)
      if not j then return nil, err end
      for k, _ in pairs(i) do i[k] = nil end
      for k, v in pairs(j) do i[k] = v end
      return i
    end,
  }
}

mt.iflink = {
  __index = function(i, k)
    if meth.iflink.index[k] then return meth.iflink.index[k](i) end
    if meth.iflink.fn[k] then return meth.iflink.fn[k] end
    if k == "inet" or k == "inet6" then return end -- might not be set, as we add it, kernel does not provide
    if c.ARPHRD[k] then return i.ifinfo.ifi_type == c.ARPHRD[k] end
  end,
  __tostring = function(i)
    local hw = ''
    if not i.loopback and i.macaddr then hw = '  HWaddr ' .. tostring(i.macaddr) end
    local s = i.name .. string.rep(' ', 10 - #i.name) .. 'Link encap:' .. i.typename .. hw .. '\n'
    if i.inet then for a = 1, #i.inet do
      s = s .. '          ' .. 'inet addr: ' .. tostring(i.inet[a].addr) .. '/' .. i.inet[a].prefixlen .. '\n'
    end end
    if i.inet6 then for a = 1, #i.inet6 do
      s = s .. '          ' .. 'inet6 addr: ' .. tostring(i.inet6[a].addr) .. '/' .. i.inet6[a].prefixlen .. '\n'
    end end
      s = s .. '          ' .. tostring(i.flags) .. '  MTU: ' .. i.mtu .. '\n'
      s = s .. '          ' .. 'RX packets:' .. i.stats.rx_packets .. ' errors:' .. i.stats.rx_errors .. ' dropped:' .. i.stats.rx_dropped .. '\n'
      s = s .. '          ' .. 'TX packets:' .. i.stats.tx_packets .. ' errors:' .. i.stats.tx_errors .. ' dropped:' .. i.stats.tx_dropped .. '\n'
    return s
  end
}

meth.rtmsg = {
  index = {
    family = function(i) return tonumber(i.rtmsg.rtm_family) end,
    dst_len = function(i) return tonumber(i.rtmsg.rtm_dst_len) end,
    src_len = function(i) return tonumber(i.rtmsg.rtm_src_len) end,
    index = function(i) return tonumber(i.oif) end,
    flags = function(i) return tonumber(i.rtmsg.rtm_flags) end,
    dest = function(i) return i.dst or addrtype(i.family) end,
    source = function(i) return i.src or addrtype(i.family) end,
    gw = function(i) return i.gateway or addrtype(i.family) end,
    -- might not be set in Lua table, so return nil
    iif = function() return nil end,
    oif = function() return nil end,
    src = function() return nil end,
    dst = function() return nil end,
  },
  flags = { -- TODO rework so iterates in fixed order. TODO Do not seem to be set, find how to retrieve.
    [c.RTF.UP] = "U",
    [c.RTF.GATEWAY] = "G",
    [c.RTF.HOST] = "H",
    [c.RTF.REINSTATE] = "R",
    [c.RTF.DYNAMIC] = "D",
    [c.RTF.MODIFIED] = "M",
    [c.RTF.REJECT] = "!",
  }
}

mt.rtmsg = {
  __index = function(i, k)
    if meth.rtmsg.index[k] then return meth.rtmsg.index[k](i) end
    -- if S.RTF[k] then return bit.band(i.flags, S.RTF[k]) ~= 0 end -- TODO see above
  end,
  __tostring = function(i) -- TODO make more like output of ip route
    local s = "dst: " .. tostring(i.dest) .. "/" .. i.dst_len .. " gateway: " .. tostring(i.gw) .. " src: " .. tostring(i.source) .. "/" .. i.src_len .. " if: " .. (i.output or i.oif)
    return s
  end,
}

meth.routes = {
  fn = {
    match = function(rs, addr, len) -- exact match
      if type(addr) == "string" then
        local sl = addr:find("/", 1, true)
        if sl then
          len = tonumber(addr:sub(sl + 1))
          addr = addr:sub(1, sl - 1)
        end
        if rs.family == c.AF.INET6 then addr = t.in6_addr(addr) else addr = t.in_addr(addr) end
      end
      local matches = {}
      for _, v in ipairs(rs) do
        if len == v.dst_len then
          if v.family == c.AF.INET then
            if addr.s_addr == v.dest.s_addr then matches[#matches + 1] = v end
          else
            local match = true
            for i = 0, 15 do
              if addr.s6_addr[i] ~= v.dest.s6_addr[i] then match = false end
            end
            if match then matches[#matches + 1] = v end
          end
        end
      end
      matches.tp, matches.family = rs.tp, rs.family
      return setmetatable(matches, mt.routes)
    end,
    refresh = function(rs)
      local nr = nl.routes(rs.family, rs.tp)
      for k, _ in pairs(rs) do rs[k] = nil end
      for k, v in pairs(nr) do rs[k] = v end
      return rs
    end,
  }
}

mt.routes = {
  __index = function(i, k)
    if meth.routes.fn[k] then return meth.routes.fn[k] end
  end,
  __tostring = function(is)
    local s = {}
    for k, v in ipairs(is) do
      s[#s + 1] = tostring(v)
    end
    return table.concat(s, '\n')
  end,
}

meth.ifaddr = {
  index = {
    family = function(i) return tonumber(i.ifaddr.ifa_family) end,
    prefixlen = function(i) return tonumber(i.ifaddr.ifa_prefixlen) end,
    index = function(i) return tonumber(i.ifaddr.ifa_index) end,
    flags = function(i) return tonumber(i.ifaddr.ifa_flags) end,
    scope = function(i) return tonumber(i.ifaddr.ifa_scope) end,
  }
}

mt.ifaddr = {
  __index = function(i, k)
    if meth.ifaddr.index[k] then return meth.ifaddr.index[k](i) end
    if c.IFA_F[k] then return bit.band(i.ifaddr.ifa_flags, c.IFA_F[k]) ~= 0 end
  end
}

-- TODO functions repetitious
local function decode_link(buf, len)
  local iface = pt.ifinfomsg(buf)
  buf = buf + nlmsg_align(s.ifinfomsg)
  len = len - nlmsg_align(s.ifinfomsg)
  local rtattr = pt.rtattr(buf)
  local ir = setmetatable({ifinfo = t.ifinfomsg()}, mt.iflink)
  ffi.copy(ir.ifinfo, iface, s.ifinfomsg)
  while rta_ok(rtattr, len) do
    if ifla_decode[rtattr.rta_type] then
      ifla_decode[rtattr.rta_type](ir, buf + rta_length(0), rta_align(rtattr.rta_len) - rta_length(0))
    end
    rtattr, buf, len = rta_next(rtattr, buf, len)
  end
  return ir
end

local function decode_address(buf, len)
  local addr = pt.ifaddrmsg(buf)
  buf = buf + nlmsg_align(s.ifaddrmsg)
  len = len - nlmsg_align(s.ifaddrmsg)
  local rtattr = pt.rtattr(buf)
  local ir = setmetatable({ifaddr = t.ifaddrmsg(), addr = {}}, mt.ifaddr)
  ffi.copy(ir.ifaddr, addr, s.ifaddrmsg)
  while rta_ok(rtattr, len) do
    if ifa_decode[rtattr.rta_type] then
      ifa_decode[rtattr.rta_type](ir, buf + rta_length(0), rta_align(rtattr.rta_len) - rta_length(0))
    end
    rtattr, buf, len = rta_next(rtattr, buf, len)
  end
  return ir
end

local function decode_route(buf, len)
  local rt = pt.rtmsg(buf)
  buf = buf + nlmsg_align(s.rtmsg)
  len = len - nlmsg_align(s.rtmsg)
  local rtattr = pt.rtattr(buf)
  local ir = setmetatable({rtmsg = t.rtmsg()}, mt.rtmsg)
  ffi.copy(ir.rtmsg, rt, s.rtmsg)
  while rta_ok(rtattr, len) do
    if rta_decode[rtattr.rta_type] then
      rta_decode[rtattr.rta_type](ir, buf + rta_length(0), rta_align(rtattr.rta_len) - rta_length(0))
    else error("NYI: " .. rtattr.rta_type)
    end
    rtattr, buf, len = rta_next(rtattr, buf, len)
  end
  return ir
end

local function decode_neigh(buf, len)
  local rt = pt.rtmsg(buf)
  buf = buf + nlmsg_align(s.rtmsg)
  len = len - nlmsg_align(s.rtmsg)
  local rtattr = pt.rtattr(buf)
  local ir = setmetatable({rtmsg = t.rtmsg()}, mt.rtmsg)
  ffi.copy(ir.rtmsg, rt, s.rtmsg)
  while rta_ok(rtattr, len) do
    if nda_decode[rtattr.rta_type] then
      nda_decode[rtattr.rta_type](ir, buf + rta_length(0), rta_align(rtattr.rta_len) - rta_length(0))
    else error("NYI: " .. rtattr.rta_type)
    end
    rtattr, buf, len = rta_next(rtattr, buf, len)
  end
  return ir
end

-- TODO other than the first few these could be a table
local nlmsg_data_decode = {
  [c.NLMSG.NOOP] = function(r, buf, len) return r end,
  [c.NLMSG.ERROR] = function(r, buf, len)
    local e = pt.nlmsgerr(buf)
    if e.error ~= 0 then r.error = t.error(-e.error) else r.ack = true end -- error zero is ACK, others negative
    return r
  end,
  [c.NLMSG.DONE] = function(r, buf, len) return r end,
  [c.NLMSG.OVERRUN] = function(r, buf, len)
    r.overrun = true
    return r
  end,
  [c.RTM.NEWADDR] = function(r, buf, len)
    local ir = decode_address(buf, len)
    ir.op, ir.newaddr, ir.nl = "newaddr", true, c.RTM.NEWADDR
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.DELADDR] = function(r, buf, len)
    local ir = decode_address(buf, len)
    ir.op, ir.deladdr, ir.nl = "delddr", true, c.RTM.DELADDR
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.GETADDR] = function(r, buf, len)
    local ir = decode_address(buf, len)
    ir.op, ir.getaddr, ir.nl = "getaddr", true, c.RTM.GETADDR
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.NEWLINK] = function(r, buf, len)
    local ir = decode_link(buf, len)
    ir.op, ir.newlink, ir.nl = "newlink", true, c.RTM.NEWLINK
    r[ir.name] = ir
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.DELLINK] = function(r, buf, len)
    local ir = decode_link(buf, len)
    ir.op, ir.dellink, ir.nl = "dellink", true, c.RTM.DELLINK
    r[ir.name] = ir
    r[#r + 1] = ir
    return r
  end,
  -- TODO need test that returns these, assume updates do
  [c.RTM.GETLINK] = function(r, buf, len)
    local ir = decode_link(buf, len)
    ir.op, ir.getlink, ir.nl = "getlink", true, c.RTM.GETLINK
    r[ir.name] = ir
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.NEWROUTE] = function(r, buf, len)
    local ir = decode_route(buf, len)
    ir.op, ir.newroute, ir.nl = "newroute", true, c.RTM.NEWROUTE
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.DELROUTE] = function(r, buf, len)
    local ir = decode_route(buf, len)
    ir.op, ir.delroute, ir.nl = "delroute", true, c.RTM.DELROUTE
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.GETROUTE] = function(r, buf, len)
    local ir = decode_route(buf, len)
    ir.op, ir.getroute, ir.nl = "getroute", true, c.RTM.GETROUTE
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.NEWNEIGH] = function(r, buf, len)
    local ir = decode_neigh(buf, len)
    ir.op, ir.newneigh, ir.nl = "newneigh", true, c.RTM.NEWNEIGH
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.DELNEIGH] = function(r, buf, len)
    local ir = decode_neigh(buf, len)
    ir.op, ir.delneigh, ir.nl = "delneigh", true, c.RTM.DELNEIGH
    r[#r + 1] = ir
    return r
  end,
  [c.RTM.GETNEIGH] = function(r, buf, len)
    local ir = decode_neigh(buf, len)
    ir.op, ir.getneigh, ir.nl = "getneigh", true, c.RTM.GETNEIGH
    r[#r + 1] = ir
    return r
  end,
}

function nl.read(s, addr, bufsize, untildone)
  addr = addr or t.sockaddr_nl() -- default to kernel
  bufsize = bufsize or 8192
  local reply = t.buffer(bufsize)
  local ior = t.iovecs{{reply, bufsize}}
  local m = t.msghdr{msg_iov = ior.iov, msg_iovlen = #ior, msg_name = addr, msg_namelen = ffi.sizeof(addr)}

  local done = false -- what should we do if we get a done message but there is some extra buffer? could be next message...
  local r = {}

  while not done do
    local len, err = s:recvmsg(m)
    if not len then return nil, err end
    local buffer = reply

    local msg = pt.nlmsghdr(buffer)

    while not done and nlmsg_ok(msg, len) do
      local tp = tonumber(msg.nlmsg_type)

      if nlmsg_data_decode[tp] then
        r = nlmsg_data_decode[tp](r, buffer + nlmsg_hdrlen, msg.nlmsg_len - nlmsg_hdrlen)

        if r.overrun then return S.read(s, addr, bufsize * 2) end -- TODO add test
        if r.error then return nil, r.error end -- not sure what the errors mean though!
        if r.ack then done = true end

      else error("unknown data " .. tp)
      end

      if tp == c.NLMSG.DONE then done = true end
      msg, buffer, len = nlmsg_next(msg, buffer, len)
    end
    if not untildone then done = true end
  end

  return r
end

-- TODO share with read side
local ifla_msg_types = {
  ifla = {
    -- IFLA.UNSPEC
    [c.IFLA.ADDRESS] = t.macaddr,
    [c.IFLA.BROADCAST] = t.macaddr,
    [c.IFLA.IFNAME] = "asciiz",
    -- TODO IFLA.MAP
    [c.IFLA.MTU] = t.uint32,
    [c.IFLA.LINK] = t.uint32,
    [c.IFLA.MASTER] = t.uint32,
    [c.IFLA.TXQLEN] = t.uint32,
    [c.IFLA.WEIGHT] = t.uint32,
    [c.IFLA.OPERSTATE] = t.uint8,
    [c.IFLA.LINKMODE] = t.uint8,
    [c.IFLA.LINKINFO] = {"ifla_info", c.IFLA_INFO},
    [c.IFLA.NET_NS_PID] = t.uint32,
    [c.IFLA.NET_NS_FD] = t.uint32,
    [c.IFLA.IFALIAS] = "asciiz",
    --[c.IFLA.VFINFO_LIST] = "nested",
    --[c.IFLA.VF_PORTS] = "nested",
    --[c.IFLA.PORT_SELF] = "nested",
    --[c.IFLA.AF_SPEC] = "nested",
  },
  ifla_info = {
    [c.IFLA_INFO.KIND] = "ascii",
    [c.IFLA_INFO.DATA] = "kind",
  },
  ifla_vlan = {
    [c.IFLA_VLAN.ID] = t.uint16,
    -- other vlan params
  },
  ifa = {
    -- IFA.UNSPEC
    [c.IFA.ADDRESS] = "address",
    [c.IFA.LOCAL] = "address",
    [c.IFA.LABEL] = "asciiz",
    [c.IFA.BROADCAST] = "address",
    [c.IFA.ANYCAST] = "address",
    -- IFA.CACHEINFO
  },
  rta = {
    -- RTA_UNSPEC
    [c.RTA.DST] = "address",
    [c.RTA.SRC] = "address",
    [c.RTA.IIF] = t.uint32,
    [c.RTA.OIF] = t.uint32,
    [c.RTA.GATEWAY] = "address",
    [c.RTA.PRIORITY] = t.uint32,
    [c.RTA.METRICS] = t.uint32,
    --          RTA.PREFSRC
    --          RTA.MULTIPATH
    --          RTA.PROTOINFO
    --          RTA.FLOW
    --          RTA.CACHEINFO
  },
  veth_info = {
    -- VETH_INFO_UNSPEC
    [c.VETH_INFO.PEER] = {"ifla", c.IFLA},
  },
  nda = {
    [c.NDA.DST]       = "address",
    [c.NDA.LLADDR]    = t.macaddr,
    [c.NDA.CACHEINFO] = t.nda_cacheinfo,
--    [c.NDA.PROBES] = ,
  },
}

--[[ TODO add
static const struct nla_policy ifla_vfinfo_policy[IFLA_VF_INFO_MAX+1] = {
        [IFLA_VF_INFO]          = { .type = NLA_NESTED },
};

static const struct nla_policy ifla_vf_policy[IFLA_VF_MAX+1] = {
        [IFLA_VF_MAC]           = { .type = NLA_BINARY,
                                    .len = sizeof(struct ifla_vf_mac) },
        [IFLA_VF_VLAN]          = { .type = NLA_BINARY,
                                    .len = sizeof(struct ifla_vf_vlan) },
        [IFLA_VF_TX_RATE]       = { .type = NLA_BINARY,
                                    .len = sizeof(struct ifla_vf_tx_rate) },
        [IFLA_VF_SPOOFCHK]      = { .type = NLA_BINARY,
                                    .len = sizeof(struct ifla_vf_spoofchk) },
};

static const struct nla_policy ifla_port_policy[IFLA_PORT_MAX+1] = {
        [IFLA_PORT_VF]          = { .type = NLA_U32 },
        [IFLA_PORT_PROFILE]     = { .type = NLA_STRING,
                                    .len = PORT_PROFILE_MAX },
        [IFLA_PORT_VSI_TYPE]    = { .type = NLA_BINARY,
                                    .len = sizeof(struct ifla_port_vsi)},
        [IFLA_PORT_INSTANCE_UUID] = { .type = NLA_BINARY,
                                      .len = PORT_UUID_MAX },
        [IFLA_PORT_HOST_UUID]   = { .type = NLA_STRING,
                                    .len = PORT_UUID_MAX },
        [IFLA_PORT_REQUEST]     = { .type = NLA_U8, },
        [IFLA_PORT_RESPONSE]    = { .type = NLA_U16, },
};
]]

local function ifla_getmsg(args, messages, values, tab, lookup, kind, af)
  local msg = table.remove(args, 1)
  local value, len
  local tp

  if type(msg) == "table" then -- for nested attributes
    local nargs = msg
    len = 0
    while #nargs ~= 0 do
      local nlen
      nlen, nargs, messages, values, kind = ifla_getmsg(nargs, messages, values, tab, lookup, kind, af)
      len = len + nlen
    end
    return len, args, messages, values, kind
  end

  if type(msg) == "cdata" or type(msg) == "userdata" then
    tp = msg
    value = table.remove(args, 1)
    if not value then error("not enough arguments") end
    value = mktype(tp, value)
    len = ffi.sizeof(value)
    messages[#messages + 1] = tp
    values[#values + 1] = value
    return len, args, messages, values, kind
  end

  local rawmsg = msg
  msg = lookup[msg]

  tp = ifla_msg_types[tab][msg]
  if not tp then error("unknown message type " .. tostring(rawmsg) .. " in " .. tab) end

  if tp == "kind" then
    local kinds = {
      vlan = {"ifla_vlan", c.IFLA_VLAN},
      veth = {"veth_info", c.VETH_INFO},
    }
    tp = kinds[kind]
  end

  if type(tp) == "table" then
    value = t.rtattr{rta_type = msg} -- missing rta_len, but have reference and can fix

    messages[#messages + 1] = t.rtattr
    values[#values + 1] = value

    tab, lookup = tp[1], tp[2]

    len, args, messages, values, kind = ifla_getmsg(args, messages, values, tab, lookup, kind, af)
    len = nlmsg_align(s.rtattr) + len

    value.rta_len = len

    return len, args, messages, values, kind

  -- recursion base case, just a value, not nested

  else
    value = table.remove(args, 1)
    if not value then error("not enough arguments") end
  end

  if tab == "ifla_info" and msg == c.IFLA_INFO.KIND then
    kind = value
  end

  local slen

  if tp == "asciiz" then -- zero terminated
    tp = t.buffer(#value + 1)
    slen = nlmsg_align(s.rtattr) + #value + 1
  elseif tp == "ascii" then -- not zero terminated
    tp = t.buffer(#value)
    slen = nlmsg_align(s.rtattr) + #value
  else
    if tp == "address" then
      tp = adtt[tonumber(af)]
    end
    value = mktype(tp, value)
  end

  len = nlmsg_align(s.rtattr) + nlmsg_align(ffi.sizeof(tp))
  slen = slen or len

  messages[#messages + 1] = t.rtattr
  messages[#messages + 1] = tp
  values[#values + 1] = t.rtattr{rta_type = msg, rta_len = slen}
  values[#values + 1] = value

  return len, args, messages, values, kind
end

local function ifla_f(tab, lookup, af, ...)
  local len, kind
  local messages, values = {t.nlmsghdr}, {false}

  local args = {...}
  while #args ~= 0 do
    len, args, messages, values, kind = ifla_getmsg(args, messages, values, tab, lookup, kind, af)
  end

  local len = 0
  local offsets = {}
  local alignment = nlmsg_align(1)
  for i, tp in ipairs(messages) do
    local item_alignment = align(ffi.sizeof(tp), alignment)
    offsets[i] = len
    len = len + item_alignment
  end
  local buf = t.buffer(len)

  for i = 2, #offsets do -- skip header
    local value = values[i]
    if type(value) == "string" then
      ffi.copy(buf + offsets[i], value)
    else
      -- slightly nasty
      if ffi.istype(t.uint32, value) then value = t.uint32_1(value) end
      if ffi.istype(t.uint16, value) then value = t.uint16_1(value) end
      if ffi.istype(t.uint8, value) then value = t.uint8_1(value) end
      ffi.copy(buf + offsets[i], value, ffi.sizeof(value))
    end
  end

  return buf, len
end

local rtpref = {
  [c.RTM.NEWLINK] = {"ifla", c.IFLA},
  [c.RTM.GETLINK] = {"ifla", c.IFLA},
  [c.RTM.DELLINK] = {"ifla", c.IFLA},
  [c.RTM.NEWADDR] = {"ifa", c.IFA},
  [c.RTM.GETADDR] = {"ifa", c.IFA},
  [c.RTM.DELADDR] = {"ifa", c.IFA},
  [c.RTM.NEWROUTE] = {"rta", c.RTA},
  [c.RTM.GETROUTE] = {"rta", c.RTA},
  [c.RTM.DELROUTE] = {"rta", c.RTA},
  [c.RTM.NEWNEIGH] = {"nda", c.NDA},
  [c.RTM.DELNEIGH] = {"nda", c.NDA},
  [c.RTM.GETNEIGH] = {"nda", c.NDA},
  [c.RTM.NEWNEIGHTBL] = {"ndtpa", c.NDTPA},
  [c.RTM.GETNEIGHTBL] = {"ndtpa", c.NDTPA},
  [c.RTM.SETNEIGHTBL] = {"ndtpa", c.NDTPA},
}

function nl.socket(tp, addr)
  tp = c.NETLINK[tp]
  local sock, err = S.socket(c.AF.NETLINK, c.SOCK.RAW, tp)
  if not sock then return nil, err end
  if addr then
    if type(addr) == "table" then addr.type = tp end -- need type to convert group names from string
    if not ffi.istype(t.sockaddr_nl, addr) then addr = t.sockaddr_nl(addr) end
    local ok, err = S.bind(sock, addr)
    if not ok then
      S.close(sock)
      return nil, err
    end
  end
  return sock
end

function nl.write(sock, dest, ntype, flags, af, ...)
  local a, err = sock:getsockname() -- to get bound address
  if not a then return nil, err end

  dest = dest or t.sockaddr_nl() -- kernel destination default

  local tl = rtpref[ntype]
  if not tl then error("NYI: ", ntype) end
  local tab, lookup = tl[1], tl[2]

  local buf, len = ifla_f(tab, lookup, af, ...)

  local hdr = pt.nlmsghdr(buf)

  hdr[0] = {nlmsg_len = len, nlmsg_type = ntype, nlmsg_flags = flags, nlmsg_seq = sock:seq(), nlmsg_pid = a.pid}

  local ios = t.iovecs{{buf, len}}
  local m = t.msghdr{msg_iov = ios.iov, msg_iovlen = #ios, msg_name = dest, msg_namelen = s.sockaddr_nl}

  return sock:sendmsg(m)
end

-- TODO "route" should be passed in as parameter, test with other netlink types
local function nlmsg(ntype, flags, af, ...)
  ntype = c.RTM[ntype]
  flags = c.NLM_F[flags]
  local sock, err = nl.socket("route", {}) -- bind to empty sockaddr_nl, kernel fills address
  if not sock then return nil, err end

  local k = t.sockaddr_nl() -- kernel destination

  local ok, err = nl.write(sock, k, ntype, flags, af, ...)
  if not ok then
    sock:close()
    return nil, err
  end

  local r, err = nl.read(sock, k, nil, true) -- true means until get done message
  if not r then
    sock:close()
    return nil, err
  end

  local ok, err = sock:close()
  if not ok then return nil, err end

  return r
end

-- TODO do not have all these different arguments for these functions, pass a table for initialization. See also iplink.

function nl.newlink(index, flags, iflags, change, ...)
  if change == 0 then change = c.IFF.NONE end -- 0 should work, but does not
  flags = c.NLM_F("request", "ack", flags)
  if type(index) == 'table' then index = index.index end
  local ifv = {ifi_index = index, ifi_flags = c.IFF[iflags], ifi_change = c.IFF[change]}
  return nlmsg("newlink", flags, nil, t.ifinfomsg, ifv, ...)
end

function nl.dellink(index, ...)
  if type(index) == 'table' then index = index.index end
  local ifv = {ifi_index = index}
  return nlmsg("dellink", "request, ack", nil, t.ifinfomsg, ifv, ...)
end

-- read interfaces and details.
function nl.getlink(...)
  return nlmsg("getlink", "request, dump", nil, t.rtgenmsg, {rtgen_family = c.AF.PACKET}, ...)
end

-- read routes
function nl.getroute(af, tp, tab, prot, scope, ...)
  local rtm = t.rtmsg{family = af, table = tab, protocol = prot, type = tp, scope = scope}
  local r, err = nlmsg(c.RTM.GETROUTE, "request, dump", af, t.rtmsg, rtm)
  if not r then return nil, err end
  return setmetatable(r, mt.routes)
end

function nl.routes(af, tp)
  af = c.AF[af]
  if not tp then tp = c.RTN.UNICAST end
  tp = c.RTN[tp]
  local r, err = nl.getroute(af, tp)
  if not r then return nil, err end
  local ifs, err = nl.getlink()
  if not ifs then return nil, err end
  local indexmap = {} -- TODO turn into metamethod as used elsewhere
  for i, v in pairs(ifs) do
    v.inet, v.inet6 = {}, {}
    indexmap[v.index] = i
  end
  for k, v in ipairs(r) do
    if ifs[indexmap[v.iif]] then v.input = ifs[indexmap[v.iif]].name end
    if ifs[indexmap[v.oif]] then v.output = ifs[indexmap[v.oif]].name end
    if tp > 0 and v.rtmsg.rtm_type ~= tp then r[k] = nil end -- filter unwanted routes
  end
  r.family = af
  r.tp = tp
  return r
end

local function preftable(tab, prefix)
  for k, v in pairs(tab) do
    if k:sub(1, #prefix) ~= prefix then
      tab[prefix .. k] = v
      tab[k] = nil
    end
  end
  return tab
end

function nl.newroute(flags, rtm, ...)
  flags = c.NLM_F("request", "ack", flags)
  rtm = mktype(t.rtmsg, rtm)
  return nlmsg("newroute", flags, rtm.family, t.rtmsg, rtm, ...)
end

function nl.delroute(rtm, ...)
  rtm = mktype(t.rtmsg, rtm)
  return nlmsg("delroute", "request, ack", rtm.family, t.rtmsg, rtm, ...)
end

-- read addresses from interface TODO flag cleanup
function nl.getaddr(af, ...)
  local family = c.AF[af]
  local ifav = {ifa_family = family}
  return nlmsg("getaddr", "request, root", family, t.ifaddrmsg, ifav, ...)
end

-- TODO may need ifa_scope
function nl.newaddr(index, af, prefixlen, flags, ...)
  if type(index) == 'table' then index = index.index end
  local family = c.AF[af]
  local ifav = {ifa_family = family, ifa_prefixlen = prefixlen or 0, ifa_flags = c.IFA_F[flags], ifa_index = index} --__TODO in __new
  return nlmsg("newaddr", "request, ack", family, t.ifaddrmsg, ifav, ...)
end

function nl.deladdr(index, af, prefixlen, ...)
  if type(index) == 'table' then index = index.index end
  local family = c.AF[af]
  local ifav = {ifa_family = family, ifa_prefixlen = prefixlen or 0, ifa_flags = 0, ifa_index = index}
  return nlmsg("deladdr", "request, ack", family, t.ifaddrmsg, ifav, ...)
end

function nl.getneigh(index, tab, ...)
  if type(index) == 'table' then index = index.index end
  tab.ifindex = index
  local ndm = t.ndmsg(tab)
  return nlmsg("getneigh", "request, dump", ndm.family, t.ndmsg, ndm, ...)
end

function nl.newneigh(index, tab, ...)
  if type(index) == 'table' then index = index.index end
  tab.ifindex = index
  local ndm = t.ndmsg(tab)
  return nlmsg("newneigh", "request, ack, excl, create", ndm.family, t.ndmsg, ndm, ...)
end

function nl.delneigh(index, tab, ...)
  if type(index) == 'table' then index = index.index end
  tab.ifindex = index
  local ndm = t.ndmsg(tab)
  return nlmsg("delneigh", "request, ack", ndm.family, t.ndmsg, ndm, ...)
end

function nl.interfaces() -- returns with address info too.
  local ifs, err = nl.getlink()
  if not ifs then return nil, err end
  local addr4, err = nl.getaddr(c.AF.INET)
  if not addr4 then return nil, err end
  local addr6, err = nl.getaddr(c.AF.INET6)
  if not addr6 then return nil, err end
  local indexmap = {}
  for i, v in pairs(ifs) do
    v.inet, v.inet6 = {}, {}
    indexmap[v.index] = i
  end
  for i = 1, #addr4 do
    local v = ifs[indexmap[addr4[i].index]]
    v.inet[#v.inet + 1] = addr4[i]
  end
  for i = 1, #addr6 do
    local v = ifs[indexmap[addr6[i].index]]
    v.inet6[#v.inet6 + 1] = addr6[i]
  end
  return setmetatable(ifs, mt.iflinks)
end

function nl.interface(i) -- could optimize just to retrieve info for one
  local ifs, err = nl.interfaces()
  if not ifs then return nil, err end
  return ifs[i]
end

local link_process_f
local link_process = { -- TODO very incomplete. generate?
  name = function(args, v) return {"ifname", v} end,
  link = function(args, v) return {"link", v} end,
  address = function(args, v) return {"address", v} end,
  type = function(args, v, tab)
    if v == "vlan" then
      local id = tab.id
      if id then
        tab.id = nil
        return {"linkinfo", {"kind", "vlan", "data", {"id", id}}}
     end
    elseif v == "veth" then
      local peer = tab.peer
      tab.peer = nil
      local peertab = link_process_f(peer)
      return {"linkinfo", {"kind", "veth", "data", {"peer", {t.ifinfomsg, {}, peertab}}}}
    end
    return {"linkinfo", "kind", v}
  end,
}

function link_process_f(tab, args)
  args = args or {}
  for _, k in ipairs{"link", "name", "type"} do
    local v = tab[k]
    if v then
      if link_process[k] then
        local a = link_process[k](args, v, tab)
        for i = 1, #a do args[#args + 1] = a[i] end
      else error("bad iplink command " .. k)
      end
    end
  end
  return args
end

-- TODO better name. even more general, not just newlink. or make this the exposed newlink interface?
-- I think this is generally a nicer interface to expose than the ones above, for all functions
function nl.iplink(tab)
  local args = {tab.index or 0, tab.modifier or 0, tab.flags or 0, tab.change or 0}
  local args = link_process_f(tab, args)
  return nl.newlink(unpack(args))
end

-- TODO iplink may not be appropriate always sort out flags
function nl.create_interface(tab)
  tab.modifier = c.NLM_F.CREATE
  return nl.iplink(tab)
end

return nl

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.arm.constants"],"module already exists")sources["syscall.linux.arm.constants"]=([===[-- <pack syscall.linux.arm.constants> --
-- arm specific constants

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local abi = require "syscall.abi"

local octal = function (s) return tonumber(s, 8) end 

local arch = {}

arch.O = {
  RDONLY    = octal('0000'),
  WRONLY    = octal('0001'),
  RDWR      = octal('0002'),
  ACCMODE   = octal('0003'),
  CREAT     = octal('0100'),
  EXCL      = octal('0200'),
  NOCTTY    = octal('0400'),
  TRUNC     = octal('01000'),
  APPEND    = octal('02000'),
  NONBLOCK  = octal('04000'),
  DSYNC     = octal('010000'),
  ASYNC     = octal('020000'),
  DIRECTORY = octal('040000'),
  NOFOLLOW  = octal('0100000'),
  DIRECT    = octal('0200000'),
  LARGEFILE = octal('0400000'),
  NOATIME   = octal('01000000'),
  CLOEXEC   = octal('02000000'),
  SYNC      = octal('04010000'),
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ppc64le.nr"],"module already exists")sources["syscall.linux.ppc64le.nr"]=([===[-- <pack syscall.linux.ppc64le.nr> --
-- ppc64le syscall numbers

local nr = {
  zeropad = true,
  SYS = {
  restart_syscall         = 0,
  exit                    = 1,
  fork                    = 2,
  read                    = 3,
  write                   = 4,
  open                    = 5,
  close                   = 6,
  waitpid                 = 7,
  creat                   = 8,
  link                    = 9,
  unlink                 = 10,
  execve                 = 11,
  chdir                  = 12,
  time                   = 13,
  mknod                  = 14,
  chmod                  = 15,
  lchown                 = 16,
  ["break"]              = 17,
  oldstat                = 18,
  lseek                  = 19,
  getpid                 = 20,
  mount                  = 21,
  umount                 = 22,
  setuid                 = 23,
  getuid                 = 24,
  stime                  = 25,
  ptrace                 = 26,
  alarm                  = 27,
  oldfstat               = 28,
  pause                  = 29,
  utime                  = 30,
  stty                   = 31,
  gtty                   = 32,
  access                 = 33,
  nice                   = 34,
  ftime                  = 35,
  sync                   = 36,
  kill                   = 37,
  rename                 = 38,
  mkdir                  = 39,
  rmdir                  = 40,
  dup                    = 41,
  pipe                   = 42,
  times                  = 43,
  prof                   = 44,
  brk                    = 45,
  setgid                 = 46,
  getgid                 = 47,
  signal                 = 48,
  geteuid                = 49,
  getegid                = 50,
  acct                   = 51,
  umount2                = 52,
  lock                   = 53,
  ioctl                  = 54,
  fcntl                  = 55,
  mpx                    = 56,
  setpgid                = 57,
  ulimit                 = 58,
  oldolduname            = 59,
  umask                  = 60,
  chroot                 = 61,
  ustat                  = 62,
  dup2                   = 63,
  getppid                = 64,
  getpgrp                = 65,
  setsid                 = 66,
  sigaction              = 67,
  sgetmask               = 68,
  ssetmask               = 69,
  setreuid               = 70,
  setregid               = 71,
  sigsuspend             = 72,
  sigpending             = 73,
  sethostname            = 74,
  setrlimit              = 75,
  getrlimit              = 76,
  getrusage              = 77,
  gettimeofday           = 78,
  settimeofday           = 79,
  getgroups              = 80,
  setgroups              = 81,
  select                 = 82,
  symlink                = 83,
  oldlstat               = 84,
  readlink               = 85,
  uselib                 = 86,
  swapon                 = 87,
  reboot                 = 88,
  readdir                = 89,
  mmap                   = 90,
  munmap                 = 91,
  truncate               = 92,
  ftruncate              = 93,
  fchmod                 = 94,
  fchown                 = 95,
  getpriority            = 96,
  setpriority            = 97,
  profil                 = 98,
  statfs                 = 99,
  fstatfs               = 100,
  ioperm                = 101,
  socketcall            = 102,
  syslog                = 103,
  setitimer             = 104,
  getitimer             = 105,
  stat                  = 106,
  lstat                 = 107,
  fstat                 = 108,
  olduname              = 109,
  iopl                  = 110,
  vhangup               = 111,
  idle                  = 112,
  vm86                  = 113,
  wait4                 = 114,
  swapoff               = 115,
  sysinfo               = 116,
  ipc                   = 117,
  fsync                 = 118,
  sigreturn             = 119,
  clone                 = 120,
  setdomainname         = 121,
  uname                 = 122,
  modify_ldt            = 123,
  adjtimex              = 124,
  mprotect              = 125,
  sigprocmask           = 126,
  create_module         = 127,
  init_module           = 128,
  delete_module         = 129,
  get_kernel_syms       = 130,
  quotactl              = 131,
  getpgid               = 132,
  fchdir                = 133,
  bdflush               = 134,
  sysfs                 = 135,
  personality           = 136,
  afs_syscall           = 137,
  setfsuid              = 138,
  setfsgid              = 139,
  _llseek               = 140,
  getdents              = 141,
  _newselect            = 142,
  flock                 = 143,
  msync                 = 144,
  readv                 = 145,
  writev                = 146,
  getsid                = 147,
  fdatasync             = 148,
  _sysctl               = 149,
  mlock                 = 150,
  munlock               = 151,
  mlockall              = 152,
  munlockall            = 153,
  sched_setparam        = 154,
  sched_getparam        = 155,
  sched_setscheduler    = 156,
  sched_getscheduler    = 157,
  sched_yield           = 158,
  sched_get_priority_max= 159,
  sched_get_priority_min= 160,
  sched_rr_get_interval = 161,
  nanosleep             = 162,
  mremap                = 163,
  setresuid             = 164,
  getresuid             = 165,
  query_module          = 166,
  poll                  = 167,
  nfsservctl            = 168,
  setresgid             = 169,
  getresgid             = 170,
  prctl                 = 171,
  rt_sigreturn          = 172,
  rt_sigaction          = 173,
  rt_sigprocmask        = 174,
  rt_sigpending         = 175,
  rt_sigtimedwait       = 176,
  rt_sigqueueinfo       = 177,
  rt_sigsuspend         = 178,
  pread64               = 179,
  pwrite64              = 180,
  chown                 = 181,
  getcwd                = 182,
  capget                = 183,
  capset                = 184,
  sigaltstack           = 185,
  sendfile              = 186,
  getpmsg               = 187,
  putpmsg               = 188,
  vfork                 = 189,
  ugetrlimit            = 190,
  readahead             = 191,
  pciconfig_read        = 198,
  pciconfig_write       = 199,
  pciconfig_iobase      = 200,
  multiplexer           = 201,
  getdents64            = 202,
  pivot_root            = 203,
  madvise               = 205,
  mincore               = 206,
  gettid                = 207,
  tkill                 = 208,
  setxattr              = 209,
  lsetxattr             = 210,
  fsetxattr             = 211,
  getxattr              = 212,
  lgetxattr             = 213,
  fgetxattr             = 214,
  listxattr             = 215,
  llistxattr            = 216,
  flistxattr            = 217,
  removexattr           = 218,
  lremovexattr          = 219,
  fremovexattr          = 220,
  futex                 = 221,
  sched_setaffinity     = 222,
  sched_getaffinity     = 223,
  tuxcall               = 225,
  io_setup              = 227,
  io_destroy            = 228,
  io_getevents          = 229,
  io_submit             = 230,
  io_cancel             = 231,
  set_tid_address       = 232,
  fadvise64             = 233,
  exit_group            = 234,
  lookup_dcookie        = 235,
  epoll_create          = 236,
  epoll_ctl             = 237,
  epoll_wait            = 238,
  remap_file_pages      = 239,
  timer_create          = 240,
  timer_settime         = 241,
  timer_gettime         = 242,
  timer_getoverrun      = 243,
  timer_delete          = 244,
  clock_settime         = 245,
  clock_gettime         = 246,
  clock_getres          = 247,
  clock_nanosleep       = 248,
  swapcontext           = 249,
  tgkill                = 250,
  utimes                = 251,
  statfs64              = 252,
  fstatfs64             = 253,
  rtas                  = 255,
  sys_debug_setcontext  = 256,
  migrate_pages         = 258,
  mbind                 = 259,
  get_mempolicy         = 260,
  set_mempolicy         = 261,
  mq_open               = 262,
  mq_unlink             = 263,
  mq_timedsend          = 264,
  mq_timedreceive       = 265,
  mq_notify             = 266,
  mq_getsetattr         = 267,
  kexec_load            = 268,
  add_key               = 269,
  request_key           = 270,
  keyctl                = 271,
  waitid                = 272,
  ioprio_set            = 273,
  ioprio_get            = 274,
  inotify_init          = 275,
  inotify_add_watch     = 276,
  inotify_rm_watch      = 277,
  spu_run               = 278,
  spu_create            = 279,
  pselect6              = 280,
  ppoll                 = 281,
  unshare               = 282,
  splice                = 283,
  tee                   = 284,
  vmsplice              = 285,
  openat                = 286,
  mkdirat               = 287,
  mknodat               = 288,
  fchownat              = 289,
  futimesat             = 290,
  newfstatat            = 291,
  unlinkat              = 292,
  renameat              = 293,
  linkat                = 294,
  symlinkat             = 295,
  readlinkat            = 296,
  fchmodat              = 297,
  faccessat             = 298,
  get_robust_list       = 299,
  set_robust_list       = 300,
  move_pages            = 301,
  getcpu                = 302,
  epoll_pwait           = 303,
  utimensat             = 304,
  signalfd              = 305,
  timerfd_create        = 306,
  eventfd               = 307,
  sync_file_range2      = 308,
  fallocate             = 309,
  subpage_prot          = 310,
  timerfd_settime       = 311,
  timerfd_gettime       = 312,
  signalfd4             = 313,
  eventfd2              = 314,
  epoll_create1         = 315,
  dup3                  = 316,
  pipe2                 = 317,
  inotify_init1         = 318,
  perf_event_open       = 319,
  preadv                = 320,
  pwritev               = 321,
  rt_tgsigqueueinfo     = 322,
  fanotify_init         = 323,
  fanotify_mark         = 324,
  prlimit64             = 325,
  socket                = 326,
  bind                  = 327,
  connect               = 328,
  listen                = 329,
  accept                = 330,
  getsockname           = 331,
  getpeername           = 332,
  socketpair            = 333,
  send                  = 334,
  sendto                = 335,
  recv                  = 336,
  recvfrom              = 337,
  shutdown              = 338,
  setsockopt            = 339,
  getsockopt            = 340,
  sendmsg               = 341,
  recvmsg               = 342,
  recvmmsg              = 343,
  accept4               = 344,
  name_to_handle_at     = 345,
  open_by_handle_at     = 346,
  clock_adjtime         = 347,
  syncfs                = 348,
  sendmmsg              = 349,
  setns                 = 350,
  process_vm_readv      = 351,
  process_vm_writev     = 352,
  finit_module          = 353,
  kcmp                  = 354,
  sched_setattr         = 355,
  sched_getattr         = 356,
  renameat2             = 357,
  seccomp               = 358,
  getrandom             = 359,
  memfd_create          = 360,
  bpf                   = 361,
  execveat              = 362,
  switch_endian         = 363,
  userfaultfd           = 364,
  membarrier            = 365,
  mlock2                = 378,
  copy_file_range       = 379,
  preadv2               = 380,
  pwritev2              = 381,
}
}

nr.SYS.fstatat = nr.SYS.newfstatat

return nr

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.cgroup"],"module already exists")sources["syscall.linux.cgroup"]=([===[-- <pack syscall.linux.cgroup> --
-- Linux cgroup API
-- this is all file system operations packaged up to be easier to use

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local function init(S)

local h = require "syscall.helpers"
local split = h.split

local abi, types, c = S.abi, S.types, S.c
local t, pt, s = types.t, types.pt, types.s

local util = S.util

local cgroup = {}

local function mkgroup(name)
  -- append default location, should be tmpfs mount
  if name:sub(1, 1) ~= "/" then return "/sys/fs/cgroup" .. name else return name end
end

function cgroup.mount(tab)
  tab.source = tab.source or "cgroup"
  tab.type = "cgroup"
  tab.target = mkgroup(tab.target)
  return S.mount(tab)
end

function cgroup.cgroups(ps)
  ps = tostring(ps or "self")
  local cgf = util.readfile("/proc/" .. ps .. "/cgroup")
  local lines = split("\n", cgf)
  local cgroups = {}
  for i = 1, #lines - 1 do
    local parts = split( ":", lines[i])
    cgroups[parts[1]] = {name = parts[2], path = parts[3]}
  end
  return cgroups
end

return cgroup

end

return {init = init}



]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.sockopt"],"module already exists")sources["syscall.linux.sockopt"]=([===[-- <pack syscall.linux.sockopt> --
-- socket options mapping

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

-- TODO add typemap for cmsghdr from syscall/types.lua as very similar
-- like ioctls and so on, socket options are a random interface that needs some help to make it nice to use
-- we need to know the types of the options (in particular those that are not the default int)
-- in fact many ints are really bool, so nicer to know that too.

-- example
--c.SOL.SOCKET, c.SO.PASSCRED - bool

-- note that currently we use c.SOL[level], c.SO[optname] as level, optname for setsockopt and nothing for getsockopt
-- but the second one depends on the first like cmsghdr options and first seems more complex.

-- eg netfilter uses c.IPPROTO.IP or c.IPPROTO.IPV6 as level and eg c.IPT_SO_GET.REVISION_TARGET as level, optname
-- so you need to pass the level of the socket you opened? We can store with fd if you use methods, so get/set sockopt know... that will be easier as we can't know option names otherwise.
-- although you can always use SOL_SOCKET (1 in Linux, ffff BSD), so need to special case. Lucky ICMP (ipproto 1) has no sockets

-- IP supports both IP_ (and MULTI_) and eg IPT_ groups - BSD more consistent I think in that IPT is at raw IP socket level
-- so will need some fudging. Obviously the numbers dont overlap (IPT is >=64) see note /usr/include/linux/netfilter_ipv4/ip_tables.h

-- draft

-- will be more complex than this

--[[
local levelmaps = {
  [c.SOL.SOCKET] = c.SO,



}

local types = {
  SO = {
-- or could use [c.SO.ACCEPTCON] but not as nice
    ACCEPTCONN = "boolean", -- NB read only, potentially useful to add
    BINDTODEVICE = "string",
    BROADCAST = "boolean",
-- ...
  },
  IP = {
    ADD_MEMBERSHIP = t.ip_mreqn, -- IP multicast

  },


}

]]

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.x86.nr"],"module already exists")sources["syscall.linux.x86.nr"]=([===[-- <pack syscall.linux.x86.nr> --
-- x86 syscall numbers

local nr = {
  SYS = {
  restart_syscall = 0,
  exit		  = 1,
  fork		  = 2,
  read		  = 3,
  write		  = 4,
  open		  = 5,
  close		  = 6,
  waitpid	  = 7,
  creat		  = 8,
  link		  = 9,
  unlink	  = 10,
  execve	  = 11,
  chdir		  = 12,
  time		  = 13,
  mknod		  = 14,
  chmod		  = 15,
  lchown	  = 16,
  ["break"]	  = 17,
  oldstat	  = 18,
  lseek		  = 19,
  getpid	  = 20,
  mount		  = 21,
  umount	  = 22,
  setuid	  = 23,
  getuid	  = 24,
  stime		  = 25,
  ptrace	  = 26,
  alarm		  = 27,
  oldfstat	  = 28,
  pause		  = 29,
  utime		  = 30,
  stty		  = 31,
  gtty		  = 32,
  access	  = 33,
  nice		  = 34,
  ftime		  = 35,
  sync		  = 36,
  kill		  = 37,
  rename	  = 38,
  mkdir		  = 39,
  rmdir		  = 40,
  dup		  = 41,
  pipe		  = 42,
  times		  = 43,
  prof		  = 44,
  brk		  = 45,
  setgid	  = 46,
  getgid	  = 47,
  signal	  = 48,
  geteuid	  = 49,
  getegid	  = 50,
  acct		  = 51,
  umount2	  = 52,
  lock		  = 53,
  ioctl		  = 54,
  fcntl		  = 55,
  mpx		  = 56,
  setpgid	  = 57,
  ulimit	  = 58,
  oldolduname	  = 59,
  umask		  = 60,
  chroot	  = 61,
  ustat		  = 62,
  dup2		  = 63,
  getppid	  = 64,
  getpgrp	  = 65,
  setsid	  = 66,
  sigaction	  = 67,
  sgetmask	  = 68,
  ssetmask	  = 69,
  setreuid	  = 70,
  setregid	  = 71,
  sigsuspend	  = 72,
  sigpending	  = 73,
  sethostname	  = 74,
  setrlimit	  = 75,
  getrlimit	  = 76,
  getrusage	  = 77,
  gettimeofday	  = 78,
  settimeofday	  = 79,
  getgroups	  = 80,
  setgroups	  = 81,
  select	  = 82,
  symlink	  = 83,
  oldlstat	  = 84,
  readlink	  = 85,
  uselib	  = 86,
  swapon	  = 87,
  reboot	  = 88,
  readdir	  = 89,
  mmap		  = 90,
  munmap	  = 91,
  truncate	  = 92,
  ftruncate	  = 93,
  fchmod	  = 94,
  fchown	  = 95,
  getpriority	  = 96,
  setpriority	  = 97,
  profil	  = 98,
  statfs	  = 99,
  fstatfs	  = 100,
  ioperm	  = 101,
  socketcall	  = 102,
  syslog	  = 103,
  setitimer	  = 104,
  getitimer	  = 105,
  stat		  = 106,
  lstat		  = 107,
  fstat		  = 108,
  olduname	  = 109,
  iopl		  = 110,
  vhangup	  = 111,
  idle		  = 112,
  vm86old	  = 113,
  wait4		  = 114,
  swapoff	  = 115,
  sysinfo	  = 116,
  ipc		  = 117,
  fsync		  = 118,
  sigreturn	  = 119,
  clone		  = 120,
  setdomainname	  = 121,
  uname		  = 122,
  modify_ldt	  = 123,
  adjtimex	  = 124,
  mprotect	  = 125,
  sigprocmask	  = 126,
  create_module	  = 127,
  init_module	  = 128,
  delete_module	  = 129,
  get_kernel_syms = 130,
  quotactl	  = 131,
  getpgid	  = 132,
  fchdir	  = 133,
  bdflush	  = 134,
  sysfs		  = 135,
  personality	  = 136,
  afs_syscall	  = 137,
  setfsuid	  = 138,
  setfsgid	  = 139,
  _llseek	  = 140,
  getdents	  = 141,
  _newselect	  = 142,
  flock		  = 143,
  msync		  = 144,
  readv		  = 145,
  writev	  = 146,
  getsid	  = 147,
  fdatasync	  = 148,
  _sysctl	  = 149,
  mlock		  = 150,
  munlock	  = 151,
  mlockall	  = 152,
  munlockall	  = 153,
  sched_setparam  = 154,
  sched_getparam  = 155,
  sched_setscheduler = 156,
  sched_getscheduler = 157,
  sched_yield	  = 158,
  sched_get_priority_max = 159,
  sched_get_priority_min = 160,
  sched_rr_get_interval	 = 161,
  nanosleep	  = 162,
  mremap	  = 163,
  setresuid	  = 164,
  getresuid	  = 165,
  vm86		  = 166,
  query_module	  = 167,
  poll		  = 168,
  nfsservctl	  = 169,
  setresgid	  = 170,
  getresgid	  = 171,
  prctl           = 172,
  rt_sigreturn	  = 173,
  rt_sigaction	  = 174,
  rt_sigprocmask  = 175,
  rt_sigpending	  = 176,
  rt_sigtimedwait = 177,
  rt_sigqueueinfo = 178,
  rt_sigsuspend	  = 179,
  pread64	  = 180,
  pwrite64	  = 181,
  chown		  = 182,
  getcwd	  = 183,
  capget	  = 184,
  capset	  = 185,
  sigaltstack	  = 186,
  sendfile	  = 187,
  getpmsg	  = 188,
  putpmsg	  = 189,
  vfork		  = 190,
  ugetrlimit	  = 191,
  mmap2		  = 192,
  truncate64	  = 193,
  ftruncate64	  = 194,
  stat64	  = 195,
  lstat64	  = 196,
  fstat64	  = 197,
  lchown32	  = 198,
  getuid32	  = 199,
  getgid32	  = 200,
  geteuid32	  = 201,
  getegid32	  = 202,
  setreuid32	  = 203,
  setregid32	  = 204,
  getgroups32	  = 205,
  setgroups32	  = 206,
  fchown32	  = 207,
  setresuid32	  = 208,
  getresuid32	  = 209,
  setresgid32	  = 210,
  getresgid32	  = 211,
  chown32	  = 212,
  setuid32	  = 213,
  setgid32	  = 214,
  setfsuid32	  = 215,
  setfsgid32	  = 216,
  pivot_root	  = 217,
  mincore	  = 218,
  madvise	  = 219,
  getdents64	  = 220,
  fcntl64	  = 221,
  gettid	  = 224,
  readahead	  = 225,
  setxattr	  = 226,
  lsetxattr	  = 227,
  fsetxattr	  = 228,
  getxattr	  = 229,
  lgetxattr	  = 230,
  fgetxattr	  = 231,
  listxattr	  = 232,
  llistxattr	  = 233,
  flistxattr	  = 234,
  removexattr	  = 235,
  lremovexattr	  = 236,
  fremovexattr	  = 237,
  tkill		  = 238,
  sendfile64	  = 239,
  futex		  = 240,
  sched_setaffinity = 241,
  sched_getaffinity = 242,
  set_thread_area = 243,
  get_thread_area = 244,
  io_setup	  = 245,
  io_destroy	  = 246,
  io_getevents	  = 247,
  io_submit	  = 248,
  io_cancel	  = 249,
  fadvise64	  = 250,
  exit_group	  = 252,
  lookup_dcookie  = 253,
  epoll_create	  = 254,
  epoll_ctl	  = 255,
  epoll_wait	  = 256,
  remap_file_pages = 257,
  set_tid_address = 258,
  timer_create	  = 259,
  timer_settime	  = 260,
  timer_gettime	  = 261,
  timer_getoverrun = 262,
  timer_delete	  = 263,
  clock_settime	  = 264,
  clock_gettime	  = 265,
  clock_getres	  = 266,
  clock_nanosleep = 267,
  statfs64	  = 268,
  fstatfs64	  = 269,
  tgkill	  = 270,
  utimes	  = 271,
  fadvise64_64	  = 272,
  vserver	  = 273,
  mbind		  = 274,
  get_mempolicy	  = 275,
  set_mempolicy	  = 276,
  mq_open 	  = 277,
  mq_unlink	  = 278,
  mq_timedsend	  = 279,
  mq_timedreceive = 280,
  mq_notify	  = 281,
  mq_getsetattr	  = 282,
  kexec_load	  = 283,
  waitid	  = 284,
  add_key	  = 286,
  request_key	  = 287,
  keyctl	  = 288,
  ioprio_set	  = 289,
  ioprio_get	  = 290,
  inotify_init	  = 291,
  inotify_add_watch = 292,
  inotify_rm_watch  = 293,
  migrate_pages	  = 294,
  openat	  = 295,
  mkdirat	  = 296,
  mknodat	  = 297,
  fchownat	  = 298,
  futimesat	  = 299,
  fstatat64	  = 300,
  unlinkat	  = 301,
  renameat	  = 302,
  linkat	  = 303,
  symlinkat	  = 304,
  readlinkat	  = 305,
  fchmodat	  = 306,
  faccessat	  = 307,
  pselect6	  = 308,
  ppoll		  = 309,
  unshare	  = 310,
  set_robust_list = 311,
  get_robust_list = 312,
  splice	  = 313,
  sync_file_range = 314,
  tee		  = 315,
  vmsplice	  = 316,
  move_pages	  = 317,
  getcpu	  = 318,
  epoll_pwait	  = 319,
  utimensat	  = 320,
  signalfd	  = 321,
  timerfd_create  = 322,
  eventfd	  = 323,
  fallocate	  = 324,
  timerfd_settime = 325,
  timerfd_gettime = 326,
  signalfd4	  = 327,
  eventfd2	  = 328,
  epoll_create1	  = 329,
  dup3		  = 330,
  pipe2		  = 331,
  inotify_init1	  = 332,
  preadv	  = 333,
  pwritev	  = 334,
  prlimit64	  = 340,
  name_to_handle_at = 341,
  open_by_handle_at = 342,
  clock_adjtime	  = 343,
  syncfs	  = 344,
  sendmmsg	  = 345,
  setns		  = 346,
  process_vm_readv = 347,
  process_vm_writev = 348,
  kcmp            = 349,
  finit_module    = 350,
  sched_setattr   = 351,
  sched_getattr   = 352,
  renameat2       = 353,
  seccomp         = 354,
  getrandom       = 355,
  memfd_create    = 356,
  bpf             = 357,
}
}

return nr

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.x86.ioctl"],"module already exists")sources["syscall.linux.x86.ioctl"]=([===[-- <pack syscall.linux.x86.ioctl> --
-- x86 ioctl differences

local arch = {
  ioctl = {
  }
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.x86.constants"],"module already exists")sources["syscall.linux.x86.constants"]=([===[-- <pack syscall.linux.x86.constants> --
-- x86 specific code

local arch = {}

-- x86 register names
arch.REG = {
  GS         = 0,
  FS         = 1,
  ES         = 2,
  DS         = 3,
  EDI        = 4,
  ESI        = 5,
  EBP        = 6,
  ESP        = 7,
  EBX        = 8,
  EDX        = 9,
  ECX        = 10,
  EAX        = 11,
  TRAPNO     = 12,
  ERR        = 13,
  EIP        = 14,
  CS         = 15,
  EFL        = 16,
  UESP       = 17,
  SS         = 18,
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.mips.constants"],"module already exists")sources["syscall.linux.mips.constants"]=([===[-- <pack syscall.linux.mips.constants> --
-- mips specific constants

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local h = require "syscall.helpers"

local octal = h.octal

local abi = require "syscall.abi"

local arch = {}

arch.SIG = {
  HUP = 1,
  INT = 2,
  QUIT = 3,
  ILL = 4,
  TRAP = 5,
  ABRT = 6,
  EMT = 7,
  FPE = 8,
  KILL = 9,
  BUS = 10,
  SEGV = 11,
  SYS = 12,
  PIPE = 13,
  ALRM = 14,
  TERM = 15,
  USR1 = 16,
  USR2 = 17,
  CHLD = 18,
  PWR = 19,
  WINCH = 20,
  URG = 21,
  IO = 22,
  STOP = 23,
  TSTP = 24,
  CONT = 25,
  TTIN = 26,
  TTOU = 27,
  VTALRM = 28,
  PROF = 29,
  XCPU = 30,
  XFSZ = 31,
}

arch.SOCK = {
  DGRAM     = 1,
  STREAM    = 2,
  RAW       = 3,
  RDM       = 4,
  SEQPACKET = 5,
  DCCP      = 6,
  PACKET    = 10,

  CLOEXEC  = octal('02000000'),
  NONBLOCK = octal('0200'),
}

arch.MAP = {
  SHARED     = 0x001,
  PRIVATE    = 0x002,
  TYPE       = 0x00f,
  FIXED      = 0x010,
  NORESERVE  = 0x0400,
  ANONYMOUS  = 0x0800,
  GROWSDOWN  = 0x1000,
  DENYWRITE  = 0x2000,
  EXECUTABLE = 0x4000,
  LOCKED     = 0x8000,
  POPULATE   = 0x10000,
  NONBLOCK   = 0x20000,
  STACK      = 0x40000,
  HUGETLB    = 0x80000,
}

local __O_SYNC = 0x4000

arch.O = {
  RDONLY   = 0x0000,
  WRONLY   = 0x0001,
  RDWR     = 0x0002,
  ACCMODE  = 0x0003,
  APPEND   = 0x0008,
  DSYNC    = 0x0010,
  NONBLOCK = 0x0080,
  CREAT    = 0x0100,
  TRUNC    = 0x0200,
  EXCL     = 0x0400,
  NOCTTY   = 0x0800,
  LARGEFILE= 0x2000,
  DIRECT   = 0x8000,
  DIRECTORY= 0x10000,
  NOFOLLOW = 0x20000,
  NOATIME  = 0x40000,
  CLOEXEC  = octal '02000000',
}

arch.O_SYNC = __O_SYNC + arch.O.DSYNC -- compatibility, see notes in header, we do not expose __O_SYNC TODO check if this is best way

arch.TFD = {
  CLOEXEC = octal '02000000',
  NONBLOCK = octal '00000200',
}

arch.E = {
  PERM          =  1,
  NOENT         =  2,
  SRCH          =  3,
  INTR          =  4,
  IO            =  5,
  NXIO          =  6,
  ["2BIG"]      =  7,
  NOEXEC        =  8,
  BADF          =  9,
  CHILD         = 10,
  AGAIN         = 11,
  NOMEM         = 12,
  ACCES         = 13,
  FAULT         = 14,
  NOTBLK        = 15,
  BUSY          = 16,
  EXIST         = 17,
  XDEV          = 18,
  NODEV         = 19,
  NOTDIR        = 20,
  ISDIR         = 21,
  INVAL         = 22,
  NFILE         = 23,
  MFILE         = 24,
  NOTTY         = 25,
  TXTBSY        = 26,
  FBIG          = 27,
  NOSPC         = 28,
  SPIPE         = 29,
  ROFS          = 30,
  MLINK         = 31,
  PIPE          = 32,
  DOM           = 33,
  RANGE         = 34,
  NOMSG         = 35,
  IDRM          = 36,
  CHRNG         = 37,
  L2NSYNC       = 38,
  L3HLT         = 39,
  L3RST         = 40,
  LNRNG         = 41,
  UNATCH        = 42,
  NOCSI         = 43,
  L2HLT         = 44,
  DEADLK        = 45,
  NOLCK         = 46,
  BADE          = 50,
  BADR          = 51,
  XFULL         = 52,
  NOANO         = 53,
  BADRQC        = 54,
  BADSLT        = 55,
  DEADLOCK      = 56,
  BFONT         = 59,
  NOSTR         = 60,
  NODATA        = 61,
  TIME          = 62,
  NOSR          = 63,
  NONET         = 64,
  NOPKG         = 65,
  REMOTE        = 66,
  NOLINK        = 67,
  ADV           = 68,
  SRMNT         = 69,
  COMM          = 70,
  PROTO         = 71,
  DOTDOT        = 73,
  MULTIHOP      = 74,
  BADMSG        = 77,
  NAMETOOLONG   = 78,
  OVERFLOW      = 79,
  NOTUNIQ       = 80,
  BADFD         = 81,
  REMCHG        = 82,
  LIBACC        = 83,
  LIBBAD        = 84,
  LIBSCN        = 85,
  LIBMAX        = 86,
  LIBEXEC       = 87,
  ILSEQ         = 88,
  NOSYS         = 89,
  LOOP          = 90,
  RESTART       = 91,
  STRPIPE       = 92,
  NOTEMPTY      = 93,
  USERS         = 94,
  NOTSOCK       = 95,
  DESTADDRREQ   = 96,
  MSGSIZE       = 97,
  PROTOTYPE     = 98,
  NOPROTOOPT    = 99,
  PROTONOSUPPORT= 120,
  SOCKTNOSUPPORT= 121,
  OPNOTSUPP     = 122,
  PFNOSUPPORT   = 123,
  AFNOSUPPORT   = 124,
  ADDRINUSE     = 125,
  ADDRNOTAVAIL  = 126,
  NETDOWN       = 127,
  NETUNREACH    = 128,
  NETRESET      = 129,
  CONNABORTED   = 130,
  CONNRESET     = 131,
  NOBUFS        = 132,
  ISCONN        = 133,
  NOTCONN       = 134,
  UCLEAN        = 135,
  NOTNAM        = 137,
  NAVAIL        = 138,
  ISNAM         = 139,
  REMOTEIO      = 140,
  INIT          = 141,
  REMDEV        = 142,
  SHUTDOWN      = 143,
  TOOMANYREFS   = 144,
  TIMEDOUT      = 145,
  CONNREFUSED   = 146,
  HOSTDOWN      = 147,
  HOSTUNREACH   = 148,
  ALREADY       = 149,
  INPROGRESS    = 150,
  STALE         = 151,
  CANCELED      = 158,
  NOMEDIUM      = 159,
  MEDIUMTYPE    = 160,
  NOKEY         = 161,
  KEYEXPIRED    = 162,
  KEYREVOKED    = 163,
  KEYREJECTED   = 164,
  OWNERDEAD     = 165,
  NOTRECOVERABLE= 166,
  RFKILL        = 167,
  HWPOISON      = 168,
  DQUOT         = 1133,
}

arch.SFD = {
  CLOEXEC  = octal "02000000",
  NONBLOCK = octal "00000200",
}

arch.IN_INIT = {
  CLOEXEC  = octal("02000000"),
  NONBLOCK = octal("00000200"),
}

arch.SA = {
  ONSTACK     = 0x08000000,
  RESETHAND   = 0x80000000,
  RESTART     = 0x10000000,
  SIGINFO     = 0x00000008,
  NODEFER     = 0x40000000,
  NOCLDWAIT   = 0x00010000,
  NOCLDSTOP   = 0x00000001,
}

arch.SIGPM = {
  BLOCK     = 1,
  UNBLOCK   = 2,
  SETMASK   = 3,
}

arch.SI = {
  ASYNCNL = -60,
  TKILL = -6,
  SIGIO = -5,
  MESGQ = -4,
  TIMER = -3,
  ASYNCIO = -2,
  QUEUE = -1,
  USER = 0,
  KERNEL = 0x80,
}

arch.POLL = {
  IN          = 0x001,
  PRI         = 0x002,
  OUT         = 0x004,
  ERR         = 0x008,
  HUP         = 0x010,
  NVAL        = 0x020,
  RDNORM      = 0x040,
  RDBAND      = 0x080,
  WRBAND      = 0x100,
  MSG         = 0x400,
  REMOVE      = 0x1000,
  RDHUP       = 0x2000,
}

arch.POLL.WRNORM = arch.POLL.OUT

arch.RLIMIT = {
  CPU        = 0,
  FSIZE      = 1,
  DATA       = 2,
  STACK      = 3,
  CORE       = 4,
  NOFILE     = 5,
  AS         = 6,
  RSS        = 7,
  NPROC      = 8,
  MEMLOCK    = 9,
  LOCKS      = 10,
  SIGPENDING = 11,
  MSGQUEUE   = 12,
  NICE       = 13,
  RTPRIO     = 14,
  RTTIME     = 15,
}

-- note RLIM64_INFINITY looks like it varies by MIPS ABI but this is a glibc bug

arch.SO = {
  DEBUG       = 0x0001,
  REUSEADDR   = 0x0004,
  KEEPALIVE   = 0x0008,
  DONTROUTE   = 0x0010,
  BROADCAST   = 0x0020,
  LINGER      = 0x0080,
  OOBINLINE   = 0x0100,
--REUSEPORT   = 0x0200, -- not in kernel headers, although MIPS has had for longer
  TYPE        = 0x1008,
  ERROR       = 0x1007,
  SNDBUF      = 0x1001,
  RCVBUF      = 0x1002,
  SNDLOWAT    = 0x1003,
  RCVLOWAT    = 0x1004,
  SNDTIMEO    = 0x1005,
  RCVTIMEO    = 0x1006,
  ACCEPTCONN  = 0x1009,
  PROTOCOL    = 0x1028,
  DOMAIN      = 0x1029,

  NO_CHECK    = 11,
  PRIORITY    = 12,
  BSDCOMPAT   = 14,
  PASSCRED    = 17,
  PEERCRED    = 18,

  SECURITY_AUTHENTICATION = 22,
  SECURITY_ENCRYPTION_TRANSPORT = 23,
  SECURITY_ENCRYPTION_NETWORK = 24,
  BINDTODEVICE       = 25,
  ATTACH_FILTER      = 26,
  DETACH_FILTER      = 27,
  PEERNAME           = 28,
  TIMESTAMP          = 29,
  PEERSEC            = 30,
  SNDBUFFORCE        = 31,
  RCVBUFFORCE        = 33,
  PASSSEC            = 34,
  TIMESTAMPNS        = 35,
  MARK               = 36,
  TIMESTAMPING       = 37,
  RXQ_OVFL           = 40,
  WIFI_STATUS        = 41,
  PEEK_OFF           = 42,
  NOFCS              = 43,
--LOCK_FILTER        = 44, -- neither in our kernel headers
--SELECT_ERR_QUEUE   = 45,
}

arch.SO.STYLE = arch.SO.TYPE

arch.SOLSOCKET = 0xffff -- remainder of SOL values same

arch.F = {
  DUPFD       = 0,
  GETFD       = 1,
  SETFD       = 2,
  GETFL       = 3,
  SETFL       = 4,
  GETLK       = 14,
  SETLK       = 6,
  SETLKW      = 7,
  SETOWN      = 24,
  GETOWN      = 23,
  SETSIG      = 10,
  GETSIG      = 11,
  GETLK64     = 33,
  SETLK64     = 34,
  SETLKW64    = 35,
  SETOWN_EX   = 15,
  GETOWN_EX   = 16,
  SETLEASE    = 1024,
  GETLEASE    = 1025,
  NOTIFY      = 1026,
  SETPIPE_SZ  = 1031,
  GETPIPE_SZ  = 1032,
  DUPFD_CLOEXEC = 1030,
}

arch.TIOCM = {
  LE  = 0x001,
  DTR = 0x002,
  RTS = 0x004,
  ST  = 0x010,
  SR  = 0x020,
  CTS = 0x040,
  CAR = 0x100,
  RNG = 0x200,
  DSR = 0x400,
  OUT1 = 0x2000,
  OUT2 = 0x4000,
  LOOP = 0x8000,
}

arch.CC = {
  VINTR         =  0,
  VQUIT         =  1,
  VERASE        =  2,
  VKILL         =  3,
  VMIN          =  4,
  VTIME         =  5,
  VEOL2         =  6,
  VSWTC         =  7,
  VSTART        =  8,
  VSTOP         =  9,
  VSUSP         = 10,
-- VDSUSP not supported
  VREPRINT      = 12,
  VDISCARD      = 13,
  VWERASE       = 14,
  VLNEXT        = 15,
  VEOF          = 16,
  VEOL          = 17,
}

arch.CC.VSWTCH = arch.CC.VSWTC

arch.LFLAG = {
  ISIG    = octal '0000001',
  ICANON  = octal '0000002',
  XCASE   = octal '0000004',
  ECHO    = octal '0000010',
  ECHOE   = octal '0000020',
  ECHOK   = octal '0000040',
  ECHONL  = octal '0000100',
  NOFLSH  = octal '0000200',
  IEXTEN  = octal '0000400',
  ECHOCTL = octal '0001000',
  ECHOPRT = octal '0002000',
  ECHOKE  = octal '0004000',
  FLUSHO  = octal '0020000',
  PENDIN  = octal '0040000',
  TOSTOP  = octal '0100000',
  EXTPROC = octal '0200000',
}

arch.LFLAG.ITOSTOP = arch.LFLAG.TOSTOP

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.shared.types"],"module already exists")sources["syscall.shared.types"]=([===[-- <pack syscall.shared.types> --
-- this module defines the types with metatypes that are always common, so do not get errors redefining metatypes

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local ffi = require "ffi"

local bit = require "syscall.bit"

local t, ctypes, pt, s = {}, {}, {}, {}
local types = {t = t, pt = pt, s = s, ctypes = ctypes}

local h = require "syscall.helpers"

local addtype, addtype_var, addtype_fn, addraw2 = h.addtype, h.addtype_var, h.addtype_fn, h.addraw2
local addtype1, addtype2, addptrtype = h.addtype1, h.addtype2, h.addptrtype
local ptt, reviter, mktype, istype, lenfn, lenmt, getfd, newfn
  = h.ptt, h.reviter, h.mktype, h.istype, h.lenfn, h.lenmt, h.getfd, h.newfn
local ntohl, ntohl, ntohs, htons, htonl = h.ntohl, h.ntohl, h.ntohs, h.htons, h.htonl
local split, trim, strflag = h.split, h.trim, h.strflag
local align = h.align

local addtypes = {
  char = "char",
  uchar = "unsigned char",
  int = "int",
  uint = "unsigned int",
  int8 = "int8_t",
  uint8 = "uint8_t",
  int16 = "int16_t",
  uint16 = "uint16_t",
  int32 = "int32_t",
  uint32 = "uint32_t",
  int64 = "int64_t",
  uint64 = "uint64_t",
  long = "long",
  ulong = "unsigned long",
}

for k, v in pairs(addtypes) do addtype(types, k, v) end

local addtypes1 = {
  char1 = "char",
  uchar1 = "unsigned char",
  int1 = "int",
  uint1 = "unsigned int",
  int16_1 = "int16_t",
  uint16_1 = "uint16_t",
  int32_1 = "int32_t",
  uint32_1 = "uint32_t",
  int64_1 = "int64_t",
  uint64_1 = "uint64_t",
  long1 = "long",
  ulong1 = "unsigned long",
  intptr1 = "intptr_t",
  size1 = "size_t",
}

for k, v in pairs(addtypes1) do addtype1(types, k, v) end

local addtypes2 = {
  char2 = "char",
  int2 = "int",
  uint2 = "unsigned int",
}

for k, v in pairs(addtypes2) do addtype2(types, k, v) end

local ptrtypes = {
  uintptr = "uintptr_t",
  intptr = "intptr_t",
}

for k, v in pairs(ptrtypes) do addptrtype(types, k, v) end

t.ints = ffi.typeof("int[?]")
t.buffer = ffi.typeof("char[?]") -- TODO rename as chars?
t.string_array = ffi.typeof("const char *[?]")

local mt = {}

mt.iovec = {
  index = {
    base = function(self) return self.iov_base end,
    len = function(self) return self.iov_len end,
  },
}

addtype(types, "iovec", "struct iovec", mt.iovec)

mt.iovecs = {
  __len = function(io) return io.count end,
  __tostring = function(io)
    local s = {}
    for i = 0, io.count - 1 do
      local iovec = io.iov[i]
      s[i + 1] = ffi.string(iovec.iov_base, iovec.iov_len)
    end
    return table.concat(s)
  end;
  __new = function(tp, is)
    if type(is) == 'number' then return ffi.new(tp, is, is) end
    local count = #is
    local iov = ffi.new(tp, count, count)
    local j = 0
    for n, i in ipairs(is) do
      if type(i) == 'string' then
        local buf = t.buffer(#i)
        ffi.copy(buf, i, #i)
        iov.iov[j].iov_base = buf
        iov.iov[j].iov_len = #i
      elseif type(i) == 'number' then
        iov.iov[j].iov_base = t.buffer(i)
        iov.iov[j].iov_len = i
      elseif ffi.istype(t.iovec, i) then
        ffi.copy(iov[n], i, s.iovec)
      elseif type(i) == 'cdata' or type(i) == 'userdata' then -- eg buffer or other structure, userdata if luaffi
        iov.iov[j].iov_base = i
        iov.iov[j].iov_len = ffi.sizeof(i)
      else -- eg table
        iov.iov[j] = i
      end
      j = j + 1
    end
    return iov
  end,
}

addtype_var(types, "iovecs", "struct {int count; struct iovec iov[?];}", mt.iovecs)

-- convert strings to inet addresses and the reverse
local function inet4_ntop(src)
  local b = pt.uchar(src)
  return b[0] .. "." .. b[1] .. "." .. b[2] .. "." .. b[3]
end

local function inet6_ntop(src)
  local a = src.s6_addr
  local parts = {256*a[0] + a[1], 256*a[2] + a[3],   256*a[4] + a[5],   256*a[6] + a[7],
                 256*a[8] + a[9], 256*a[10] + a[11], 256*a[12] + a[13], 256*a[14] + a[15]}

  for i = 1, #parts do parts[i] = string.format("%x", parts[i]) end

  local start, max = 0, 0
  for i = 1, #parts do
    if parts[i] == "0" then
      local count = 0
      for j = i, #parts do
        if parts[j] == "0" then count = count + 1 else break end
      end
      if count > max then max, start = count, i end
    end
  end

  if max > 2 then
    parts[start] = ""
    if start == 1 or start + max == 9 then parts[start] = ":" end
    if start == 1 and start + max == 9 then parts[start] = "::" end 
    for i = 1, max - 1 do table.remove(parts, start + 1) end
  end

  return table.concat(parts, ":")
end

local function inet4_pton(src)
  local ip4 = split("%.", src)
  if #ip4 ~= 4 then error "malformed IP address" end
  return htonl(tonumber(ip4[1]) * 0x1000000 + tonumber(ip4[2]) * 0x10000 + tonumber(ip4[3]) * 0x100 + tonumber(ip4[4]))
end

local function hex(str) return tonumber("0x" .. str) end

local function inet6_pton(src, addr)
  -- TODO allow form with decimals at end for ipv4 addresses
  local ip8 = split(":", src)
  if #ip8 > 8 then return nil end
  local before, after = src:find("::")
  before, after = src:sub(1, before - 1), src:sub(after + 1)
  if before then
    if #ip8 == 8 then return nil end -- must be some missing
    if before == "" then before = "0" end
    if after == "" then after = "0" end
    src = before .. ":" .. string.rep("0:", 8 - #ip8 + 1) .. after
    ip8 = split(":", src)
  end
  for i = 1, 8 do
    addr.s6_addr[i * 2 - 1] = bit.band(hex(ip8[i]), 0xff)
    addr.s6_addr[i * 2 - 2] = bit.rshift(hex(ip8[i]), 8)
  end
  return addr
end

local inaddr = strflag {
  ANY = "0.0.0.0",
  LOOPBACK = "127.0.0.1",
  BROADCAST = "255.255.255.255",
}

local in6addr = strflag {
  ANY = "::",
  LOOPBACK = "::1",
}

 -- given this address and a mask, return a netmask and broadcast as in_addr
local function mask_bcast(address, netmask)
  local bcast = t.in_addr()
  local nmask = t.in_addr() -- TODO
  if netmask > 32 then error("bad netmask " .. netmask) end
  if netmask < 32 then nmask.s_addr = htonl(bit.rshift(-1, netmask)) end
  bcast.s_addr = bit.bor(tonumber(address.s_addr), nmask.s_addr)
  return {address = address, broadcast = bcast, netmask = nmask}
end

mt.in_addr = {
  __index = {
    get_mask_bcast = function(addr, mask) return mask_bcast(addr, mask) end,
  },
  newindex = {
    addr = function(addr, s)
      if ffi.istype(t.in_addr, s) then
        addr.s_addr = s.s_addr
      elseif type(s) == "string" then
        if inaddr[s] then s = inaddr[s] end
        addr.s_addr = inet4_pton(s)
      else -- number
        addr.s_addr = htonl(s)
      end
    end,
  },
  __tostring = inet4_ntop,
  __new = function(tp, s)
    local addr = ffi.new(tp)
    if s then addr.addr = s end
    return addr
  end,
  __len = lenfn,
}

addtype(types, "in_addr", "struct in_addr", mt.in_addr)

mt.in6_addr = {
  __tostring = inet6_ntop,
  __new = function(tp, s)
    local addr = ffi.new(tp)
    if s then
      if in6addr[s] then s = in6addr[s] end
      addr = inet6_pton(s, addr)
    end
    return addr
  end,
  __len = lenfn,
}

addtype(types, "in6_addr", "struct in6_addr", mt.in6_addr)

-- ip, udp types. Need endian conversions.
local ptchar = ffi.typeof("char *")
local uint16 = ffi.typeof("uint16_t[1]")

local function ip_checksum(buf, size, c, notfinal)
  c = c or 0
  local b8 = ffi.cast(ptchar, buf)
  local i16 = uint16()
  for i = 0, size - 1, 2 do
    ffi.copy(i16, b8 + i, 2)
    c = c + i16[0]
  end
  if size % 2 == 1 then
    i16[0] = 0
    ffi.copy(i16, b8[size - 1], 1)
    c = c + i16[0]
  end

  local v = bit.band(c, 0xffff)
  if v < 0 then v = v + 0x10000 end -- positive
  c = bit.rshift(c, 16) + v
  c = c + bit.rshift(c, 16)

  if not notfinal then c = bit.bnot(c) end
  if c < 0 then c = c + 0x10000 end -- positive
  return c
end

mt.iphdr = {
  index = {
    checksum = function(i) return function(i)
      i.check = 0
      i.check = ip_checksum(i, s.iphdr)
      return i.check
    end end,
  },
}

addtype(types, "iphdr", "struct iphdr", mt.iphdr)

local udphdr_size = ffi.sizeof("struct udphdr")

-- ugh, naming problems as cannot remove namespace as usual
-- checksum = function(u, ...) return 0 end, -- TODO checksum, needs IP packet info too. as method.
mt.udphdr = {
  index = {
    src = function(u) return ntohs(u.source) end,
    dst = function(u) return ntohs(u.dest) end,
    length = function(u) return ntohs(u.len) end,
    checksum = function(i) return function(i, ip, body)
      local bip = pt.char(ip)
      local bup = pt.char(i)
      local cs = 0
      -- checksum pseudo header
      cs = ip_checksum(bip + ffi.offsetof(ip, "saddr"), 4, cs, true)
      cs = ip_checksum(bip + ffi.offsetof(ip, "daddr"), 4, cs, true)
      local pr = t.char2(0, 17) -- c.IPPROTO.UDP
      cs = ip_checksum(pr, 2, cs, true)
      cs = ip_checksum(bup + ffi.offsetof(i, "len"), 2, cs, true)
      -- checksum udp header
      i.check = 0
      cs = ip_checksum(i, udphdr_size, cs, true)
      -- checksum body
      cs = ip_checksum(body, i.length - udphdr_size, cs)
      if cs == 0 then cs = 0xffff end
      i.check = cs
      return cs
    end end,
  },
  newindex = {
    src = function(u, v) u.source = htons(v) end,
    dst = function(u, v) u.dest = htons(v) end,
    length = function(u, v) u.len = htons(v) end,
  },
}

addtype(types, "udphdr", "struct udphdr", mt.udphdr)

mt.ethhdr = {
  -- TODO
}

addtype(types, "ethhdr", "struct ethhdr", mt.ethhdr)

mt.winsize = {
  index = {
    row = function(ws) return ws.ws_row end,
    col = function(ws) return ws.ws_col end,
    xpixel = function(ws) return ws.ws_xpixel end,
    ypixel = function(ws) return ws.ws_ypixel end,
  },
  newindex = {
    row = function(ws, v) ws.ws_row = v end,
    col = function(ws, v) ws.ws_col = v end,
    xpixel = function(ws, v) ws.ws_xpixel = v end,
    ypixel = function(ws, v) ws.ws_ypixel = v end,
  },
  __new = newfn,
}

addtype(types, "winsize", "struct winsize", mt.winsize)

return types

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ffi"],"module already exists")sources["syscall.linux.ffi"]=([===[-- <pack syscall.linux.ffi> --
-- ffi definitions of Linux types

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local abi = require "syscall.abi"

local ffi = require "ffi"

require "syscall.ffitypes"

local arch = require("syscall.linux." .. abi.arch .. ".ffi") -- architecture specific definitions

local defs = {}

local function append(str) defs[#defs + 1] = str end

append [[
typedef uint32_t mode_t;
typedef unsigned short int sa_family_t;
typedef uint64_t rlim64_t;
typedef unsigned long nlink_t;
typedef unsigned long ino_t;
typedef long time_t;
typedef int32_t daddr_t;
typedef long blkcnt_t;
typedef long blksize_t;
typedef int32_t clockid_t;
typedef long clock_t;
typedef uint32_t off32_t; /* only used for eg mmap2 on Linux */
typedef uint32_t le32; /* this is little endian - not really using it yet */
typedef uint32_t id_t;
typedef unsigned int tcflag_t;
typedef unsigned int speed_t;
typedef int timer_t;
typedef uint64_t fsblkcnt_t;
typedef uint64_t fsfilcnt_t;

/* despite glibc, Linux uses 32 bit dev_t */
typedef uint32_t dev_t;

typedef unsigned long aio_context_t;
typedef unsigned long nfds_t;

// should be a word, but we use 32 bits as bitops are signed 32 bit in LuaJIT at the moment
typedef int32_t fd_mask;

// again should be a long, and we have wrapped in a struct
// TODO ok to wrap Lua types but not syscall? https://github.com/justincormack/ljsyscall/issues/36
// TODO is this size right? check
struct cpu_set_t {
  int32_t val[1024 / (8 * sizeof (int32_t))];
};

typedef int mqd_t;
typedef int idtype_t; /* defined as enum */

struct timespec {
  time_t tv_sec;
  long   tv_nsec;
};

// misc
typedef void (*sighandler_t) (int);

// structs
struct timeval {
  long    tv_sec;         /* seconds */
  long    tv_usec;        /* microseconds */
};
struct itimerspec {
  struct timespec it_interval;
  struct timespec it_value;
};
struct itimerval {
  struct timeval it_interval;
  struct timeval it_value;
};
typedef struct __fsid_t {
  int __val[2];
} fsid_t;
//static const int UTSNAME_LENGTH = 65;
struct utsname {
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
  char domainname[65];
};
struct pollfd {
  int fd;
  short int events;
  short int revents;
};
typedef struct { /* based on Linux FD_SETSIZE = 1024, the kernel can do more, so can increase */
  fd_mask fds_bits[1024 / (sizeof (fd_mask) * 8)];
} fd_set;
struct ucred {
  pid_t pid;
  uid_t uid;
  gid_t gid;
};
struct rlimit64 {
  rlim64_t rlim_cur;
  rlim64_t rlim_max;
};
struct sysinfo {
  long uptime;
  unsigned long loads[3];
  unsigned long totalram;
  unsigned long freeram;
  unsigned long sharedram;
  unsigned long bufferram;
  unsigned long totalswap;
  unsigned long freeswap;
  unsigned short procs;
  unsigned short pad;
  unsigned long totalhigh;
  unsigned long freehigh;
  unsigned int mem_unit;
  char _f[20-2*sizeof(long)-sizeof(int)]; /* TODO ugh, remove calculation */
};
struct timex {
  unsigned int modes;
  long int offset;
  long int freq;
  long int maxerror;
  long int esterror;
  int status;
  long int constant;
  long int precision;
  long int tolerance;
  struct timeval time;
  long int tick;

  long int ppsfreq;
  long int jitter;
  int shift;
  long int stabil;
  long int jitcnt;
  long int calcnt;
  long int errcnt;
  long int stbcnt;

  int tai;

  int  :32; int  :32; int  :32; int  :32;
  int  :32; int  :32; int  :32; int  :32;
  int  :32; int  :32; int  :32;
};
typedef union sigval {
  int sival_int;
  void *sival_ptr;
} sigval_t;
struct cmsghdr {
  size_t cmsg_len;
  int cmsg_level;
  int cmsg_type;
  char cmsg_data[?];
};
struct msghdr {
  void *msg_name;
  socklen_t msg_namelen;
  struct iovec *msg_iov;
  size_t msg_iovlen;
  void *msg_control;
  size_t msg_controllen;
  int msg_flags;
};
struct mmsghdr {
  struct msghdr msg_hdr;
  unsigned int msg_len;
};
struct sockaddr {
  sa_family_t sa_family;
  char sa_data[14];
};
struct sockaddr_storage {
  sa_family_t ss_family;
  unsigned long int __ss_align;
  char __ss_padding[128 - 2 * sizeof(unsigned long int)]; /* total length 128 TODO no calculations */
};
struct sockaddr_in {
  sa_family_t    sin_family;
  in_port_t      sin_port;
  struct in_addr sin_addr;
  unsigned char  sin_zero[8];
};
struct sockaddr_in6 {
  sa_family_t    sin6_family;
  in_port_t sin6_port;
  uint32_t sin6_flowinfo;
  struct in6_addr sin6_addr;
  uint32_t sin6_scope_id;
};
struct sockaddr_un {
  sa_family_t sun_family;
  char        sun_path[108];
};
struct sockaddr_nl {
  sa_family_t     nl_family;
  unsigned short  nl_pad;
  uint32_t        nl_pid;
  uint32_t        nl_groups;
};
struct sockaddr_ll {
  unsigned short  sll_family;
  unsigned short  sll_protocol; /* __be16 */
  int             sll_ifindex;
  unsigned short  sll_hatype;
  unsigned char   sll_pkttype;
  unsigned char   sll_halen;
  unsigned char   sll_addr[8];
};
struct nlmsghdr {
  uint32_t           nlmsg_len;
  uint16_t           nlmsg_type;
  uint16_t           nlmsg_flags;
  uint32_t           nlmsg_seq;
  uint32_t           nlmsg_pid;
};
struct rtgenmsg {
  unsigned char rtgen_family;
};
struct ifinfomsg {
  unsigned char   ifi_family;
  unsigned char   __ifi_pad;
  unsigned short  ifi_type;
  int             ifi_index;
  unsigned        ifi_flags;
  unsigned        ifi_change;
};
struct rtattr {
  unsigned short  rta_len;
  unsigned short  rta_type;
};
struct nlmsgerr {
  int             error;
  struct nlmsghdr msg;
};
struct rtmsg {
  unsigned char rtm_family;
  unsigned char rtm_dst_len;
  unsigned char rtm_src_len;
  unsigned char rtm_tos;
  unsigned char rtm_table;
  unsigned char rtm_protocol;
  unsigned char rtm_scope;
  unsigned char rtm_type;
  unsigned int  rtm_flags;
};

static const int IFNAMSIZ = 16;

struct ifmap {
  unsigned long mem_start;
  unsigned long mem_end;
  unsigned short base_addr; 
  unsigned char irq;
  unsigned char dma;
  unsigned char port;
};
struct rtnl_link_stats {
  uint32_t rx_packets;
  uint32_t tx_packets;
  uint32_t rx_bytes;
  uint32_t tx_bytes;
  uint32_t rx_errors;
  uint32_t tx_errors;
  uint32_t rx_dropped;
  uint32_t tx_dropped;
  uint32_t multicast;
  uint32_t collisions;
  uint32_t rx_length_errors;
  uint32_t rx_over_errors;
  uint32_t rx_crc_errors;
  uint32_t rx_frame_errors;
  uint32_t rx_fifo_errors;
  uint32_t rx_missed_errors;
  uint32_t tx_aborted_errors;
  uint32_t tx_carrier_errors;
  uint32_t tx_fifo_errors;
  uint32_t tx_heartbeat_errors;
  uint32_t tx_window_errors;
  uint32_t rx_compressed;
  uint32_t tx_compressed;
};
struct ndmsg {
  uint8_t  ndm_family;
  uint8_t  ndm_pad1;
  uint16_t ndm_pad2;
  int32_t  ndm_ifindex;
  uint16_t ndm_state;
  uint8_t  ndm_flags;
  uint8_t  ndm_type;
};
struct nda_cacheinfo {
  uint32_t ndm_confirmed;
  uint32_t ndm_used;
  uint32_t ndm_updated;
  uint32_t ndm_refcnt;
};
struct ndt_stats {
  uint64_t ndts_allocs;
  uint64_t ndts_destroys;
  uint64_t ndts_hash_grows;
  uint64_t ndts_res_failed;
  uint64_t ndts_lookups;
  uint64_t ndts_hits;
  uint64_t ndts_rcv_probes_mcast;
  uint64_t ndts_rcv_probes_ucast;
  uint64_t ndts_periodic_gc_runs;
  uint64_t ndts_forced_gc_runs;
};
struct ndtmsg {
  uint8_t  ndtm_family;
  uint8_t  ndtm_pad1;
  uint16_t ndtm_pad2;
};
struct ndt_config {
  uint16_t ndtc_key_len;
  uint16_t ndtc_entry_size;
  uint32_t ndtc_entries;
  uint32_t ndtc_last_flush;
  uint32_t ndtc_last_rand;
  uint32_t ndtc_hash_rnd;
  uint32_t ndtc_hash_mask;
  uint32_t ndtc_hash_chain_gc;
  uint32_t ndtc_proxy_qlen;
};
typedef struct { 
  unsigned int clock_rate;
  unsigned int clock_type;
  unsigned short loopback;
} sync_serial_settings;
typedef struct { 
  unsigned int clock_rate;
  unsigned int clock_type;
  unsigned short loopback;
  unsigned int slot_map;
} te1_settings;
typedef struct {
  unsigned short encoding;
  unsigned short parity;
} raw_hdlc_proto;
typedef struct {
  unsigned int t391;
  unsigned int t392;
  unsigned int n391;
  unsigned int n392;
  unsigned int n393;
  unsigned short lmi;
  unsigned short dce;
} fr_proto;
typedef struct {
  unsigned int dlci;
} fr_proto_pvc;
typedef struct {
  unsigned int dlci;
  char master[IFNAMSIZ];
} fr_proto_pvc_info;
typedef struct {
  unsigned int interval;
  unsigned int timeout;
} cisco_proto;
struct if_settings {
  unsigned int type;
  unsigned int size;
  union {
    raw_hdlc_proto          *raw_hdlc;
    cisco_proto             *cisco;
    fr_proto                *fr;
    fr_proto_pvc            *fr_pvc;
    fr_proto_pvc_info       *fr_pvc_info;

    sync_serial_settings    *sync;
    te1_settings            *te1;
  } ifs_ifsu;
};
struct ifreq {
  union {
    char ifrn_name[IFNAMSIZ];
  } ifr_ifrn;
  union {
    struct  sockaddr ifru_addr;
    struct  sockaddr ifru_dstaddr;
    struct  sockaddr ifru_broadaddr;
    struct  sockaddr ifru_netmask;
    struct  sockaddr ifru_hwaddr;
    short   ifru_flags;
    int     ifru_ivalue;
    int     ifru_mtu;
    struct  ifmap ifru_map;
    char    ifru_slave[IFNAMSIZ];
    char    ifru_newname[IFNAMSIZ];
    void *  ifru_data;
    struct  if_settings ifru_settings;
  } ifr_ifru;
};
struct ifaddrmsg {
  uint8_t  ifa_family;
  uint8_t  ifa_prefixlen;
  uint8_t  ifa_flags;
  uint8_t  ifa_scope;
  uint32_t ifa_index;
};
struct ifa_cacheinfo {
  uint32_t ifa_prefered;
  uint32_t ifa_valid;
  uint32_t cstamp;
  uint32_t tstamp;
};
struct rta_cacheinfo {
  uint32_t rta_clntref;
  uint32_t rta_lastuse;
  uint32_t rta_expires;
  uint32_t rta_error;
  uint32_t rta_used;
  uint32_t rta_id;
  uint32_t rta_ts;
  uint32_t rta_tsage;
};
struct fdb_entry {
  uint8_t mac_addr[6];
  uint8_t port_no;
  uint8_t is_local;
  uint32_t ageing_timer_value;
  uint8_t port_hi;
  uint8_t pad0;
  uint16_t unused;
};
struct inotify_event {
  int wd;
  uint32_t mask;
  uint32_t cookie;
  uint32_t len;
  char name[?];
};
struct linux_dirent64 {
  uint64_t        d_ino;
  int64_t         d_off;
  unsigned short  d_reclen;
  unsigned char   d_type;
  char            d_name[0];
};
struct flock64 {
  short int l_type;
  short int l_whence;
  off_t l_start;
  off_t l_len;
  pid_t l_pid;
};
typedef union epoll_data {
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;
struct signalfd_siginfo {
  uint32_t ssi_signo;
  int32_t ssi_errno;
  int32_t ssi_code;
  uint32_t ssi_pid;
  uint32_t ssi_uid;
  int32_t ssi_fd;
  uint32_t ssi_tid;
  uint32_t ssi_band;
  uint32_t ssi_overrun;
  uint32_t ssi_trapno;
  int32_t ssi_status;
  int32_t ssi_int;
  uint64_t ssi_ptr;
  uint64_t ssi_utime;
  uint64_t ssi_stime;
  uint64_t ssi_addr;
  uint8_t __pad[48];
};
struct io_event {
  uint64_t           data;
  uint64_t           obj;
  int64_t            res;
  int64_t            res2;
};
struct seccomp_data {
  int nr;
  uint32_t arch;
  uint64_t instruction_pointer;
  uint64_t args[6];
};
struct sock_filter {
  uint16_t   code;
  uint8_t    jt;
  uint8_t    jf;
  uint32_t   k;
};
struct bpf_insn {
  uint8_t code;   /* opcode */
  uint8_t dst_reg:4;  /* dest register */
  uint8_t src_reg:4;  /* source register */
  uint16_t off;   /* signed offset */
  uint32_t imm;   /* signed immediate constant */
};
struct sock_fprog {
  unsigned short len;
  struct sock_filter *filter;
};
union bpf_attr {
  struct {
    uint32_t   map_type;
    uint32_t   key_size;
    uint32_t   value_size;
    uint32_t   max_entries;
  };
  struct {
    uint32_t   map_fd;
    uint64_t   key __attribute__((aligned(8)));
    union {
      uint64_t value __attribute__((aligned(8)));
      uint64_t next_key __attribute__((aligned(8)));
    };
    uint64_t   flags;
  };
  struct {
    uint32_t   prog_type;
    uint32_t   insn_cnt;
    uint64_t   insns __attribute__((aligned(8)));
    uint64_t   license __attribute__((aligned(8)));
    uint32_t   log_level;
    uint32_t   log_size;
    uint64_t   log_buf __attribute__((aligned(8)));
    uint32_t   kern_version;
  };
  struct {
    uint64_t   pathname __attribute__((aligned(8)));
    uint32_t   bpf_fd;
  };
} __attribute__((aligned(8)));
struct perf_event_attr {
  uint32_t pe_type;
  uint32_t size;
  uint64_t pe_config;
  union {
    uint64_t sample_period;
    uint64_t sample_freq;
  };
  uint64_t pe_sample_type;
  uint64_t read_format;
  uint32_t disabled:1,
    inherit:1,
    pinned:1,
    exclusive:1,
    exclude_user:1,
    exclude_kernel:1,
    exclude_hv:1,
    exclude_idle:1,
    mmap:1,
    comm:1,
    freq:1,
    inherit_stat:1,
    enable_on_exec:1,
    task:1,
    watermark:1,
    precise_ip:2,
    mmap_data:1,
    sample_id_all:1,
    exclude_host:1,
    exclude_guest:1,
    exclude_callchain_kernel:1,
    exclude_callchain_user:1,
    mmap2:1,
    comm_exec:1,
    use_clockid:1,
    __reserved_1a:6;
    uint32_t __reserved_1b;
  union {
    uint32_t wakeup_events;
    uint32_t wakeup_watermark;
  };
  uint32_t bp_type;
  union {
    uint64_t bp_addr;
    uint64_t config1;
  };
  union {
    uint64_t bp_len;
    uint64_t config2;
  };
  uint64_t branch_sample_type;
  uint64_t sample_regs_user;
  uint32_t sample_stack_user;
  int32_t clockid;
  uint64_t sample_regs_intr;
  uint32_t aux_watermark;
  uint32_t __reserved_2;
};
struct perf_event_mmap_page {
  uint32_t version;
  uint32_t compat_version;
  uint32_t lock;
  uint32_t index;
  int64_t offset;
  uint64_t time_enabled;
  uint64_t time_running;
  union {
     uint64_t   capabilities;
     struct {
         uint32_t cap_bit0 : 1,
           cap_bit0_is_deprecated : 1,
           cap_user_rdpmc         : 1,
           cap_user_time          : 1,
           cap_user_time_zero     : 1;
     };
  };
  uint16_t pmc_width;
  uint16_t time_shift;
  uint32_t time_mult;
  uint64_t time_offset;
  uint64_t __reserved[120];
  volatile uint64_t data_head;
  volatile uint64_t data_tail;
  volatile uint64_t data_offset;
  volatile uint64_t data_size;
  uint64_t aux_head;
  uint64_t aux_tail;
  uint64_t aux_offset;
  uint64_t aux_size;
};
struct perf_event_header {
  uint32_t   type;
  uint16_t   misc;
  uint16_t   size;
};
struct mq_attr {
  long mq_flags, mq_maxmsg, mq_msgsize, mq_curmsgs, __unused[4];
};
struct termios2 {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_line;
    cc_t c_cc[19];
    speed_t c_ispeed;
    speed_t c_ospeed;
};
struct input_event {
    struct timeval time;
    uint16_t type;
    uint16_t code;
    int32_t value;
};
struct input_id {
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
};
struct input_absinfo {
    int32_t value;
    int32_t minimum;
    int32_t maximum;
    int32_t fuzz;
    int32_t flat;
    int32_t resolution;
};
struct input_keymap_entry {
    uint8_t  flags;
    uint8_t  len;
    uint16_t index;
    uint32_t keycode;
    uint8_t  scancode[32];
};
struct ff_replay {
    uint16_t length;
    uint16_t delay;
};
struct ff_trigger {
    uint16_t button;
    uint16_t interval;
};
struct ff_envelope {
    uint16_t attack_length;
    uint16_t attack_level;
    uint16_t fade_length;
    uint16_t fade_level;
};
struct ff_constant_effect {
    int16_t level;
    struct ff_envelope envelope;
};
struct ff_ramp_effect {
    int16_t start_level;
    int16_t end_level;
    struct ff_envelope envelope;
};
struct ff_condition_effect {
    uint16_t right_saturation;
    uint16_t left_saturation;
    int16_t right_coeff;
    int16_t left_coeff;
    uint16_t deadband;
    int16_t center;
};
struct ff_periodic_effect {
    uint16_t waveform;
    uint16_t period;
    int16_t magnitude;
    int16_t offset;
    uint16_t phase;
    struct ff_envelope envelope;
    uint32_t custom_len;
    int16_t *custom_data;
};
struct ff_rumble_effect {
    uint16_t strong_magnitude;
    uint16_t weak_magnitude;
};
struct ff_effect {
    uint16_t type;
    int16_t id;
    uint16_t direction;
    struct ff_trigger trigger;
    struct ff_replay replay;
    union {
        struct ff_constant_effect constant;
        struct ff_ramp_effect ramp;
        struct ff_periodic_effect periodic;
        struct ff_condition_effect condition[2];
        struct ff_rumble_effect rumble;
    } u;
};
typedef struct {
  int     val[2];
} kernel_fsid_t;
/* we define the underlying structs not the pointer typedefs for capabilities */
struct user_cap_header {
  uint32_t version;
  int pid;
};
struct user_cap_data {
  uint32_t effective;
  uint32_t permitted;
  uint32_t inheritable;
};
/* this are overall capabilities structs to put metatables on */
struct cap {
  uint32_t cap[2];
};
struct capabilities {
  uint32_t version;
  int pid;
  struct cap effective;
  struct cap permitted;
  struct cap inheritable;
};
struct xt_get_revision {
  char name[29];
  uint8_t revision;
};
struct vfs_cap_data {
  le32 magic_etc;
  struct {
    le32 permitted;    /* Little endian */
    le32 inheritable;  /* Little endian */
  } data[2];
};
typedef struct {
  void *ss_sp;
  int ss_flags;
  size_t ss_size;
} stack_t;
struct sched_param {
  int sched_priority;
  /* unused after here */
  int sched_ss_low_priority;
  struct timespec sched_ss_repl_period;
  struct timespec sched_ss_init_budget;
  int sched_ss_max_repl;
};
struct tun_filter {
  uint16_t flags;
  uint16_t count;
  uint8_t addr[0][6];
};
struct tun_pi {
  uint16_t flags;
  uint16_t proto; /* __be16 */
};
struct vhost_vring_state {
  unsigned int index;
  unsigned int num;
};
struct vhost_vring_file {
  unsigned int index;
  int fd;
};
struct vhost_vring_addr {
  unsigned int index;
  unsigned int flags;
  uint64_t desc_user_addr;
  uint64_t used_user_addr;
  uint64_t avail_user_addr;
  uint64_t log_guest_addr;
};
struct vhost_memory_region {
  uint64_t guest_phys_addr;
  uint64_t memory_size;
  uint64_t userspace_addr;
  uint64_t flags_padding;
};
struct vhost_memory {
  uint32_t nregions;
  uint32_t padding;
  struct vhost_memory_region regions[0];
};
struct rusage {
  struct timeval ru_utime;
  struct timeval ru_stime;
  long    ru_maxrss;
  long    ru_ixrss;
  long    ru_idrss;
  long    ru_isrss;
  long    ru_minflt;
  long    ru_majflt;
  long    ru_nswap;
  long    ru_inblock;
  long    ru_oublock;
  long    ru_msgsnd;
  long    ru_msgrcv;
  long    ru_nsignals;
  long    ru_nvcsw;
  long    ru_nivcsw;
};
]]

append(arch.nsig or [[
static const int _NSIG = 64;
]]
)

append(arch.sigset or [[
// again, should be a long
static const int _NSIG_BPW = 32;
typedef struct {
  int32_t sig[_NSIG / _NSIG_BPW];
} sigset_t;
]]
)

-- both Glibc and Musl have larger termios at least for some architectures; I believe this is correct for kernel
append(arch.termios or [[
struct termios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[19];
};
]]
)

-- Linux struct siginfo padding depends on architecture
if abi.abi64 then
append [[
static const int SI_MAX_SIZE = 128;
static const int SI_PAD_SIZE = (SI_MAX_SIZE / sizeof (int)) - 4;
]]
else
append [[
static const int SI_MAX_SIZE = 128;
static const int SI_PAD_SIZE = (SI_MAX_SIZE / sizeof (int)) - 3;
]]
end

append(arch.siginfo or [[
typedef struct siginfo {
  int si_signo;
  int si_errno;
  int si_code;

  union {
    int _pad[SI_PAD_SIZE];

    struct {
      pid_t si_pid;
      uid_t si_uid;
    } kill;

    struct {
      int si_tid;
      int si_overrun;
      sigval_t si_sigval;
    } timer;

    struct {
      pid_t si_pid;
      uid_t si_uid;
      sigval_t si_sigval;
    } rt;

    struct {
      pid_t si_pid;
      uid_t si_uid;
      int si_status;
      clock_t si_utime;
      clock_t si_stime;
    } sigchld;

    struct {
      void *si_addr;
    } sigfault;

    struct {
      long int si_band;
       int si_fd;
    } sigpoll;
  } _sifields;
} siginfo_t;
]]
)

-- this is the type used by the rt_sigaction syscall NB have renamed the fields to sa_
append(arch.sigaction or [[
struct k_sigaction {
  void (*sa_handler)(int);
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  unsigned sa_mask[2];
};
]]
)

-- these could vary be arch but do not yet
append [[
static const int sigev_preamble_size = sizeof(int) * 2 + sizeof(sigval_t);
static const int sigev_max_size = 64;
static const int sigev_pad_size = (sigev_max_size - sigev_preamble_size) / sizeof(int);
typedef struct sigevent {
  sigval_t sigev_value;
  int sigev_signo;
  int sigev_notify;
  union {
    int _pad[sigev_pad_size];
    int _tid;
    struct {
      void (*_function)(sigval_t);
      void *_attribute;
    } _sigev_thread;
  } _sigev_un;
} sigevent_t;
]]

append(arch.ucontext) -- there is no default for ucontext and related types as very machine specific

if arch.statfs then append(arch.statfs)
else
-- Linux struct statfs/statfs64 depends on 64/32 bit
if abi.abi64 then
append [[
typedef long statfs_word;
]]
else
append [[
typedef uint32_t statfs_word;
]]
end

append [[
struct statfs64 {
  statfs_word f_type;
  statfs_word f_bsize;
  uint64_t f_blocks;
  uint64_t f_bfree;
  uint64_t f_bavail;
  uint64_t f_files;
  uint64_t f_ffree;
  kernel_fsid_t f_fsid;
  statfs_word f_namelen;
  statfs_word f_frsize;
  statfs_word f_flags;
  statfs_word f_spare[4];
};
]]
end

append(arch.stat)

-- epoll packed on x86_64 only (so same as x86)
append(arch.epoll or [[
struct epoll_event {
  uint32_t events;
  epoll_data_t data;
};
]]
)

-- endian dependent
if abi.le then
append [[
struct iocb {
  uint64_t   aio_data;
  uint32_t   aio_key, aio_reserved1;
  uint16_t   aio_lio_opcode;
  int16_t    aio_reqprio;
  uint32_t   aio_fildes;
  uint64_t   aio_buf;
  uint64_t   aio_nbytes;
  int64_t    aio_offset;
  uint64_t   aio_reserved2;
  uint32_t   aio_flags;
  uint32_t   aio_resfd;
};
]]
else
append [[
struct iocb {
  uint64_t   aio_data;
  uint32_t   aio_reserved1, aio_key;
  uint16_t   aio_lio_opcode;
  int16_t    aio_reqprio;
  uint32_t   aio_fildes;
  uint64_t   aio_buf;
  uint64_t   aio_nbytes;
  int64_t    aio_offset;
  uint64_t   aio_reserved2;
  uint32_t   aio_flags;
  uint32_t   aio_resfd;
};
]]
end

-- functions, minimal for Linux as mainly use syscall
append [[
long syscall(int number, ...);

int gettimeofday(struct timeval *tv, void *tz);
int clock_gettime(clockid_t clk_id, struct timespec *tp);

void exit(int status);
]]

ffi.cdef(table.concat(defs, ""))

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.types"],"module already exists")sources["syscall.linux.types"]=([===[-- <pack syscall.linux.types> --
-- Linux kernel types

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

-- TODO add __len to metatables of more

local function init(types)

local abi = require "syscall.abi"

local t, pt, s, ctypes = types.t, types.pt, types.s, types.ctypes

local ffi = require "ffi"
local bit = require "syscall.bit"

local h = require "syscall.helpers"

local addtype, addtype_var, addtype_fn, addraw2 = h.addtype, h.addtype_var, h.addtype_fn, h.addraw2
local ptt, reviter, mktype, istype, lenfn, lenmt, getfd, newfn
  = h.ptt, h.reviter, h.mktype, h.istype, h.lenfn, h.lenmt, h.getfd, h.newfn
local ntohl, ntohl, ntohs, htons = h.ntohl, h.ntohl, h.ntohs, h.htons
local split, trim = h.split, h.trim

local c = require "syscall.linux.constants"

local mt = {} -- metatables

-- TODO cleanup this (what should provide this?)
local signal_reasons_gen = {}
local signal_reasons = {}

for k, v in pairs(c.SI) do
  signal_reasons_gen[v] = k
end

signal_reasons[c.SIG.ILL] = {}
for k, v in pairs(c.SIGILL) do
  signal_reasons[c.SIG.ILL][v] = k
end

signal_reasons[c.SIG.FPE] = {}
for k, v in pairs(c.SIGFPE ) do
  signal_reasons[c.SIG.FPE][v] = k
end

signal_reasons[c.SIG.SEGV] = {}
for k, v in pairs(c.SIGSEGV) do
  signal_reasons[c.SIG.SEGV][v] = k
end

signal_reasons[c.SIG.BUS] = {}
for k, v in pairs(c.SIGBUS) do
  signal_reasons[c.SIG.BUS][v] = k
end

signal_reasons[c.SIG.TRAP] = {}
for k, v in pairs(c.SIGTRAP) do
  signal_reasons[c.SIG.TRAP][v] = k
end

signal_reasons[c.SIG.CHLD] = {}
for k, v in pairs(c.SIGCLD) do
  signal_reasons[c.SIG.CHLD][v] = k
end

signal_reasons[c.SIG.POLL] = {}
for k, v in pairs(c.SIGPOLL or {}) do
  signal_reasons[c.SIG.POLL][v] = k
end

local addtypes = {
  fdset = "fd_set",
  clockid = "clockid_t",
  sighandler = "sighandler_t",
  aio_context = "aio_context_t",
  clockid = "clockid_t",
}

local addstructs = {
  ucred = "struct ucred",
  sysinfo = "struct sysinfo",
  nlmsghdr = "struct nlmsghdr",
  rtgenmsg = "struct rtgenmsg",
  ifinfomsg = "struct ifinfomsg",
  ifaddrmsg = "struct ifaddrmsg",
  rtattr = "struct rtattr",
  rta_cacheinfo = "struct rta_cacheinfo",
  nlmsgerr = "struct nlmsgerr",
  nda_cacheinfo = "struct nda_cacheinfo",
  ndt_stats = "struct ndt_stats",
  ndtmsg = "struct ndtmsg",
  ndt_config = "struct ndt_config",
  utsname = "struct utsname",
  fdb_entry = "struct fdb_entry",
  seccomp_data = "struct seccomp_data",
  rtnl_link_stats = "struct rtnl_link_stats",
  statfs = "struct statfs64",
  ifa_cacheinfo = "struct ifa_cacheinfo",
  input_event = "struct input_event",
  input_id = "struct input_id",
  input_absinfo = "struct input_absinfo",
  input_keymap_entry = "struct input_keymap_entry",
  ff_replay = "struct ff_replay",
  ff_trigger = "struct ff_trigger",
  ff_envelope = "struct ff_envelope",
  ff_constant_effect = "struct ff_constant_effect",
  ff_ramp_effect = "struct ff_ramp_effect",
  ff_condition_effect = "struct ff_condition_effect",
  ff_periodic_effect = "struct ff_periodic_effect",
  ff_rumble_effect = "struct ff_rumble_effect",
  ff_effect = "struct ff_effect",
  sock_fprog = "struct sock_fprog",
  bpf_attr = "union bpf_attr",
  user_cap_header = "struct user_cap_header",
  user_cap_data = "struct user_cap_data",
  xt_get_revision = "struct xt_get_revision",
  vfs_cap_data = "struct vfs_cap_data",
  ucontext = "ucontext_t",
  mcontext = "mcontext_t",
  tun_pi = "struct tun_pi",
  tun_filter = "struct tun_filter",
  vhost_vring_state = "struct vhost_vring_state",
  vhost_vring_file = "struct vhost_vring_file",
  vhost_vring_addr = "struct vhost_vring_addr",
  vhost_memory_region = "struct vhost_memory_region",
  vhost_memory = "struct vhost_memory",
}

for k, v in pairs(addtypes) do addtype(types, k, v) end
for k, v in pairs(addstructs) do addtype(types, k, v, lenmt) end

-- these ones not in table as not helpful with vararg or arrays TODO add more addtype variants
t.inotify_event = ffi.typeof("struct inotify_event")
pt.inotify_event = ptt("struct inotify_event") -- still need pointer to this
pt.perf_event_header = ptt("struct perf_event_header")

t.aio_context1 = ffi.typeof("aio_context_t[1]")
t.sock_fprog1 = ffi.typeof("struct sock_fprog[1]")
t.bpf_attr1 = ffi.typeof("union bpf_attr[1]")
t.perf_event_attr1 = ffi.typeof("struct perf_event_attr[1]")

t.user_cap_data2 = ffi.typeof("struct user_cap_data[2]")

-- luaffi gets confused if call ffi.typeof("...[?]") it calls __new so redefine as functions
local iocbs = ffi.typeof("struct iocb[?]")
t.iocbs = function(n, ...) return ffi.new(iocbs, n, ...) end
local sock_filters = ffi.typeof("struct sock_filter[?]")
t.sock_filters = function(n, ...) return ffi.new(sock_filters, n, ...) end
local bpf_insns = ffi.typeof("struct bpf_insn[?]")
t.bpf_insns = function(n, ...) return ffi.new(bpf_insns, n, ...) end
local iocb_ptrs = ffi.typeof("struct iocb *[?]")
t.iocb_ptrs = function(n, ...) return ffi.new(iocb_ptrs, n, ...) end

-- types with metatypes

-- Note 32 bit dev_t; glibc has 64 bit dev_t but we use syscall API which does not
local function makedev(major, minor)
  if type(major) == "table" then major, minor = major[1], major[2] end
  local dev = major or 0
  if minor then dev = bit.bor(bit.lshift(bit.band(minor, 0xffffff00), 12), bit.band(minor, 0xff), bit.lshift(major, 8)) end
  return dev
end

mt.device = {
  index = {
    major = function(dev)
      local d = dev.dev
      return bit.band(bit.rshift(d, 8), 0x00000fff)
    end,
    minor = function(dev)
      local d = dev.dev
      return bit.bor(bit.band(d, 0x000000ff), bit.band(bit.rshift(d, 12), 0x000000ff))
    end,
    device = function(dev) return tonumber(dev.dev) end,
  },
  newindex = {
    device = function(dev, major, minor) dev.dev = makedev(major, minor) end,
  },
  __new = function(tp, major, minor)
    return ffi.new(tp, makedev(major, minor))
  end,
}

addtype(types, "device", "struct {dev_t dev;}", mt.device)

mt.sockaddr = {
  index = {
    family = function(sa) return sa.sa_family end,
  },
}

addtype(types, "sockaddr", "struct sockaddr", mt.sockaddr)

-- cast socket address to actual type based on family, defined later
local samap_pt = {}

mt.sockaddr_storage = {
  index = {
    family = function(sa) return sa.ss_family end,
  },
  newindex = {
    family = function(sa, v) sa.ss_family = c.AF[v] end,
  },
  __index = function(sa, k)
    if mt.sockaddr_storage.index[k] then return mt.sockaddr_storage.index[k](sa) end
    local st = samap_pt[sa.ss_family]
    if st then
      local cs = st(sa)
      return cs[k]
    end
    error("invalid index " .. k)
  end,
  __newindex = function(sa, k, v)
    if mt.sockaddr_storage.newindex[k] then
      mt.sockaddr_storage.newindex[k](sa, v)
      return
    end
    local st = samap_pt[sa.ss_family]
    if st then
      local cs = st(sa)
      cs[k] = v
      return
    end
    error("invalid index " .. k)
  end,
  __new = function(tp, init)
    local ss = ffi.new(tp)
    local family
    if init and init.family then family = c.AF[init.family] end
    local st
    if family then
      st = samap_pt[family]
      ss.ss_family = family
      init.family = nil
    end
    if st then
      local cs = st(ss)
      for k, v in pairs(init) do
        cs[k] = v
      end
    end
    return ss
  end,
  -- netbsd likes to see the correct size when it gets a sockaddr; Linux was ok with a longer one
  __len = function(sa)
    if samap_pt[sa.family] then
      local cs = samap_pt[sa.family](sa)
      return #cs
    else
      return s.sockaddr_storage
    end
  end,
}

-- experiment, see if we can use this as generic type, to avoid allocations.
addtype(types, "sockaddr_storage", "struct sockaddr_storage", mt.sockaddr_storage)

mt.sockaddr_in = {
  index = {
    family = function(sa) return sa.sin_family end,
    port = function(sa) return ntohs(sa.sin_port) end,
    addr = function(sa) return sa.sin_addr end,
  },
  newindex = {
    family = function(sa, v) sa.sin_family = v end,
    port = function(sa, v) sa.sin_port = htons(v) end,
    addr = function(sa, v) sa.sin_addr = mktype(t.in_addr, v) end,
  },
  __new = function(tp, port, addr)
    if type(port) == "table" then return newfn(tp, port) end
    return newfn(tp, {family = c.AF.INET, port = port, addr = addr})
  end,
  __len = function(tp) return s.sockaddr_in end,
}

addtype(types, "sockaddr_in", "struct sockaddr_in", mt.sockaddr_in)

mt.sockaddr_in6 = {
  index = {
    family = function(sa) return sa.sin6_family end,
    port = function(sa) return ntohs(sa.sin6_port) end,
    addr = function(sa) return sa.sin6_addr end,
  },
  newindex = {
    family = function(sa, v) sa.sin6_family = v end,
    port = function(sa, v) sa.sin6_port = htons(v) end,
    addr = function(sa, v) sa.sin6_addr = mktype(t.in6_addr, v) end,
    flowinfo = function(sa, v) sa.sin6_flowinfo = v end,
    scope_id = function(sa, v) sa.sin6_scope_id = v end,
  },
  __new = function(tp, port, addr, flowinfo, scope_id) -- reordered initialisers.
    if type(port) == "table" then return newfn(tp, port) end
    return newfn(tp, {family = c.AF.INET6, port = port, addr = addr, flowinfo = flowinfo, scope_id = scope_id})
  end,
  __len = function(tp) return s.sockaddr_in6 end,
}

addtype(types, "sockaddr_in6", "struct sockaddr_in6", mt.sockaddr_in6)

-- we do provide this directly for compatibility, only use for standard names
mt.sockaddr_un = {
  index = {
    family = function(sa) return sa.sun_family end,
    path = function(sa) return ffi.string(sa.sun_path) end, -- only valid for proper names
  },
  newindex = {
    family = function(sa, v) sa.sun_family = v end,
    path = function(sa, v) ffi.copy(sa.sun_path, v) end,
  },
  __new = function(tp, path) return newfn(tp, {family = c.AF.UNIX, path = path}) end, -- TODO accept table initialiser
  __len = function(tp) return s.sockaddr_un end, -- TODO lenfn (default) instead
}

addtype(types, "sockaddr_un", "struct sockaddr_un", mt.sockaddr_un)

-- this is a bit odd, but we actually use Lua metatables for sockaddr_un, and use t.sa to multiplex
-- basically the lINUX unix socket structure is not possible to interpret without size, but does not have size in struct
-- nasty, but have not thought of a better way yet; could make an ffi type
local lua_sockaddr_un_mt = {
  __index = function(un, k)
    local sa = un.addr
    if k == 'family' then return sa.family end
    local namelen = un.addrlen - s.sun_family
    if namelen > 0 then
      if sa.sun_path[0] == 0 then
        if k == 'abstract' then return true end
        if k == 'name' then return ffi.string(sa.sun_path, namelen) end -- should we also remove leading \0?
      else
        if k == 'name' then return ffi.string(sa.sun_path) end
      end
    else
      if k == 'unnamed' then return true end
    end
  end,
  __len = function(un) return un.addrlen end,
}

function t.sa(addr, addrlen)
  local family = addr.family
  if family == c.AF.UNIX then -- we return Lua metatable not metatype, as need length to decode
    local sa = t.sockaddr_un()
    ffi.copy(sa, addr, addrlen)
    return setmetatable({addr = sa, addrlen = addrlen}, lua_sockaddr_un_mt)
  end
  return addr
end

local nlgroupmap = { -- map from netlink socket type to group names. Note there are two forms of name though, bits and shifts.
  [c.NETLINK.ROUTE] = c.RTMGRP, -- or RTNLGRP_ and shift not mask TODO make shiftflags function
  -- add rest of these
--  [c.NETLINK.SELINUX] = c.SELNLGRP,
}

mt.sockaddr_nl = {
  index = {
    family = function(sa) return sa.nl_family end,
    pid = function(sa) return sa.nl_pid end,
    groups = function(sa) return sa.nl_groups end,
  },
  newindex = {
    pid = function(sa, v) sa.nl_pid = v end,
    groups = function(sa, v) sa.nl_groups = v end,
  },
  __new = function(tp, pid, groups, nltype)
    if type(pid) == "table" then
      local tb = pid
      pid, groups, nltype = tb.nl_pid or tb.pid, tb.nl_groups or tb.groups, tb.type
    end
    if nltype and nlgroupmap[nltype] then groups = nlgroupmap[nltype][groups] end -- see note about shiftflags
    return ffi.new(tp, {nl_family = c.AF.NETLINK, nl_pid = pid, nl_groups = groups})
  end,
  __len = function(tp) return s.sockaddr_nl end,
}

addtype(types, "sockaddr_nl", "struct sockaddr_nl", mt.sockaddr_nl)

mt.sockaddr_ll = {
  index = {
    family = function(sa) return sa.sll_family end,
    protocol = function(sa) return ntohs(sa.sll_protocol) end,
    ifindex = function(sa) return sa.sll_ifindex end,
    hatype = function(sa) return sa.sll_hatype end,
    pkttype = function(sa) return sa.sll_pkttype end,
    halen = function(sa) return sa.sll_halen end,
    addr = function(sa)
      if sa.sll_halen == 6 then return pt.macaddr(sa.sll_addr) else return ffi.string(sa.sll_addr, sa.sll_halen) end
    end,
  },
  newindex = {
    protocol = function(sa, v) sa.sll_protocol = htons(c.ETH_P[v]) end,
    ifindex = function(sa, v) sa.sll_ifindex = v end,
    hatype = function(sa, v) sa.sll_hatype = v end,
    pkttype = function(sa, v) sa.sll_pkttype = v end,
    halen = function(sa, v) sa.sll_halen = v end,
    addr = function(sa, v)
      if ffi.istype(t.macaddr, v) then
        sa.sll_halen = 6
        ffi.copy(sa.sll_addr, v, 6)
      else sa.sll_addr = v end
    end,
  },
  __new = function(tp, tb)
    local sa = ffi.new(tp, {sll_family = c.AF.PACKET})
    for k, v in pairs(tb or {}) do sa[k] = v end
    return sa
  end,
  __len = function(tp) return s.sockaddr_ll end,
}

addtype(types, "sockaddr_ll", "struct sockaddr_ll", mt.sockaddr_ll)

mt.stat = {
  index = {
    dev = function(st) return t.device(st.st_dev) end,
    ino = function(st) return tonumber(st.st_ino) end,
    mode = function(st) return st.st_mode end,
    nlink = function(st) return tonumber(st.st_nlink) end,
    uid = function(st) return st.st_uid end,
    gid = function(st) return st.st_gid end,
    size = function(st) return tonumber(st.st_size) end,
    blksize = function(st) return tonumber(st.st_blksize) end,
    blocks = function(st) return tonumber(st.st_blocks) end,
    atime = function(st) return tonumber(st.st_atime) end,
    ctime = function(st) return tonumber(st.st_ctime) end,
    mtime = function(st) return tonumber(st.st_mtime) end,
    rdev = function(st) return t.device(st.st_rdev) end,

    type = function(st) return bit.band(st.st_mode, c.S_I.FMT) end,
    todt = function(st) return bit.rshift(st.type, 12) end,
    isreg = function(st) return st.type == c.S_I.FREG end,
    isdir = function(st) return st.type == c.S_I.FDIR end,
    ischr = function(st) return st.type == c.S_I.FCHR end,
    isblk = function(st) return st.type == c.S_I.FBLK end,
    isfifo = function(st) return st.type == c.S_I.FIFO end,
    islnk = function(st) return st.type == c.S_I.FLNK end,
    issock = function(st) return st.type == c.S_I.FSOCK end,
  },
}

-- add some friendlier names to stat, also for luafilesystem compatibility
mt.stat.index.access = mt.stat.index.atime
mt.stat.index.modification = mt.stat.index.mtime
mt.stat.index.change = mt.stat.index.ctime

local namemap = {
  file             = mt.stat.index.isreg,
  directory        = mt.stat.index.isdir,
  link             = mt.stat.index.islnk,
  socket           = mt.stat.index.issock,
  ["char device"]  = mt.stat.index.ischr,
  ["block device"] = mt.stat.index.isblk,
  ["named pipe"]   = mt.stat.index.isfifo,
}

mt.stat.index.typename = function(st)
  for k, v in pairs(namemap) do if v(st) then return k end end
  return "other"
end

addtype(types, "stat", "struct stat", mt.stat)

local signames = {}
local duplicates = {IOT = true, CLD = true, POLL = true}
for k, v in pairs(c.SIG) do
  if not duplicates[k] then signames[v] = k end
end

-- TODO this is broken, need to use fields from the correct union technically
-- ie check which of the unions we should be using and get all fields from that
-- (note as per Musl list the standard kernel,glibc definitions are wrong too...)
mt.siginfo = {
  index = {
    signo   = function(s) return s.si_signo end,
    errno   = function(s) return s.si_errno end,
    code    = function(s) return s.si_code end,
    pid     = function(s) return s._sifields.kill.si_pid end,
    uid     = function(s) return s._sifields.kill.si_uid end,
    timerid = function(s) return s._sifields.timer.si_tid end,
    overrun = function(s) return s._sifields.timer.si_overrun end,
    status  = function(s) return s._sifields.sigchld.si_status end,
    utime   = function(s) return s._sifields.sigchld.si_utime end,
    stime   = function(s) return s._sifields.sigchld.si_stime end,
    value   = function(s) return s._sifields.rt.si_sigval end,
    int     = function(s) return s._sifields.rt.si_sigval.sival_int end,
    ptr     = function(s) return s._sifields.rt.si_sigval.sival_ptr end,
    addr    = function(s) return s._sifields.sigfault.si_addr end,
    band    = function(s) return s._sifields.sigpoll.si_band end,
    fd      = function(s) return s._sifields.sigpoll.si_fd end,
    signame = function(s) return signames[s.signo] end,
  },
  newindex = {
    signo   = function(s, v) s.si_signo = v end,
    errno   = function(s, v) s.si_errno = v end,
    code    = function(s, v) s.si_code = v end,
    pid     = function(s, v) s._sifields.kill.si_pid = v end,
    uid     = function(s, v) s._sifields.kill.si_uid = v end,
    timerid = function(s, v) s._sifields.timer.si_tid = v end,
    overrun = function(s, v) s._sifields.timer.si_overrun = v end,
    status  = function(s, v) s._sifields.sigchld.si_status = v end,
    utime   = function(s, v) s._sifields.sigchld.si_utime = v end,
    stime   = function(s, v) s._sifields.sigchld.si_stime = v end,
    value   = function(s, v) s._sifields.rt.si_sigval = v end,
    int     = function(s, v) s._sifields.rt.si_sigval.sival_int = v end,
    ptr     = function(s, v) s._sifields.rt.si_sigval.sival_ptr = v end,
    addr    = function(s, v) s._sifields.sigfault.si_addr = v end,
    band    = function(s, v) s._sifields.sigpoll.si_band = v end,
    fd      = function(s, v) s._sifields.sigpoll.si_fd = v end,
  },
}

addtype(types, "siginfo", "struct siginfo", mt.siginfo)

-- Linux internally uses non standard sigaction type k_sigaction
local sa_handler_type = ffi.typeof("void (*)(int)")
local to_handler = function(v) return ffi.cast(sa_handler_type, t.uintptr(v)) end -- luaffi needs uintptr, and full cast
mt.sigaction = {
  index = {
    handler = function(sa) return sa.sa_handler end,
    sigaction = function(sa) return sa.sa_handler end,
    mask = function(sa) return sa.sa_mask end, -- TODO would rather return type of sigset_t
    flags = function(sa) return tonumber(sa.sa_flags) end,
  },
  newindex = {
    handler = function(sa, v)
      if type(v) == "string" then v = to_handler(c.SIGACT[v]) end
      if type(v) == "number" then v = to_handler(v) end
      sa.sa_handler = v
    end,
    sigaction = function(sa, v)
      if type(v) == "string" then v = to_handler(c.SIGACT[v]) end
      if type(v) == "number" then v = to_handler(v) end
      sa.sa_handler.sa_sigaction = v
    end,
    mask = function(sa, v)
      if not ffi.istype(t.sigset, v) then v = t.sigset(v) end
      ffi.copy(sa.sa_mask, v, ffi.sizeof(sa.sa_mask))
    end,
    flags = function(sa, v) sa.sa_flags = c.SA[v] end,
  },
  __new = function(tp, tab)
    local sa = ffi.new(tp)
    if tab then for k, v in pairs(tab) do sa[k] = v end end
    if tab and tab.sigaction then sa.sa_flags = bit.bor(sa.flags, c.SA.SIGINFO) end -- this flag must be set if sigaction set
    return sa
  end,
}

addtype(types, "sigaction", "struct k_sigaction", mt.sigaction)

mt.rlimit = {
  index = {
    cur = function(r) if r.rlim_cur == c.RLIM.INFINITY then return -1 else return tonumber(r.rlim_cur) end end,
    max = function(r) if r.rlim_max == c.RLIM.INFINITY then return -1 else return tonumber(r.rlim_max) end end,
  },
  newindex = {
    cur = function(r, v)
      if v == -1 then v = c.RLIM.INFINITY end
      r.rlim_cur = c.RLIM[v] -- allows use of "infinity"
    end,
    max = function(r, v)
      if v == -1 then v = c.RLIM.INFINITY end
      r.rlim_max = c.RLIM[v] -- allows use of "infinity"
    end,
  },
  __new = newfn,
}

-- TODO some fields still missing
mt.sigevent = {
  index = {
    notify = function(self) return self.sigev_notify end,
    signo = function(self) return self.sigev_signo end,
    value = function(self) return self.sigev_value end,
  },
  newindex = {
    notify = function(self, v) self.sigev_notify = c.SIGEV[v] end,
    signo = function(self, v) self.sigev_signo = c.SIG[v] end,
    value = function(self, v) self.sigev_value = t.sigval(v) end, -- auto assigns based on type
  },
  __new = newfn,
}

addtype(types, "sigevent", "struct sigevent", mt.sigevent)

addtype(types, "rlimit", "struct rlimit64", mt.rlimit)

mt.signalfd = {
  index = {
    signo = function(ss) return tonumber(ss.ssi_signo) end,
    code = function(ss) return tonumber(ss.ssi_code) end,
    pid = function(ss) return tonumber(ss.ssi_pid) end,
    uid = function(ss) return tonumber(ss.ssi_uid) end,
    fd = function(ss) return tonumber(ss.ssi_fd) end,
    tid = function(ss) return tonumber(ss.ssi_tid) end,
    band = function(ss) return tonumber(ss.ssi_band) end,
    overrun = function(ss) return tonumber(ss.ssi_overrun) end,
    trapno = function(ss) return tonumber(ss.ssi_trapno) end,
    status = function(ss) return tonumber(ss.ssi_status) end,
    int = function(ss) return tonumber(ss.ssi_int) end,
    ptr = function(ss) return ss.ssi_ptr end,
    utime = function(ss) return tonumber(ss.ssi_utime) end,
    stime = function(ss) return tonumber(ss.ssi_stime) end,
    addr = function(ss) return ss.ssi_addr end,
  },
  __index = function(ss, k) -- TODO simplify this
    local sig = c.SIG[k]
    if sig then return tonumber(ss.ssi_signo) == sig end
    local rname = signal_reasons_gen[ss.ssi_code]
    if not rname and signal_reasons[ss.ssi_signo] then rname = signal_reasons[ss.ssi_signo][ss.ssi_code] end
    if rname == k then return true end
    if rname == k:upper() then return true end -- TODO use some metatable to hide this?
    if mt.signalfd.index[k] then return mt.signalfd.index[k](ss) end
    error("invalid index " .. k)
  end,
}

addtype(types, "signalfd_siginfo", "struct signalfd_siginfo", mt.signalfd)

mt.siginfos = {
  __index = function(ss, k)
    return ss.sfd[k - 1]
  end,
  __len = function(p) return p.count end,
  __new = function(tp, ss)
    return ffi.new(tp, ss, ss, ss * s.signalfd_siginfo)
  end,
}

addtype_var(types, "siginfos", "struct {int count, bytes; struct signalfd_siginfo sfd[?];}", mt.siginfos)

-- TODO convert to use constants? note missing some macros eg WCOREDUMP(). Allow lower case. Also do not create table dynamically.
mt.wait = {
  __index = function(w, k)
    local WTERMSIG = bit.band(w.status, 0x7f)
    local EXITSTATUS = bit.rshift(bit.band(w.status, 0xff00), 8)
    local WIFEXITED = (WTERMSIG == 0)
    local tab = {
      WIFEXITED = WIFEXITED,
      WIFSTOPPED = bit.band(w.status, 0xff) == 0x7f,
      WIFSIGNALED = not WIFEXITED and bit.band(w.status, 0x7f) ~= 0x7f -- I think this is right????? TODO recheck, cleanup
    }
    if tab.WIFEXITED then tab.EXITSTATUS = EXITSTATUS end
    if tab.WIFSTOPPED then tab.WSTOPSIG = EXITSTATUS end
    if tab.WIFSIGNALED then tab.WTERMSIG = WTERMSIG end
    if tab[k] then return tab[k] end
    local uc = 'W' .. k:upper()
    if tab[uc] then return tab[uc] end
  end
}

-- cannot use metatype as just an integer
function t.waitstatus(status)
  return setmetatable({status = status}, mt.wait)
end

-- termios

local bits_to_speed = {}
for k, v in pairs(c.B) do
  bits_to_speed[v] = tonumber(k)
end

mt.termios = {
  makeraw = function(termios)
    termios.c_iflag = bit.band(termios.c_iflag, bit.bnot(c.IFLAG["IGNBRK,BRKINT,PARMRK,ISTRIP,INLCR,IGNCR,ICRNL,IXON"]))
    termios.c_oflag = bit.band(termios.c_oflag, bit.bnot(c.OFLAG["OPOST"]))
    termios.c_lflag = bit.band(termios.c_lflag, bit.bnot(c.LFLAG["ECHO,ECHONL,ICANON,ISIG,IEXTEN"]))
    termios.c_cflag = bit.bor(bit.band(termios.c_cflag, bit.bnot(c.CFLAG["CSIZE,PARENB"])), c.CFLAG.CS8)
    termios.c_cc[c.CC.VMIN] = 1
    termios.c_cc[c.CC.VTIME] = 0
    return true
  end,
  index = {
    iflag = function(termios) return termios.c_iflag end,
    oflag = function(termios) return termios.c_oflag end,
    cflag = function(termios) return termios.c_cflag end,
    lflag = function(termios) return termios.c_lflag end,
    makeraw = function(termios) return mt.termios.makeraw end,
    speed = function(termios)
      local bits = bit.band(termios.c_cflag, c.CBAUD)
      return bits_to_speed[bits]
    end,
  },
  newindex = {
    iflag = function(termios, v) termios.c_iflag = c.IFLAG(v) end,
    oflag = function(termios, v) termios.c_oflag = c.OFLAG(v) end,
    cflag = function(termios, v) termios.c_cflag = c.CFLAG(v) end,
    lflag = function(termios, v) termios.c_lflag = c.LFLAG(v) end,
    speed = function(termios, speed)
      local speed = c.B[speed]
      termios.c_cflag = bit.bor(bit.band(termios.c_cflag, bit.bnot(c.CBAUD)), speed)
    end,
  },
}

mt.termios.index.ospeed = mt.termios.index.speed
mt.termios.index.ispeed = mt.termios.index.speed
mt.termios.newindex.ospeed = mt.termios.newindex.speed
mt.termios.newindex.ispeed = mt.termios.newindex.speed

for k, i in pairs(c.CC) do
  mt.termios.index[k] = function(termios) return termios.c_cc[i] end
  mt.termios.newindex[k] = function(termios, v) termios.c_cc[i] = v end
end

addtype(types, "termios", "struct termios", mt.termios)
addtype(types, "termios2", "struct termios2", mt.termios)

mt.iocb = {
  index = {
    opcode = function(iocb) return iocb.aio_lio_opcode end,
    data = function(iocb) return tonumber(iocb.aio_data) end,
    reqprio = function(iocb) return iocb.aio_reqprio end,
    fildes = function(iocb) return iocb.aio_fildes end, -- do not convert to fd as will already be open, don't want to gc
    buf = function(iocb) return iocb.aio_buf end,
    nbytes = function(iocb) return tonumber(iocb.aio_nbytes) end,
    offset = function(iocb) return tonumber(iocb.aio_offset) end,
    resfd = function(iocb) return iocb.aio_resfd end,
    flags = function(iocb) return iocb.aio_flags end,
  },
  newindex = {
    opcode = function(iocb, v) iocb.aio_lio_opcode = c.IOCB_CMD[v] end,
    data = function(iocb, v) iocb.aio_data = v end,
    reqprio = function(iocb, v) iocb.aio_reqprio = v end,
    fildes = function(iocb, v) iocb.aio_fildes = getfd(v) end,
    buf = function(iocb, v) iocb.aio_buf = ffi.cast(t.int64, pt.void(v)) end,
    nbytes = function(iocb, v) iocb.aio_nbytes = v end,
    offset = function(iocb, v) iocb.aio_offset = v end,
    flags = function(iocb, v) iocb.aio_flags = c.IOCB_FLAG[v] end,
    resfd = function(iocb, v)
      iocb.aio_flags = bit.bor(iocb.aio_flags, c.IOCB_FLAG.RESFD)
      iocb.aio_resfd = getfd(v)
    end,
  },
  __new = newfn,
}

addtype(types, "iocb", "struct iocb", mt.iocb)

-- aio operations want an array of pointers to struct iocb. To make sure no gc, we provide a table with array and pointers
-- easiest to do as Lua table not ffi type. 
-- expects Lua table of either tables or iocb as input. can provide ptr table too
-- TODO check maybe the implementation actually copies these? only the posix aio says you need to keep.

t.iocb_array = function(tab, ptrs)
  local nr = #tab
  local a = {nr = nr, iocbs = {}, ptrs = ptrs or t.iocb_ptrs(nr)}
  for i = 1, nr do
    local iocb = tab[i]
    a.iocbs[i] = istype(t.iocb, iocb) or t.iocb(iocb)
    a.ptrs[i - 1] = a.iocbs[i]
  end
  return a
end

mt.sock_filter = {
  __new = function(tp, code, k, jt, jf)
    return ffi.new(tp, c.BPF[code], jt or 0, jf or 0, k or 0)
  end
}

addtype(types, "sock_filter", "struct sock_filter", mt.sock_filter)

mt.bpf_insn = {
  __new = function(tp, code, dst_reg, src_reg, off, imm)
    return ffi.new(tp, c.BPF[code], dst_reg or 0, src_reg or 0, off or 0, imm or 0)
  end
}

addtype(types, "bpf_insn", "struct bpf_insn", mt.bpf_insn)

-- capabilities data is an array so cannot put metatable on it. Also depends on version, so combine into one structure.

-- TODO maybe add caching
local function capflags(val, str)
  if not str then return val end
  if #str == 0 then return val end
  local a = h.split(",", str)
  for i, v in ipairs(a) do
    local s = h.trim(v):upper()
    if not c.CAP[s] then error("invalid capability " .. s) end
    val[s] = true
  end
  return val
end

mt.cap = {
  __index = function(cap, k)
    local ci = c.CAP[k]
    if not ci then error("invalid capability " .. k) end
    local i, shift = h.divmod(ci, 32)
    local mask = bit.lshift(1, shift)
    return bit.band(cap.cap[i], mask) ~= 0
  end,
  __newindex = function(cap, k, v)
    if v == true then v = 1 elseif v == false then v = 0 end
    local ci = c.CAP[k]
    if not ci then error("invalid capability " .. k) end
    local i, shift = h.divmod(ci, 32)
    local mask = bit.bnot(bit.lshift(1, shift))
    local set = bit.lshift(v, shift)
    cap.cap[i] = bit.bor(bit.band(cap.cap[i], mask), set)
  end,
  __tostring = function(cap)
    local tab = {}
    for k, _ in pairs(c.CAP) do
      if cap[k] then tab[#tab + 1] = k end
    end
    return table.concat(tab, ",")
  end,
  __new = function(tp, str)
    local cap = ffi.new(tp)
    if str then capflags(cap, str) end
    return cap
  end,
}

addtype(types, "cap", "struct cap", mt.cap)

mt.capabilities = {
    hdrdata = function(cap)
      local hdr, data = t.user_cap_header(cap.version, cap.pid), t.user_cap_data2()
      data[0].effective, data[1].effective = cap.effective.cap[0], cap.effective.cap[1]
      data[0].permitted, data[1].permitted = cap.permitted.cap[0], cap.permitted.cap[1]
      data[0].inheritable, data[1].inheritable = cap.inheritable.cap[0], cap.inheritable.cap[1]
      return hdr, data
    end,
    index = {
      hdrdata = function(cap) return mt.capabilities.hdrdata end,
    },
  __new = function(tp, hdr, data)
    local cap = ffi.new(tp, c.LINUX_CAPABILITY_VERSION[3], 0)
    if type(hdr) == "table" then
      if hdr.permitted then cap.permitted = t.cap(hdr.permitted) end
      if hdr.effective then cap.effective = t.cap(hdr.effective) end
      if hdr.inheritable then cap.inheritable = t.cap(hdr.inheritable) end
      cap.pid = hdr.pid or 0
      if hdr.version then cap.version = c.LINUX_CAPABILITY_VERSION[hdr.version] end
      return cap
    end
    -- not passed a table
    if hdr then cap.version, cap.pid = hdr.version, hdr.pid end
    if data then
      cap.effective.cap[0], cap.effective.cap[1] = data[0].effective, data[1].effective
      cap.permitted.cap[0], cap.permitted.cap[1] = data[0].permitted, data[1].permitted
      cap.inheritable.cap[0], cap.inheritable.cap[1] = data[0].inheritable, data[1].inheritable
    end
    return cap
  end,
  __tostring = function(cap)
    local str = ""
    for nm, capt in pairs{permitted = cap.permitted, inheritable = cap.inheritable, effective = cap.effective} do
      str = str .. nm .. ": "
      str = str .. tostring(capt) .. "\n"
    end
    return str
  end,
}

addtype(types, "capabilities", "struct capabilities", mt.capabilities)

-- difficult to sanely use an ffi metatype for inotify events, so use Lua table
mt.inotify_events = {
  __index = function(tab, k)
    if c.IN[k] then return bit.band(tab.mask, c.IN[k]) ~= 0 end
    error("invalid index " .. k)
  end
}

t.inotify_events = function(buffer, len)
  local off, ee = 0, {}
  while off < len do
    local ev = pt.inotify_event(buffer + off)
    local le = setmetatable({wd = ev.wd, mask = ev.mask, cookie = ev.cookie}, mt.inotify_events)
    if ev.len > 0 then le.name = ffi.string(ev.name) end
    ee[#ee + 1] = le
    off = off + ffi.sizeof(t.inotify_event(ev.len))
  end
  return ee
end

-- TODO for input should be able to set modes automatically from which fields are set.
mt.timex = {
  __new = function(tp, a)
    if type(a) == 'table' then
      if a.modes then a.modes = c.ADJ[a.modes] end
      if a.status then a.status = c.STA[a.status] end
      return ffi.new(tp, a)
    end
    return ffi.new(tp)
  end,
}

addtype(types, "timex", "struct timex", mt.timex)

-- not sane to convert to ffi metatype, only used as adjtimex needs to return ret and a struct
mt.adjtimex = {
  __index = function(timex, k)
    if c.TIME[k] then return timex.state == c.TIME[k] end
    return nil
  end
}

t.adjtimex = function(ret, timex)
  return setmetatable({state = ret, timex = timex}, mt.adjtimex)
end

mt.epoll_event = {
  index = {
    fd = function(e) return tonumber(e.data.fd) end,
    u64 = function(e) return e.data.u64 end,
    u32 = function(e) return e.data.u32 end,
    ptr = function(e) return e.data.ptr end,
  },
  newindex = {
    fd = function(e, v) e.data.fd = v end,
    u64 = function(e, v) e.data.u64 = v end,
    u32 = function(e, v) e.data.u32 = v end,
    ptr = function(e, v) e.data.ptr = v end,
  },
  __new = function(tp, a)
    local e = ffi.new(tp)
    if a then
      if type(a) == "string" then a.events = c.EPOLL[a]
      else 
        if a.events then a.events = c.EPOLL[a.events] end
        for k, v in pairs(a) do e[k] = v end
      end
    end
    return e
  end,
}

for k, v in pairs(c.EPOLL) do
  mt.epoll_event.index[k] = function(e) return bit.band(e.events, v) ~= 0 end
end

addtype(types, "epoll_event", "struct epoll_event", mt.epoll_event)

mt.epoll_events = {
  __len = function(ep) return ep.count end,
  __new = function(tp, n) return ffi.new(tp, n, n) end,
  __ipairs = function(ep) return reviter, ep.ep, ep.count end
}

addtype_var(types, "epoll_events", "struct {int count; struct epoll_event ep[?];}", mt.epoll_events)

mt.io_event = {
  index = {
    error = function(ev) if (ev.res < 0) then return t.error(-ev.res) end end,
  }
}

addtype(types, "io_event", "struct io_event", mt.io_event)

mt.io_events = {
  __len = function(evs) return evs.count end,
  __new = function(tp, n) return ffi.new(tp, n, n) end,
  __ipairs = function(evs) return reviter, evs.ev, evs.count end
}

addtype_var(types, "io_events", "struct {int count; struct io_event ev[?];}", mt.io_events)

mt.cpu_set = {
  index = {
    zero = function(set) ffi.fill(set, s.cpu_set) end,
    set = function(set, cpu)
      if type(cpu) == "table" then -- table is an array of CPU numbers eg {1, 2, 4}
        for i = 1, #cpu do set:set(cpu[i]) end
        return set
      end
      local d = bit.rshift(cpu, 5) -- 5 is 32 bits
      set.val[d] = bit.bor(set.val[d], bit.lshift(1, cpu % 32))
      return set
    end,
    clear = function(set, cpu)
      if type(cpu) == "table" then -- table is an array of CPU numbers eg {1, 2, 4}
        for i = 1, #cpu do set:clear(cpu[i]) end
        return set
      end
      local d = bit.rshift(cpu, 5) -- 5 is 32 bits
      set.val[d] = bit.band(set.val[d], bit.bnot(bit.lshift(1, cpu % 32)))
      return set
    end,
    get = function(set, cpu)
      local d = bit.rshift(cpu, 5) -- 5 is 32 bits
      return bit.band(set.val[d], bit.lshift(1, cpu % 32)) ~= 0
    end,
    -- TODO add rest of interface from man(3) CPU_SET
  },
  __index = function(set, k)
    if mt.cpu_set.index[k] then return mt.cpu_set.index[k] end
    if type(k) == "number" then return set:get(k) end
    error("invalid index " .. k)
  end,
  __newindex = function(set, k, v)
    if type(k) ~= "number" then error("invalid index " .. k) end
    if v then set:set(k) else set:clear(k) end
  end,
  __new = function(tp, tab)
    local set = ffi.new(tp)
    if tab then set:set(tab) end
    return set
  end,
  __tostring = function(set)
    local tab = {}
    for i = 0, s.cpu_set * 8 - 1 do if set:get(i) then tab[#tab + 1] = i end end
    return "{" .. table.concat(tab, ",") .. "}"
  end,
}

addtype(types, "cpu_set", "struct cpu_set_t", mt.cpu_set)

mt.mq_attr = {
  index = {
    flags = function(mqa) return tonumber(mqa.mq_flags) end,
    maxmsg = function(mqa) return tonumber(mqa.mq_maxmsg) end,
    msgsize = function(mqa) return tonumber(mqa.mq_msgsize) end,
    curmsgs = function(mqa) return tonumber(mqa.mq_curmsgs) end,
  },
  newindex = {
    flags = function(mqa, v) mqa.mq_flags = c.OMQATTR[v] end, -- only allows O.NONBLOCK
    maxmsg = function(mqa, v) mqa.mq_maxmsg = v end,
    msgsize = function(mqa, v) mqa.mq_msgsize = v end,
    -- no sense in writing curmsgs
  },
  __new = newfn,
}

addtype(types, "mq_attr", "struct mq_attr", mt.mq_attr)

mt.ifreq = {
  index = {
    name = function(ifr) return ffi.string(ifr.ifr_ifrn.ifrn_name) end,
    addr = function(ifr) return ifr.ifr_ifru.ifru_addr end,
    dstaddr = function(ifr) return ifr.ifr_ifru.ifru_dstaddr end,
    broadaddr = function(ifr) return ifr.ifr_ifru.ifru_broadaddr end,
    netmask = function(ifr) return ifr.ifr_ifru.ifru_netmask end,
    hwaddr = function(ifr) return ifr.ifr_ifru.ifru_hwaddr end,
    flags = function(ifr) return ifr.ifr_ifru.ifru_flags end,
    ivalue = function(ifr) return ifr.ifr_ifru.ifru_ivalue end,
    -- TODO rest of fields
  },
  newindex = {
    name = function(ifr, v)
      assert(#v <= c.IFNAMSIZ, "name too long")
      ifr.ifr_ifrn.ifrn_name = v
    end,
    flags = function(ifr, v) ifr.ifr_ifru.ifru_flags = c.IFREQ[v] end,
    ivalue = function(ifr, v) ifr.ifr_ifru.ifru_ivalue = v end,
    -- TODO rest of fields
  },
  __new = newfn,
}

addtype(types, "ifreq", "struct ifreq", mt.ifreq)

-- note t.dirents iterator is defined in common types
local d_name_offset = ffi.offsetof("struct linux_dirent64", "d_name") -- d_name is at end of struct
mt.dirent = {
  index = {
    ino = function(self) return tonumber(self.d_ino) end,
    off = function(self) return self.d_off end,
    reclen = function(self) return self.d_reclen end,
    name = function(self) return ffi.string(pt.char(self) + d_name_offset) end,
    type = function(self) return self.d_type end,
    toif = function(self) return bit.lshift(self.d_type, 12) end, -- convert to stat types
  },
  __len = function(self) return self.d_reclen end,
}

-- TODO previously this allowed lower case values, but this static version does not
-- could add mt.dirent.index[tolower(k)] = mt.dirent.index[k] but need to do consistently elsewhere
for k, v in pairs(c.DT) do
  mt.dirent.index[k] = function(self) return self.type == v end
end

addtype(types, "dirent", "struct linux_dirent64", mt.dirent)

mt.rtmsg = {
  index = {
    family = function(self) return tonumber(self.rtm_family) end,
  },
  newindex = {
    family = function(self, v) self.rtm_family = c.AF[v] end,
    protocol = function(self, v) self.rtm_protocol = c.RTPROT[v] end,
    type = function(self, v) self.rtm_type = c.RTN[v] end,
    scope = function(self, v) self.rtm_scope = c.RT_SCOPE[v] end,
    flags = function(self, v) self.rtm_flags = c.RTM_F[v] end,
    table = function(self, v) self.rtm_table = c.RT_TABLE[v] end,
    dst_len = function(self, v) self.rtm_dst_len = v end,
    src_len = function(self, v) self.rtm_src_len = v end,
    tos = function(self, v) self.rtm_tos = v end,
  },
  __new = newfn,
}

addtype(types, "rtmsg", "struct rtmsg", mt.rtmsg)

mt.ndmsg = {
  index = {
    family = function(self) return tonumber(self.ndm_family) end,
  },
  newindex = {
    family = function(self, v) self.ndm_family = c.AF[v] end,
    state = function(self, v) self.ndm_state = c.NUD[v] end,
    flags = function(self, v) self.ndm_flags = c.NTF[v] end,
    type = function(self, v) self.ndm_type = v end, -- which lookup?
    ifindex = function(self, v) self.ndm_ifindex = v end,
  },
  __new = newfn,
}

addtype(types, "ndmsg", "struct ndmsg", mt.ndmsg)

mt.sched_param = {
  __new = function(tp, v) -- allow positional parameters as only first is ever used
    local obj = ffi.new(tp)
    obj.sched_priority = v or 0
    return obj
  end,
}

addtype(types, "sched_param", "struct sched_param", mt.sched_param)

mt.flock = {
  index = {
    type = function(self) return self.l_type end,
    whence = function(self) return self.l_whence end,
    start = function(self) return self.l_start end,
    len = function(self) return self.l_len end,
    pid = function(self) return self.l_pid end,
  },
  newindex = {
    type = function(self, v) self.l_type = c.FCNTL_LOCK[v] end,
    whence = function(self, v) self.l_whence = c.SEEK[v] end,
    start = function(self, v) self.l_start = v end,
    len = function(self, v) self.l_len = v end,
    pid = function(self, v) self.l_pid = v end,
  },
  __new = newfn,
}

addtype(types, "flock", "struct flock64", mt.flock)

mt.mmsghdr = {
  index = {
    hdr = function(self) return self.msg_hdr end,
    len = function(self) return self.msg_len end,
  },
  newindex = {
    hdr = function(self, v) self.hdr = v end,
  },
  __new = newfn,
}

addtype(types, "mmsghdr", "struct mmsghdr", mt.mmsghdr)

mt.mmsghdrs = {
  __len = function(p) return p.count end,
  __new = function(tp, ps)
    if type(ps) == 'number' then return ffi.new(tp, ps, ps) end
    local count = #ps
    local mms = ffi.new(tp, count, count)
    for n = 1, count do
      mms.msg[n - 1].msg_hdr = mktype(t.msghdr, ps[n])
    end
    return mms
  end,
  __ipairs = function(p) return reviter, p.msg, p.count end -- TODO want forward iterator really...
}

addtype_var(types, "mmsghdrs", "struct {int count; struct mmsghdr msg[?];}", mt.mmsghdrs)

addtype(types, "bpf_attr", "union bpf_attr")

-- Metatype for Linux perf events
mt.perf_event_attr = {
  index = {
    type = function(self)   return self.pe_type end,
    config = function(self) return self.pe_config end,
    sample_type = function(self) return self.pe_sample_type end,
  },
  newindex = {
    type = function(self, v) self.pe_type = c.PERF_TYPE[v] end,
    config = function(self, v) self.pe_config = c.PERF_COUNT[v] end,
    sample_type = function(self, v) self.pe_sample_type = c.PERF_SAMPLE[v] end,
  },
}
addtype(types, "perf_event_attr", "struct perf_event_attr", mt.perf_event_attr)

-- this is declared above
samap_pt = {
  [c.AF.UNIX] = pt.sockaddr_un,
  [c.AF.INET] = pt.sockaddr_in,
  [c.AF.INET6] = pt.sockaddr_in6,
  [c.AF.NETLINK] = pt.sockaddr_nl,
  [c.AF.PACKET] = pt.sockaddr_ll,
}

return types

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.util"],"module already exists")sources["syscall.linux.util"]=([===[-- <pack syscall.linux.util> --
-- misc utils

-- aim is to move a lot of stuff that is not strictly syscalls out of main code to modularise better
-- most code here is man(1) or man(3) or misc helpers for common tasks.

-- TODO rework so that items can be methods on fd again, for eventfd, timerfd, signalfd and tty

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local function init(S)

local abi, types, c = S.abi, S.types, S.c
local t, pt, s = types.t, types.pt, types.s

local h = require "syscall.helpers"

local ffi = require "ffi"

local bit = require "syscall.bit"

local octal = h.octal

-- TODO move to helpers? see notes in syscall.lua about reworking though
local function istype(tp, x)
  if ffi.istype(tp, x) then return x end
  return false
end

local util = {}

local mt = {}

local function if_nametoindex(name, s)
  local ifr = t.ifreq{name = name}
  local ret, err = S.ioctl(s, "SIOCGIFINDEX", ifr)
  if not ret then return nil, err end
  return ifr.ivalue
end

function util.if_nametoindex(name) -- standard function in some libc versions
  local s, err = S.socket(c.AF.LOCAL, c.SOCK.STREAM, 0)
  if not s then return nil, err end
  local i, err = if_nametoindex(name, s)
  if not i then
     S.close(s)
     return nil, err
  end
  local ok, err = S.close(s)
  if not ok then return nil, err end
  return i
end

-- bridge functions.
local function bridge_ioctl(io, name)
  local s, err = S.socket(c.AF.LOCAL, c.SOCK.STREAM, 0)
  if not s then return nil, err end
  local ret, err = S.ioctl(s, io, name)
  if not ret then
    s:close()
    return nil, err
  end
  local ok, err = s:close()
  if not ok then return nil, err end
  return ret
end

function util.bridge_add(name) return bridge_ioctl("SIOCBRADDBR", name) end
function util.bridge_del(name) return bridge_ioctl("SIOCBRDELBR", name) end

local function bridge_if_ioctl(io, name, dev)
  local err, s, ifr, len, ret, ok
  s, err = S.socket(c.AF.LOCAL, c.SOCK.STREAM, 0)
  if not s then return nil, err end
  if type(dev) == "string" then
    dev, err = if_nametoindex(dev, s)
    if not dev then return nil, err end
  end
  ifr = t.ifreq{name = name, ivalue = dev}
  ret, err = S.ioctl(s, io, ifr);
  if not ret then
    s:close()
    return nil, err
  end
  ok, err = s:close()
  if not ok then return nil, err end
  return ret
end

function util.bridge_add_interface(bridge, dev) return bridge_if_ioctl(c.SIOC.BRADDIF, bridge, dev) end
function util.bridge_add_interface(bridge, dev) return bridge_if_ioctl(c.SIOC.BRDELIF, bridge, dev) end

local function brinfo(d) -- can be used as subpart of general interface info
  local bd = "/sys/class/net/" .. d .. "/" .. c.SYSFS_BRIDGE_ATTR
  if not S.stat(bd) then return nil end
  local bridge = {}
  for fn, f in util.ls(bd) do
    local s = util.readfile(bd .. "/" .. fn)
    if s then
      s = s:sub(1, #s - 1) -- remove newline at end
      if fn == "group_addr" or fn == "root_id" or fn == "bridge_id" then -- string values
        bridge[fn] = s
      elseif f == "stp_state" then -- bool
        bridge[fn] = s == 1
      elseif fn ~= "." and fn ~=".." then
        bridge[fn] = tonumber(s) -- not quite correct, most are timevals TODO
      end
    end
  end

  local brif, err = util.dirtable("/sys/class/net/" .. d .. "/" .. c.SYSFS_BRIDGE_PORT_SUBDIR, true)
  if not brif then return nil end

  local fdb = "/sys/class/net/" .. d .. "/" .. c.SYSFS_BRIDGE_FDB
  if not S.stat(fdb) then return nil end
  local sl = 2048
  local buffer = t.buffer(sl)
  local fd = S.open(fdb, "rdonly")
  if not fd then return nil end
  local brforward = {}

  repeat
    local n = S.read(fd, buffer, sl)
    if not n then return nil end

    local fdbs = pt.fdb_entry(buffer)

    for i = 1, bit.rshift(n, 4) do -- fdb_entry is 16 bytes
      local fdb = fdbs[i - 1]
      local mac = t.macaddr()
      ffi.copy(mac, fdb.mac_addr, s.macaddr)

      -- TODO ageing_timer_value is not an int, time, float
      brforward[#brforward + 1] = {
        mac_addr = mac, port_no = tonumber(fdb.port_no),
        is_local = fdb.is_local ~= 0,
        ageing_timer_value = tonumber(fdb.ageing_timer_value)
      }
    end

  until n == 0
  if not fd:close() then return nil end

  return {bridge = bridge, brif = brif, brforward = brforward}
end

function util.bridge_list()
  local b = {}
  for d in util.ls("/sys/class/net") do
    if d ~= "." and d ~= ".." then b[d] = brinfo(d) end
  end
  return b
end

-- eventfd read and write helpers, as in glibc but Lua friendly. Note returns 0 for EAGAIN, as 0 never returned directly
-- returns Lua number - if you need all 64 bits, pass your own value in and use that for the exact result
function util.eventfd_read(fd, value)
  if not value then value = t.uint64_1() end
  local ret, err = S.read(fd, value, 8)
  if err and err.AGAIN then
    value[0] = 0
    return 0
  end
  if not ret then return nil, err end
  return tonumber(value[0])
end
function util.eventfd_write(fd, value)
  if not value then value = 1 end
  if type(value) == "number" then value = t.uint64_1(value) end
  local ret, err = S.write(fd, value, 8)
  if not ret then return nil, err end
  return true
end

function util.signalfd_read(fd, ss)
  ss = istype(t.siginfos, ss) or t.siginfos(ss or 8)
  local ret, err = S.read(fd, ss.sfd, ss.bytes)
  if ret == 0 or (err and err.AGAIN) then return {} end
  if not ret then return nil, err end
  ss.count = ret / s.signalfd_siginfo -- may not be full length
  return ss
end

function util.timerfd_read(fd, buffer)
  if not buffer then buffer = t.uint64_1() end
  local ret, err = S.read(fd, buffer, 8)
  if not ret and err.AGAIN then return 0 end -- will never actually return 0
  if not ret then return nil, err end
  return tonumber(buffer[0])
end

local auditarch_le = {
  x86 = "I386",
  x64 = "X86_64",
  arm = "ARM",
  arm64 = "AARCH64",
  mipsel = "MIPSEL",
  ppc64le = "PPC64LE",
}

local auditarch_be = {
  ppc = "PPC",
  arm = "ARMEB",
  arm64 = "AARCH64",
  mips = "MIPS",
}

function util.auditarch()
  if abi.le then return c.AUDIT_ARCH[auditarch_le[abi.arch]] else return c.AUDIT_ARCH[auditarch_be[abi.arch]] end
end

-- file system capabilities
local seccap = "security.capability"

function util.capget(f)
  local attr, err
  if type(f) == "string" then attr, err = S.getxattr(f, seccap) else attr, err = f:getxattr(seccap) end
  if not attr then return nil, err end
  local vfs = pt.vfs_cap_data(attr)
  local magic_etc = h.convle32(vfs.magic_etc)
  local version = bit.band(c.VFS_CAP.REVISION_MASK, magic_etc)
  -- TODO if you need support for version 1 filesystem caps add here, fairly simple
  assert(version == c.VFS_CAP.REVISION_2, "FIXME: Currently only support version 2 filesystem capabilities")
  local cap = t.capabilities()
  cap.permitted.cap[0], cap.permitted.cap[1] = h.convle32(vfs.data[0].permitted), h.convle32(vfs.data[1].permitted)
  cap.inheritable.cap[0], cap.inheritable.cap[1] = h.convle32(vfs.data[0].inheritable), h.convle32(vfs.data[1].inheritable)
  if bit.band(magic_etc, c.VFS_CAP_FLAGS.EFFECTIVE) ~= 0 then
    cap.effective.cap[0] = bit.bor(cap.permitted.cap[0], cap.inheritable.cap[0])
    cap.effective.cap[1] = bit.bor(cap.permitted.cap[1], cap.inheritable.cap[1])
  end
  return cap
end

function util.capset(f, cap, flags)
  cap = istype(t.capabilities, cap) or t.capabilities(cap)
  local vfsflags = 0
  -- is this the correct way to do this? TODO check
  for k, _ in pairs(c.CAP) do if cap.effective[k] then vfsflags = c.VFS_CAP_FLAGS.EFFECTIVE end end
  local vfs = t.vfs_cap_data()
  vfs.magic_etc = h.convle32(c.VFS_CAP.REVISION_2 + vfsflags)
  vfs.data[0].permitted, vfs.data[1].permitted = h.convle32(cap.permitted.cap[0]), h.convle32(cap.permitted.cap[1])
  vfs.data[0].inheritable, vfs.data[1].inheritable = h.convle32(cap.inheritable.cap[0]), h.convle32(cap.inheritable.cap[1])
  if type(f) == "string" then return S.setxattr(f, seccap, vfs, flags) else return f:getxattr(seccap, vfs, flags) end
end

-- TODO could add umount method.
mt.mount = {
  __tostring = function(m) return m.source .. " on " .. m.target .. " type " .. m.type .. " (" .. m.flags .. ")" end,
}

mt.mounts = {
  __tostring = function(ms)
  local rs = ""
  for i = 1, #ms do
    rs = rs .. tostring(ms[i]) .. '\n'
  end
  return rs
end
}

-- will work on netbsd with Linux compat, but should use getvfsstat()
function util.mounts(file)
  local mf, err = util.readfile(file or "/proc/mounts")
  if not mf then return nil, err end
  local mounts = {}
  for line in mf:gmatch("[^\r\n]+") do
    local l = {}
    local parts = {"source", "target", "type", "flags", "freq", "passno"}
    local p = 1
    for word in line:gmatch("%S+") do
      l[parts[p]] = word
      p = p + 1
    end
    mounts[#mounts + 1] = setmetatable(l, mt.mount)
  end
  -- TODO some of the options you get in /proc/mounts are file system specific and should be moved to l.data
  -- idea is you can round-trip this data
  -- a lot of the fs specific options are key=value so easier to recognise
  return setmetatable(mounts, mt.mounts)
end

-- table based mount, more cross OS compatible
function util.mount(tab)
  local source = tab.source or "none" -- standard default
  local target = tab.target or tab.dir -- netbsd compatible
  local filesystemtype = tab.type
  local mountflags = tab.flags
  local data = tab.data
  return S.mount(source, target, filesystemtype, mountflags, data)
end

function util.sendcred(fd, pid, uid, gid)
  if not pid then pid = S.getpid() end
  if not uid then uid = S.getuid() end
  if not gid then gid = S.getgid() end
  local ucred = t.ucred{pid = pid, uid = uid, gid = gid}
  local buf1 = t.buffer(1) -- need to send one byte
  local io = t.iovecs{{buf1, 1}}
  local cmsg = t.cmsghdr("socket", "credentials", ucred)
  local msg = t.msghdr{iov = io, control = cmsg}
  return S.sendmsg(fd, msg, 0)
end

return util

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.arm.ffi"],"module already exists")sources["syscall.linux.arm.ffi"]=([===[-- <pack syscall.linux.arm.ffi> --
-- arm specific definitions

return {
  ucontext = [[
typedef int greg_t, gregset_t[18];
typedef struct sigcontext {
  unsigned long trap_no, error_code, oldmask;
  unsigned long arm_r0, arm_r1, arm_r2, arm_r3;
  unsigned long arm_r4, arm_r5, arm_r6, arm_r7;
  unsigned long arm_r8, arm_r9, arm_r10, arm_fp;
  unsigned long arm_ip, arm_sp, arm_lr, arm_pc;
  unsigned long arm_cpsr, fault_address;
} mcontext_t;
typedef struct __ucontext {
  unsigned long uc_flags;
  struct __ucontext *uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  sigset_t uc_sigmask;
  unsigned long long uc_regspace[64];
} ucontext_t;
]],
  stat = [[
struct stat {
  unsigned long long      st_dev;
  unsigned char   __pad0[4];
  unsigned long   __st_ino;
  unsigned int    st_mode;
  unsigned int    st_nlink;
  unsigned long   st_uid;
  unsigned long   st_gid;
  unsigned long long      st_rdev;
  unsigned char   __pad3[4];
  long long       st_size;
  unsigned long   st_blksize;
  unsigned long long      st_blocks;
  unsigned long   st_atime;
  unsigned long   st_atime_nsec;
  unsigned long   st_mtime;
  unsigned int    st_mtime_nsec;
  unsigned long   st_ctime;
  unsigned long   st_ctime_nsec;
  unsigned long long      st_ino;
};
]],
  statfs = [[
typedef uint32_t statfs_word;
struct statfs64 {
  statfs_word f_type;
  statfs_word f_bsize;
  uint64_t f_blocks;
  uint64_t f_bfree;
  uint64_t f_bavail;
  uint64_t f_files;
  uint64_t f_ffree;
  kernel_fsid_t f_fsid;
  statfs_word f_namelen;
  statfs_word f_frsize;
  statfs_word f_flags;
  statfs_word f_spare[4];
} __attribute__((packed,aligned(4)));
]],
}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.x64.ioctl"],"module already exists")sources["syscall.linux.x64.ioctl"]=([===[-- <pack syscall.linux.x64.ioctl> --
-- x64 ioctl differences

local arch = {
  ioctl = {
  }
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.c"],"module already exists")sources["syscall.linux.c"]=([===[-- <pack syscall.linux.c> --
-- This sets up the table of C functions

-- this should be generated ideally, as it is the ABI spec

--[[
Note a fair number are being deprecated, see include/uapi/asm-generic/unistd.h under __ARCH_WANT_SYSCALL_NO_AT, __ARCH_WANT_SYSCALL_NO_FLAGS, and __ARCH_WANT_SYSCALL_DEPRECATED
Some of these we already don't use, but some we do, eg use open not openat etc.
]]

local require, tonumber, pcall, select =
require, tonumber, pcall, select

local abi = require "syscall.abi"

local ffi = require "ffi"

local bit = require "syscall.bit"

require "syscall.linux.ffi"

local voidp = ffi.typeof("void *")

local function void(x)
  return ffi.cast(voidp, x)
end

-- basically all types passed to syscalls are int or long, so we do not need to use nicely named types, so we can avoid importing t.
local int, long = ffi.typeof("int"), ffi.typeof("long")
local uint, ulong = ffi.typeof("unsigned int"), ffi.typeof("unsigned long")

local h = require "syscall.helpers"
local err64 = h.err64

local i6432, u6432 = bit.i6432, bit.u6432

local arg64, arg64u
if abi.le then
  arg64 = function(val)
    local v2, v1 = i6432(val)
    return v1, v2
  end
  arg64u = function(val)
    local v2, v1 = u6432(val)
    return v1, v2
  end
else
  arg64 = function(val) return i6432(val) end
  arg64u = function(val) return u6432(val) end
end
-- _llseek very odd, preadv
local function llarg64(val) return i6432(val) end

local C = {}

local nr = require("syscall.linux.nr")

local zeropad = nr.zeropad
local sys = nr.SYS
local socketcalls = nr.socketcalls

local u64 = ffi.typeof("uint64_t")

-- TODO could make these return errno here, also are these best casts?
local syscall_long = ffi.C.syscall -- returns long
local function syscall(...) return tonumber(syscall_long(...)) end -- int is default as most common
local function syscall_void(...) return void(syscall_long(...)) end
local function syscall_off(...) return u64(syscall_long(...)) end -- off_t

local longstype = ffi.typeof("long[?]")

local function longs(...)
  local n = select('#', ...)
  local ll = ffi.new(longstype, n)
  for i = 1, n do
    ll[i - 1] = ffi.cast(long, select(i, ...))
  end
  return ll
end

-- now for the system calls

-- use 64 bit fileops on 32 bit always. As may be missing will use syscalls directly
if abi.abi32 then
  if zeropad then
    function C.truncate(path, length)
      local len1, len2 = arg64u(length)
      return syscall(sys.truncate64, path, int(0), long(len1), long(len2))
    end
    function C.ftruncate(fd, length)
      local len1, len2 = arg64u(length)
      return syscall(sys.ftruncate64, int(fd), int(0), long(len1), long(len2))
    end
    function C.readahead(fd, offset, count)
      local off1, off2 = arg64u(offset)
      return syscall(sys.readahead, int(fd), int(0), long(off1), long(off2), ulong(count))
    end
    function C.pread(fd, buf, size, offset)
      local off1, off2 = arg64(offset)
      return syscall_long(sys.pread64, int(fd), void(buf), ulong(size), int(0), long(off1), long(off2))
    end
    function C.pwrite(fd, buf, size, offset)
      local off1, off2 = arg64(offset)
      return syscall_long(sys.pwrite64, int(fd), void(buf), ulong(size), int(0), long(off1), long(off2))
    end
  else
    function C.truncate(path, length)
      local len1, len2 = arg64u(length)
      return syscall(sys.truncate64, path, long(len1), long(len2))
    end
    function C.ftruncate(fd, length)
      local len1, len2 = arg64u(length)
      return syscall(sys.ftruncate64, int(fd), long(len1), long(len2))
    end
    function C.readahead(fd, offset, count)
      local off1, off2 = arg64u(offset)
      return syscall(sys.readahead, int(fd), long(off1), long(off2), ulong(count))
    end
    function C.pread(fd, buf, size, offset)
      local off1, off2 = arg64(offset)
      return syscall_long(sys.pread64, int(fd), void(buf), ulong(size), long(off1), long(off2))
    end
    function C.pwrite(fd, buf, size, offset)
      local off1, off2 = arg64(offset)
      return syscall_long(sys.pwrite64, int(fd), void(buf), ulong(size), long(off1), long(off2))
    end
  end
  -- note statfs,fstatfs pass size of struct on 32 bit only
  function C.statfs(path, buf) return syscall(sys.statfs64, void(path), uint(ffi.sizeof(buf)), void(buf)) end
  function C.fstatfs(fd, buf) return syscall(sys.fstatfs64, int(fd), uint(ffi.sizeof(buf)), void(buf)) end
  -- Note very odd split 64 bit arguments even on 64 bit platform.
  function C.preadv(fd, iov, iovcnt, offset)
    local off1, off2 = llarg64(offset)
    return syscall_long(sys.preadv, int(fd), void(iov), int(iovcnt), long(off2), long(off1))
  end
  function C.pwritev(fd, iov, iovcnt, offset)
    local off1, off2 = llarg64(offset)
    return syscall_long(sys.pwritev, int(fd), void(iov), int(iovcnt), long(off2), long(off1))
  end
  -- lseek is a mess in 32 bit, use _llseek syscall to get clean result.
  -- TODO move this to syscall.lua
  local off1 = ffi.typeof("uint64_t[1]")
  function C.lseek(fd, offset, whence)
    local result = off1()
    local off1, off2 = llarg64(offset)
    local ret = syscall(sys._llseek, int(fd), long(off1), long(off2), void(result), uint(whence))
    if ret == -1 then return err64 end
    return result[0]
  end
  function C.sendfile(outfd, infd, offset, count)
    return syscall_long(sys.sendfile64, int(outfd), int(infd), void(offset), ulong(count))
  end
  -- on 32 bit systems mmap uses off_t so we cannot tell what ABI is. Use underlying mmap2 syscall
  function C.mmap(addr, length, prot, flags, fd, offset)
    local pgoffset = bit.rshift(offset, 12)
    return syscall_void(sys.mmap2, void(addr), ulong(length), int(prot), int(flags), int(fd), uint(pgoffset))
  end
else -- 64 bit
  function C.truncate(path, length) return syscall(sys.truncate, void(path), ulong(length)) end
  function C.ftruncate(fd, length) return syscall(sys.ftruncate, int(fd), ulong(length)) end
  function C.readahead(fd, offset, count) return syscall(sys.readahead, int(fd), ulong(offset), ulong(count)) end
  function C.pread(fd, buf, count, offset) return syscall_long(sys.pread64, int(fd), void(buf), ulong(count), ulong(offset)) end
  function C.pwrite(fd, buf, count, offset) return syscall_long(sys.pwrite64, int(fd), void(buf), ulong(count), ulong(offset)) end
  function C.statfs(path, buf) return syscall(sys.statfs, void(path), void(buf)) end
  function C.fstatfs(fd, buf) return syscall(sys.fstatfs, int(fd), void(buf)) end
  function C.preadv(fd, iov, iovcnt, offset) return syscall_long(sys.preadv, int(fd), void(iov), long(iovcnt), ulong(offset)) end
  function C.pwritev(fd, iov, iovcnt, offset) return syscall_long(sys.pwritev, int(fd), void(iov), long(iovcnt), ulong(offset)) end
  function C.lseek(fd, offset, whence) return syscall_off(sys.lseek, int(fd), ulong(offset), int(whence)) end
  function C.sendfile(outfd, infd, offset, count)
    return syscall_long(sys.sendfile, int(outfd), int(infd), void(offset), ulong(count))
  end
  function C.mmap(addr, length, prot, flags, fd, offset)
    return syscall_void(sys.mmap, void(addr), ulong(length), int(prot), int(flags), int(fd), ulong(offset))
  end
end

-- glibc caches pid, but this fails to work eg after clone().
function C.getpid() return syscall(sys.getpid) end

-- underlying syscalls
function C.exit_group(status) return syscall(sys.exit_group, int(status)) end -- void return really
function C.exit(status) return syscall(sys.exit, int(status)) end -- void return really

C._exit = C.exit_group -- standard method

-- clone interface provided is not same as system one, and is less convenient
function C.clone(flags, signal, stack, ptid, tls, ctid)
  return syscall(sys.clone, int(flags), void(stack), void(ptid), void(tls), void(ctid)) -- technically long
end

-- getdents is not provided by glibc. Musl has weak alias so not visible.
function C.getdents(fd, buf, size)
  return syscall(sys.getdents64, int(fd), buf, uint(size))
end

-- glibc has request as an unsigned long, kernel is unsigned int, other libcs are int, so use syscall directly
function C.ioctl(fd, request, arg)
  return syscall(sys.ioctl, int(fd), uint(request), void(arg))
end

-- getcwd in libc may allocate memory and has inconsistent return value, so use syscall
function C.getcwd(buf, size) return syscall(sys.getcwd, void(buf), ulong(size)) end

-- nice in libc may or may not return old value, syscall never does; however nice syscall may not exist
if sys.nice then
  function C.nice(inc) return syscall(sys.nice, int(inc)) end
end

-- avoid having to set errno by calling getpriority directly and adjusting return values
function C.getpriority(which, who) return syscall(sys.getpriority, int(which), int(who)) end

-- uClibc only provides a version of eventfd without flags, and we cannot detect this
function C.eventfd(initval, flags) return syscall(sys.eventfd2, uint(initval), int(flags)) end

-- Musl always returns ENOSYS for these
function C.sched_getscheduler(pid) return syscall(sys.sched_getscheduler, int(pid)) end
function C.sched_setscheduler(pid, policy, param)
  return syscall(sys.sched_setscheduler, int(pid), int(policy), void(param))
end

local sys_fadvise64 = sys.fadvise64_64 or sys.fadvise64
if abi.abi64 then
  if sys.stat then
    function C.stat(path, buf)
      return syscall(sys.stat, path, void(buf))
    end
  end
  if sys.lstat then
    function C.lstat(path, buf)
      return syscall(sys.lstat, path, void(buf))
    end
  end
  function C.fstat(fd, buf)
    return syscall(sys.fstat, int(fd), void(buf))
  end
  function C.fstatat(fd, path, buf, flags)
    return syscall(sys.fstatat, int(fd), path, void(buf), int(flags))
  end
  function C.fadvise64(fd, offset, len, advise)
    return syscall(sys_fadvise64, int(fd), ulong(offset), ulong(len), int(advise))
  end
  function C.fallocate(fd, mode, offset, len)
    return syscall(sys.fallocate, int(fd), uint(mode), ulong(offset), ulong(len))
  end
else
  function C.stat(path, buf)
    return syscall(sys.stat64, path, void(buf))
  end
  function C.lstat(path, buf)
    return syscall(sys.lstat64, path, void(buf))
  end
  function C.fstat(fd, buf)
    return syscall(sys.fstat64, int(fd), void(buf))
  end
  function C.fstatat(fd, path, buf, flags)
    return syscall(sys.fstatat64, int(fd), path, void(buf), int(flags))
  end
  if zeropad then
    function C.fadvise64(fd, offset, len, advise)
      local off1, off2 = arg64u(offset)
      local len1, len2 = arg64u(len)
      return syscall(sys_fadvise64, int(fd), 0, uint(off1), uint(off2), uint(len1), uint(len2), int(advise))
    end
  else
    function C.fadvise64(fd, offset, len, advise)
      local off1, off2 = arg64u(offset)
      local len1, len2 = arg64u(len)
      return syscall(sys_fadvise64, int(fd), uint(off1), uint(off2), uint(len1), uint(len2), int(advise))
    end
  end
  function C.fallocate(fd, mode, offset, len)
    local off1, off2 = arg64u(offset)
    local len1, len2 = arg64u(len)
    return syscall(sys.fallocate, int(fd), uint(mode), uint(off1), uint(off2), uint(len1), uint(len2))
  end
end

-- native Linux aio not generally supported by libc, only posix API
function C.io_setup(nr_events, ctx)
  return syscall(sys.io_setup, uint(nr_events), void(ctx))
end
function C.io_destroy(ctx)
  return syscall(sys.io_destroy, ulong(ctx))
end
function C.io_cancel(ctx, iocb, result)
  return syscall(sys.io_cancel, ulong(ctx), void(iocb), void(result))
end
function C.io_getevents(ctx, min, nr, events, timeout)
  return syscall(sys.io_getevents, ulong(ctx), long(min), long(nr), void(events), void(timeout))
end
function C.io_submit(ctx, iocb, nr)
  return syscall(sys.io_submit, ulong(ctx), long(nr), void(iocb))
end

-- mq functions in -rt for glibc, plus syscalls differ slightly
function C.mq_open(name, flags, mode, attr)
  return syscall(sys.mq_open, void(name), int(flags), uint(mode), void(attr))
end
function C.mq_unlink(name) return syscall(sys.mq_unlink, void(name)) end
function C.mq_getsetattr(mqd, new, old)
  return syscall(sys.mq_getsetattr, int(mqd), void(new), void(old))
end
function C.mq_timedsend(mqd, msg_ptr, msg_len, msg_prio, abs_timeout)
  return syscall(sys.mq_timedsend, int(mqd), void(msg_ptr), ulong(msg_len), uint(msg_prio), void(abs_timeout))
end
function C.mq_timedreceive(mqd, msg_ptr, msg_len, msg_prio, abs_timeout)
  return syscall(sys.mq_timedreceive, int(mqd), void(msg_ptr), ulong(msg_len), void(msg_prio), void(abs_timeout))
end

if sys.mknod then
  function C.mknod(pathname, mode, dev) return syscall(sys.mknod, pathname, uint(mode), uint(dev)) end
end
function C.mknodat(fd, pathname, mode, dev)
  return syscall(sys.mknodat, int(fd), pathname, uint(mode), uint(dev))
end
-- pivot_root is not provided by glibc, is provided by Musl
function C.pivot_root(new_root, put_old)
  return syscall(sys.pivot_root, new_root, put_old)
end
-- setns not in some glibc versions
function C.setns(fd, nstype)
  return syscall(sys.setns, int(fd), int(nstype))
end
-- prlimit64 not in my ARM glibc
function C.prlimit64(pid, resource, new_limit, old_limit)
  return syscall(sys.prlimit64, int(pid), int(resource), void(new_limit), void(old_limit))
end

-- sched_setaffinity and sched_getaffinity not in Musl at the moment, use syscalls. Could test instead.
function C.sched_getaffinity(pid, len, mask)
  return syscall(sys.sched_getaffinity, int(pid), uint(len), void(mask))
end
function C.sched_setaffinity(pid, len, mask)
  return syscall(sys.sched_setaffinity, int(pid), uint(len), void(mask))
end
-- sched_setparam and sched_getparam in Musl return ENOSYS, probably as they work on threads not processes.
function C.sched_getparam(pid, param)
  return syscall(sys.sched_getparam, int(pid), void(param))
end
function C.sched_setparam(pid, param)
  return syscall(sys.sched_setparam, int(pid), void(param))
end

-- in librt for glibc but use syscalls instead of loading another library
function C.clock_nanosleep(clk_id, flags, req, rem)
  return syscall(sys.clock_nanosleep, int(clk_id), int(flags), void(req), void(rem))
end
function C.clock_getres(clk_id, ts)
  return syscall(sys.clock_getres, int(clk_id), void(ts))
end
function C.clock_settime(clk_id, ts)
  return syscall(sys.clock_settime, int(clk_id), void(ts))
end

-- glibc will not call this with a null path, which is needed to implement futimens in Linux
function C.utimensat(fd, path, times, flags)
  return syscall(sys.utimensat, int(fd), void(path), void(times), int(flags))
end

-- not in Android Bionic
function C.linkat(olddirfd, oldpath, newdirfd, newpath, flags)
  return syscall(sys.linkat, int(olddirfd), void(oldpath), int(newdirfd), void(newpath), int(flags))
end
function C.symlinkat(oldpath, newdirfd, newpath)
  return syscall(sys.symlinkat, void(oldpath), int(newdirfd), void(newpath))
end
function C.readlinkat(dirfd, pathname, buf, bufsiz)
  return syscall(sys.readlinkat, int(dirfd), void(pathname), void(buf), ulong(bufsiz))
end
function C.inotify_init1(flags)
  return syscall(sys.inotify_init1, int(flags))
end
function C.adjtimex(buf)
  return syscall(sys.adjtimex, void(buf))
end
function C.epoll_create1(flags)
  return syscall(sys.epoll_create1, int(flags))
end
if sys.epoll_wait then
  function C.epoll_wait(epfd, events, maxevents, timeout)
    return syscall(sys.epoll_wait, int(epfd), void(events), int(maxevents), int(timeout))
  end
end
function C.swapon(path, swapflags)
  return syscall(sys.swapon, void(path), int(swapflags))
end
function C.swapoff(path)
  return syscall(sys.swapoff, void(path))
end
function C.timerfd_create(clockid, flags)
  return syscall(sys.timerfd_create, int(clockid), int(flags))
end
function C.timerfd_settime(fd, flags, new_value, old_value)
  return syscall(sys.timerfd_settime, int(fd), int(flags), void(new_value), void(old_value))
end
function C.timerfd_gettime(fd, curr_value)
  return syscall(sys.timerfd_gettime, int(fd), void(curr_value))
end
function C.splice(fd_in, off_in, fd_out, off_out, len, flags)
  return syscall(sys.splice, int(fd_in), void(off_in), int(fd_out), void(off_out), ulong(len), uint(flags))
end
function C.tee(src, dest, len, flags)
  return syscall(sys.tee, int(src), int(dest), ulong(len), uint(flags))
end
function C.vmsplice(fd, iovec, cnt, flags)
  return syscall(sys.vmsplice, int(fd), void(iovec), ulong(cnt), uint(flags))
end
-- TODO note that I think these may be incorrect on 32 bit platforms, and strace is buggy
if sys.sync_file_range then
  if abi.abi64 then
    function C.sync_file_range(fd, pos, len, flags)
      return syscall(sys.sync_file_range, int(fd), long(pos), long(len), uint(flags))
    end
  else
    if zeropad then -- only on mips
      function C.sync_file_range(fd, pos, len, flags)
        local pos1, pos2 = arg64(pos)
        local len1, len2 = arg64(len)
        -- TODO these args appear to be reversed but is this mistaken/endianness/also true elsewhere? strace broken...
        return syscall(sys.sync_file_range, int(fd), 0, long(pos2), long(pos1), long(len2), long(len1), uint(flags))
      end
    else
      function C.sync_file_range(fd, pos, len, flags)
       local pos1, pos2 = arg64(pos)
       local len1, len2 = arg64(len)
        return syscall(sys.sync_file_range, int(fd), long(pos1), long(pos2), long(len1), long(len2), uint(flags))
      end
    end
  end
elseif sys.sync_file_range2 then -- only on 32 bit platforms
  function C.sync_file_range(fd, pos, len, flags)
    local pos1, pos2 = arg64(pos)
    local len1, len2 = arg64(len)
    return syscall(sys.sync_file_range2, int(fd), uint(flags), long(pos1), long(pos2), long(len1), long(len2))
  end
end

-- TODO this should be got from somewhere more generic
-- started moving into linux/syscall.lua som explicit (see signalfd) but needs some more cleanups
local sigset_size = 8
if abi.arch == "mips" or abi.arch == "mipsel" then
  sigset_size = 16
end

local function sigmasksize(sigmask)
  local size = 0
  if sigmask then size = sigset_size end
  return ulong(size)
end

function C.epoll_pwait(epfd, events, maxevents, timeout, sigmask)
  return syscall(sys.epoll_pwait, int(epfd), void(events), int(maxevents), int(timeout), void(sigmask), sigmasksize(sigmask))
end

function C.ppoll(fds, nfds, timeout_ts, sigmask)
  return syscall(sys.ppoll, void(fds), ulong(nfds), void(timeout_ts), void(sigmask), sigmasksize(sigmask))
end
function C.signalfd(fd, mask, size, flags)
  return syscall(sys.signalfd4, int(fd), void(mask), ulong(size), int(flags))
end

-- adding more
function C.dup(oldfd) return syscall(sys.dup, int(oldfd)) end
if sys.dup2 then function C.dup2(oldfd, newfd) return syscall(sys.dup2, int(oldfd), int(newfd)) end end
function C.dup3(oldfd, newfd, flags) return syscall(sys.dup3, int(oldfd), int(newfd), int(flags)) end
if sys.chmod then function C.chmod(path, mode) return syscall(sys.chmod, void(path), uint(mode)) end end
function C.fchmod(fd, mode) return syscall(sys.fchmod, int(fd), uint(mode)) end
function C.umask(mode) return syscall(sys.umask, uint(mode)) end
if sys.access then function C.access(path, mode) return syscall(sys.access, void(path), uint(mode)) end end
function C.getppid() return syscall(sys.getppid) end
function C.getuid() return syscall(sys.getuid) end
function C.geteuid() return syscall(sys.geteuid) end
function C.getgid() return syscall(sys.getgid) end
function C.getegid() return syscall(sys.getegid) end
function C.getresuid(ruid, euid, suid) return syscall(sys.getresuid, void(ruid), void(euid), void(suid)) end
function C.getresgid(rgid, egid, sgid) return syscall(sys.getresgid, void(rgid), void(egid), void(sgid)) end
function C.setuid(id) return syscall(sys.setuid, uint(id)) end
function C.setgid(id) return syscall(sys.setgid, uint(id)) end
function C.setresuid(ruid, euid, suid) return syscall(sys.setresuid, uint(ruid), uint(euid), uint(suid)) end
function C.setresgid(rgid, egid, sgid) return syscall(sys.setresgid, uint(rgid), uint(egid), uint(sgid)) end
function C.setreuid(uid, euid) return syscall(sys.setreuid, uint(uid), uint(euid)) end
function C.setregid(gid, egid) return syscall(sys.setregid, uint(gid), uint(egid)) end
function C.flock(fd, operation) return syscall(sys.flock, int(fd), int(operation)) end
function C.getrusage(who, usage) return syscall(sys.getrusage, int(who), void(usage)) end
if sys.rmdir then function C.rmdir(path) return syscall(sys.rmdir, void(path)) end end
function C.chdir(path) return syscall(sys.chdir, void(path)) end
function C.fchdir(fd) return syscall(sys.fchdir, int(fd)) end
if sys.chown then function C.chown(path, owner, group) return syscall(sys.chown, void(path), uint(owner), uint(group)) end end
function C.fchown(fd, owner, group) return syscall(sys.fchown, int(fd), uint(owner), uint(group)) end
function C.lchown(path, owner, group) return syscall(sys.lchown, void(path), uint(owner), uint(group)) end
if sys.open then
  function C.open(pathname, flags, mode) return syscall(sys.open, void(pathname), int(flags), uint(mode)) end
end
function C.openat(dirfd, pathname, flags, mode) return syscall(sys.openat, int(dirfd), void(pathname), int(flags), uint(mode)) end
if sys.creat then function C.creat(pathname, mode) return syscall(sys.creat, void(pathname), uint(mode)) end end
function C.close(fd) return syscall(sys.close, int(fd)) end
function C.read(fd, buf, count) return syscall_long(sys.read, int(fd), void(buf), ulong(count)) end
function C.write(fd, buf, count) return syscall_long(sys.write, int(fd), void(buf), ulong(count)) end
function C.readv(fd, iov, iovcnt) return syscall_long(sys.readv, int(fd), void(iov), long(iovcnt)) end
function C.writev(fd, iov, iovcnt) return syscall_long(sys.writev, int(fd), void(iov), long(iovcnt)) end
if sys.readlink then function C.readlink(path, buf, bufsiz) return syscall_long(sys.readlink, void(path), void(buf), ulong(bufsiz)) end end
if sys.rename then function C.rename(oldpath, newpath) return syscall(sys.rename, void(oldpath), void(newpath)) end end
function C.renameat(olddirfd, oldpath, newdirfd, newpath)
  return syscall(sys.renameat, int(olddirfd), void(oldpath), int(newdirfd), void(newpath))
end
if sys.renameat2 then
  function C.renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
    return syscall(sys.renameat2, int(olddirfd), void(oldpath), int(newdirfd), void(newpath), int(flags))
  end
end
if sys.unlink then function C.unlink(pathname) return syscall(sys.unlink, void(pathname)) end end
function C.unlinkat(dirfd, pathname, flags) return syscall(sys.unlinkat, int(dirfd), void(pathname), int(flags)) end
function C.prctl(option, arg2, arg3, arg4, arg5)
  return syscall(sys.prctl, int(option), ulong(arg2), ulong(arg3), ulong(arg4), ulong(arg5))
end
if abi.arch ~= "mips" and abi.arch ~= "mipsel" and sys.pipe then -- mips uses old style dual register return calling convention that we cannot use
  function C.pipe(pipefd) return syscall(sys.pipe, void(pipefd)) end
end
function C.pipe2(pipefd, flags) return syscall(sys.pipe2, void(pipefd), int(flags)) end
function C.pause() return syscall(sys.pause) end
function C.remap_file_pages(addr, size, prot, pgoff, flags)
  return syscall(sys.remap_file_pages, void(addr), ulong(size), int(prot), long(pgoff), int(flags))
end
if sys.fork then function C.fork() return syscall(sys.fork) end end
function C.kill(pid, sig) return syscall(sys.kill, int(pid), int(sig)) end
if sys.mkdir then function C.mkdir(pathname, mode) return syscall(sys.mkdir, void(pathname), uint(mode)) end end
function C.fsync(fd) return syscall(sys.fsync, int(fd)) end
function C.fdatasync(fd) return syscall(sys.fdatasync, int(fd)) end
function C.sync() return syscall(sys.sync) end
function C.syncfs(fd) return syscall(sys.syncfs, int(fd)) end
if sys.link then function C.link(oldpath, newpath) return syscall(sys.link, void(oldpath), void(newpath)) end end
if sys.symlink then function C.symlink(oldpath, newpath) return syscall(sys.symlink, void(oldpath), void(newpath)) end end
function C.epoll_ctl(epfd, op, fd, event) return syscall(sys.epoll_ctl, int(epfd), int(op), int(fd), void(event)) end
function C.uname(buf) return syscall(sys.uname, void(buf)) end
function C.getsid(pid) return syscall(sys.getsid, int(pid)) end
function C.getpgid(pid) return syscall(sys.getpgid, int(pid)) end
function C.setpgid(pid, pgid) return syscall(sys.setpgid, int(pid), int(pgid)) end
if sys.getpgrp then function C.getpgrp() return syscall(sys.getpgrp) end end
function C.setsid() return syscall(sys.setsid) end
function C.chroot(path) return syscall(sys.chroot, void(path)) end
function C.mount(source, target, filesystemtype, mountflags, data)
  return syscall(sys.mount, void(source), void(target), void(filesystemtype), ulong(mountflags), void(data))
end
function C.umount(target) return syscall(sys.umount, void(target)) end
function C.umount2(target, flags) return syscall(sys.umount2, void(target), int(flags)) end
function C.listxattr(path, list, size) return syscall_long(sys.listxattr, void(path), void(list), ulong(size)) end
function C.llistxattr(path, list, size) return syscall_long(sys.llistxattr, void(path), void(list), ulong(size)) end
function C.flistxattr(fd, list, size) return syscall_long(sys.flistxattr, int(fd), void(list), ulong(size)) end
function C.setxattr(path, name, value, size, flags)
  return syscall(sys.setxattr, void(path), void(name), void(value), ulong(size), int(flags))
end
function C.lsetxattr(path, name, value, size, flags)
  return syscall(sys.lsetxattr, void(path), void(name), void(value), ulong(size), int(flags))
end
function C.fsetxattr(fd, name, value, size, flags)
  return syscall(sys.fsetxattr, int(fd), void(name), void(value), ulong(size), int(flags))
end
function C.getxattr(path, name, value, size)
  return syscall_long(sys.getxattr, void(path), void(name), void(value), ulong(size))
end
function C.lgetxattr(path, name, value, size)
  return syscall_long(sys.lgetxattr, void(path), void(name), void(value), ulong(size))
end
function C.fgetxattr(fd, name, value, size)
  return syscall_long(sys.fgetxattr, int(fd), void(name), void(value), ulong(size))
end
function C.removexattr(path, name) return syscall(sys.removexattr, void(path), void(name)) end
function C.lremovexattr(path, name) return syscall(sys.lremovexattr, void(path), void(name)) end
function C.fremovexattr(fd, name) return syscall(sys.fremovexattr, int(fd), void(name)) end
function C.inotify_add_watch(fd, pathname, mask) return syscall(sys.inotify_add_watch, int(fd), void(pathname), uint(mask)) end
function C.inotify_rm_watch(fd, wd) return syscall(sys.inotify_rm_watch, int(fd), int(wd)) end
function C.unshare(flags) return syscall(sys.unshare, int(flags)) end
function C.reboot(magic, magic2, cmd) return syscall(sys.reboot, int(magic), int(magic2), int(cmd)) end
function C.sethostname(name, len) return syscall(sys.sethostname, void(name), ulong(len)) end
function C.setdomainname(name, len) return syscall(sys.setdomainname, void(name), ulong(len)) end
function C.getitimer(which, curr_value) return syscall(sys.getitimer, int(which), void(curr_value)) end
function C.setitimer(which, new_value, old_value) return syscall(sys.setitimer, int(which), void(new_value), void(old_value)) end
function C.sched_yield() return syscall(sys.sched_yield) end
function C.acct(filename) return syscall(sys.acct, void(filename)) end
function C.munmap(addr, length) return syscall(sys.munmap, void(addr), ulong(length)) end
function C.faccessat(dirfd, path, mode, flags) return syscall(sys.faccessat, int(dirfd), void(path), uint(mode), int(flags)) end
function C.fchmodat(dirfd, path, mode, flags) return syscall(sys.fchmodat, int(dirfd), void(path), uint(mode), int(flags)) end
function C.mkdirat(dirfd, pathname, mode) return syscall(sys.mkdirat, int(dirfd), void(pathname), uint(mode)) end
function C.fchownat(dirfd, pathname, owner, group, flags)
  return syscall(sys.fchownat, int(dirfd), void(pathname), uint(owner), uint(group), int(flags))
end
function C.setpriority(which, who, prio) return syscall(sys.setpriority, int(which), int(who), int(prio)) end
function C.sched_get_priority_min(policy) return syscall(sys.sched_get_priority_min, int(policy)) end
function C.sched_get_priority_max(policy) return syscall(sys.sched_get_priority_max, int(policy)) end
function C.sched_rr_get_interval(pid, tp) return syscall(sys.sched_rr_get_interval, int(pid), void(tp)) end
if sys.poll then function C.poll(fds, nfds, timeout) return syscall(sys.poll, void(fds), int(nfds), int(timeout)) end end
function C.msync(addr, length, flags) return syscall(sys.msync, void(addr), ulong(length), int(flags)) end
function C.madvise(addr, length, advice) return syscall(sys.madvise, void(addr), ulong(length), int(advice)) end
function C.mlock(addr, len) return syscall(sys.mlock, void(addr), ulong(len)) end
function C.munlock(addr, len) return syscall(sys.munlock, void(addr), ulong(len)) end
function C.mlockall(flags) return syscall(sys.mlockall, int(flags)) end
function C.munlockall() return syscall(sys.munlockall) end
function C.capget(hdrp, datap) return syscall(sys.capget, void(hdrp), void(datap)) end
function C.capset(hdrp, datap) return syscall(sys.capset, void(hdrp), void(datap)) end
function C.sysinfo(info) return syscall(sys.sysinfo, void(info)) end
function C.execve(filename, argv, envp) return syscall(sys.execve, void(filename), void(argv), void(envp)) end
function C.getgroups(size, list) return syscall(sys.getgroups, int(size), void(list)) end
function C.setgroups(size, list) return syscall(sys.setgroups, int(size), void(list)) end
function C.klogctl(tp, bufp, len) return syscall(sys.syslog, int(tp), void(bufp), int(len)) end
function C.sigprocmask(how, set, oldset)
  return syscall(sys.rt_sigprocmask, int(how), void(set), void(oldset), sigmasksize(set or oldset))
end
function C.sigpending(set) return syscall(sys.rt_sigpending, void(set), sigmasksize(set)) end
function C.mremap(old_address, old_size, new_size, flags, new_address)
  return syscall_void(sys.mremap, void(old_address), ulong(old_size), ulong(new_size), int(flags), void(new_address))
end
function C.nanosleep(req, rem) return syscall(sys.nanosleep, void(req), void(rem)) end
function C.wait4(pid, status, options, rusage) return syscall(sys.wait4, int(pid), void(status), int(options), void(rusage)) end
function C.waitid(idtype, id, infop, options, rusage)
  return syscall(sys.waitid, int(idtype), uint(id), void(infop), int(options), void(rusage))
end
function C.settimeofday(tv, tz)
  return syscall(sys.settimeofday, void(tv), void(tz))
end
function C.timer_create(clockid, sevp, timerid) return syscall(sys.timer_create, int(clockid), void(sevp), void(timerid)) end
function C.timer_settime(timerid, flags, new_value, old_value)
  return syscall(sys.timer_settime, int(timerid), int(flags), void(new_value), void(old_value))
end
function C.timer_gettime(timerid, curr_value) return syscall(sys.timer_gettime, int(timerid), void(curr_value)) end
function C.timer_delete(timerid) return syscall(sys.timer_delete, int(timerid)) end
function C.timer_getoverrun(timerid) return syscall(sys.timer_getoverrun, int(timerid)) end
function C.vhangup() return syscall(sys.vhangup) end

-- only on some architectures
if sys.waitpid then
  function C.waitpid(pid, status, options) return syscall(sys.waitpid, int(pid), void(status), int(options)) end
end

-- fcntl needs a cast as last argument may be int or pointer
local fcntl = sys.fcntl64 or sys.fcntl
function C.fcntl(fd, cmd, arg) return syscall(fcntl, int(fd), int(cmd), ffi.cast(long, arg)) end

function C.pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask)
  local size = 0
  if sigmask then size = sigset_size end
  local data = longs(void(sigmask), size)
  return syscall(sys.pselect6, int(nfds), void(readfds), void(writefds), void(exceptfds), void(timeout), void(data))
end

-- need _newselect syscall on some platforms
local sysselect = sys._newselect or sys.select
if sysselect then
  function C.select(nfds, readfds, writefds, exceptfds, timeout)
    return syscall(sysselect, int(nfds), void(readfds), void(writefds), void(exceptfds), void(timeout))
  end
end

-- missing on some platforms eg ARM
if sys.alarm then
  function C.alarm(seconds) return syscall(sys.alarm, uint(seconds)) end
end

-- new system calls, may be missing TODO fix so is not
if sys.getrandom then
  function C.getrandom(buf, count, flags) return syscall(sys.getrandom, void(buf), uint(count), uint(flags)) end
end
if sys.memfd_create then
  function C.memfd_create(name, flags) return syscall(sys.memfd_create, void(name), uint(flags)) end
end

-- kernel sigaction structures actually rather different in Linux from libc ones
function C.sigaction(signum, act, oldact)
  return syscall(sys.rt_sigaction, int(signum), void(act), void(oldact), ulong(sigset_size)) -- size is size of sigset field
end

-- in VDSO for many archs, so use ffi for speed; TODO read VDSO to find functions there, needs elf reader
if pcall(function(k) return ffi.C[k] end, "clock_gettime") then
  C.clock_gettime = ffi.C.clock_gettime
else
  function C.clock_gettime(clk_id, ts) return syscall(sys.clock_gettime, int(clk_id), void(ts)) end
end

C.gettimeofday = ffi.C.gettimeofday
--function C.gettimeofday(tv, tz) return syscall(sys.gettimeofday, void(tv), void(tz)) end

-- glibc does not provide getcpu; it is however VDSO
function C.getcpu(cpu, node, tcache) return syscall(sys.getcpu, void(cpu), void(node), void(tcache)) end
-- time is VDSO but not really performance critical; does not exist for some architectures
if sys.time then
  function C.time(t) return syscall(sys.time, void(t)) end
end

-- bpf syscall that is only on Linux 3.19+
if sys.bpf then
  function C.bpf(cmd, attr)
    return syscall(sys.bpf, int(cmd), void(attr), u64(ffi.sizeof('union bpf_attr')))
  end
end
if sys.perf_event_open then
  function C.perf_event_open(attr, pid, cpu, group_fd, flags)
    return syscall(sys.perf_event_open, void(attr), int(pid), int(cpu), int(group_fd), ulong(flags))
  end
end

-- socketcalls
if not sys.socketcall then
  function C.socket(domain, tp, protocol) return syscall(sys.socket, int(domain), int(tp), int(protocol)) end
  function C.bind(sockfd, addr, addrlen) return syscall(sys.bind, int(sockfd), void(addr), uint(addrlen)) end
  function C.connect(sockfd, addr, addrlen) return syscall(sys.connect, int(sockfd), void(addr), uint(addrlen)) end
  function C.listen(sockfd, backlog) return syscall(sys.listen, int(sockfd), int(backlog)) end
  function C.accept(sockfd, addr, addrlen)
    return syscall(sys.accept, int(sockfd), void(addr), void(addrlen))
  end
  function C.getsockname(sockfd, addr, addrlen) return syscall(sys.getsockname, int(sockfd), void(addr), void(addrlen)) end
  function C.getpeername(sockfd, addr, addrlen) return syscall(sys.getpeername, int(sockfd), void(addr), void(addrlen)) end
  function C.socketpair(domain, tp, protocol, sv) return syscall(sys.socketpair, int(domain), int(tp), int(protocol), void(sv)) end
  function C.send(sockfd, buf, len, flags) return syscall_long(sys.send, int(sockfd), void(buf), ulong(len), int(flags)) end
  function C.recv(sockfd, buf, len, flags) return syscall_long(sys.recv, int(sockfd), void(buf), ulong(len), int(flags)) end
  function C.sendto(sockfd, buf, len, flags, dest_addr, addrlen)
    return syscall_long(sys.sendto, int(sockfd), void(buf), ulong(len), int(flags), void(dest_addr), uint(addrlen))
  end
  function C.recvfrom(sockfd, buf, len, flags, src_addr, addrlen)
    return syscall_long(sys.recvfrom, int(sockfd), void(buf), ulong(len), int(flags), void(src_addr), void(addrlen))
  end
  function C.shutdown(sockfd, how) return syscall(sys.shutdown, int(sockfd), int(how)) end
  function C.setsockopt(sockfd, level, optname, optval, optlen)
    return syscall(sys.setsockopt, int(sockfd), int(level), int(optname), void(optval), uint(optlen))
  end
  function C.getsockopt(sockfd, level, optname, optval, optlen)
    return syscall(sys.getsockopt, int(sockfd), int(level), int(optname), void(optval), void(optlen))
  end
  function C.sendmsg(sockfd, msg, flags) return syscall_long(sys.sendmsg, int(sockfd), void(msg), int(flags)) end
  function C.recvmsg(sockfd, msg, flags) return syscall_long(sys.recvmsg, int(sockfd), void(msg), int(flags)) end
  function C.accept4(sockfd, addr, addrlen, flags)
    return syscall(sys.accept4, int(sockfd), void(addr), void(addrlen), int(flags))
  end
  function C.recvmmsg(sockfd, msgvec, vlen, flags, timeout)
    return syscall(sys.recvmmsg, int(sockfd), void(msgvec), uint(vlen), int(flags), void(timeout))
  end
  function C.sendmmsg(sockfd, msgvec, vlen, flags)
    return syscall(sys.sendmmsg, int(sockfd), void(msgvec), uint(vlen), int(flags))
  end
else
  function C.socket(domain, tp, protocol)
    local args = longs(domain, tp, protocol)
    return syscall(sys.socketcall, int(socketcalls.SOCKET), void(args))
  end
  function C.bind(sockfd, addr, addrlen)
    local args = longs(sockfd, void(addr), addrlen)
    return syscall(sys.socketcall, int(socketcalls.BIND), void(args))
  end
  function C.connect(sockfd, addr, addrlen)
    local args = longs(sockfd, void(addr), addrlen)
    return syscall(sys.socketcall, int(socketcalls.CONNECT), void(args))
  end
  function C.listen(sockfd, backlog)
    local args = longs(sockfd, backlog)
    return syscall(sys.socketcall, int(socketcalls.LISTEN), void(args))
  end
  function C.accept(sockfd, addr, addrlen)
    local args = longs(sockfd, void(addr), void(addrlen))
    return syscall(sys.socketcall, int(socketcalls.ACCEPT), void(args))
  end
  function C.getsockname(sockfd, addr, addrlen)
    local args = longs(sockfd, void(addr), void(addrlen))
    return syscall(sys.socketcall, int(socketcalls.GETSOCKNAME), void(args))
  end
  function C.getpeername(sockfd, addr, addrlen)
    local args = longs(sockfd, void(addr), void(addrlen))
    return syscall(sys.socketcall, int(socketcalls.GETPEERNAME), void(args))
  end
  function C.socketpair(domain, tp, protocol, sv)
    local args = longs(domain, tp, protocol, void(sv))
    return syscall(sys.socketcall, int(socketcalls.SOCKETPAIR), void(args))
  end
  function C.send(sockfd, buf, len, flags)
    local args = longs(sockfd, void(buf), len, flags)
    return syscall_long(sys.socketcall, int(socketcalls.SEND), void(args))
  end
  function C.recv(sockfd, buf, len, flags)
    local args = longs(sockfd, void(buf), len, flags)
    return syscall_long(sys.socketcall, int(socketcalls.RECV), void(args))
  end
  function C.sendto(sockfd, buf, len, flags, dest_addr, addrlen)
    local args = longs(sockfd, void(buf), len, flags, void(dest_addr), addrlen)
    return syscall_long(sys.socketcall, int(socketcalls.SENDTO), void(args))
  end
  function C.recvfrom(sockfd, buf, len, flags, src_addr, addrlen)
    local args = longs(sockfd, void(buf), len, flags, void(src_addr), void(addrlen))
    return syscall_long(sys.socketcall, int(socketcalls.RECVFROM), void(args))
  end
  function C.shutdown(sockfd, how)
    local args = longs(sockfd, how)
    return syscall(sys.socketcall, int(socketcalls.SHUTDOWN), void(args))
  end
  function C.setsockopt(sockfd, level, optname, optval, optlen)
    local args = longs(sockfd, level, optname, void(optval), optlen)
    return syscall(sys.socketcall, int(socketcalls.SETSOCKOPT), void(args))
  end
  function C.getsockopt(sockfd, level, optname, optval, optlen)
    local args = longs(sockfd, level, optname, void(optval), void(optlen))
    return syscall(sys.socketcall, int(socketcalls.GETSOCKOPT), void(args))
  end
  function C.sendmsg(sockfd, msg, flags)
    local args = longs(sockfd, void(msg), flags)
    return syscall_long(sys.socketcall, int(socketcalls.SENDMSG), void(args))
  end
  function C.recvmsg(sockfd, msg, flags)
    local args = longs(sockfd, void(msg), flags)
    return syscall_long(sys.socketcall, int(socketcalls.RECVMSG), void(args))
  end
  function C.accept4(sockfd, addr, addrlen, flags)
    local args = longs(sockfd, void(addr), void(addrlen), flags)
    return syscall(sys.socketcall, int(socketcalls.ACCEPT4), void(args))
  end
  function C.recvmmsg(sockfd, msgvec, vlen, flags, timeout)
    local args = longs(sockfd, void(msgvec), vlen, flags, void(timeout))
    return syscall(sys.socketcall, int(socketcalls.RECVMMSG), void(args))
  end
  function C.sendmmsg(sockfd, msgvec, vlen, flags)
    local args = longs(sockfd, void(msgvec), vlen, flags)
    return syscall(sys.socketcall, int(socketcalls.SENDMMSG), void(args))
  end
end

return C


]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.syscalls"],"module already exists")sources["syscall.linux.syscalls"]=([===[-- <pack syscall.linux.syscalls> --
-- This is the actual system calls for Linux

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local abi = require "syscall.abi"

return function(S, hh, c, C, types)

local ret64, retnum, retfd, retbool, retptr, retiter = hh.ret64, hh.retnum, hh.retfd, hh.retbool, hh.retptr, hh.retiter

local ffi = require "ffi"
local errno = ffi.errno

local bit = require "syscall.bit"

local t, pt, s = types.t, types.pt, types.s

local h = require "syscall.helpers"

local istype, mktype, getfd = h.istype, h.mktype, h.getfd

if abi.abi32 then
  -- override open call with largefile -- TODO move this hack to c.lua instead
  function S.open(pathname, flags, mode)
    flags = c.O(flags, "LARGEFILE")
    return retfd(C.open(pathname, flags, c.MODE[mode]))
  end
  function S.openat(dirfd, pathname, flags, mode)
    flags = c.O(flags, "LARGEFILE")
    return retfd(C.openat(c.AT_FDCWD[dirfd], pathname, flags, c.MODE[mode]))
  end
  -- creat has no largefile flag so cannot be used
  function S.creat(pathname, mode) return S.open(pathname, "CREAT,WRONLY,TRUNC", mode) end
end

function S.pause() return retbool(C.pause()) end

function S.acct(filename) return retbool(C.acct(filename)) end

function S.getpriority(which, who)
  local ret, err = C.getpriority(c.PRIO[which], who or 0)
  if ret == -1 then return nil, t.error(err or errno()) end
  return 20 - ret -- adjust for kernel returned values as this is syscall not libc
end

-- we could allocate ptid, ctid, tls if required in flags instead. TODO add signal into flag parsing directly
function S.clone(flags, signal, stack, ptid, tls, ctid)
  flags = c.CLONE[flags] + c.SIG[signal or 0]
  return retnum(C.clone(flags, stack, ptid, tls, ctid))
end

if C.unshare then -- quite new, also not defined in rump yet
  function S.unshare(flags) return retbool(C.unshare(c.CLONE[flags])) end
end
if C.setns then
  function S.setns(fd, nstype) return retbool(C.setns(getfd(fd), c.CLONE[nstype])) end
end

function S.reboot(cmd)
  return retbool(C.reboot(c.LINUX_REBOOT.MAGIC1, c.LINUX_REBOOT.MAGIC2, c.LINUX_REBOOT_CMD[cmd]))
end

-- note waitid also provides rusage that Posix does not have, override default
function S.waitid(idtype, id, options, infop, rusage) -- note order of args, as usually dont supply infop, rusage
  if not infop then infop = t.siginfo() end
  if not rusage and rusage ~= false then rusage = t.rusage() end
  local ret, err = C.waitid(c.P[idtype], id or 0, infop, c.W[options], rusage)
  if ret == -1 then return nil, t.error(err or errno()) end
  return infop, nil, rusage
end

function S.exit(status) C.exit_group(c.EXIT[status or 0]) end

function S.sync_file_range(fd, offset, count, flags)
  return retbool(C.sync_file_range(getfd(fd), offset, count, c.SYNC_FILE_RANGE[flags]))
end

function S.getcwd(buf, size)
  size = size or c.PATH_MAX
  buf = buf or t.buffer(size)
  local ret, err = C.getcwd(buf, size)
  if ret == -1 then return nil, t.error(err or errno()) end
  return ffi.string(buf)
end

function S.statfs(path)
  local st = t.statfs()
  local ret, err = C.statfs(path, st)
  if ret == -1 then return nil, t.error(err or errno()) end
  return st
end

function S.fstatfs(fd)
  local st = t.statfs()
  local ret, err = C.fstatfs(getfd(fd), st)
  if ret == -1 then return nil, t.error(err or errno()) end
  return st
end

function S.mremap(old_address, old_size, new_size, flags, new_address)
  return retptr(C.mremap(old_address, old_size, new_size, c.MREMAP[flags], new_address))
end
function S.remap_file_pages(addr, size, prot, pgoff, flags)
  return retbool(C.remap_file_pages(addr, size, c.PROT[prot], pgoff, c.MAP[flags]))
end
function S.fadvise(fd, advice, offset, len) -- note argument order TODO change back?
  return retbool(C.fadvise64(getfd(fd), offset or 0, len or 0, c.POSIX_FADV[advice]))
end
function S.fallocate(fd, mode, offset, len)
  return retbool(C.fallocate(getfd(fd), c.FALLOC_FL[mode], offset or 0, len))
end
function S.posix_fallocate(fd, offset, len) return S.fallocate(fd, 0, offset, len) end
function S.readahead(fd, offset, count) return retbool(C.readahead(getfd(fd), offset, count)) end

-- TODO change to type?
function S.uname()
  local u = t.utsname()
  local ret, err = C.uname(u)
  if ret == -1 then return nil, t.error(err or errno()) end
  return {sysname = ffi.string(u.sysname), nodename = ffi.string(u.nodename), release = ffi.string(u.release),
          version = ffi.string(u.version), machine = ffi.string(u.machine), domainname = ffi.string(u.domainname)}
end

function S.sethostname(s, len) return retbool(C.sethostname(s, len or #s)) end
function S.setdomainname(s, len) return retbool(C.setdomainname(s, len or #s)) end

if C.time then
  function S.time(time) return retnum(C.time(time)) end
end

function S.sysinfo(info)
  info = info or t.sysinfo()
  local ret, err = C.sysinfo(info)
  if ret == -1 then return nil, t.error(err or errno()) end
  return info
end

function S.signalfd(set, flags, fd) -- note different order of args, as fd usually empty. See also signalfd_read()
  set = mktype(t.sigset, set)
  if fd then fd = getfd(fd) else fd = -1 end
  -- note includes (hidden) size argument
  return retfd(C.signalfd(fd, set, s.sigset, c.SFD[flags]))
end

-- note that syscall does return timeout remaining but libc does not, due to standard prototype TODO use syscall
-- note this is the only difference with NetBSD pollts, so could merge them
function S.ppoll(fds, timeout, set)
  if timeout then timeout = mktype(t.timespec, timeout) end
  if set then set = mktype(t.sigset, set) end
  return retnum(C.ppoll(fds.pfd, #fds, timeout, set))
end
if not S.poll then
  function S.poll(fd, timeout)
    if timeout then timeout = mktype(t.timespec, timeout / 1000) end
    return S.ppoll(fd, timeout)
  end
end
function S.mount(source, target, fstype, mountflags, data)
  return retbool(C.mount(source or "none", target, fstype, c.MS[mountflags], data))
end

function S.umount(target, flags)
  return retbool(C.umount2(target, c.UMOUNT[flags]))
end

function S.prlimit(pid, resource, new_limit, old_limit)
  if new_limit then new_limit = mktype(t.rlimit, new_limit) end
  old_limit = old_limit or t.rlimit()
  local ret, err = C.prlimit64(pid or 0, c.RLIMIT[resource], new_limit, old_limit)
  if ret == -1 then return nil, t.error(err or errno()) end
  return old_limit
end

function S.epoll_create(flags)
  return retfd(C.epoll_create1(c.EPOLLCREATE[flags]))
end

function S.epoll_ctl(epfd, op, fd, event)
  if type(event) == "string" or type(event) == "number" then event = {events = event, fd = getfd(fd)} end
  event = mktype(t.epoll_event, event)
  return retbool(C.epoll_ctl(getfd(epfd), c.EPOLL_CTL[op], getfd(fd), event))
end

if C.epoll_wait then
  function S.epoll_wait(epfd, events, timeout)
    local ret, err = C.epoll_wait(getfd(epfd), events.ep, #events, timeout or -1)
    return retiter(ret, err, events.ep)
  end
else
  function S.epoll_wait(epfd, events, timeout)
    local ret, err = C.epoll_pwait(getfd(epfd), events.ep, #events, timeout or -1, nil)
    return retiter(ret, err, events.ep)
  end
end

function S.epoll_pwait(epfd, events, timeout, sigmask)
  if sigmask then sigmask = mktype(t.sigset, sigmask) end
  local ret, err = C.epoll_pwait(getfd(epfd), events.ep, #events, timeout or -1, sigmask)
  return retiter(ret, err, events.ep)
end

function S.splice(fd_in, off_in, fd_out, off_out, len, flags)
  local offin, offout = off_in, off_out
  if off_in and not ffi.istype(t.off1, off_in) then
    offin = t.off1()
    offin[0] = off_in
  end
  if off_out and not ffi.istype(t.off1, off_out) then
    offout = t.off1()
    offout[0] = off_out
  end
  return retnum(C.splice(getfd(fd_in), offin, getfd(fd_out), offout, len, c.SPLICE_F[flags]))
end

function S.vmsplice(fd, iov, flags)
  iov = mktype(t.iovecs, iov)
  return retnum(C.vmsplice(getfd(fd), iov.iov, #iov, c.SPLICE_F[flags]))
end

function S.tee(fd_in, fd_out, len, flags)
  return retnum(C.tee(getfd(fd_in), getfd(fd_out), len, c.SPLICE_F[flags]))
end

function S.inotify_init(flags) return retfd(C.inotify_init1(c.IN_INIT[flags])) end
function S.inotify_add_watch(fd, pathname, mask) return retnum(C.inotify_add_watch(getfd(fd), pathname, c.IN[mask])) end
function S.inotify_rm_watch(fd, wd) return retbool(C.inotify_rm_watch(getfd(fd), wd)) end

function S.sendfile(out_fd, in_fd, offset, count)
  if type(offset) == "number" then
    offset = t.off1(offset)
  end
  return retnum(C.sendfile(getfd(out_fd), getfd(in_fd), offset, count))
end

function S.eventfd(initval, flags) return retfd(C.eventfd(initval or 0, c.EFD[flags])) end

function S.timerfd_create(clockid, flags)
  return retfd(C.timerfd_create(c.CLOCK[clockid], c.TFD[flags]))
end

function S.timerfd_settime(fd, flags, it, oldtime)
  oldtime = oldtime or t.itimerspec()
  local ret, err = C.timerfd_settime(getfd(fd), c.TFD_TIMER[flags or 0], mktype(t.itimerspec, it), oldtime)
  if ret == -1 then return nil, t.error(err or errno()) end
  return oldtime
end

function S.timerfd_gettime(fd, curr_value)
  curr_value = curr_value or t.itimerspec()
  local ret, err = C.timerfd_gettime(getfd(fd), curr_value)
  if ret == -1 then return nil, t.error(err or errno()) end
  return curr_value
end

function S.pivot_root(new_root, put_old) return retbool(C.pivot_root(new_root, put_old)) end

-- aio functions
function S.io_setup(nr_events)
  local ctx = t.aio_context1()
  local ret, err = C.io_setup(nr_events, ctx)
  if ret == -1 then return nil, t.error(err or errno()) end
  return ctx[0]
end

function S.io_destroy(ctx) return retbool(C.io_destroy(ctx)) end

function S.io_cancel(ctx, iocb, result)
  result = result or t.io_event()
  local ret, err = C.io_cancel(ctx, iocb, result)
  if ret == -1 then return nil, t.error(err or errno()) end
  return result
end

function S.io_getevents(ctx, min, events, timeout)
  if timeout then timeout = mktype(t.timespec, timeout) end
  local ret, err = C.io_getevents(ctx, min or events.count, events.count, events.ev, timeout)
  return retiter(ret, err, events.ev)
end

-- iocb must persist until retrieved (as we get pointer), so cannot be passed as table must take t.iocb_array
function S.io_submit(ctx, iocb)
  return retnum(C.io_submit(ctx, iocb.ptrs, iocb.nr))
end

-- TODO prctl should be in a seperate file like ioctl fnctl (this is a Linux only interface)
-- map for valid options for arg2
local prctlmap = {
  [c.PR.CAPBSET_READ] = c.CAP,
  [c.PR.CAPBSET_DROP] = c.CAP,
  [c.PR.SET_ENDIAN] = c.PR_ENDIAN,
  [c.PR.SET_FPEMU] = c.PR_FPEMU,
  [c.PR.SET_FPEXC] = c.PR_FP_EXC,
  [c.PR.SET_PDEATHSIG] = c.SIG,
  --[c.PR.SET_SECUREBITS] = c.SECBIT, -- TODO not defined yet
  [c.PR.SET_TIMING] = c.PR_TIMING,
  [c.PR.SET_TSC] = c.PR_TSC,
  [c.PR.SET_UNALIGN] = c.PR_UNALIGN,
  [c.PR.MCE_KILL] = c.PR_MCE_KILL,
  [c.PR.SET_SECCOMP] = c.SECCOMP_MODE,
  [c.PR.SET_NO_NEW_PRIVS] = h.booltoc,
}

local prctlrint = { -- returns an integer directly TODO add metatables to set names
  [c.PR.GET_DUMPABLE] = true,
  [c.PR.GET_KEEPCAPS] = true,
  [c.PR.CAPBSET_READ] = true,
  [c.PR.GET_TIMING] = true,
  [c.PR.GET_SECUREBITS] = true,
  [c.PR.MCE_KILL_GET] = true,
  [c.PR.GET_SECCOMP] = true,
  [c.PR.GET_NO_NEW_PRIVS] = true,
}

local prctlpint = { -- returns result in a location pointed to by arg2
  [c.PR.GET_ENDIAN] = true,
  [c.PR.GET_FPEMU] = true,
  [c.PR.GET_FPEXC] = true,
  [c.PR.GET_PDEATHSIG] = true,
  [c.PR.GET_UNALIGN] = true,
}

-- this is messy, TODO clean up, its own file see above
function S.prctl(option, arg2, arg3, arg4, arg5)
  local i, name
  option = c.PR[option]
  local m = prctlmap[option]
  if m then arg2 = m[arg2] end
  if option == c.PR.MCE_KILL and arg2 == c.PR_MCE_KILL.SET then
    arg3 = c.PR_MCE_KILL_OPT[arg3]
  elseif prctlpint[option] then
    i = t.int1()
    arg2 = ffi.cast(t.ulong, i)
  elseif option == c.PR.GET_NAME then
    name = t.buffer(16)
    arg2 = ffi.cast(t.ulong, name)
  elseif option == c.PR.SET_NAME then
    if type(arg2) == "string" then arg2 = ffi.cast(t.ulong, arg2) end
  elseif option == c.PR.SET_SECCOMP then
    arg3 = t.intptr(arg3 or 0)
  end
  local ret = C.prctl(option, arg2 or 0, arg3 or 0, arg4 or 0, arg5 or 0)
  if ret == -1 then return nil, t.error() end
  if prctlrint[option] then return ret end
  if prctlpint[option] then return i[0] end
  if option == c.PR.GET_NAME then
    if name[15] ~= 0 then return ffi.string(name, 16) end -- actually, 15 bytes seems to be longest, aways 0 terminated
    return ffi.string(name)
  end
  return true
end

function S.syslog(tp, buf, len)
  if not buf and (tp == 2 or tp == 3 or tp == 4) then
    if not len then
      -- this is the glibc name for the syslog syscall
      len = C.klogctl(10, nil, 0) -- get size so we can allocate buffer
      if len == -1 then return nil, t.error() end
    end
    buf = t.buffer(len)
  end
  local ret, err = C.klogctl(tp, buf or nil, len or 0)
  if ret == -1 then return nil, t.error(err or errno()) end
  if tp == 9 or tp == 10 then return tonumber(ret) end
  if tp == 2 or tp == 3 or tp == 4 then return ffi.string(buf, ret) end
  return true
end

function S.adjtimex(a)
  a = mktype(t.timex, a)
  local ret, err = C.adjtimex(a)
  if ret == -1 then return nil, t.error(err or errno()) end
  return t.adjtimex(ret, a)
end

if C.alarm then
  function S.alarm(s) return C.alarm(s) end
end

function S.setreuid(ruid, euid) return retbool(C.setreuid(ruid, euid)) end
function S.setregid(rgid, egid) return retbool(C.setregid(rgid, egid)) end

function S.getresuid(ruid, euid, suid)
  ruid, euid, suid = ruid or t.uid1(), euid or t.uid1(), suid or t.uid1()
  local ret, err = C.getresuid(ruid, euid, suid)
  if ret == -1 then return nil, t.error(err or errno()) end
  return true, nil, ruid[0], euid[0], suid[0]
end
function S.getresgid(rgid, egid, sgid)
  rgid, egid, sgid = rgid or t.gid1(), egid or t.gid1(), sgid or t.gid1()
  local ret, err = C.getresgid(rgid, egid, sgid)
  if ret == -1 then return nil, t.error(err or errno()) end
  return true, nil, rgid[0], egid[0], sgid[0]
end
function S.setresuid(ruid, euid, suid) return retbool(C.setresuid(ruid, euid, suid)) end
function S.setresgid(rgid, egid, sgid) return retbool(C.setresgid(rgid, egid, sgid)) end

function S.vhangup() return retbool(C.vhangup()) end

function S.swapon(path, swapflags) return retbool(C.swapon(path, c.SWAP_FLAG[swapflags])) end
function S.swapoff(path) return retbool(C.swapoff(path)) end

if C.getrandom then
  function S.getrandom(buf, count, flags)
    return retnum(C.getrandom(buf, count or #buf or 64, c.GRND[flags]))
  end
end

if C.memfd_create then
  function S.memfd_create(name, flags) return retfd(C.memfd_create(name, c.MFD[flags])) end
end

-- capabilities. Somewhat complex kernel interface due to versioning, Posix requiring malloc in API.
-- only support version 3, should be ok for recent kernels, or pass your own hdr, data in
-- to detect capability API version, pass in hdr with empty version, version will be set
function S.capget(hdr, data) -- normally just leave as nil for get, can pass pid in
  hdr = istype(t.user_cap_header, hdr) or t.user_cap_header(c.LINUX_CAPABILITY_VERSION[3], hdr or 0)
  if not data and hdr.version ~= 0 then data = t.user_cap_data2() end
  local ret, err = C.capget(hdr, data)
  if ret == -1 then return nil, t.error(err or errno()) end
  if not data then return hdr end
  return t.capabilities(hdr, data)
end

function S.capset(hdr, data)
  if ffi.istype(t.capabilities, hdr) then hdr, data = hdr:hdrdata() end
  return retbool(C.capset(hdr, data))
end

function S.getcpu(cpu, node)
  cpu = cpu or t.uint1()
  node = node or t.uint1()
  local ret, err = C.getcpu(cpu, node)
  if ret == -1 then return nil, t.error(err or errno()) end
  return {cpu = cpu[0], node = node[0]}
end

function S.sched_getscheduler(pid) return retnum(C.sched_getscheduler(pid or 0)) end
function S.sched_setscheduler(pid, policy, param)
  param = mktype(t.sched_param, param or 0)
  return retbool(C.sched_setscheduler(pid or 0, c.SCHED[policy], param))
end
function S.sched_yield() return retbool(C.sched_yield()) end

function S.sched_getaffinity(pid, mask, len) -- note len last as rarely used. All parameters optional
  mask = mktype(t.cpu_set, mask)
  local ret, err = C.sched_getaffinity(pid or 0, len or s.cpu_set, mask)
  if ret == -1 then return nil, t.error(err or errno()) end
  return mask
end

function S.sched_setaffinity(pid, mask, len) -- note len last as rarely used
  return retbool(C.sched_setaffinity(pid or 0, len or s.cpu_set, mktype(t.cpu_set, mask)))
end

function S.sched_get_priority_max(policy) return retnum(C.sched_get_priority_max(c.SCHED[policy])) end
function S.sched_get_priority_min(policy) return retnum(C.sched_get_priority_min(c.SCHED[policy])) end

function S.sched_setparam(pid, param)
  return retbool(C.sched_setparam(pid or 0, mktype(t.sched_param, param or 0)))
end
function S.sched_getparam(pid, param)
  param = mktype(t.sched_param, param or 0)
  local ret, err = C.sched_getparam(pid or 0, param)
  if ret == -1 then return nil, t.error(err or errno()) end
  return param.sched_priority -- only one useful parameter
end

function S.sched_rr_get_interval(pid, ts)
  ts = mktype(t.timespec, ts)
  local ret, err = C.sched_rr_get_interval(pid or 0, ts)
  if ret == -1 then return nil, t.error(err or errno()) end
  return ts
end

-- this is recommended way to size buffers for xattr
local function growattrbuf(f, a, b)
  local len = 512
  local buffer = t.buffer(len)
  local ret, err
  repeat
    if b then
      ret, err = f(a, b, buffer, len)
    else
      ret, err = f(a, buffer, len)
    end
    ret = tonumber(ret)
    if ret == -1 and (err or errno()) ~= c.E.RANGE then return nil, t.error(err or errno()) end
    if ret == -1 then
      len = len * 2
      buffer = t.buffer(len)
    end
  until ret >= 0

  return ffi.string(buffer, ret)
end

local function lattrbuf(f, a)
  local s, err = growattrbuf(f, a)
  if not s then return nil, err end
  local tab = h.split('\0', s)
  tab[#tab] = nil -- there is a trailing \0 so one extra
  return tab
end

-- TODO Note these should be in NetBSD too, but no useful filesystem (ex nfs) has xattr support, so never tested
if C.listxattr then
  function S.listxattr(path) return lattrbuf(C.listxattr, path) end
  function S.llistxattr(path) return lattrbuf(C.llistxattr, path) end
  function S.flistxattr(fd) return lattrbuf(C.flistxattr, getfd(fd)) end
end

if C.setxattr then
  function S.setxattr(path, name, value, flags) return retbool(C.setxattr(path, name, value, #value, c.XATTR[flags])) end
  function S.lsetxattr(path, name, value, flags) return retbool(C.lsetxattr(path, name, value, #value, c.XATTR[flags])) end
  function S.fsetxattr(fd, name, value, flags) return retbool(C.fsetxattr(getfd(fd), name, value, #value, c.XATTR[flags])) end
end

if C.getxattr then
  function S.getxattr(path, name) return growattrbuf(C.getxattr, path, name) end
  function S.lgetxattr(path, name) return growattrbuf(C.lgetxattr, path, name) end
  function S.fgetxattr(fd, name) return growattrbuf(C.fgetxattr, getfd(fd), name) end
end

if C.removexattr then
  function S.removexattr(path, name) return retbool(C.removexattr(path, name)) end
  function S.lremovexattr(path, name) return retbool(C.lremovexattr(path, name)) end
  function S.fremovexattr(fd, name) return retbool(C.fremovexattr(getfd(fd), name)) end
end

-- helper function to set and return attributes in tables
-- TODO this would make more sense as types?
-- TODO listxattr should return an iterator not a table?
local function xattr(list, get, set, remove, path, t)
  local l, err = list(path)
  if not l then return nil, err end
  if not t then -- no table, so read
    local r = {}
    for _, name in ipairs(l) do
      r[name] = get(path, name) -- ignore errors
    end
    return r
  end
  -- write
  for _, name in ipairs(l) do
    if t[name] then
      set(path, name, t[name]) -- ignore errors, replace
      t[name] = nil
    else
      remove(path, name)
    end
  end
  for name, value in pairs(t) do
    set(path, name, value) -- ignore errors, create
  end
  return true
end

if S.listxattr and S.getxattr then
function S.xattr(path, t) return xattr(S.listxattr, S.getxattr, S.setxattr, S.removexattr, path, t) end
function S.lxattr(path, t) return xattr(S.llistxattr, S.lgetxattr, S.lsetxattr, S.lremovexattr, path, t) end
function S.fxattr(fd, t) return xattr(S.flistxattr, S.fgetxattr, S.fsetxattr, S.fremovexattr, fd, t) end
end

-- POSIX message queues. Note there is no mq_close as it is just close in Linux
function S.mq_open(name, flags, mode, attr)
  local ret, err = C.mq_open(name, c.O[flags], c.MODE[mode], mktype(t.mq_attr, attr))
  if ret == -1 then return nil, t.error(err or errno()) end
  return t.mqd(ret)
end

function S.mq_unlink(name)
  return retbool(C.mq_unlink(name))
end

function S.mq_getsetattr(mqd, new, old) -- provided for completeness, but use getattr, setattr which are methods
  return retbool(C.mq_getsetattr(getfd(mqd), new, old))
end

function S.mq_timedsend(mqd, msg_ptr, msg_len, msg_prio, abs_timeout)
  if abs_timeout then abs_timeout = mktype(t.timespec, abs_timeout) end
  return retbool(C.mq_timedsend(getfd(mqd), msg_ptr, msg_len or #msg_ptr, msg_prio or 0, abs_timeout))
end

-- like read, return string if buffer not provided. Length required. TODO should we return prio?
function S.mq_timedreceive(mqd, msg_ptr, msg_len, msg_prio, abs_timeout)
  if abs_timeout then abs_timeout = mktype(t.timespec, abs_timeout) end
  if msg_ptr then return retbool(C.mq_timedreceive(getfd(mqd), msg_ptr, msg_len or #msg_ptr, msg_prio, abs_timeout)) end
  msg_ptr = t.buffer(msg_len)
  local ret, err = C.mq_timedreceive(getfd(mqd), msg_ptr, msg_len or #msg_ptr, msg_prio, abs_timeout)
  if ret == -1 then return nil, t.error(err or errno()) end
  return ffi.string(msg_ptr,ret)
end

-- pty functions where not in common code TODO move to linux/libc?
function S.grantpt(fd) return true end -- Linux does not need to do anything here (Musl does not)
function S.unlockpt(fd) return S.ioctl(fd, "TIOCSPTLCK", 0) end
function S.ptsname(fd)
  local pts, err = S.ioctl(fd, "TIOCGPTN")
  if not pts then return nil, err end
  return "/dev/pts/" .. tostring(pts)
end
function S.tcgetattr(fd) return S.ioctl(fd, "TCGETS") end
local tcsets = {
  [c.TCSA.NOW]   = "TCSETS",
  [c.TCSA.DRAIN] = "TCSETSW",
  [c.TCSA.FLUSH] = "TCSETSF",
}
function S.tcsetattr(fd, optional_actions, tio)
  local inc = c.TCSA[optional_actions]
  return S.ioctl(fd, tcsets[inc], tio)
end
function S.tcsendbreak(fd, duration)
  return S.ioctl(fd, "TCSBRK", pt.void(0)) -- Linux ignores duration
end
function S.tcdrain(fd)
  return S.ioctl(fd, "TCSBRK", pt.void(1)) -- note use of literal 1 cast to pointer
end
function S.tcflush(fd, queue_selector)
  return S.ioctl(fd, "TCFLSH", pt.void(c.TCFLUSH[queue_selector]))
end
function S.tcflow(fd, action)
  return S.ioctl(fd, "TCXONC", pt.void(c.TCFLOW[action]))
end

-- compat code for stuff that is not actually a syscall under Linux

-- old rlimit functions in Linux are 32 bit only so now defined using prlimit
function S.getrlimit(resource)
  return S.prlimit(0, resource)
end

function S.setrlimit(resource, rlim)
  local ret, err = S.prlimit(0, resource, rlim)
  if not ret then return nil, err end
  return true
end

function S.gethostname()
  local u, err = S.uname()
  if not u then return nil, err end
  return u.nodename
end

function S.getdomainname()
  local u, err = S.uname()
  if not u then return nil, err end
  return u.domainname
end

function S.killpg(pgrp, sig) return S.kill(-pgrp, sig) end

-- helper function to read inotify structs as table from inotify fd, TODO could be in util
function S.inotify_read(fd, buffer, len)
  len = len or 1024
  buffer = buffer or t.buffer(len)
  local ret, err = S.read(fd, buffer, len)
  if not ret then return nil, err end
  return t.inotify_events(buffer, ret)
end

-- in Linux mkfifo is not a syscall, emulate
function S.mkfifo(path, mode) return S.mknod(path, bit.bor(c.MODE[mode], c.S_I.FIFO)) end
function S.mkfifoat(fd, path, mode) return S.mknodat(fd, path, bit.bor(c.MODE[mode], c.S_I.FIFO), 0) end

-- in Linux getpagesize is not a syscall for most architectures.
-- It is pretty obscure how you get the page size for architectures that have variable page size, I think it is coded into libc
-- that matches kernel. Which is not much use for us.
-- fortunately Linux (unlike BSD) checks correct offsets on mapping /dev/zero
local pagesize -- store so we do not repeat this

if not S.getpagesize then
  function S.getpagesize()
    if pagesize then return pagesize end
    local sz = 4096
    local fd, err = S.open("/dev/zero", "rdwr")
    if not fd then return nil, err end
    while sz < 4096 * 1024 + 1024 do
      local mm, err = S.mmap(nil, sz, "read", "shared", fd, sz)
      if mm then
        S.munmap(mm, sz)
        pagesize = sz
        return sz
      end
      sz = sz * 2
    end
  end
end

-- in Linux shm_open and shm_unlink are not syscalls
local shm = "/dev/shm"

function S.shm_open(pathname, flags, mode)
  if pathname:sub(1, 1) ~= "/" then pathname = "/" .. pathname end
  pathname = shm .. pathname
  return S.open(pathname, c.O(flags, "nofollow", "cloexec", "nonblock"), mode)
end

function S.shm_unlink(pathname)
  if pathname:sub(1, 1) ~= "/" then pathname = "/" .. pathname end
  pathname = shm .. pathname
  return S.unlink(pathname)
end

-- TODO setpgrp and similar - see the man page

-- in Linux pathconf can just return constants

-- TODO these could go into constants, although maybe better to get from here
local PAGE_SIZE = S.getpagesize
local NAME_MAX = 255
local PATH_MAX = 4096 -- TODO this is in constants, inconsistently
local PIPE_BUF = 4096
local FILESIZEBITS = 64
local SYMLINK_MAX = 255
local _POSIX_LINK_MAX = 8
local _POSIX_MAX_CANON = 255
local _POSIX_MAX_INPUT = 255

local pathconf_values = {
  [c.PC.LINK_MAX] = _POSIX_LINK_MAX,
  [c.PC.MAX_CANON] = _POSIX_MAX_CANON,
  [c.PC.MAX_INPUT] = _POSIX_MAX_INPUT,
  [c.PC.NAME_MAX] = NAME_MAX,
  [c.PC.PATH_MAX] = PATH_MAX,
  [c.PC.PIPE_BUF] = PIPE_BUF,
  [c.PC.CHOWN_RESTRICTED] = 1,
  [c.PC.NO_TRUNC] = 1,
  [c.PC.VDISABLE] = 0,
  [c.PC.SYNC_IO] = 1,
  [c.PC.ASYNC_IO] = -1,
  [c.PC.PRIO_IO] = -1,
  [c.PC.SOCK_MAXBUF] = -1,
  [c.PC.FILESIZEBITS] = FILESIZEBITS,
  [c.PC.REC_INCR_XFER_SIZE] = PAGE_SIZE,
  [c.PC.REC_MAX_XFER_SIZE] = PAGE_SIZE,
  [c.PC.REC_MIN_XFER_SIZE] = PAGE_SIZE,
  [c.PC.REC_XFER_ALIGN] = PAGE_SIZE,
  [c.PC.ALLOC_SIZE_MIN] = PAGE_SIZE,
  [c.PC.SYMLINK_MAX] = SYMLINK_MAX,
  [c.PC["2_SYMLINKS"]] = 1,
}

function S.pathconf(_, name)
  local pc = pathconf_values[c.PC[name]]
  if type(pc) == "function" then pc = pc() end
  return pc
end
S.fpathconf = S.pathconf

-- setegid and set euid are not syscalls
function S.seteuid(euid) return S.setresuid(-1, euid, -1) end
function S.setegid(egid) return S.setresgid(-1, egid, -1) end

-- in Linux sysctl is not a sycall any more (well it is but legacy)
-- note currently all returned as strings, may want to list which should be numbers
function S.sysctl(name, new)
  name = "/proc/sys/" .. name:gsub("%.", "/")
  local flag = c.O.RDONLY
  if new then flag = c.O.RDWR end
  local fd, err = S.open(name, flag)
  if not fd then return nil, err end
  local len = 1024
  local old, err = S.read(fd, nil, len)
  if not old then return nil, err end
  old = old:sub(1, #old - 1) -- remove trailing newline
  if not new then return old end
  local ok, err = S.write(fd, new)
  if not ok then return nil, err end
  return old
end

-- BPF syscall has a complex semantics with one union serving for all purposes
-- The interface exports both raw syscall and helper functions based on libbpf
if C.bpf then
  local function ptr_to_u64(p) return ffi.cast('uint64_t', ffi.cast('void *', p)) end
  function S.bpf(cmd, attr)
    return C.bpf(cmd, attr)
  end
  function S.bpf_prog_load(type, insns, len, license, version, log_level)
    if not license then license = "GPL" end          -- Must stay alive during the syscall
    local bpf_log_buf = ffi.new('char [?]', 64*1024) -- Must stay alive during the syscall
    if not version then
      -- We have no better way to extract current kernel hex-string other
      -- than parsing headers, compiling a helper function or reading /proc
      local ver_str, count = S.sysctl('kernel.osrelease'):match('%d+.%d+.%d+'), 2
      version = 0
      for i in ver_str:gmatch('%d+') do -- Convert 'X.Y.Z' to 0xXXYYZZ
        version = bit.bor(version, bit.lshift(tonumber(i), 8*count))
        count = count - 1
      end
    end
    local attr = t.bpf_attr1()
    attr[0].prog_type = type
    attr[0].insns = ptr_to_u64(insns)
    attr[0].insn_cnt = len
    attr[0].license = ptr_to_u64(license)
    attr[0].log_buf = ptr_to_u64(bpf_log_buf)
    attr[0].log_size = ffi.sizeof(bpf_log_buf)
    attr[0].log_level = log_level or 1
    attr[0].kern_version = version -- MUST match current kernel version
    local fd = S.bpf(c.BPF_CMD.PROG_LOAD, attr)
    if fd < 0 then
      return nil, t.error(errno()), ffi.string(bpf_log_buf)
    end
    return retfd(fd), ffi.string(bpf_log_buf)
  end
  function S.bpf_map_create(type, key_size, value_size, max_entries)
    local attr = t.bpf_attr1()
    attr[0].map_type = type
    attr[0].key_size = key_size
    attr[0].value_size = value_size
    attr[0].max_entries = max_entries
    local fd = S.bpf(c.BPF_CMD.MAP_CREATE, attr)
    if fd < 0 then
      return nil, t.error(errno())
    end
    return retfd(fd)
  end
  function S.bpf_map_op(op, fd, key, val_or_next, flags)
    local attr = t.bpf_attr1()
    attr[0].map_fd = fd
    attr[0].key = ptr_to_u64(key)
    attr[0].value = ptr_to_u64(val_or_next)
    attr[0].flags = flags or 0
    local ret = S.bpf(op, attr)
    if ret ~= 0 then
      return nil, t.error(errno())
    end
    return ret
  end
end

-- Linux performance monitoring
if C.perf_event_open then
  -- Open perf event fd
  -- @note see man 2 perf_event_open
  -- @return fd, err
  function S.perf_event_open(attr, pid, cpu, group_fd, flags)
    if attr[0].size == 0 then attr[0].size = ffi.sizeof(attr[0]) end
    local fd = C.perf_event_open(attr, pid or 0, cpu or -1, group_fd or -1, c.PERF_FLAG[flags or 0])
    if fd < 0 then
      return nil, t.error(errno())
    end
    return retfd(fd)
  end
  -- Read the tracepoint configuration (see "/sys/kernel/debug/tracing/available_events")
  -- @param event_path path to tracepoint (e.g. "/sys/kernel/debug/tracing/events/syscalls/sys_enter_write")
  -- @return tp, err (e.g. 538, nil)
  function S.perf_tracepoint(event_path)
    local config = nil
    event_path = event_path.."/id"
    local fd, err = S.open(event_path, c.O.RDONLY)
    if fd then
      local ret, err = fd:read(nil, 256)
      if ret then
        config = tonumber(ret)
      end
      fd:close()
    end
    return config, err
  end
  -- Attach or detach a probe, same semantics as Lua tables.
  -- See https://www.kernel.org/doc/Documentation/trace/kprobetrace.txt
  -- (When the definition is not nil, it will be created, otherwise it will be detached)
  -- @param probe_type either "kprobe" or "uprobe", no other probe types are supported
  -- @param name chosen probe name (e.g. "myprobe")
  -- @param definition (set to nil to disable probe) (e.g. "do_sys_open $retval")
  -- @param retval true/false if this should be entrypoint probe or return probe
  -- @return tp, err (e.g. 1099, nil)
  function S.perf_probe(probe_type, name, definition, retval)
    local event_path = string.format('/sys/kernel/debug/tracing/%s_events', probe_type)
    local probe_path = string.format('/sys/kernel/debug/tracing/events/%ss/%s', probe_type, name)
    -- Check if probe already exists
    if definition and S.statfs(probe_path) then return nil, t.error(c.E.EEXIST) end
    local fd, err = S.open(event_path, "wronly, append")
    if not fd then return nil, err end
    -- Format a probe definition
    if not definition then
      definition = "-:"..name -- Detach
    else
      definition = string.format("%s:%s %s", retval and "r" or "p", name, definition)
    end
    local ok, err = fd:write(definition)
    fd:close()
    -- Return tracepoint or success
    if ok and definition then
      return S.perf_tracepoint(probe_path)
    end
    return ok, err
  end
  -- Attach perf event reader to tracepoint (see "/sys/kernel/debug/tracing/available_events")
  -- @param tp tracepoint identifier (e.g.: 538, use `S.perf_tracepoint()`)
  -- @param type perf_attr.sample_type (default: "raw")
  -- @param attrs table of attributes (e.g. {sample_type="raw, callchain"}, see `struct perf_event_attr`)
  -- @return reader, err
  function S.perf_attach_tracepoint(tp, pid, cpu, group_fd, attrs)
    local pe = t.perf_event_attr1()
    pe[0].type = "tracepoint"
    pe[0].config = tp
    pe[0].sample_type = "raw"
    pe[0].sample_period = 1
    pe[0].wakeup_events = 1
    if attrs then
      for k,v in pairs(attrs) do pe[0][k] = v end
    end
    -- Open perf event reader with given parameters
    local fd, err = S.perf_event_open(pe, pid, cpu, group_fd, "fd_cloexec")
    if not fd then return nil, err end
    return t.perf_reader(fd)
  end
end

return S

end

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.x64.constants"],"module already exists")sources["syscall.linux.x64.constants"]=([===[-- <pack syscall.linux.x64.constants> --
-- x64 specific constants

local arch = {}

arch.REG = {
  R8         = 0,
  R9         = 1,
  R10        = 2,
  R11        = 3,
  R12        = 4,
  R13        = 5,
  R14        = 6,
  R15        = 7,
  RDI        = 8,
  RSI        = 9,
  RBP        = 10,
  RBX        = 11,
  RDX        = 12,
  RAX        = 13,
  RCX        = 14,
  RSP        = 15,
  RIP        = 16,
  EFL        = 17,
  CSGSFS     = 18,
  ERR        = 19,
  TRAPNO     = 20,
  OLDMASK    = 21,
  CR2        = 22,
}

return arch


]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ppc64le.ioctl"],"module already exists")sources["syscall.linux.ppc64le.ioctl"]=([===[-- <pack syscall.linux.ppc64le.ioctl> --
-- ppc ioctl differences

local arch = {
  IOC = {
    SIZEBITS  = 13,
    DIRBITS   = 3,
    NONE      = 1,
    READ      = 2,
    WRITE     = 4,
  },
  ioctl = function(_IO, _IOR, _IOW, _IORW)
    return {
      FIOCLEX	= _IO('f', 1),
      FIONCLEX	= _IO('f', 2),
      FIOQSIZE	= _IOR('f', 128, "off"),
      FIOASYNC	= _IOW('f', 125, "int"),
      TCGETS	= _IOR('t', 19, "termios"),
      TCSETS	= _IOW('t', 20, "termios"),
      TCSETSW	= _IOW('t', 21, "termios"),
      TCSETSF	= _IOW('t', 22, "termios"),
      TCSBRK	= _IO('t', 29),
      TCXONC	= _IO('t', 30),
      TCFLSH	= _IO('t', 31),
      TIOCSWINSZ = _IOW('t', 103, "winsize"),
      TIOCGWINSZ = _IOR('t', 104, "winsize"),
      TIOCOUTQ  = _IOR('t', 115, "int"),
      TIOCSPGRP	= _IOW('t', 118, "int"),
      TIOCGPGRP	= _IOR('t', 119, "int"),
      FIONBIO	= _IOW('f', 126, "int"),
      FIONREAD	= _IOR('f', 127, "int"),
    }
  end,
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.mips.ioctl"],"module already exists")sources["syscall.linux.mips.ioctl"]=([===[-- <pack syscall.linux.mips.ioctl> --
-- MIPS ioctl differences

local arch = {
  IOC = {
    SIZEBITS = 13,
    DIRBITS = 3,
    NONE = 1,
    READ = 2,
    WRITE = 4,
  },
  ioctl = function(_IO, _IOR, _IOW, _IORW)
    return {
      FIONREAD	     = 0x467f,
      TCSBRK	     = 0x5405,
      TCXONC	     = 0x5406,
      TCFLSH	     = 0x5407,
      TCGETS	     = {number = 0x540d, read = true, type = "termios"},
      TCSETS	     = 0x540e,
      TCSETSW	     = 0x540f,
      TCSETSF	     = 0x5410,
      TIOCPKT	     = 0x5470,
      TIOCNOTTY	     = 0x5471,
      TIOCSTI	     = 0x5472,
      TIOCSCTTY	     = 0x5480,
      TIOCGSOFTCAR   = 0x5481,
      TIOCSSOFTCAR   = 0x5482,
      TIOCLINUX	     = 0x5483,
      TIOCGSERIAL    = 0x5484,
      TIOCSSERIAL    = 0x5485,
      TCSBRKP	     = 0x5486,
      TIOCSERCONFIG  = 0x5488,
      TIOCSERGWILD   = 0x5489,
      TIOCSERSWILD   = 0x548a,
      TIOCGLCKTRMIOS = 0x548b,
      TIOCSLCKTRMIOS = 0x548c,
      TIOCSERGSTRUCT = 0x548d,
      TIOCSERGETLSR  = 0x548e,
      TIOCSERGETMULTI= 0x548f,
      TIOCSERSETMULTI= 0x5490,
      TIOCMIWAIT     = 0x5491,
      TIOCGICOUNT    = 0x5492,
      FIOCLEX	     = 0x6601,
      FIONCLEX	     = 0x6602,
      FIOASYNC	     = 0x667d,
      FIONBIO        = 0x667e,
      FIOQSIZE	     = 0x667f,
      TIOCGETD	     = 0x7400,
      TIOCSETD	     = 0x7401,
      TIOCEXCL	     = 0x740d,
      TIOCNXCL	     = 0x740e,
      TIOCGSID	     = 0x7416,
      TIOCMSET	     = 0x741a,
      TIOCMBIS	     = 0x741b,
      TIOCMBIC	     = 0x741c,
      TIOCMGET	     = 0x741d,
      TIOCOUTQ	     = 0x7472,
      FIOGETOWN      = _IOR('f', 123, "int"),
      FIOSETOWN      = _IOW('f', 124, "int"),
      SIOCATMARK     = _IOR('s', 7, "int"),
      SIOCSPGRP      = _IOW('s', 8, "pid"),
      SIOCGPGRP      = _IOR('s', 9, "pid"),
      TIOCSWINSZ     = _IOW('t', 103, "winsize"),
      TIOCGWINSZ     = _IOR('t', 104, "winsize"),
      TIOCSPGRP	     = _IOW('t', 118, "int"),
      TIOCGPGRP	     = _IOR('t', 119, "int"),
      TIOCCONS	     = _IOW('t', 120, "int"),
    }
  end,
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ioctl"],"module already exists")sources["syscall.linux.ioctl"]=([===[-- <pack syscall.linux.ioctl> --
-- ioctls, filling in as needed
-- note there are some architecture dependent values

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local function init(types)

local abi = require "syscall.abi"

local s, t = types.s, types.t

local strflag = require "syscall.helpers".strflag

local arch = require("syscall.linux." .. abi.arch .. ".ioctl")

local bit = require "syscall.bit"

local band = bit.band
local function bor(...)
  local r = bit.bor(...)
  if r < 0 then r = r + 4294967296 end -- TODO see note in NetBSD
  return r
end
local lshift = bit.lshift
local rshift = bit.rshift

-- these can vary by architecture
local IOC = arch.IOC or {
  SIZEBITS = 14,
  DIRBITS = 2,
  NONE = 0,
  WRITE = 1,
  READ = 2,
}

IOC.READWRITE = IOC.READ + IOC.WRITE

IOC.NRBITS	= 8
IOC.TYPEBITS	= 8

IOC.NRMASK	= lshift(1, IOC.NRBITS) - 1
IOC.TYPEMASK	= lshift(1, IOC.TYPEBITS) - 1
IOC.SIZEMASK	= lshift(1, IOC.SIZEBITS) - 1
IOC.DIRMASK	= lshift(1, IOC.DIRBITS) - 1

IOC.NRSHIFT   = 0
IOC.TYPESHIFT = IOC.NRSHIFT + IOC.NRBITS
IOC.SIZESHIFT = IOC.TYPESHIFT + IOC.TYPEBITS
IOC.DIRSHIFT  = IOC.SIZESHIFT + IOC.SIZEBITS

local function ioc(dir, ch, nr, size)
  if type(ch) == "string" then ch = ch:byte() end
  return bor(lshift(dir, IOC.DIRSHIFT), 
	     lshift(ch, IOC.TYPESHIFT), 
	     lshift(nr, IOC.NRSHIFT), 
	     lshift(size, IOC.SIZESHIFT))
end

local singletonmap = {
  int = "int1",
  char = "char1",
  uint = "uint1",
  uint32 = "uint32_1",
  uint64 = "uint64_1",
}

local function _IOC(dir, ch, nr, tp)
  if not tp or type(tp) == "number" then return ioc(dir, ch, nr, tp or 0) end
  local size = s[tp]
  local singleton = singletonmap[tp] ~= nil
  tp = singletonmap[tp] or tp
  return {number = ioc(dir, ch, nr, size),
          read = dir == IOC.READ or dir == IOC.READWRITE, write = dir == IOC.WRITE or dir == IOC.READWRITE,
          type = t[tp], singleton = singleton}
end

-- used to create numbers
local _IO    = function(ch, nr)		return _IOC(IOC.NONE, ch, nr, 0) end
local _IOR   = function(ch, nr, tp)	return _IOC(IOC.READ, ch, nr, tp) end
local _IOW   = function(ch, nr, tp)	return _IOC(IOC.WRITE, ch, nr, tp) end
local _IOWR  = function(ch, nr, tp)	return _IOC(IOC.READWRITE, ch, nr, tp) end

-- used to decode ioctl numbers..
local _IOC_DIR  = function(nr) return band(rshift(nr, IOC.DIRSHIFT), IOC.DIRMASK) end
local _IOC_TYPE = function(nr) return band(rshift(nr, IOC.TYPESHIFT), IOC.TYPEMASK) end
local _IOC_NR   = function(nr) return band(rshift(nr, IOC.NRSHIFT), IOC.NRMASK) end
local _IOC_SIZE = function(nr) return band(rshift(nr, IOC.SIZESHIFT), IOC.SIZEMASK) end

-- ...and for the drivers/sound files...

IOC.IN		= lshift(IOC.WRITE, IOC.DIRSHIFT)
IOC.OUT		= lshift(IOC.READ, IOC.DIRSHIFT)
IOC.INOUT		= lshift(bor(IOC.WRITE, IOC.READ), IOC.DIRSHIFT)
local IOCSIZE_MASK	= lshift(IOC.SIZEMASK, IOC.SIZESHIFT)
local IOCSIZE_SHIFT	= IOC.SIZESHIFT

-- VFIO driver writer decided not to use standard IOR/IOW alas
local function vfio(dir, nr, tp)
  local ch = ";"
  nr = nr + 100 -- vfio base
  dir = IOC[string.upper(dir)]
  local io = _IOC(dir, ch, nr, tp)
  if type(io) == "number" then return io end -- if just IO, not return
  io.number = ioc(IOC.NONE, ch, nr, 0) -- number encode nothing, but we want to know anyway
  return io
end

local ioctl = strflag {
-- termios, non standard values generally 0x54 = 'T'
  TCGETS          = {number = 0x5401, read = true, type = "termios"},
  TCSETS          = 0x5402,
  TCSETSW         = 0x5403,
  TCSETSF         = 0x5404,
  TCSBRK          = 0x5409, -- takes literal number
  TCXONC          = 0x540A,
  TCFLSH          = 0x540B, -- takes literal number
  TIOCEXCL        = 0x540C,
  TIOCNXCL        = 0x540D,
  TIOCSCTTY       = 0x540E,
  TIOCGPGRP       = 0x540F,
  TIOCSPGRP       = 0x5410,
  TIOCOUTQ        = 0x5411,
  TIOCSTI         = 0x5412,
  TIOCGWINSZ      = {number = 0x5413, read = true, type = "winsize"},
  TIOCSWINSZ      = {number = 0x5414, write = true, type = "winsize"},
  TIOCMGET        = 0x5415,
  TIOCMBIS        = 0x5416,
  TIOCMBIC        = 0x5417,
  TIOCMSET        = 0x5418,
  TIOCGSOFTCAR    = 0x5419,
  TIOCSSOFTCAR    = 0x541A,
  FIONREAD        = 0x541B,
  TIOCLINUX       = 0x541C,
  TIOCCONS        = 0x541D,
  TIOCGSERIAL     = 0x541E,
  TIOCSSERIAL     = 0x541F,
  TIOCPKT         = 0x5420,
  FIONBIO         = 0x5421,
  TIOCNOTTY       = 0x5422,
  TIOCSETD        = 0x5423,
  TIOCGETD        = 0x5424,
  TCSBRKP         = 0x5425,
  TIOCSBRK        = 0x5427,
  TIOCCBRK        = 0x5428,
  TIOCGSID        = 0x5429,
  TCGETS2         = _IOR('T', 0x2A, "termios2"),
  TCSETS2         = _IOW('T', 0x2B, "termios2"),
  TCSETSW2        = _IOW('T', 0x2C, "termios2"),
  TCSETSF2        = _IOW('T', 0x2D, "termios2"),
  TIOCGPTN        = _IOR('T', 0x30, "uint"),
  TIOCSPTLCK      = _IOW('T', 0x31, "int"),
  TIOCGDEV        = _IOR('T', 0x32, "uint"),
  TCGETX          = 0x5432,
  TCSETX          = 0x5433,
  TCSETXF         = 0x5434,
  TCSETXW         = 0x5435,
  TIOCSIG         = _IOW('T', 0x36, "int"),
  TIOCVHANGUP     = 0x5437,
  FIONCLEX        = 0x5450,
  FIOCLEX         = 0x5451,
  FIOASYNC        = 0x5452,
  TIOCSERCONFIG   = 0x5453,
  TIOCSERGWILD    = 0x5454,
  TIOCSERSWILD    = 0x5455,
  TIOCGLCKTRMIOS  = 0x5456,
  TIOCSLCKTRMIOS  = 0x5457,
  TIOCSERGSTRUCT  = 0x5458,
  TIOCSERGETLSR   = 0x5459,
  TIOCSERGETMULTI = 0x545A,
  TIOCSERSETMULTI = 0x545B,
  TIOCMIWAIT      = 0x545C,
  TIOCGICOUNT     = 0x545D,
  FIOQSIZE        = 0x5460,
-- socket ioctls from linux/sockios.h - for many of these you can use netlink instead
  FIOSETOWN       = 0x8901,
  SIOCSPGRP       = 0x8902,
  FIOGETOWN       = 0x8903,
  SIOCGPGRP       = 0x8904,
  SIOCATMARK      = 0x8905,
  SIOCGSTAMP      = 0x8906,
  SIOCGSTAMPNS    = 0x8907,

  SIOCADDRT       = 0x890B,
  SIOCDELRT       = 0x890C,
  SIOCRTMSG       = 0x890D,

  SIOCGIFINDEX    = 0x8933,

  SIOCDARP        = 0x8953,
  SIOCGARP        = 0x8954,
  SIOCSARP        = 0x8955,

  SIOCBRADDBR     = 0x89a0,
  SIOCBRDELBR     = 0x89a1,
  SIOCBRADDIF     = 0x89a2,
  SIOCBRDELIF     = 0x89a3,
-- event system
  EVIOCGVERSION   = _IOR('E', 0x01, "int"),
  EVIOCGID        = _IOR('E', 0x02, "input_id"),
  EVIOCGREP       = _IOR('E', 0x03, "uint2"),
  EVIOCSREP       = _IOW('E', 0x03, "uint2"),
  EVIOCGKEYCODE   = _IOR('E', 0x04, "uint2"),
  EVIOCGKEYCODE_V2 = _IOR('E', 0x04, "input_keymap_entry"),
  EVIOCSKEYCODE   = _IOW('E', 0x04, "uint2"),
  EVIOCSKEYCODE_V2 = _IOW('E', 0x04, "input_keymap_entry"),
  EVIOCGNAME = function(len) return _IOC(IOC.READ, 'E', 0x06, len) end,
  EVIOCGPHYS = function(len) return _IOC(IOC.READ, 'E', 0x07, len) end,
  EVIOCGUNIQ = function(len) return _IOC(IOC.READ, 'E', 0x08, len) end,
  EVIOCGPROP = function(len) return _IOC(IOC.READ, 'E', 0x09, len) end,
  EVIOCGKEY  = function(len) return _IOC(IOC.READ, 'E', 0x18, len) end,
  EVIOCGLED  = function(len) return _IOC(IOC.READ, 'E', 0x19, len) end,
  EVIOCGSND  = function(len) return _IOC(IOC.READ, 'E', 0x1a, len) end,
  EVIOCGSW   = function(len) return _IOC(IOC.READ, 'E', 0x1b, len) end,
  EVIOCGBIT  = function(ev, len) return _IOC(IOC.READ, 'E', 0x20 + ev, len) end,
  EVIOCGABS  = function(abs) return _IOR('E', 0x40 + abs, "input_absinfo") end,
  EVIOCSABS  = function(abs) return _IOW('E', 0xc0 + abs, "input_absinfo") end,
  EVIOCSFF   = _IOC(IOC.WRITE, 'E', 0x80, "ff_effect"),
  EVIOCRMFF  = _IOW('E', 0x81, "int"),
  EVIOCGEFFECTS = _IOR('E', 0x84, "int"),
  EVIOCGRAB  = _IOW('E', 0x90, "int"),
-- input devices
  UI_DEV_CREATE  = _IO ('U', 1),
  UI_DEV_DESTROY = _IO ('U', 2),
  UI_SET_EVBIT   = _IOW('U', 100, "int"),
  UI_SET_KEYBIT  = _IOW('U', 101, "int"),
-- tun/tap
  TUNSETNOCSUM   = _IOW('T', 200, "int"),
  TUNSETDEBUG    = _IOW('T', 201, "int"),
  TUNSETIFF      = _IOW('T', 202, "int"),
  TUNSETPERSIST  = _IOW('T', 203, "int"),
  TUNSETOWNER    = _IOW('T', 204, "int"),
  TUNSETLINK     = _IOW('T', 205, "int"),
  TUNSETGROUP    = _IOW('T', 206, "int"),
  TUNGETFEATURES = _IOR('T', 207, "uint"),
  TUNSETOFFLOAD  = _IOW('T', 208, "uint"),
  TUNSETTXFILTER = _IOW('T', 209, "uint"),
  TUNGETIFF      = _IOR('T', 210, "uint"),
  TUNGETSNDBUF   = _IOR('T', 211, "int"),
  TUNSETSNDBUF   = _IOW('T', 212, "int"),
  TUNATTACHFILTER= _IOW('T', 213, "sock_fprog"),
  TUNDETACHFILTER= _IOW('T', 214, "sock_fprog"),
  TUNGETVNETHDRSZ= _IOR('T', 215, "int"),
  TUNSETVNETHDRSZ= _IOW('T', 216, "int"),
  TUNSETQUEUE    = _IOW('T', 217, "int"),
-- from linux/vhost.h VHOST_VIRTIO 0xAF
  VHOST_GET_FEATURES   = _IOR(0xAF, 0x00, "uint64"),
  VHOST_SET_FEATURES   = _IOW(0xAF, 0x00, "uint64"),
  VHOST_SET_OWNER      = _IO(0xAF, 0x01),
  VHOST_RESET_OWNER    = _IO(0xAF, 0x02),
  VHOST_SET_MEM_TABLE  = _IOW(0xAF, 0x03, "vhost_memory"),
  VHOST_SET_LOG_BASE   = _IOW(0xAF, 0x04, "uint64"),
  VHOST_SET_LOG_FD     = _IOW(0xAF, 0x07, "int"),
  VHOST_SET_VRING_NUM  = _IOW(0xAF, 0x10, "vhost_vring_state"),
  VHOST_SET_VRING_ADDR = _IOW(0xAF, 0x11, "vhost_vring_addr"),
  VHOST_SET_VRING_BASE = _IOW(0xAF, 0x12, "vhost_vring_state"),
  VHOST_GET_VRING_BASE = _IOWR(0xAF, 0x12, "vhost_vring_state"),
  VHOST_SET_VRING_KICK = _IOW(0xAF, 0x20, "vhost_vring_file"),
  VHOST_SET_VRING_CALL = _IOW(0xAF, 0x21, "vhost_vring_file"),
  VHOST_SET_VRING_ERR  = _IOW(0xAF, 0x22, "vhost_vring_file"),
  VHOST_NET_SET_BACKEND= _IOW(0xAF, 0x30, "vhost_vring_file"),
-- from linux/vfio.h type is ';' base is 100
  VFIO_GET_API_VERSION = vfio('NONE', 0),
  VFIO_CHECK_EXTENSION = vfio('WRITE', 1, "uint32"),
-- from linux/perf_event.h
  PERF_EVENT_IOC_ENABLE    = _IO('$', 0),
  PERF_EVENT_IOC_DISABLE   = _IO('$', 1),
  PERF_EVENT_IOC_REFRESH   = _IO('$', 2),
  PERF_EVENT_IOC_RESET     = _IO('$', 3),
  PERF_EVENT_IOC_PERIOD    = _IOW('$', 4, "uint64"),
  PERF_EVENT_IOC_SET_OUTPUT= _IO('$', 5),
  PERF_EVENT_IOC_SET_FILTER= _IOW('$', 6, "uintptr"),
  PERF_EVENT_IOC_ID        = _IOR('$', 7, "uint64_1"),
  PERF_EVENT_IOC_SET_BPF   = _IOW('$', 8, "uint32"),

-- allow user defined ioctls
  _IO = _IO,
  _IOR = _IOR, 
  _IOW = _IOW,
  _IOWR = _IOWR,
}

local override = arch.ioctl or {}
if type(override) == "function" then override = override(_IO, _IOR, _IOW, _IOWR) end
for k, v in pairs(override) do ioctl[k] = v end

-- allow names for types in table ioctls
for k, v in pairs(ioctl) do if type(v) == "table" and type(v.type) == "string" then v.type = t[v.type] end end

-- alternate names
ioctl.TIOCINQ = ioctl.FIONREAD

return ioctl

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.arm64.ioctl"],"module already exists")sources["syscall.linux.arm64.ioctl"]=([===[-- <pack syscall.linux.arm64.ioctl> --
-- arm64 ioctl differences

local arch = {
  ioctl = {
  }
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ppc64le.ffi"],"module already exists")sources["syscall.linux.ppc64le.ffi"]=([===[-- <pack syscall.linux.ppc64le.ffi> --
-- ppc specific definitions

return {
  termios = [[
struct termios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_cc[19];
  cc_t c_line;
  speed_t c_ispeed;
  speed_t c_ospeed;
};
]],
  ucontext = [[
typedef unsigned long greg_t, gregset_t[48];
typedef struct {
  double fpregs[32];
  double fpscr;
  unsigned _pad[2];
} fpregset_t;
typedef struct {
  unsigned vrregs[32][4];
  unsigned vrsave;
  unsigned _pad[2];
  unsigned vscr;
} vrregset_t;
typedef struct {
  gregset_t gregs;
  fpregset_t fpregs;
  vrregset_t vrregs __attribute__((__aligned__(16)));
} mcontext_t;
typedef struct ucontext {
  unsigned long int uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  sigset_t uc_sigmask;
  mcontext_t uc_mcontext;
} ucontext_t;
]],
  stat = [[
struct stat {
  unsigned long   st_dev;
  unsigned long   st_ino;
  unsigned long   st_nlink;
  unsigned int    st_mode;
  unsigned int    st_uid;
  unsigned int    st_gid;
  unsigned int    __pad0;
  unsigned long   st_rdev;
  long            st_size;
  long            st_blksize;
  long            st_blocks;
  unsigned long   st_atime;
  unsigned long   st_atime_nsec;
  unsigned long   st_mtime;
  unsigned long   st_mtime_nsec;
  unsigned long   st_ctime;
  unsigned long   st_ctime_nsec;
  long            __unused[3];
};
]],
}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.helpers"],"module already exists")sources["syscall.helpers"]=([===[-- <pack syscall.helpers> --
-- misc helper functions that we use across the board

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string, math = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string, math

local debug, collectgarbage = require "debug", collectgarbage

local abi = require "syscall.abi"

local ffi = require "ffi"
local bit = require "syscall.bit"

local h = {}

-- generic assert helper, mainly for tests
function h.assert(cond, err, ...)
  if not cond then
    error(tostring(err or "unspecified error")) -- annoyingly, assert does not call tostring!
  end
  collectgarbage("collect") -- force gc, to test for bugs
  if type(cond) == "function" then return cond, err, ... end
  if cond == true then return ... end
  return cond, ...
end

local voidp = ffi.typeof("void *")

local function ptvoid(x)
  return ffi.cast(voidp, x)
end

local function ptt(tp)
  local ptp = ffi.typeof(tp .. " *")
  return function(x) return ffi.cast(ptp, x) end
end
h.ptt = ptt

-- constants
h.uint64_max = ffi.cast("uint64_t", 0) - ffi.cast("uint64_t", 1)
h.err64 = ffi.cast("int64_t", -1)
if abi.abi64 then h.errpointer = ptvoid(h.err64) else h.errpointer = ptvoid(0xffffffff) end
h.uint32_max = ffi.cast("uint32_t", 0xffffffff)
h.int32_max = 0x7fffffff
if abi.abi64 then h.longmax = bit.rshift64(h.err64, 1) else h.longmax = h.int32_max end

-- generic iterator that counts down so needs no closure to hold state
function h.reviter(array, i)
  i = i - 1
  if i >= 0 then return i, array[i] end
end

function h.mktype(tp, x) if ffi.istype(tp, x) then return x else return tp(x) end end
function h.istype(tp, x) if ffi.istype(tp, x) then return x else return false end end

local function lenfn(tp) return ffi.sizeof(tp) end
h.lenfn = lenfn
h.lenmt = {__len = lenfn}

local tint = ffi.typeof("int")
local function getfd(fd)
  if type(fd) == "number" or ffi.istype(tint, fd) then return fd end
  return fd:getfd()
end
h.getfd = getfd

-- generic function for __new
function h.newfn(tp, tab)
  local obj = ffi.new(tp)
  if not tab then return obj end
  -- these are split out so __newindex is called, not just initialisers luajit understands
  for k, v in pairs(tab) do if type(k) == "string" then obj[k] = v end end -- set string indexes
  return obj
end

-- generic function for __tostring
local function simpleprint(pt, x)
  local out = {}
  for _, v in ipairs(pt) do out[#out + 1] = v .. " = " .. tostring(x[v]) end
  return "{ " .. table.concat(out, ", ") .. " }"
end

-- type initialisation helpers
function h.addtype(types, name, tp, mt)
  if abi.rumpfn then tp = abi.rumpfn(tp) end
  if mt then
    if mt.index and not mt.__index then -- generic index method
      local index = mt.index
      mt.index = nil
      mt.__index = function(tp, k) if index[k] then return index[k](tp) else error("invalid index " .. k) end end
    end
    if mt.newindex and not mt.__newindex then -- generic newindex method
      local newindex = mt.newindex
      mt.newindex = nil
      mt.__newindex = function(tp, k, v) if newindex[k] then newindex[k](tp, v) else error("invalid index " .. k) end end
    end
    if not mt.__len then mt.__len = lenfn end -- default length function is just sizeof
    if not mt.__tostring and mt.print then mt.__tostring = function(x) return simpleprint(mt.print, x) end end
    types.t[name] = ffi.metatype(tp, mt)
  else
    types.t[name] = ffi.typeof(tp)
  end
  types.ctypes[tp] = types.t[name]
  types.pt[name] = ptt(tp)
  types.s[name] = ffi.sizeof(types.t[name])
end

-- for variables length types, ie those with arrays
function h.addtype_var(types, name, tp, mt)
  if abi.rumpfn then tp = abi.rumpfn(tp) end
  if not mt.__len then mt.__len = lenfn end -- default length function is just sizeof, gives instance size for var lngth
  types.t[name] = ffi.metatype(tp, mt)
  types.pt[name] = ptt(tp)
end

function h.addtype_fn(types, name, tp)
  if abi.rumpfn then tp = abi.rumpfn(tp) end
  types.t[name] = ffi.typeof(tp)
  types.s[name] = ffi.sizeof(types.t[name])
end

function h.addraw2(types, name, tp)
  if abi.rumpfn then tp = abi.rumpfn(tp) end
  types.t[name] = ffi.typeof(tp .. "[2]")
end

function h.addtype1(types, name, tp)
  types.t[name] = ffi.typeof(tp .. "[1]")
  types.s[name] = ffi.sizeof(types.t[name])
end

function h.addtype2(types, name, tp)
  types.t[name] = ffi.typeof(tp .. "[2]")
  types.s[name] = ffi.sizeof(types.t[name])
end

function h.addptrtype(types, name, tp)
  local ptr = ffi.typeof(tp)
  types.t[name] = function(v) return ffi.cast(ptr, v) end
  types.s[name] = ffi.sizeof(ptr)
end

-- endian conversion
-- TODO add tests eg for signs.
if abi.be then -- nothing to do
  function h.htonl(b) return b end
  function h.htons(b) return b end
  function h.convle32(b) return bit.bswap(b) end -- used by file system capabilities, always stored as le
else
  function h.htonl(b) return bit.bswap(b) end
  function h.htons(b) return bit.rshift(bit.bswap(b), 16) end
  function h.convle32(b) return b end -- used by file system capabilities, always stored as le
end
h.ntohl = h.htonl -- reverse is the same
h.ntohs = h.htons -- reverse is the same

function h.octal(s) return tonumber(s, 8) end
local octal = h.octal

function h.split(delimiter, text)
  if delimiter == "" then return {text} end
  if #text == 0 then return {} end
  local list = {}
  local pos = 1
  while true do
    local first, last = text:find(delimiter, pos)
    if first then
      list[#list + 1] = text:sub(pos, first - 1)
      pos = last + 1
    else
      list[#list + 1] = text:sub(pos)
      break
    end
  end
  return list
end

function h.trim(s) -- TODO should replace underscore with space
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local split, trim = h.split, h.trim

-- for AT_FDCWD
function h.atflag(tab)
  local function flag(cache, str)
    if not str then return tab.FDCWD end
    if type(str) == "number" then return str end
    if type(str) ~= "string" then return getfd(str) end
    if #str == 0 then return 0 end
    local s = trim(str):upper()
    if #s == 0 then return 0 end
    local val = rawget(tab, s)
    if not val then error("invalid flag " .. s) end
    cache[str] = val
    return val
  end
  return setmetatable(tab, {__index = setmetatable({}, {__index = flag}), __call = function(t, a) return t[a] end})
end

-- for single valued flags
function h.strflag(tab)
  local function flag(cache, str)
    if type(str) ~= "string" then return str end
    if #str == 0 then return 0 end
    local s = trim(str):upper()
    if #s == 0 then return 0 end
    local val = rawget(tab, s)
    if not val then return nil end
    cache[str] = val
    return val
  end
  return setmetatable(tab, {__index = setmetatable({}, {__index = flag}), __call = function(t, a) return t[a] end})
end

-- take a bunch of flags in a string and return a number
-- allows multiple comma sep flags that are ORed
function h.multiflags(tab)
  local function flag(cache, str)
    if not str then return 0 end
    if type(str) ~= "string" then return str end
    if #str == 0 then return 0 end
    local f = 0
    local a = split(",", str)
    if #a == 1 and str == str:upper() then return nil end -- this is to allow testing for presense, while catching errors
    for _, v in ipairs(a) do
      local s = trim(v):upper()
      if #s == 0 then error("empty flag") end
      local val = rawget(tab, s)
      if not val then error("invalid flag " .. s) end
      f = bit.bor(f, val)
    end
    cache[str] = f
    return f
  end
  return setmetatable(tab, {
    __index = setmetatable({}, {__index = flag}),
    __call = function(tab, x, ...) -- this allows easily adding or removing a flag
      local a = tab[x]
      for _, v in ipairs{...} do
        if type(v) == "string" and v:find("~") then -- allow negation eg c.IFF(old, "~UP")
          local sa = split(",", v)
          for _, vv in ipairs(sa) do
            local s = trim(vv):upper()
            if #s == 0 then error("empty flag") end
            local negate = false
            if s:sub(1, 1) == "~" then
              negate = true
              s = trim(s:sub(2))
              if #s == 0 then error("empty flag") end
            end
            local val = rawget(tab, s)
            if not val then error("invalid flag " .. s) end
            if negate then a = bit.band(a, bit.bnot(val)) else a = bit.bor(a, val) end
          end
        else
          a = bit.bor(a, tab[v])
        end
      end
      return a
    end,
  })
end

-- like multiflags but also allow octal values in string
function h.modeflags(tab)
  local function flag(cache, str)
    if not str then return 0 end
    if type(str) ~= "string" then return str end
    if #str == 0 then return 0 end
    local f = 0
    local a = split(",", str)
    if #a == 1 and str == str:upper() and str:sub(1,1) ~= "0" then return nil end -- this is to allow testing for presense, while catching errors
    for i, v in ipairs(a) do
      local s = trim(v):upper()
      if #s == 0 then error("empty flag") end
      local val
      if s:sub(1, 1) == "0" then
        val = octal(s)
      else
        val = rawget(tab, s)
        if not val then error("invalid flag " .. s) end
      end
      f = bit.bor(f, val)
    end
    cache[str] = f
    return f
  end
  return setmetatable(tab, {__index = setmetatable({}, {__index = flag}), __call = function(t, a) return t[a] end})
end

function h.swapflags(tab)
  local function flag(cache, str)
    if not str then return 0 end
    if type(str) ~= "string" then return str end
    if #str == 0 then return 0 end
    local f = 0
    local a = split(",", str)
    if #a == 1 and str == str:upper() then return nil end -- this is to allow testing for presense, while catching errors
    for i, v in ipairs(a) do
      local s = trim(v):upper()
      if #s == 0 then error("empty flag") end
      if tonumber(s) then
        local val = tonumber(s)
        f = bit.bor(f, rawget(tab, "PREFER"), bit.lshift(bit.band(rawget(tab, "PRIO_MASK"), val), rawget(tab, "PRIO_SHIFT")))
      else
        local val = rawget(tab, s)
        if not val then error("invalid flag " .. s) end
        f = bit.bor(f, val)
      end
    end
    cache[str] = f
    return f
  end
  return setmetatable(tab, {__index = setmetatable({}, {__index = flag}), __call = function(t, a) return t[a] end})
end

-- single char flags, eg used for access which allows "rwx"
function h.charflags(tab)
  local function flag(cache, str)
    if not str then return 0 end
    if type(str) ~= "string" then return str end
    str = trim(str:upper())
    local flag = 0
    for i = 1, #str do
      local c = str:sub(i, i)
      local val = rawget(tab, c)
      if not val then error("invalid flag " .. c) end
      flag = bit.bor(flag, val)
    end
    cache[str] = flag
    return flag
  end
  return setmetatable(tab, {__index = setmetatable({}, {__index = flag}), __call = function(t, a) return t[a] end})
end

h.divmod = function(a, b)
  return math.floor(a / b), a % b
end

h.booltoc = setmetatable({
  [0] = 0,
  [1] = 1,
  [false] = 0,
  [true] = 1,
}, {__call = function(tb, arg) return tb[arg or 0] end}) -- allow nil as false

function h.ctobool(i) return tonumber(i) ~= 0 end

local function align(len, a) return bit.band(tonumber(len) + a - 1, bit.bnot(a - 1)) end
h.align = align

return h

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.abi"],"module already exists")sources["syscall.abi"]=([===[-- <pack syscall.abi> --
-- This simply returns ABI information
-- Makes it easier to substitute for non-ffi solution, eg to run tests

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

do
	local ok,err = pcall(require, "ffi")
	if not ok then
		error("ffi seems not available. Do you use luajit ?\n"..err)
	end
end
local ffi = require "ffi"

local function inlibc_fn(k) return ffi.C[k] end

local abi = {
  arch = ffi.arch, -- ppc, x86, arm, x64, mips
  abi32 = ffi.abi("32bit"), -- boolean
  abi64 = ffi.abi("64bit"), -- boolean
  le = ffi.abi("le"), -- boolean
  be = ffi.abi("be"), -- boolean
  os = ffi.os:lower(), -- bsd, osx, linux
}

-- Makes no difference to us I believe
if abi.arch == "ppcspe" then abi.arch = "ppc" end

if abi.arch == "arm" and not ffi.abi("eabi") then error("only support eabi for arm") end

if (abi.arch == "mips" or abi.arch == "mipsel") then abi.mipsabi = "o32" end -- only one supported now

if abi.os == "bsd" or abi.os == "osx" then abi.bsd = true end -- some shared BSD functionality

-- Xen generally behaves like NetBSD, but our tests need to do rump-like setup; bit of a hack
ffi.cdef[[
  int __ljsyscall_under_xen;
]]
if pcall(inlibc_fn, "__ljsyscall_under_xen") then abi.xen = true end

-- BSD detection
-- OpenBSD doesn't have sysctlbyname
-- The good news is every BSD has utsname
-- The bad news is that on FreeBSD it is a legacy version that has 32 byte unless you use __xuname
-- fortunately sysname is first so we can use this value
if not abi.xen and not abi.rump and abi.os == "bsd" then
  ffi.cdef [[
  struct _utsname {
  char    sysname[256];
  char    nodename[256];
  char    release[256];
  char    version[256];
  char    machine[256];
  };
  int uname(struct _utsname *);
  ]]
  local uname = ffi.new("struct _utsname")
  ffi.C.uname(uname)
  abi.os = ffi.string(uname.sysname):lower()
  abi.uname = uname
end

-- rump params
abi.host = abi.os -- real OS, used for rump at present may change this
abi.types = "netbsd" -- you can set to linux, or monkeypatch (see tests) to use Linux types

return abi
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ppc64le.constants"],"module already exists")sources["syscall.linux.ppc64le.constants"]=([===[-- <pack syscall.linux.ppc64le.constants> --
-- ppc specific constants

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local h = require "syscall.helpers"

local octal = h.octal

local arch = {}

arch.EDEADLOCK = 58 -- only error that differs from generic

arch.SO = { -- 16-21 differ for ppc
  DEBUG       = 1,
  REUSEADDR   = 2,
  TYPE        = 3,
  ERROR       = 4,
  DONTROUTE   = 5,
  BROADCAST   = 6,
  SNDBUF      = 7,
  RCVBUF      = 8,
  KEEPALIVE   = 9,
  OOBINLINE   = 10,
  NO_CHECK    = 11,
  PRIORITY    = 12,
  LINGER      = 13,
  BSDCOMPAT   = 14,
--REUSEPORT   = 15, -- new, may not be defined yet
  RCVLOWAT    = 16,
  SNDLOWAT    = 17,
  RCVTIMEO    = 18,
  SNDTIMEO    = 19,
  PASSCRED    = 20,
  PEERCRED    = 21,
  SECURITY_AUTHENTICATION = 22,
  SECURITY_ENCRYPTION_TRANSPORT = 23,
  SECURITY_ENCRYPTION_NETWORK = 24,
  BINDTODEVICE       = 25,
  ATTACH_FILTER      = 26,
  DETACH_FILTER      = 27,
  PEERNAME           = 28,
  TIMESTAMP          = 29,
  ACCEPTCONN         = 30,
  PEERSEC            = 31,
  SNDBUFFORCE        = 32,
  RCVBUFFORCE        = 33,
  PASSSEC            = 34,
  TIMESTAMPNS        = 35,
  MARK               = 36,
  TIMESTAMPING       = 37,
  PROTOCOL           = 38,
  DOMAIN             = 39,
  RXQ_OVFL           = 40,
  WIFI_STATUS        = 41,
  PEEK_OFF           = 42,
  NOFCS              = 43,
}

arch.OFLAG = {
  OPOST  = octal('00000001'),
  ONLCR  = octal('00000002'),
  OLCUC  = octal('00000004'),
  OCRNL  = octal('00000010'),
  ONOCR  = octal('00000020'),
  ONLRET = octal('00000040'),
  OFILL  = octal('00000100'),
  OFDEL  = octal('00000200'),
  NLDLY  = octal('00001400'),
  NL0    = octal('00000000'),
  NL1    = octal('00000400'),
  NL2    = octal('00001000'),
  NL3    = octal('00001400'),
  CRDLY  = octal('00030000'),
  CR0    = octal('00000000'),
  CR1    = octal('00010000'),
  CR2    = octal('00020000'),
  CR3    = octal('00030000'),
  TABDLY = octal('00006000'),
  TAB0   = octal('00000000'),
  TAB1   = octal('00002000'),
  TAB2   = octal('00004000'),
  TAB3   = octal('00006000'),
  BSDLY  = octal('00100000'),
  BS0    = octal('00000000'),
  BS1    = octal('00100000'),
  FFDLY  = octal('00040000'),
  FF0    = octal('00000000'),
  FF1    = octal('00040000'),
  VTDLY  = octal('00200000'),
  VT0    = octal('00000000'),
  VT1    = octal('00200000'),
  XTABS  = octal('00006000'),
}

arch.LFLAG = {
  ISIG    = 0x00000080,
  ICANON  = 0x00000100,
  XCASE   = 0x00004000,
  ECHO    = 0x00000008,
  ECHOE   = 0x00000002,
  ECHOK   = 0x00000004,
  ECHONL  = 0x00000010,
  NOFLSH  = 0x80000000,
  TOSTOP  = 0x00400000,
  ECHOCTL = 0x00000040,
  ECHOPRT = 0x00000020,
  ECHOKE  = 0x00000001,
  FLUSHO  = 0x00800000,
  PENDIN  = 0x20000000,
  IEXTEN  = 0x00000400,
  EXTPROC = 0x10000000,
}

-- TODO these will be in a table
arch.CBAUD      = octal('0000377')
arch.CBAUDEX    = octal('0000000')
arch.CIBAUD     = octal('077600000')

arch.CFLAG = {
  CSIZE      = octal('00001400'),
  CS5        = octal('00000000'),
  CS6        = octal('00000400'),
  CS7        = octal('00001000'),
  CS8        = octal('00001400'),
  CSTOPB     = octal('00002000'),
  CREAD      = octal('00004000'),
  PARENB     = octal('00010000'),
  PARODD     = octal('00020000'),
  HUPCL      = octal('00040000'),
  CLOCAL     = octal('00100000'),
}

arch.IFLAG = {
  IGNBRK  = octal('0000001'),
  BRKINT  = octal('0000002'),
  IGNPAR  = octal('0000004'),
  PARMRK  = octal('0000010'),
  INPCK   = octal('0000020'),
  ISTRIP  = octal('0000040'),
  INLCR   = octal('0000100'),
  IGNCR   = octal('0000200'),
  ICRNL   = octal('0000400'),
  IXON    = octal('0001000'),
  IXOFF   = octal('0002000'),
  IXANY   = octal('0004000'),
  IUCLC   = octal('0010000'),
  IMAXBEL = octal('0020000'),
  IUTF8   = octal('0040000'),
}

arch.CC = {
  VINTR           = 0,
  VQUIT           = 1,
  VERASE          = 2,
  VKILL           = 3,
  VEOF            = 4,
  VMIN            = 5,
  VEOL            = 6,
  VTIME           = 7,
  VEOL2           = 8,
  VSWTC           = 9,
  VWERASE         = 10,
  VREPRINT        = 11,
  VSUSP           = 12,
  VSTART          = 13,
  VSTOP           = 14,
  VLNEXT          = 15,
  VDISCARD        = 16,
}

arch.B = {
  ['0'] = octal('0000000'),
  ['50'] = octal('0000001'),
  ['75'] = octal('0000002'),
  ['110'] = octal('0000003'),
  ['134'] = octal('0000004'),
  ['150'] = octal('0000005'),
  ['200'] = octal('0000006'),
  ['300'] = octal('0000007'),
  ['600'] = octal('0000010'),
  ['1200'] = octal('0000011'),
  ['1800'] = octal('0000012'),
  ['2400'] = octal('0000013'),
  ['4800'] = octal('0000014'),
  ['9600'] = octal('0000015'),
  ['19200'] = octal('0000016'),
  ['38400'] = octal('0000017'),
  ['57600'] = octal('00020'),
  ['115200'] = octal('00021'),
  ['230400'] = octal('00022'),
  ['460800'] = octal('00023'),
  ['500000'] = octal('00024'),
  ['576000'] = octal('00025'),
  ['921600'] = octal('00026'),
  ['1000000'] = octal('00027'),
  ['1152000'] = octal('00030'),
  ['1500000'] = octal('00031'),
  ['2000000'] = octal('00032'),
  ['2500000'] = octal('00033'),
  ['3000000'] = octal('00034'),
  ['3500000'] = octal('00035'),
  ['4000000'] = octal('00036'),
}

arch.O = {
  RDONLY    = octal('0000'),
  WRONLY    = octal('0001'),
  RDWR      = octal('0002'),
  ACCMODE   = octal('0003'),
  CREAT     = octal('0100'),
  EXCL      = octal('0200'),
  NOCTTY    = octal('0400'),
  TRUNC     = octal('01000'),
  APPEND    = octal('02000'),
  NONBLOCK  = octal('04000'),
  DSYNC     = octal('010000'),
  ASYNC     = octal('020000'),
  DIRECTORY = octal('040000'),
  NOFOLLOW  = octal('0100000'),
  LARGEFILE = octal('0200000'),
  DIRECT    = octal('0400000'),
  NOATIME   = octal('01000000'),
  CLOEXEC   = octal('02000000'),
  SYNC      = octal('04010000'),
}

arch.MAP = {
  FILE       = 0,
  SHARED     = 0x01,
  PRIVATE    = 0x02,
  TYPE       = 0x0f,
  FIXED      = 0x10,
  ANONYMOUS  = 0x20,
  NORESERVE  = 0x40,
  LOCKED     = 0x80,
  GROWSDOWN  = 0x00100,
  DENYWRITE  = 0x00800,
  EXECUTABLE = 0x01000,
  POPULATE   = 0x08000,
  NONBLOCK   = 0x10000,
  STACK      = 0x20000,
  HUGETLB    = 0x40000,
}

arch.MCL = {
  CURRENT    = 0x2000,
  FUTURE     = 0x4000,
}

arch.PROT = {
  SAO       = 0x10, -- Strong Access Ordering
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.ffitypes"],"module already exists")sources["syscall.ffitypes"]=([===[-- <pack syscall.ffitypes> --
-- these are types which are currently the same for all ports
-- in a module so rump does not import twice
-- note that even if type is same (like pollfd) if the metatype is different cannot be here due to ffi

-- TODO not sure we want these long term, merge to individual OS files.

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local ffi = require "ffi"

local abi = require "syscall.abi"

local defs = {}

local function append(str) defs[#defs + 1] = str end

append [[
// 8 bit
typedef unsigned char cc_t;

// 16 bit
typedef uint16_t in_port_t;

// 32 bit
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef int32_t pid_t;

typedef unsigned int socklen_t;

// 64 bit
typedef int64_t off_t;

// defined as long even though eg NetBSD defines as int on 32 bit, its the same.
typedef long ssize_t;
typedef unsigned long size_t;

// sighandler in Linux
typedef void (*sig_t)(int);

struct iovec {
  void *iov_base;
  size_t iov_len;
};
struct winsize {
  unsigned short ws_row;
  unsigned short ws_col;
  unsigned short ws_xpixel;
  unsigned short ws_ypixel;
};
struct in_addr {
  uint32_t       s_addr;
};
struct in6_addr {
  unsigned char  s6_addr[16];
};
struct ethhdr {
  unsigned char   h_dest[6];
  unsigned char   h_source[6];
  unsigned short  h_proto; /* __be16 */
} __attribute__((packed));
struct udphdr {
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};
]]

-- endian dependent TODO not really, define in independent way
if abi.le then
append [[
struct iphdr {
  uint8_t  ihl:4,
           version:4;
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};
]]
else
append [[
struct iphdr {
  uint8_t  version:4,
           ihl:4;
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};
]]
end

ffi.cdef(table.concat(defs, ""))


]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.lfs"],"module already exists")sources["syscall.lfs"]=([===[-- <pack syscall.lfs> --
-- this is intended to be compatible with luafilesystem https://github.com/keplerproject/luafilesystem

-- currently does not implement locks

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

-- TODO allow use eg with rump kernel, needs an initialisation option
-- maybe return a table with a metatable that allows init or uses default if no init?
local S = require "syscall"

-- TODO not implemented
-- lfs.lock_dir
-- lfs.lock
-- unlock

local function lfswrap(f)
  return function(...)
    local ret, err = f(...)
    if not ret then return nil, tostring(err) end
    return ret
  end
end

local lfs = {}

lfs._VERSION = "ljsyscall lfs 1"

local attributes = {
  dev = "dev",
  ino = "ino",
  mode = "typename", -- not sure why lfs insists on calling this mode
  nlink = "nlink",
  uid = "uid",
  gid = "gid",
  rdev = "rdev",
  access = "access",
  modification = "modification",
  change = "change",
  size = "size",
  blocks = "blocks",
  blksize = "blksize",
}

local function attr(st, aname)
  if aname then
    aname = attributes[aname]
    return st[aname]
  end
  local ret = {}
  for k, v in pairs(attributes) do ret[k] = st[v] end
  return ret
end

function lfs.attributes(filepath, aname)
  local st, err = S.stat(filepath)
  if not st then return nil, tostring(err) end
  return attr(st, aname)
end
function lfs.symlinkattributes(filepath, aname)
  local st, err = S.lstat(filepath)
  if not st then return nil, tostring(err) end
  return attr(st, aname)
end

lfs.chdir = lfswrap(S.chdir)
lfs.currentdir = lfswrap(S.getcwd)
lfs.rmdir = lfswrap(S.rmdir)
lfs.touch = lfswrap(S.utime)

function lfs.mkdir(path)
  local ret, err = S.mkdir(path, "0777")
  if not ret then return nil, tostring(err) end
  return ret
end

local function dir_close(dir)
  dir.fd:close()
  dir.fd = nil
end

local function dir_next(dir)
  if not dir.fd then error "dir ended" end
  local d
  repeat
    if not dir.di then
      local err
      dir.di, err = dir.fd:getdents(dir.buf, dir.size)
      if not dir.di then
        dir_close(dir)
        error(tostring(err)) -- not sure how we are suppose to handle errors
      end
      dir.first = true
    end
    d = dir.di()
    if not d then
      dir.di = nil
      if dir.first then
        dir_close(dir)
        return nil
      end
    end
    dir.first = false
  until d
  return d.name
end

function lfs.dir(path)
  local size = 4096
  local buf = S.t.buffer(size)
  local fd, err = S.open(path, "directory, rdonly")
  if err then return nil, tostring(err) end
  return dir_next, {size = size, buf = buf, fd = fd, next = dir_next, close = dir_close}
end

local flink, fsymlink = lfswrap(S.link), lfswrap(S.symlink)

function lfs.link(old, new, symlink)
  if symlink then
    return fsymlink(old, new)
  else
    return flink(old, new)
  end
end

function lfs.setmode(file, mode) return true, "binary" end

return lfs

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.nr"],"module already exists")sources["syscall.linux.nr"]=([===[-- <pack syscall.linux.nr> --
local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local abi = require "syscall.abi"

local nr = require("syscall.linux." .. abi.arch .. ".nr")

if nr.SYS.socketcall then nr.socketcalls = {
  SOCKET      = 1,
  BIND        = 2,
  CONNECT     = 3,
  LISTEN      = 4,
  ACCEPT      = 5,
  GETSOCKNAME = 6,
  GETPEERNAME = 7,
  SOCKETPAIR  = 8,
  SEND        = 9,
  RECV        = 10,
  SENDTO      = 11,
  RECVFROM    = 12,
  SHUTDOWN    = 13,
  SETSOCKOPT  = 14,
  GETSOCKOPT  = 15,
  SENDMSG     = 16,
  RECVMSG     = 17,
  ACCEPT4     = 18,
  RECVMMSG    = 19,
  SENDMMSG    = 20,
}
end

return nr

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ppc.nr"],"module already exists")sources["syscall.linux.ppc.nr"]=([===[-- <pack syscall.linux.ppc.nr> --
-- ppc syscall numbers

local nr = {
  zeropad = true,
  SYS = {
  restart_syscall         = 0,
  exit                    = 1,
  fork                    = 2,
  read                    = 3,
  write                   = 4,
  open                    = 5,
  close                   = 6,
  waitpid                 = 7,
  creat                   = 8,
  link                    = 9,
  unlink                 = 10,
  execve                 = 11,
  chdir                  = 12,
  time                   = 13,
  mknod                  = 14,
  chmod                  = 15,
  lchown                 = 16,
  ["break"]              = 17,
  oldstat                = 18,
  lseek                  = 19,
  getpid                 = 20,
  mount                  = 21,
  umount                 = 22,
  setuid                 = 23,
  getuid                 = 24,
  stime                  = 25,
  ptrace                 = 26,
  alarm                  = 27,
  oldfstat               = 28,
  pause                  = 29,
  utime                  = 30,
  stty                   = 31,
  gtty                   = 32,
  access                 = 33,
  nice                   = 34,
  ftime                  = 35,
  sync                   = 36,
  kill                   = 37,
  rename                 = 38,
  mkdir                  = 39,
  rmdir                  = 40,
  dup                    = 41,
  pipe                   = 42,
  times                  = 43,
  prof                   = 44,
  brk                    = 45,
  setgid                 = 46,
  getgid                 = 47,
  signal                 = 48,
  geteuid                = 49,
  getegid                = 50,
  acct                   = 51,
  umount2                = 52,
  lock                   = 53,
  ioctl                  = 54,
  fcntl                  = 55,
  mpx                    = 56,
  setpgid                = 57,
  ulimit                 = 58,
  oldolduname            = 59,
  umask                  = 60,
  chroot                 = 61,
  ustat                  = 62,
  dup2                   = 63,
  getppid                = 64,
  getpgrp                = 65,
  setsid                 = 66,
  sigaction              = 67,
  sgetmask               = 68,
  ssetmask               = 69,
  setreuid               = 70,
  setregid               = 71,
  sigsuspend             = 72,
  sigpending             = 73,
  sethostname            = 74,
  setrlimit              = 75,
  getrlimit              = 76,
  getrusage              = 77,
  gettimeofday           = 78,
  settimeofday           = 79,
  getgroups              = 80,
  setgroups              = 81,
  select                 = 82,
  symlink                = 83,
  oldlstat               = 84,
  readlink               = 85,
  uselib                 = 86,
  swapon                 = 87,
  reboot                 = 88,
  readdir                = 89,
  mmap                   = 90,
  munmap                 = 91,
  truncate               = 92,
  ftruncate              = 93,
  fchmod                 = 94,
  fchown                 = 95,
  getpriority            = 96,
  setpriority            = 97,
  profil                 = 98,
  statfs                 = 99,
  fstatfs               = 100,
  ioperm                = 101,
  socketcall            = 102,
  syslog                = 103,
  setitimer             = 104,
  getitimer             = 105,
  stat                  = 106,
  lstat                 = 107,
  fstat                 = 108,
  olduname              = 109,
  iopl                  = 110,
  vhangup               = 111,
  idle                  = 112,
  vm86                  = 113,
  wait4                 = 114,
  swapoff               = 115,
  sysinfo               = 116,
  ipc                   = 117,
  fsync                 = 118,
  sigreturn             = 119,
  clone                 = 120,
  setdomainname         = 121,
  uname                 = 122,
  modify_ldt            = 123,
  adjtimex              = 124,
  mprotect              = 125,
  sigprocmask           = 126,
  create_module         = 127,
  init_module           = 128,
  delete_module         = 129,
  get_kernel_syms       = 130,
  quotactl              = 131,
  getpgid               = 132,
  fchdir                = 133,
  bdflush               = 134,
  sysfs                 = 135,
  personality           = 136,
  afs_syscall           = 137,
  setfsuid              = 138,
  setfsgid              = 139,
  _llseek               = 140,
  getdents              = 141,
  _newselect            = 142,
  flock                 = 143,
  msync                 = 144,
  readv                 = 145,
  writev                = 146,
  getsid                = 147,
  fdatasync             = 148,
  _sysctl               = 149,
  mlock                 = 150,
  munlock               = 151,
  mlockall              = 152,
  munlockall            = 153,
  sched_setparam        = 154,
  sched_getparam        = 155,
  sched_setscheduler    = 156,
  sched_getscheduler    = 157,
  sched_yield           = 158,
  sched_get_priority_max= 159,
  sched_get_priority_min= 160,
  sched_rr_get_interval = 161,
  nanosleep             = 162,
  mremap                = 163,
  setresuid             = 164,
  getresuid             = 165,
  query_module          = 166,
  poll                  = 167,
  nfsservctl            = 168,
  setresgid             = 169,
  getresgid             = 170,
  prctl                 = 171,
  rt_sigreturn          = 172,
  rt_sigaction          = 173,
  rt_sigprocmask        = 174,
  rt_sigpending         = 175,
  rt_sigtimedwait       = 176,
  rt_sigqueueinfo       = 177,
  rt_sigsuspend         = 178,
  pread64               = 179,
  pwrite64              = 180,
  chown                 = 181,
  getcwd                = 182,
  capget                = 183,
  capset                = 184,
  sigaltstack           = 185,
  sendfile              = 186,
  getpmsg               = 187,
  putpmsg               = 188,
  vfork                 = 189,
  ugetrlimit            = 190,
  readahead             = 191,
  mmap2                 = 192,
  truncate64            = 193,
  ftruncate64           = 194,
  stat64                = 195,
  lstat64               = 196,
  fstat64               = 197,
  pciconfig_read        = 198,
  pciconfig_write       = 199,
  pciconfig_iobase      = 200,
  multiplexer           = 201,
  getdents64            = 202,
  pivot_root            = 203,
  fcntl64               = 204,
  madvise               = 205,
  mincore               = 206,
  gettid                = 207,
  tkill                 = 208,
  setxattr              = 209,
  lsetxattr             = 210,
  fsetxattr             = 211,
  getxattr              = 212,
  lgetxattr             = 213,
  fgetxattr             = 214,
  listxattr             = 215,
  llistxattr            = 216,
  flistxattr            = 217,
  removexattr           = 218,
  lremovexattr          = 219,
  fremovexattr          = 220,
  futex                 = 221,
  sched_setaffinity     = 222,
  sched_getaffinity     = 223,
  tuxcall               = 225,
  sendfile64            = 226,
  io_setup              = 227,
  io_destroy            = 228,
  io_getevents          = 229,
  io_submit             = 230,
  io_cancel             = 231,
  set_tid_address       = 232,
  fadvise64             = 233,
  exit_group            = 234,
  lookup_dcookie        = 235,
  epoll_create          = 236,
  epoll_ctl             = 237,
  epoll_wait            = 238,
  remap_file_pages      = 239,
  timer_create          = 240,
  timer_settime         = 241,
  timer_gettime         = 242,
  timer_getoverrun      = 243,
  timer_delete          = 244,
  clock_settime         = 245,
  clock_gettime         = 246,
  clock_getres          = 247,
  clock_nanosleep       = 248,
  swapcontext           = 249,
  tgkill                = 250,
  utimes                = 251,
  statfs64              = 252,
  fstatfs64             = 253,
  fadvise64_64          = 254,
  rtas                  = 255,
  sys_debug_setcontext  = 256,
  migrate_pages         = 258,
  mbind                 = 259,
  get_mempolicy         = 260,
  set_mempolicy         = 261,
  mq_open               = 262,
  mq_unlink             = 263,
  mq_timedsend          = 264,
  mq_timedreceive       = 265,
  mq_notify             = 266,
  mq_getsetattr         = 267,
  kexec_load            = 268,
  add_key               = 269,
  request_key           = 270,
  keyctl                = 271,
  waitid                = 272,
  ioprio_set            = 273,
  ioprio_get            = 274,
  inotify_init          = 275,
  inotify_add_watch     = 276,
  inotify_rm_watch      = 277,
  spu_run               = 278,
  spu_create            = 279,
  pselect6              = 280,
  ppoll                 = 281,
  unshare               = 282,
  splice                = 283,
  tee                   = 284,
  vmsplice              = 285,
  openat                = 286,
  mkdirat               = 287,
  mknodat               = 288,
  fchownat              = 289,
  futimesat             = 290,
  fstatat64             = 291,
  unlinkat              = 292,
  renameat              = 293,
  linkat                = 294,
  symlinkat             = 295,
  readlinkat            = 296,
  fchmodat              = 297,
  faccessat             = 298,
  get_robust_list       = 299,
  set_robust_list       = 300,
  move_pages            = 301,
  getcpu                = 302,
  epoll_pwait           = 303,
  utimensat             = 304,
  signalfd              = 305,
  timerfd_create        = 306,
  eventfd               = 307,
  sync_file_range2      = 308,
  fallocate             = 309,
  subpage_prot          = 310,
  timerfd_settime       = 311,
  timerfd_gettime       = 312,
  signalfd4             = 313,
  eventfd2              = 314,
  epoll_create1         = 315,
  dup3                  = 316,
  pipe2                 = 317,
  inotify_init1         = 318,
  perf_event_open       = 319,
  preadv                = 320,
  pwritev               = 321,
  rt_tgsigqueueinfo     = 322,
  fanotify_init         = 323,
  fanotify_mark         = 324,
  prlimit64             = 325,
  socket                = 326,
  bind                  = 327,
  connect               = 328,
  listen                = 329,
  accept                = 330,
  getsockname           = 331,
  getpeername           = 332,
  socketpair            = 333,
  send                  = 334,
  sendto                = 335,
  recv                  = 336,
  recvfrom              = 337,
  shutdown              = 338,
  setsockopt            = 339,
  getsockopt            = 340,
  sendmsg               = 341,
  recvmsg               = 342,
  recvmmsg              = 343,
  accept4               = 344,
  name_to_handle_at     = 345,
  open_by_handle_at     = 346,
  clock_adjtime         = 347,
  syncfs                = 348,
  sendmmsg              = 349,
  setns                 = 350,
  process_vm_readv      = 351,
  process_vm_writev     = 352,
  kcmp                  = 353,
  finit_module          = 354,
  sched_setattr         = 355,
  sched_getattr         = 356,
  renameat2             = 357,
  seccomp               = 358,
  getrandom             = 359,
  memfd_create          = 360,
  bpf                   = 361,
}
}

return nr

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ppc.constants"],"module already exists")sources["syscall.linux.ppc.constants"]=([===[-- <pack syscall.linux.ppc.constants> --
-- ppc specific constants

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local h = require "syscall.helpers"

local octal = h.octal

local arch = {}

arch.EDEADLOCK = 58 -- only error that differs from generic

arch.SO = { -- 16-21 differ for ppc
  DEBUG       = 1,
  REUSEADDR   = 2,
  TYPE        = 3,
  ERROR       = 4,
  DONTROUTE   = 5,
  BROADCAST   = 6,
  SNDBUF      = 7,
  RCVBUF      = 8,
  KEEPALIVE   = 9,
  OOBINLINE   = 10,
  NO_CHECK    = 11,
  PRIORITY    = 12,
  LINGER      = 13,
  BSDCOMPAT   = 14,
--REUSEPORT   = 15, -- new, may not be defined yet
  RCVLOWAT    = 16,
  SNDLOWAT    = 17,
  RCVTIMEO    = 18,
  SNDTIMEO    = 19,
  PASSCRED    = 20,
  PEERCRED    = 21,
  SECURITY_AUTHENTICATION = 22,
  SECURITY_ENCRYPTION_TRANSPORT = 23,
  SECURITY_ENCRYPTION_NETWORK = 24,
  BINDTODEVICE       = 25,
  ATTACH_FILTER      = 26,
  DETACH_FILTER      = 27,
  PEERNAME           = 28,
  TIMESTAMP          = 29,
  ACCEPTCONN         = 30,
  PEERSEC            = 31,
  SNDBUFFORCE        = 32,
  RCVBUFFORCE        = 33,
  PASSSEC            = 34,
  TIMESTAMPNS        = 35,
  MARK               = 36,
  TIMESTAMPING       = 37,
  PROTOCOL           = 38,
  DOMAIN             = 39,
  RXQ_OVFL           = 40,
  WIFI_STATUS        = 41,
  PEEK_OFF           = 42,
  NOFCS              = 43,
}

arch.OFLAG = {
  OPOST  = octal('00000001'),
  ONLCR  = octal('00000002'),
  OLCUC  = octal('00000004'),
  OCRNL  = octal('00000010'),
  ONOCR  = octal('00000020'),
  ONLRET = octal('00000040'),
  OFILL  = octal('00000100'),
  OFDEL  = octal('00000200'),
  NLDLY  = octal('00001400'),
  NL0    = octal('00000000'),
  NL1    = octal('00000400'),
  NL2    = octal('00001000'),
  NL3    = octal('00001400'),
  CRDLY  = octal('00030000'),
  CR0    = octal('00000000'),
  CR1    = octal('00010000'),
  CR2    = octal('00020000'),
  CR3    = octal('00030000'),
  TABDLY = octal('00006000'),
  TAB0   = octal('00000000'),
  TAB1   = octal('00002000'),
  TAB2   = octal('00004000'),
  TAB3   = octal('00006000'),
  BSDLY  = octal('00100000'),
  BS0    = octal('00000000'),
  BS1    = octal('00100000'),
  FFDLY  = octal('00040000'),
  FF0    = octal('00000000'),
  FF1    = octal('00040000'),
  VTDLY  = octal('00200000'),
  VT0    = octal('00000000'),
  VT1    = octal('00200000'),
  XTABS  = octal('00006000'),
}

arch.LFLAG = {
  ISIG    = 0x00000080,
  ICANON  = 0x00000100,
  XCASE   = 0x00004000,
  ECHO    = 0x00000008,
  ECHOE   = 0x00000002,
  ECHOK   = 0x00000004,
  ECHONL  = 0x00000010,
  NOFLSH  = 0x80000000,
  TOSTOP  = 0x00400000,
  ECHOCTL = 0x00000040,
  ECHOPRT = 0x00000020,
  ECHOKE  = 0x00000001,
  FLUSHO  = 0x00800000,
  PENDIN  = 0x20000000,
  IEXTEN  = 0x00000400,
  EXTPROC = 0x10000000,
}

-- TODO these will be in a table
arch.CBAUD      = octal('0000377')
arch.CBAUDEX    = octal('0000000')
arch.CIBAUD     = octal('077600000')

arch.CFLAG = {
  CSIZE      = octal('00001400'),
  CS5        = octal('00000000'),
  CS6        = octal('00000400'),
  CS7        = octal('00001000'),
  CS8        = octal('00001400'),
  CSTOPB     = octal('00002000'),
  CREAD      = octal('00004000'),
  PARENB     = octal('00010000'),
  PARODD     = octal('00020000'),
  HUPCL      = octal('00040000'),
  CLOCAL     = octal('00100000'),
}

arch.IFLAG = {
  IGNBRK  = octal('0000001'),
  BRKINT  = octal('0000002'),
  IGNPAR  = octal('0000004'),
  PARMRK  = octal('0000010'),
  INPCK   = octal('0000020'),
  ISTRIP  = octal('0000040'),
  INLCR   = octal('0000100'),
  IGNCR   = octal('0000200'),
  ICRNL   = octal('0000400'),
  IXON    = octal('0001000'),
  IXOFF   = octal('0002000'),
  IXANY   = octal('0004000'),
  IUCLC   = octal('0010000'),
  IMAXBEL = octal('0020000'),
  IUTF8   = octal('0040000'),
}

arch.CC = {
  VINTR           = 0,
  VQUIT           = 1,
  VERASE          = 2,
  VKILL           = 3,
  VEOF            = 4,
  VMIN            = 5,
  VEOL            = 6,
  VTIME           = 7,
  VEOL2           = 8,
  VSWTC           = 9,
  VWERASE         = 10,
  VREPRINT        = 11,
  VSUSP           = 12,
  VSTART          = 13,
  VSTOP           = 14,
  VLNEXT          = 15,
  VDISCARD        = 16,
}

arch.B = {
  ['0'] = octal('0000000'),
  ['50'] = octal('0000001'),
  ['75'] = octal('0000002'),
  ['110'] = octal('0000003'),
  ['134'] = octal('0000004'),
  ['150'] = octal('0000005'),
  ['200'] = octal('0000006'),
  ['300'] = octal('0000007'),
  ['600'] = octal('0000010'),
  ['1200'] = octal('0000011'),
  ['1800'] = octal('0000012'),
  ['2400'] = octal('0000013'),
  ['4800'] = octal('0000014'),
  ['9600'] = octal('0000015'),
  ['19200'] = octal('0000016'),
  ['38400'] = octal('0000017'),
  ['57600'] = octal('00020'),
  ['115200'] = octal('00021'),
  ['230400'] = octal('00022'),
  ['460800'] = octal('00023'),
  ['500000'] = octal('00024'),
  ['576000'] = octal('00025'),
  ['921600'] = octal('00026'),
  ['1000000'] = octal('00027'),
  ['1152000'] = octal('00030'),
  ['1500000'] = octal('00031'),
  ['2000000'] = octal('00032'),
  ['2500000'] = octal('00033'),
  ['3000000'] = octal('00034'),
  ['3500000'] = octal('00035'),
  ['4000000'] = octal('00036'),
}

arch.O = {
  RDONLY    = octal('0000'),
  WRONLY    = octal('0001'),
  RDWR      = octal('0002'),
  ACCMODE   = octal('0003'),
  CREAT     = octal('0100'),
  EXCL      = octal('0200'),
  NOCTTY    = octal('0400'),
  TRUNC     = octal('01000'),
  APPEND    = octal('02000'),
  NONBLOCK  = octal('04000'),
  DSYNC     = octal('010000'),
  ASYNC     = octal('020000'),
  DIRECTORY = octal('040000'),
  NOFOLLOW  = octal('0100000'),
  LARGEFILE = octal('0200000'),
  DIRECT    = octal('0400000'),
  NOATIME   = octal('01000000'),
  CLOEXEC   = octal('02000000'),
  SYNC      = octal('04010000'),
}

arch.MAP = {
  FILE       = 0,
  SHARED     = 0x01,
  PRIVATE    = 0x02,
  TYPE       = 0x0f,
  FIXED      = 0x10,
  ANONYMOUS  = 0x20,
  NORESERVE  = 0x40,
  LOCKED     = 0x80,
  GROWSDOWN  = 0x00100,
  DENYWRITE  = 0x00800,
  EXECUTABLE = 0x01000,
  POPULATE   = 0x08000,
  NONBLOCK   = 0x10000,
  STACK      = 0x20000,
  HUGETLB    = 0x40000,
}

arch.MCL = {
  CURRENT    = 0x2000,
  FUTURE     = 0x4000,
}

arch.PROT = {
  SAO       = 0x10, -- Strong Access Ordering
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.errors"],"module already exists")sources["syscall.linux.errors"]=([===[-- <pack syscall.linux.errors> --
-- Linux error messages

return {
  PERM = "Operation not permitted",
  NOENT = "No such file or directory",
  SRCH = "No such process",
  INTR = "Interrupted system call",
  IO = "Input/output error",
  NXIO = "No such device or address",
  ["2BIG"] = "Argument list too long",
  NOEXEC = "Exec format error",
  BADF = "Bad file descriptor",
  CHILD = "No child processes",
  AGAIN = "Resource temporarily unavailable",
  NOMEM = "Cannot allocate memory",
  ACCES = "Permission denied",
  FAULT = "Bad address",
  NOTBLK = "Block device required",
  BUSY = "Device or resource busy",
  EXIST = "File exists",
  XDEV = "Invalid cross-device link",
  NODEV = "No such device",
  NOTDIR = "Not a directory",
  ISDIR = "Is a directory",
  INVAL = "Invalid argument",
  NFILE = "Too many open files in system",
  MFILE = "Too many open files",
  NOTTY = "Inappropriate ioctl for device",
  TXTBSY = "Text file busy",
  FBIG = "File too large",
  NOSPC = "No space left on device",
  SPIPE = "Illegal seek",
  ROFS = "Read-only file system",
  MLINK = "Too many links",
  PIPE = "Broken pipe",
  DOM = "Numerical argument out of domain",
  RANGE = "Numerical result out of range",
  DEADLK = "Resource deadlock avoided",
  NAMETOOLONG = "File name too long",
  NOLCK = "No locks available",
  NOSYS = "Function not implemented",
  NOTEMPTY = "Directory not empty",
  LOOP = "Too many levels of symbolic links",
  NOMSG = "No message of desired type",
  IDRM = "Identifier removed",
  CHRNG = "Channel number out of range",
  L2NSYNC = "Level 2 not synchronized",
  L3HLT = "Level 3 halted",
  L3RST = "Level 3 reset",
  LNRNG = "Link number out of range",
  UNATCH = "Protocol driver not attached",
  NOCSI = "No CSI structure available",
  L2HLT = "Level 2 halted",
  BADE = "Invalid exchange",
  BADR = "Invalid request descriptor",
  XFULL = "Exchange full",
  NOANO = "No anode",
  BADRQC = "Invalid request code",
  BADSLT = "Invalid slot",
  BFONT = "Bad font file format",
  NOSTR = "Device not a stream",
  NODATA = "No data available",
  TIME = "Timer expired",
  NOSR = "Out of streams resources",
  NONET = "Machine is not on the network",
  NOPKG = "Package not installed",
  REMOTE = "Object is remote",
  NOLINK = "Link has been severed",
  ADV = "Advertise error",
  SRMNT = "Srmount error",
  COMM = "Communication error on send",
  PROTO = "Protocol error",
  MULTIHOP = "Multihop attempted",
  DOTDOT = "RFS specific error",
  BADMSG = "Bad message",
  OVERFLOW = "Value too large for defined data type",
  NOTUNIQ = "Name not unique on network",
  BADFD = "File descriptor in bad state",
  REMCHG = "Remote address changed",
  LIBACC = "Can not access a needed shared library",
  LIBBAD = "Accessing a corrupted shared library",
  LIBSCN = ".lib section in a.out corrupted",
  LIBMAX = "Attempting to link in too many shared libraries",
  LIBEXEC = "Cannot exec a shared library directly",
  ILSEQ = "Invalid or incomplete multibyte or wide character",
  RESTART = "Interrupted system call should be restarted",
  STRPIPE = "Streams pipe error",
  USERS = "Too many users",
  NOTSOCK = "Socket operation on non-socket",
  DESTADDRREQ = "Destination address required",
  MSGSIZE = "Message too long",
  PROTOTYPE = "Protocol wrong type for socket",
  NOPROTOOPT = "Protocol not available",
  PROTONOSUPPORT = "Protocol not supported",
  SOCKTNOSUPPORT = "Socket type not supported",
  OPNOTSUPP = "Operation not supported",
  PFNOSUPPORT = "Protocol family not supported",
  AFNOSUPPORT = "Address family not supported by protocol",
  ADDRINUSE = "Address already in use",
  ADDRNOTAVAIL = "Cannot assign requested address",
  NETDOWN = "Network is down",
  NETUNREACH = "Network is unreachable",
  NETRESET = "Network dropped connection on reset",
  CONNABORTED = "Software caused connection abort",
  CONNRESET = "Connection reset by peer",
  NOBUFS = "No buffer space available",
  ISCONN = "Transport endpoint is already connected",
  NOTCONN = "Transport endpoint is not connected",
  SHUTDOWN = "Cannot send after transport endpoint shutdown",
  TOOMANYREFS = "Too many references: cannot splice",
  TIMEDOUT = "Connection timed out",
  CONNREFUSED = "Connection refused",
  HOSTDOWN = "Host is down",
  HOSTUNREACH = "No route to host",
  ALREADY = "Operation already in progress",
  INPROGRESS = "Operation now in progress",
  STALE = "Stale NFS file handle",
  UCLEAN = "Structure needs cleaning",
  NOTNAM = "Not a XENIX named type file",
  NAVAIL = "No XENIX semaphores available",
  ISNAM = "Is a named type file",
  REMOTEIO = "Remote I/O error",
  DQUOT = "Disk quota exceeded",
  NOMEDIUM = "No medium found",
  MEDIUMTYPE = "Wrong medium type",
  CANCELED = "Operation canceled",
  NOKEY = "Required key not available",
  KEYEXPIRED = "Key has expired",
  KEYREVOKED = "Key has been revoked",
  KEYREJECTED = "Key was rejected by service",
  OWNERDEAD = "Owner died",
  NOTRECOVERABLE = "State not recoverable",
  RFKILL = "Operation not possible due to RF-kill",
  -- only on some platforms
  DEADLOCK = "File locking deadlock error",
  INIT = "Reserved EINIT", -- what is correct message?
  REMDEV = "Remote device", -- what is correct message?
  HWPOISON = "Reserved EHWPOISON", -- what is correct message?
}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ppc.ioctl"],"module already exists")sources["syscall.linux.ppc.ioctl"]=([===[-- <pack syscall.linux.ppc.ioctl> --
-- ppc ioctl differences

local arch = {
  IOC = {
    SIZEBITS  = 13,
    DIRBITS   = 3,
    NONE      = 1,
    READ      = 2,
    WRITE     = 4,
  },
  ioctl = function(_IO, _IOR, _IOW, _IORW)
    return {
      FIOCLEX   = _IO('f', 1),
      FIONCLEX  = _IO('f', 2),
      FIOQSIZE  = _IOR('f', 128, "off"),
      FIOASYNC  = _IOW('f', 125, "int"),
      TCGETS    = _IOR('t', 19, "termios"),
      TCSETS    = _IOW('t', 20, "termios"),
      TCSETSW   = _IOW('t', 21, "termios"),
      TCSETSF   = _IOW('t', 22, "termios"),
      TCSBRK    = _IO('t', 29),
      TCXONC    = _IO('t', 30),
      TCFLSH    = _IO('t', 31),
      TIOCSWINSZ = _IOW('t', 103, "winsize"),
      TIOCGWINSZ = _IOR('t', 104, "winsize"),
      TIOCOUTQ  = _IOR('t', 115, "int"),
      TIOCSPGRP = _IOW('t', 118, "int"),
      TIOCGPGRP = _IOR('t', 119, "int"),
      FIONBIO   = _IOW('f', 126, "int"),
      FIONREAD  = _IOR('f', 127, "int"),
    }
  end,
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.fcntl"],"module already exists")sources["syscall.linux.fcntl"]=([===[-- <pack syscall.linux.fcntl> --
-- fcntl is one of those bits of the Unix API that is a bit random, so give it its own file

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

local function init(types)

local c = require "syscall.linux.constants"

local ffi = require "ffi"

local t, pt, s = types.t, types.pt, types.s

local fcntl = {
  commands = {
    [c.F.SETFL] = function(arg) return c.O[arg] end,
    [c.F.SETFD] = function(arg) return c.FD[arg] end,
    [c.F.GETLK] = t.flock,
    [c.F.SETLK] = t.flock,
    [c.F.SETLKW] = t.flock,
    [c.F.ADD_SEALS] = function(arg) return c.F_SEAL[arg] end,
  },
  ret = {
    [c.F.DUPFD] = function(ret) return t.fd(ret) end,
    [c.F.DUPFD_CLOEXEC] = function(ret) return t.fd(ret) end,
    [c.F.GETFD] = function(ret) return tonumber(ret) end,
    [c.F.GETFL] = function(ret) return tonumber(ret) end,
    [c.F.GETLEASE] = function(ret) return tonumber(ret) end,
    [c.F.GETOWN] = function(ret) return tonumber(ret) end,
    [c.F.GETSIG] = function(ret) return tonumber(ret) end,
    [c.F.GETPIPE_SZ] = function(ret) return tonumber(ret) end,
    [c.F.GETLK] = function(ret, arg) return arg end,
    [c.F.GET_SEALS] = function(ret) return tonumber(ret) end,
  }
}

return fcntl

end

return {init = init}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.mips.nr"],"module already exists")sources["syscall.linux.mips.nr"]=([===[-- <pack syscall.linux.mips.nr> --
-- MIPS syscall numbers

local require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string = 
require, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string

-- these are different for different ABIs TODO add the rest, TODO maybe put them in different files

local abi = require "syscall.abi"
assert(abi.mipsabi == "o32", "FIXME: syscalls only defined for o32 MIPS ABI")

local nr = {
  zeropad = true,
  SYS = {
  syscall               = 4000,
  exit                  = 4001,
  fork                  = 4002,
  read                  = 4003,
  write                 = 4004,
  open                  = 4005,
  close                 = 4006,
  waitpid               = 4007,
  creat                 = 4008,
  link                  = 4009,
  unlink                = 4010,
  execve                = 4011,
  chdir                 = 4012,
  time                  = 4013,
  mknod                 = 4014,
  chmod                 = 4015,
  lchown                = 4016,
  ["break"]             = 4017,
  unused18              = 4018,
  lseek                 = 4019,
  getpid                = 4020,
  mount                 = 4021,
  umount                = 4022,
  setuid                = 4023,
  getuid                = 4024,
  stime                 = 4025,
  ptrace                = 4026,
  alarm                 = 4027,
  unused28              = 4028,
  pause                 = 4029,
  utime                 = 4030,
  stty                  = 4031,
  gtty                  = 4032,
  access                = 4033,
  nice                  = 4034,
  ftime                 = 4035,
  sync                  = 4036,
  kill                  = 4037,
  rename                = 4038,
  mkdir                 = 4039,
  rmdir                 = 4040,
  dup                   = 4041,
  pipe                  = 4042,
  times                 = 4043,
  prof                  = 4044,
  brk                   = 4045,
  setgid                = 4046,
  getgid                = 4047,
  signal                = 4048,
  geteuid               = 4049,
  getegid               = 4050,
  acct                  = 4051,
  umount2               = 4052,
  lock                  = 4053,
  ioctl                 = 4054,
  fcntl                 = 4055,
  mpx                   = 4056,
  setpgid               = 4057,
  ulimit                = 4058,
  unused59              = 4059,
  umask                 = 4060,
  chroot                = 4061,
  ustat                 = 4062,
  dup2                  = 4063,
  getppid               = 4064,
  getpgrp               = 4065,
  setsid                = 4066,
  sigaction             = 4067,
  sgetmask              = 4068,
  ssetmask              = 4069,
  setreuid              = 4070,
  setregid              = 4071,
  sigsuspend            = 4072,
  sigpending            = 4073,
  sethostname           = 4074,
  setrlimit             = 4075,
  getrlimit             = 4076,
  getrusage             = 4077,
  gettimeofday          = 4078,
  settimeofday          = 4079,
  getgroups             = 4080,
  setgroups             = 4081,
  reserved82            = 4082,
  symlink               = 4083,
  unused84              = 4084,
  readlink              = 4085,
  uselib                = 4086,
  swapon                = 4087,
  reboot                = 4088,
  readdir               = 4089,
  mmap                  = 4090,
  munmap                = 4091,
  truncate              = 4092,
  ftruncate             = 4093,
  fchmod                = 4094,
  fchown                = 4095,
  getpriority           = 4096,
  setpriority           = 4097,
  profil                = 4098,
  statfs                = 4099,
  fstatfs               = 4100,
  ioperm                = 4101,
  socketcall            = 4102,
  syslog                = 4103,
  setitimer             = 4104,
  getitimer             = 4105,
  stat                  = 4106,
  lstat                 = 4107,
  fstat                 = 4108,
  unused109             = 4109,
  iopl                  = 4110,
  vhangup               = 4111,
  idle                  = 4112,
  vm86                  = 4113,
  wait4                 = 4114,
  swapoff               = 4115,
  sysinfo               = 4116,
  ipc                   = 4117,
  fsync                 = 4118,
  sigreturn             = 4119,
  clone                 = 4120,
  setdomainname         = 4121,
  uname                 = 4122,
  modify_ldt            = 4123,
  adjtimex              = 4124,
  mprotect              = 4125,
  sigprocmask           = 4126,
  create_module         = 4127,
  init_module           = 4128,
  delete_module         = 4129,
  get_kernel_syms       = 4130,
  quotactl              = 4131,
  getpgid               = 4132,
  fchdir                = 4133,
  bdflush               = 4134,
  sysfs                 = 4135,
  personality           = 4136,
  afs_syscall           = 4137,
  setfsuid              = 4138,
  setfsgid              = 4139,
  _llseek               = 4140,
  getdents              = 4141,
  _newselect            = 4142,
  flock                 = 4143,
  msync                 = 4144,
  readv                 = 4145,
  writev                = 4146,
  cacheflush            = 4147,
  cachectl              = 4148,
  sysmips               = 4149,
  unused150             = 4150,
  getsid                = 4151,
  fdatasync             = 4152,
  _sysctl               = 4153,
  mlock                 = 4154,
  munlock               = 4155,
  mlockall              = 4156,
  munlockall            = 4157,
  sched_setparam        = 4158,
  sched_getparam        = 4159,
  sched_setscheduler    = 4160,
  sched_getscheduler    = 4161,
  sched_yield           = 4162,
  sched_get_priority_max= 4163,
  sched_get_priority_min= 4164,
  sched_rr_get_interval = 4165,
  nanosleep             = 4166,
  mremap                = 4167,
  accept                = 4168,
  bind                  = 4169,
  connect               = 4170,
  getpeername           = 4171,
  getsockname           = 4172,
  getsockopt            = 4173,
  listen                = 4174,
  recv                  = 4175,
  recvfrom              = 4176,
  recvmsg               = 4177,
  send                  = 4178,
  sendmsg               = 4179,
  sendto                = 4180,
  setsockopt            = 4181,
  shutdown              = 4182,
  socket                = 4183,
  socketpair            = 4184,
  setresuid             = 4185,
  getresuid             = 4186,
  query_module          = 4187,
  poll                  = 4188,
  nfsservctl            = 4189,
  setresgid             = 4190,
  getresgid             = 4191,
  prctl                 = 4192,
  rt_sigreturn          = 4193,
  rt_sigaction          = 4194,
  rt_sigprocmask        = 4195,
  rt_sigpending         = 4196,
  rt_sigtimedwait       = 4197,
  rt_sigqueueinfo       = 4198,
  rt_sigsuspend         = 4199,
  pread64               = 4200,
  pwrite64              = 4201,
  chown                 = 4202,
  getcwd                = 4203,
  capget                = 4204,
  capset                = 4205,
  sigaltstack           = 4206,
  sendfile              = 4207,
  getpmsg               = 4208,
  putpmsg               = 4209,
  mmap2                 = 4210,
  truncate64            = 4211,
  ftruncate64           = 4212,
  stat64                = 4213,
  lstat64               = 4214,
  fstat64               = 4215,
  pivot_root            = 4216,
  mincore               = 4217,
  madvise               = 4218,
  getdents64            = 4219,
  fcntl64               = 4220,
  reserved221           = 4221,
  gettid                = 4222,
  readahead             = 4223,
  setxattr              = 4224,
  lsetxattr             = 4225,
  fsetxattr             = 4226,
  getxattr              = 4227,
  lgetxattr             = 4228,
  fgetxattr             = 4229,
  listxattr             = 4230,
  llistxattr            = 4231,
  flistxattr            = 4232,
  removexattr           = 4233,
  lremovexattr          = 4234,
  fremovexattr          = 4235,
  tkill                 = 4236,
  sendfile64            = 4237,
  futex                 = 4238,
  sched_setaffinity     = 4239,
  sched_getaffinity     = 4240,
  io_setup              = 4241,
  io_destroy            = 4242,
  io_getevents          = 4243,
  io_submit             = 4244,
  io_cancel             = 4245,
  exit_group            = 4246,
  lookup_dcookie        = 4247,
  epoll_create          = 4248,
  epoll_ctl             = 4249,
  epoll_wait            = 4250,
  remap_file_pages      = 4251,
  set_tid_address       = 4252,
  restart_syscall       = 4253,
  fadvise64             = 4254,
  statfs64              = 4255,
  fstatfs64             = 4256,
  timer_create          = 4257,
  timer_settime         = 4258,
  timer_gettime         = 4259,
  timer_getoverrun      = 4260,
  timer_delete          = 4261,
  clock_settime         = 4262,
  clock_gettime         = 4263,
  clock_getres          = 4264,
  clock_nanosleep       = 4265,
  tgkill                = 4266,
  utimes                = 4267,
  mbind                 = 4268,
  get_mempolicy         = 4269,
  set_mempolicy         = 4270,
  mq_open               = 4271,
  mq_unlink             = 4272,
  mq_timedsend          = 4273,
  mq_timedreceive       = 4274,
  mq_notify             = 4275,
  mq_getsetattr         = 4276,
  vserver               = 4277,
  waitid                = 4278,
  add_key               = 4280,
  request_key           = 4281,
  keyctl                = 4282,
  set_thread_area       = 4283,
  inotify_init          = 4284,
  inotify_add_watch     = 4285,
  inotify_rm_watch      = 4286,
  migrate_pages         = 4287,
  openat                = 4288,
  mkdirat               = 4289,
  mknodat               = 4290,
  fchownat              = 4291,
  futimesat             = 4292,
  fstatat64             = 4293,
  unlinkat              = 4294,
  renameat              = 4295,
  linkat                = 4296,
  symlinkat             = 4297,
  readlinkat            = 4298,
  fchmodat              = 4299,
  faccessat             = 4300,
  pselect6              = 4301,
  ppoll                 = 4302,
  unshare               = 4303,
  splice                = 4304,
  sync_file_range       = 4305,
  tee                   = 4306,
  vmsplice              = 4307,
  move_pages            = 4308,
  set_robust_list       = 4309,
  get_robust_list       = 4310,
  kexec_load            = 4311,
  getcpu                = 4312,
  epoll_pwait           = 4313,
  ioprio_set            = 4314,
  ioprio_get            = 4315,
  utimensat             = 4316,
  signalfd              = 4317,
  timerfd               = 4318,
  eventfd               = 4319,
  fallocate             = 4320,
  timerfd_create        = 4321,
  timerfd_gettime       = 4322,
  timerfd_settime       = 4323,
  signalfd4             = 4324,
  eventfd2              = 4325,
  epoll_create1         = 4326,
  dup3                  = 4327,
  pipe2                 = 4328,
  inotify_init1         = 4329,
  preadv                = 4330,
  pwritev               = 4331,
  rt_tgsigqueueinfo     = 4332,
  perf_event_open       = 4333,
  accept4               = 4334,
  recvmmsg              = 4335,
  fanotify_init         = 4336,
  fanotify_mark         = 4337,
  prlimit64             = 4338,
  name_to_handle_at     = 4339,
  open_by_handle_at     = 4340,
  clock_adjtime         = 4341,
  syncfs                = 4342,
  sendmmsg              = 4343,
  setns                 = 4344,
  process_vm_readv      = 4345,
  process_vm_writev     = 4346,
}
}

return nr

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.x64.nr"],"module already exists")sources["syscall.linux.x64.nr"]=([===[-- <pack syscall.linux.x64.nr> --
-- x64 syscall numbers

local nr = {
  SYS = {
  read    = 0,
  write   = 1,
  open    = 2,
  close   = 3,
  stat    = 4,
  fstat   = 5,
  lstat   = 6,
  poll    = 7,
  lseek   = 8,
  mmap    = 9,
  mprotect  = 10,
  munmap    = 11,
  brk       = 12,
  rt_sigaction    = 13,
  rt_sigprocmask  = 14,
  rt_sigreturn    = 15,
  ioctl    = 16,
  pread64  = 17,
  pwrite64 = 18,
  readv    = 19,
  writev   = 20,
  access   = 21,
  pipe     = 22,
  select   = 23,
  sched_yield = 24,
  mremap   = 25,
  msync    = 26,
  mincore  = 27,
  madvise  = 28,
  shmget   = 29,
  shmat    = 30,
  shmctl   = 31,
  dup      = 32,
  dup2     = 33,
  pause    = 34,
  nanosleep    = 35,
  getitimer    = 36,
  alarm        = 37,
  setitimer    = 38,
  getpid       = 39,
  sendfile     = 40,
  socket       = 41,
  connect      = 42,
  accept       = 43,
  sendto       = 44,
  recvfrom     = 45,
  sendmsg      = 46,
  recvmsg      = 47,
  shutdown     = 48,
  bind         = 49,
  listen       = 50,
  getsockname  = 51,
  getpeername  = 52,
  socketpair   = 53,
  setsockopt   = 54,
  getsockopt   = 55,
  clone        = 56,
  fork         = 57,
  vfork        = 58,
  execve       = 59,
  exit         = 60,
  wait4        = 61,
  kill         = 62,
  uname        = 63,
  semget       = 64,
  semop        = 65,
  semctl       = 66,
  shmdt        = 67,
  msgget       = 68,
  msgsnd       = 69,
  msgrcv       = 70,
  msgctl       = 71,
  fcntl        = 72,
  flock        = 73,
  fsync        = 74,
  fdatasync    = 75,
  truncate     = 76,
  ftruncate    = 77,
  getdents     = 78,
  getcwd       = 79,
  chdir        = 80,
  fchdir       = 81,
  rename       = 82,
  mkdir        = 83,
  rmdir        = 84,
  creat        = 85,
  link         = 86,
  unlink       = 87,
  symlink      = 88,
  readlink     = 89,
  chmod        = 90,
  fchmod       = 91,
  chown        = 92,
  fchown       = 93,
  lchown       = 94,
  umask        = 95,
  gettimeofday = 96,
  getrlimit    = 97,
  getrusage    = 98,
  sysinfo      = 99,
  times        = 100,
  ptrace       = 101,
  getuid       = 102,
  syslog       = 103,
  getgid       = 104,
  setuid       = 105,
  setgid       = 106,
  geteuid      = 107,
  getegid      = 108,
  setpgid      = 109,
  getppid      = 110,
  getpgrp      = 111,
  setsid       = 112,
  setreuid     = 113,
  setregid     = 114,
  getgroups    = 115,
  setgroups    = 116,
  setresuid    = 117,
  getresuid    = 118,
  setresgid    = 119,
  getresgid    = 120,
  getpgid      = 121,
  setfsuid     = 122,
  setfsgid     = 123,
  getsid       = 124,
  capget       = 125,
  capset       = 126,
  rt_sigpending   = 127,
  rt_sigtimedwait = 128,
  rt_sigqueueinfo = 129,
  rt_sigsuspend   = 130,
  sigaltstack  = 131,
  utime        = 132,
  mknod        = 133,
  uselib       = 134,
  personality  = 135,
  ustat        = 136,
  statfs       = 137,
  fstatfs      = 138,
  sysfs        = 139,
  getpriority  = 140,
  setpriority  = 141,
  sched_setparam = 142,
  sched_getparam = 143,
  sched_setscheduler = 144,
  sched_getscheduler = 145,
  sched_get_priority_max = 146,
  sched_get_priority_min = 147,
  sched_rr_get_interval = 148,
  mlock        = 149,
  munlock      = 150,
  mlockall     = 151,
  munlockall   = 152,
  vhangup      = 153,
  modify_ldt   = 154,
  pivot_root   = 155,
  _sysctl      = 156,
  prctl        = 157,
  arch_prctl   = 158,
  adjtimex     = 159,
  setrlimit    = 160,
  chroot       = 161,
  sync         = 162,
  acct         = 163,
  settimeofday = 164,
  mount        = 165,
  umount2      = 166,
  swapon       = 167,
  swapoff      = 168,
  reboot       = 169,
  sethostname  = 170,
  setdomainname = 171,
  iopl         = 172,
  ioperm       = 173,
  create_module = 174,
  init_module  = 175,
  delete_module = 176,
  get_kernel_syms = 177,
  query_module = 178,
  quotactl     = 179,
  nfsservctl   = 180,
  getpmsg      = 181,
  putpmsg      = 182,
  afs_syscall  = 183,
  tuxcall      = 184,
  security     = 185,
  gettid       = 186,
  readahead    = 187,
  setxattr     = 188,
  lsetxattr    = 189,
  fsetxattr    = 190,
  getxattr     = 191,
  lgetxattr    = 192,
  fgetxattr    = 193,
  listxattr    = 194,
  llistxattr   = 195,
  flistxattr   = 196,
  removexattr  = 197,
  lremovexattr = 198,
  fremovexattr = 199,
  tkill        = 200,
  time         = 201,
  futex        = 202,
  sched_setaffinity = 203,
  sched_getaffinity = 204,
  set_thread_area   = 205,
  io_setup     = 206,
  io_destroy   = 207,
  io_getevents = 208,
  io_submit    = 209,
  io_cancel    = 210,
  get_thread_area = 211,
  lookup_dcookie  = 212,
  epoll_create  = 213,
  epoll_ctl_old = 214,
  epoll_wait_old = 215,
  remap_file_pages = 216,
  getdents64   = 217,
  set_tid_address = 218,
  restart_syscall = 219,
  semtimedop   = 220,
  fadvise64    = 221,
  timer_create = 222,
  timer_settime = 223,
  timer_gettime = 224,
  timer_getoverrun = 225,
  timer_delete  = 226,
  clock_settime = 227,
  clock_gettime = 228,
  clock_getres  = 229,
  clock_nanosleep = 230,
  exit_group   = 231,
  epoll_wait   = 232,
  epoll_ctl    = 233,
  tgkill       = 234,
  utimes       = 235,
  vserver      = 236,
  mbind        = 237,
  set_mempolicy = 238,
  get_mempolicy = 239,
  mq_open      = 240,
  mq_unlink    = 241,
  mq_timedsend = 242,
  mq_timedreceive = 243,
  mq_notify    = 244,
  mq_getsetattr = 245,
  kexec_load   = 246,
  waitid       = 247,
  add_key      = 248,
  request_key  = 249,
  keyctl       = 250,
  ioprio_set   = 251,
  ioprio_get   = 252,
  inotify_init = 253,
  inotify_add_watch = 254,
  inotify_rm_watch = 255,
  migrate_pages    = 256,
  openat       = 257,
  mkdirat      = 258,
  mknodat      = 259,
  fchownat     = 260,
  futimesat    = 261,
  newfstatat   = 262,
  unlinkat     = 263,
  renameat     = 264,
  linkat       = 265,
  symlinkat    = 266,
  readlinkat   = 267,
  fchmodat     = 268,
  faccessat    = 269,
  pselect6     = 270,
  ppoll        = 271,
  unshare      = 272,
  set_robust_list = 273,
  get_robust_list = 274,
  splice       = 275,
  tee          = 276,
  sync_file_range = 277,
  vmsplice     = 278,
  move_pages   = 279,
  utimensat    = 280,
  epoll_pwait  = 281,
  signalfd     = 282,
  timerfd_create = 283,
  eventfd      = 284,
  fallocate    = 285,
  timerfd_settime = 286,
  timerfd_gettime = 287,
  accept4      = 288,
  signalfd4    = 289,
  eventfd2     = 290,
  epoll_create1 = 291,
  dup3         = 292,
  pipe2        = 293,
  inotify_init1 = 294,
  preadv       = 295,
  pwritev      = 296,
  rt_tgsigqueueinfo = 297,
  perf_event_open = 298,
  recvmmsg     = 299,
  fanotify_init = 300,
  fanotify_mark = 301,
  prlimit64    = 302,
  name_to_handle_at = 303,
  open_by_handle_at = 304,
  clock_adjtime = 305,
  syncfs       = 306,
  sendmmsg     = 307,
  setns        = 308,
  getcpu       = 309,
  process_vm_readv = 310,
  process_vm_writev = 311,
  kcmp         = 312,
  finit_module = 313,
  sched_setattr= 314,
  sched_getattr= 315,
  renameat2    = 316,
  seccomp      = 317,
  getrandom    = 318,
  memfd_create = 319,
  kexec_file_load = 320,
  bpf          = 321,
}
}

nr.SYS.fstatat = nr.SYS.newfstatat

return nr

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.arm64.ffi"],"module already exists")sources["syscall.linux.arm64.ffi"]=([===[-- <pack syscall.linux.arm64.ffi> --
-- arm64 specific definitions

return {
  ucontext = [[
typedef unsigned long greg_t;
typedef unsigned long gregset_t[34];
typedef struct {
  long double vregs[32];
  unsigned int fpsr;
  unsigned int fpcr;
} fpregset_t;
typedef struct sigcontext
{
  unsigned long fault_address;
  unsigned long regs[31];
  unsigned long sp, pc, pstate;
  long double __reserved[256];
} mcontext_t;
typedef struct __ucontext {
  unsigned long uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  sigset_t uc_sigmask;
  mcontext_t uc_mcontext;
} ucontext_t;
]],
  stat = [[
struct stat {
  unsigned long   st_dev;
  unsigned long   st_ino;
  unsigned int    st_mode;
  unsigned int    st_nlink;
  unsigned int    st_uid;
  unsigned int    st_gid;
  unsigned long   st_rdev;
  unsigned long   __pad1;
  long            st_size;
  int             st_blksize;
  int             __pad2;
  long            st_blocks;
  long            st_atime;
  unsigned long   st_atime_nsec;
  long            st_mtime;
  unsigned long   st_mtime_nsec;
  long            st_ctime;
  unsigned long   st_ctime_nsec;
  unsigned int    __unused4;
  unsigned int    __unused5;
};
]],
  statfs = [[
struct statfs64 {
  unsigned long f_type, f_bsize;
  fsblkcnt_t f_blocks, f_bfree, f_bavail;
  fsfilcnt_t f_files, f_ffree;
  fsid_t f_fsid;
  unsigned long f_namelen, f_frsize, f_flags, f_spare[4];
};
]],
}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.arm.ioctl"],"module already exists")sources["syscall.linux.arm.ioctl"]=([===[-- <pack syscall.linux.arm.ioctl> --
-- ARM ioctl differences

local arch = {
  ioctl = {
    FIOQSIZE = 0x545E,
  }
}

return arch

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["syscall.linux.ppc.ffi"],"module already exists")sources["syscall.linux.ppc.ffi"]=([===[-- <pack syscall.linux.ppc.ffi> --
-- ppc specific definitions

return {
  termios = [[
struct termios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_cc[19];
  cc_t c_line;
  speed_t c_ispeed;
  speed_t c_ospeed;
};
]],
  ucontext = [[
typedef unsigned long greg_t, gregset_t[48];
typedef struct {
  double fpregs[32];
  double fpscr;
  unsigned _pad[2];
} fpregset_t;
typedef struct {
  unsigned vrregs[32][4];
  unsigned vrsave;
  unsigned _pad[2];
  unsigned vscr;
} vrregset_t;
typedef struct {
  gregset_t gregs;
  fpregset_t fpregs;
  vrregset_t vrregs __attribute__((__aligned__(16)));
} mcontext_t;
typedef struct ucontext {
  unsigned long int uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  int uc_pad[7];
  union uc_regs_ptr {
    struct pt_regs *regs;
    mcontext_t *uc_regs;
  } uc_mcontext;
  sigset_t    uc_sigmask;
  char uc_reg_space[sizeof(mcontext_t) + 12];  /* last for extensibility */
} ucontext_t;
]],
  stat = [[
struct stat {
  unsigned long long st_dev;
  unsigned long long st_ino;
  unsigned int    st_mode;
  unsigned int    st_nlink;
  unsigned int    st_uid;
  unsigned int    st_gid;
  unsigned long long st_rdev;
  unsigned long long __pad1;
  long long       st_size;
  int             st_blksize;
  int             __pad2;
  long long       st_blocks;
  int             st_atime;
  unsigned int    st_atime_nsec;
  int             st_mtime;
  unsigned int    st_mtime_nsec;
  int             st_ctime;
  unsigned int    st_ctime_nsec;
  unsigned int    __unused4;
  unsigned int    __unused5;
};
]],
}

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
local add
--if not pcall(function() add = require"aioruntime".add end) then
	local loadstring=_G.loadstring or _G.load; local preload = require"package".preload
	add = function(name, rawcode)
		if preload[name] and putwarning and type(putwarning)=="function" then
			putwarning("WARNING: overwrite "..name)
		end
		preload[name] = function(...) return assert(loadstring(rawcode), "loadstring: "..name.." failed")(...) end
		preload[name..".__bundle"] = function() return {_BUNDLE=true,_BUNDLEFORMAT="v0.1.0.alpha1",_BUNDLEOF=name} end
	end
--end
for name, rawcode in pairs(sources) do add(name, rawcode, priorities[name]) end
end; --}};
do -- preload auto aliasing...
	local p = require("package").preload
	for k,v in pairs(p) do
		if k:find("%.init$") then
			local short = k:gsub("%.init$", "")
			if not p[short] then
				p[short] = v
			end
		end
	end
end
-- this puts everything into one table ready to use

local require, print, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string, math = 
require, print, error, assert, tonumber, tostring,
setmetatable, pairs, ipairs, unpack, rawget, rawset,
pcall, type, table, string, math

local abi = require "syscall.abi"

if abi.rump and abi.types then abi.os = abi.types end -- pretend to be NetBSD for normal rump, Linux for rumplinux

if abi.os == "netbsd" then
  -- TODO merge
  require("syscall.netbsd.ffitypes")
  if not abi.rump then
    require("syscall.netbsd.ffifunctions")
  end
else
  require("syscall." .. abi.os .. ".ffi")
end

local c = require("syscall." .. abi.os .. ".constants")

local ostypes = require("syscall." .. abi.os .. ".types")
local bsdtypes
if (abi.rump and abi.types == "netbsd") or (not abi.rump and abi.bsd) then
  bsdtypes = require("syscall.bsd.types")
end
local types = require "syscall.types".init(c, ostypes, bsdtypes)

local C
if abi.rump then -- TODO merge these with conditionals
  C = require("syscall.rump.c")
else
  C = require("syscall." .. abi.os .. ".c")
end

-- cannot put in S, needed for tests, cannot be put in c earlier due to deps TODO remove see #94
c.IOCTL = require("syscall." .. abi.os .. ".ioctl").init(types)

local S = require "syscall.syscalls".init(C, c, types)

S.abi, S.types, S.t, S.c = abi, types, types.t, c -- add to main table returned

-- add compatibility code
S = require "syscall.compat".init(S)

-- add functions from libc
S = require "syscall.libc".init(S)

-- add methods
S = require "syscall.methods".init(S)

-- add utils
S.util = require "syscall.util".init(S)

if abi.os == "linux" then
  S.cgroup = require "syscall.linux.cgroup".init(S)
  S.nl = require "syscall.linux.nl".init(S)
  -- TODO add the other Linux specific modules here
end

S._VERSION = "v0.11pre"
S._DESCRIPTION = "ljsyscall: A Unix system call API for LuaJIT"
S._COPYRIGHT = "Copyright (C) 2011-2014 Justin Cormack. MIT licensed."

return S

