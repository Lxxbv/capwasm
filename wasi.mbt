// CapWasm: Complete Capability-Guarded WASI (`wasi_snapshot_preview1`) System Call Layer
// Bridges standard WASI preview1 imports (19 syscalls) to CapWasm's in-memory VFS,
// virtual path mounts (`ExtismPathMount`), and `PluginSecurityGuard` audit ledger.

///|
/// WasiEnvironment holds per-plugin WASI arguments, environment variables, preopened mounts,
/// virtual monotonic clock, and deterministic PRNG state.
pub(all) struct WasiEnvironment {
  args : Array[String]
  env_vars : Array[(String, String)]
  mounts : Array[ExtismPathMount]
  mut virtual_clock_ns : Int64
  mut prng_state : UInt64
  mut last_exit_code : Int32?
}

///|
pub fn WasiEnvironment::new() -> WasiEnvironment {
  {
    args: ["plugin.wasm"],
    env_vars: [],
    mounts: [],
    virtual_clock_ns: 1700000000000000000L,
    prng_state: 0x853C49E6748FEA9BUL,
    last_exit_code: None,
  }
}

///|
pub fn WasiEnvironment::add_arg(self : WasiEnvironment, arg : String) -> Unit {
  self.args.push(arg)
}

///|
pub fn WasiEnvironment::set_env(
  self : WasiEnvironment,
  key : String,
  value : String,
) -> Unit {
  for i = 0; i < self.env_vars.length(); i = i + 1 {
    let (k, _) = self.env_vars[i]
    if k == key {
      self.env_vars[i] = (key, value)
      return
    }
  }
  self.env_vars.push((key, value))
}

///|
pub fn WasiEnvironment::add_mount(
  self : WasiEnvironment,
  mount : ExtismPathMount,
) -> Unit {
  self.mounts.push(mount)
}

///|
/// Generates the next deterministic pseudo-random byte using xorshift64*.
pub fn WasiEnvironment::next_random_byte(self : WasiEnvironment) -> Byte {
  let mut x = self.prng_state
  x = x ^ (x >> 12)
  x = x ^ (x << 25)
  x = x ^ (x >> 27)
  self.prng_state = x
  let r = x * 2685821657736338717UL
  ((r >> 32) & 0xFFUL).to_int().to_byte()
}

///|
/// Registers all 19 standard `wasi_snapshot_preview1` system calls into `Linker`,
/// enforcing `PluginSecurityGuard` capability policies on every I/O, clock, and env operation.
pub fn register_wasi_preview1_host_functions(
  linker : Linker,
  sec_guard : PluginSecurityGuard,
  vfs : VirtualFileSystem,
  fd_table : WasiFdTable,
  wasi_env : WasiEnvironment,
) -> Unit {
  let ns = "wasi_snapshot_preview1"

  // 1. args_sizes_get(argc_ptr: i32, argv_buf_size_ptr: i32) -> i32
  linker.register_func(
    ns,
    "args_sizes_get",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32]),
      fn(ctx, args) {
        let argc_ptr = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let buf_size_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let mut total_bytes = 0
        for a in wasi_env.args {
          total_bytes = total_bytes + a.length() + 1
        }
        let _ = mem.write_i32(argc_ptr, wasi_env.args.length())
        let _ = mem.write_i32(buf_size_ptr, total_bytes)
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 2. args_get(argv_ptr: i32, argv_buf_ptr: i32) -> i32
  linker.register_func(
    ns,
    "args_get",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32]),
      fn(ctx, args) {
        let argv_ptr = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let mut buf_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        for i = 0; i < wasi_env.args.length(); i = i + 1 {
          let arg_str = wasi_env.args[i]
          let _ = mem.write_i32(argv_ptr + i * 4, buf_ptr)
          let _ = mem.write_string(buf_ptr, arg_str)
          let _ = mem.write_u8(buf_ptr + arg_str.length(), 0)
          buf_ptr = buf_ptr + arg_str.length() + 1
        }
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 3. environ_sizes_get(envc_ptr: i32, env_buf_size_ptr: i32) -> i32
  linker.register_func(
    ns,
    "environ_sizes_get",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32]),
      fn(ctx, args) {
        let envc_ptr = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let buf_size_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let mut count = 0
        let mut total_bytes = 0
        for item in wasi_env.env_vars {
          let (k, v) = item
          match sec_guard.check_env(k) {
            Ok(_) => {
              count = count + 1
              total_bytes = total_bytes + k.length() + 1 + v.length() + 1
            }
            Err(_) => ()
          }
        }
        let _ = mem.write_i32(envc_ptr, count)
        let _ = mem.write_i32(buf_size_ptr, total_bytes)
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 4. environ_get(environ_ptr: i32, environ_buf_ptr: i32) -> i32
  linker.register_func(
    ns,
    "environ_get",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32]),
      fn(ctx, args) {
        let env_ptr = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let mut buf_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let mut idx = 0
        for item in wasi_env.env_vars {
          let (k, v) = item
          // Check against policy without duplicating audit logs if already checked
          let mut allowed = false
          for a in sec_guard.policy.allowed_env_vars {
            if a == "*" || a == k {
              allowed = true
              break
            }
          }
          if allowed {
            let entry = k + "=" + v
            let _ = mem.write_i32(env_ptr + idx * 4, buf_ptr)
            let _ = mem.write_string(buf_ptr, entry)
            let _ = mem.write_u8(buf_ptr + entry.length(), 0)
            buf_ptr = buf_ptr + entry.length() + 1
            idx = idx + 1
          }
        }
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 5. clock_res_get(clock_id: i32, resolution_ptr: i32) -> i32
  linker.register_func(
    ns,
    "clock_res_get",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32]),
      fn(ctx, args) {
        let res_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        match sec_guard.check_clock() {
          Ok(_) => ()
          Err(_) => return Ok([Value::I32(wasi_errno_access)])
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let _ = mem.write_i64(res_ptr, 1000L) // 1 microsecond resolution
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 6. clock_time_get(clock_id: i32, precision: i64, time_ptr: i32) -> i32
  linker.register_func(
    ns,
    "clock_time_get",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I64, ValueType::I32], [
        ValueType::I32,
      ]),
      fn(ctx, args) {
        let time_ptr = match args[2] {
          Value::I32(v) => v
          _ => 0
        }
        match sec_guard.check_clock() {
          Ok(_) => ()
          Err(_) => return Ok([Value::I32(wasi_errno_access)])
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        wasi_env.virtual_clock_ns = wasi_env.virtual_clock_ns + 1000000L
        let _ = mem.write_i64(time_ptr, wasi_env.virtual_clock_ns)
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 7. fd_prestat_get(fd: i32, prestat_ptr: i32) -> i32
  linker.register_func(
    ns,
    "fd_prestat_get",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32]),
      fn(ctx, args) {
        let fd = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let prestat_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let mount_idx = fd - 3
        if mount_idx < 0 || mount_idx >= wasi_env.mounts.length() {
          return Ok([Value::I32(wasi_errno_badf)])
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let guest_dir = wasi_env.mounts[mount_idx].guest_path
        let _ = mem.write_u8(prestat_ptr, 0) // __WASI_PREOPENTYPE_DIR = 0
        let _ = mem.write_i32(prestat_ptr + 4, guest_dir.length())
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 8. fd_prestat_dir_name(fd: i32, path_ptr: i32, path_len: i32) -> i32
  linker.register_func(
    ns,
    "fd_prestat_dir_name",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32, ValueType::I32], [
        ValueType::I32,
      ]),
      fn(ctx, args) {
        let fd = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let path_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let path_len = match args[2] {
          Value::I32(v) => v
          _ => 0
        }
        let mount_idx = fd - 3
        if mount_idx < 0 || mount_idx >= wasi_env.mounts.length() {
          return Ok([Value::I32(wasi_errno_badf)])
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let guest_dir = wasi_env.mounts[mount_idx].guest_path
        let copy_len = if guest_dir.length() < path_len {
          guest_dir.length()
        } else {
          path_len
        }
        for i = 0; i < copy_len; i = i + 1 {
          let _ = mem.write_u8(path_ptr + i, guest_dir[i].to_int())
        }
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 9. fd_fdstat_get(fd: i32, fdstat_ptr: i32) -> i32
  linker.register_func(
    ns,
    "fd_fdstat_get",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32]),
      fn(ctx, args) {
        let fd = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let fdstat_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let _ = mem.fill(fdstat_ptr, b'\x00', 24)
        // filetype: 2 for char device (stdin/out/err), 3 for directory, 4 for regular file
        let ftype = if fd >= 0 && fd <= 2 { 2 } else { 4 }
        let _ = mem.write_u8(fdstat_ptr, ftype)
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 10. fd_fdstat_set_flags(fd: i32, flags: i32) -> i32
  linker.register_func(
    ns,
    "fd_fdstat_set_flags",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32]),
      fn(_ctx, _args) { Ok([Value::I32(wasi_errno_success)]) },
    ),
  )

  // 11. path_open(dirfd, dirflags, path_ptr, path_len, oflags, rights_base, rights_inh, fdflags, opened_fd_ptr) -> i32
  linker.register_func(
    ns,
    "path_open",
    HostFunction::new(
      FuncType::new(
        [
          ValueType::I32,
          ValueType::I32,
          ValueType::I32,
          ValueType::I32,
          ValueType::I32,
          ValueType::I64,
          ValueType::I64,
          ValueType::I32,
          ValueType::I32,
        ],
        [ValueType::I32],
      ),
      fn(ctx, args) {
        let path_ptr = match args[2] {
          Value::I32(v) => v
          _ => 0
        }
        let path_len = match args[3] {
          Value::I32(v) => v
          _ => 0
        }
        let oflags = match args[4] {
          Value::I32(v) => v
          _ => 0
        }
        let rights_base = match args[5] {
          Value::I64(v) => v
          _ => 0L
        }
        let opened_fd_ptr = match args[8] {
          Value::I32(v) => v
          _ => 0
        }

        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let raw_guest_path = match mem.read_string(path_ptr, path_len) {
          Ok(s) => s
          Err(e) => return Err(e)
        }

        // Determine if write/create is requested (O_CREAT=1, O_TRUNC=8, or __WASI_RIGHT_FD_WRITE=64)
        let wants_create = (oflags & 1) != 0
        let wants_trunc = (oflags & 8) != 0
        let wants_write = wants_create ||
          wants_trunc ||
          (rights_base & 64L) != 0L

        // Resolve guest path through ExtismPathMount table if mounts are configured
        let host_path = match
          resolve_mounted_path(wasi_env.mounts, raw_guest_path, wants_write) {
          Ok(hp) => hp
          Err(_) => {
            // Record audit failure via security guard
            let _ = if wants_write {
              sec_guard.check_fs_write(raw_guest_path)
            } else {
              sec_guard.check_fs_read(raw_guest_path)
            }
            return Ok([Value::I32(wasi_errno_access)])
          }
        }

        // Enforce PluginSecurityGuard capability check on the resolved host VFS path
        if wants_write {
          match sec_guard.check_fs_write(host_path) {
            Ok(_) => ()
            Err(_) => return Ok([Value::I32(wasi_errno_access)])
          }
        } else {
          match sec_guard.check_fs_read(host_path) {
            Ok(_) => ()
            Err(_) => return Ok([Value::I32(wasi_errno_access)])
          }
        }

        let canonical_hp = match canonicalize_path(host_path) {
          Ok(p) => p
          Err(_) => return Ok([Value::I32(wasi_errno_access)])
        }

        let file_obj = match vfs.find_file(canonical_hp) {
          Some(f) => {
            if wants_trunc {
              f.data = []
            }
            f.cursor = 0
            f
          }
          None =>
            if wants_create {
              match vfs.create_file(canonical_hp, []) {
                Ok(f) => f
                Err(_) => return Ok([Value::I32(wasi_errno_access)])
              }
            } else {
              return Ok([Value::I32(wasi_errno_noent)])
            }
        }

        let flags = if wants_write {
          OpenFlags::read_write()
        } else {
          OpenFlags::read_only()
        }
        let new_fd = fd_table.open_file(file_obj, flags)
        let _ = mem.write_i32(opened_fd_ptr, new_fd)
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 12. fd_read(fd: i32, iovs_ptr: i32, iovs_len: i32, nread_ptr: i32) -> i32
  linker.register_func(
    ns,
    "fd_read",
    HostFunction::new(
      FuncType::new(
        [ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32],
        [ValueType::I32],
      ),
      fn(ctx, args) {
        let fd = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let iovs_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let iovs_len = match args[2] {
          Value::I32(v) => v
          _ => 0
        }
        let nread_ptr = match args[3] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let mut total_read = 0
        for i = 0; i < iovs_len; i = i + 1 {
          let base_off = iovs_ptr + i * 8
          let buf_ptr = match mem.read_i32(base_off) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let buf_len = match mem.read_i32(base_off + 4) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          match fd_table.read(fd, buf_len) {
            Ok(chunk) => {
              for j = 0; j < chunk.length(); j = j + 1 {
                let _ = mem.write_u8(buf_ptr + j, chunk[j].to_int())
              }
              total_read = total_read + chunk.length()
            }
            Err(errno) => return Ok([Value::I32(errno)])
          }
        }
        let _ = mem.write_i32(nread_ptr, total_read)
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 13. fd_write(fd: i32, iovs_ptr: i32, iovs_len: i32, nwritten_ptr: i32) -> i32
  linker.register_func(
    ns,
    "fd_write",
    HostFunction::new(
      FuncType::new(
        [ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32],
        [ValueType::I32],
      ),
      fn(ctx, args) {
        let fd = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let iovs_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let iovs_len = match args[2] {
          Value::I32(v) => v
          _ => 0
        }
        let nwritten_ptr = match args[3] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let mut total_written = 0
        for i = 0; i < iovs_len; i = i + 1 {
          let base_off = iovs_ptr + i * 8
          let buf_ptr = match mem.read_i32(base_off) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let buf_len = match mem.read_i32(base_off + 4) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let bytes = match mem.read_bytes(buf_ptr, buf_len) {
            Ok(b) => b
            Err(e) => return Err(e)
          }
          match fd_table.write(fd, bytes) {
            Ok(w) => total_written = total_written + w
            Err(errno) => return Ok([Value::I32(errno)])
          }
        }
        let _ = mem.write_i32(nwritten_ptr, total_written)
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 14. fd_seek(fd: i32, offset: i64, whence: i32, newoffset_ptr: i32) -> i32
  linker.register_func(
    ns,
    "fd_seek",
    HostFunction::new(
      FuncType::new(
        [ValueType::I32, ValueType::I64, ValueType::I32, ValueType::I32],
        [ValueType::I32],
      ),
      fn(ctx, args) {
        let fd = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let delta = match args[1] {
          Value::I64(v) => v.to_int()
          _ => 0
        }
        let whence = match args[2] {
          Value::I32(v) => v
          _ => 0
        }
        let newoffset_ptr = match args[3] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        match fd_table.seek(fd, delta, whence) {
          Ok(new_off) => {
            let _ = mem.write_i64(newoffset_ptr, new_off.to_int64())
            Ok([Value::I32(wasi_errno_success)])
          }
          Err(errno) => Ok([Value::I32(errno)])
        }
      },
    ),
  )

  // 15. fd_sync(fd: i32) -> i32
  linker.register_func(
    ns,
    "fd_sync",
    HostFunction::new(FuncType::new([ValueType::I32], [ValueType::I32]), fn(
      _ctx,
      _args,
    ) {
      Ok([Value::I32(wasi_errno_success)])
    }),
  )

  // 16. fd_close(fd: i32) -> i32
  linker.register_func(
    ns,
    "fd_close",
    HostFunction::new(FuncType::new([ValueType::I32], [ValueType::I32]), fn(
      _ctx,
      args,
    ) {
      let fd = match args[0] {
        Value::I32(v) => v
        _ => 0
      }
      match fd_table.close_fd(fd) {
        Ok(_) => Ok([Value::I32(wasi_errno_success)])
        Err(errno) => Ok([Value::I32(errno)])
      }
    }),
  )

  // 17. path_unlink_file(dirfd: i32, path_ptr: i32, path_len: i32) -> i32
  linker.register_func(
    ns,
    "path_unlink_file",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32, ValueType::I32], [
        ValueType::I32,
      ]),
      fn(ctx, args) {
        let path_ptr = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let path_len = match args[2] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let raw_path = match mem.read_string(path_ptr, path_len) {
          Ok(s) => s
          Err(e) => return Err(e)
        }
        let host_path = match
          resolve_mounted_path(wasi_env.mounts, raw_path, true) {
          Ok(hp) => hp
          Err(_) => return Ok([Value::I32(wasi_errno_access)])
        }
        match sec_guard.check_fs_write(host_path) {
          Ok(_) => ()
          Err(_) => return Ok([Value::I32(wasi_errno_access)])
        }
        match vfs.remove_file(host_path) {
          Ok(_) => Ok([Value::I32(wasi_errno_success)])
          Err(_) => Ok([Value::I32(wasi_errno_noent)])
        }
      },
    ),
  )

  // 18. random_get(buf_ptr: i32, buf_len: i32) -> i32
  linker.register_func(
    ns,
    "random_get",
    HostFunction::new(
      FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32]),
      fn(ctx, args) {
        let buf_ptr = match args[0] {
          Value::I32(v) => v
          _ => 0
        }
        let buf_len = match args[1] {
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        for i = 0; i < buf_len; i = i + 1 {
          let rb = wasi_env.next_random_byte()
          match mem.write_u8(buf_ptr + i, rb.to_int()) {
            Ok(_) => ()
            Err(e) => return Err(e)
          }
        }
        Ok([Value::I32(wasi_errno_success)])
      },
    ),
  )

  // 19. proc_exit(exit_code: i32) -> ()
  linker.register_func(
    ns,
    "proc_exit",
    HostFunction::new(FuncType::new([ValueType::I32], []), fn(_ctx, args) {
      let code = match args[0] {
        Value::I32(v) => v
        _ => 0
      }
      wasi_env.last_exit_code = Some(code)
      if code != 0 {
        Err(
          Trap::HostError(
            "WASI proc_exit called with non-zero status: " + code.to_string(),
          ),
        )
      } else {
        Ok([])
      }
    }),
  )
}
