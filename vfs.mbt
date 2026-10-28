// CapWasm: Virtual File System (VFS) and WASI Abstraction Layer
// Provides sandboxed, capability-gated in-memory filesystem and POSIX/WASI file descriptor table.

///|
/// File open flags for VFS operations.
pub(all) struct OpenFlags {
  read : Bool
  write : Bool
  create : Bool
  truncate : Bool
  append : Bool
} derive(Eq)

///|
pub fn OpenFlags::read_only() -> OpenFlags {
  { read: true, write: false, create: false, truncate: false, append: false, }
}

///|
pub fn OpenFlags::write_only() -> OpenFlags {
  { read: false, write: true, create: true, truncate: false, append: false, }
}

///|
pub fn OpenFlags::read_write() -> OpenFlags {
  { read: true, write: true, create: true, truncate: false, append: false, }
}

///|
/// Standard WASI errno codes.
pub let wasi_errno_success : Int32 = 0

///|
pub let wasi_errno_access : Int32 = 2

///|
pub let wasi_errno_badf : Int32 = 8

///|
pub let wasi_errno_inval : Int32 = 28

///|
pub let wasi_errno_noent : Int32 = 44

///|
pub let wasi_errno_exist : Int32 = 20

///|
pub let wasi_errno_overflow : Int32 = 61

///|
/// In-memory File node within the Virtual File System.
pub(all) struct InMemoryFile {
  path : String
  mut data : Array[Byte]
  mut cursor : Int32
  mut is_open : Bool
}

///|
pub fn InMemoryFile::new(
  path : String,
  initial_content : Array[Byte],
) -> InMemoryFile {
  { path, data: initial_content, cursor: 0, is_open: true, }
}

///|
pub fn InMemoryFile::read(
  self : InMemoryFile,
  max_bytes : Int32,
) -> Array[Byte] {
  let available = self.data.length() - self.cursor
  if available <= 0 || max_bytes <= 0 {
    return []
  }
  let to_read = if max_bytes < available { max_bytes } else { available }
  let result = Array::make(to_read, b'\x00')
  for i = 0; i < to_read; i = i + 1 {
    result[i] = self.data[self.cursor + i]
  }
  self.cursor = self.cursor + to_read
  result
}

///|
pub fn InMemoryFile::write(self : InMemoryFile, bytes : Array[Byte]) -> Int32 {
  let len = bytes.length()
  for i = 0; i < len; i = i + 1 {
    let pos = self.cursor + i
    if pos < self.data.length() {
      self.data[pos] = bytes[i]
    } else {
      self.data.push(bytes[i])
    }
  }
  self.cursor = self.cursor + len
  len
}

///|
pub fn InMemoryFile::seek(
  self : InMemoryFile,
  offset : Int32,
  whence : Int32,
) -> Result[Int32, Int32] {
  // whence: 0 = SET, 1 = CUR, 2 = END
  let new_pos = match whence {
    0 => offset
    1 => self.cursor + offset
    2 => self.data.length() + offset
    _ => return Err(wasi_errno_inval)
  }
  if new_pos < 0 {
    return Err(wasi_errno_inval)
  }
  self.cursor = new_pos
  Ok(self.cursor)
}

///|
/// Directory node containing registered child entries.
pub(all) struct InMemoryDirectory {
  path : String
  subdirectories : Array[String]
  files : Array[String]
}

///|
pub fn InMemoryDirectory::new(path : String) -> InMemoryDirectory {
  { path, subdirectories: [], files: [], }
}

///|
/// Path normalizer: resolves '.' and '..' components safely.
pub fn canonicalize_path(raw_path : String) -> Result[String, SecurityError] {
  if raw_path.length() == 0 {
    return Ok("/")
  }

  // Split path into segments by '/' or '\\'
  let segments = Array::new()
  let buf = StringBuilder::new()
  for i = 0; i < raw_path.length(); i = i + 1 {
    let c = raw_path[i]
    if c == '/' || c == '\\' {
      let seg = buf.to_string()
      if seg.length() > 0 {
        segments.push(seg)
      }
      buf.reset()
    } else {
      buf.write_char(c.to_int().unsafe_to_char())
    }
  }
  let last_seg = buf.to_string()
  if last_seg.length() > 0 {
    segments.push(last_seg)
  }

  // Process segments
  let stack = Array::new()
  for seg in segments {
    if seg == "." {
      // current directory, skip
      continue
    } else if seg == ".." {
      if stack.length() > 0 {
        let _ = stack.pop()
      } else {
        // Escaping root boundary is a path traversal violation
        return Err(SecurityError::PathTraversalAttempt(raw_path))
      }
    } else {
      stack.push(seg)
    }
  }

  // Reconstruct canonical path
  if stack.length() == 0 {
    return Ok("/")
  }
  let out = StringBuilder::new()
  for seg in stack {
    out.write_char('/')
    out.write_string(seg)
  }
  Ok(out.to_string())
}

///|
/// Virtual File System table managing in-memory files and guest mount policies.
pub(all) struct VirtualFileSystem {
  files : Array[InMemoryFile]
  directories : Array[InMemoryDirectory]
  mounts : Array[(String, String)] // (guest_prefix, host_prefix)
}

///|
pub fn VirtualFileSystem::new() -> VirtualFileSystem {
  let vfs = { files: [], directories: [], mounts: [], }
  vfs.directories.push(InMemoryDirectory::new("/"))
  vfs
}

///|
pub fn VirtualFileSystem::mount(
  self : VirtualFileSystem,
  guest_prefix : String,
  host_prefix : String,
) -> Unit {
  self.mounts.push((guest_prefix, host_prefix))
}

///|
pub fn VirtualFileSystem::find_file(
  self : VirtualFileSystem,
  canonical_path : String,
) -> InMemoryFile? {
  for f in self.files {
    if f.path == canonical_path {
      return Some(f)
    }
  }
  None
}

///|
pub fn VirtualFileSystem::create_file(
  self : VirtualFileSystem,
  raw_path : String,
  initial_data : Array[Byte],
) -> Result[InMemoryFile, SecurityError] {
  let path = match canonicalize_path(raw_path) {
    Ok(p) => p
    Err(e) => return Err(e)
  }

  for f in self.files {
    if f.path == path {
      f.data = initial_data
      f.cursor = 0
      f.is_open = true
      return Ok(f)
    }
  }

  let new_file = InMemoryFile::new(path, initial_data)
  self.files.push(new_file)
  Ok(new_file)
}

///|
pub fn VirtualFileSystem::read_file(
  self : VirtualFileSystem,
  raw_path : String,
) -> Result[Array[Byte], SecurityError] {
  let path = match canonicalize_path(raw_path) {
    Ok(p) => p
    Err(e) => return Err(e)
  }

  match self.find_file(path) {
    Some(f) => {
      let copy = Array::make(f.data.length(), b'\x00')
      for i = 0; i < f.data.length(); i = i + 1 {
        copy[i] = f.data[i]
      }
      Ok(copy)
    }
    None =>
      Err(SecurityError::PermissionDenied("File not found in VFS: " + path))
  }
}

///|
pub fn VirtualFileSystem::write_file(
  self : VirtualFileSystem,
  raw_path : String,
  content : Array[Byte],
) -> Result[Int32, SecurityError] {
  let path = match canonicalize_path(raw_path) {
    Ok(p) => p
    Err(e) => return Err(e)
  }

  match self.find_file(path) {
    Some(f) => {
      f.data = content
      f.cursor = content.length()
      Ok(content.length())
    }
    None => {
      let _ = self.create_file(path, content)
      Ok(content.length())
    }
  }
}

///|
pub fn VirtualFileSystem::exists(
  self : VirtualFileSystem,
  raw_path : String,
) -> Bool {
  match canonicalize_path(raw_path) {
    Ok(p) =>
      match self.find_file(p) {
        Some(_) => true
        None => false
      }
    Err(_) => false
  }
}

///|
pub fn VirtualFileSystem::remove_file(
  self : VirtualFileSystem,
  raw_path : String,
) -> Result[Unit, SecurityError] {
  let path = match canonicalize_path(raw_path) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let mut idx = -1
  for i = 0; i < self.files.length(); i = i + 1 {
    if self.files[i].path == path {
      idx = i
      break
    }
  }
  if idx >= 0 {
    let _ = self.files.remove(idx)
    Ok(())
  } else {
    Err(SecurityError::PermissionDenied("File not found in VFS: " + path))
  }
}

///|
/// WASI File Descriptor entry.
pub(all) struct WasiFd {
  fd : Int32
  path : String
  file : InMemoryFile
  flags : OpenFlags
}

///|
/// WASI File Descriptor Table managing stdio (0, 1, 2) and open virtual files.
pub(all) struct WasiFdTable {
  fds : Array[WasiFd]
  mut next_fd : Int32
}

///|
pub fn WasiFdTable::new() -> WasiFdTable {
  let table = { fds: [], next_fd: 3, }
  // Stdin (fd 0)
  table.fds.push({
    fd: 0,
    path: "<stdin>",
    file: InMemoryFile::new("<stdin>", []),
    flags: OpenFlags::read_only(),
  })
  // Stdout (fd 1)
  table.fds.push({
    fd: 1,
    path: "<stdout>",
    file: InMemoryFile::new("<stdout>", []),
    flags: OpenFlags::write_only(),
  })
  // Stderr (fd 2)
  table.fds.push({
    fd: 2,
    path: "<stderr>",
    file: InMemoryFile::new("<stderr>", []),
    flags: OpenFlags::write_only(),
  })
  table
}

///|
pub fn WasiFdTable::get_fd(self : WasiFdTable, fd : Int32) -> WasiFd? {
  for item in self.fds {
    if item.fd == fd {
      return Some(item)
    }
  }
  None
}

///|
pub fn WasiFdTable::open_file(
  self : WasiFdTable,
  file : InMemoryFile,
  flags : OpenFlags,
) -> Int32 {
  let fd = self.next_fd
  self.next_fd = self.next_fd + 1
  self.fds.push({ fd, path: file.path, file, flags, })
  fd
}

///|
pub fn WasiFdTable::close_fd(
  self : WasiFdTable,
  fd : Int32,
) -> Result[Unit, Int32] {
  if fd < 3 {
    return Err(wasi_errno_access) // Protected standard handles
  }
  let mut target_idx = -1
  for i = 0; i < self.fds.length(); i = i + 1 {
    if self.fds[i].fd == fd {
      target_idx = i
      break
    }
  }
  if target_idx >= 0 {
    let _ = self.fds.remove(target_idx)
    Ok(())
  } else {
    Err(wasi_errno_badf)
  }
}

///|
pub fn WasiFdTable::read(
  self : WasiFdTable,
  fd : Int32,
  max_len : Int32,
) -> Result[Array[Byte], Int32] {
  match self.get_fd(fd) {
    Some(wasi_fd) => {
      if not(wasi_fd.flags.read) {
        return Err(wasi_errno_access)
      }
      Ok(wasi_fd.file.read(max_len))
    }
    None => Err(wasi_errno_badf)
  }
}

///|
pub fn WasiFdTable::write(
  self : WasiFdTable,
  fd : Int32,
  data : Array[Byte],
) -> Result[Int32, Int32] {
  match self.get_fd(fd) {
    Some(wasi_fd) => {
      if not(wasi_fd.flags.write) {
        return Err(wasi_errno_access)
      }
      Ok(wasi_fd.file.write(data))
    }
    None => Err(wasi_errno_badf)
  }
}

///|
pub fn WasiFdTable::seek(
  self : WasiFdTable,
  fd : Int32,
  offset : Int32,
  whence : Int32,
) -> Result[Int32, Int32] {
  match self.get_fd(fd) {
    Some(wasi_fd) => wasi_fd.file.seek(offset, whence)
    None => Err(wasi_errno_badf)
  }
}

///|
pub fn WasiFdTable::get_stdout_string(self : WasiFdTable) -> String {
  match self.get_fd(1) {
    Some(wasi_fd) => {
      let buf = StringBuilder::new()
      for b in wasi_fd.file.data {
        buf.write_char(Char::from_int(b.to_int()))
      }
      buf.to_string()
    }
    None => ""
  }
}

///|
pub fn WasiFdTable::get_stderr_string(self : WasiFdTable) -> String {
  match self.get_fd(2) {
    Some(wasi_fd) => {
      let buf = StringBuilder::new()
      for b in wasi_fd.file.data {
        buf.write_char(Char::from_int(b.to_int()))
      }
      buf.to_string()
    }
    None => ""
  }
}
