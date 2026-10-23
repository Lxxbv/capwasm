// CapWasm Virtual File System (VFS) and WASI Test Suite

///|
test "vfs: path canonicalization normal paths" {
  assert_eq(@capwasm.canonicalize_path("/"), Ok("/"))
  assert_eq(@capwasm.canonicalize_path("/a/b/c"), Ok("/a/b/c"))
  assert_eq(@capwasm.canonicalize_path("a/b/c"), Ok("/a/b/c"))
  assert_eq(@capwasm.canonicalize_path("./a/./b/./c"), Ok("/a/b/c"))
  assert_eq(@capwasm.canonicalize_path("/a/b/../c"), Ok("/a/c"))
  assert_eq(@capwasm.canonicalize_path("/a/b/c/../../d"), Ok("/a/d"))
}

///|
test "vfs: path canonicalization blocks path traversal attacks" {
  let r1 = @capwasm.canonicalize_path("/..")
  assert_eq(r1, Err(@capwasm.SecurityError::PathTraversalAttempt("/..")))

  let r2 = @capwasm.canonicalize_path("/a/../../etc/passwd")
  assert_eq(
    r2,
    Err(@capwasm.SecurityError::PathTraversalAttempt("/a/../../etc/passwd")),
  )

  let r3 = @capwasm.canonicalize_path("../../secret.key")
  assert_eq(
    r3,
    Err(@capwasm.SecurityError::PathTraversalAttempt("../../secret.key")),
  )
}

///|
test "vfs: in-memory file create, read, write" {
  let vfs = @capwasm.VirtualFileSystem::new()
  let content : Array[Byte] = [b'\x48', b'\x65', b'\x6c', b'\x6c', b'\x6f']
  let res = vfs.create_file("/workspace/hello.txt", content)
  assert_true(res is Ok(_))

  assert_eq(vfs.exists("/workspace/hello.txt"), true)
  assert_eq(vfs.exists("/workspace/nonexistent.txt"), false)

  let read_res = vfs.read_file("/workspace/hello.txt")
  assert_eq(read_res, Ok(content))
}

///|
test "vfs: in-memory file seek operations" {
  let initial : Array[Byte] = [b'\x01', b'\x02', b'\x03', b'\x04', b'\x05']
  let file = @capwasm.InMemoryFile::new("/test.bin", initial)

  // Seek SET
  assert_eq(file.seek(2, 0), Ok(2))
  let chunk1 = file.read(2)
  assert_eq(chunk1, [b'\x03', b'\x04'])

  // Seek CUR
  assert_eq(file.seek(-1, 1), Ok(3))
  let chunk2 = file.read(1)
  assert_eq(chunk2, [b'\x04'])

  // Seek END
  assert_eq(file.seek(0, 2), Ok(5))
  let chunk3 = file.read(1)
  assert_eq(chunk3, [])
}

///|
test "vfs: wasi fd table stdio operations" {
  let table = @capwasm.WasiFdTable::new()

  // Stdout write
  let out_bytes : Array[Byte] = [b'\x50', b'\x41', b'\x53', b'\x53']
  let w_res = table.write(1, out_bytes)
  assert_eq(w_res, Ok(4))
  assert_eq(table.get_stdout_string(), "PASS")

  // Stderr write
  let err_bytes : Array[Byte] = [b'\x45', b'\x52', b'\x52']
  let e_res = table.write(2, err_bytes)
  assert_eq(e_res, Ok(3))
  assert_eq(table.get_stderr_string(), "ERR")

  // Closing standard handles rejected
  assert_eq(table.close_fd(0), Err(@capwasm.wasi_errno_access))
  assert_eq(table.close_fd(1), Err(@capwasm.wasi_errno_access))
}

///|
test "vfs: wasi dynamic file open, read, write, close" {
  let table = @capwasm.WasiFdTable::new()
  let file = @capwasm.InMemoryFile::new("/data.txt", [b'\x41', b'\x42'])

  let fd = table.open_file(file, @capwasm.OpenFlags::read_write())
  assert_true(fd >= 3)

  let read_data = table.read(fd, 2)
  assert_eq(read_data, Ok([b'\x41', b'\x42']))

  let write_len = table.write(fd, [b'\x43', b'\x44'])
  assert_eq(write_len, Ok(2))

  assert_eq(table.close_fd(fd), Ok(()))
  assert_eq(table.read(fd, 1), Err(@capwasm.wasi_errno_badf))
}
