// CapWasm LEB128 Encoding and Decoding Test Suite

///|
test "leb128: u32 single byte boundaries" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_u32(0)
  writer.write_u32(1)
  writer.write_u32(63)
  writer.write_u32(127)

  let reader = @capwasm.BinaryReader::new(writer.to_bytes())
  assert_eq(reader.read_u32(), Ok(0))
  assert_eq(reader.read_u32(), Ok(1))
  assert_eq(reader.read_u32(), Ok(63))
  assert_eq(reader.read_u32(), Ok(127))
}

///|
test "leb128: u32 multibyte encoding" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_u32(128)
  writer.write_u32(255)
  writer.write_u32(16383)
  writer.write_u32(16384)
  writer.write_u32(2097151)
  writer.write_u32(2097152)

  let reader = @capwasm.BinaryReader::new(writer.to_bytes())
  assert_eq(reader.read_u32(), Ok(128))
  assert_eq(reader.read_u32(), Ok(255))
  assert_eq(reader.read_u32(), Ok(16383))
  assert_eq(reader.read_u32(), Ok(16384))
  assert_eq(reader.read_u32(), Ok(2097151))
  assert_eq(reader.read_u32(), Ok(2097152))
}

///|
test "leb128: u32 max int boundary" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_u32(0x7FFFFFFF)

  let reader = @capwasm.BinaryReader::new(writer.to_bytes())
  assert_eq(reader.read_u32(), Ok(0x7FFFFFFF))
}

///|
test "leb128: i32 positive small integers" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_i32(0)
  writer.write_i32(1)
  writer.write_i32(63)

  let reader = @capwasm.BinaryReader::new(writer.to_bytes())
  assert_eq(reader.read_i32(), Ok(0))
  assert_eq(reader.read_i32(), Ok(1))
  assert_eq(reader.read_i32(), Ok(63))
}

///|
test "leb128: i32 negative small integers" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_i32(-1)
  writer.write_i32(-2)
  writer.write_i32(-64)

  let reader = @capwasm.BinaryReader::new(writer.to_bytes())
  assert_eq(reader.read_i32(), Ok(-1))
  assert_eq(reader.read_i32(), Ok(-2))
  assert_eq(reader.read_i32(), Ok(-64))
}

///|
test "leb128: i32 negative multi-byte values" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_i32(-65)
  writer.write_i32(-128)
  writer.write_i32(-129)
  writer.write_i32(-1000)
  writer.write_i32(-65536)

  let reader = @capwasm.BinaryReader::new(writer.to_bytes())
  assert_eq(reader.read_i32(), Ok(-65))
  assert_eq(reader.read_i32(), Ok(-128))
  assert_eq(reader.read_i32(), Ok(-129))
  assert_eq(reader.read_i32(), Ok(-1000))
  assert_eq(reader.read_i32(), Ok(-65536))
}

///|
test "leb128: i32 extreme boundaries" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_i32(1000000)
  writer.write_i32(-1000000)

  let reader = @capwasm.BinaryReader::new(writer.to_bytes())
  assert_eq(reader.read_i32(), Ok(1000000))
  assert_eq(reader.read_i32(), Ok(-1000000))
}

///|
test "leb128: string name roundtrip" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_name("capwasm_export")
  writer.write_name("wasi_snapshot_preview1")
  writer.write_name("")

  let reader = @capwasm.BinaryReader::new(writer.to_bytes())
  assert_eq(reader.read_name(), Ok("capwasm_export"))
  assert_eq(reader.read_name(), Ok("wasi_snapshot_preview1"))
  assert_eq(reader.read_name(), Ok(""))
}

///|
test "leb128: reader byte array operations" {
  let bytes : Array[Byte] = [b'\x48', b'\x65', b'\x6c', b'\x6c', b'\x6f']
  let reader = @capwasm.BinaryReader::new(bytes)
  assert_eq(reader.remaining(), 5)
  assert_eq(reader.has_more(), true)

  let read_b = reader.read_bytes(5)
  assert_eq(read_b, Ok(bytes))
  assert_eq(reader.remaining(), 0)
  assert_eq(reader.has_more(), false)

  let eof = reader.read_byte()
  assert_eq(eof, Err(@capwasm.DecodeError::UnexpectedEof("read_byte")))
}
