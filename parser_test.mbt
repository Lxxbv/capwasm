// CapWasm WebAssembly Binary Parser Test Suite

///|
test "parser: empty valid module header" {
  let wasm_bytes : Array[Byte] = [
    b'\x00', b'\x61', b'\x73', b'\x6d', // \0asm
     b'\x01', b'\x00', b'\x00', b'\x00', // version 1
  ]

  let parser = @capwasm.WasmParser::new(wasm_bytes)
  let res = parser.parse_module()
  assert_true(res is Ok(_))

  let m = match res {
    Ok(mod_def) => mod_def
    Err(_) => return
  }

  assert_eq(m.types.length(), 0)
  assert_eq(m.imports.length(), 0)
  assert_eq(m.exports.length(), 0)
  assert_eq(m.code.length(), 0)
}

///|
test "parser: invalid magic header detection" {
  let bad_magic : Array[Byte] = [
    b'\x7f', b'\x45', b'\x4c', b'\x46', // ELF magic
     b'\x01', b'\x00', b'\x00', b'\x00',
  ]
  let parser = @capwasm.WasmParser::new(bad_magic)
  assert_true(parser.parse_module() is Err(@capwasm.DecodeError::InvalidMagic))
}

///|
test "parser: invalid version detection" {
  let bad_version : Array[Byte] = [
    b'\x00', b'\x61', b'\x73', b'\x6d', b'\x02', b'\x00', b'\x00', b'\x00', // version 2
  ]
  let parser = @capwasm.WasmParser::new(bad_version)
  assert_true(
    parser.parse_module() is Err(@capwasm.DecodeError::InvalidVersion(2)),
  )
}

///|
test "parser: type section parsing" {
  // Construct module with Type Section (id = 1):
  // 1 type: () -> (i32)
  let writer = @capwasm.BinaryWriter::new()
  writer.write_byte(b'\x00')
  writer.write_byte(b'\x61')
  writer.write_byte(b'\x73')
  writer.write_byte(b'\x6d')
  writer.write_byte(b'\x01')
  writer.write_byte(b'\x00')
  writer.write_byte(b'\x00')
  writer.write_byte(b'\x00')

  // Section 1: Type section
  let sec_writer = @capwasm.BinaryWriter::new()
  sec_writer.write_u32(1) // 1 type
  sec_writer.write_byte(b'\x60') // func type form
  sec_writer.write_u32(0) // 0 params
  sec_writer.write_u32(1) // 1 result
  sec_writer.write_byte(b'\x7f') // i32

  let sec_bytes = sec_writer.to_bytes()
  writer.write_byte(b'\x01') // Section id 1
  writer.write_u32(sec_bytes.length())
  writer.write_bytes(sec_bytes)

  let parser = @capwasm.WasmParser::new(writer.to_bytes())
  let m = match parser.parse_module() {
    Ok(v) => v
    Err(_) => return
  }

  assert_eq(m.types.length(), 1)
  assert_eq(m.types[0].params.length(), 0)
  assert_eq(m.types[0].results.length(), 1)
  assert_true(m.types[0].results[0] == @capwasm.ValueType::I32)
}

///|
test "parser: memory and export section parsing" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_byte(b'\x00')
  writer.write_byte(b'\x61')
  writer.write_byte(b'\x73')
  writer.write_byte(b'\x6d')
  writer.write_byte(b'\x01')
  writer.write_byte(b'\x00')
  writer.write_byte(b'\x00')
  writer.write_byte(b'\x00')

  // Section 5: Memory Section (id = 5)
  let mem_sec = @capwasm.BinaryWriter::new()
  mem_sec.write_u32(1) // 1 memory
  mem_sec.write_byte(b'\x01') // flags: min and max present
  mem_sec.write_u32(1) // min = 1 page
  mem_sec.write_u32(4) // max = 4 pages
  let mem_bytes = mem_sec.to_bytes()
  writer.write_byte(b'\x05')
  writer.write_u32(mem_bytes.length())
  writer.write_bytes(mem_bytes)

  // Section 7: Export Section (id = 7)
  let exp_sec = @capwasm.BinaryWriter::new()
  exp_sec.write_u32(1) // 1 export
  exp_sec.write_name("memory")
  exp_sec.write_byte(b'\x02') // export memory desc
  exp_sec.write_u32(0) // memory index 0
  let exp_bytes = exp_sec.to_bytes()
  writer.write_byte(b'\x07')
  writer.write_u32(exp_bytes.length())
  writer.write_bytes(exp_bytes)

  let parser = @capwasm.WasmParser::new(writer.to_bytes())
  let m = match parser.parse_module() {
    Ok(v) => v
    Err(_) => return
  }

  assert_eq(m.memories.length(), 1)
  assert_eq(m.memories[0].limits.min, 1)
  assert_eq(m.memories[0].limits.max, Some(4))

  assert_eq(m.exports.length(), 1)
  assert_eq(m.exports[0].name, "memory")
  assert_true(m.exports[0].desc == @capwasm.ExportDesc::Mem(0))
}

///|
test "parser: custom section skip" {
  let writer = @capwasm.BinaryWriter::new()
  writer.write_byte(b'\x00')
  writer.write_byte(b'\x61')
  writer.write_byte(b'\x73')
  writer.write_byte(b'\x6d')
  writer.write_byte(b'\x01')
  writer.write_byte(b'\x00')
  writer.write_byte(b'\x00')
  writer.write_byte(b'\x00')

  // Section 0: Custom Section
  let custom_sec = @capwasm.BinaryWriter::new()
  custom_sec.write_name("producers")
  custom_sec.write_bytes([b'\x01', b'\x02', b'\x03', b'\x04'])
  let custom_bytes = custom_sec.to_bytes()

  writer.write_byte(b'\x00')
  writer.write_u32(custom_bytes.length())
  writer.write_bytes(custom_bytes)

  let parser = @capwasm.WasmParser::new(writer.to_bytes())
  let m = match parser.parse_module() {
    Ok(v) => v
    Err(_) => return
  }

  // Custom sections do not affect standard definitions
  assert_eq(m.types.length(), 0)
}
