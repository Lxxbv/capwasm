// CapWasm: Linear Memory Engine
// Implements Wasm 1.0 page-based linear memory with boundary checks and typed accessors.

///|
/// PAGE_SIZE represents the WebAssembly standard memory page size (64 KiB).
pub let page_size : Int32 = 65536

///|
/// LinearMemory represents a sandboxed linear byte array.
pub(all) struct LinearMemory {
  mut data : Array[Byte]
  limits : Limits
}

///|
pub fn LinearMemory::new(limits : Limits) -> Result[LinearMemory, Trap] {
  let initial_bytes = limits.min * page_size
  let data = Array::make(initial_bytes, b'\x00')
  Ok({ data, limits, })
}

///|
pub fn LinearMemory::size_in_pages(self : LinearMemory) -> Int32 {
  self.data.length() / page_size
}

///|
pub fn LinearMemory::size_in_bytes(self : LinearMemory) -> Int32 {
  self.data.length()
}

///|
pub fn LinearMemory::grow(self : LinearMemory, delta_pages : Int32) -> Int32 {
  if delta_pages < 0 {
    return -1
  }
  let current_pages = self.size_in_pages()
  if delta_pages == 0 {
    return current_pages
  }

  let new_pages = current_pages + delta_pages
  match self.limits.max {
    Some(max_p) => if new_pages > max_p { return -1 }
    None => ()
  }

  // WebAssembly limits memory to 4 GiB (65536 pages)
  if new_pages > 65536 {
    return -1
  }

  let add_bytes = delta_pages * page_size
  for i = 0; i < add_bytes; i = i + 1 {
    self.data.push(b'\x00')
  }

  current_pages
}

///|
fn LinearMemory::check_bounds(
  self : LinearMemory,
  offset : Int32,
  size : Int32,
) -> Result[Unit, Trap] {
  if offset < 0 || size < 0 || offset + size > self.data.length() {
    Err(Trap::MemoryOutOfBounds(offset, size))
  } else {
    Ok(())
  }
}

///|
pub fn LinearMemory::read_u8(
  self : LinearMemory,
  offset : Int32,
) -> Result[Int32, Trap] {
  match self.check_bounds(offset, 1) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  Ok(self.data[offset].to_int() & 0xFF)
}

///|
pub fn LinearMemory::read_i8(
  self : LinearMemory,
  offset : Int32,
) -> Result[Int32, Trap] {
  let u = match self.read_u8(offset) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if (u & 0x80) != 0 {
    Ok(u | (-1 << 8))
  } else {
    Ok(u)
  }
}

///|
pub fn LinearMemory::write_u8(
  self : LinearMemory,
  offset : Int32,
  value : Int32,
) -> Result[Unit, Trap] {
  match self.check_bounds(offset, 1) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  self.data[offset] = (value & 0xFF).to_byte()
  Ok(())
}

///|
pub fn LinearMemory::read_u16(
  self : LinearMemory,
  offset : Int32,
) -> Result[Int32, Trap] {
  match self.check_bounds(offset, 2) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let b0 = self.data[offset].to_int() & 0xFF
  let b1 = self.data[offset + 1].to_int() & 0xFF
  Ok(b0 | (b1 << 8))
}

///|
pub fn LinearMemory::read_i16(
  self : LinearMemory,
  offset : Int32,
) -> Result[Int32, Trap] {
  let u = match self.read_u16(offset) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if (u & 0x8000) != 0 {
    Ok(u | (-1 << 16))
  } else {
    Ok(u)
  }
}

///|
pub fn LinearMemory::write_u16(
  self : LinearMemory,
  offset : Int32,
  value : Int32,
) -> Result[Unit, Trap] {
  match self.check_bounds(offset, 2) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  self.data[offset] = (value & 0xFF).to_byte()
  self.data[offset + 1] = ((value >> 8) & 0xFF).to_byte()
  Ok(())
}

///|
pub fn LinearMemory::read_i32(
  self : LinearMemory,
  offset : Int32,
) -> Result[Int32, Trap] {
  match self.check_bounds(offset, 4) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let b0 = self.data[offset].to_int() & 0xFF
  let b1 = self.data[offset + 1].to_int() & 0xFF
  let b2 = self.data[offset + 2].to_int() & 0xFF
  let b3 = self.data[offset + 3].to_int() & 0xFF
  Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
}

///|
pub fn LinearMemory::write_i32(
  self : LinearMemory,
  offset : Int32,
  value : Int32,
) -> Result[Unit, Trap] {
  match self.check_bounds(offset, 4) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  self.data[offset] = (value & 0xFF).to_byte()
  self.data[offset + 1] = ((value >> 8) & 0xFF).to_byte()
  self.data[offset + 2] = ((value >> 16) & 0xFF).to_byte()
  self.data[offset + 3] = ((value >> 24) & 0xFF).to_byte()
  Ok(())
}

///|
pub fn LinearMemory::read_i64(
  self : LinearMemory,
  offset : Int32,
) -> Result[Int64, Trap] {
  match self.check_bounds(offset, 8) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let mut res : Int64 = 0L
  for i = 0; i < 8; i = i + 1 {
    let b = (self.data[offset + i].to_int() & 0xFF).to_int64()
    res = res | (b << (i * 8))
  }
  Ok(res)
}

///|
pub fn LinearMemory::write_i64(
  self : LinearMemory,
  offset : Int32,
  value : Int64,
) -> Result[Unit, Trap] {
  match self.check_bounds(offset, 8) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let mut v = value
  for i = 0; i < 8; i = i + 1 {
    self.data[offset + i] = (v.to_int() & 0xFF).to_byte()
    v = v >> 8
  }
  Ok(())
}

///|
pub fn LinearMemory::read_bytes(
  self : LinearMemory,
  offset : Int32,
  length : Int32,
) -> Result[Array[Byte], Trap] {
  match self.check_bounds(offset, length) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let res = Array::make(length, b'\x00')
  for i = 0; i < length; i = i + 1 {
    res[i] = self.data[offset + i]
  }
  Ok(res)
}

///|
pub fn LinearMemory::write_bytes(
  self : LinearMemory,
  offset : Int32,
  bytes : Array[Byte],
) -> Result[Unit, Trap] {
  let len = bytes.length()
  match self.check_bounds(offset, len) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  for i = 0; i < len; i = i + 1 {
    self.data[offset + i] = bytes[i]
  }
  Ok(())
}

///|
pub fn LinearMemory::read_string(
  self : LinearMemory,
  offset : Int32,
  length : Int32,
) -> Result[String, Trap] {
  let raw = match self.read_bytes(offset, length) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let buf = StringBuilder::new()
  for b in raw {
    buf.write_char(Char::from_int(b.to_int()))
  }
  Ok(buf.to_string())
}

///|
pub fn LinearMemory::write_string(
  self : LinearMemory,
  offset : Int32,
  str : String,
) -> Result[Int32, Trap] {
  let len = str.length()
  match self.check_bounds(offset, len) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  for i = 0; i < len; i = i + 1 {
    self.data[offset + i] = str[i].to_int().to_byte()
  }
  Ok(len)
}

///|
pub fn LinearMemory::fill(
  self : LinearMemory,
  offset : Int32,
  val : Byte,
  count : Int32,
) -> Result[Unit, Trap] {
  match self.check_bounds(offset, count) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  for i = 0; i < count; i = i + 1 {
    self.data[offset + i] = val
  }
  Ok(())
}

///|
pub fn LinearMemory::copy(
  self : LinearMemory,
  dst_offset : Int32,
  src_offset : Int32,
  count : Int32,
) -> Result[Unit, Trap] {
  match self.check_bounds(dst_offset, count) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  match self.check_bounds(src_offset, count) {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  if dst_offset <= src_offset {
    for i = 0; i < count; i = i + 1 {
      self.data[dst_offset + i] = self.data[src_offset + i]
    }
  } else {
    let mut i = count - 1
    while i >= 0 {
      self.data[dst_offset + i] = self.data[src_offset + i]
      i = i - 1
    }
  }
  Ok(())
}
