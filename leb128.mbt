// CapWasm: LEB128 Binary Encoding and Decoding Engine
// Provides high-performance unsigned and signed LEB128 variable-length integer parsing.

///|
/// BinaryReader provides cursor-based byte stream reading with bounds checking.
pub(all) struct BinaryReader {
  bytes : Array[Byte]
  mut pos : Int32
}

///|
pub fn BinaryReader::new(bytes : Array[Byte]) -> BinaryReader {
  { bytes, pos: 0, }
}

///|
pub fn BinaryReader::from_string(str : String) -> BinaryReader {
  let arr = Array::new(capacity=str.length())
  for i = 0; i < str.length(); i = i + 1 {
    arr.push(str[i].to_int().to_byte())
  }
  { bytes: arr, pos: 0, }
}

///|
pub fn BinaryReader::remaining(self : BinaryReader) -> Int32 {
  let rem = self.bytes.length() - self.pos
  if rem < 0 {
    0
  } else {
    rem
  }
}

///|
pub fn BinaryReader::has_more(self : BinaryReader) -> Bool {
  self.pos < self.bytes.length()
}

///|
pub fn BinaryReader::get_position(self : BinaryReader) -> Int32 {
  self.pos
}

///|
pub fn BinaryReader::set_position(
  self : BinaryReader,
  new_pos : Int32,
) -> Result[Unit, DecodeError] {
  if new_pos < 0 || new_pos > self.bytes.length() {
    Err(DecodeError::UnexpectedEof("Seek out of bounds"))
  } else {
    self.pos = new_pos
    Ok(())
  }
}

///|
pub fn BinaryReader::read_byte(
  self : BinaryReader,
) -> Result[Byte, DecodeError] {
  if self.pos >= self.bytes.length() {
    Err(DecodeError::UnexpectedEof("read_byte"))
  } else {
    let b = self.bytes[self.pos]
    self.pos = self.pos + 1
    Ok(b)
  }
}

///|
pub fn BinaryReader::peek_byte(
  self : BinaryReader,
) -> Result[Byte, DecodeError] {
  if self.pos >= self.bytes.length() {
    Err(DecodeError::UnexpectedEof("peek_byte"))
  } else {
    Ok(self.bytes[self.pos])
  }
}

///|
pub fn BinaryReader::read_bytes(
  self : BinaryReader,
  count : Int32,
) -> Result[Array[Byte], DecodeError] {
  if count < 0 || self.pos + count > self.bytes.length() {
    return Err(DecodeError::UnexpectedEof("read_bytes(\{count})"))
  }
  let res = Array::new(capacity=count)
  for i = 0; i < count; i = i + 1 {
    res.push(self.bytes[self.pos + i])
  }
  self.pos = self.pos + count
  Ok(res)
}

///|
/// Decodes unsigned 32-bit LEB128 integer.
pub fn BinaryReader::read_u32(
  self : BinaryReader,
) -> Result[Int32, DecodeError] {
  let mut result : Int32 = 0
  let mut shift : Int32 = 0
  let mut count : Int32 = 0

  while count < 5 {
    if self.pos >= self.bytes.length() {
      return Err(DecodeError::UnexpectedEof("read_u32"))
    }
    let byte_val = self.bytes[self.pos].to_int()
    self.pos = self.pos + 1
    count = count + 1

    let payload = byte_val & 0x7F
    result = result | (payload << shift)
    shift = shift + 7

    if (byte_val & 0x80) == 0 {
      return Ok(result)
    }
  }

  Err(DecodeError::Leb128Overflow)
}

///|
/// Decodes signed 32-bit LEB128 integer.
pub fn BinaryReader::read_i32(
  self : BinaryReader,
) -> Result[Int32, DecodeError] {
  let mut result : Int32 = 0
  let mut shift : Int32 = 0
  let mut count : Int32 = 0
  let mut byte_val : Int32 = 0

  while count < 5 {
    if self.pos >= self.bytes.length() {
      return Err(DecodeError::UnexpectedEof("read_i32"))
    }
    byte_val = self.bytes[self.pos].to_int()
    self.pos = self.pos + 1
    count = count + 1

    let payload = byte_val & 0x7F
    result = result | (payload << shift)
    shift = shift + 7

    if (byte_val & 0x80) == 0 {
      if shift < 32 && (byte_val & 0x40) != 0 {
        result = result | (-1 << shift)
      }
      return Ok(result)
    }
  }

  Err(DecodeError::Leb128Overflow)
}

///|
/// Decodes signed 64-bit LEB128 integer.
pub fn BinaryReader::read_i64(
  self : BinaryReader,
) -> Result[Int64, DecodeError] {
  let mut result : Int64 = 0L
  let mut shift : Int32 = 0
  let mut count : Int32 = 0
  let mut byte_val : Int32 = 0

  while count < 10 {
    if self.pos >= self.bytes.length() {
      return Err(DecodeError::UnexpectedEof("read_i64"))
    }
    byte_val = self.bytes[self.pos].to_int()
    self.pos = self.pos + 1
    count = count + 1

    let payload = (byte_val & 0x7F).to_int64()
    result = result | (payload << shift)
    shift = shift + 7

    if (byte_val & 0x80) == 0 {
      if shift < 64 && (byte_val & 0x40) != 0 {
        let mask = -1L << shift
        result = result | mask
      }
      return Ok(result)
    }
  }

  Err(DecodeError::Leb128Overflow)
}

///|
/// Reads a UTF-8 encoded string prefixed with its LEB128 length.
pub fn BinaryReader::read_name(
  self : BinaryReader,
) -> Result[String, DecodeError] {
  let len = match self.read_u32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let raw_bytes = match self.read_bytes(len) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let buf = StringBuilder::new(size_hint=len)
  for b in raw_bytes {
    buf.write_char(Char::from_int(b.to_int()))
  }
  Ok(buf.to_string())
}

///|
/// BinaryWriter provides in-memory encoding of primitives and LEB128 values.
pub(all) struct BinaryWriter {
  bytes : Array[Byte]
}

///|
pub fn BinaryWriter::new() -> BinaryWriter {
  { bytes: [], }
}

///|
pub fn BinaryWriter::to_bytes(self : BinaryWriter) -> Array[Byte] {
  self.bytes
}

///|
pub fn BinaryWriter::length(self : BinaryWriter) -> Int32 {
  self.bytes.length()
}

///|
pub fn BinaryWriter::write_byte(self : BinaryWriter, b : Byte) -> Unit {
  self.bytes.push(b)
}

///|
pub fn BinaryWriter::write_bytes(
  self : BinaryWriter,
  arr : Array[Byte],
) -> Unit {
  for b in arr {
    self.bytes.push(b)
  }
}

///|
pub fn BinaryWriter::write_u32(self : BinaryWriter, value : Int32) -> Unit {
  let mut v = value
  while true {
    let byte_val = v & 0x7F
    v = v >> 7
    if v != 0 {
      self.bytes.push((byte_val | 0x80).to_byte())
    } else {
      self.bytes.push(byte_val.to_byte())
      break
    }
  }
}

///|
pub fn BinaryWriter::write_i32(self : BinaryWriter, value : Int32) -> Unit {
  let mut v = value
  let mut more = true
  while more {
    let byte_val = v & 0x7F
    v = v >> 7
    let sign_bit = (byte_val & 0x40) != 0
    if (v == 0 && not(sign_bit)) || (v == -1 && sign_bit) {
      more = false
      self.bytes.push(byte_val.to_byte())
    } else {
      self.bytes.push((byte_val | 0x80).to_byte())
    }
  }
}

///|
pub fn BinaryWriter::write_name(self : BinaryWriter, name : String) -> Unit {
  self.write_u32(name.length())
  for i = 0; i < name.length(); i = i + 1 {
    self.bytes.push(name[i].to_int().to_byte())
  }
}
