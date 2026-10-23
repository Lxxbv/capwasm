// CapWasm: Binary WebAssembly Decoder and Parser
// Parses standard Wasm Core 1.0 binary modules and section structures.

///|
pub fn parse_value_type(b : Byte) -> Result[ValueType, DecodeError] {
  match b.to_int() {
    0x7F => Ok(ValueType::I32)
    0x7E => Ok(ValueType::I64)
    0x7D => Ok(ValueType::F32)
    0x7C => Ok(ValueType::F64)
    other => Err(DecodeError::InvalidValueType(other))
  }
}

///|
pub fn parse_limits(reader : BinaryReader) -> Result[Limits, DecodeError] {
  let flag_byte = match reader.read_byte() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let flag = flag_byte.to_int()
  let min = match reader.read_u32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  match flag {
    0x00 => Ok(Limits::new(min, None))
    0x01 => {
      let max = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Limits::new(min, Some(max)))
    }
    other => Err(DecodeError::InvalidLimits(other))
  }
}

///|
pub fn parse_func_type(reader : BinaryReader) -> Result[FuncType, DecodeError] {
  let form_byte = match reader.read_byte() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let form = form_byte.to_int()
  if form != 0x60 {
    return Err(
      DecodeError::MalformedModule("Expected func type form 0x60, got \{form}"),
    )
  }
  let param_count = match reader.read_u32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let params = Array::new(capacity=param_count)
  for i = 0; i < param_count; i = i + 1 {
    let b = match reader.read_byte() {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let vt = match parse_value_type(b) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    params.push(vt)
  }
  let result_count = match reader.read_u32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let results = Array::new(capacity=result_count)
  for i = 0; i < result_count; i = i + 1 {
    let b = match reader.read_byte() {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let vt = match parse_value_type(b) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    results.push(vt)
  }
  Ok(FuncType::new(params, results))
}

///|
pub fn parse_global_type(
  reader : BinaryReader,
) -> Result[GlobalType, DecodeError] {
  let b = match reader.read_byte() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let val_type = match parse_value_type(b) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let mut_byte = match reader.read_byte() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let mutability = match mut_byte.to_int() {
    0x00 => Mutability::Const
    0x01 => Mutability::Var
    other => return Err(DecodeError::InvalidMutability(other))
  }
  Ok(GlobalType::new(val_type, mutability))
}

///|
pub fn parse_mem_arg(reader : BinaryReader) -> Result[MemArg, DecodeError] {
  let align = match reader.read_u32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let offset = match reader.read_u32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  Ok(MemArg::new(align, offset))
}

///|
pub fn parse_block_type(
  reader : BinaryReader,
) -> Result[BlockType, DecodeError] {
  let peek_b = match reader.peek_byte() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let b = peek_b.to_int()
  if b == 0x40 {
    let _ = match reader.read_byte() {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    return Ok(BlockType::Empty)
  }
  match b {
    0x7F | 0x7E | 0x7D | 0x7C => {
      let _ = match reader.read_byte() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      let vt = match parse_value_type(peek_b) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(BlockType::Value(vt))
    }
    _ => {
      let idx = match reader.read_i32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(BlockType::FuncTypeIndex(idx))
    }
  }
}

///|
pub fn parse_instruction(
  reader : BinaryReader,
) -> Result[Instruction, DecodeError] {
  let op_b = match reader.read_byte() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let opcode = op_b.to_int()
  match opcode {
    0x00 => Ok(Instruction::Unreachable)
    0x01 => Ok(Instruction::Nop)
    0x02 => {
      let bt = match parse_block_type(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::Block(bt))
    }
    0x03 => {
      let bt = match parse_block_type(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::Loop(bt))
    }
    0x04 => {
      let bt = match parse_block_type(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::If(bt))
    }
    0x05 => Ok(Instruction::Else)
    0x0B => Ok(Instruction::End)
    0x0C => {
      let idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::Br(idx))
    }
    0x0D => {
      let idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::BrIf(idx))
    }
    0x0E => {
      let count = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      let targets = Array::new(capacity=count)
      for i = 0; i < count; i = i + 1 {
        let t = match reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        targets.push(t)
      }
      let default_target = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::BrTable(targets, default_target))
    }
    0x0F => Ok(Instruction::Return)
    0x10 => {
      let idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::Call(idx))
    }
    0x11 => {
      let type_idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      let table_idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::CallIndirect(type_idx, table_idx))
    }
    0x1A => Ok(Instruction::Drop)
    0x1B => Ok(Instruction::Select)
    0x20 => {
      let idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::LocalGet(idx))
    }
    0x21 => {
      let idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::LocalSet(idx))
    }
    0x22 => {
      let idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::LocalTee(idx))
    }
    0x23 => {
      let idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::GlobalGet(idx))
    }
    0x24 => {
      let idx = match reader.read_u32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::GlobalSet(idx))
    }
    0x28 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I32Load(arg))
    }
    0x29 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Load(arg))
    }
    0x2A => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::F32Load(arg))
    }
    0x2B => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::F64Load(arg))
    }
    0x2C => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I32Load8S(arg))
    }
    0x2D => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I32Load8U(arg))
    }
    0x2E => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I32Load16S(arg))
    }
    0x2F => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I32Load16U(arg))
    }
    0x30 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Load8S(arg))
    }
    0x31 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Load8U(arg))
    }
    0x32 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Load16S(arg))
    }
    0x33 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Load16U(arg))
    }
    0x34 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Load32S(arg))
    }
    0x35 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Load32U(arg))
    }
    0x36 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I32Store(arg))
    }
    0x37 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Store(arg))
    }
    0x38 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::F32Store(arg))
    }
    0x39 => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::F64Store(arg))
    }
    0x3A => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I32Store8(arg))
    }
    0x3B => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I32Store16(arg))
    }
    0x3C => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Store8(arg))
    }
    0x3D => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Store16(arg))
    }
    0x3E => {
      let arg = match parse_mem_arg(reader) {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Store32(arg))
    }
    0x3F => {
      let _ = match reader.read_byte() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::MemorySize)
    }
    0x40 => {
      let _ = match reader.read_byte() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::MemoryGrow)
    }
    0x41 => {
      let c = match reader.read_i32() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I32Const(c))
    }
    0x42 => {
      let c = match reader.read_i64() {
        Ok(v) => v
        Err(e) => return Err(e)
      }
      Ok(Instruction::I64Const(c))
    }
    0x45 => Ok(Instruction::I32Eqz)
    0x46 => Ok(Instruction::I32Eq)
    0x47 => Ok(Instruction::I32Ne)
    0x48 => Ok(Instruction::I32LtS)
    0x49 => Ok(Instruction::I32LtU)
    0x4A => Ok(Instruction::I32GtS)
    0x4B => Ok(Instruction::I32GtU)
    0x4C => Ok(Instruction::I32LeS)
    0x4D => Ok(Instruction::I32LeU)
    0x4E => Ok(Instruction::I32GeS)
    0x4F => Ok(Instruction::I32GeU)
    0x50 => Ok(Instruction::I64Eqz)
    0x51 => Ok(Instruction::I64Eq)
    0x52 => Ok(Instruction::I64Ne)
    0x53 => Ok(Instruction::I64LtS)
    0x54 => Ok(Instruction::I64LtU)
    0x55 => Ok(Instruction::I64GtS)
    0x56 => Ok(Instruction::I64GtU)
    0x57 => Ok(Instruction::I64LeS)
    0x58 => Ok(Instruction::I64LeU)
    0x59 => Ok(Instruction::I64GeS)
    0x5A => Ok(Instruction::I64GeU)
    0x67 => Ok(Instruction::I32Clz)
    0x68 => Ok(Instruction::I32Ctz)
    0x69 => Ok(Instruction::I32Popcnt)
    0x6A => Ok(Instruction::I32Add)
    0x6B => Ok(Instruction::I32Sub)
    0x6C => Ok(Instruction::I32Mul)
    0x6D => Ok(Instruction::I32DivS)
    0x6E => Ok(Instruction::I32DivU)
    0x6F => Ok(Instruction::I32RemS)
    0x70 => Ok(Instruction::I32RemU)
    0x71 => Ok(Instruction::I32And)
    0x72 => Ok(Instruction::I32Or)
    0x73 => Ok(Instruction::I32Xor)
    0x74 => Ok(Instruction::I32Shl)
    0x75 => Ok(Instruction::I32ShrS)
    0x76 => Ok(Instruction::I32ShrU)
    0x77 => Ok(Instruction::I32Rotl)
    0x78 => Ok(Instruction::I32Rotr)
    0x79 => Ok(Instruction::I64Clz)
    0x7A => Ok(Instruction::I64Ctz)
    0x7B => Ok(Instruction::I64Popcnt)
    0x7C => Ok(Instruction::I64Add)
    0x7D => Ok(Instruction::I64Sub)
    0x7E => Ok(Instruction::I64Mul)
    0x7F => Ok(Instruction::I64DivS)
    0x80 => Ok(Instruction::I64DivU)
    0x81 => Ok(Instruction::I64RemS)
    0x82 => Ok(Instruction::I64RemU)
    0x83 => Ok(Instruction::I64And)
    0x84 => Ok(Instruction::I64Or)
    0x85 => Ok(Instruction::I64Xor)
    0x86 => Ok(Instruction::I64Shl)
    0x87 => Ok(Instruction::I64ShrS)
    0x88 => Ok(Instruction::I64ShrU)
    0x89 => Ok(Instruction::I64Rotl)
    0x8A => Ok(Instruction::I64Rotr)
    0xA7 => Ok(Instruction::I32WrapI64)
    0xAC => Ok(Instruction::I64ExtendI32S)
    0xAD => Ok(Instruction::I64ExtendI32U)
    other => Err(DecodeError::InvalidOpcode(other))
  }
}

///|
pub fn parse_expression(
  reader : BinaryReader,
) -> Result[Array[Instruction], DecodeError] {
  let instructions = Array::new()
  while true {
    let instr = match parse_instruction(reader) {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    instructions.push(instr)
    match instr {
      Instruction::End => break
      _ => ()
    }
  }
  Ok(instructions)
}

///|
/// WasmParser parses binary .wasm streams into a WasmModule structure.
pub(all) struct WasmParser {
  reader : BinaryReader
}

///|
pub fn WasmParser::new(bytes : Array[Byte]) -> WasmParser {
  { reader: BinaryReader::new(bytes), }
}

///|
pub fn WasmParser::parse_module(
  self : WasmParser,
) -> Result[WasmModule, DecodeError] {
  // Validate magic: '\0asm'
  let magic = match self.reader.read_bytes(4) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if magic[0].to_int() != 0x00 ||
    magic[1].to_int() != 0x61 ||
    magic[2].to_int() != 0x73 ||
    magic[3].to_int() != 0x6D {
    return Err(DecodeError::InvalidMagic)
  }

  // Validate version: 0x00000001
  let version = match self.reader.read_bytes(4) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let v = version[0].to_int() |
    (version[1].to_int() << 8) |
    (version[2].to_int() << 16) |
    (version[3].to_int() << 24)
  if v != 1 {
    return Err(DecodeError::InvalidVersion(v))
  }

  let mut types : Array[FuncType] = []
  let mut imports : Array[ImportEntry] = []
  let mut func_types : Array[Int] = []
  let mut tables : Array[TableType] = []
  let mut memories : Array[MemoryType] = []
  let mut globals : Array[GlobalEntry] = []
  let mut exports : Array[ExportEntry] = []
  let mut start_func : Int? = None
  let mut elements : Array[ElementSegment] = []
  let mut code : Array[FunctionBody] = []
  let mut data : Array[DataSegment] = []

  while self.reader.has_more() {
    let section_id_byte = match self.reader.read_byte() {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let section_id = section_id_byte.to_int()
    let section_size = match self.reader.read_u32() {
      Ok(v) => v
      Err(e) => return Err(e)
    }
    let start_pos = self.reader.get_position()

    match section_id {
      0 => {
        // Custom section: skip payload
        let _ = match self.reader.read_bytes(section_size) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
      }
      1 => {
        // Type section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        types = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let ft = match parse_func_type(self.reader) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          types.push(ft)
        }
      }
      2 => {
        // Import section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        imports = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let mod_name = match self.reader.read_name() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let field_name = match self.reader.read_name() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let tag_b = match self.reader.read_byte() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let tag = tag_b.to_int()
          let desc = match tag {
            0 => {
              let idx = match self.reader.read_u32() {
                Ok(v) => v
                Err(e) => return Err(e)
              }
              ImportDesc::Func(idx)
            }
            1 => {
              let _elem_type = match self.reader.read_byte() {
                Ok(v) => v
                Err(e) => return Err(e)
              }
              let lim = match parse_limits(self.reader) {
                Ok(v) => v
                Err(e) => return Err(e)
              }
              ImportDesc::Table(TableType::new(lim))
            }
            2 => {
              let lim = match parse_limits(self.reader) {
                Ok(v) => v
                Err(e) => return Err(e)
              }
              ImportDesc::Mem(MemoryType::new(lim))
            }
            3 => {
              let gt = match parse_global_type(self.reader) {
                Ok(v) => v
                Err(e) => return Err(e)
              }
              ImportDesc::Global(gt)
            }
            other =>
              return Err(
                DecodeError::MalformedModule("Unknown import tag: \{other}"),
              )
          }
          imports.push(ImportEntry::new(mod_name, field_name, desc))
        }
      }
      3 => {
        // Function section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        func_types = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let idx = match self.reader.read_u32() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          func_types.push(idx)
        }
      }
      4 => {
        // Table section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        tables = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let _elem_type = match self.reader.read_byte() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let lim = match parse_limits(self.reader) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          tables.push(TableType::new(lim))
        }
      }
      5 => {
        // Memory section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        memories = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let lim = match parse_limits(self.reader) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          memories.push(MemoryType::new(lim))
        }
      }
      6 => {
        // Global section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        globals = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let gt = match parse_global_type(self.reader) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let init_expr = match parse_expression(self.reader) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          globals.push(GlobalEntry::new(gt, init_expr))
        }
      }
      7 => {
        // Export section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        exports = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let name = match self.reader.read_name() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let tag_b = match self.reader.read_byte() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let tag = tag_b.to_int()
          let idx = match self.reader.read_u32() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let desc = match tag {
            0 => ExportDesc::Func(idx)
            1 => ExportDesc::Table(idx)
            2 => ExportDesc::Mem(idx)
            3 => ExportDesc::Global(idx)
            other =>
              return Err(
                DecodeError::MalformedModule("Unknown export tag: \{other}"),
              )
          }
          exports.push(ExportEntry::new(name, desc))
        }
      }
      8 => {
        // Start section
        let s = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        start_func = Some(s)
      }
      9 => {
        // Element section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        elements = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let table_idx = match self.reader.read_u32() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let offset_expr = match parse_expression(self.reader) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let num_funcs = match self.reader.read_u32() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let funcs = Array::new(capacity=num_funcs)
          for j = 0; j < num_funcs; j = j + 1 {
            let f = match self.reader.read_u32() {
              Ok(v) => v
              Err(e) => return Err(e)
            }
            funcs.push(f)
          }
          elements.push(ElementSegment::new(table_idx, offset_expr, funcs))
        }
      }
      10 => {
        // Code section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        code = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let body_size = match self.reader.read_u32() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let body_start = self.reader.get_position()
          let local_count = match self.reader.read_u32() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let locals = Array::new(capacity=local_count)
          for j = 0; j < local_count; j = j + 1 {
            let n = match self.reader.read_u32() {
              Ok(v) => v
              Err(e) => return Err(e)
            }
            let b = match self.reader.read_byte() {
              Ok(v) => v
              Err(e) => return Err(e)
            }
            let vt = match parse_value_type(b) {
              Ok(v) => v
              Err(e) => return Err(e)
            }
            locals.push(LocalDecl::new(n, vt))
          }
          let instructions = match parse_expression(self.reader) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let body_end = self.reader.get_position()
          if body_end - body_start != body_size {
            return Err(
              DecodeError::SectionSizeMismatch(body_size, body_end - body_start),
            )
          }
          code.push(FunctionBody::new(locals, instructions))
        }
      }
      11 => {
        // Data section
        let count = match self.reader.read_u32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        data = Array::new(capacity=count)
        for i = 0; i < count; i = i + 1 {
          let mem_idx = match self.reader.read_u32() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let offset_expr = match parse_expression(self.reader) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let byte_count = match self.reader.read_u32() {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          let segment_data = match self.reader.read_bytes(byte_count) {
            Ok(v) => v
            Err(e) => return Err(e)
          }
          data.push(DataSegment::new(mem_idx, offset_expr, segment_data))
        }
      }
      other => return Err(DecodeError::InvalidSectionId(other))
    }

    let end_pos = self.reader.get_position()
    if section_id != 0 && end_pos - start_pos != section_size {
      return Err(
        DecodeError::SectionSizeMismatch(section_size, end_pos - start_pos),
      )
    }
  }

  Ok({
    types,
    imports,
    func_types,
    tables,
    memories,
    globals,
    exports,
    start_func,
    elements,
    code,
    data,
  })
}
