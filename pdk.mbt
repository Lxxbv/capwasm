// CapWasm: Extism Guest Plugin Development Kit (PDK) & Wasm 1.0 Binary Encoder
// Enables programmatic construction and compilation of standard Extism/WASI `.wasm` plugin
// binaries (`WasmModule::encode_to_bytes`) with automatic LEB128 section framing.

///|
/// Appends all bytes from `src` into `dst`.
fn append_bytes(dst : Array[Byte], src : Array[Byte]) -> Unit {
  for b in src {
    dst.push(b)
  }
}

///|
/// Appends an unsigned 32-bit LEB128 integer into `dst`.
fn append_u32_leb128(dst : Array[Byte], val : Int32) -> Unit {
  let mut v = val.reinterpret_as_uint()
  while true {
    let byte_val = (v & 0x7FU).reinterpret_as_int()
    v = v >> 7
    if v != 0U {
      dst.push((byte_val | 0x80).to_byte())
    } else {
      dst.push(byte_val.to_byte())
      break
    }
  }
}

///|
/// Appends a signed 32-bit LEB128 integer into `dst`.
fn append_i32_leb128(dst : Array[Byte], val : Int32) -> Unit {
  let mut v = val
  let mut more = true
  while more {
    let byte_val = v & 0x7F
    v = v >> 7
    let sign_bit = (byte_val & 0x40) != 0
    if (v == 0 && not(sign_bit)) || (v == -1 && sign_bit) {
      more = false
      dst.push(byte_val.to_byte())
    } else {
      dst.push((byte_val | 0x80).to_byte())
    }
  }
}

///|
/// Appends a signed 64-bit LEB128 integer into `dst`.
fn append_i64_leb128(dst : Array[Byte], val : Int64) -> Unit {
  let mut v = val
  let mut more = true
  while more {
    let byte_val = (v & 0x7FL).to_int()
    v = v >> 7
    let sign_bit = (byte_val & 0x40) != 0
    if (v == 0L && not(sign_bit)) || (v == -1L && sign_bit) {
      more = false
      dst.push(byte_val.to_byte())
    } else {
      dst.push((byte_val | 0x80).to_byte())
    }
  }
}

///|
/// Appends a length-prefixed UTF-8 string into `dst`.
fn append_wasm_name(dst : Array[Byte], name : String) -> Unit {
  append_u32_leb128(dst, name.length())
  for i = 0; i < name.length(); i = i + 1 {
    dst.push(name[i].to_int().to_byte())
  }
}

///|
/// Appends a Wasm `ValueType` byte into `dst`.
fn append_val_type(dst : Array[Byte], vt : ValueType) -> Unit {
  let b : Byte = match vt {
    ValueType::I32 => b'\x7f'
    ValueType::I64 => b'\x7e'
    ValueType::F32 => b'\x7d'
    ValueType::F64 => b'\x7c'
  }
  dst.push(b)
}

///|
/// Appends a Wasm `Limits` structure into `dst`.
fn append_limits(dst : Array[Byte], lim : Limits) -> Unit {
  match lim.max {
    Some(m) => {
      dst.push(b'\x01')
      append_u32_leb128(dst, lim.min)
      append_u32_leb128(dst, m)
    }
    None => {
      dst.push(b'\x00')
      append_u32_leb128(dst, lim.min)
    }
  }
}

///|
/// Appends a single Wasm `Instruction` into `dst`.
pub fn encode_instruction(dst : Array[Byte], instr : Instruction) -> Unit {
  match instr {
    Instruction::Unreachable => dst.push(b'\x00')
    Instruction::Nop => dst.push(b'\x01')
    Instruction::Block(bt) => {
      dst.push(b'\x02')
      match bt {
        BlockType::Empty => dst.push(b'\x40')
        BlockType::Value(vt) => append_val_type(dst, vt)
        BlockType::FuncTypeIndex(idx) => append_u32_leb128(dst, idx)
      }
    }
    Instruction::Loop(bt) => {
      dst.push(b'\x03')
      match bt {
        BlockType::Empty => dst.push(b'\x40')
        BlockType::Value(vt) => append_val_type(dst, vt)
        BlockType::FuncTypeIndex(idx) => append_u32_leb128(dst, idx)
      }
    }
    Instruction::If(bt) => {
      dst.push(b'\x04')
      match bt {
        BlockType::Empty => dst.push(b'\x40')
        BlockType::Value(vt) => append_val_type(dst, vt)
        BlockType::FuncTypeIndex(idx) => append_u32_leb128(dst, idx)
      }
    }
    Instruction::Else => dst.push(b'\x05')
    Instruction::End => dst.push(b'\x0b')
    Instruction::Br(d) => {
      dst.push(b'\x0c')
      append_u32_leb128(dst, d)
    }
    Instruction::BrIf(d) => {
      dst.push(b'\x0d')
      append_u32_leb128(dst, d)
    }
    Instruction::BrTable(targets, def_t) => {
      dst.push(b'\x0e')
      append_u32_leb128(dst, targets.length())
      for t in targets {
        append_u32_leb128(dst, t)
      }
      append_u32_leb128(dst, def_t)
    }
    Instruction::Return => dst.push(b'\x0f')
    Instruction::Call(fidx) => {
      dst.push(b'\x10')
      append_u32_leb128(dst, fidx)
    }
    Instruction::CallIndirect(tidx, tbl_idx) => {
      dst.push(b'\x11')
      append_u32_leb128(dst, tidx)
      append_u32_leb128(dst, tbl_idx)
    }
    Instruction::Drop => dst.push(b'\x1a')
    Instruction::Select => dst.push(b'\x1b')
    Instruction::LocalGet(idx) => {
      dst.push(b'\x20')
      append_u32_leb128(dst, idx)
    }
    Instruction::LocalSet(idx) => {
      dst.push(b'\x21')
      append_u32_leb128(dst, idx)
    }
    Instruction::LocalTee(idx) => {
      dst.push(b'\x22')
      append_u32_leb128(dst, idx)
    }
    Instruction::GlobalGet(idx) => {
      dst.push(b'\x23')
      append_u32_leb128(dst, idx)
    }
    Instruction::GlobalSet(idx) => {
      dst.push(b'\x24')
      append_u32_leb128(dst, idx)
    }
    Instruction::I32Load(arg) => {
      dst.push(b'\x28')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::I64Load(arg) => {
      dst.push(b'\x29')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::I32Load8S(arg) => {
      dst.push(b'\x2c')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::I32Load8U(arg) => {
      dst.push(b'\x2d')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::I32Load16S(arg) => {
      dst.push(b'\x2e')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::I32Load16U(arg) => {
      dst.push(b'\x2f')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::I32Store(arg) => {
      dst.push(b'\x36')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::I64Store(arg) => {
      dst.push(b'\x37')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::I32Store8(arg) => {
      dst.push(b'\x3a')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::I32Store16(arg) => {
      dst.push(b'\x3b')
      append_u32_leb128(dst, arg.align)
      append_u32_leb128(dst, arg.offset)
    }
    Instruction::MemorySize => {
      dst.push(b'\x3f')
      dst.push(b'\x00')
    }
    Instruction::MemoryGrow => {
      dst.push(b'\x40')
      dst.push(b'\x00')
    }
    Instruction::I32Const(v) => {
      dst.push(b'\x41')
      append_i32_leb128(dst, v)
    }
    Instruction::I64Const(v) => {
      dst.push(b'\x42')
      append_i64_leb128(dst, v)
    }
    Instruction::I32Eqz => dst.push(b'\x45')
    Instruction::I32Eq => dst.push(b'\x46')
    Instruction::I32Ne => dst.push(b'\x47')
    Instruction::I32LtS => dst.push(b'\x48')
    Instruction::I32LtU => dst.push(b'\x49')
    Instruction::I32GtS => dst.push(b'\x4a')
    Instruction::I32GtU => dst.push(b'\x4b')
    Instruction::I32LeS => dst.push(b'\x4c')
    Instruction::I32LeU => dst.push(b'\x4d')
    Instruction::I32GeS => dst.push(b'\x4e')
    Instruction::I32GeU => dst.push(b'\x4f')
    Instruction::I64Eqz => dst.push(b'\x50')
    Instruction::I64Eq => dst.push(b'\x51')
    Instruction::I64Ne => dst.push(b'\x52')
    Instruction::I64LtS => dst.push(b'\x53')
    Instruction::I64GtS => dst.push(b'\x55')
    Instruction::I64LeS => dst.push(b'\x57')
    Instruction::I64GeS => dst.push(b'\x59')
    Instruction::I32Add => dst.push(b'\x6a')
    Instruction::I32Sub => dst.push(b'\x6b')
    Instruction::I32Mul => dst.push(b'\x6c')
    Instruction::I32DivS => dst.push(b'\x6d')
    Instruction::I32DivU => dst.push(b'\x6e')
    Instruction::I32RemS => dst.push(b'\x6f')
    Instruction::I32RemU => dst.push(b'\x70')
    Instruction::I32And => dst.push(b'\x71')
    Instruction::I32Or => dst.push(b'\x72')
    Instruction::I32Xor => dst.push(b'\x73')
    Instruction::I32Shl => dst.push(b'\x74')
    Instruction::I32ShrS => dst.push(b'\x75')
    Instruction::I32ShrU => dst.push(b'\x76')
    Instruction::I64Add => dst.push(b'\x7c')
    Instruction::I64Sub => dst.push(b'\x7d')
    Instruction::I64Mul => dst.push(b'\x7e')
    Instruction::I64DivS => dst.push(b'\x7f')
    Instruction::I64RemS => dst.push(b'\x81')
    Instruction::I64And => dst.push(b'\x83')
    Instruction::I64Or => dst.push(b'\x84')
    Instruction::I64Xor => dst.push(b'\x85')
    Instruction::I64Shl => dst.push(b'\x86')
    Instruction::I64ShrS => dst.push(b'\x87')
    Instruction::I32WrapI64 => dst.push(b'\xa7')
    Instruction::I64ExtendI32S => dst.push(b'\xac')
    Instruction::I64ExtendI32U => dst.push(b'\xad')
    _ => dst.push(b'\x01')
  }
}

///|
/// Appends a framed Wasm section `(section_id, payload_len_leb128, payload)` into `out`.
fn append_section(
  out : Array[Byte],
  section_id : Int32,
  payload : Array[Byte],
) -> Unit {
  if payload.length() == 0 {
    return
  }
  out.push(section_id.to_byte())
  append_u32_leb128(out, payload.length())
  append_bytes(out, payload)
}

///|
/// Encodes a `WasmModule` AST into a standard WebAssembly 1.0 binary byte array (`\0asm\x01\x00\x00\x00`).
pub fn WasmModule::encode_to_bytes(self : WasmModule) -> Array[Byte] {
  let out : Array[Byte] = [
    b'\x00', b'\x61', b'\x73', b'\x6d', b'\x01', b'\x00', b'\x00', b'\x00',
  ]

  // Section 1: Type Section
  if self.types.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.types.length())
    for ft in self.types {
      payload.push(b'\x60')
      append_u32_leb128(payload, ft.params.length())
      for p in ft.params {
        append_val_type(payload, p)
      }
      append_u32_leb128(payload, ft.results.length())
      for r in ft.results {
        append_val_type(payload, r)
      }
    }
    append_section(out, 1, payload)
  }

  // Section 2: Import Section
  if self.imports.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.imports.length())
    for imp in self.imports {
      append_wasm_name(payload, imp.mod_name)
      append_wasm_name(payload, imp.field_name)
      match imp.desc {
        ImportDesc::Func(tidx) => {
          payload.push(b'\x00')
          append_u32_leb128(payload, tidx)
        }
        ImportDesc::Table(tt) => {
          payload.push(b'\x01')
          payload.push(b'\x70')
          append_limits(payload, tt.limits)
        }
        ImportDesc::Mem(mt) => {
          payload.push(b'\x02')
          append_limits(payload, mt.limits)
        }
        ImportDesc::Global(gt) => {
          payload.push(b'\x03')
          append_val_type(payload, gt.val_type)
          let m_byte : Byte = match gt.mutability {
            Mutability::Const => b'\x00'
            Mutability::Var => b'\x01'
          }
          payload.push(m_byte)
        }
      }
    }
    append_section(out, 2, payload)
  }

  // Section 3: Function Section
  if self.func_types.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.func_types.length())
    for tidx in self.func_types {
      append_u32_leb128(payload, tidx)
    }
    append_section(out, 3, payload)
  }

  // Section 4: Table Section
  if self.tables.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.tables.length())
    for t in self.tables {
      payload.push(b'\x70')
      append_limits(payload, t.limits)
    }
    append_section(out, 4, payload)
  }

  // Section 5: Memory Section
  if self.memories.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.memories.length())
    for m in self.memories {
      append_limits(payload, m.limits)
    }
    append_section(out, 5, payload)
  }

  // Section 6: Global Section
  if self.globals.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.globals.length())
    for g in self.globals {
      append_val_type(payload, g.global_type.val_type)
      let m_byte : Byte = match g.global_type.mutability {
        Mutability::Const => b'\x00'
        Mutability::Var => b'\x01'
      }
      payload.push(m_byte)
      for instr in g.init_expr {
        encode_instruction(payload, instr)
      }
    }
    append_section(out, 6, payload)
  }

  // Section 7: Export Section
  if self.exports.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.exports.length())
    for exp in self.exports {
      append_wasm_name(payload, exp.name)
      match exp.desc {
        ExportDesc::Func(idx) => {
          payload.push(b'\x00')
          append_u32_leb128(payload, idx)
        }
        ExportDesc::Table(idx) => {
          payload.push(b'\x01')
          append_u32_leb128(payload, idx)
        }
        ExportDesc::Mem(idx) => {
          payload.push(b'\x02')
          append_u32_leb128(payload, idx)
        }
        ExportDesc::Global(idx) => {
          payload.push(b'\x03')
          append_u32_leb128(payload, idx)
        }
      }
    }
    append_section(out, 7, payload)
  }

  // Section 9: Element Section
  if self.elements.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.elements.length())
    for elem in self.elements {
      append_u32_leb128(payload, elem.table_index)
      for instr in elem.offset_expr {
        encode_instruction(payload, instr)
      }
      append_u32_leb128(payload, elem.func_indices.length())
      for fidx in elem.func_indices {
        append_u32_leb128(payload, fidx)
      }
    }
    append_section(out, 9, payload)
  }

  // Section 10: Code Section
  if self.code.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.code.length())
    for body in self.code {
      let body_bytes : Array[Byte] = []
      append_u32_leb128(body_bytes, body.locals.length())
      for decl in body.locals {
        append_u32_leb128(body_bytes, decl.count)
        append_val_type(body_bytes, decl.val_type)
      }
      for instr in body.instructions {
        encode_instruction(body_bytes, instr)
      }
      append_u32_leb128(payload, body_bytes.length())
      append_bytes(payload, body_bytes)
    }
    append_section(out, 10, payload)
  }

  // Section 11: Data Section
  if self.data.length() > 0 {
    let payload : Array[Byte] = []
    append_u32_leb128(payload, self.data.length())
    for d in self.data {
      append_u32_leb128(payload, d.mem_index)
      for instr in d.offset_expr {
        encode_instruction(payload, instr)
      }
      append_u32_leb128(payload, d.data.length())
      append_bytes(payload, d.data)
    }
    append_section(out, 11, payload)
  }

  out
}
