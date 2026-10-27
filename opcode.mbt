// CapWasm: WebAssembly 1.0 Instruction Set and Opcode Definitions
// Implements core opcode specifications, immediate arguments, and instruction AST.

///|
/// MemArg represents memory access immediate arguments (alignment & offset).
pub(all) struct MemArg {
  align : Int32
  offset : Int32
} derive(Eq)

///|
pub impl Show for MemArg with fn output(self, logger) {
  logger.write_string("MemArg(align=\{self.align}, offset=\{self.offset})")
}

///|
pub fn MemArg::new(align : Int32, offset : Int32) -> MemArg {
  { align, offset, }
}

///|
/// BlockType describes return type of block/loop/if constructs.
pub(all) enum BlockType {
  Empty
  Value(ValueType)
  FuncTypeIndex(Int32)
} derive(Eq)

///|
pub impl Show for BlockType with fn output(self, logger) {
  match self {
    Empty => logger.write_string("BlockType::Empty")
    Value(t) => logger.write_string("BlockType::Value(\{t})")
    FuncTypeIndex(idx) => logger.write_string("BlockType::TypeIndex(\{idx})")
  }
}

///|
/// Instruction represents a decoded WebAssembly bytecode instruction.
pub(all) enum Instruction {
  // Control Instructions
  Unreachable
  Nop
  Block(BlockType)
  Loop(BlockType)
  If(BlockType)
  Else
  End
  Br(Int32)
  BrIf(Int32)
  BrTable(Array[Int32], Int32)
  Return
  Call(Int32)
  CallIndirect(Int32, Int32)

  // Parametric Instructions
  Drop
  Select

  // Variable Instructions
  LocalGet(Int32)
  LocalSet(Int32)
  LocalTee(Int32)
  GlobalGet(Int32)
  GlobalSet(Int32)

  // Memory Instructions
  I32Load(MemArg)
  I64Load(MemArg)
  F32Load(MemArg)
  F64Load(MemArg)
  I32Load8S(MemArg)
  I32Load8U(MemArg)
  I32Load16S(MemArg)
  I32Load16U(MemArg)
  I64Load8S(MemArg)
  I64Load8U(MemArg)
  I64Load16S(MemArg)
  I64Load16U(MemArg)
  I64Load32S(MemArg)
  I64Load32U(MemArg)
  I32Store(MemArg)
  I64Store(MemArg)
  F32Store(MemArg)
  F64Store(MemArg)
  I32Store8(MemArg)
  I32Store16(MemArg)
  I64Store8(MemArg)
  I64Store16(MemArg)
  I64Store32(MemArg)
  MemorySize
  MemoryGrow

  // Constants
  I32Const(Int32)
  I64Const(Int64)
  F32Const(Float)
  F64Const(Double)

  // Comparison & Arithmetic (i32)
  I32Eqz
  I32Eq
  I32Ne
  I32LtS
  I32LtU
  I32GtS
  I32GtU
  I32LeS
  I32LeU
  I32GeS
  I32GeU
  I32Clz
  I32Ctz
  I32Popcnt
  I32Add
  I32Sub
  I32Mul
  I32DivS
  I32DivU
  I32RemS
  I32RemU
  I32And
  I32Or
  I32Xor
  I32Shl
  I32ShrS
  I32ShrU
  I32Rotl
  I32Rotr

  // Comparison & Arithmetic (i64)
  I64Eqz
  I64Eq
  I64Ne
  I64LtS
  I64LtU
  I64GtS
  I64GtU
  I64LeS
  I64LeU
  I64GeS
  I64GeU
  I64Clz
  I64Ctz
  I64Popcnt
  I64Add
  I64Sub
  I64Mul
  I64DivS
  I64DivU
  I64RemS
  I64RemU
  I64And
  I64Or
  I64Xor
  I64Shl
  I64ShrS
  I64ShrU
  I64Rotl
  I64Rotr

  // Conversions
  I32WrapI64
  I64ExtendI32S
  I64ExtendI32U
} derive(Eq)

///|
pub impl Show for Instruction with fn output(self, logger) {
  match self {
    Unreachable => logger.write_string("unreachable")
    Nop => logger.write_string("nop")
    Block(bt) => logger.write_string("block \{bt}")
    Loop(bt) => logger.write_string("loop \{bt}")
    If(bt) => logger.write_string("if \{bt}")
    Else => logger.write_string("else")
    End => logger.write_string("end")
    Br(idx) => logger.write_string("br \{idx}")
    BrIf(idx) => logger.write_string("br_if \{idx}")
    BrTable(targets, default) =>
      logger.write_string("br_table(\{targets.length()} -> \{default})")
    Return => logger.write_string("return")
    Call(idx) => logger.write_string("call \{idx}")
    CallIndirect(type_idx, table_idx) =>
      logger.write_string("call_indirect type=\{type_idx} table=\{table_idx}")
    Drop => logger.write_string("drop")
    Select => logger.write_string("select")
    LocalGet(idx) => logger.write_string("local.get \{idx}")
    LocalSet(idx) => logger.write_string("local.set \{idx}")
    LocalTee(idx) => logger.write_string("local.tee \{idx}")
    GlobalGet(idx) => logger.write_string("global.get \{idx}")
    GlobalSet(idx) => logger.write_string("global.set \{idx}")
    I32Load(arg) => logger.write_string("i32.load \{arg}")
    I64Load(arg) => logger.write_string("i64.load \{arg}")
    F32Load(arg) => logger.write_string("f32.load \{arg}")
    F64Load(arg) => logger.write_string("f64.load \{arg}")
    I32Load8S(arg) => logger.write_string("i32.load8_s \{arg}")
    I32Load8U(arg) => logger.write_string("i32.load8_u \{arg}")
    I32Load16S(arg) => logger.write_string("i32.load16_s \{arg}")
    I32Load16U(arg) => logger.write_string("i32.load16_u \{arg}")
    I64Load8S(arg) => logger.write_string("i64.load8_s \{arg}")
    I64Load8U(arg) => logger.write_string("i64.load8_u \{arg}")
    I64Load16S(arg) => logger.write_string("i64.load16_s \{arg}")
    I64Load16U(arg) => logger.write_string("i64.load16_u \{arg}")
    I64Load32S(arg) => logger.write_string("i64.load32_s \{arg}")
    I64Load32U(arg) => logger.write_string("i64.load32_u \{arg}")
    I32Store(arg) => logger.write_string("i32.store \{arg}")
    I64Store(arg) => logger.write_string("i64.store \{arg}")
    F32Store(arg) => logger.write_string("f32.store \{arg}")
    F64Store(arg) => logger.write_string("f64.store \{arg}")
    I32Store8(arg) => logger.write_string("i32.store8 \{arg}")
    I32Store16(arg) => logger.write_string("i32.store16 \{arg}")
    I64Store8(arg) => logger.write_string("i64.store8 \{arg}")
    I64Store16(arg) => logger.write_string("i64.store16 \{arg}")
    I64Store32(arg) => logger.write_string("i64.store32 \{arg}")
    MemorySize => logger.write_string("memory.size")
    MemoryGrow => logger.write_string("memory.grow")
    I32Const(c) => logger.write_string("i32.const \{c}")
    I64Const(c) => logger.write_string("i64.const \{c}")
    F32Const(c) => logger.write_string("f32.const \{c}")
    F64Const(c) => logger.write_string("f64.const \{c}")
    I32Eqz => logger.write_string("i32.eqz")
    I32Eq => logger.write_string("i32.eq")
    I32Ne => logger.write_string("i32.ne")
    I32LtS => logger.write_string("i32.lt_s")
    I32LtU => logger.write_string("i32.lt_u")
    I32GtS => logger.write_string("i32.gt_s")
    I32GtU => logger.write_string("i32.gt_u")
    I32LeS => logger.write_string("i32.le_s")
    I32LeU => logger.write_string("i32.le_u")
    I32GeS => logger.write_string("i32.ge_s")
    I32GeU => logger.write_string("i32.ge_u")
    I32Clz => logger.write_string("i32.clz")
    I32Ctz => logger.write_string("i32.ctz")
    I32Popcnt => logger.write_string("i32.popcnt")
    I32Add => logger.write_string("i32.add")
    I32Sub => logger.write_string("i32.sub")
    I32Mul => logger.write_string("i32.mul")
    I32DivS => logger.write_string("i32.div_s")
    I32DivU => logger.write_string("i32.div_u")
    I32RemS => logger.write_string("i32.rem_s")
    I32RemU => logger.write_string("i32.rem_u")
    I32And => logger.write_string("i32.and")
    I32Or => logger.write_string("i32.or")
    I32Xor => logger.write_string("i32.xor")
    I32Shl => logger.write_string("i32.shl")
    I32ShrS => logger.write_string("i32.shr_s")
    I32ShrU => logger.write_string("i32.shr_u")
    I32Rotl => logger.write_string("i32.rotl")
    I32Rotr => logger.write_string("i32.rotr")
    I64Eqz => logger.write_string("i64.eqz")
    I64Eq => logger.write_string("i64.eq")
    I64Ne => logger.write_string("i64.ne")
    I64LtS => logger.write_string("i64.lt_s")
    I64LtU => logger.write_string("i64.lt_u")
    I64GtS => logger.write_string("i64.gt_s")
    I64GtU => logger.write_string("i64.gt_u")
    I64LeS => logger.write_string("i64.le_s")
    I64LeU => logger.write_string("i64.le_u")
    I64GeS => logger.write_string("i64.ge_s")
    I64GeU => logger.write_string("i64.ge_u")
    I64Clz => logger.write_string("i64.clz")
    I64Ctz => logger.write_string("i64.ctz")
    I64Popcnt => logger.write_string("i64.popcnt")
    I64Add => logger.write_string("i64.add")
    I64Sub => logger.write_string("i64.sub")
    I64Mul => logger.write_string("i64.mul")
    I64DivS => logger.write_string("i64.div_s")
    I64DivU => logger.write_string("i64.div_u")
    I64RemS => logger.write_string("i64.rem_s")
    I64RemU => logger.write_string("i64.rem_u")
    I64And => logger.write_string("i64.and")
    I64Or => logger.write_string("i64.or")
    I64Xor => logger.write_string("i64.xor")
    I64Shl => logger.write_string("i64.shl")
    I64ShrS => logger.write_string("i64.shr_s")
    I64ShrU => logger.write_string("i64.shr_u")
    I64Rotl => logger.write_string("i64.rotl")
    I64Rotr => logger.write_string("i64.rotr")
    I32WrapI64 => logger.write_string("i32.wrap_i64")
    I64ExtendI32S => logger.write_string("i64.extend_i32_s")
    I64ExtendI32U => logger.write_string("i64.extend_i32_u")
  }
}
