// CapWasm: Execution Stack and Control Frame Architecture
// Manages runtime operand evaluation stacks, call frames, and structured branch targets.

///|
/// ControlBlockType categorizes control flow constructs.
pub(all) enum ControlBlockType {
  Block(BlockType)
  Loop(BlockType)
  If(BlockType)
  Function(FuncType)
} derive(Eq)

///|
pub impl Show for ControlBlockType with fn output(self, logger) {
  match self {
    Block(bt) => logger.write_string("Block(\{bt})")
    Loop(bt) => logger.write_string("Loop(\{bt})")
    If(bt) => logger.write_string("If(\{bt})")
    Function(ft) => logger.write_string("Function(\{ft})")
  }
}

///|
/// ControlFrame tracks block/loop/if targets for relative branching instructions.
pub(all) struct ControlFrame {
  kind : ControlBlockType
  stack_height : Int32
  continuation_pc : Int32
  loop_pc : Int32?
} derive(Eq)

///|
pub fn ControlFrame::new(
  kind : ControlBlockType,
  stack_height : Int32,
  continuation_pc : Int32,
  loop_pc : Int32?,
) -> ControlFrame {
  { kind, stack_height, continuation_pc, loop_pc, }
}

///|
/// CallFrame represents a single function invocation context.
pub(all) struct CallFrame {
  func_index : Int32
  locals : Array[Value]
  mut pc : Int32
  stack_base : Int32
  control_base : Int32
  result_types : Array[ValueType]
}

///|
pub fn CallFrame::new(
  func_index : Int32,
  locals : Array[Value],
  stack_base : Int32,
  control_base : Int32,
  result_types : Array[ValueType],
) -> CallFrame {
  { func_index, locals, pc: 0, stack_base, control_base, result_types, }
}

///|
pub fn CallFrame::get_local(
  self : CallFrame,
  idx : Int32,
) -> Result[Value, Trap] {
  if idx < 0 || idx >= self.locals.length() {
    Err(Trap::TypeMismatch("Local variable index out of bounds: \{idx}"))
  } else {
    Ok(self.locals[idx])
  }
}

///|
pub fn CallFrame::set_local(
  self : CallFrame,
  idx : Int32,
  val : Value,
) -> Result[Unit, Trap] {
  if idx < 0 || idx >= self.locals.length() {
    Err(Trap::TypeMismatch("Local variable index out of bounds: \{idx}"))
  } else {
    self.locals[idx] = val
    Ok(())
  }
}

///|
/// OperandStack provides a LIFO evaluation stack for runtime values.
pub(all) struct OperandStack {
  values : Array[Value]
  max_depth : Int32
}

///|
pub fn OperandStack::new(max_depth : Int32) -> OperandStack {
  { values: [], max_depth, }
}

///|
pub fn OperandStack::height(self : OperandStack) -> Int32 {
  self.values.length()
}

///|
pub fn OperandStack::push(
  self : OperandStack,
  val : Value,
) -> Result[Unit, Trap] {
  if self.values.length() >= self.max_depth {
    Err(Trap::StackOverflow)
  } else {
    self.values.push(val)
    Ok(())
  }
}

///|
pub fn OperandStack::pop(self : OperandStack) -> Result[Value, Trap] {
  let len = self.values.length()
  if len <= 0 {
    Err(Trap::StackUnderflow)
  } else {
    let last = self.values[len - 1]
    let _ = self.values.pop()
    Ok(last)
  }
}

///|
pub fn OperandStack::pop_i32(self : OperandStack) -> Result[Int32, Trap] {
  let val = match self.pop() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  val.as_i32()
}

///|
pub fn OperandStack::pop_i64(self : OperandStack) -> Result[Int64, Trap] {
  let val = match self.pop() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  val.as_i64()
}

///|
pub fn OperandStack::peek(self : OperandStack) -> Result[Value, Trap] {
  let len = self.values.length()
  if len <= 0 {
    Err(Trap::StackUnderflow)
  } else {
    Ok(self.values[len - 1])
  }
}

///|
pub fn OperandStack::truncate(
  self : OperandStack,
  target_height : Int32,
) -> Result[Unit, Trap] {
  if target_height < 0 || target_height > self.values.length() {
    Err(Trap::StackUnderflow)
  } else {
    while self.values.length() > target_height {
      let _ = self.values.pop()
    }
    Ok(())
  }
}

///|
pub fn OperandStack::pop_n(
  self : OperandStack,
  n : Int32,
) -> Result[Array[Value], Trap] {
  if n < 0 || self.values.length() < n {
    return Err(Trap::StackUnderflow)
  }
  let res = Array::new(capacity=n)
  let start_idx = self.values.length() - n
  for i = 0; i < n; i = i + 1 {
    res.push(self.values[start_idx + i])
  }
  for i = 0; i < n; i = i + 1 {
    let _ = self.values.pop()
  }
  Ok(res)
}
