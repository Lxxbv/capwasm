// CapWasm: Stack-Based WebAssembly Execution Engine
// Implements instruction dispatch, arithmetic primitives, structured branching, and gas limits.

///|
/// GlobalInstance holds runtime mutable or immutable global values.
pub(all) struct GlobalInstance {
  mut val : Value
  mutability : Mutability
}

///|
pub fn GlobalInstance::new(
  val : Value,
  mutability : Mutability,
) -> GlobalInstance {
  { val, mutability, }
}

///|
/// FunctionInstance represents either an internal defined function or an imported host function.
pub(all) enum FunctionInstance {
  Defined(FuncType, FunctionBody)
  Host(HostFunction)
}

///|
/// WasmInstance represents an instantiated, executable WebAssembly module.
pub(all) struct WasmInstance {
  functions : Array[FunctionInstance]
  memories : Array[LinearMemory]
  globals : Array[GlobalInstance]
  stack : OperandStack
  call_stack : Array[CallFrame]
  control_stack : Array[ControlFrame]
  host_context : HostContext
  mut gas_limit : Int
  mut gas_consumed : Int
}

///|
pub fn WasmInstance::new(
  functions : Array[FunctionInstance],
  memories : Array[LinearMemory],
  globals : Array[GlobalInstance],
  host_context : HostContext,
  gas_limit : Int,
) -> WasmInstance {
  {
    functions,
    memories,
    globals,
    stack: OperandStack::new(2048),
    call_stack: [],
    control_stack: [],
    host_context,
    gas_limit,
    gas_consumed: 0,
  }
}

///|
pub fn WasmInstance::get_memory(
  self : WasmInstance,
  idx : Int,
) -> Result[LinearMemory, Trap] {
  if idx < 0 || idx >= self.memories.length() {
    Err(Trap::UnknownMemory(idx))
  } else {
    Ok(self.memories[idx])
  }
}

///|
pub fn WasmInstance::consume_gas(
  self : WasmInstance,
  amount : Int,
) -> Result[Unit, Trap] {
  self.gas_consumed = self.gas_consumed + amount
  if self.gas_limit > 0 && self.gas_consumed > self.gas_limit {
    Err(Trap::GasExhausted(self.gas_consumed, self.gas_limit))
  } else {
    Ok(())
  }
}

///|
/// Invokes a function by its index in the module function table.
pub fn WasmInstance::invoke(
  self : WasmInstance,
  func_index : Int,
  args : Array[Value],
) -> Result[Array[Value], Trap] {
  if func_index < 0 || func_index >= self.functions.length() {
    return Err(Trap::UnknownFunction(func_index))
  }

  match self.functions[func_index] {
    FunctionInstance::Host(hf) => {
      // Direct host function execution
      match self.consume_gas(10) {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
      (hf.callback)(self.host_context, args)
    }
    FunctionInstance::Defined(ft, body) => {
      if args.length() != ft.params.length() {
        return Err(
          Trap::TypeMismatch(
            "Argument count mismatch: expected \{ft.params.length()}, got \{args.length()}",
          ),
        )
      }

      // Prepare locals: args + declared locals (initialized to zero)
      let locals = Array::new(capacity=args.length() + body.locals.length())
      for a in args {
        locals.push(a)
      }
      for decl in body.locals {
        for i = 0; i < decl.count; i = i + 1 {
          let zero_val = match decl.val_type {
            ValueType::I32 => Value::I32(0)
            ValueType::I64 => Value::I64(0L)
            ValueType::F32 => Value::F32(0.0)
            ValueType::F64 => Value::F64(0.0)
          }
          locals.push(zero_val)
        }
      }

      let frame = CallFrame::new(
        func_index,
        locals,
        self.stack.height(),
        self.control_stack.length(),
        ft.results,
      )
      self.call_stack.push(frame)

      // Push function-level control frame
      self.control_stack.push(
        ControlFrame::new(
          ControlBlockType::Function(ft),
          self.stack.height(),
          body.instructions.length(),
          None,
        ),
      )

      match self.execute_bytecode(body) {
        Ok(vals) => Ok(vals)
        Err(e) => Err(e)
      }
    }
  }
}

///|
fn find_matching_end(instructions : Array[Instruction], start_pc : Int) -> Int {
  let mut depth = 1
  let mut pc = start_pc
  while pc < instructions.length() {
    match instructions[pc] {
      Instruction::Block(_) | Instruction::Loop(_) | Instruction::If(_) =>
        depth = depth + 1
      Instruction::End => {
        depth = depth - 1
        if depth == 0 {
          return pc
        }
      }
      _ => ()
    }
    pc = pc + 1
  }
  instructions.length()
}

///|
fn WasmInstance::execute_bytecode(
  self : WasmInstance,
  body : FunctionBody,
) -> Result[Array[Value], Trap] {
  let initial_call_depth = self.call_stack.length()
  let curr_frame = self.call_stack[initial_call_depth - 1]
  let ret_count = match self.functions[curr_frame.func_index] {
    FunctionInstance::Defined(ft, _) => ft.results.length()
    _ => 0
  }

  while self.call_stack.length() >= initial_call_depth {
    let curr_frame = self.call_stack[self.call_stack.length() - 1]
    if curr_frame.pc >= body.instructions.length() {
      // Reached end of current function body without explicit return
      let _ = self.call_stack.pop()
      let _ = self.control_stack.pop()
      break
    }

    let instr = body.instructions[curr_frame.pc]
    curr_frame.pc = curr_frame.pc + 1

    match self.consume_gas(1) {
      Ok(_) => ()
      Err(e) => return Err(e)
    }

    match instr {
      Instruction::Unreachable => return Err(Trap::Unreachable)
      Instruction::Nop => ()
      Instruction::End => {
        if self.control_stack.length() > curr_frame.control_base {
          let _ = self.control_stack.pop()
        }
        if self.control_stack.length() == curr_frame.control_base {
          // Reached end of function block
          let _ = self.call_stack.pop()
          break
        }
      }
      Instruction::Return => {
        while self.control_stack.length() > curr_frame.control_base {
          let _ = self.control_stack.pop()
        }
        let _ = self.call_stack.pop()
        break
      }
      Instruction::Block(bt) => {
        let end_pc = find_matching_end(body.instructions, curr_frame.pc)
        self.control_stack.push(
          ControlFrame::new(
            ControlBlockType::Block(bt),
            self.stack.height(),
            end_pc,
            None,
          ),
        )
      }
      Instruction::Loop(bt) => {
        let loop_start = curr_frame.pc
        let end_pc = find_matching_end(body.instructions, curr_frame.pc)
        self.control_stack.push(
          ControlFrame::new(
            ControlBlockType::Loop(bt),
            self.stack.height(),
            end_pc,
            Some(loop_start),
          ),
        )
      }
      Instruction::Br(depth) => {
        let target_idx = self.control_stack.length() - 1 - depth
        if target_idx < curr_frame.control_base {
          return Err(Trap::Unreachable)
        }
        let target_frame = self.control_stack[target_idx]
        match target_frame.loop_pc {
          Some(loop_pc) => {
            while self.control_stack.length() > target_idx + 1 {
              let _ = self.control_stack.pop()
            }
            curr_frame.pc = loop_pc
          }
          None => {
            while self.control_stack.length() > target_idx {
              let _ = self.control_stack.pop()
            }
            curr_frame.pc = target_frame.continuation_pc
          }
        }
      }
      Instruction::BrIf(depth) => {
        let cond = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        if cond != 0 {
          let target_idx = self.control_stack.length() - 1 - depth
          if target_idx < curr_frame.control_base {
            return Err(Trap::Unreachable)
          }
          let target_frame = self.control_stack[target_idx]
          match target_frame.loop_pc {
            Some(loop_pc) => {
              while self.control_stack.length() > target_idx + 1 {
                let _ = self.control_stack.pop()
              }
              curr_frame.pc = loop_pc
            }
            None => {
              while self.control_stack.length() > target_idx {
                let _ = self.control_stack.pop()
              }
              curr_frame.pc = target_frame.continuation_pc
            }
          }
        }
      }
      Instruction::Drop => {
        let _ = match self.stack.pop() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
      }
      Instruction::Select => {
        let cond = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let val2 = match self.stack.pop() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let val1 = match self.stack.pop() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        if cond != 0 {
          match self.stack.push(val1) {
            Ok(_) => ()
            Err(e) => return Err(e)
          }
        } else {
          match self.stack.push(val2) {
            Ok(_) => ()
            Err(e) => return Err(e)
          }
        }
      }

      // Constants
      Instruction::I32Const(c) =>
        match self.stack.push(Value::I32(c)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      Instruction::I64Const(c) =>
        match self.stack.push(Value::I64(c)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }

      // Locals
      Instruction::LocalGet(idx) => {
        let val = match curr_frame.get_local(idx) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(val) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::LocalSet(idx) => {
        let val = match self.stack.pop() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match curr_frame.set_local(idx, val) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::LocalTee(idx) => {
        let val = match self.stack.peek() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match curr_frame.set_local(idx, val) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }

      // Globals
      Instruction::GlobalGet(idx) => {
        if idx < 0 || idx >= self.globals.length() {
          return Err(Trap::UnknownGlobal(idx))
        }
        match self.stack.push(self.globals[idx].val) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::GlobalSet(idx) => {
        if idx < 0 || idx >= self.globals.length() {
          return Err(Trap::UnknownGlobal(idx))
        }
        let g = self.globals[idx]
        if g.mutability == Mutability::Const {
          return Err(
            Trap::TypeMismatch("Cannot mutate immutable global \{idx}"),
          )
        }
        let val = match self.stack.pop() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        g.val = val
      }

      // Function calls
      Instruction::Call(callee_idx) => {
        if callee_idx < 0 || callee_idx >= self.functions.length() {
          return Err(Trap::UnknownFunction(callee_idx))
        }
        let callee = self.functions[callee_idx]
        let (param_count, _) = match callee {
          FunctionInstance::Defined(ft, _) =>
            (ft.params.length(), ft.results.length())
          FunctionInstance::Host(hf) =>
            (hf.func_type.params.length(), hf.func_type.results.length())
        }

        let args = match self.stack.pop_n(param_count) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let results = match self.invoke(callee_idx, args) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        for r in results {
          match self.stack.push(r) {
            Ok(_) => ()
            Err(e) => return Err(e)
          }
        }
      }

      // Integer arithmetic (i32)
      Instruction::I32Add => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(a + b)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Sub => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(a - b)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Mul => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(a * b)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32DivS => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        if b == 0 {
          return Err(Trap::DivisionByZero)
        }
        match self.stack.push(Value::I32(a / b)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32RemS => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        if b == 0 {
          return Err(Trap::DivisionByZero)
        }
        match self.stack.push(Value::I32(a % b)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32And => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(a & b)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Or => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(a | b)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Xor => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(a ^ b)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Shl => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(a << (b & 31))) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32ShrS => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(a >> (b & 31))) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }

      // Comparisons (i32)
      Instruction::I32Eqz => {
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let res = if a == 0 { 1 } else { 0 }
        match self.stack.push(Value::I32(res)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Eq => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let res = if a == b { 1 } else { 0 }
        match self.stack.push(Value::I32(res)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Ne => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let res = if a != b { 1 } else { 0 }
        match self.stack.push(Value::I32(res)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32LtS => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let res = if a < b { 1 } else { 0 }
        match self.stack.push(Value::I32(res)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32GtS => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let res = if a > b { 1 } else { 0 }
        match self.stack.push(Value::I32(res)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32LeS => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let res = if a <= b { 1 } else { 0 }
        match self.stack.push(Value::I32(res)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32GeS => {
        let b = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let a = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let res = if a >= b { 1 } else { 0 }
        match self.stack.push(Value::I32(res)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }

      // Memory operations
      Instruction::I32Load(arg) => {
        let base = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let mem = match self.get_memory(0) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let val = match mem.read_i32(base + arg.offset) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(val)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Load8U(arg) => {
        let base = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let mem = match self.get_memory(0) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let val = match mem.read_u8(base + arg.offset) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(val)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Store(arg) => {
        let val = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let base = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let mem = match self.get_memory(0) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match mem.write_i32(base + arg.offset, val) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::I32Store8(arg) => {
        let val = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let base = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let mem = match self.get_memory(0) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match mem.write_u8(base + arg.offset, val) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::MemorySize => {
        let mem = match self.get_memory(0) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        match self.stack.push(Value::I32(mem.size_in_pages())) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      Instruction::MemoryGrow => {
        let delta = match self.stack.pop_i32() {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let mem = match self.get_memory(0) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let prev_pages = mem.grow(delta)
        match self.stack.push(Value::I32(prev_pages)) {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      _ => ()
    }
  }

  // Collect return results
  self.stack.pop_n(ret_count)
}

///|
pub fn WasmInstance::get_consumed_gas(self : WasmInstance) -> Int {
  self.gas_consumed
}

///|
pub fn WasmInstance::call_exported(
  self : WasmInstance,
  module_def : WasmModule,
  func_name : String,
  args : Array[Value],
) -> Result[Array[Value], Trap] {
  for exp in module_def.exports {
    if exp.name == func_name {
      match exp.desc {
        ExportDesc::Func(idx) => return self.invoke(idx, args)
        _ =>
          return Err(Trap::HostError("Export is not a function: " + func_name))
      }
    }
  }
  Err(Trap::HostError("Export not found: " + func_name))
}

///|
pub fn WasmModule::instantiate(
  self : WasmModule,
  linker : Linker,
  host_context : HostContext,
  gas_limit : Int,
) -> Result[WasmInstance, Trap] {
  let funcs = Array::new()
  let mems = Array::new()
  let globs = Array::new()

  // 1. Process imported functions & memories
  for imp in self.imports {
    match imp.desc {
      ImportDesc::Func(_type_idx) =>
        match linker.resolve_func(imp.mod_name, imp.field_name) {
          Some(hf) => funcs.push(FunctionInstance::Host(hf))
          None =>
            return Err(
              Trap::HostError(
                "Unresolved import function: " +
                imp.mod_name +
                "." +
                imp.field_name,
              ),
            )
        }
      ImportDesc::Mem(_) =>
        match linker.resolve_memory(imp.mod_name, imp.field_name) {
          Some(mem) => mems.push(mem)
          None =>
            return Err(
              Trap::HostError(
                "Unresolved import memory: " +
                imp.mod_name +
                "." +
                imp.field_name,
              ),
            )
        }
      _ => ()
    }
  }

  // 2. Process defined functions
  for i = 0; i < self.code.length(); i = i + 1 {
    let ft_idx = self.func_types[i]
    let ft = self.types[ft_idx]
    let body = self.code[i]
    funcs.push(FunctionInstance::Defined(ft, body))
  }

  // 3. Process defined memories
  for m in self.memories {
    match LinearMemory::new(m.limits) {
      Ok(mem) => mems.push(mem)
      Err(e) => return Err(e)
    }
  }

  // Connect memory to host_context
  if mems.length() > 0 {
    host_context.set_memory(mems[0])
  }

  // 4. Process defined globals
  for g in self.globals {
    let init_val = if g.init_expr.length() > 0 {
      match g.init_expr[0] {
        Instruction::I32Const(v) => Value::I32(v)
        Instruction::I64Const(v) => Value::I64(v)
        Instruction::F32Const(v) => Value::F32(v)
        Instruction::F64Const(v) => Value::F64(v)
        _ => Value::I32(0)
      }
    } else {
      Value::I32(0)
    }
    globs.push(GlobalInstance::new(init_val, g.global_type.mutability))
  }

  // 5. Initialize data segments
  for d in self.data {
    let offset = if d.offset_expr.length() > 0 {
      match d.offset_expr[0] {
        Instruction::I32Const(v) => v
        _ => 0
      }
    } else {
      0
    }
    if d.mem_index < mems.length() {
      let target_mem = mems[d.mem_index]
      match target_mem.write_bytes(offset, d.data) {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
  }

  let instance = WasmInstance::new(funcs, mems, globs, host_context, gas_limit)

  // 6. Execute start function if present
  match self.start_func {
    Some(sf) => {
      let _ = instance.invoke(sf, [])
      ()
    }
    None => ()
  }

  Ok(instance)
}
