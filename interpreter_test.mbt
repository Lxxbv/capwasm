// CapWasm Interpreter & Execution Engine Test Suite

///|
test "interpreter: operand stack basic operations" {
  let stack = @capwasm.OperandStack::new(16)
  assert_eq(stack.height(), 0)

  let _ = stack.push(@capwasm.Value::I32(42))
  let _ = stack.push(@capwasm.Value::I32(100))
  assert_eq(stack.height(), 2)

  let top = stack.peek()
  assert_eq(top, Ok(@capwasm.Value::I32(100)))

  let val1 = stack.pop_i32()
  assert_eq(val1, Ok(100))

  let val2 = stack.pop_i32()
  assert_eq(val2, Ok(42))

  assert_eq(stack.height(), 0)
  assert_eq(stack.pop(), Err(@capwasm.Trap::StackUnderflow))
}

///|
test "interpreter: i32 arithmetic instructions" {
  // Test function: (add, sub, mul)
  // func(a, b): return (a + b) * (a - b)
  let ft = @capwasm.FuncType::new(
    [@capwasm.ValueType::I32, @capwasm.ValueType::I32],
    [@capwasm.ValueType::I32],
  )
  let body = @capwasm.FunctionBody::new([], [
    @capwasm.Instruction::LocalGet(0),
    @capwasm.Instruction::LocalGet(1),
    @capwasm.Instruction::I32Add,
    @capwasm.Instruction::LocalGet(0),
    @capwasm.Instruction::LocalGet(1),
    @capwasm.Instruction::I32Sub,
    @capwasm.Instruction::I32Mul,
  ])

  let funcs = [@capwasm.FunctionInstance::Defined(ft, body)]
  let host_ctx = @capwasm.HostContext::new("test-math")
  let inst = @capwasm.WasmInstance::new(funcs, [], [], host_ctx, 1000)

  // (10 + 4) * (10 - 4) = 14 * 6 = 84
  let res = inst.invoke(0, [@capwasm.Value::I32(10), @capwasm.Value::I32(4)])
  assert_eq(res, Ok([@capwasm.Value::I32(84)]))
}

///|
test "interpreter: i32 division by zero trap" {
  let ft = @capwasm.FuncType::new(
    [@capwasm.ValueType::I32, @capwasm.ValueType::I32],
    [@capwasm.ValueType::I32],
  )
  let body = @capwasm.FunctionBody::new([], [
    @capwasm.Instruction::LocalGet(0),
    @capwasm.Instruction::LocalGet(1),
    @capwasm.Instruction::I32DivS,
  ])

  let funcs = [@capwasm.FunctionInstance::Defined(ft, body)]
  let host_ctx = @capwasm.HostContext::new("test-div")
  let inst = @capwasm.WasmInstance::new(funcs, [], [], host_ctx, 1000)

  let res = inst.invoke(0, [@capwasm.Value::I32(50), @capwasm.Value::I32(0)])
  assert_eq(res, Err(@capwasm.Trap::DivisionByZero))
}

///|
test "interpreter: i32 comparison logic" {
  let ft = @capwasm.FuncType::new(
    [@capwasm.ValueType::I32, @capwasm.ValueType::I32],
    [@capwasm.ValueType::I32],
  )
  let body = @capwasm.FunctionBody::new([], [
    @capwasm.Instruction::LocalGet(0),
    @capwasm.Instruction::LocalGet(1),
    @capwasm.Instruction::I32LtS,
  ])

  let funcs = [@capwasm.FunctionInstance::Defined(ft, body)]
  let host_ctx = @capwasm.HostContext::new("test-cmp")
  let inst = @capwasm.WasmInstance::new(funcs, [], [], host_ctx, 1000)

  let r1 = inst.invoke(0, [@capwasm.Value::I32(5), @capwasm.Value::I32(10)])
  assert_eq(r1, Ok([@capwasm.Value::I32(1)]))

  let r2 = inst.invoke(0, [@capwasm.Value::I32(20), @capwasm.Value::I32(10)])
  assert_eq(r2, Ok([@capwasm.Value::I32(0)]))
}

///|
test "interpreter: local variable mutation" {
  // func(): var x = 10; x = x + 5; return x
  let ft = @capwasm.FuncType::new([], [@capwasm.ValueType::I32])
  let body = @capwasm.FunctionBody::new(
    [@capwasm.LocalDecl::new(1, @capwasm.ValueType::I32)],
    [
      @capwasm.Instruction::I32Const(10),
      @capwasm.Instruction::LocalSet(0),
      @capwasm.Instruction::LocalGet(0),
      @capwasm.Instruction::I32Const(5),
      @capwasm.Instruction::I32Add,
      @capwasm.Instruction::LocalTee(0),
    ],
  )

  let funcs = [@capwasm.FunctionInstance::Defined(ft, body)]
  let host_ctx = @capwasm.HostContext::new("test-locals")
  let inst = @capwasm.WasmInstance::new(funcs, [], [], host_ctx, 1000)

  let res = inst.invoke(0, [])
  assert_eq(res, Ok([@capwasm.Value::I32(15)]))
}

///|
test "interpreter: gas limit enforcement on infinite loops" {
  // Loop forever: loop { br 0 }
  let ft = @capwasm.FuncType::new([], [])
  let body = @capwasm.FunctionBody::new([], [
    @capwasm.Instruction::Loop(@capwasm.BlockType::Empty),
    @capwasm.Instruction::Br(0),
    @capwasm.Instruction::End,
  ])

  let funcs = [@capwasm.FunctionInstance::Defined(ft, body)]
  let host_ctx = @capwasm.HostContext::new("test-gas")
  // Limit execution to 200 steps
  let inst = @capwasm.WasmInstance::new(funcs, [], [], host_ctx, 200)

  let res = inst.invoke(0, [])
  assert_true(res is Err(@capwasm.Trap::GasExhausted(_, _)))
  assert_true(inst.get_consumed_gas() > 200)
}

///|
test "interpreter: linear memory load and store" {
  let limits = @capwasm.Limits::{ min: 1, max: Some(2), }
  let mem = match @capwasm.LinearMemory::new(limits) {
    Ok(m) => m
    Err(_) => return
  }

  // func(): store 0x12345678 at offset 4, then load it back
  let ft = @capwasm.FuncType::new([], [@capwasm.ValueType::I32])
  let mem_arg = @capwasm.MemArg::new(2, 4)
  let body = @capwasm.FunctionBody::new([], [
    @capwasm.Instruction::I32Const(0), // base offset 0
    @capwasm.Instruction::I32Const(0x12345678),
    @capwasm.Instruction::I32Store(mem_arg),
    @capwasm.Instruction::I32Const(0), // load from base offset 0 + align 4
    @capwasm.Instruction::I32Load(mem_arg),
  ])

  let funcs = [@capwasm.FunctionInstance::Defined(ft, body)]
  let host_ctx = @capwasm.HostContext::new("test-mem")
  let inst = @capwasm.WasmInstance::new(funcs, [mem], [], host_ctx, 1000)

  let res = inst.invoke(0, [])
  assert_eq(res, Ok([@capwasm.Value::I32(0x12345678)]))
}

///|
test "interpreter: structured if-else control flow and i64 arithmetic" {
  // func(x: i32) -> i64:
  //   if x > 0 { return i64.extend_i32_s(x) * 100L } else { return 42L }
  let ft = @capwasm.FuncType::new([@capwasm.ValueType::I32], [
    @capwasm.ValueType::I64,
  ])
  let body = @capwasm.FunctionBody::new([], [
    @capwasm.Instruction::LocalGet(0),
    @capwasm.Instruction::I32Const(0),
    @capwasm.Instruction::I32GtS,
    @capwasm.Instruction::If(@capwasm.BlockType::Value(@capwasm.ValueType::I64)),
    @capwasm.Instruction::LocalGet(0),
    @capwasm.Instruction::I64ExtendI32S,
    @capwasm.Instruction::I64Const(100L),
    @capwasm.Instruction::I64Mul,
    @capwasm.Instruction::Else,
    @capwasm.Instruction::I64Const(42L),
    @capwasm.Instruction::End,
    @capwasm.Instruction::End,
  ])

  let funcs = [@capwasm.FunctionInstance::Defined(ft, body)]
  let host_ctx = @capwasm.HostContext::new("test-if-i64")
  let inst = @capwasm.WasmInstance::new(funcs, [], [], host_ctx, 1000)

  let r_pos = inst.invoke(0, [@capwasm.Value::I32(7)])
  assert_eq(r_pos, Ok([@capwasm.Value::I64(700L)]))

  let r_neg = inst.invoke(0, [@capwasm.Value::I32(-3)])
  assert_eq(r_neg, Ok([@capwasm.Value::I64(42L)]))
}

///|
test "interpreter: memory.grow respects capability security guard ceiling" {
  let limits = @capwasm.Limits::{ min: 1, max: Some(8), }
  let mem = match @capwasm.LinearMemory::new(limits) {
    Ok(m) => m
    Err(_) => return
  }
  let policy = @capwasm.CapabilityPolicyBuilder::new()
    .max_memory_pages(2)
    .build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("mem-grow-guard", policy)
  let host_ctx = @capwasm.HostContext::new("mem-grow-guard")
  host_ctx.set_guard(sec_guard)

  // func(delta: i32) -> i32 { memory.grow(delta) }
  let ft = @capwasm.FuncType::new([@capwasm.ValueType::I32], [
    @capwasm.ValueType::I32,
  ])
  let body = @capwasm.FunctionBody::new([], [
    @capwasm.Instruction::LocalGet(0),
    @capwasm.Instruction::MemoryGrow,
    @capwasm.Instruction::End,
  ])
  let funcs = [@capwasm.FunctionInstance::Defined(ft, body)]
  let inst = @capwasm.WasmInstance::new(funcs, [mem], [], host_ctx, 1000)

  // Grow by 1 page (1 -> 2 pages, within max_memory_pages=2) -> returns previous size 1
  let ok_grow = inst.invoke(0, [@capwasm.Value::I32(1)])
  assert_eq(ok_grow, Ok([@capwasm.Value::I32(1)]))

  // Grow by another 1 page (2 -> 3 pages, exceeds max_memory_pages=2) -> denied, returns -1
  let denied_grow = inst.invoke(0, [@capwasm.Value::I32(1)])
  assert_eq(denied_grow, Ok([@capwasm.Value::I32(-1)]))
}
