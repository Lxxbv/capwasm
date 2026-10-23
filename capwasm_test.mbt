// CapWasm Capability and Security Guard Integration Test Suite

///|
test "plugin sandbox: allowed file read" {
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.allow_read_path("./docs/").build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("good-plugin", policy)
  let result = sec_guard.check_fs_read("./docs/readme.txt")
  assert_eq(result, Ok(()))

  let logs = sec_guard.get_audit_logs()
  assert_eq(logs.length(), 1)
  assert_eq(logs[0].allowed, true)
}

///|
test "plugin sandbox: unauthorized path rejected" {
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.allow_read_path("./docs/").build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("evil-plugin", policy)
  let result = sec_guard.check_fs_read("./secret/key.pem")
  assert_eq(
    result,
    Err(
      @capwasm.SecurityError::PermissionDenied(
        "Path not allowed: ./secret/key.pem",
      ),
    ),
  )

  let logs = sec_guard.get_audit_logs()
  assert_eq(logs.length(), 1)
  assert_eq(logs[0].allowed, false)
}

///|
test "plugin sandbox: path traversal attack blocked" {
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.allow_read_path("./docs/").build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("attacker-plugin", policy)
  let result = sec_guard.check_fs_read("./docs/../../etc/passwd")
  assert_eq(
    result,
    Err(@capwasm.SecurityError::PathTraversalAttempt("./docs/../../etc/passwd")),
  )

  let logs = sec_guard.get_audit_logs()
  assert_eq(logs.length(), 1)
  assert_eq(logs[0].allowed, false)
}

///|
test "plugin sandbox: write permissions enforced" {
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.allow_write_path("/tmp/output/").build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("writer-plugin", policy)

  assert_eq(sec_guard.check_fs_write("/tmp/output/result.json"), Ok(()))
  assert_eq(
    sec_guard.check_fs_write("/etc/crontab"),
    Err(
      @capwasm.SecurityError::PermissionDenied(
        "Write not allowed: /etc/crontab",
      ),
    ),
  )
  assert_eq(
    sec_guard.check_fs_write("/tmp/output/../escaped.txt"),
    Err(
      @capwasm.SecurityError::PathTraversalAttempt("/tmp/output/../escaped.txt"),
    ),
  )
}

///|
test "plugin sandbox: network isolation" {
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.allow_network_host("api.trusted.com").build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("net-plugin", policy)
  assert_eq(sec_guard.check_network("api.trusted.com"), Ok(()))

  let evil_net = sec_guard.check_network("malicious-c2.net")
  assert_eq(
    evil_net,
    Err(
      @capwasm.SecurityError::PermissionDenied(
        "Network forbidden: malicious-c2.net",
      ),
    ),
  )
}

///|
test "plugin sandbox: step quota limits infinite loop" {
  let quota = @capwasm.ResourceQuota::default()
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.set_quota(quota).build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("loop-plugin", policy)
  assert_eq(sec_guard.consume_steps(50000), Ok(()))
  assert_eq(sec_guard.consume_steps(40000), Ok(()))

  let over = sec_guard.consume_steps(20000)
  assert_eq(
    over,
    Err(@capwasm.SecurityError::OutOfQuota("Instruction limit exceeded")),
  )
}

///|
test "plugin sandbox: memory slice and host context" {
  let slice = @capwasm.MemorySlice::new(1024, 64)
  assert_eq(slice.offset, 1024)
  assert_eq(slice.length, 64)

  let ctx = @capwasm.HostContext::new("ctx-test")
  let limits = @capwasm.Limits::{ min: 1, max: Some(1), }
  let mem = match @capwasm.LinearMemory::new(limits) {
    Ok(m) => m
    Err(_) => return
  }

  ctx.set_memory(mem)
  assert_true(ctx.get_memory() is Ok(_))
}

///|
test "plugin sandbox: linker host registration" {
  let linker = @capwasm.Linker::new()
  let sig = @capwasm.FuncType::new([], [])
  let host_fn = @capwasm.HostFunction::new(sig, fn(_ctx, _args) { Ok([]) })

  linker.register_func("env", "test_fn", host_fn)
  assert_true(linker.resolve_func("env", "test_fn") is Some(_))
  assert_true(linker.resolve_func("env", "missing_fn") is None)
}
