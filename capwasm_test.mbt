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

test "plugin sandbox: unauthorized path rejected" {
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.allow_read_path("./docs/").build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("evil-plugin", policy)
  let result = sec_guard.check_fs_read("./secret/key.pem")
  assert_eq(result, Err(@capwasm.SecurityError::PermissionDenied("Path not allowed: ./secret/key.pem")))
  
  let logs = sec_guard.get_audit_logs()
  assert_eq(logs.length(), 1)
  assert_eq(logs[0].allowed, false)
}

test "plugin sandbox: path traversal attack blocked" {
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.allow_read_path("./docs/").build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("attacker-plugin", policy)
  let result = sec_guard.check_fs_read("./docs/../../etc/passwd")
  assert_eq(result, Err(@capwasm.SecurityError::PathTraversalAttempt("./docs/../../etc/passwd")))
  
  let logs = sec_guard.get_audit_logs()
  assert_eq(logs.length(), 1)
  assert_eq(logs[0].allowed, false)
}

test "plugin sandbox: network isolation" {
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.allow_network_host("api.trusted.com").build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("net-plugin", policy)
  assert_eq(sec_guard.check_network("api.trusted.com"), Ok(()))
  
  let evil_net = sec_guard.check_network("malicious-c2.net")
  assert_eq(evil_net, Err(@capwasm.SecurityError::PermissionDenied("Network forbidden: malicious-c2.net")))
}

test "plugin sandbox: step quota limits infinite loop" {
  let quota = @capwasm.ResourceQuota::default()
  let builder = @capwasm.CapabilityPolicyBuilder::new()
  let policy = builder.set_quota(quota).build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("loop-plugin", policy)
  assert_eq(sec_guard.consume_steps(50000), Ok(()))
  assert_eq(sec_guard.consume_steps(40000), Ok(()))
  
  let over = sec_guard.consume_steps(20000)
  assert_eq(over, Err(@capwasm.SecurityError::OutOfQuota("Instruction limit exceeded")))
}
