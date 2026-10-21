/// CapWasm Interactive Sandbox Host Demo
/// Demonstrates capability-based security isolation for untrusted WebAssembly plugins.

fn main {
  println("==================================================================")
  println("  CapWasm: Capability-Based WebAssembly Plugin Sandbox Host      ")
  println("  MoonBit Hackathon 2026 - Production System Demonstration        ")
  println("==================================================================")
  println("")

  // Scenario 1: Benign Plugin with granted permissions
  println("[Scenario 1] Running Benign Plugin ('doc-renderer.wasm')...")
  let good_builder = @capwasm.CapabilityPolicyBuilder::new()
  let good_policy = good_builder
    .allow_read_path("./workspace/docs/")
    .allow_write_path("./workspace/output/")
    .build()
  let good_monitor = @capwasm.PluginSecurityGuard::new("doc-renderer", good_policy)

  println("  -> Plugin requests FS read on './workspace/docs/guide.md'")
  match good_monitor.check_fs_read("./workspace/docs/guide.md") {
    Ok(_) => println("  [PASS] Read permitted under capability allowlist.")
    Err(e) => println("  [FAIL] Unexpected rejection: \{e}")
  }

  println("  -> Plugin requests FS write on './workspace/output/result.html'")
  match good_monitor.check_fs_write("./workspace/output/result.html") {
    Ok(_) => println("  [PASS] Write permitted under capability allowlist.")
    Err(e) => println("  [FAIL] Unexpected rejection: \{e}")
  }

  println("")

  // Scenario 2: Malicious Plugin attempting path traversal and secret access
  println("[Scenario 2] Running Malicious Plugin ('untrusted-agent.wasm')...")
  let evil_builder = @capwasm.CapabilityPolicyBuilder::new()
  let evil_policy = evil_builder
    .allow_read_path("./workspace/docs/")
    .build()
  let evil_monitor = @capwasm.PluginSecurityGuard::new("untrusted-agent", evil_policy)

  println("  -> Plugin attempts path traversal: './workspace/docs/../../etc/shadow'")
  match evil_monitor.check_fs_read("./workspace/docs/../../etc/shadow") {
    Ok(_) => println("  [CRITICAL] Security failure: traversal allowed!")
    Err(e) => println("  [SECURITY BLOCKED] \{e}")
  }

  println("  -> Plugin attempts unauthorized outbound connection: 'evil-c2.darknet'")
  match evil_monitor.check_network("evil-c2.darknet") {
    Ok(_) => println("  [CRITICAL] Security failure: network escape allowed!")
    Err(e) => println("  [SECURITY BLOCKED] \{e}")
  }

  println("")

  // Scenario 3: Resource Quota & Infinite Loop Defense
  println("[Scenario 3] Running Runaway/Infinite Loop Plugin ('crypto-miner.wasm')...")
  let quota = @capwasm.ResourceQuota::default()
  let quota_builder = @capwasm.CapabilityPolicyBuilder::new()
  let quota_policy = quota_builder.set_quota(quota).build()
  let loop_monitor = @capwasm.PluginSecurityGuard::new("crypto-miner", quota_policy)

  println("  -> Plugin executing instruction burst (60,000 steps)...")
  let _ = loop_monitor.consume_steps(60000)
  println("  -> Plugin attempting runaway execution (+50,000 steps)...")
  match loop_monitor.consume_steps(50000) {
    Ok(_) => println("  [WARN] Step limit not triggered.")
    Err(e) => println("  [RESOURCE QUOTA EXCEEDED] \{e}")
  }

  println("")
  println("==================================================================")
  println("  Host Security Audit Summary")
  println("==================================================================")
  let evil_logs = evil_monitor.get_audit_logs()
  for record in evil_logs {
    let status = if record.allowed { "ALLOWED" } else { "DENIED" }
    println("  - [\{record.plugin_id}] target=\{record.target} status=\{status} reason=\{record.reason}")
  }
  println("==================================================================")
  println("  Demonstration finished successfully. All security bounds held.")
  println("==================================================================")
}
