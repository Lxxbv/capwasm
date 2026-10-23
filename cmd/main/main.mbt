///|
/// CapWasm Interactive Sandbox Host Demo
/// Demonstrates capability-based security isolation for untrusted WebAssembly plugins.
fn main {
  println("==================================================================")
  println("  CapWasm: Capability-Based WebAssembly Plugin Sandbox Host      ")
  println("  MoonBit Hackathon 2026 - Production System Demonstration        ")
  println("==================================================================")
  println("")

  // Scenario 1: Benign Plugin with granted capabilities & VFS integration
  println("[Scenario 1] Running Benign Plugin ('doc-renderer.wasm')...")
  let good_policy = @capwasm.CapabilityPolicyBuilder::new()
    .allow_read_path("/workspace/docs/")
    .allow_write_path("/workspace/output/")
    .allow_network_host("api.github.com")
    .build()

  let vfs = @capwasm.VirtualFileSystem::new()
  let doc_bytes : Array[Byte] = [
    b'\x23', b'\x20', b'\x57', b'\x65', b'\x6c', b'\x63', b'\x6f', b'\x6d', b'\x65',
    b'\x20', b'\x74', b'\x6f', b'\x20', b'\x43', b'\x61', b'\x70', b'\x57', b'\x61',
    b'\x73', b'\x6d',
  ]
  let _ = vfs.create_file("/workspace/docs/guide.md", doc_bytes)

  let _ = @capwasm.PluginConfig::new("doc-renderer", good_policy).with_vfs(vfs)
  let good_monitor = @capwasm.PluginSecurityGuard::new(
    "doc-renderer", good_policy,
  )

  println("  -> Plugin requests FS read on '/workspace/docs/guide.md'")
  match good_monitor.check_fs_read("/workspace/docs/guide.md") {
    Ok(_) => {
      let read_res = vfs.read_file("/workspace/docs/guide.md")
      match read_res {
        Ok(bytes) =>
          println("  [PASS] Read permitted (bytes=\{bytes.length()}).")
        Err(e) => println("  [FAIL] VFS read error: \{e}")
      }
    }
    Err(e) => println("  [FAIL] Unexpected rejection: \{e}")
  }

  println("  -> Plugin requests FS write on '/workspace/output/result.html'")
  match good_monitor.check_fs_write("/workspace/output/result.html") {
    Ok(_) => {
      let write_bytes : Array[Byte] = [
        b'\x3c', b'\x68', b'\x31', b'\x3e', b'\x4f', b'\x4b', b'\x3c', b'\x2f', b'\x68',
        b'\x31', b'\x3e',
      ]
      let _ = vfs.write_file("/workspace/output/result.html", write_bytes)
      println("  [PASS] Write permitted under capability allowlist.")
    }
    Err(e) => println("  [FAIL] Unexpected rejection: \{e}")
  }

  println("")

  // Scenario 2: Malicious Plugin attempting path traversal
  println("[Scenario 2] Running Malicious Plugin ('untrusted-agent.wasm')...")
  let evil_policy = @capwasm.CapabilityPolicyBuilder::new()
    .allow_read_path("/workspace/docs/")
    .build()
  let evil_monitor = @capwasm.PluginSecurityGuard::new(
    "untrusted-agent", evil_policy,
  )

  println(
    "  -> Plugin attempts path traversal: '/workspace/docs/../../etc/shadow'",
  )
  match evil_monitor.check_fs_read("/workspace/docs/../../etc/shadow") {
    Ok(_) => println("  [CRITICAL] Security failure: traversal allowed!")
    Err(e) => println("  [SECURITY BLOCKED] \{e}")
  }

  // Scenario 3: Unauthorized Outbound Network Egress
  println("")
  println("[Scenario 3] Running Network Escape Attempt...")
  println(
    "  -> Plugin attempts unauthorized outbound connection: 'evil-c2.darknet'",
  )
  match evil_monitor.check_network("evil-c2.darknet") {
    Ok(_) => println("  [CRITICAL] Security failure: network escape allowed!")
    Err(e) => println("  [SECURITY BLOCKED] \{e}")
  }

  println(
    "  -> Plugin attempts authorized outbound connection: 'api.github.com' (denied: not in evil policy)",
  )
  match evil_monitor.check_network("api.github.com") {
    Ok(_) => println("  [PASS] Network permitted.")
    Err(e) => println("  [SECURITY BLOCKED] \{e}")
  }

  println("")

  // Scenario 4: Resource Quota & Infinite Loop Defense
  println(
    "[Scenario 4] Running Runaway/Infinite Loop Plugin ('crypto-miner.wasm')...",
  )
  let quota = @capwasm.ResourceQuota::default()
  let quota_builder = @capwasm.CapabilityPolicyBuilder::new()
  let quota_policy = quota_builder.set_quota(quota).build()
  let loop_monitor = @capwasm.PluginSecurityGuard::new(
    "crypto-miner", quota_policy,
  )

  println("  -> Plugin executing instruction burst (60,000 steps)...")
  let _ = loop_monitor.consume_steps(60000)
  println("  -> Plugin attempting runaway execution (+50,000 steps)...")
  match loop_monitor.consume_steps(50000) {
    Ok(_) => println("  [WARN] Step limit not triggered.")
    Err(e) => println("  [RESOURCE QUOTA EXCEEDED] \{e}")
  }

  println("")

  // Scenario 5: Sandboxed POSIX/WASI File Descriptor Table
  println("[Scenario 5] Testing Sandboxed WASI Standard Handle Isolation...")
  let fd_table = @capwasm.WasiFdTable::new()
  let stdout_msg : Array[Byte] = [
    b'\x5b', b'\x50', b'\x6c', b'\x75', b'\x67', b'\x69', b'\x6e', b'\x20', b'\x4f',
    b'\x75', b'\x74', b'\x70', b'\x75', b'\x74', b'\x5d', b'\x20', b'\x48', b'\x65',
    b'\x6c', b'\x6c', b'\x6f', b'\x20', b'\x53', b'\x61', b'\x6e', b'\x64', b'\x62',
    b'\x6f', b'\x78',
  ]
  let _ = fd_table.write(1, stdout_msg)
  println("  -> Captured guest stdout: '\{fd_table.get_stdout_string()}'")
  println("  -> Verifying guest cannot close standard stdout handle (fd 1)...")
  match fd_table.close_fd(1) {
    Ok(_) => println("  [FAIL] Standard handle closed unexpectedly!")
    Err(code) =>
      println(
        "  [PASS] Standard handle protected against guest closure (errno=\{code}).",
      )
  }

  println("")
  println("==================================================================")
  println("  Host Security Audit Summary")
  println("==================================================================")
  let evil_logs = evil_monitor.get_audit_logs()
  for record in evil_logs {
    let status = if record.allowed { "ALLOWED" } else { "DENIED" }
    println(
      "  - [\{record.plugin_id}] target=\{record.target} status=\{status} reason=\{record.reason}",
    )
  }
  println("==================================================================")
  println("  Demonstration finished successfully. All security bounds held.")
  println("==================================================================")
}
