test "wbtest" {
  let builder = CapabilityPolicyBuilder::new()
  let policy = builder.allow_read_path("./docs/").build()
  let sec_guard = PluginSecurityGuard::new("good-plugin", policy)
  let result = sec_guard.check_fs_read("./docs/readme.txt")
  assert_eq(result, Ok(()))
}
