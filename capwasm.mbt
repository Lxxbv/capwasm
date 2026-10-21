// CapWasm: Capability-Based WebAssembly Plugin Sandbox for MoonBit
// Designed for production-grade plugin isolation, capability management, and runtime security.

/// SecurityError represents a violation of sandboxing rules or execution limits.
pub(all) enum SecurityError {
  PermissionDenied(String)
  PathTraversalAttempt(String)
  OutOfQuota(String)
  MemoryOutOfBounds(Int, Int)
  Aborted(String)
} derive(Debug, Eq)

pub impl Show for SecurityError with output(self, logger) {
  match self {
    PermissionDenied(msg) => logger.write_string("PermissionDenied: " + msg)
    PathTraversalAttempt(path) => logger.write_string("PathTraversalAttempt: " + path)
    OutOfQuota(msg) => logger.write_string("OutOfQuota: " + msg)
    MemoryOutOfBounds(_off, _len) => logger.write_string("MemoryOutOfBounds")
    Aborted(msg) => logger.write_string("Aborted: " + msg)
  }
}

/// ActionType represents the type of action requested by a plugin.
pub(all) enum ActionType {
  FsRead
  FsWrite
  NetConnect
  ClockRead
  EnvRead
} derive(Debug, Eq)

/// ResourceQuota defines physical resource boundaries for a sandboxed plugin.
pub(all) struct ResourceQuota {
  max_memory_pages : Int
  max_execution_steps : Int
} derive(Debug, Eq)

pub fn ResourceQuota::default() -> ResourceQuota {
  { max_memory_pages: 16, max_execution_steps: 100_000 }
}

/// CapabilityPolicy defines the permissions granted to a specific plugin instance.
pub(all) struct CapabilityPolicy {
  allowed_read_paths : Array[String]
  allowed_write_paths : Array[String]
  allowed_network_hosts : Array[String]
  allow_clock : Bool
  allowed_env_vars : Array[String]
  quota : ResourceQuota
} derive(Debug)

pub fn CapabilityPolicy::builder() -> CapabilityPolicyBuilder {
  CapabilityPolicyBuilder::new()
}

pub(all) struct CapabilityPolicyBuilder {
  mut read_paths : Array[String]
  mut write_paths : Array[String]
  mut hosts : Array[String]
  mut allow_clock : Bool
  mut env_vars : Array[String]
  mut quota : ResourceQuota
}

pub fn CapabilityPolicyBuilder::new() -> CapabilityPolicyBuilder {
  {
    read_paths: [],
    write_paths: [],
    hosts: [],
    allow_clock: false,
    env_vars: [],
    quota: ResourceQuota::default(),
  }
}

pub fn CapabilityPolicyBuilder::allow_read_path(
  self : CapabilityPolicyBuilder,
  path : String
) -> CapabilityPolicyBuilder {
  self.read_paths.push(path)
  self
}

pub fn CapabilityPolicyBuilder::allow_write_path(
  self : CapabilityPolicyBuilder,
  path : String
) -> CapabilityPolicyBuilder {
  self.write_paths.push(path)
  self
}

pub fn CapabilityPolicyBuilder::allow_network_host(
  self : CapabilityPolicyBuilder,
  host : String
) -> CapabilityPolicyBuilder {
  self.hosts.push(host)
  self
}

pub fn CapabilityPolicyBuilder::allow_clock(
  self : CapabilityPolicyBuilder,
  allowed : Bool
) -> CapabilityPolicyBuilder {
  self.allow_clock = allowed
  self
}

pub fn CapabilityPolicyBuilder::set_quota(
  self : CapabilityPolicyBuilder,
  quota : ResourceQuota
) -> CapabilityPolicyBuilder {
  self.quota = quota
  self
}

pub fn CapabilityPolicyBuilder::build(
  self : CapabilityPolicyBuilder
) -> CapabilityPolicy {
  {
    allowed_read_paths: self.read_paths,
    allowed_write_paths: self.write_paths,
    allowed_network_hosts: self.hosts,
    allow_clock: self.allow_clock,
    allowed_env_vars: self.env_vars,
    quota: self.quota,
  }
}
