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
