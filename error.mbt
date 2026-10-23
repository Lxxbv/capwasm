// CapWasm: Runtime Traps and Internal Errors
// Defines error categories for parsing, validation, execution, and security violations.

///|
/// Trap represents an unrecoverable Wasm runtime execution trap.
pub(all) enum Trap {
  Unreachable
  MemoryOutOfBounds(Int, Int)
  DivisionByZero
  IntegerOverflow
  InvalidConversion
  StackOverflow
  StackUnderflow
  UndefinedElement(Int)
  UninitializedElement(Int)
  IndirectCallTypeMismatch
  TypeMismatch(String)
  UnknownFunction(Int)
  UnknownGlobal(Int)
  UnknownMemory(Int)
  UnknownTable(Int)
  HostError(String)
  GasExhausted(Int, Int)
  Abort(String)
} derive(Debug, Eq)

///|
pub impl Show for Trap with fn output(self, logger) {
  match self {
    Unreachable => logger.write_string("Trap::Unreachable")
    MemoryOutOfBounds(offset, size) =>
      logger.write_string(
        "Trap::MemoryOutOfBounds(offset=\{offset}, size=\{size})",
      )
    DivisionByZero => logger.write_string("Trap::DivisionByZero")
    IntegerOverflow => logger.write_string("Trap::IntegerOverflow")
    InvalidConversion => logger.write_string("Trap::InvalidConversion")
    StackOverflow => logger.write_string("Trap::StackOverflow")
    StackUnderflow => logger.write_string("Trap::StackUnderflow")
    UndefinedElement(idx) =>
      logger.write_string("Trap::UndefinedElement(\{idx})")
    UninitializedElement(idx) =>
      logger.write_string("Trap::UninitializedElement(\{idx})")
    IndirectCallTypeMismatch =>
      logger.write_string("Trap::IndirectCallTypeMismatch")
    TypeMismatch(msg) => logger.write_string("Trap::TypeMismatch(" + msg + ")")
    UnknownFunction(idx) => logger.write_string("Trap::UnknownFunction(\{idx})")
    UnknownGlobal(idx) => logger.write_string("Trap::UnknownGlobal(\{idx})")
    UnknownMemory(idx) => logger.write_string("Trap::UnknownMemory(\{idx})")
    UnknownTable(idx) => logger.write_string("Trap::UnknownTable(\{idx})")
    HostError(msg) => logger.write_string("Trap::HostError(" + msg + ")")
    GasExhausted(consumed, limit) =>
      logger.write_string(
        "Trap::GasExhausted(consumed=\{consumed}, limit=\{limit})",
      )
    Abort(msg) => logger.write_string("Trap::Abort(" + msg + ")")
  }
}

///|
/// DecodeError represents errors encountered while parsing binary .wasm byte streams.
pub(all) enum DecodeError {
  UnexpectedEof(String)
  InvalidMagic
  InvalidVersion(Int)
  InvalidSectionId(Int)
  InvalidValueType(Int)
  InvalidMutability(Int)
  InvalidLimits(Int)
  InvalidOpcode(Int)
  Leb128Overflow
  SectionSizeMismatch(Int, Int)
  InvalidUtf8
  MalformedModule(String)
} derive(Debug, Eq)

///|
pub impl Show for DecodeError with fn output(self, logger) {
  match self {
    UnexpectedEof(ctx) =>
      logger.write_string("DecodeError::UnexpectedEof(" + ctx + ")")
    InvalidMagic => logger.write_string("DecodeError::InvalidMagic")
    InvalidVersion(v) =>
      logger.write_string("DecodeError::InvalidVersion(\{v})")
    InvalidSectionId(id) =>
      logger.write_string("DecodeError::InvalidSectionId(\{id})")
    InvalidValueType(b) =>
      logger.write_string("DecodeError::InvalidValueType(\{b})")
    InvalidMutability(b) =>
      logger.write_string("DecodeError::InvalidMutability(\{b})")
    InvalidLimits(b) => logger.write_string("DecodeError::InvalidLimits(\{b})")
    InvalidOpcode(op) =>
      logger.write_string("DecodeError::InvalidOpcode(\{op})")
    Leb128Overflow => logger.write_string("DecodeError::Leb128Overflow")
    SectionSizeMismatch(expected, actual) =>
      logger.write_string(
        "DecodeError::SectionSizeMismatch(expected=\{expected}, actual=\{actual})",
      )
    InvalidUtf8 => logger.write_string("DecodeError::InvalidUtf8")
    MalformedModule(msg) =>
      logger.write_string("DecodeError::MalformedModule(" + msg + ")")
  }
}

///|
/// LinkError represents errors during symbol resolution and module instantiation.
pub(all) enum LinkError {
  MissingImport(String, String)
  ImportTypeMismatch(String, String, String)
  DuplicateExport(String)
  StartFunctionNotFound(Int)
  IncompatibleMemoryLimits
  IncompatibleTableLimits
} derive(Debug, Eq)

///|
pub impl Show for LinkError with fn output(self, logger) {
  match self {
    MissingImport(mod_name, field) =>
      logger.write_string("LinkError::MissingImport(\{mod_name}.\{field})")
    ImportTypeMismatch(mod_name, field, detail) =>
      logger.write_string(
        "LinkError::ImportTypeMismatch(\{mod_name}.\{field}: " + detail + ")",
      )
    DuplicateExport(name) =>
      logger.write_string("LinkError::DuplicateExport(\{name})")
    StartFunctionNotFound(idx) =>
      logger.write_string("LinkError::StartFunctionNotFound(\{idx})")
    IncompatibleMemoryLimits =>
      logger.write_string("LinkError::IncompatibleMemoryLimits")
    IncompatibleTableLimits =>
      logger.write_string("LinkError::IncompatibleTableLimits")
  }
}
