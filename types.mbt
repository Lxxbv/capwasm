// CapWasm: WebAssembly Core Types and Domain Definitions
// Implements Wasm 1.0 core type specification for the sandboxed runtime.

///|
/// ValueType represents the fundamental Wasm primitive types.
pub(all) enum ValueType {
  I32
  I64
  F32
  F64
} derive(Eq)

///|
pub impl Show for ValueType with fn output(self, logger) {
  match self {
    I32 => logger.write_string("i32")
    I64 => logger.write_string("i64")
    F32 => logger.write_string("f32")
    F64 => logger.write_string("f64")
  }
}

///|
/// Limits represents the min/max page limits for memories and tables.
pub(all) struct Limits {
  min : Int
  max : Int?
} derive(Eq)

///|
pub impl Show for Limits with fn output(self, logger) {
  match self.max {
    Some(m) => logger.write_string("Limits(min=\{self.min}, max=\{m})")
    None => logger.write_string("Limits(min=\{self.min})")
  }
}

///|
pub fn Limits::new(min : Int, max : Int?) -> Limits {
  { min, max, }
}

///|
/// FuncType represents a function signature (parameters -> results).
pub(all) struct FuncType {
  params : Array[ValueType]
  results : Array[ValueType]
} derive(Eq)

///|
pub impl Show for FuncType with fn output(self, logger) {
  logger.write_string("FuncType(params=[")
  for i = 0; i < self.params.length(); i = i + 1 {
    if i > 0 {
      logger.write_string(", ")
    }
    logger.write_string(self.params[i].to_string())
  }
  logger.write_string("] -> [")
  for i = 0; i < self.results.length(); i = i + 1 {
    if i > 0 {
      logger.write_string(", ")
    }
    logger.write_string(self.results[i].to_string())
  }
  logger.write_string("])")
}

///|
pub fn FuncType::new(
  params : Array[ValueType],
  results : Array[ValueType],
) -> FuncType {
  { params, results, }
}

///|
/// Value represents runtime instance values.
pub(all) enum Value {
  I32(Int)
  I64(Int64)
  F32(Float)
  F64(Double)
} derive(Debug, Eq)

///|
pub impl Show for Value with fn output(self, logger) {
  match self {
    I32(v) => logger.write_string("i32(" + v.to_string() + ")")
    I64(v) => logger.write_string("i64(" + v.to_string() + ")")
    F32(v) => logger.write_string("f32(" + v.to_string() + ")")
    F64(v) => logger.write_string("f64(" + v.to_string() + ")")
  }
}

///|
pub fn Value::as_i32(self : Value) -> Result[Int, Trap] {
  match self {
    I32(v) => Ok(v)
    _ => Err(Trap::TypeMismatch("Expected i32 value"))
  }
}

///|
pub fn Value::as_i64(self : Value) -> Result[Int64, Trap] {
  match self {
    I64(v) => Ok(v)
    _ => Err(Trap::TypeMismatch("Expected i64 value"))
  }
}

///|
pub fn Value::get_type(self : Value) -> ValueType {
  match self {
    I32(_) => ValueType::I32
    I64(_) => ValueType::I64
    F32(_) => ValueType::F32
    F64(_) => ValueType::F64
  }
}

///|
/// Mutability denotes whether a global variable is mutable.
pub(all) enum Mutability {
  Const
  Var
} derive(Eq)

///|
pub impl Show for Mutability with fn output(self, logger) {
  match self {
    Const => logger.write_string("const")
    Var => logger.write_string("var")
  }
}

///|
/// GlobalType describes a global variable's type and mutability.
pub(all) struct GlobalType {
  val_type : ValueType
  mutability : Mutability
} derive(Eq)

///|
pub impl Show for GlobalType with fn output(self, logger) {
  logger.write_string("GlobalType(\{self.val_type}, \{self.mutability})")
}

///|
pub fn GlobalType::new(
  val_type : ValueType,
  mutability : Mutability,
) -> GlobalType {
  { val_type, mutability, }
}

///|
/// TableType describes table parameters.
pub(all) struct TableType {
  limits : Limits
} derive(Eq)

///|
pub impl Show for TableType with fn output(self, logger) {
  logger.write_string("TableType(\{self.limits})")
}

///|
pub fn TableType::new(limits : Limits) -> TableType {
  { limits, }
}

///|
/// MemoryType describes linear memory limits.
pub(all) struct MemoryType {
  limits : Limits
} derive(Eq)

///|
pub impl Show for MemoryType with fn output(self, logger) {
  logger.write_string("MemoryType(\{self.limits})")
}

///|
pub fn MemoryType::new(limits : Limits) -> MemoryType {
  { limits, }
}

///|
/// ImportDesc describes external imports into a module.
pub(all) enum ImportDesc {
  Func(Int)
  Table(TableType)
  Mem(MemoryType)
  Global(GlobalType)
} derive(Eq)

///|
pub impl Show for ImportDesc with fn output(self, logger) {
  match self {
    Func(idx) => logger.write_string("ImportDesc::Func(\{idx})")
    Table(t) => logger.write_string("ImportDesc::Table(\{t})")
    Mem(m) => logger.write_string("ImportDesc::Mem(\{m})")
    Global(g) => logger.write_string("ImportDesc::Global(\{g})")
  }
}

///|
/// ImportEntry represents one import declaration.
pub(all) struct ImportEntry {
  mod_name : String
  field_name : String
  desc : ImportDesc
} derive(Eq)

///|
pub impl Show for ImportEntry with fn output(self, logger) {
  logger.write_string(
    "ImportEntry(\{self.mod_name}.\{self.field_name}: \{self.desc})",
  )
}

///|
pub fn ImportEntry::new(
  mod_name : String,
  field_name : String,
  desc : ImportDesc,
) -> ImportEntry {
  { mod_name, field_name, desc, }
}

///|
/// ExportDesc describes an exported symbol type.
pub(all) enum ExportDesc {
  Func(Int)
  Table(Int)
  Mem(Int)
  Global(Int)
} derive(Eq)

///|
pub impl Show for ExportDesc with fn output(self, logger) {
  match self {
    Func(idx) => logger.write_string("ExportDesc::Func(\{idx})")
    Table(idx) => logger.write_string("ExportDesc::Table(\{idx})")
    Mem(idx) => logger.write_string("ExportDesc::Mem(\{idx})")
    Global(idx) => logger.write_string("ExportDesc::Global(\{idx})")
  }
}

///|
/// ExportEntry represents an exported entity.
pub(all) struct ExportEntry {
  name : String
  desc : ExportDesc
} derive(Eq)

///|
pub impl Show for ExportEntry with fn output(self, logger) {
  logger.write_string("ExportEntry(\{self.name}: \{self.desc})")
}

///|
pub fn ExportEntry::new(name : String, desc : ExportDesc) -> ExportEntry {
  { name, desc, }
}

///|
/// LocalDecl represents local variables inside a function body.
pub(all) struct LocalDecl {
  count : Int
  val_type : ValueType
} derive(Eq)

///|
pub impl Show for LocalDecl with fn output(self, logger) {
  logger.write_string("LocalDecl(count=\{self.count}, type=\{self.val_type})")
}

///|
pub fn LocalDecl::new(count : Int, val_type : ValueType) -> LocalDecl {
  { count, val_type, }
}
