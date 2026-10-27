// CapWasm: WebAssembly Module Structure and Component Representations
// Encapsulates the static representation of a validated or parsed Wasm module.

///|
/// FunctionBody represents bytecode instructions and local declarations for a defined function.
pub(all) struct FunctionBody {
  locals : Array[LocalDecl]
  instructions : Array[Instruction]
} derive(Eq)

///|
pub impl Show for FunctionBody with fn output(self, logger) {
  logger.write_string(
    "FunctionBody(locals=\{self.locals.length()}, instrs=\{self.instructions.length()})",
  )
}

///|
pub fn FunctionBody::new(
  locals : Array[LocalDecl],
  instructions : Array[Instruction],
) -> FunctionBody {
  { locals, instructions, }
}

///|
/// GlobalEntry represents a global variable declaration with its initializer expression.
pub(all) struct GlobalEntry {
  global_type : GlobalType
  init_expr : Array[Instruction]
} derive(Eq)

///|
pub impl Show for GlobalEntry with fn output(self, logger) {
  logger.write_string(
    "GlobalEntry(\{self.global_type}, init=\{self.init_expr.length()} instrs)",
  )
}

///|
pub fn GlobalEntry::new(
  global_type : GlobalType,
  init_expr : Array[Instruction],
) -> GlobalEntry {
  { global_type, init_expr, }
}

///|
/// ElementSegment represents table initialization element segment.
pub(all) struct ElementSegment {
  table_index : Int32
  offset_expr : Array[Instruction]
  func_indices : Array[Int32]
} derive(Eq)

///|
pub impl Show for ElementSegment with fn output(self, logger) {
  logger.write_string(
    "ElementSegment(table=\{self.table_index}, funcs=\{self.func_indices.length()})",
  )
}

///|
pub fn ElementSegment::new(
  table_index : Int32,
  offset_expr : Array[Instruction],
  func_indices : Array[Int32],
) -> ElementSegment {
  { table_index, offset_expr, func_indices, }
}

///|
/// DataSegment represents memory initialization segment.
pub(all) struct DataSegment {
  mem_index : Int32
  offset_expr : Array[Instruction]
  data : Array[Byte]
} derive(Eq)

///|
pub impl Show for DataSegment with fn output(self, logger) {
  logger.write_string(
    "DataSegment(mem=\{self.mem_index}, bytes=\{self.data.length()})",
  )
}

///|
pub fn DataSegment::new(
  mem_index : Int32,
  offset_expr : Array[Instruction],
  data : Array[Byte],
) -> DataSegment {
  { mem_index, offset_expr, data, }
}

///|
/// WasmModule encapsulates all static sections of a decoded WebAssembly module.
pub(all) struct WasmModule {
  types : Array[FuncType]
  imports : Array[ImportEntry]
  func_types : Array[Int32]
  tables : Array[TableType]
  memories : Array[MemoryType]
  globals : Array[GlobalEntry]
  exports : Array[ExportEntry]
  start_func : Int32?
  elements : Array[ElementSegment]
  code : Array[FunctionBody]
  data : Array[DataSegment]
} derive(Eq)

///|
pub impl Show for WasmModule with fn output(self, logger) {
  logger.write_string("WasmModule(\n")
  logger.write_string("  types: \{self.types.length()}\n")
  logger.write_string("  imports: \{self.imports.length()}\n")
  logger.write_string("  functions: \{self.func_types.length()}\n")
  logger.write_string("  tables: \{self.tables.length()}\n")
  logger.write_string("  memories: \{self.memories.length()}\n")
  logger.write_string("  globals: \{self.globals.length()}\n")
  logger.write_string("  exports: \{self.exports.length()}\n")
  logger.write_string("  elements: \{self.elements.length()}\n")
  logger.write_string("  data: \{self.data.length()}\n")
  logger.write_string(")")
}

///|
pub fn WasmModule::empty() -> WasmModule {
  {
    types: [],
    imports: [],
    func_types: [],
    tables: [],
    memories: [],
    globals: [],
    exports: [],
    start_func: None,
    elements: [],
    code: [],
    data: [],
  }
}

///|
pub fn WasmModule::get_export(self : WasmModule, name : String) -> ExportDesc? {
  for exp in self.exports {
    if exp.name == name {
      return Some(exp.desc)
    }
  }
  None
}

///|
pub fn WasmModule::find_func_export(self : WasmModule, name : String) -> Int32? {
  match self.get_export(name) {
    Some(ExportDesc::Func(idx)) => Some(idx)
    _ => None
  }
}

///|
pub fn WasmModule::get_imported_func_count(self : WasmModule) -> Int32 {
  let mut count = 0
  for imp in self.imports {
    match imp.desc {
      ImportDesc::Func(_) => count = count + 1
      _ => ()
    }
  }
  count
}

///|
pub fn WasmModule::get_func_type(
  self : WasmModule,
  func_index : Int32,
) -> Result[FuncType, Trap] {
  let mut imported_func_idx = 0
  for imp in self.imports {
    match imp.desc {
      ImportDesc::Func(type_idx) => {
        if imported_func_idx == func_index {
          if type_idx < 0 || type_idx >= self.types.length() {
            return Err(Trap::UnknownFunction(func_index))
          }
          return Ok(self.types[type_idx])
        }
        imported_func_idx = imported_func_idx + 1
      }
      _ => ()
    }
  }

  let defined_func_idx = func_index - imported_func_idx
  if defined_func_idx < 0 || defined_func_idx >= self.func_types.length() {
    return Err(Trap::UnknownFunction(func_index))
  }

  let type_idx = self.func_types[defined_func_idx]
  if type_idx < 0 || type_idx >= self.types.length() {
    return Err(Trap::UnknownFunction(func_index))
  }

  Ok(self.types[type_idx])
}
