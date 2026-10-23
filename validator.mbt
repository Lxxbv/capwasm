// CapWasm: WebAssembly Static Module Validation
// Performs pre-execution consistency checks, type verification, and structural validation.

///|
pub(all) struct ModuleValidator {
  module_def : WasmModule
}

///|
pub fn ModuleValidator::new(module_def : WasmModule) -> ModuleValidator {
  { module_def, }
}

///|
pub fn ModuleValidator::validate(
  self : ModuleValidator,
) -> Result[Unit, DecodeError] {
  // 1. Verify types
  for i = 0; i < self.module_def.types.length(); i = i + 1 {
    let ft = self.module_def.types[i]
    if ft.results.length() > 1 {
      return Err(
        DecodeError::MalformedModule(
          "Multi-value return not supported in Wasm 1.0 at type index \{i}",
        ),
      )
    }
  }

  // 2. Verify functions and code length consistency
  if self.module_def.func_types.length() != self.module_def.code.length() {
    return Err(
      DecodeError::MalformedModule(
        "Function section count (\{self.module_def.func_types.length()}) does not match code section count (\{self.module_def.code.length()})",
      ),
    )
  }

  // 3. Verify function type indices
  let type_count = self.module_def.types.length()
  for i = 0; i < self.module_def.func_types.length(); i = i + 1 {
    let t_idx = self.module_def.func_types[i]
    if t_idx < 0 || t_idx >= type_count {
      return Err(
        DecodeError::MalformedModule(
          "Function \{i} references out-of-range type index \{t_idx}",
        ),
      )
    }
  }

  // 4. Verify memories
  let total_mems = self.module_def.memories.length()
  let mut imported_mems = 0
  for imp in self.module_def.imports {
    match imp.desc {
      ImportDesc::Mem(_) => imported_mems = imported_mems + 1
      _ => ()
    }
  }
  if total_mems + imported_mems > 1 {
    return Err(
      DecodeError::MalformedModule(
        "Multiple memories not permitted in Wasm 1.0",
      ),
    )
  }

  // 5. Verify memory limits
  for i = 0; i < self.module_def.memories.length(); i = i + 1 {
    let mem = self.module_def.memories[i]
    if mem.limits.min < 0 || mem.limits.min > 65536 {
      return Err(DecodeError::InvalidLimits(mem.limits.min))
    }
    match mem.limits.max {
      Some(max_p) =>
        if max_p < mem.limits.min || max_p > 65536 {
          return Err(DecodeError::InvalidLimits(max_p))
        }
      None => ()
    }
  }

  // 6. Verify table limits
  for i = 0; i < self.module_def.tables.length(); i = i + 1 {
    let tbl = self.module_def.tables[i]
    match tbl.limits.max {
      Some(max_entries) =>
        if max_entries < tbl.limits.min {
          return Err(DecodeError::InvalidLimits(max_entries))
        }
      None => ()
    }
  }

  // 7. Verify exports reference valid items
  let total_funcs = self.module_def.get_imported_func_count() +
    self.module_def.func_types.length()
  for exp in self.module_def.exports {
    match exp.desc {
      ExportDesc::Func(idx) =>
        if idx < 0 || idx >= total_funcs {
          return Err(
            DecodeError::MalformedModule(
              "Export '\{exp.name}' references invalid function index \{idx}",
            ),
          )
        }
      ExportDesc::Mem(idx) =>
        if idx < 0 || idx >= total_mems + imported_mems {
          return Err(
            DecodeError::MalformedModule(
              "Export '\{exp.name}' references invalid memory index \{idx}",
            ),
          )
        }
      _ => ()
    }
  }

  Ok(())
}
