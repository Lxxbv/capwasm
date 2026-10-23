// CapWasm: Host Function Linker and Binding Framework
// Enables native MoonBit host function injection into the sandboxed Wasm environment.

///|
/// HostContext gives host functions access to runtime memory and execution metadata.
pub(all) struct HostContext {
  plugin_id : String
  mut memory : LinearMemory?
  mut sec_guard : PluginSecurityGuard?
}

///|
pub fn HostContext::new(plugin_id : String) -> HostContext {
  { plugin_id, memory: None, sec_guard: None, }
}

///|
pub fn HostContext::set_memory(self : HostContext, mem : LinearMemory) -> Unit {
  self.memory = Some(mem)
}

///|
pub fn HostContext::set_guard(
  self : HostContext,
  sec_guard : PluginSecurityGuard,
) -> Unit {
  self.sec_guard = Some(sec_guard)
}

///|
pub fn HostContext::get_memory(
  self : HostContext,
) -> Result[LinearMemory, Trap] {
  match self.memory {
    Some(m) => Ok(m)
    None => Err(Trap::UnknownMemory(0))
  }
}

///|
pub fn HostContext::get_guard(
  self : HostContext,
) -> Result[PluginSecurityGuard, Trap] {
  match self.sec_guard {
    Some(g) => Ok(g)
    None => Err(Trap::HostError("No security guard attached to host context"))
  }
}

///|
/// HostFunctionSignature defines parameter and return types for host imports.
pub(all) struct HostFunction {
  func_type : FuncType
  callback : (HostContext, Array[Value]) -> Result[Array[Value], Trap]
}

///|
pub fn HostFunction::new(
  func_type : FuncType,
  callback : (HostContext, Array[Value]) -> Result[Array[Value], Trap],
) -> HostFunction {
  { func_type, callback, }
}

///|
/// Linker manages resolution of imported module symbols against registered host functions.
pub(all) struct Linker {
  functions : Array[(String, String, HostFunction)]
  memories : Array[(String, String, LinearMemory)]
}

///|
pub fn Linker::new() -> Linker {
  { functions: [], memories: [], }
}

///|
pub fn Linker::register_func(
  self : Linker,
  mod_name : String,
  field_name : String,
  host_func : HostFunction,
) -> Unit {
  self.functions.push((mod_name, field_name, host_func))
}

///|
pub fn Linker::register_memory(
  self : Linker,
  mod_name : String,
  field_name : String,
  memory : LinearMemory,
) -> Unit {
  self.memories.push((mod_name, field_name, memory))
}

///|
pub fn Linker::resolve_func(
  self : Linker,
  mod_name : String,
  field_name : String,
) -> HostFunction? {
  for item in self.functions {
    let (m, f, hf) = item
    if m == mod_name && f == field_name {
      return Some(hf)
    }
  }
  None
}

///|
pub fn Linker::resolve_memory(
  self : Linker,
  mod_name : String,
  field_name : String,
) -> LinearMemory? {
  for item in self.memories {
    let (m, f, mem) = item
    if m == mod_name && f == field_name {
      return Some(mem)
    }
  }
  None
}
