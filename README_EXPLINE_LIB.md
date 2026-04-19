# CppMinHook Step By Step Explanation

This file explains all main steps in your library from project setup to runtime hook flow.

## 1. What the library is

CppMinHook is a class-based C++20 Windows inline-hooking library.
It patches function entry bytes so execution jumps to a detour function.
It also builds a trampoline so detour code can still call the original behavior.

## 2. Core building blocks

1. Status
- Purpose: return explicit success or failure values for every operation.
- Typical values: ok, not_initialized, already_created, unsupported_target, module_not_found.

2. PageProtectionGuard
- Purpose: temporarily change page protection with VirtualProtect while writing code bytes.
- Benefit: RAII cleanup restores previous protection automatically.

3. TrampolineBuffer
- Purpose: allocate executable memory using VirtualAlloc for trampoline code.
- Lifecycle: allocate when creating a hook, free when hook is removed.

4. Hook
- Purpose: represent one target and one detour.
- Responsibilities:
	- Validate addresses.
	- Compute safe patch size on instruction boundaries.
	- Copy original bytes.
	- Build trampoline bytes.
	- Enable patch, disable patch, remove hook.
	- Support queued enable or disable operations.

5. HookEngine
- Purpose: manage many Hook objects.
- Responsibilities:
	- initialize and uninitialize engine lifecycle.
	- create_hook and remove_hook.
	- enable_all and disable_all.
	- queue_enable, queue_disable, queue_enable_all, queue_disable_all, apply_queued.
	- resolve_api_target and create_hook_api for loaded module exports.

## 3. Build and run steps

1. Configure project
- Command: cmake -S . -B build

2. Build project
- Command: cmake --build build --config Debug

3. Run demo
- Command: .\build\Debug\cppminhook_demo.exe

4. Run tests
- Command: ctest --test-dir build -C Debug --output-on-failure

## 4. Runtime hook flow

1. Engine initialization
- Call HookEngine.initialize.
- Engine switches to initialized state.

2. Hook creation
- Call create_hook with target address and detour address.
- Hook validates addresses are executable.
- Hook decodes instructions to find a safe patch window.
- Hook copies original target bytes into storage.
- Hook allocates trampoline buffer and writes trampoline jump-back.

3. Hook enable
- Hook temporarily unlocks target memory protection.
- Hook writes jump stub at target entry.
- Instruction cache is flushed.
- Calls to target now redirect to detour.

4. Calling original function from detour
- Use Hook.original to get trampoline function pointer.
- Detour can call trampoline to execute preserved original bytes and continue into remaining target code.

5. Hook disable
- Hook rewrites original bytes back to target entry.
- Instruction cache is flushed.

6. Hook remove or engine uninitialize
- Hook buffer is freed.
- Hook state is cleared.
- Engine can clear all hooks on uninitialize.

## 5. Queued batch operations

Queue operations let you stage changes and apply them in one pass.

1. Queue operations
- queue_enable(target) or queue_disable(target)
- queue_enable_all or queue_disable_all

2. Apply
- apply_queued executes staged changes across hooks.

3. Why this helps
- You can coordinate multiple hook state transitions together.

## 6. API resolution flow

1. resolve_api_target(moduleName, procName, outTarget)
- Uses GetModuleHandleW and GetProcAddress.
- Returns module_not_found or function_not_found when needed.

2. create_hook_api(moduleName, procName, detour)
- Resolves target address first.
- Then creates hook using normal creation path.

## 7. Demo behavior summary

The demo does this sequence:

1. Creates a tiny executable in-memory function.
2. Calls it before hooking and prints original result.
3. Creates and enables hook.
4. Detour calls trampoline original path and modifies the return value.
5. Disables hook and confirms original behavior is restored.

## 8. Test coverage summary

Current tests validate:

1. Engine lifecycle behavior.
2. Queue plus apply flow.
3. Trampoline original-call scenario in a controlled sample.
4. API resolution success and failure paths.

## 9. Current limitations

1. Windows only.
2. x64 jump patching uses a fixed absolute stub format.
3. Full relocation for all branch-heavy real-world prologues is not implemented yet.

## 10. Recommended next steps

1. Extend instruction relocation support for more complex prologues.
2. Add stress tests for many simultaneous hooks.
3. Add thread-safety strategy for concurrent hook updates.
4. Add logging hooks for diagnostics in debug builds.
