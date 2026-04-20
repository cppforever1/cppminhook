## This library is inspired by original MinHook (https://github.com/TsudaKageyu/minhook)

 ██████   ██████  ███             █████   █████                   █████     
░░██████ ██████  ░░░             ░░███   ░░███                   ░░███      
 ░███░█████░███  ████  ████████   ░███    ░███   ██████   ██████  ░███ █████
 ░███░░███ ░███ ░░███ ░░███░░███  ░███████████  ███░░███ ███░░███ ░███░░███ 
 ░███ ░░░  ░███  ░███  ░███ ░███  ░███░░░░░███ ░███ ░███░███ ░███ ░██████░  
 ░███      ░███  ░███  ░███ ░███  ░███    ░███ ░███ ░███░███ ░███ ░███░░███ 
 █████     █████ █████ ████ █████ █████   █████░░██████ ░░██████  ████ █████
░░░░░     ░░░░░ ░░░░░ ░░░░ ░░░░░ ░░░░░   ░░░░░  ░░░░░░   ░░░░░░  ░░░░ ░░░░░                                                          

## CppMinHook

CppMinHook is an original C++20 Windows hooking project built around classes instead of a C API. It is inspired by the same problem space as MinHook, but this repository contains a clean-room implementation with a different architecture and a much smaller feature surface.

## Project goals

- Use modern C++20 classes and RAII instead of global C state.
- Keep the project small and easy to inspect.
- Demonstrate inline detours, trampoline allocation, and lifecycle management.
- Provide a buildable example executable.

## Project layout

- `include/cppminhook/status.h`: status codes and string conversion.
- `include/cppminhook/memory_protection.h`: page protection guard around `VirtualProtect`.
- `include/cppminhook/trampoline_buffer.h`: executable trampoline allocation.
- `include/cppminhook/diagnostics.h`: last-error context, default per-run file logger, and optional callback override.
- `include/cppminhook/hook.h`: single hook object that owns patching state.
- `include/cppminhook/hook_engine.h`: manager for multiple hooks.
- `tests/test_main.cpp`: fixture, stress, rollback, transaction, and fuzz-like tests run through CTest.
- `benchmarks/benchmark_main.cpp`: micro-benchmark for baseline vs hooked call overhead.
- `.github/workflows/ci.yml`: GitHub Actions matrix for Debug and Release builds.
- `src/`: implementation files.
- `examples/demo.cpp`: executable example that hooks a generated in-memory function.

## Quick start

```powershell
cmake -S . -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
.\build\Debug\cppminhook_demo.exe
.\build\Debug\cppminhook_bench.exe
```

## Rebuild all targets

```powershell
cmake -S . -B build
cmake --build build --config Debug --target ALL_BUILD --clean-first
cmake --build build --config Release --target ALL_BUILD --clean-first
```

## Test both configurations

```powershell
ctest --test-dir build -C Debug --output-on-failure
ctest --test-dir build -C Release --output-on-failure
```
Optional profiles:

```powershell
# Enable sanitizer profile (Clang/GCC)
cmake -S . -B build-asan -DCPPMINHOOK_ENABLE_SANITIZERS=ON

# Enable Capstone decoder backend when library is installed
cmake -S . -B build-capstone -DCPPMINHOOK_ENABLE_CAPSTONE=ON

# Enable Zydis decoder backend when library is installed
cmake -S . -B build-zydis -DCPPMINHOOK_ENABLE_ZYDIS=ON
```

The demo executable target is `cppminhook_demo`.

## Targets

- `cppminhook`: static library.
- `cppminhook_demo`: demo executable.
- `cppminhook_tests`: CTest executable.
- `cppminhook_bench`: micro-benchmark executable.
- `cppminhook_api_options_example`: API-hooking example executable.
## Example

The demo creates a small executable code block in memory, installs a hook, calls the original path through the trampoline from inside the detour, and then restores the original bytes.

## Additional engine features

- Instruction-boundary-aware patch sizing instead of blindly overwriting a fixed number of bytes.
- Trampoline relocation support for common relative `call`/`jmp` and RIP-relative memory operands on x64.
- Queued batch operations with `queue_enable`, `queue_disable`, `queue_enable_all`, `queue_disable_all`, and `apply_queued`.
- Transaction lifecycle for staged multi-hook updates: `begin_transaction`, `commit_transaction`, `abort_transaction`.
- API resolution helpers for loaded modules through `resolve_api_target` and `create_hook_api`.
- Mutex-guarded engine mutation APIs for safer concurrent usage.
- Rollback-capable queued apply path when one queued hook update fails.
- Default diagnostics file logging active from process start; each run creates a new uniquely-named log file.
- Custom logging callback support via `set_log_callback`; overrides the default file logger.
- Per-hook policy object (`HookOptions`) for strictness and decoder backend selection.

## Decoder backends

- `DecoderBackend::internal`: enabled by default and fully integrated.
- `DecoderBackend::capstone`: fully wired behind `CPPMINHOOK_ENABLE_CAPSTONE`; when enabled and found at configure time, it performs real instruction decoding.
- `DecoderBackend::zydis`: available behind `CPPMINHOOK_ENABLE_ZYDIS` and uses Zydis decoding when configured.

## Supported instruction patterns

- Straightforward prologues with push/pop, mov, add/sub, cmp, test, nop, ret, and common ModRM forms.
- Relative `E8` call and `E9` near jump relocation in trampoline copy.
- `0F 8x` near conditional branch relocation in trampoline copy.
- x64 RIP-relative memory displacement adjustment for common ModRM instructions.

## Not yet supported

- Full relocation for all branch-heavy and hand-written assembly prologues.
- Complete production-grade instruction semantics across the full x86/x64 ISA.

## Relocation behavior notes

- Short branch widening is supported when `HookOptions.allowShortBranchWidening` is enabled.
- Forwarded export resolution is supported in `create_hook_api` and controlled by `HookOptions.resolveForwardedExports`.
- Module auto-load for API hooks is available through `HookOptions.loadModuleIfNeeded`.

## Safety notes

- This project mutates executable memory and should be treated as low-level systems code.
- Prefer testing detours in isolated binaries before applying to larger real-world targets.
- Use queued APIs when changing multiple hooks, and check returned status after every operation.
- Use diagnostics helpers to inspect operation name and Windows error values on failures.
- Structured diagnostic JSON output is available via `format_diagnostic_json` and `format_last_diagnostic_json`.
- Default file logging writes one JSON line per diagnostic event to a uniquely-named file in the working directory.
- Retrieve the active log file path at runtime with `cppminhook::default_log_file_path()`.
- Override or disable default file logging with `set_log_callback(myCallback)` or `set_log_callback(nullptr)`.

## Default diagnostics logging

Logging is active automatically on every run without any setup. A new file is created each time the process starts, named after the current timestamp and process ID:

```
cppminhook_20260420_153042_123_pid12345.log
```

Each line in the log is a JSON-formatted diagnostic event. Example:

```json
{"status":"unsupported_target","code":"unsupported_instruction","operation":"Hook::create.patch_size_too_small","patchSize":3,"systemError":0}
```

To query the log path from code:

```cpp
std::string path = cppminhook::default_log_file_path();
```

To replace the default logger with your own callback:

```cpp
cppminhook::set_log_callback([](const cppminhook::DiagnosticContext& ctx) {
    // your handler
});
```

To disable logging entirely:

```cpp
cppminhook::set_log_callback(nullptr);
```

## Thread-safety guarantees

- Engine lifecycle and mutation operations are guarded by a mutex.
- Hook transaction methods are serialized with other engine mutation calls.
- Hook object direct calls are intended to be orchestrated by `HookEngine` in multi-threaded scenarios.

| API | Thread-safety contract |
| --- | --- |
| `HookEngine::initialize` / `uninitialize` | Thread-safe, serialized by engine mutex. |
| `HookEngine::create_hook*` / `remove_hook` | Thread-safe, serialized by engine mutex. |
| `HookEngine::queue_*` / `apply_queued` | Thread-safe, serialized by engine mutex. |
| `HookEngine::begin_transaction` / `commit_transaction` / `abort_transaction` | Thread-safe, serialized by engine mutex. |
| `HookEngine::find_hook` / `resolve_api_target` | Thread-safe for reads under engine mutex. |
| `Hook::enable` / `disable` / `remove` | Not independently synchronized across threads; prefer engine orchestration. |

## API/options example

- `examples/api_options_example.cpp` demonstrates:
- `create_hook_api` for module/export resolution.
- Per-hook `HookOptions` selection.
- Queued enable/disable flow with trampoline-based original call.

## CI and quality gates

- GitHub Actions runs Windows builds for both Debug and Release configurations.
- CI executes CTest with `--output-on-failure`.
- CI runs `cppminhook_bench` in Debug, writes benchmark metrics, and enforces a simple regression threshold.
- CI uploads benchmark artifacts for trend tracking across runs.
- Tests include deterministic relocation fixtures and fuzz-like prologue robustness loops.

## Package install and reuse

- CMake install exports package config files for downstream `find_package(CppMinHook CONFIG REQUIRED)` usage.
- Installed target name is `CppMinHook::cppminhook`.

Install and consume example:

```powershell
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=C:/local/cppminhook
cmake --build build --config Release
cmake --install build --config Release
```

```cmake
find_package(CppMinHook CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE CppMinHook::cppminhook)
```
## Current limitations

- Windows only.
- x64 patching still uses a fixed absolute jump stub.
- Relocation coverage is intentionally scoped and does not cover every instruction encoding.
- External decoder backends are policy-level integration points and are not bundled by default.
- It is suitable as a class-based foundation and educational scaffold, not as a production-complete replacement for MinHook.

## Clean-room note

This repository does not contain a direct rewrite of the upstream MinHook source. It is an original C++20 design created for the same general domain.

