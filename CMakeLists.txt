cmake_minimum_required(VERSION 3.20)
project(CppMinHook VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
	message(FATAL_ERROR "CppMinHook currently targets Windows only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CPPMINHOOK_ENABLE_SANITIZERS "Enable address/undefined sanitizers for supported compilers" OFF)
option(CPPMINHOOK_ENABLE_CAPSTONE "Enable Capstone decoder backend if available" OFF)
option(CPPMINHOOK_ENABLE_ZYDIS "Enable Zydis decoder backend if available" OFF)

add_library(cppminhook STATIC
	src/status.cpp
	src/diagnostics.cpp
	src/memory_protection.cpp
	src/trampoline_buffer.cpp
	src/relocator.cpp
	src/hook.cpp
	src/hook_engine.cpp
)

target_include_directories(cppminhook
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(cppminhook PUBLIC cxx_std_20)
target_compile_definitions(cppminhook PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)

add_library(CppMinHook::cppminhook ALIAS cppminhook)

if(MSVC)
	target_compile_options(cppminhook PRIVATE /W4 /permissive-)
else()
	target_compile_options(cppminhook PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(CPPMINHOOK_ENABLE_SANITIZERS)
	if(MSVC)
		message(WARNING "Sanitizers are not configured for MSVC in this project profile.")
	elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
		target_compile_options(cppminhook PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
		target_link_options(cppminhook PRIVATE -fsanitize=address,undefined)
	else()
		message(WARNING "Unsupported compiler for sanitizers: ${CMAKE_CXX_COMPILER_ID}")
	endif()
endif()

if(CPPMINHOOK_ENABLE_CAPSTONE)
	find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)
	find_library(CAPSTONE_LIBRARY NAMES capstone)
	if(CAPSTONE_INCLUDE_DIR AND CAPSTONE_LIBRARY)
		target_compile_definitions(cppminhook PRIVATE CPPMINHOOK_ENABLE_CAPSTONE)
		target_include_directories(cppminhook PRIVATE ${CAPSTONE_INCLUDE_DIR})
		target_link_libraries(cppminhook PRIVATE ${CAPSTONE_LIBRARY})
	else()
		message(FATAL_ERROR "CPPMINHOOK_ENABLE_CAPSTONE=ON but Capstone was not found")
	endif()
endif()

if(CPPMINHOOK_ENABLE_ZYDIS)
	find_path(ZYDIS_INCLUDE_DIR Zydis/Zydis.h)
	find_library(ZYDIS_LIBRARY NAMES Zydis)
	if(ZYDIS_INCLUDE_DIR AND ZYDIS_LIBRARY)
		target_compile_definitions(cppminhook PRIVATE CPPMINHOOK_ENABLE_ZYDIS)
		target_include_directories(cppminhook PRIVATE ${ZYDIS_INCLUDE_DIR})
		target_link_libraries(cppminhook PRIVATE ${ZYDIS_LIBRARY})
	else()
		message(FATAL_ERROR "CPPMINHOOK_ENABLE_ZYDIS=ON but Zydis was not found")
	endif()
endif()

add_executable(cppminhook_demo
	examples/demo.cpp
)

target_link_libraries(cppminhook_demo PRIVATE cppminhook)

if(MSVC)
	target_compile_options(cppminhook_demo PRIVATE /W4 /permissive-)
else()
	target_compile_options(cppminhook_demo PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
enable_testing()

add_executable(cppminhook_tests
	tests/test_main.cpp
)

target_link_libraries(cppminhook_tests PRIVATE cppminhook)

if(MSVC)
	target_compile_options(cppminhook_tests PRIVATE /W4 /permissive-)
else()
	target_compile_options(cppminhook_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME cppminhook_tests COMMAND cppminhook_tests)

add_executable(cppminhook_bench
	benchmarks/benchmark_main.cpp
)

target_link_libraries(cppminhook_bench PRIVATE cppminhook)

if(MSVC)
	target_compile_options(cppminhook_bench PRIVATE /W4 /permissive-)
else()
	target_compile_options(cppminhook_bench PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(cppminhook_api_options_example
	examples/api_options_example.cpp
)

target_link_libraries(cppminhook_api_options_example PRIVATE cppminhook)

if(MSVC)
	target_compile_options(cppminhook_api_options_example PRIVATE /W4 /permissive-)
else()
	target_compile_options(cppminhook_api_options_example PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS cppminhook
	EXPORT CppMinHookTargets
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT CppMinHookTargets
	FILE CppMinHookTargets.cmake
	NAMESPACE CppMinHook::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CppMinHook
)

configure_package_config_file(
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/CppMinHookConfig.cmake.in
	${CMAKE_CURRENT_BINARY_DIR}/CppMinHookConfig.cmake
	INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CppMinHook
)

write_basic_package_version_file(
	${CMAKE_CURRENT_BINARY_DIR}/CppMinHookConfigVersion.cmake
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY SameMajorVersion
)

install(FILES
	${CMAKE_CURRENT_BINARY_DIR}/CppMinHookConfig.cmake
	${CMAKE_CURRENT_BINARY_DIR}/CppMinHookConfigVersion.cmake
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CppMinHook
)

