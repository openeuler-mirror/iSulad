project(iSulad_UT)

execute_process(COMMAND bash "-c" "find /usr -name *libclang_rt.fuzzer-${CMAKE_HOST_SYSTEM_PROCESSOR}* | head -1"
    OUTPUT_VARIABLE LIB_FUZZING_ENGINE
    OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(COMMAND bash "-c" "which gclang"
    OUTPUT_VARIABLE GCLANG_BINARY
    OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(COMMAND bash "-c" "which gclang++"
    OUTPUT_VARIABLE GCLANG_PP_BINARY
    OUTPUT_STRIP_TRAILING_WHITESPACE)

IF(LIB_FUZZING_ENGINE STREQUAL "")
    MESSAGE(WARNING "LIB_FUZZING_ENGINE IS NULL, WILL IGNORE DIRECTORY <FUZZ> COMPILE")
    RETURN()
ENDIF()

IF(GCLANG_BINARY STREQUAL "")
    MESSAGE(WARNING "GCLANG_BINARY IS NULL, WILL IGNORE DIRECTORY <FUZZ> COMPILE")
    RETURN()
ENDIF()

IF(GCLANG_PP_BINARY STREQUAL "")
    MESSAGE(WARNING "GCLANG_PP_BINARY IS NULL, WILL IGNORE DIRECTORY <FUZZ> COMPILE")
    RETURN()
ENDIF()

MESSAGE(STATUS "LIB_FUZZING_ENGINE is set to ${LIB_FUZZING_ENGINE}")
MESSAGE(STATUS "GCLANG_BINARY is set to ${GCLANG_BINARY}")
MESSAGE(STATUS "GCLANG_PP_BINARY is set to ${GCLANG_PP_BINARY}")

SET(CMAKE_C_COMPILER "${GCLANG_BINARY}")
SET(CMAKE_CXX_COMPILER "${GCLANG_PP_BINARY}")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 --coverage -fsanitize=fuzzer,address -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep")

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
if (COMPILER_SUPPORTS_CXX17)
    message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has C++17 support.")
    set(CMAKE_CXX_VERSION "-std=c++17")
else()
    message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++17 support. Use C++11.")
    set(CMAKE_CXX_VERSION "-std=c++11")
endif()

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 --coverage ${CMAKE_CXX_VERSION} -fsanitize=fuzzer,address -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep")
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

SET(EXE0 test_volume_mount_spec_fuzz)
SET(EXE1 test_volume_parse_volume_fuzz)
SET(EXE2 test_pw_obj_parser_fuzz)
SET(EXE3 test_gr_obj_parser_fuzz)
add_executable(${EXE0}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_mount_spec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/config/isulad_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/config/daemon_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/common/err_msg.c
    test_volume_mount_spec_fuzz.cc
    )
add_executable(${EXE1}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/modules/spec/parse_volume.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/config/isulad_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/config/daemon_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/common/err_msg.c
    test_volume_parse_volume_fuzz.cc
    )
add_executable(${EXE2}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_pwgr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/path.c
    test_pw_obj_parser_fuzz.cc
    )
add_executable(${EXE3}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_pwgr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/path.c
    test_gr_obj_parser_fuzz.cc
    )

SET(IMAGE_FUZZ_INCLUDE_DIRS
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/http
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/modules
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/modules/api
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/daemon/modules/spec
    )

target_include_directories(${EXE0} PUBLIC
    ${IMAGE_FUZZ_INCLUDE_DIRS}
    )

target_include_directories(${EXE1} PUBLIC
    ${IMAGE_FUZZ_INCLUDE_DIRS}
    )

target_include_directories(${EXE2} PUBLIC
    ${IMAGE_FUZZ_INCLUDE_DIRS}
)

target_include_directories(${EXE3} PUBLIC
    ${IMAGE_FUZZ_INCLUDE_DIRS}
)

set_target_properties(${EXE0} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${EXE0} PROPERTIES LINK_FLAGS "--coverage -fsanitize=fuzzer,address -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep")
target_link_libraries(${EXE0} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} ${LIB_FUZZING_ENGINE} pthread rt -lcrypto -lyajl -lz)

set_target_properties(${EXE1} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${EXE1} PROPERTIES LINK_FLAGS "--coverage -fsanitize=fuzzer,address -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep")
target_link_libraries(${EXE1} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} ${LIB_FUZZING_ENGINE} pthread rt -lcrypto -lyajl -lz)

set_target_properties(${EXE2} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${EXE2} PROPERTIES LINK_FLAGS "--coverage -fsanitize=fuzzer,address -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep")
target_link_libraries(${EXE2} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} ${LIB_FUZZING_ENGINE} pthread rt -lcrypto -lyajl -lz)

set_target_properties(${EXE3} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${EXE3} PROPERTIES LINK_FLAGS "--coverage -fsanitize=fuzzer,address -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep")
target_link_libraries(${EXE3} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} ${LIB_FUZZING_ENGINE} pthread rt -lcrypto -lyajl -lz)
