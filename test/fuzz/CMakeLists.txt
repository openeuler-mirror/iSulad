project(iSulad_UT)

execute_process(COMMAND bash "-c" "find /usr -name *libclang_rt.fuzzer-${CMAKE_HOST_SYSTEM_PROCESSOR}*"
    OUTPUT_VARIABLE LIB_FUZZING_ENGINE
    OUTPUT_STRIP_TRAILING_WHITESPACE)

IF(LIB_FUZZING_ENGINE STREQUAL "")
    MESSAGE(WARNING "LIB_FUZZING_ENGINE IS NULL, WILL IGNORE DIRECTORY <FUZZ> COMPILE")
    RETURN()
ENDIF()

MESSAGE(STATUS "LIB_FUZZING_ENGINE is set to ${LIB_FUZZING_ENGINE}")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fsanitize-coverage=trace-pc")
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUGS} -fsanitize=address -fsanitize-coverage=trace-pc")
SET(EXE im_oci_image_exist_fuzz)
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_executable(${EXE} im_oci_image_exist_fuzz.cpp)

target_include_directories(${EXE} PUBLIC
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
    )

set_target_properties(${EXE} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${EXE} PROPERTIES LINK_FLAGS "-fsanitize=address -fsanitize-coverage=trace-pc")
target_link_libraries(${EXE} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} ${LIB_FUZZING_ENGINE} pthread rt -lisulad_img)
