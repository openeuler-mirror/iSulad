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
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

SET(EXE0 im_oci_image_exist_fuzz)
SET(EXE1 im_config_image_exist_fuzz)
SET(EXE2 im_get_image_count_fuzz)
add_executable(${EXE0} im_oci_image_exist_fuzz.cpp)
add_executable(${EXE1} im_config_image_exist_fuzz.cpp)
add_executable(${EXE2} im_get_image_count_fuzz.cpp)

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

set_target_properties(${EXE0} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${EXE0} PROPERTIES LINK_FLAGS "-fsanitize=address -fsanitize-coverage=trace-pc")
target_link_libraries(${EXE0} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} ${LIB_FUZZING_ENGINE} pthread rt -lisulad_img)

set_target_properties(${EXE1} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${EXE1} PROPERTIES LINK_FLAGS "-fsanitize=address -fsanitize-coverage=trace-pc")
target_link_libraries(${EXE1} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} ${LIB_FUZZING_ENGINE} pthread rt -lisulad_img)

set_target_properties(${EXE2} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${EXE2} PROPERTIES LINK_FLAGS "-fsanitize=address -fsanitize-coverage=trace-pc")
target_link_libraries(${EXE2} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} ${LIB_FUZZING_ENGINE} pthread rt -lisulad_img)
