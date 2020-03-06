project(iSulad_LLT)

SET(EXE isulad-shim_llt)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad-shim/process.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad-shim/common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/json/schema/src/read_file.c
    ${CMAKE_BINARY_DIR}/json/json_common.c
    ${CMAKE_BINARY_DIR}/json/host_config.c
    ${CMAKE_BINARY_DIR}/json/shim_client_process_state.c
    isulad-shim_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad-shim
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/json
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/json/schema/src/
    ${CMAKE_BINARY_DIR}/json
    ${CMAKE_BINARY_DIR}/conf
    )
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} -lyajl)
