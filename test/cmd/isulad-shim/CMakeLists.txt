project(iSulad_UT)

SET(EXE isulad-shim_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad-shim/process.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad-shim/common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad-shim/terminal.c
    isulad-shim_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad-shim
    ${CMAKE_BINARY_DIR}/conf
    )
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lyajl)
add_test(NAME ${EXE} COMMAND ${EXE})
