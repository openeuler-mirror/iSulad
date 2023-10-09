project(iSulad_UT)

SET(EXE shim_mainloop_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks/mainloop_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cmd/isulad-shim/mainloop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cmd/isulad-shim/common.c
    shim_mainloop_ut.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cmd/isulad-shim
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks
    )

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULAD_SHIM_LIBUTILS_LIBRARY} -lcrypto -lyajl -lz)
add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
set_tests_properties(${EXE} PROPERTIES TIMEOUT 120)