project(iSulad_UT)

SET(EXE template_string_parse_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/template_string_parse.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/client_show_format.c
    template_string_parse_ut.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula
    )
    
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} libutils_ut -lcrypto -lyajl -lz)
add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
set_tests_properties(${EXE} PROPERTIES TIMEOUT 120)
