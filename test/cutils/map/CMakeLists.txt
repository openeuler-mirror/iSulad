project(iSulad_UT)

SET(EXE map_ut)

add_executable(${EXE}
    map_ut.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/map
    )

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} libutils_ut -lcrypto -lyajl -lz)
add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
