project(iSulad_UT)

SET(EXE utils_network_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/utils_network_mock.cc
    utils_network_ut.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks
    )

target_link_libraries(${EXE}
    ${GTEST_BOTH_LIBRARIES}
    ${GMOCK_LIBRARY}
    ${GMOCK_MAIN_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${ISULA_LIBUTILS_LIBRARY}
    libutils_ut -lcrypto -lyajl -lz)

add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
set_tests_properties(${EXE} PROPERTIES TIMEOUT 120)
