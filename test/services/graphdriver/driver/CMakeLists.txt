project(iSulad_LLT)

SET(EXE driver_llt)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks/driver_overlay2_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks/image_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks/isulad_config_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/graphdriver/driver.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/graphdriver/devmapper/driver_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libisulad.c
    ${CMAKE_BINARY_DIR}/json/json_common.c
    driver_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/json
    ${ENGINES_INCS}
    ${RUNTIME_INCS}
    ${IMAGE_INCS}
    ${CMAKE_BINARY_DIR}/json
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/graphdriver/devmapper
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/graphdriver/overlay2
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/image
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/image/oci
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cmd
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks
    )

#set_target_properties(${EXE} PROPERTIES LINK_FLAGS)
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
