project(iSulad_UT)

aux_source_directory(${CMAKE_SOURCE_DIR}/src/utils/cutils local_cutils_srcs)
aux_source_directory(${CMAKE_SOURCE_DIR}/src/utils/cutils/map local_cutils_map_srcs)

add_library(libutils_ut STATIC
    ${local_cutils_srcs}
    ${local_cutils_map_srcs}
    )
set_target_properties(libutils_ut PROPERTIES PREFIX "")
target_link_libraries(libutils_ut ${ISULA_LIBUTILS_LIBRARY})
target_include_directories(libutils_ut
    PUBLIC ${CMAKE_SOURCE_DIR}/src/common
    PUBLIC ${CMAKE_SOURCE_DIR}/src/utils/cutils
    PUBLIC ${CMAKE_SOURCE_DIR}/src/utils/cutils/map
)

add_subdirectory(mainloop)
add_subdirectory(utils_string)
add_subdirectory(utils_convert)
add_subdirectory(utils_array)
add_subdirectory(utils_base64)
add_subdirectory(utils_pwgr)
add_subdirectory(utils_namespace)
add_subdirectory(utils_aes)
add_subdirectory(utils_error)
add_subdirectory(utils_fs)
add_subdirectory(utils_file)
add_subdirectory(utils_filters)
add_subdirectory(utils_timestamp)
add_subdirectory(utils_mount_spec)
add_subdirectory(utils_regex)
add_subdirectory(utils_utils)
add_subdirectory(utils_verify)
add_subdirectory(utils_network)
add_subdirectory(utils_transform)
add_subdirectory(utils_version)
add_subdirectory(map)
