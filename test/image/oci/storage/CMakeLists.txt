project(iSulad_UT)

add_subdirectory(images)
add_subdirectory(rootfs)
add_subdirectory(layers)
IF (ENABLE_REMOTE_LAYER_STORE)
add_subdirectory(remote_layer_support)
ENDIF()
