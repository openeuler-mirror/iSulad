set(CHECKED_INCLUDE_DIRS
    ${STD_HEADER_CTYPE}
    ${STD_HEADER_SYS_PARAM}
    ${LIBYAJL_INCLUDE_DIR}
    ${LIBARCHIVE_INCLUDE_DIR}
    ${HTTP_PARSER_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIR}
    ${SYSTEMD_INCLUDE_DIR}
    ${ISULA_LIBUTILS_INCLUDE_DIR}
    )

if (GRPC_CONNECTOR)
    list(APPEND CHECKED_INCLUDE_DIRS
        ${GRPC_INCLUDE_DIR}
        ${CLIBCNI_INCLUDE_DIR}
        ${WEBSOCKET_INCLUDE_DIR}
        )
else()
    list(APPEND CHECKED_INCLUDE_DIRS
        ${SQLIT3_INCLUDE_DIR}
        ${EVENT_INCLUDE_DIR}
        ${EVHTP_INCLUDE_DIR}
        )
endif()
list(REMOVE_DUPLICATES CHECKED_INCLUDE_DIRS)

set(SHARED_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/cutils 
    ${CMAKE_CURRENT_SOURCE_DIR}/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/console
    ${CMAKE_CURRENT_SOURCE_DIR}/map
    ${CMAKE_BINARY_DIR}/conf
    ${CHECKED_INCLUDE_DIRS}
    )

add_subdirectory(tar)
add_subdirectory(sha256)
add_subdirectory(cutils)
add_subdirectory(console)
add_subdirectory(map)

set(SHARED_SRCS
    ${TAR_SRCS}
    ${SHA256_SRCS}
    ${CUTILS_SRCS}
    ${CONSOLE_SRCS}
    ${MAP_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/container_def.c
    )

# get all c and header files
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/connect)

if (GRPC_CONNECTOR)
    # GRPC
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/types CONNECT_API_TYPES)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/containers CONNECT_API_CONTAINERS)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/images CONNECT_API_IMAGES)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/cri CONNECT_API_CRI)
    set(CONNECT_API ${CONNECT_API_TYPES} ${CONNECT_API_CONTAINERS} ${CONNECT_API_IMAGES} ${CONNECT_API_CRI})

    list(APPEND SHARED_INCS
        ${CMAKE_BINARY_DIR}/grpc/src/api/types
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/containers
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/images
        ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri
        ${CMAKE_CURRENT_SOURCE_DIR}/cpputils
        )

    add_subdirectory(cpputils)
    add_subdirectory(websocket)

    list(APPEND SHARED_SRCS ${CPPUTILS_SRCS})
else()
    list(APPEND SHARED_INCS
         ${CMAKE_CURRENT_SOURCE_DIR}/api/services/containers/rest
         ${CMAKE_CURRENT_SOURCE_DIR}/api/services/images/rest
         )
endif()

list(APPEND SHARED_SRCS ${CONNECT_API} ${CPPUTILS_SRCS})
list(REMOVE_DUPLICATES SHARED_INCS)
list(REMOVE_DUPLICATES SHARED_SRCS)

add_subdirectory(http)

# ------ build libisula ------
if (OPENSSL_VERIFY)
    list(APPEND CONNECTOR ${CMAKE_CURRENT_SOURCE_DIR}/http/certificate.c)
endif()

add_library(libisula ${LIBTYPE}
    ${CMAKE_CURRENT_SOURCE_DIR}/libisula.c
    ${CONNECTOR}
    ${SHARED_SRCS}
    )

target_include_directories(libisula PUBLIC
    ${SHARED_INCS}
    ${CONNECTOR_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/http
    )

# set libisula FLAGS
set_target_properties(libisula PROPERTIES PREFIX "")
target_link_libraries(libisula ${LIBYAJL_LIBRARY} ${SELINUX_LIBRARY} ${ISULA_LIBUTILS_LIBRARY} ${LIBARCHIVE_LIBRARY})

if (GRPC_CONNECTOR)
    target_link_libraries(libisula -Wl,--as-needed -lstdc++ -lcrypto)
    target_link_libraries(libisula -Wl,--as-needed ${PROTOBUF_LIBRARY})
    target_link_libraries(libisula -Wl,--no-as-needed ${GRPC_PP_REFLECTION_LIBRARY} ${GRPC_PP_LIBRARY} ${GRPC_LIBRARY} ${GPR_LIBRARY})
else()
    target_link_libraries(libisula ${EVHTP_LIBRARY} ${EVENT_LIBRARY} ${ZLIB_LIBRARY} -ldl libhttpclient)
endif()
# ------ build libisula finish -----

add_subdirectory(cmd)
# ------ build isula -------
add_executable(isula
    ${ISULA_SRCS}
    )
target_include_directories(isula PUBLIC ${ISULA_INCS} ${SHARED_INCS})
target_link_libraries(isula libisula -lpthread)
# ------ build isula finish -------

# ------ build isulad-shim -------
add_executable(isulad-shim
    ${ISULAD_SHIM_SRCS}
    )
target_include_directories(isulad-shim PUBLIC ${ISULAD_SHIM_INCS} ${SHARED_INCS})
target_link_libraries(isulad-shim ${LIBYAJL_LIBRARY} ${ISULA_LIBUTILS_LIBRARY} -lpthread)

# ------ build isula-shim finish -------

# ------ build isulad -------
add_subdirectory(services)
add_subdirectory(image)
add_subdirectory(runtime)

if (ENABLE_OCI_IMAGE)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/types CONNECT_API_TYPES)
    aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/image_client/ IMAGE_CLIENT_SRCS)

    list(APPEND IMAGE_SRCS
        ${ISULA_IMAGE_CLIENT_SRCS}
        ${CONNECT_API_TYPES} ${IMAGE_CLIENT_SRCS}
        )
    list(APPEND IMAGE_INCS
        ${CMAKE_BINARY_DIR}/grpc/src/api/types
        ${CMAKE_BINARY_DIR}/grpc/src/api/image_client
        ${GRPC_INCLUDE_DIR}
        ${ISULA_IMAGE_CLIENT_INCS}
        )
endif()

add_subdirectory(engines)

add_subdirectory(plugin)
add_subdirectory(config)

add_executable(isulad
    ${CONNECT_SOCKET} ${SHARED_SRCS}
    ${ISULAD_SRCS} ${SERVICES_SRCS}
    ${HTTP_SRCS}
    ${ENGINES_SRCS}
    ${IMAGE_SRCS}
    ${RUNTIME_SRCS}
    ${PLUGIN_SRCS}
    ${CONFIG_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/libisulad.c
    ${WEBSOCKET_SERVICE_SRCS}
    )

target_include_directories(isulad PUBLIC
    ${SHARED_INCS}
    ${CONNECT_SOCKET_INCS}
    ${SERVICES_INCS}
    ${IMAGE_INCS}
    ${RUNTIME_INCS}
    ${ENGINES_INCS}
    ${ISULAD_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${CMAKE_CURRENT_SOURCE_DIR}/http
    ${WEBSOCKET_SERVICE_INCS}
    )

target_link_libraries(isulad ${LIBYAJL_LIBRARY} ${SYSTEMD_LIBRARY} ${SELINUX_LIBRARY} ${LIBARCHIVE_LIBRARY})
target_link_libraries(isulad -ldl ${ZLIB_LIBRARY} ${ISULA_LIBUTILS_LIBRARY} -lpthread libhttpclient)
if (ENABLE_EMBEDDED_IMAGE)
    target_link_libraries(isulad ${SQLITE3_LIBRARY})
endif()

if (GRPC_CONNECTOR)
    message("GRPC iSulad")
    target_link_libraries(isulad -Wl,--as-needed -lstdc++ -lcrypto)
    target_link_libraries(isulad -Wl,--as-needed ${PROTOBUF_LIBRARY})
    target_link_libraries(isulad -Wl,--no-as-needed ${GRPC_PP_REFLECTION_LIBRARY} ${GRPC_PP_LIBRARY} ${GRPC_LIBRARY} ${GPR_LIBRARY})
    target_link_libraries(isulad ${CLIBCNI_LIBRARY} ${WEBSOCKET_LIBRARY})
    target_link_libraries(isula ${WEBSOCKET_LIBRARY})
else()
    message("Restful iSulad")
    target_link_libraries(isulad ${EVHTP_LIBRARY} ${EVENT_LIBRARY})
endif()

if (ENABLE_OCI_IMAGE)
    target_link_libraries(isulad -Wl,--as-needed -lstdc++)
    target_link_libraries(isulad -Wl,--as-needed -ldevmapper)
    target_link_libraries(isulad -Wl,--as-needed ${PROTOBUF_LIBRARY})
    target_link_libraries(isulad -Wl,--no-as-needed ${GRPC_PP_REFLECTION_LIBRARY} ${GRPC_PP_LIBRARY} ${GRPC_LIBRARY} ${GPR_LIBRARY})
endif()

if (ISULAD_GCOV)
    target_link_libraries(isula -lgcov)
    target_link_libraries(libisula -lgcov)
    target_link_libraries(isulad -lgcov)
endif()

# ------ build isulad finish -------

# ------ install binary --------
install(TARGETS libisula
  LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(TARGETS isula
	RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(TARGETS isulad-shim
	RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(TARGETS isulad
	RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
