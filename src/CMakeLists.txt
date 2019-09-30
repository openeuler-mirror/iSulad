# generate .c and .h to analyse json file
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/json)
# get json generate source files
aux_source_directory(${CMAKE_BINARY_DIR}/json generatesrcs)
message("--  Get generate srcs: " ${generatesrcs})
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/json/schema/src commonjsonsrcs)
message("--  Get common json srcs: " ${commonjsonsrcs})
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/json topjsonsrcs)
message("--  Get top json srcs: " ${topjsonsrcs})
list(APPEND JSON_FILES ${generatesrcs} ${commonjsonsrcs} ${topjsonsrcs})
list(REMOVE_DUPLICATES JSON_FILES)

set(CHECKED_INCLUDE_DIRS
    ${STD_HEADER_CTYPE}
    ${STD_HEADER_SYS_PARAM}
    ${LIBSECUREC_INCLUDE_DIR}
    ${LIBYAJL_INCLUDE_DIR}
    ${HTTP_PARSER_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIR}
    ${SYSTEMD_INCLUDE_DIR}
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
    ${CMAKE_CURRENT_SOURCE_DIR}/json
    ${CMAKE_CURRENT_SOURCE_DIR}/json/schema/src
    ${CMAKE_BINARY_DIR}/json
    ${CMAKE_BINARY_DIR}/conf
    ${CHECKED_INCLUDE_DIRS}
    )

add_subdirectory(tar)
add_subdirectory(sha256)
add_subdirectory(cutils)
add_subdirectory(console)

set(SHARED_SRCS
    ${JSON_FILES}
    ${TAR_SRCS}
    ${SHA256_SRCS}
    ${CUTILS_SRCS}
    ${CONSOLE_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/container_def.c
    ${CMAKE_CURRENT_SOURCE_DIR}/types_def.c
    ${CMAKE_CURRENT_SOURCE_DIR}/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mainloop.c
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

# ------ build liblcrc ------
if (OPENSSL_VERIFY)
    list(APPEND CONNECTOR ${CMAKE_CURRENT_SOURCE_DIR}/http/certificate.c)
endif()

add_library(liblcrc ${LIBTYPE} 
    ${CMAKE_CURRENT_SOURCE_DIR}/liblcrc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pack_config.c
    ${CONNECTOR}
    ${SHARED_SRCS}
    )

target_include_directories(liblcrc PUBLIC 
    ${SHARED_INCS}
    ${CONNECTOR_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/http
    )

# set liblcrc FLAGS
set_target_properties(liblcrc PROPERTIES PREFIX "")
target_link_libraries(liblcrc ${LIBYAJL_LIBRARY} ${LIBSECUREC_LIBRARY})

if (GRPC_CONNECTOR)
    target_link_libraries(liblcrc -Wl,--as-needed -lstdc++ -lcrypto)
    target_link_libraries(liblcrc -Wl,--as-needed ${PROTOBUF_LIBRARY})
    target_link_libraries(liblcrc -Wl,--no-as-needed ${GRPC_PP_REFLECTION_LIBRARY} ${GRPC_PP_LIBRARY} ${GRPC_LIBRARY} ${GPR_LIBRARY})
else()
    target_link_libraries(liblcrc ${EVHTP_LIBRARY} ${EVENT_LIBRARY} ${ZLIB_LIBRARY} -ldl libhttpclient)
endif()
# ------ build liblcrc finish -----

add_subdirectory(cmd)
# ------ build lcrc -------
add_executable(lcrc
    ${LCRC_SRCS}
    )
target_include_directories(lcrc PUBLIC ${LCRC_INCS} ${SHARED_INCS})
target_link_libraries(lcrc liblcrc -lpthread)
# ------ build lcrc finish -------

# ------ build lcrd -------
add_subdirectory(services)
add_subdirectory(image)
add_subdirectory(engines)

add_subdirectory(plugin)
add_subdirectory(map)
add_subdirectory(config)

add_executable(lcrd
    ${CONNECT_SOCKET} ${SHARED_SRCS}
    ${LCRD_SRCS} ${SERVICES_SRCS}
    ${HTTP_SRCS}
    ${ENGINES_SRCS}
    ${IMAGE_SRCS}
    ${PLUGIN_SRCS}
    ${MAP_SRCS} ${CONFIG_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/filters.c
    ${CMAKE_CURRENT_SOURCE_DIR}/namespace.c
    ${CMAKE_CURRENT_SOURCE_DIR}/liblcrd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sysctl_tools.c
    ${WEBSOCKET_SERVICE_SRCS}
    )

target_include_directories(lcrd PUBLIC
    ${SHARED_INCS}
    ${CONNECT_SOCKET_INCS}
    ${SERVICES_INCS}
    ${IMAGE_INCS}
    ${ENGINES_INCS}
    ${LCRD_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin
    ${CMAKE_CURRENT_SOURCE_DIR}/map
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${CMAKE_CURRENT_SOURCE_DIR}/http
    ${WEBSOCKET_SERVICE_INCS}
    )

target_link_libraries(lcrd ${LIBYAJL_LIBRARY} ${LIBSECUREC_LIBRARY} ${SYSTEMD_LIBRARY})
target_link_libraries(lcrd -ldl ${ZLIB_LIBRARY} -lpthread libhttpclient)
if (ENABLE_EMBEDDED)
    target_link_libraries(lcrd ${SQLITE3_LIBRARY})
endif()

if (GRPC_CONNECTOR)
    message("GRPC iSulad")
    target_link_libraries(lcrd -Wl,--as-needed -lstdc++ -lcrypto)
    target_link_libraries(lcrd -Wl,--as-needed ${PROTOBUF_LIBRARY})
    target_link_libraries(lcrd -Wl,--no-as-needed ${GRPC_PP_REFLECTION_LIBRARY} ${GRPC_PP_LIBRARY} ${GRPC_LIBRARY} ${GPR_LIBRARY})
    target_link_libraries(lcrd ${CLIBCNI_LIBRARY} ${WEBSOCKET_LIBRARY})
else()
    message("Restful iSulad")
    target_link_libraries(lcrd ${EVHTP_LIBRARY} ${EVENT_LIBRARY})
endif()

if (ISULAD_GCOV)
    target_link_libraries(lcrc -lgcov)
    target_link_libraries(liblcrc -lgcov)
    target_link_libraries(lcrd -lgcov)
endif()

# ------ build lcrd finish -------

# ------ install binary --------
install(TARGETS liblcrc
  LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(TARGETS lcrc
	RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(TARGETS lcrd
	RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
