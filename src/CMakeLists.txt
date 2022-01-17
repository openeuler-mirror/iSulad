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

if (ENABLE_SHIM_V2)
	list(APPEND CHECKED_INCLUDE_DIRS
	    ${LIBSHIM_V2_INCLUDE_DIR}
	    )
endif()

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

add_subdirectory(utils)
add_subdirectory(common)

set(SHARED_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	${COMMON_INCS}
	${UTILS_INCS}
	${CMAKE_BINARY_DIR}/conf
	${CHECKED_INCLUDE_DIRS}
    )

add_library(libisulad_tools ${LIBTYPE} ${UTILS_SRCS} )
target_include_directories(libisulad_tools
    PUBLIC ${SHARED_INCS}
    PUBLIC ${ISULA_LIBUTILS_INCLUDE_DIR}
)
set_target_properties(libisulad_tools PROPERTIES PREFIX "")
target_link_libraries(libisulad_tools ${ZLIB_LIBRARY} ${ISULA_LIBUTILS_LIBRARY} ${CRYPTO_LIBRARY})

if (ENABLE_OCI_IMAGE)
    target_link_libraries(libisulad_tools ${LIBARCHIVE_LIBRARY})
endif()
if (NOT GRPC_CONNECTOR)
    set_target_properties(libisulad_tools PROPERTIES LINKER_LANGUAGE "C")
endif()

# get all c and header files
list(REMOVE_DUPLICATES SHARED_INCS)

# ------ build libisula ------

add_subdirectory(client)
if (OPENSSL_VERIFY)
    list(APPEND CLIENT_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/utils/http/certificate.c)
endif()

add_library(libisula ${LIBTYPE}
    ${CLIENT_SRCS}
    )

target_include_directories(libisula PUBLIC
    ${SHARED_INCS}
    ${CLIENT_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/http
    )

# set libisula FLAGS
set_target_properties(libisula PROPERTIES PREFIX "")

target_link_libraries(libisula libisulad_tools)

if (GRPC_CONNECTOR)
    target_link_libraries(libisula -Wl,--as-needed -lstdc++)
    target_link_libraries(libisula -Wl,--as-needed ${PROTOBUF_LIBRARY})
    target_link_libraries(libisula -Wl,--no-as-needed ${GRPC_PP_REFLECTION_LIBRARY} ${GRPC_PP_LIBRARY} ${GRPC_LIBRARY} ${GPR_LIBRARY})
    if(ABSL_SYNC_LIB)
        target_link_libraries(libisula -Wl,--no-as-needed ${ABSL_SYNC_LIB})
    endif()
else()
    target_link_libraries(libisula -ldl libhttpclient)
    set_target_properties(libisula PROPERTIES LINKER_LANGUAGE "C")
endif()
# ------ build libisula finish -----

add_subdirectory(cmd)
# ------ build isula -------
add_executable(isula
    ${ISULA_SRCS}
    )
target_include_directories(isula PUBLIC ${ISULA_INCS} ${SHARED_INCS})
target_link_libraries(isula libisula ${LIBYAJL_LIBRARY} -lpthread)
# ------ build isula finish -------

# ------ build isulad-shim -------
add_executable(isulad-shim
    ${ISULAD_SHIM_SRCS}
    )
target_include_directories(isulad-shim PUBLIC ${ISULAD_SHIM_INCS} ${SHARED_INCS})
target_link_libraries(isulad-shim libisulad_tools -lpthread)
if (NOT GRPC_CONNECTOR)
    set_target_properties(isulad-shim PROPERTIES LINKER_LANGUAGE "C")
endif()

# ------ build isula-shim finish -------

# ------ build isulad -------
add_subdirectory(daemon)

add_executable(isulad
    ${DAEMON_SRCS}
    ${ISULAD_SRCS}
    ${HTTP_SRCS}
    )

target_include_directories(isulad PUBLIC
    ${DAEMON_INCS}
    ${SHARED_INCS}
    ${CONNECT_SOCKET_INCS}
    ${ISULAD_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/http
    )

target_link_libraries(isulad ${LIBTAR_LIBRARY})

if (SYSTEMD_NOTIFY)
    target_link_libraries(isulad ${SYSTEMD_LIBRARY})
endif()

if (ENABLE_SELINUX)
    target_link_libraries(isulad ${SELINUX_LIBRARY})
endif()

if (ENABLE_SHIM_V2)
    target_link_libraries(isulad ${LIBSHIM_V2_LIBRARY})
endif()

if (ENABLE_EMBEDDED_IMAGE)
    target_link_libraries(isulad ${SQLITE3_LIBRARY})
endif()

if (ENABLE_OCI_IMAGE)
    target_link_libraries(isulad ${DEVMAPPER_LIBRARY})
endif()

if (GRPC_CONNECTOR)
    message("GRPC iSulad")
    target_link_libraries(isulad -Wl,--as-needed -lstdc++)
    target_link_libraries(isulad -Wl,--as-needed ${WEBSOCKET_LIBRARY} ${PROTOBUF_LIBRARY})
    target_link_libraries(isulad -Wl,--no-as-needed ${GRPC_PP_REFLECTION_LIBRARY} ${GRPC_PP_LIBRARY} ${GRPC_LIBRARY} ${GPR_LIBRARY})
    if(ABSL_SYNC_LIB)
        target_link_libraries(isulad -Wl,--no-as-needed ${ABSL_SYNC_LIB})
    endif()
    target_link_libraries(isulad ${CLIBCNI_LIBRARY})
else()
    message("Restful iSulad")
    target_link_libraries(isulad ${EVHTP_LIBRARY} ${EVENT_LIBRARY})
    set_target_properties(isulad PROPERTIES LINKER_LANGUAGE "C")
endif()

target_link_libraries(isulad libisulad_tools libhttpclient -ldl -lpthread)

if (ISULAD_GCOV)
    target_link_libraries(isula -lgcov)
    target_link_libraries(libisula -lgcov)
    target_link_libraries(isulad -lgcov)
endif()

# ------ build isulad finish -------

# ------ install binary --------
install(TARGETS libisulad_tools
    ${INSTALL_TYPE} DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(TARGETS libisula
    ${INSTALL_TYPE} DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(TARGETS isula
	RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(TARGETS isulad-shim
	RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(TARGETS isulad
	RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
