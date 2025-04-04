set(CHECKED_INCLUDE_DIRS
    ${STD_HEADER_CTYPE}
    ${STD_HEADER_SYS_PARAM}
    ${LIBYAJL_INCLUDE_DIR}
    ${LIBARCHIVE_INCLUDE_DIR}
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

if (ENABLE_NRI)
    list(APPEND CHECKED_INCLUDE_DIRS
        ${NRI_INCLUDE_DIR}
        )
endif()

if (GRPC_CONNECTOR)
    list(APPEND CHECKED_INCLUDE_DIRS
        ${GRPC_INCLUDE_DIR}
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

add_subdirectory(common)
add_subdirectory(utils)

set(SHARED_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${COMMON_INCS}
    ${UTILS_INCS}
    ${CMAKE_BINARY_DIR}/conf
    ${CHECKED_INCLUDE_DIRS}
    )

add_library(libisulad_tools ${LIBTYPE} ${UTILS_SRCS})
target_include_directories(libisulad_tools
    PUBLIC ${SHARED_INCS}
    PUBLIC ${ISULA_LIBUTILS_INCLUDE_DIR}
    )

set_target_properties(libisulad_tools PROPERTIES PREFIX "")
target_link_libraries(libisulad_tools ${ZLIB_LIBRARY} ${ISULA_LIBUTILS_LIBRARY} ${CRYPTO_LIBRARY} ${CAP_LIBRARY})

if (ENABLE_OCI_IMAGE)
    target_link_libraries(libisulad_tools ${LIBARCHIVE_LIBRARY})
endif()
if (NOT GRPC_CONNECTOR)
    set_target_properties(libisulad_tools PROPERTIES LINKER_LANGUAGE "C")
endif()

# get all c and header files
list(REMOVE_DUPLICATES SHARED_INCS)

# ------ build libisula_client ------

add_subdirectory(client)
if (OPENSSL_VERIFY)
    list(APPEND CLIENT_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/utils/http/certificate.c)
endif()

add_library(libisula_client ${LIBTYPE}
    ${CLIENT_SRCS}
    )

target_include_directories(libisula_client PUBLIC
    ${SHARED_INCS}
    ${CLIENT_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/http
    )

# set libisula_client FLAGS
set_target_properties(libisula_client PROPERTIES PREFIX "")

target_link_libraries(libisula_client libisulad_tools)

if (GRPC_CONNECTOR)
    target_link_libraries(libisula_client -Wl,--as-needed -lstdc++)
    target_link_libraries(libisula_client -Wl,--as-needed ${PROTOBUF_LIBRARY})
    target_link_libraries(libisula_client -Wl,--as-needed ${GRPC_PP_REFLECTION_LIBRARY} ${GRPC_PP_LIBRARY} ${GRPC_LIBRARY} ${GPR_LIBRARY})
    target_link_libraries(libisula_client -Wl,--as-needed ${ISULAD_ABSL_USED_TARGETS})
else()
    target_link_libraries(libisula_client -ldl libhttpclient)
    set_target_properties(libisula_client PROPERTIES LINKER_LANGUAGE "C")
endif()
# ------ build libisula_client finish -----

add_subdirectory(cmd)
# ------ build isula -------
add_executable(isula
    ${ISULA_SRCS}
    )
target_include_directories(isula PUBLIC ${ISULA_INCS} ${SHARED_INCS})
target_link_libraries(isula libisula_client ${LIBYAJL_LIBRARY})
if (GRPC_CONNECTOR)
    target_link_libraries(isula ${NCURSES_LIBRARY})
endif()

if (ANDROID OR MUSL)
    target_link_libraries(isula ${LIBSSL_LIBRARY})
else()
    target_link_libraries(isula -lpthread)
endif()
# ------ build isula finish -------

# ------ build isulad-shim -------
add_executable(isulad-shim
    ${ISULAD_SHIM_SRCS}
    )
target_include_directories(isulad-shim PUBLIC 
    ${ISULAD_SHIM_INCS} 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${COMMON_INCS}
    ${CMAKE_BINARY_DIR}/conf
    ${CHECKED_INCLUDE_DIRS}
    ${SHARED_INCS}
    ${ISULA_LIBUTILS_INCLUDE_DIR}
    )
target_link_libraries(isulad-shim ${ISULAD_SHIM_LIBUTILS_LIBRARY} ${LIBYAJL_LIBRARY})
if (ANDROID OR MUSL)
    target_link_libraries(isulad-shim ${LIBSSL_LIBRARY})
else()
    target_link_libraries(isulad-shim -lpthread)
endif()
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
    ${DAEMON_NETWORK_SRCS}
    )

target_include_directories(isulad PUBLIC
    ${DAEMON_INCS}
    ${SHARED_INCS}
    ${CONNECT_SOCKET_INCS}
    ${ISULAD_INCS}
    ${DAEMON_NETWORK_INCS}
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

if (ENABLE_NRI)
    target_link_libraries(isulad ${LIBISULA_NRI_LIBRARY})
endif()

if (ENABLE_EMBEDDED_IMAGE)
    target_link_libraries(isulad ${SQLITE3_LIBRARY})
endif()

if (ENABLE_OCI_IMAGE)
    target_link_libraries(isulad ${DEVMAPPER_LIBRARY})
endif()

if (GRPC_CONNECTOR)
    target_link_libraries(isulad -Wl,--as-needed -lstdc++)
    target_link_libraries(isulad -Wl,--as-needed ${WEBSOCKET_LIBRARY} ${PROTOBUF_LIBRARY})
    target_link_libraries(isulad -Wl,--as-needed ${GRPC_PP_REFLECTION_LIBRARY} ${GRPC_PP_LIBRARY} ${GRPC_LIBRARY} ${GPR_LIBRARY})
    if (ENABLE_METRICS)
        target_link_libraries(isulad ${EVHTP_LIBRARY} ${EVENT_LIBRARY})
    endif()
    target_link_libraries(isulad -Wl,--as-needed ${ISULAD_ABSL_USED_TARGETS})
else()
    message("Restful iSulad")
    target_link_libraries(isulad ${EVHTP_LIBRARY} ${EVENT_LIBRARY})
    set_target_properties(isulad PROPERTIES LINKER_LANGUAGE "C")
endif()

if (ENABLE_SANDBOXER)
    target_link_libraries(isulad isula_sandbox)
endif()

target_link_libraries(isulad libisulad_tools libhttpclient -ldl)
if (ANDROID OR MUSL)
    target_link_libraries(isulad ${LIBSSL_LIBRARY} ${LIBYAJL_LIBRARY})
else()
    target_link_libraries(isulad -lpthread)
endif()

if (ISULAD_GCOV)
    target_link_libraries(isula -lgcov)
    target_link_libraries(libisula_client -lgcov)
    target_link_libraries(isulad -lgcov)
endif()

# ------ build isulad finish -------

# ------ install binary --------
install(TARGETS libisulad_tools
    ${INSTALL_TYPE} DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(TARGETS libisula_client
    ${INSTALL_TYPE} DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(TARGETS isula
    RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(TARGETS isulad-shim
    RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(TARGETS isulad
    RUNTIME DESTINATION bin PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
