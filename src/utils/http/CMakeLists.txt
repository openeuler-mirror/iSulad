# set sources and headers for libhttpclient
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} http_client_srcs)

if (NOT OPENSSL_VERIFY)
    list(REMOVE_ITEM http_client_srcs "${CMAKE_CURRENT_SOURCE_DIR}/certificate.c")
endif()

add_library(libhttpclient ${LIBTYPE} ${http_client_srcs})

target_include_directories(libhttpclient PUBLIC 
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/utils
    ${CMAKE_SOURCE_DIR}/src/utils/cutils
    ${CMAKE_SOURCE_DIR}/src/utils/http
    ${CHECKED_INCLUDE_DIRS}
    )

# set libhttpclient FLAGS
set_target_properties(libhttpclient PROPERTIES PREFIX "")
target_link_libraries(libhttpclient ${HTTP_PARSER_LIBRARY} ${CURL_LIBRARY})

if (ISULAD_GCOV)
    target_link_libraries(libhttpclient -lgcov)
endif()

install(TARGETS libhttpclient 
    LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
