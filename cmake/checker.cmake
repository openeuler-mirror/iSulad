include(CheckIncludeFile)

# check depends library and headers
find_package(PkgConfig REQUIRED)

# check python3
find_program(CMD_PYTHON python3)
_CHECK(CMD_PYTHON "CMD_PYTHON-NOTFOUND" "python3")

# check tools
find_program(CMD_TAR tar)
_CHECK(CMD_TAR "CMD_TAR-NOTFOUND" "tar")
find_program(CMD_SHA256 sha256sum)
_CHECK(CMD_SHA256 "CMD_SHA256-NOTFOUND" "sha256sum")
find_program(CMD_GZIP gzip)
_CHECK(CMD_GZIP "CMD_GZIP-NOTFOUND" "gzip")

# check std headers ctype.h sys/param.h sys/capability.h
find_path(STD_HEADER_CTYPE ctype.h)
_CHECK(STD_HEADER_CTYPE "STD_HEADER_CTYPE-NOTFOUND" "ctype.h")

find_path(STD_HEADER_SYS_PARAM sys/param.h)
_CHECK(STD_HEADER_SYS_PARAM "STD_HEADER_SYS_PARAM-NOTFOUND" "sys/param.h")

CHECK_INCLUDE_FILE(sys/capability.h HAVE_LIBCAP)
if (HAVE_LIBCAP)
    message("--  found linux capability.h --- works")
    add_definitions(-DHAVE_LIBCAP_H=1)
else()
    message("--  found linux capability.h --- no")
endif()

if (SYSTEMD_NOTIFY)
# check systemd
    find_path(SYSTEMD_INCLUDE_DIR systemd/sd-daemon.h)
    _CHECK(SYSTEMD_INCLUDE_DIR "SYSTEMD_INCLUDE_DIR-NOTFOUND" "systemd/sd-daemon.h")
    find_library(SYSTEMD_LIBRARY systemd)
    _CHECK(SYSTEMD_LIBRARY "SYSTEMD_LIBRARY-NOTFOUND" "libsystemd.so")
endif()

# check zlib
pkg_check_modules(PC_ZLIB "zlib>=1.2.8")
find_path(ZLIB_INCLUDE_DIR zlib.h
    HINTS ${PC_ZLIB_INCLUDEDIR} ${PC_ZLIB_INCLUDE_DIRS})
_CHECK(ZLIB_INCLUDE_DIR "ZLIB_INCLUDE_DIR-NOTFOUND" "zlib.h")
find_library(ZLIB_LIBRARY z
  HINTS ${PC_ZLIB_LIBDIR} ${PC_ZLIB_LIBRARY_DIRS})
_CHECK(ZLIB_LIBRARY "ZLIB_LIBRARY-NOTFOUND" "libz.so")

# check libyajl
pkg_check_modules(PC_LIBYAJL REQUIRED "yajl>=2")
find_path(LIBYAJL_INCLUDE_DIR yajl/yajl_tree.h
	HINTS ${PC_LIBYAJL_INCLUDEDIR} ${PC_LIBYAJL_INCLUDE_DIRS})
_CHECK(LIBYAJL_INCLUDE_DIR "LIBYAJL_INCLUDE_DIR-NOTFOUND" "yajl/yajl_tree.h")
find_library(LIBYAJL_LIBRARY yajl
    HINTS ${PC_LIBYAJL_LIBDIR} ${PC_LIBYAJL_LIBRARY_DIRS})
_CHECK(LIBYAJL_LIBRARY "LIBYAJL_LIBRARY-NOTFOUND" "libyajl.so")

# check libarchive
pkg_check_modules(PC_LIBARCHIVE REQUIRED "libarchive>=3.4")
find_path(LIBARCHIVE_INCLUDE_DIR archive.h
	HINTS ${PC_LIBARCHIVE_INCLUDEDIR} ${PC_LIBARCHIVE_INCLUDE_DIRS})
_CHECK(LIBARCHIVE_INCLUDE_DIR "LIBARCHIVE_INCLUDE_DIR-NOTFOUND" "archive.h")
find_library(LIBARCHIVE_LIBRARY archive
    HINTS ${PC_LIBARCHIVE_LIBDIR} ${PC_LIBARCHIVE_LIBRARY_DIRS})
_CHECK(LIBARCHIVE_LIBRARY "LIBARCHIVE_LIBRARY-NOTFOUND" "libarchive.so")

# check libcrypto
pkg_check_modules(PC_CRYPTO REQUIRED "libcrypto")
find_library(CRYPTO_LIBRARY crypto
    HINTS ${PC_CRYPTO_LIBDIR} ${PC_LIBCRYPTO_LIBRARY_DIRS})
_CHECK(CRYPTO_LIBRARY "CRYPTO_LIBRARY-NOTFOUND" "libcrypto.so")

# check websocket
find_path(WEBSOCKET_INCLUDE_DIR libwebsockets.h)
_CHECK(WEBSOCKET_INCLUDE_DIR "WEBSOCKET_INCLUDE_DIR-NOTFOUND" libwebsockets.h)
find_library(WEBSOCKET_LIBRARY websockets)
_CHECK(WEBSOCKET_LIBRARY "WEBSOCKET_LIBRARY-NOTFOUND" "libwebsockets.so")

find_path(HTTP_PARSER_INCLUDE_DIR http_parser.h)
_CHECK(HTTP_PARSER_INCLUDE_DIR "HTTP_PARSER_INCLUDE_DIR-NOTFOUND" "http_parser.h")
find_library(HTTP_PARSER_LIBRARY http_parser)
_CHECK(HTTP_PARSER_LIBRARY "HTTP_PARSER_LIBRARY-NOTFOUND" "libhttp_parser.so")

pkg_check_modules(PC_CURL "libcurl>=7.4.0")
find_path(CURL_INCLUDE_DIR "curl/curl.h"
    HINTS ${PC_CURL_INCLUDEDIR} ${PC_CURL_INCLUDE_DIRS})
_CHECK(CURL_INCLUDE_DIR "CURL_INCLUDE_DIR-NOTFOUND" "curl/curl.h")
find_library(CURL_LIBRARY curl
	HINTS ${PC_CURL_LIBDIR} ${PC_CURL_LIBRARY_DIRS})
_CHECK(CURL_LIBRARY "CURL_LIBRARY-NOTFOUND" "libcurl.so")

if (ENABLE_SELINUX)
    pkg_check_modules(PC_SELINUX "libselinux>=2.0")
    find_path(SELINUX_INCLUDE_DIR "selinux/selinux.h"
        HINTS ${PC_SELINUX_INCLUDEDIR} ${PC_SELINUX_INCLUDE_DIRS})
    _CHECK(SELINUX_INCLUDE_DIR "SELINUX_INCLUDE_DIR-NOTFOUND" "selinux/selinux.h")
    find_library(SELINUX_LIBRARY selinux
        HINTS ${PC_SELINUX_LIBDIR} ${PC_SELINUX_LIBRARY_DIRS})
    _CHECK(SELINUX_LIBRARY "SELINUX_LIBRARY-NOTFOUND" "libselinux.so")
endif()

# check iSula libutils
pkg_check_modules(PC_ISULA_LIBUTILS REQUIRED "lcr")
find_path(ISULA_LIBUTILS_INCLUDE_DIR isula_libutils/log.h
	HINTS ${PC_ISULA_LIBUTILS_INCLUDEDIR} ${PC_ISULA_LIBUTILS_INCLUDE_DIRS})
_CHECK(ISULA_LIBUTILS_INCLUDE_DIR "ISULA_LIBUTILS_INCLUDE_DIR-NOTFOUND" "isula_libutils/log.h")

find_library(ISULA_LIBUTILS_LIBRARY isula_libutils
	HINTS ${PC_ISULA_LIBUTILS_LIBDIR} ${PC_ISULA_LIBUTILS_LIBRARY_DIRS})
_CHECK(ISULA_LIBUTILS_LIBRARY "ISULA_LIBUTILS_LIBRARY-NOTFOUND" "libisula_libutils.so")

find_path(LIBSHIM_V2_INCLUDE_DIR shim_v2.h)
_CHECK(LIBSHIM_V2_INCLUDE_DIR "LIBSHIM_V2_INCLUDE_DIR-NOTFOUND" "shim_v2.h")
find_library(LIBSHIM_V2_LIBRARY shim_v2)
_CHECK(LIBSHIM_V2_LIBRARY "LIBSHIM_V2_LIBRARY-NOTFOUND" "libshim_v2.so")

if (OPENSSL_VERIFY)
    find_path(OPENSSL_INCLUDE_DIR openssl/x509.h)
    _CHECK(OPENSSL_INCLUDE_DIR "OPENSSL_INCLUDE_DIR-NOTFOUND" "openssl/x509.h")
endif()

if (GRPC_CONNECTOR OR ENABLE_OCI_IMAGE)
    # check protobuf
    pkg_check_modules(PC_PROTOBUF "protobuf>=3.1.0")
    find_library(PROTOBUF_LIBRARY protobuf
        HINTS ${PC_PROTOBUF_LIBDIR} ${PC_PROTOBUF_LIBRARY_DIRS})
    _CHECK(PROTOBUF_LIBRARY "PROTOBUF_LIBRARY-NOTFOUND" "libprotobuf.so")

    find_program(CMD_PROTOC protoc)
    _CHECK(CMD_PROTOC "CMD_PROTOC-NOTFOUND" "protoc")
    find_program(CMD_GRPC_CPP_PLUGIN grpc_cpp_plugin)
    _CHECK(CMD_GRPC_CPP_PLUGIN "CMD_GRPC_CPP_PLUGIN-NOTFOUND" "grpc_cpp_plugin")

    # check grpc
    find_path(GRPC_INCLUDE_DIR grpc/grpc.h)
    _CHECK(GRPC_INCLUDE_DIR "GRPC_INCLUDE_DIR-NOTFOUND" "grpc/grpc.h")
    find_library(GRPC_PP_REFLECTION_LIBRARY grpc++_reflection)
    _CHECK(GRPC_PP_REFLECTION_LIBRARY "GRPC_PP_REFLECTION_LIBRARY-NOTFOUND" "libgrpc++_reflection.so")
    find_library(GRPC_PP_LIBRARY grpc++)
    _CHECK(GRPC_PP_LIBRARY "GRPC_PP_LIBRARY-NOTFOUND" "libgrpc++.so")
    find_library(GRPC_LIBRARY grpc)
    _CHECK(GRPC_LIBRARY "GRPC_LIBRARY-NOTFOUND" "libgrpc.so")
    find_library(GPR_LIBRARY gpr)
    _CHECK(GPR_LIBRARY "GPR_LIBRARY-NOTFOUND" "libgpr.so")

    # check devmapper
    find_path(DEVMAPPER_INCLUDE_DIR libdevmapper.h)
    _CHECK(DEVMAPPER_INCLUDE_DIR "DEVMAPPER_INCLUDE_DIR-NOTFOUND" "libdevmapper.h")
    find_library(DEVMAPPER_LIBRARY devmapper)
    _CHECK(DEVMAPPER_LIBRARY "DEVMAPPER_LIBRARY-NOTFOUND" "libdevmapper.so")
endif()

if (GRPC_CONNECTOR)
    # check clibcni
    pkg_check_modules(PC_CLIBCNI REQUIRED "clibcni")
    find_path(CLIBCNI_INCLUDE_DIR clibcni/api.h
        HINTS ${PC_CLIBCNI_INCLUDEDIR} ${PC_CLIBCNI_INCLUDE_DIRS})
    _CHECK(CLIBCNI_INCLUDE_DIR "CLIBCNI_INCLUDE_DIR-NOTFOUND" "clibcni/api.h")
    find_library(CLIBCNI_LIBRARY clibcni
        HINTS ${PC_CLIBCNI_LIBDIR} ${PC_CLIBCNI_LIBRARY_DIRS})
    _CHECK(CLIBCNI_LIBRARY "CLIBCNI_LIBRARY-NOTFOUND" "libclibcni.so")
else()
    pkg_check_modules(PC_EVENT "event>=2.1.8")
    find_path(EVENT_INCLUDE_DIR event.h
        HINTS ${PC_EVENT_INCLUDEDIR} ${PC_EVENT_INCLUDE_DIRS})
    _CHECK(EVENT_INCLUDE_DIR "EVENT_INCLUDE_DIR-NOTFOUND" "event.h")
    find_library(EVENT_LIBRARY event
        HINTS ${PC_EVENT_LIBDIR} ${PC_EVENT_LIBRARY_DIRS})
    _CHECK(EVENT_LIBRARY "EVENT_LIBRARY-NOTFOUND" "libevent.so")

    pkg_check_modules(PC_EVHTP "evhtp>=1.2.16")
    find_path(EVHTP_INCLUDE_DIR evhtp/evhtp.h
        HINTS ${PC_EVHTP_INCLUDEDIR} ${PC_EVHTP_INCLUDE_DIRS})
    _CHECK(EVHTP_INCLUDE_DIR "EVHTP_INCLUDE_DIR-NOTFOUND" "evhtp/evhtp.h")
    find_library(EVHTP_LIBRARY evhtp
        HINTS ${PC_EVHTP_LIBDIR} ${PC_EVHTP_LIBRARY_DIRS})
    _CHECK(EVHTP_LIBRARY "EVHTP_LIBRARY-NOTFOUND" "libevhtp.so")
endif()

if (ENABLE_EMBEDDED_IMAGE)
    pkg_check_modules(PC_SQLITE3 "sqlite3>=3.7.17")
    find_path(SQLIT3_INCLUDE_DIR sqlite3.h
        HINTS ${PC_SQLITE3_INCLUDEDIR} ${PC_SQLITE3_INCLUDE_DIRS})
    _CHECK(SQLIT3_INCLUDE_DIR "SQLIT3_INCLUDE_DIR-NOTFOUND" "sqlite3.h")
    find_library(SQLITE3_LIBRARY sqlite3
        HINTS ${PC_SQLITE3_LIBDIR} ${PC_SQLITE3_LIBRARY_DIRS})
    _CHECK(SQLITE3_LIBRARY "SQLITE3_LIBRARY-NOTFOUND" "libsqlite3.so")
endif()
