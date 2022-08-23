option(PACKAGE "set isulad package" ON)
if (PACKAGE STREQUAL "ON")
    set(ISULAD_PACKAGE "iSulad")
    message("${BoldBlue}PackageName: ${ISULAD_PACKAGE} ${ColourReset}")
endif()

option(VERSION "set isulad version" ON)
if (VERSION STREQUAL "ON")
    set(ISULAD_VERSION "2.0.16")
    message("${BoldBlue}Version: ${ISULAD_VERSION} ${ColourReset}")
endif()

message("${BoldGreen}---- Selected options begin ----${ColourReset}")

# build which type of lcr library
option(USESHARED "set type of libs, default is shared" ON)
if (USESHARED STREQUAL "ON")
    set(LIBTYPE "SHARED")
    message("${Green}--  Build shared library${ColourReset}")
    set(INSTALL_TYPE LIBRARY)
else ()
    set(LIBTYPE "STATIC")
    message("${Green}--  Build static library${ColourReset}")
    set(INSTALL_TYPE ARCHIVE)
endif()

option(ENABLE_GRPC "Use grpc as connector" ON)
if (ENABLE_GRPC STREQUAL "ON")
    add_definitions(-DGRPC_CONNECTOR)
    set(GRPC_CONNECTOR 1)
    message("${Green}--  Use grpc connector${ColourReset}")
endif()

option(ENABLE_SYSTEMD_NOTIFY "Enable systemd notify" ON)
if (ENABLE_SYSTEMD_NOTIFY STREQUAL "ON")
    add_definitions(-DSYSTEMD_NOTIFY)
    set(SYSTEMD_NOTIFY 1)
    message("${Green}--  Enable systemd notify${ColourReset}")
endif()

option(ENABLE_OPENSSL_VERIFY "use ssl with connector" ON)
if (ENABLE_OPENSSL_VERIFY STREQUAL "ON")
    add_definitions(-DOPENSSL_VERIFY)
    set(OPENSSL_VERIFY 1)
    message("${Green}--  Enable ssl with connector${ColourReset}")
endif()

option(DEBUG "set isulad gcc option" ON)
if (DEBUG STREQUAL "ON")
    add_definitions("-g -O2")
endif()

option(GCOV "set isulad gcov option" OFF)
if (GCOV STREQUAL "ON")
    set(ISULAD_GCOV "ON")
    message("${Green}--  Enable GCOV${ColourReset}")
endif()
OPTION(ENABLE_UT "ut switch" OFF)
if (ENABLE_UT STREQUAL "ON")
    set(ENABLE_UT 1)
    message("${Green}--  Enable UT${ColourReset}")
endif()
OPTION(ENABLE_FUZZ "fuzz switch" OFF)
if (ENABLE_FUZZ STREQUAL "ON")
    set(ENABLE_FUZZ 1)
    message("${Green}--  Enable FUZZ${ColourReset}")
endif()

# set OCI image server type
option(DISABLE_OCI "disable oci image" OFF)
if (DISABLE_OCI STREQUAL "ON")
    message("${Green}--  Disable OCI image${ColourReset}")
else()
    add_definitions(-DENABLE_OCI_IMAGE=1)
    set(ENABLE_OCI_IMAGE 2)
    message("${Green}--  Enable OCI image${ColourReset}")
endif()

option(ENABLE_EMBEDDED "enable embedded image" OFF)
if (ENABLE_EMBEDDED STREQUAL "ON")
    add_definitions(-DENABLE_EMBEDDED_IMAGE=1)
    set(ENABLE_EMBEDDED_IMAGE 1)
    message("${Green}--  Enable embedded image${ColourReset}")
endif()

option(ENABLE_SELINUX "enable isulad daemon selinux option" ON)
if (ENABLE_SELINUX STREQUAL "ON")
    add_definitions(-DENABLE_SELINUX=1)
    set(ENABLE_SELINUX 1)
    message("${Green}--  Enable selinux${ColourReset}")
endif()

option(ENABLE_SHIM_V2 "enable shim v2 runtime" OFF)
if (ENABLE_SHIM_V2 STREQUAL "ON")
	add_definitions(-DENABLE_SHIM_V2=1)
	set(ENABLE_SHIM_V2 1)
    message("${Green}--  Enable shim v2 runtime${ColourReset}")
endif()

option(EANBLE_IMAGE_LIBARAY "create libisulad_image.so" ON)
if (EANBLE_IMAGE_LIBARAY STREQUAL "ON")
    add_definitions(-DEANBLE_IMAGE_LIBARAY)
    set(EANBLE_IMAGE_LIBARAY 1)
endif()

option(ENABLE_USERNS_REMAP "enable userns remap" OFF)
if (ENABLE_USERNS_REMAP)
    add_definitions(-DENABLE_USERNS_REMAP)
    message("${Green}--  Enable userns remap${ColourReset}")
endif()

option(ENABLE_SUP_GROUPS "enable sup groups" OFF)
if (ENABLE_SUP_GROUPS)
    add_definitions(-DENABLE_SUP_GROUPS)
    message("${Green}--  Enable sup groups${ColourReset}")
endif()

if (NOT RUNPATH)
    set(RUNPATH "/var/run")
endif()
add_definitions(-DRUNPATH="${RUNPATH}")
message("${Green}--  RUNPATH=${RUNPATH}${ColourReset}")

if (NOT SYSCONFDIR_PREFIX)
    set(SYSCONFDIR_PREFIX "")
endif()
add_definitions(-DSYSCONFDIR_PREFIX="${SYSCONFDIR_PREFIX}")
message("${Green}--  SYSCONFDIR_PREFIX=${SYSCONFDIR_PREFIX}${ColourReset}")

message("${BoldGreen}---- Selected options end ----${ColourReset}")
