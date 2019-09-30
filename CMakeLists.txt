cmake_minimum_required (VERSION 3.12.1)
project (lcrd)

include(cmake/helper.cmake)

include(cmake/options.cmake)

include(cmake/set_build_flags.cmake)

#set(CMAKE_C_COMPILER "gcc" CACHE PATH "c compiler")

# Get the latest abbreviated commit hash of the working branch
execute_process(
	COMMAND git rev-parse HEAD
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	OUTPUT_VARIABLE GIT_COMMIT_HASH
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
message("--  commit id: " ${GIT_COMMIT_HASH})
add_definitions(-DLCRD_GIT_COMMIT="${GIT_COMMIT_HASH}")

execute_process(
	COMMAND sh -c "date --rfc-3339 ns | sed -e 's/ /T/'"
	OUTPUT_VARIABLE BUILD_DATE
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
message("-- build time: " ${BUILD_DATE})
add_definitions(-DLCRD_BUILD_TIME="${BUILD_DATE}")

if (NOT LCRD_ROOT_PATH)
add_definitions(-DLCRD_ROOT_PATH="/var/lib/lcrd")
endif()
if (NOT LCRD_STATE_PATH)
add_definitions(-DLCRD_STATE_PATH="/var/run/lcrd")
endif()

if (LIB_INSTALL_DIR)
  set(LIB_INSTALL_DIR_DEFAULT ${LIB_INSTALL_DIR})
else()
  set(LIB_INSTALL_DIR_DEFAULT "lib")
endif()

# check depends library and headers
include(cmake/checker.cmake)
if (CHECKER_RESULT)
    message(FATAL_ERROR "ERROR: Check library and headers failed")
endif()

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
	"${CMAKE_BINARY_DIR}/conf/config.h"
)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/lcrd.pc.in"
	"${CMAKE_BINARY_DIR}/conf/lcrd.pc"
)

if (GRPC_CONNECTOR)
    # parse .proto files
    include(cmake/protoc.cmake)
endif()

# enable embedded image
if (ENABLE_EMBEDDED)
	add_definitions(-DENABLE_EMBEDDED_IMAGE=1)
endif()

# disable oci image
if (NOT DISABLE_OCI)
	add_definitions(-DENABLE_OCI_IMAGE=1)
endif()

# llt and coverage
SET(CMAKE_VERBOSE_MAKEFILE OFF)
OPTION(ENABLE_COVERAGE "coverage switch" OFF)
IF(ENABLE_COVERAGE)
    MESSAGE(STATUS "Enable coverage compile option")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -fprofile-arcs -ftest-coverage")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -fprofile-arcs -ftest-coverage")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -g -fprofile-arcs -ftest-coverage -lgcov")
ENDIF(ENABLE_COVERAGE)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)
OPTION(ENABLE_LLT "llt switch" OFF)
IF(ENABLE_LLT)
    enable_testing()
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/test)
ENDIF(ENABLE_LLT)

# install all files
install(FILES ${CMAKE_BINARY_DIR}/conf/lcrd.pc
  DESTINATION ${LIB_INSTALL_DIR_DEFAULT}/pkgconfig PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/liblcrc.h
	DESTINATION include/lcrd)
install(FILES src/connect/client/lcrc_connect.h
	DESTINATION include/lcrd)
install(FILES src/container_def.h
	DESTINATION include/lcrd)
install(FILES src/types_def.h
	DESTINATION include/lcrd)
install(FILES src/error.h
	DESTINATION include/lcrd)
install(FILES src/engines/engine.h
	DESTINATION include/lcrd)

# install config files
set(conf_prefix "/etc")
if (CMAKE_INSTALL_SYSCONFDIR)
    set(conf_prefix ${CMAKE_INSTALL_SYSCONFDIR})
endif()
install(FILES src/contrib/config/daemon.json
    DESTINATION ${conf_prefix}/isulad PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/contrib/config/config.json
    DESTINATION ${conf_prefix}/default/lcrd PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/contrib/config/seccomp_default.json
    DESTINATION ${conf_prefix}/isulad PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/contrib/config/hooks/default.json
    DESTINATION ${conf_prefix}/default/lcrd/hooks PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/contrib/sysmonitor/isulad-check.sh
    DESTINATION ${conf_prefix}/default/lcrd PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(FILES src/contrib/sysmonitor/isulad-monit
    DESTINATION ${conf_prefix}/sysmonitor/process PERMISSIONS OWNER_READ OWNER_WRITE)
