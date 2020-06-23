cmake_minimum_required (VERSION 2.8)
project (isulad)

include(cmake/helper.cmake)

include(cmake/options.cmake)

include(cmake/set_build_flags.cmake)

#set(CMAKE_C_COMPILER "gcc" CACHE PATH "c compiler")

set(GIT_COMMIT_HASH "191411002d5001425aadbc0526eb3545921ee0c5")
message("--  commit id: " ${GIT_COMMIT_HASH})
add_definitions(-DISULAD_GIT_COMMIT="${GIT_COMMIT_HASH}")

execute_process(
	COMMAND sh -c "date --rfc-3339 ns | sed -e 's/ /T/'"
	OUTPUT_VARIABLE BUILD_DATE
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
message("-- build time: " ${BUILD_DATE})
add_definitions(-DISULAD_BUILD_TIME="${BUILD_DATE}")

if (NOT ISULAD_ROOT_PATH)
add_definitions(-DISULAD_ROOT_PATH="/var/lib/isulad")
endif()
if (NOT ISULAD_STATE_PATH)
add_definitions(-DISULAD_STATE_PATH="/var/run/isulad")
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
	"${CMAKE_CURRENT_SOURCE_DIR}/isulad.pc.in"
	"${CMAKE_BINARY_DIR}/conf/isulad.pc"
)

# parse .proto files
include(cmake/protoc.cmake)

# unit test and coverage
SET(CMAKE_VERBOSE_MAKEFILE OFF)
IF(ENABLE_COVERAGE)
    MESSAGE(STATUS "Enable coverage compile option")
    SET(COVERAGE_C_OPTION "${COVERAGE_OPTION} -fprofile-arcs -ftest-coverage -fkeep-inline-functions")
    SET(COVERAGE_CXX_OPTION "${COVERAGE_OPTION} -fprofile-arcs -ftest-coverage")
ENDIF(ENABLE_COVERAGE)

IF(ENABLE_ASAN)
    MESSAGE(STATUS "Enable asan compile option")
    SET(ASAN_OPTIONS "${ASAN_OPTION} -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer")
ENDIF(ENABLE_ASAN)

IF(CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${COVERAGE_C_OPTION} ${ASAN_OPTIONS}")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COVERAGE_CXX_OPTION} ${ASAN_OPTIONS}")
ENDIF()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)
OPTION(ENABLE_UT "ut switch" OFF)
IF(ENABLE_UT)
    enable_testing()
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/test)
ENDIF(ENABLE_UT)

# install all files
install(FILES ${CMAKE_BINARY_DIR}/conf/isulad.pc
  DESTINATION ${LIB_INSTALL_DIR_DEFAULT}/pkgconfig PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/client/libisula.h
	DESTINATION include/isulad)
install(FILES src/client/connect/isula_connect.h
	DESTINATION include/isulad)
install(FILES src/cutils/utils_timestamp.h
	DESTINATION include/isulad)
install(FILES src/cutils/error.h
	DESTINATION include/isulad)
install(FILES src/daemon/runtime/engines/engine.h
	DESTINATION include/isulad)

# install config files
set(conf_prefix "/etc")
if (CMAKE_INSTALL_SYSCONFDIR)
    set(conf_prefix ${CMAKE_INSTALL_SYSCONFDIR})
endif()
install(FILES src/contrib/config/daemon.json
    DESTINATION ${conf_prefix}/isulad PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/contrib/config/config.json src/contrib/config/systemcontainer_config.json
    DESTINATION ${conf_prefix}/default/isulad PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/contrib/config/seccomp_default.json
    DESTINATION ${conf_prefix}/isulad PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/contrib/config/hooks/default.json
    DESTINATION ${conf_prefix}/default/isulad/hooks PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/contrib/sysmonitor/isulad-check.sh
    DESTINATION ${conf_prefix}/default/isulad PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(FILES src/contrib/sysmonitor/isulad-monit
    DESTINATION ${conf_prefix}/sysmonitor/process PERMISSIONS OWNER_READ OWNER_WRITE)
