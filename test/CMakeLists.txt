project(iSulad_UT)

function(gmock_find_library _name)
  find_library(${_name}
    NAMES ${ARGN}
    HINTS
      $ENV{GMOCK_ROOT}
      ${GMOCK_ROOT}
  )
  mark_as_advanced(${_name})
endfunction()

find_path(GMOCK_INCLUDE_DIR gmock/gmock.h
  HINTS
    $ENV{GMOCK_ROOT}/include
    ${GMOCK_ROOT}/include
)
mark_as_advanced(GMOCK_INCLUDE_DIR)

gmock_find_library(GMOCK_LIBRARY            gmock)
gmock_find_library(GMOCK_LIBRARY_DEBUG      gmockd)
gmock_find_library(GMOCK_MAIN_LIBRARY       gmock_main)
gmock_find_library(GMOCK_MAIN_LIBRARY_DEBUG gmock_maind)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GMock DEFAULT_MSG GMOCK_LIBRARY GMOCK_INCLUDE_DIR GMOCK_MAIN_LIBRARY)

if(GMOCK_FOUND)
  set(GMOCK_INCLUDE_DIRS ${GMOCK_INCLUDE_DIR})
  set(GMOCK_BOTH_LIBRARIES ${GMOCK_LIBRARIES} ${GMOCK_MAIN_LIBRARIES})
endif()

# setup testing
find_package(Threads REQUIRED)
find_package(GTest REQUIRED)

include_directories(${GTEST_INCLUDE_DIR})
include_directories(${GMOCK_INCLUDE_DIRS})

IF(ENABLE_UT)
    add_subdirectory(cutils)
    add_subdirectory(image)
    add_subdirectory(cmd)
    add_subdirectory(runtime)
    if (ENABLE_CRI_API_V1 AND ENABLE_GRPC)
      add_subdirectory(sandbox)
    endif()
    add_subdirectory(specs)
    add_subdirectory(services)
    add_subdirectory(network)
    add_subdirectory(volume)
    add_subdirectory(cgroup)
    add_subdirectory(id_name_manager)

ENDIF(ENABLE_UT)

IF(ENABLE_FUZZ)
    add_subdirectory(fuzz)
ENDIF(ENABLE_FUZZ)

IF(ENABLE_COVERAGE)
    add_custom_target(coverage
        COMMAND lcov --directory . --zerocounters --rc lcov_branch_coverage=1
        COMMAND lcov -c -i -d . -o coverage.base --rc lcov_branch_coverage=1

        COMMAND ctest

        COMMAND lcov --directory . --capture --output-file coverage.info --rc lcov_branch_coverage=1
        COMMAND lcov -a coverage.base -a coverage.info --output-file coverage.total --rc lcov_branch_coverage=1
        COMMAND lcov --remove coverage.total '/usr/include/*' --output-file coverage.total --rc lcov_branch_coverage=1
        COMMAND lcov --remove coverage.total ${COVERAGE_EXCLUDES} --output-file ${PROJECT_BINARY_DIR}/coverage.info.cleaned --rc lcov_branch_coverage=1
        COMMAND genhtml -o coverage ${PROJECT_BINARY_DIR}/coverage.info.cleaned --branch-coverage --rc lcov_branch_coverage=1
        COMMAND ${CMAKE_COMMAND} -E remove coverage.base coverage.total ${PROJECT_BINARY_DIR}/coverage.info.cleaned

        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        COMMENT "generating report..."
    )

    add_custom_command(TARGET coverage POST_BUILD
        COMMAND ;
        COMMENT "open .test/coverage/index.html in browser to view the coverage analysis report."
    )
ENDIF(ENABLE_COVERAGE)
