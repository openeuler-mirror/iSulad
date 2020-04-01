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

# add_subdirectory(cutils)
add_subdirectory(image)
# add_subdirectory(path)
# add_subdirectory(cmd)
# add_subdirectory(runtime)
# add_subdirectory(specs)
# add_subdirectory(services)
