# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_information_srcs)

if(NOT ENABLE_NATIVE_NETWORK)
    list(REMOVE_ITEM isula_information_srcs "${CMAKE_CURRENT_SOURCE_DIR}/port.c")
endif()

set(ISULA_INFORMATION_SRCS
    ${isula_information_srcs}
    PARENT_SCOPE
    )
