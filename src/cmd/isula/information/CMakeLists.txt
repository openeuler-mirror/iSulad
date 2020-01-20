# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_information_srcs)

set(ISULA_INFORMATION_SRCS
    ${isula_information_srcs}
    PARENT_SCOPE
    )
