# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} lcrc_information_srcs)

set(LCRC_INFORMATION_SRCS
    ${lcrc_information_srcs}
    PARENT_SCOPE
    )
