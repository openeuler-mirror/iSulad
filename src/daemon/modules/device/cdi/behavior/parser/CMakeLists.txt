# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_cdi_parser_srcs)
set(PARSER_SRCS ${local_cdi_parser_srcs} PARENT_SCOPE)
