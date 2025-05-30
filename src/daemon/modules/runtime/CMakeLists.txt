# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} runtime_top_srcs)
if (ENABLE_LCR)
add_subdirectory(engines)
endif()
add_subdirectory(isula)
if (ENABLE_SHIM_V2)
    add_subdirectory(shim)
endif()

set(local_runtime_srcs
    ${runtime_top_srcs}
    ${ISULA_SRCS}
    )

if (ENABLE_SHIM_V2)
    list(APPEND local_runtime_srcs ${SHIM_SRCS})
endif()

if (ENABLE_LCR)
    list(APPEND local_runtime_srcs ${ENGINES_SRCS})
endif()

set(local_runtime_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/isula
    )
if (ENABLE_SHIM_V2)
    list(APPEND local_runtime_incs ${CMAKE_CURRENT_SOURCE_DIR}/shim)
endif()
if (ENABLE_LCR)
	list(APPEND local_runtime_incs ${ENGINES_INCS})
endif()


set(RUNTIME_SRCS
    ${local_runtime_srcs}
    PARENT_SCOPE
    )
set(RUNTIME_INCS
    ${local_runtime_incs}
    PARENT_SCOPE
    )
