# get current directory sources files

set(MODULES_API_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
set(MODULES_API_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )

if (NOT ENABLE_PLUGIN)
    list(REMOVE_ITEM MODULES_API_INCS "${CMAKE_CURRENT_SOURCE_DIR}/plugin_api.h")
endif()
