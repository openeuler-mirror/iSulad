project(iSulad_UT)

if (ENABLE_CRI_API_V1)
    add_subdirectory(controller)
    add_subdirectory(sandbox_manager)
    add_subdirectory(sandbox)
endif()
