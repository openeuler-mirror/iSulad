project(iSulad_UT)

if (ENABLE_SANDBOXER)
    add_subdirectory(controller)
    add_subdirectory(sandbox_manager)
    add_subdirectory(sandbox)
endif()
