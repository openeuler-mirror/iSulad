project(iSulad_UT)

add_subdirectory(lcr)
add_subdirectory(isula)
if (ENABLE_SHIM_V2)
    add_subdirectory(shim)
endif()
