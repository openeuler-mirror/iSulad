set(cmdpath python3)
set(pysrcpath ${CMAKE_CURRENT_SOURCE_DIR}/src/generate.py)
set(schemapath ${CMAKE_CURRENT_SOURCE_DIR}/schema)
set(outputpath ${CMAKE_BINARY_DIR}/json)

message("--  Generate .c and .h file into: " ${outputpath})
add_subdirectory(src)

execute_process(COMMAND ${cmdpath} ${pysrcpath} --gen-common --gen-ref -r --root=${schemapath} --out=${outputpath} ${schemapath}
    ERROR_VARIABLE err
    )

if (err)
    message(FATAL_ERROR "ERROR: " ${err})
endif()
