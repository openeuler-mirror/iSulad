# use to check result
macro(_CHECK)
    if (${ARGV0} STREQUAL "${ARGV1}")
        message("ERROR: can not find " ${ARGV2} " program")
        set(CHECKER_RESULT 1)
    else()
        message("--  found " ${ARGV2} " --- works")
    endif()
endmacro()
