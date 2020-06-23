# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_manager_srcs)
add_subdirectory(restore)
add_subdirectory(supervisor)
add_subdirectory(health_check)
add_subdirectory(container_gc)
add_subdirectory(restart_manager)

set(MANAGER_SRCS
	${local_manager_srcs}
	${RESTORE_SRCS}
	${SUPERVISOR_SRCS}
	${HEALTH_CHECK_SRCS}
	${GC_SRCS}
	${RESTART_MANAGER_SRCS}
	PARENT_SCOPE
	)

set(MANAGER_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	${RESTORE_INCS}
	${SUPERVISOR_INCS}
	${HEALTH_CHECK_INCS}
	${GC_INCS}
	${RESTART_MANAGER_INCS}
	PARENT_SCOPE
	)
