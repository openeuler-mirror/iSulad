project(iSulad_UT)

aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/sandbox/types grpc_sandbox_type_srcs)
list(APPEND grpc_sandbox_type_srcs ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/sandbox.pb.cc)
list(APPEND grpc_sandbox_type_srcs ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/v1/api_v1.pb.cc)
list(APPEND grpc_sandbox_type_srcs ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/gogo.pb.cc)
add_subdirectory(sandboxer)
add_subdirectory(manager)
