###########################################################
## TARGETS
###########################################################

add_executable(shm-client client.c)
add_executable(tcp-server tcp-server.c)
add_executable(tcp-client tcp-client.c)
add_executable(shm-server server.c)
add_executable(shm shm.c)

###########################################################
## COMMON
###########################################################

target_link_libraries(shm-client ipc-bench-common)
target_link_libraries(tcp-server ipc-bench-common)
target_link_libraries(tcp-client ipc-bench-common)
target_link_libraries(shm-server ipc-bench-common)
target_link_libraries(shm ipc-bench-common)
