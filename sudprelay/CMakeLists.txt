## CMakeList.txt : CMake project for sudprelay, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

configure_file(../config/sudprelay_config.h.in ${PROJECT_SOURCE_DIR}/sudprelay/sudprelay_config.h NEWLINE_STYLE WIN32)

add_executable ("${PROJECT_NAME}" "sudprelay.c" "winerr.h" "show_dump.h" "ip2.h" "acpdump2.h" "sys_time.h" "sys_time.c" "sudprelay.h")

target_link_libraries("${PROJECT_NAME}" ${CMAKE_DL_LIBS})	# for dlopen, dlclose, dlsym

target_include_directories("${PROJECT_NAME}" PUBLIC "${PROJECT_BINARY_DIR}")


# TODO: Add tests and install targets if needed.
install(TARGETS "${PROJECT_NAME}" DESTINATION bin)    #${CMAKE_INSTALL_PREFIX}/bin 