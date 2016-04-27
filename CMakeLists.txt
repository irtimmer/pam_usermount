project(pam_mounter C)
cmake_minimum_required(VERSION 3.1)
SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)

find_package(PAM REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(MOUNT mount)

aux_source_directory(./src SRC_LIST)
add_library(pam_mounter SHARED ${SRC_LIST})
set_target_properties (pam_mounter PROPERTIES PREFIX "")
target_include_directories(pam_mounter PRIVATE ${PAM_INCLUDE_DIR} ${MOUNT_INCLUDE_DIRS})
target_link_libraries(pam_mounter ${PAM_LIBRARY} ${MOUNT_LIBRARIES})

install(TARGETS pam_mounter DESTINATION ${CMAKE_INSTALL_LIBDIR}/security)
