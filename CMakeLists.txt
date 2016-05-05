project(pam_usermount C)
cmake_minimum_required(VERSION 3.1)
SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)

find_package(PAM REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(MOUNT mount)
pkg_check_modules(CRYPTSETUP libcryptsetup)

aux_source_directory(./src/pam PAM_SRC_LIST)
add_library(pam_usermount SHARED ${PAM_SRC_LIST})
set_target_properties (pam_usermount PROPERTIES PREFIX "")
target_include_directories(pam_usermount PRIVATE ${PAM_INCLUDE_DIR} ${MOUNT_INCLUDE_DIRS} ${CRYPTSETUP_INCLUDE_DIRS})
target_link_libraries(pam_usermount ${PAM_LIBRARY} ${MOUNT_LIBRARIES} ${CRYPTSETUP_LIBRARIES})

aux_source_directory(./src/pmcount PMCOUNT_SRC_LIST)
add_executable(pmcount ${PMCOUNT_SRC_LIST})

install(TARGETS pam_usermount DESTINATION ${CMAKE_INSTALL_LIBDIR}/security)
install(TARGETS pmcount DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES pam_usermount.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/security)
