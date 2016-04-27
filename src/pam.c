/*
 * This file is part of Pam_mounter.
 *
 * Copyright (C) 2016 Iwan Timmer
 *
 * Pam_mounter is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pam_mounter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Pam_mounter; if not, see <http://www.gnu.org/licenses/>.
 */

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <libmount.h>

#include <stdio.h>

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  //Skip no arguments
  if (argc < 2)
    return PAM_SUCCESS;

  struct libmnt_context *cxt = mnt_new_context();
  if (cxt) {
    mnt_context_set_source(cxt, argv[0]);
    mnt_context_set_target(cxt, argv[1]);
    
    int ret;
    if ((ret = mnt_context_mount(cxt)))
      printf("mount failed: %d, %d\n", ret, mnt_context_get_syscall_errno(cxt));
    else
      printf("succesfully mounted\n");
    
    mnt_free_context(cxt);
  } else
    printf("no context\n");

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  //Skip no arguments
  if (argc < 2)
    return PAM_SUCCESS;

  struct libmnt_context *cxt = mnt_new_context();
  if (cxt) {
    mnt_context_set_source(cxt, argv[0]);
    mnt_context_set_target(cxt, argv[1]);
    
    int ret;
    if ((ret = mnt_context_umount(cxt)))
      printf("umount failed: %d, %d\n", ret, mnt_context_get_syscall_errno(cxt));
    else
      printf("succesfully unmounted\n");

    mnt_free_context(cxt);
  } else
    printf("no context\n");

  return PAM_SUCCESS;
}
