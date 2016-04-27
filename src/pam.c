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

#include "config.h"

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <libmount.h>
#include <libcryptsetup.h>

#include <sys/mman.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define CONFIGFILE "/etc/security/pam_mounter.conf"

static char* encode_device_name(const char* device) {
  char* device_name = strdup(device);
  if (device_name == NULL) {
    return NULL;
  }

  for (char* c = device_name; *c != '\0'; ++c) {
    if (!isalpha(*c) && !isdigit(*c))
      *c = '_';
  }

  return device_name;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

static void clean_authtok(pam_handle_t *pamh, void *data, int errcode) {
  if (data != NULL) {
    unsigned int len = strlen(data) + 1;
    memset(data, 0, len);
    munlock(data, len);
    free(data);
  }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const char *ptr = NULL;
  char* authtok;
  int ret;
  if ((ret = pam_get_item(pamh, PAM_AUTHTOK, (const void**) &ptr)) == PAM_SUCCESS && ptr != NULL)
    authtok = strdup(ptr);
  else {
    pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &authtok, "Password: ");
    if ((ret = pam_set_item(pamh, PAM_AUTHTOK, authtok)) != PAM_SUCCESS)
      printf("Failed to set password");
  }

  if (authtok != NULL) {
    if ((ret = pam_set_data(pamh, "pam_mounter_authtok", authtok, clean_authtok)) == PAM_SUCCESS) {
      if (mlock(authtok, strlen(authtok) + 1) < 0)
        printf("mlock authtok: %s\n", strerror(errno));
    }
  }

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  int r;
  const char *authtok = NULL;
  if ((r = pam_get_data(pamh, "pam_mounter_authtok", (const void**) &authtok)) != PAM_SUCCESS)
    return PAM_SUCCESS;

  PENTRY config = config_load(CONFIGFILE);
  const char* source = map_get(&config, "source", NULL);
  const char* target = map_get(&config, "target", NULL);

  struct crypt_device *cd;
  if ((r = crypt_init(&cd, source)) < 0) {
    printf("crypt_init() failed for %s.\n", source);
    return PAM_SUCCESS;
  }

  if ((r = crypt_load(cd, CRYPT_LUKS1, NULL)) < 0) {
    printf("crypt_load() failed on device %s.\n", crypt_get_device_name(cd));
    crypt_free(cd);
    return PAM_SUCCESS;
  }

  char* device_name = encode_device_name(source);
  if (device_name == NULL) {
    crypt_free(cd);
    return PAM_SUCCESS;
  }

  if ((r = crypt_activate_by_passphrase(cd, device_name, CRYPT_ANY_SLOT, authtok, strlen(authtok), 0)) < 0) {
    printf("Device %s activation failed.\n", device_name);
    crypt_free(cd);
    free(device_name);
    return PAM_SUCCESS;
  };

  char* device_name_path = malloc(strlen(crypt_get_dir()) + 1 + strlen(device_name) + 1);
  sprintf(device_name_path, "%s/%s", crypt_get_dir(), device_name);
  crypt_free(cd);

  struct libmnt_context *cxt = mnt_new_context();
  if (cxt) {
    mnt_context_set_source(cxt, device_name_path);
    mnt_context_set_target(cxt, target);
    
    int ret;
    if ((ret = mnt_context_mount(cxt)))
      printf("mount failed: %d, %d\n", ret, mnt_context_get_syscall_errno(cxt));
    else
      printf("succesfully mounted\n");
    
    mnt_free_context(cxt);
  } else
    printf("no context\n");

  free(device_name);
  free(device_name_path);
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  PENTRY config = config_load(CONFIGFILE);
  const char* source = map_get(&config, "source", NULL);
  const char* target = map_get(&config, "target", NULL);
  
  char* device_name = encode_device_name(source);
  if (device_name == NULL) {
    return PAM_SUCCESS;
  }

  char* device_name_path = malloc(strlen(crypt_get_dir()) + 1 + strlen(device_name) + 1);
  if (device_name == NULL) {
    free(device_name);
    return PAM_SUCCESS;
  }
  sprintf(device_name_path, "%s/%s", crypt_get_dir(), device_name);

  struct libmnt_context *cxt = mnt_new_context();
  if (cxt) {
    mnt_context_set_source(cxt, device_name_path);
    mnt_context_set_target(cxt, target);
    
    int ret;
    if ((ret = mnt_context_umount(cxt)))
      printf("umount failed: %d, %d\n", ret, mnt_context_get_syscall_errno(cxt));
    else
      printf("succesfully unmounted\n");

    mnt_free_context(cxt);
  } else
    printf("no context\n");

  struct crypt_device *cd;
  int r;

  if ((r = crypt_init_by_name(&cd, device_name)) >= 0) {
    if (crypt_status(cd, device_name) != CRYPT_ACTIVE) {
      printf("Something failed perhaps, device %s is not active.\n", device_name);
      free(device_name_path);
      free(device_name);
      crypt_free(cd);
      return PAM_SUCCESS;
    }
    if ((r = crypt_deactivate(cd, device_name)) < 0) {
      printf("crypt_deactivate() failed.\n");
      free(device_name_path);
      free(device_name);
      crypt_free(cd);
      return PAM_SUCCESS;
    }
    printf("Device %s is now deactivated.\n", device_name);
    crypt_free(cd);
  } else
    printf("crypt_init_by_name() failed for %s.\n", device_name);

  free(device_name_path);
  free(device_name);
  return PAM_SUCCESS;
}
