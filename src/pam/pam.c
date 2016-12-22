/*
 * This file is part of Pam_usermount.
 *
 * Copyright (C) 2016 Iwan Timmer
 *
 * Pam_usermount is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pam_usermount is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Pam_usermount; if not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include "mounter.h"
#include "crypt.h"

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <libcryptsetup.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>

#define CONFIGFILE "/etc/security/pam_usermount.conf"
#define PMCOUNT_CMD "pmcount"

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

static int get_count(const char* user, int amount) {
  char* cmd = malloc(strlen(PMCOUNT_CMD) + 1 + strlen(user) + 1 + 2 + 1);
  if (cmd == NULL)
    return -1;

  sprintf(cmd, PMCOUNT_CMD " %s %d", user, amount);
  FILE *fp = popen(cmd, "r");
  free(cmd);

  int count = -1;
  if (fp != NULL) {
    fscanf(fp, "%d", &count);
    fclose(fp);
  }
  return count;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
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
      fprintf(stderr, "pam_usermount: Failed to set password");
  }

  if (authtok != NULL) {
    if ((ret = pam_set_data(pamh, "pam_usermount_authtok", authtok, clean_authtok)) == PAM_SUCCESS) {
      if (mlock(authtok, strlen(authtok) + 1) < 0)
        fprintf(stderr, "pam_usermount: Failed to memory lock authtok: %s\n", strerror(errno));
    }
  }

  return PAM_SUCCESS;
}

static void pam_open_mount(PENTRY config, const char* user, const char* authtok) {
  char* device_name_path = NULL;
  char* device_name = NULL;

  const char* source = map_get(&config, "source", NULL);
  const char* target = map_get(&config, "target", NULL);

  int ret;
  if (strcmp(map_get(&config, "helper", ""), "crypt") == 0) {
    device_name = encode_device_name(source);
    if (device_name == NULL) {
        fprintf(stderr, "pam_usermount: Not enough memory\n");
        goto cleanup;
    }

    int flags = strcmp(map_get(&config, "discard", ""), "true") ? CRYPT_ACTIVATE_ALLOW_DISCARDS : 0;
    if ((ret = crypt_unlock(source, authtok, device_name, flags)) < 0) {
        fprintf(stderr, "pam_usermount: Device %s activation failed: %d\n", device_name, ret);
        goto cleanup;
    }

    device_name_path = malloc(strlen(crypt_get_dir()) + 1 + strlen(device_name) + 1);
    if (device_name_path == NULL) {
        fprintf(stderr, "pam_usermount: Not enough memory\n");
        goto cleanup;
    }
    sprintf(device_name_path, "%s/%s", crypt_get_dir(), device_name);
    source = device_name_path;
  }

  struct passwd *pent;
  if ((pent = getpwnam(user)) == NULL) {
    fprintf(stderr, "pam_usermount: Can't get info for user '%s'\n", user);
    goto cleanup;
  }

  char* last = target;
  do {
    last = strchr(last + 1, '/');
    if (last != NULL)
      *last = '\0';

    struct stat info;
    if (stat(target, &info) == 0)
      goto created;

    if (setegid(pent->pw_gid) < 0 || seteuid(pent->pw_uid) < 0) {
      fprintf(stderr, "pam_usermount: Failed to set gid and uid\n", user);
    } else if (mkdir(target, S_IRWXU | S_IXUSR | S_IXGRP | S_IXOTH) != 0) {
      //Retry as root
      if (seteuid(0) < 0) {
        fprintf(stderr, "pam_usermount: Failed to create target directory as root\n");
        goto cleanup;
      }

      if (mkdir(target, S_IRWXU | S_IXUSR | S_IXGRP | S_IXOTH) < 0) {
        fprintf(stderr, "pam_usermount: Failed to create target directory '%s'\n", target);
        goto cleanup;
      }

      chown(target, pent->pw_uid, pent->pw_gid);
    }
    
    created:
    if (last != NULL)
      *last = '/';
  } while (last != NULL);

  if ((ret = mounter_mount(source, target, map_get(&config, "fstype", "auto"), map_get(&config, "options", "defaults"))))
    fprintf(stderr, "pam_usermount: Mount failed for '%s' on '%s': %s\n", source, target, strerror(errno));

  cleanup:
  if (device_name != NULL)
    free(device_name);

  if (device_name_path != NULL)
    free(device_name_path);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const char* user;
  if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
    fprintf(stderr, "pam_usermount: Can't get username\n");
    return PAM_SUCCESS;
  }

  int ret;
  const char *authtok = NULL;
  if ((ret = pam_get_data(pamh, "pam_usermount_authtok", (const void**) &authtok)) != PAM_SUCCESS) {
    fprintf(stderr, "pam_usermount: Can't get auth token\n");
    return PAM_SUCCESS;
  }

  if (get_count(user, 1) > 1)
    return PAM_SUCCESS;

  PENTRY config = config_load(CONFIGFILE);
  while (config != NULL) {
    PENTRY section = (PENTRY) config->value;
    if (strcmp(config->key, "mount") == 0 && strcmp(map_get(&section, "user", user), user) == 0)
      pam_open_mount(section, user, authtok);

    config = config->next;
  }

  return PAM_SUCCESS;
}

static void pam_close_mount(PENTRY config) {
  char* device_name = NULL;
  char* device_name_path = NULL;

  const char* source = map_get(&config, "source", NULL);
  const char* target = map_get(&config, "target", NULL);
  
  if (strcmp(map_get(&config, "helper", ""), "crypt") == 0) {
    device_name = encode_device_name(source);
    if (device_name == NULL) {
        fprintf(stderr, "pam_usermount: Not enough memory\n");
        goto cleanup;
    }

    device_name_path = malloc(strlen(crypt_get_dir()) + 1 + strlen(device_name) + 1);
    if (device_name_path == NULL) {
        fprintf(stderr, "pam_usermount: Not enough memory\n");
        goto cleanup;
    }
    sprintf(device_name_path, "%s/%s", crypt_get_dir(), device_name);
    source = device_name_path;
  }

  int ret;
  if ((ret = mounter_umount(source, target))) {
    fprintf(stderr, "pam_usermount: Mount failed for '%s' on '%s': %s\n", source, target, strerror(errno));
    goto cleanup;
  }

  if (device_name != NULL && (ret = crypt_lock(device_name) < 0))
    fprintf(stderr, "pam_usermount: Device %s deactivation failed: %d\n", device_name, ret);

  cleanup:
  if (device_name_path != NULL)
    free(device_name_path);

  if (device_name != NULL)
    free(device_name);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const char* user;
  if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
    fprintf(stderr, "pam_usermount: Can't get username\n");
    return PAM_SUCCESS;
  }

  if (get_count(user, -1) > 0)
    return PAM_SUCCESS;

  PENTRY config = config_load(CONFIGFILE);
  while (config != NULL) {
    PENTRY section = (PENTRY) config->value;
    if (strcmp(config->key, "mount") == 0 && strcmp(map_get(&section, "user", user), user) == 0)
      pam_close_mount(section);

    config = config->next;
  }

  return PAM_SUCCESS;
}
