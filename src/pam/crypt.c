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

#include <libcryptsetup.h>

#include <stdio.h>
#include <string.h>

static struct crypt_device* crypt_create_context(const char* path) {
  struct crypt_device *cd = NULL;
  int ret;
  if ((ret = crypt_init(&cd, path)) < 0)
    printf("crypt_init() failed for %s.\n", path);

  return cd;
}

int crypt_unlock(const char* path, const char* authtok, const char* name) {
  int ret = -1;
  struct crypt_device *cd = crypt_create_context(path);
  if (cd) {
    if ((ret = crypt_load(cd, CRYPT_LUKS1, NULL)) < 0)
      printf("crypt_load() failed on device %s.\n", crypt_get_device_name(cd));
    else
      ret = crypt_activate_by_passphrase(cd, name, CRYPT_ANY_SLOT, authtok, strlen(authtok), 0);

    crypt_free(cd);
  }

  return ret;
}

int crypt_lock(const char* path, const char* name) {
  int ret = -1;
  struct crypt_device *cd = crypt_create_context(path);
  if (cd) {
    if (crypt_status(cd, name) != CRYPT_ACTIVE)
      printf("Something failed perhaps, device %s is not active.\n", name);
    else 
      ret = crypt_deactivate(cd, name);

    crypt_free(cd);
  }

  return ret;
}
