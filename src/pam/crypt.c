/*
 * This file is part of Pam_usermount.
 *
 * Copyright (C) 2016-2019 Iwan Timmer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <libcryptsetup.h>

#include <stdio.h>
#include <string.h>

int crypt_unlock(const char* path, const char* authtok, const char* name, int flags) {
  int ret = -1;
  struct crypt_device *cd = NULL;
  if ((ret = crypt_init(&cd, path)) < 0)
    fprintf(stderr, "pam_usermount: crypt_init() failed for '%s': %d\n", path, ret);
  else {
    if (crypt_status(cd, name) == CRYPT_ACTIVE)
      fprintf(stderr, "pam_usermount: Device %s is already active\n", name);
    else if ((ret = crypt_load(cd, CRYPT_LUKS, NULL)) >= 0)
      ret = crypt_activate_by_passphrase(cd, name, CRYPT_ANY_SLOT, authtok, strlen(authtok), flags);

    crypt_free(cd);
  }

  return ret;
}

int crypt_lock(const char* name) {
  int ret = -1;
  struct crypt_device *cd = NULL;
  if ((ret = crypt_init_by_name(&cd, name)) < 0)
    fprintf(stderr, "pam_usermount: crypt_init_by_name() failed for '%s': %d\n", name, ret);
  else {
    if (crypt_status(cd, name) != CRYPT_ACTIVE)
      fprintf(stderr, "pam_usermount: Device %s isn't active\n", name);
    else 
      ret = crypt_deactivate(cd, name);

    crypt_free(cd);
  }

  return ret;
}
