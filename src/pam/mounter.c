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

#include <libmount.h>

#include <stdio.h>

static struct libmnt_context* mounter_create_context(const char* source, const char* target) {
  struct libmnt_context *cxt = mnt_new_context();
  if (cxt) {
    mnt_context_set_source(cxt, source);
    mnt_context_set_target(cxt, target);
  }
  return cxt;
}

int mounter_mount(const char* source, const char* target, const char* fstype, const char* options) {
    int ret = 0;
    struct libmnt_context *cxt = mounter_create_context(source, target);
    mnt_context_set_fstype(cxt, fstype);
    mnt_context_set_options(cxt, options);
    if (cxt != NULL) {
      ret = mnt_context_mount(cxt);
      mnt_free_context(cxt);
    }
    return ret;
}

int mounter_umount(const char* source, const char* target) {
    int ret = 0;
    struct libmnt_context *cxt = mounter_create_context(source, target);
    if (cxt != NULL) {
      ret = mnt_context_umount(cxt);
      mnt_free_context(cxt);
    }
    return ret;
}
