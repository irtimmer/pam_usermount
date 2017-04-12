/*
 * This file is part of Pam_usermount.
 *
 * Copyright (C) 2016, 2017 Iwan Timmer
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

#include "config.h"

#include <stdio.h>

PENTRY config_load(const char* filename) {
  FILE* fd = fopen(filename, "r");
  if (fd == NULL) {
    fprintf(stderr, "Can't open configuration file: %s\n", filename);
    return NULL;
  }

  PENTRY map = NULL;
  char *line = NULL;
  size_t len = 0;

  while (getline(&line, &len, fd) != -1) {
    char *key = NULL, *value = NULL;
    if (sscanf(line, "[%m[^]]]", &key) == 1)
      map_put(&map, key, NULL);
    else if (sscanf(line, "%ms = %m[^\n]", &key, &value) == 2) {
      if (map != NULL)
        map_put((PENTRY*) &map->value, key, value);
    }
  }

  fclose(fd);
  return map;
}
