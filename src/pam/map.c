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

#include "map.h"

#include <malloc.h>
#include <string.h>

void map_put(PENTRY* map, const char* key, const void* value) {
  PENTRY entry = malloc(sizeof(ENTRY));
  entry->value = value;
  entry->key = key;
  entry->next = *map;
  *map = entry;
}

const void* map_get(PENTRY* map, const char* key, const void* ret) {
  PENTRY entry = *map;
  while (entry != NULL) {
    if (strcmp(key, entry->key) == 0)
      return entry->value;

    entry = entry->next;
  }
  return ret;
}
