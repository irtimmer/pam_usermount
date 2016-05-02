/*
 * This file is part of Pam_mounter.
 *
 * Copyright (C) 2016 Iwan Timmer
 * 
 * This work is based upon pmvarrun of the pam_mount project
 * 
 * Copyright Bastian Kleineidam <calvin [at] debian org>, 2005
 * Copyright W. Michael Petullo <mike@flyn.org>, 2004
 * Copyright Jan Engelhardt, 2005-2011
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

#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>

#define VAR_RUN_PMCOUNT "/run/pmcount"

static void help() {
  fprintf(stderr, "Usage: pmcount USER [AMOUNT]\n");
}

static bool create_dir() {
  struct stat sb;
  if (stat(VAR_RUN_PMCOUNT, &sb) < 0) {
    if (errno == ENOENT) {
      if (mkdir(VAR_RUN_PMCOUNT, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
        return false;
      if (chown(VAR_RUN_PMCOUNT, 0, 0) < 0)
        return false;
      if (chmod(VAR_RUN_PMCOUNT, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
        return false;
    } else
      return false;
  }

  return true;
}

static int open_and_lock(const char *filename, long uid) {
  int fd;
  if ((fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) < 0)
    return -errno;

  if (fchown(fd, uid, -1) < 0)
    return -errno;

  /*
   * Note: Waiting too long might interfere with LOGIN_TIMEOUT from
   * /etc/login.defs, and /bin/login itself may prematurely kill the
   * /session.
   */
  alarm(10);
  struct flock lockinfo = {
    .l_type = F_WRLCK,
    .l_whence = SEEK_SET,
    .l_start = 0,
    .l_len = 0,
  };
  int ret = fcntl(fd, F_SETLKW, &lockinfo);
  alarm(0);
  if (ret == EAGAIN) {
    //Return ESTALE if lock can't be acquired
    close(fd);
    return -ESTALE;
  }

  /*
   * It is possible at this point that the file has been removed by a
   * previous login; if this happens, we need to start over.
   */
  struct stat sb;
  if (stat(filename, &sb) < 0) {
    ret = -errno;
    close(fd);
    if (ret == -ENOENT)
      return -EAGAIN;

    return ret;
  }

  return fd;
}

static long read_count(int fd, const char *filename) {
  char buf[10] = {};
  long ret;

  if ((ret = read(fd, buf, sizeof(buf))) < 0)
    return -errno;
  else if (ret == 0)
    ret = 0;
  else if (ret < sizeof(buf)) {
    char *end;
    if ((ret = strtol(buf, &end, 0)) >= LONG_MAX || end == buf)
      return -EOVERFLOW;
  } else if (ret >= sizeof(buf))
    return -EOVERFLOW;

  return ret;
}

static int write_count(int fd, const char *filename, long count) {
  if (count <= 0) {
    if (unlink(filename) >= 0)
      return true;

    // Fallback to just blanking the file.
    if (ftruncate(fd, 0) < 0)
      return -errno;
    
    return true;
  }

  int ret;
  if ((ret = lseek(fd, 0, SEEK_SET)) != 0)
    return -errno;

  char buf[10];
  int len = snprintf(buf, sizeof(buf), "0x%lX", count);
  if (write(fd, buf, len) != len)
    return -errno;
  
  if (ftruncate(fd, len) < 0)
    return -errno;

  return true;
}

int main(int argc, const char **argv) {
  if (argc != 3 && argc != 2) {
    help();
    return EXIT_FAILURE;
  }

  char *end = "\0";
  long amount = argc == 3 ? strtol(argv[2], &end, 0) : 0;
  const char* user = argv[1];

  if (*end != '\0') {
    help();
    return EXIT_FAILURE;
  }
  
  if (!create_dir())
    return EXIT_FAILURE;

  struct passwd *pent;
  if ((pent = getpwnam(user)) == NULL) {
    fprintf(stderr, "Can't get info for user '%s'\n", user);
    return EXIT_FAILURE;
  }

  char filename[PATH_MAX + 1];
  snprintf(filename, sizeof(filename), VAR_RUN_PMCOUNT "/%s", user);

  int fd;
  while ((fd = open_and_lock(filename, pent->pw_uid)) == -EAGAIN);
  if (fd < 0) {
    fprintf(stderr, "Can't open and lock file '%s': %s\n", filename, strerror(-fd));
    return EXIT_FAILURE;
  }

  int val;
  if ((val = read_count(fd, filename)) < 0) {
    fprintf(stderr, "Can't read count from file '%s': %s\n", filename, strerror(-val));
    close(fd);
    return EXIT_FAILURE;
  }

  int ret = 1;
  if (amount != 0) {
    if ((ret = write_count(fd, filename, val + amount)) < 0)
      fprintf(stderr, "Can't write count to file '%s': %s\n", filename, strerror(-val));
  }

  close(fd);
  if (ret < 0)
    return EXIT_FAILURE;

  printf("%ld\n", val + amount);
  return EXIT_SUCCESS;
}
