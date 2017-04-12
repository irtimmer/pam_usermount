# Pam_usermount

Pam_usermount is a PAM module for automounting (encrypted) volumes on login.

## Features

* Mount volumes on login
* use user password for unlocking LUKS volumes
* Unmount on logout
* Keep track of the number of active sessions to prevent unnecessary mounting/unmounting

## Usage

Insert the following lines in the /etc/pam.d configuration files to load pam_usermount on login

```
auth      optional  pam_usermount.so
session   optional  pam_usermount.so
```

Edit the /etc/security/pam_usermount.conf file to add and remove volumes to be mounted on login

## Contribute

1. Fork us
2. Write code
3. Send Pull Requests

## Copyright and license
Copyright 2016, 2017 Iwan Timmer. Distributed under the GNU GPL v2 and partly under the GNU LGPL v2.1. For full terms see the LICENSE and LICENSE.LGPL2 file
