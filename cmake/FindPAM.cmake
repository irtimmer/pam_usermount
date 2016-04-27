# - Try to find the PAM libraries
# Once done this will define
#
#  PAM_FOUND - system has pam
#  PAM_INCLUDE_DIR - the pam include directory
#  PAM_LIBRARIES - libpam library
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products 
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

if (PAM_INCLUDE_DIR AND PAM_LIBRARY)
	# Already in cache, be silent
	set(PAM_FIND_QUIETLY TRUE)
endif (PAM_INCLUDE_DIR AND PAM_LIBRARY)

find_path(PAM_INCLUDE_DIR NAMES security/pam_appl.h pam/pam_appl.h)
find_library(PAM_LIBRARY pam)
find_library(DL_LIBRARY dl)

if (PAM_INCLUDE_DIR AND PAM_LIBRARY)
	set(PAM_FOUND TRUE)
	if (DL_LIBRARY)
		set(PAM_LIBRARIES ${PAM_LIBRARY} ${DL_LIBRARY})
	else (DL_LIBRARY)
		set(PAM_LIBRARIES ${PAM_LIBRARY})
	endif (DL_LIBRARY)
endif (PAM_INCLUDE_DIR AND PAM_LIBRARY)

if (PAM_FOUND)
	if (NOT PAM_FIND_QUIETLY)
		message(STATUS "Found PAM: ${PAM_LIBRARIES}")
	endif (NOT PAM_FIND_QUIETLY)
else (PAM_FOUND)
	if (PAM_FIND_REQUIRED)
		message(FATAL_ERROR "PAM was not found")
	endif(PAM_FIND_REQUIRED)
endif (PAM_FOUND)

mark_as_advanced(PAM_INCLUDE_DIR PAM_LIBRARY DL_LIBRARY)
