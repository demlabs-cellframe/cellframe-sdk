/*
  CRC32C_ADLER -- Computes CRC32C Checksums
  Version 1.2, Date 05/21/18
  Copyright (C) 2013 Mark Adler <madler@alumni.caltech.edu>
  Copyright (C) 2018 Fonic <https://github.com/fonic>

  Provides both a hardware-accelerated algorithm (*) and a software algorithm.
  Note that this computes CRC32C checksums, not CRC32 (without 'C') checksums
  used by Ethernet, gzip, etc.

  (*) CRC instruction on Intel SSE 4.2 processors.  SSE 4.2 was first supported
      by Nehalem processors introduced in November, 2008.

  Version history:
  1.0  10 Feb 2013  First version
  1.1   1 Aug 2013  Correct comments on why three crc instructions in parallel
  1.2  21 May 2018  Add header file, revise hardware support check, eliminate
                    pthreads, restructure code, revise comments and description

  Version 1.1 by Mark Adler was originally published here:
  https://stackoverflow.com/a/17646775

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software.  If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/
#ifndef CRC32C_ADLER_H
#define CRC32C_ADLER_H

/* Compute CRC32C checksum using software algorithm (1). */
uint32_t crc32c_sw(uint32_t crci, const void *buf, size_t len);

/* Compute CRC32C checksum using software algorithm (2). */
uint32_t crc32c_sw2(uint32_t crci, const void *buf, size_t len);

/* Compute CRC32C checksum using hardware algorithm. */
uint32_t crc32c_hw(uint32_t crc, const void *buf, size_t len);

/* Check if hardware-support (i.e. SSE 4.2) is available. */
int crc32c_hw_support();

/* Disable hardware algorithm even if supported by hardware. */
void crc32c_hw_disable();

/* Compute CRC32C checksum. Use hardware algorithm if supported,
   fall back on software algorithm otherwise. */
uint32_t crc32c(uint32_t crc, const void *buf, size_t len);

#endif // CRC32C_ADLER_H
