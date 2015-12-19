/* IMPORTANT NOTE: This is not the original bzip2 distribution.

   This file is copyright (C) 2005 Ralf Hoffmann
   (ralf@boomerangsworld.de)

   The modified software can be distributed under the same licence as
   the original software (see bellow).
*/

/*-------------------------------------------------------------*/
/*--- Library top-level functions.                          ---*/
/*---                                               bzlib.c ---*/
/*-------------------------------------------------------------*/

/*--
  This file is a part of bzip2 and/or libbzip2, a program and
  library for lossless, block-sorting data compression.

  Copyright (C) 1996-2000 Julian R Seward.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. The origin of this software must not be misrepresented; you must 
     not claim that you wrote the original software.  If you use this 
     software in a product, an acknowledgment in the product 
     documentation would be appreciated but is not required.

  3. Altered source versions must be plainly marked as such, and must
     not be misrepresented as being the original software.

  4. The name of the author may not be used to endorse or promote 
     products derived from this software without specific prior written 
     permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Julian Seward, Cambridge, UK.
  jseward@acm.org
  bzip2/libbzip2 version 1.0 of 21 March 2000

  This program is based on (at least) the work of:
     Mike Burrows
     David Wheeler
     Peter Fenwick
     Alistair Moffat
     Radford Neal
     Ian H. Witten
     Robert Sedgewick
     Jon L. Bentley

  For more information on these sources, see the manual.
--*/

#ifndef BZCONF_H
#define BZCONF_H

#define BZ_PREFIX 1

#ifdef BZ_PREFIX
#  define BZ2_blockSort ABZ_BZ2_blockSort
#  define BZ2_hbAssignCodes ABZ_BZ2_hbAssignCodes
#  define BZ2_hbCreateDecodeTables ABZ_BZ2_hbCreateDecodeTables
#  define BZ2_hbMakeCodeLengths ABZ_BZ2_hbMakeCodeLengths
#  define BZ2_bsInitWrite ABZ_BZ2_bsInitWrite
#  define BZ2_compressBlock ABZ_BZ2_compressBlock
#  define BZ2_decompress ABZ_BZ2_decompress
#  define BZ2_bzBuffToBuffCompress ABZ_BZ2_bzBuffToBuffCompress
#  define BZ2_bzBuffToBuffDecompress ABZ_BZ2_bzBuffToBuffDecompress
#  define BZ2_bzCompress ABZ_BZ2_bzCompress
#  define BZ2_bzCompressEnd ABZ_BZ2_bzCompressEnd
#  define BZ2_bzCompressInit ABZ_BZ2_bzCompressInit
#  define BZ2_bzDecompress ABZ_BZ2_bzDecompress
#  define BZ2_bzDecompressEnd ABZ_BZ2_bzDecompressEnd
#  define BZ2_bzDecompressInit ABZ_BZ2_bzDecompressInit
#  define BZ2_bzRestoreBlockEnd ABZ_BZ2_bzRestoreBlockEnd
#  define BZ2_bzSetBlockEndHandler ABZ_BZ2_bzSetBlockEndHandler
#  define BZ2_bzlibVersion ABZ_BZ2_bzlibVersion
#  define BZ2_indexIntoF ABZ_BZ2_indexIntoF
#  define BZ2_crc32Table ABZ_BZ2_crc32Table
#  define BZ2_rNums ABZ_BZ2_rNums
#endif

#endif
