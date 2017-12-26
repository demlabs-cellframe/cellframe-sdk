/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef _ENC_FNAM2_H_
#define _ENC_FNAM2_H_
#include <stddef.h>

struct enc_key;

extern void enc_fnam2_key_new(struct enc_key * key);

extern size_t enc_fnam2_decode(struct enc_key * key, const void * in, size_t in_size,void * out);
extern size_t enc_fnam2_encode(struct enc_key * key,const void * in, size_t in_size,void * out);

#endif
