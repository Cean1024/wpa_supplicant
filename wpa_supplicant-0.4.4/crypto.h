/*
 * WPA Supplicant / wrapper functions for libcrypto
 * Copyright (c) 2004-2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

void md4_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac);
void md4(const u8 *addr, size_t len, u8 *mac);
void des_encrypt(const u8 *clear, const u8 *key, u8 *cypher);

#endif /* CRYPTO_H */
