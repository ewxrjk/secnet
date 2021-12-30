/*
 * This file is part of secnet.
 * See LICENCE and this file CREDITS for full list of copyright holders.
 * SPDX-License-Identifier: GPL-3.0-or-later
 * There is NO WARRANTY.
 */

#ifndef serpent_h
#define serpent_h

struct keyInstance {
      uint32_t key[8];             /* The key in binary */
      uint32_t subkeys[33][4];	/* Serpent subkeys */
};

/*  Function protoypes  */
void serpent_makekey(struct keyInstance *key, int keyLen,
		     const uint8_t *keyMaterial);
void serpentbe_makekey(struct keyInstance *key, int keyLen,
		     const uint8_t *keyMaterial);

void serpent_encrypt(struct keyInstance *key, const uint8_t plaintext[16],
		     uint8_t ciphertext[16]);
void serpentbe_encrypt(struct keyInstance *key, const uint8_t plaintext[16],
		     uint8_t ciphertext[16]);

void serpent_decrypt(struct keyInstance *key, const uint8_t ciphertext[16],
		     uint8_t plaintext[16]);
void serpentbe_decrypt(struct keyInstance *key, const uint8_t ciphertext[16],
		     uint8_t plaintext[16]);

#endif /* serpent_h */
