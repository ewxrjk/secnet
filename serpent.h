#ifndef serpent_h
#define serpent_h

struct keyInstance {
      uint32_t key[8];             /* The key in binary */
      uint32_t subkeys[33][4];	/* Serpent subkeys */
};

/*  Function protoypes  */
void serpent_makekey(struct keyInstance *key, int keyLen,
		     const uint8_t *keyMaterial);

void serpent_encrypt(struct keyInstance *key, const uint8_t plaintext[16],
		     uint8_t ciphertext[16]);

void serpent_decrypt(struct keyInstance *key, const uint8_t ciphertext[16],
		     uint8_t plaintext[16]);

#endif /* serpent_h */
