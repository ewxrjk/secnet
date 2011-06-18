#ifndef serpent_h
#define serpent_h

struct keyInstance {
      uint32_t key[8];             /* The key in binary */
      uint32_t subkeys[33][4];	/* Serpent subkeys */
};

/*  Function protoypes  */
void serpent_makekey(struct keyInstance *key, int keyLen,
		     uint8_t *keyMaterial);

void serpent_encrypt(struct keyInstance *key, uint32_t plaintext[4],
		     uint32_t ciphertext[4]);

void serpent_decrypt(struct keyInstance *key, uint32_t ciphertext[4],
		     uint32_t plaintext[4]);

#endif /* serpent_h */
