#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h> // Include RSA library from OpenSSL
#include <openssl/pem.h>

#define KEY_LENGTH  2048 // Define key length
#define PUB_EXP     3 // Define public exponent
#define BLOCK_SIZE  245 // Define block size for encryption/decryption

// Encrypt a file using RSA
int encrypt_file(const char* input_filename, const char* output_filename, RSA* key) {
    FILE* input_file = fopen(input_filename, "rb"); // Open input file for reading in binary mode
    if (input_file == NULL) {
        printf("Failed to open input file %s\n", input_filename);
        return -1;
    }

    FILE* output_file = fopen(output_filename, "wb"); // Open output file for writing in binary mode
    if (output_file == NULL) {
        printf("Failed to open output file %s\n", output_filename);
        fclose(input_file); // Close input file if failed to open output file
        return -1;
    }

    unsigned char input_block[BLOCK_SIZE];
    unsigned char output_block[KEY_LENGTH / 8];

    int bytes_read = 0;
    while ((bytes_read = fread(input_block, 1, BLOCK_SIZE, input_file)) > 0) { // Read input file in block size
        int encrypted_size = RSA_public_encrypt(bytes_read, input_block, output_block, key, RSA_PKCS1_PADDING); // Encrypt input block using RSA public key
        if (encrypted_size == -1) {
            printf("Failed to encrypt input block\n");
            fclose(input_file); // Close input file if failed to encrypt input block
            fclose(output_file); // Close output file if failed to encrypt input block
            return -1;
        }

        fwrite(output_block, 1, encrypted_size, output_file); // Write encrypted block to output file
    }

    fclose(input_file);
    fclose(output_file);

    return 0;

// Decrypt a file using RSA
int decrypt_file(const char* input_filename, const char* output_filename, RSA* key) {
    FILE* input_file = fopen(input_filename, "rb");
    if (input_file == NULL) {
        printf("Failed to open input file %s\n", input_filename);
        return -1;
    }

    FILE* output_file = fopen(output_filename, "wb");
    if (output_file == NULL) {
        printf("Failed to open output file %s\n", output_filename);
        fclose(input_file);
        return -1;
    }

    unsigned char input_block[KEY_LENGTH / 8];
    unsigned char output_block[BLOCK_SIZE];

    int bytes_read = 0;
    while ((bytes_read = fread(input_block, 1, KEY_LENGTH / 8, input_file)) > 0) {
        int decrypted_size = RSA_private_decrypt(bytes_read, input_block, output_block, key, RSA_PKCS1_PADDING);
        if (decrypted_size == -1) {
            printf("Failed to decrypt input block\n");
            fclose(input_file);
            fclose(output_file);
            return -1;
        }

        fwrite(output_block, 1, decrypted_size, output_file);
    }

    fclose(input_file);
    fclose(output_file);

    return 0;
}
