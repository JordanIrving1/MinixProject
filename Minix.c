#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <pthread.h> // Include pthread library for multi-threading

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define BLOCK_SIZE  245

struct file_data {
    const char* input_filename;
    const char* output_filename;
    RSA* key;
};

// Thread function to encrypt a file
void* encrypt_file_thread(void* arg) {
    struct file_data* data = (struct file_data*)arg;
    const char* input_filename = data->input_filename;
    const char* output_filename = data->output_filename;
    RSA* key = data->key;

    FILE* input_file = fopen(input_filename, "rb");
    if (input_file == NULL) {
        printf("Failed to open input file %s\n", input_filename);
        return NULL;
    }

    FILE* output_file = fopen(output_filename, "wb");
    if (output_file == NULL) {
        printf("Failed to open output file %s\n", output_filename);
        fclose(input_file);
        return NULL;
    }

    unsigned char input_block[BLOCK_SIZE];
    unsigned char output_block[KEY_LENGTH / 8];

    int bytes_read = 0;
    while ((bytes_read = fread(input_block, 1, BLOCK_SIZE, input_file)) > 0) {
        int encrypted_size = RSA_public_encrypt(bytes_read, input_block, output_block, key, RSA_PKCS1_PADDING);
        if (encrypted_size == -1) {
            printf("Failed to encrypt input block\n");
            fclose(input_file);
            fclose(output_file);
            return NULL;
        }

        fwrite(output_block, 1, encrypted_size, output_file);
    }

    fclose(input_file);
    fclose(output_file);

    printf("Encryption completed for file %s\n", input_filename);
    return NULL;
}

// Thread function to decrypt a file
void* decrypt_file_thread(void* arg) {
    struct file_data* data = (struct file_data*)arg;
    const char* input_filename = data->input_filename;
    const char* output_filename = data->output_filename;
    RSA* key = data->key;

    FILE* input_file = fopen(input_filename, "rb");
    if (input_file == NULL) {
        printf("Failed to open input file %s\n", input_filename);
        return NULL;
    }

    FILE* output_file = fopen(output_filename, "wb");
    if (output_file == NULL) {
        printf("Failed to open output file %s\n", output_filename);
        fclose(input_file);
        return NULL;
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
            return NULL;
        }

        fwrite(output_block, 1, decrypted_size, output_file);
    }

    fclose(input_file);
    fclose(output_file);

    printf("Decryption completed for file %s\n", input_filename);
    return NULL;
}

int main() {
    // Generate RSA key pair
    RSA* key = generate_key_pair();

    // Encrypt input file
    encrypt_file("input.txt", "encrypted.bin", key);

    // Decrypt encrypted file
    decrypt_file("encrypted.bin", "output.txt", key);

    // Free RSA key pair
    RSA_free(key);

    return 0;
}
