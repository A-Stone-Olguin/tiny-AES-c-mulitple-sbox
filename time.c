// This file is made to test the timing differences between using multiple s-boxes over different AES methods
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <limits.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include "aes.h"

static void time_enc_dec(int mode, const char* mode_name);
static void enc_dec_file(char* filename, int mode);

int main(void) {

    // Time the encode and decode of 
    //  0: ECB
    //  1: CBC
    //  2: CTR
    printf("\n\n");
    const char* mode_names[] = {"ECB", "CBC", "CTR"};
    for (int i = 0; i < 3; i++) {
        time_enc_dec(i, mode_names[i]);
    }
    printf("\n\n");
    return 0;
}

static void enc_dec_file(char* filename, int mode) {
    uint8_t *text = NULL;
    long num_rows = 0;
    long bufsize = 0;
    int padding = 0;

    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }

    /* Go to the end of the file. */
    if (fseek(fp, 0L, SEEK_END) == 0) {
        /* Get the size of the file. */
        bufsize = ftell(fp);
        if (bufsize == -1) { perror("Error getting file size!"); fclose(fp); return;}

        num_rows = bufsize / 16;

        /* Allocate our buffer to that size. */
        text = malloc(sizeof(char) * (bufsize + 1));

        if (text == NULL) {
            printf("Error allocating memory for plaintext on file: %s\n", filename);
            fclose(fp);
            return;
        }

        /* Go back to the start of the file. */
        if (fseek(fp, 0L, SEEK_SET) != 0) { 
            perror("Error going back to the start of the file");
            free(text); 
            fclose(fp);
            return;
        }

        /* Read the entire file into memory. */
        size_t newLen = fread(text, sizeof(char), bufsize, fp);
        if ( ferror( fp ) != 0 ) {
            fputs("Error reading file", stderr);
        } else {
            text[newLen++] = '\0'; /* Just to be safe. */
        }
        fclose(fp);


        // Adding padding
        padding = 16 - (newLen % 16);
        if (padding != 0) {
            text = realloc(text, newLen + padding);
            if (text == NULL) {
                perror("Error reallocating memory for padding");
                free(text);
                return;
            }
        }
        for (size_t i = newLen; i < newLen + padding; ++i) {
            text[i] = (char)padding;
        }
        newLen += padding;
        text[newLen] = '\0';
    }

    uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
    struct AES_ctx ctx;

    // Encrypt
    // 0 mode is ecb
    if (mode == 0) {
        for (size_t i = 0; i < num_rows; ++i) {
            AES_init_ctx(&ctx, key);
            AES_ECB_encrypt(&ctx, text + (i * 16));
        }
    }
    // 1 mode is cbc
    else if (mode == 1) {
        for (size_t i = 0; i < num_rows; ++i) {
            uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CBC_encrypt_buffer(&ctx, text, 64);
        }

    }
    // 2 mode is ctr
    else if (mode == 2) {
        for (size_t i = 0; i < num_rows; ++i) {
            uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CTR_xcrypt_buffer(&ctx, text, 64);
        }

    }
    // Otherwise, invalid mode
    else {
        printf("Invalid mode given: %d", mode);
        return;
    }

    // Now we decrypt
    // Create a new AES context to not confuse with encrypt
    struct AES_ctx ctx2;

    // 0 mode is ecb
    if (mode == 0) {
        for (size_t i = 0; i < num_rows; ++i) {
            AES_init_ctx(&ctx2, key);
            AES_ECB_decrypt(&ctx2, text + (i * 16));
        }
    }
    // 1 mode is cbc
    else if (mode == 1) {
        for (size_t i = 0; i < num_rows; ++i) {
            uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
            AES_init_ctx_iv(&ctx2, key, iv);
            AES_CBC_decrypt_buffer(&ctx2, text, 64);
        }

    }
    // 2 mode is ctr
    else if (mode == 2) {
        for (size_t i = 0; i < num_rows; ++i) {
            uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
            AES_init_ctx_iv(&ctx2, key, iv);
            AES_CTR_xcrypt_buffer(&ctx2, text, 64);
        }

    }
    // Otherwise, invalid mode
    else {
        printf("Invalid mode given: %d", mode);
        return;
    }

    // Free the text buffer from memory
    free(text);
    return;
}


static void time_enc_dec(int mode, const char* mode_name) {
    struct dirent * dp;
    DIR *dfd;
    char *dir = "dummy_files/";
    clock_t start, end;
    int num_files = 0;

    if ((dfd = opendir(dir)) == NULL) {
        fprintf(stderr, "Can't open%s\n", dir);
        return;
    }

    start = clock();
    while ((dp = readdir(dfd)) != NULL) {
        char full_path[PATH_MAX];      // FIle names will have at most 30 length
        snprintf(full_path, sizeof(full_path), "%s%s", dir, dp->d_name);
        struct stat st;

        // Ensure we only encrypt regular files (Does a bit of slowdown)
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
            enc_dec_file(full_path, mode);
            num_files++;
        }
    }
    end = clock();

    closedir(dfd);
    double time_elapsed = ((double) (end - start)/ CLOCKS_PER_SEC);
    double average_time = time_elapsed / (double) num_files;

    printf("For mode %s with %d S-box(es):\n\t", mode_name, SBOX2 + 1);
    printf("The time elapsed was %f seconds (%f ms) with an average time of %f seconds (%f ms)\n", time_elapsed, time_elapsed * 100, average_time, average_time * 100);
    return;
}