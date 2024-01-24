// This file is made to test the timing differences between using multiple s-boxes over different AES methods
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <limits.h>
#include <math.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef DIR_SIZE
#define DIR_SIZE 4096
#endif
#ifndef DEBUG 
#define DEBUG 0
#endif

#include "aes.h"

static void time_enc_dec(int mode, const char* mode_name, int debug);
static void enc_dec_file(char* filename, int mode, int debug);
void mean_std_arr(double arr[], int size);
static void phex(uint8_t* str);

int main(void) {

    // Time the encode and decode of 
    //  0: ECB
    //  1: CBC
    //  2: CTR
    printf("\n\n");
    const char* mode_names[] = {"ECB", "CBC", "CTR"};
    for (int i = 0; i < 3; i++) {
        time_enc_dec(i, mode_names[i], DEBUG);
    }
    printf("\n\n");
    return 0;
}

static void enc_dec_file(char* filename, int mode, int debug) {
    uint8_t *text = NULL;
    long num_rows = 0;
    long bufsize = 0;
    int padding = 0;
    size_t last_byte = 0;

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

        last_byte = newLen -1;
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

    if (debug) {
        printf("The plaintext is:\n");
        phex(text);
        printf("\n");
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
    
    if (debug) {
        printf("The ciphertext is:\n");
        phex(text);
        printf("\n");
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

    // Remove the padding
    if (text[last_byte] <= 16) {
        size_t padding_start = last_byte - text[last_byte] + 1;

        for (size_t i = padding_start; i < last_byte; ++i) {
            if (text[i] != text[last_byte]) {
                printf("Invalid padding!\n");
                return;
            }
        }
        text[padding_start] = '\0';
    }

    if (debug) {
        printf("The decoded ciphertext is:\n");
        phex(text);
        printf("\n");
    }

    // Free the text buffer from memory
    free(text);
    return;
}

// Given an array of doubles with its size, compute the average and standard deviation
void mean_std_arr(double arr[], int size) {
    double sum = 0;
    double total_time = 0;
    double average = 0;
    double stdev = 0;
    // Compute the average
    for (int i = 0; i < size; i++) {
        total_time += arr[i];
    }
    average = size == 0 ? 0 : total_time / (double) size;

    // Reset the sum for the standard deviation
    sum = 0;
    for (int i = 0; i < size; i++) {
        sum += pow(arr[i] - average, 2);
    }
    // Calculate variance
    double variance = size == 0 ? 0 : sum / (double) size;

    // Calculate variance
    stdev = sqrt(variance);

    // Print the results
    printf("\tThe total time elapsed was: %f seconds\n", total_time);
    printf("\tThe average time was: %f seconds\n", average);
    printf("\tThe standard deviation was: %f seconds\n", stdev);
    printf("\tThe sample size was %d files\n", size);
}

static void time_enc_dec(int mode, const char* mode_name, int debug) {
    struct dirent * dp;
    DIR *dfd;
    char *dir = "dummy_files/";
    clock_t start, end;
    int num_files = 0;

    if ((dfd = opendir(dir)) == NULL) {
        fprintf(stderr, "Can't open%s\n", dir);
        return;
    }

    // This will store all the timings for each run, a maximum of 4096
    double timings[DIR_SIZE];

    while ((dp = readdir(dfd)) != NULL) {
        char full_path[PATH_MAX];      
        snprintf(full_path, sizeof(full_path), "%s%s", dir, dp->d_name);
        struct stat st;

        // Ensure we only encrypt regular files (Does a bit of slowdown)
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
            start = clock();
            enc_dec_file(full_path, mode, debug);
            end = clock();
            timings[num_files] = ((double) (end-start)/ CLOCKS_PER_SEC);
            num_files++;
        }
    }

    closedir(dfd);

    printf("For mode %s with SBOX2=%d\n", mode_name, SBOX2);
    // printf("The time elapsed was %f seconds (%f ms) with an average time of %f seconds (%f ms)\n", time_elapsed, time_elapsed * 100, average_time, average_time * 100);
    mean_std_arr(timings, num_files);
    return;
}

// prints string as hex
static void phex(uint8_t* str)
{

#if defined(AES256)
    uint8_t len = 32;
#elif defined(AES192)
    uint8_t len = 24;
#elif defined(AES128)
    uint8_t len = 16;
#endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}