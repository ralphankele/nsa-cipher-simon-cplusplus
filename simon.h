// Source code base on code from: https://github.com/mmeh/simon-speck-cryptanalysis
// ===========================================================================
// SIMON implementation and cryptanalytic methods
// =========================================================================
// Copyright (c) 2013 Martin M. Lauridsen and Hoda A. Alkhzaimi.

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#ifndef _SIMON_H_
#define _SIMON_H_

#include <cstdint>

//Definitions
//16 (4), 24 (3,4), 32 (3,4), 48 (2,3), 64 (2,3,4)
#define WORD_SIZE 16
#define KEY_WORDS 4

#if (WORD_SIZE == 64)
    #define WORD_MASK (0xffffffffffffffffull)
#else
    #define WORD_MASK ((0x1ull << (WORD_SIZE&63)) - 1)
#endif

#define CONST_C ((0xffffffffffffffffull ^ 0x3ull) & WORD_MASK)

#if (WORD_SIZE == 16)
    #define ROUNDS (32)
    #define CONST_J (0)
#elif (WORD_SIZE == 24)
    #if (KEY_WORDS == 3)
        #define ROUNDS (36)
        #define CONST_J (0)
    #elif (KEY_WORDS == 4)
        #define ROUNDS (36)
        #define CONST_J (1)
    #endif
#elif (WORD_SIZE == 32)
    #if (KEY_WORDS == 3)
        #define ROUNDS (42)
        #define CONST_J (2)
    #elif (KEY_WORDS == 4)
        #define ROUNDS (44)
        #define CONST_J (3)
    #endif
#elif (WORD_SIZE == 48)
    #if (KEY_WORDS == 2)
        #define ROUNDS (52)
        #define CONST_J (2)
    #elif (KEY_WORDS == 3)
        #define ROUNDS (54)
        #define CONST_J (3)
    #endif
#elif (WORD_SIZE == 64)
    #if (KEY_WORDS == 2)
        #define ROUNDS (68)
        #define CONST_J (2)
    #elif (KEY_WORDS == 3)
        #define ROUNDS (69)
        #define CONST_J (3)
    #elif (KEY_WORDS == 4)
        #define ROUNDS (72)
        #define CONST_J (4)
    #endif
#endif

//Functions
void keySchedule();
void encrypt(uint64_t &left, uint64_t &right);
void encrypt(uint64_t &left, uint64_t &right, int rounds);
void decrypt(uint64_t &left, uint64_t &right);
void decrypt(uint64_t &left, uint64_t &right, int rounds);

void printz();
int test1();
int test2();

//Helper Functions
uint64_t S(uint64_t state, int distance);
uint64_t F(uint64_t state);
void generateKey();

//Test-Functions
int test_vectors();

#endif
