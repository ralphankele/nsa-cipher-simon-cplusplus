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

#include "attack.h"
#include "simon.h"
#include <iostream>
#include <set>

int impossibleDifferentialAttack(){

    //Generate and store all possible Keys
    printf("generate Key: \n");
    generateKey();
    
    std::set<uint64_t> candidateKeys;
    for(uint64_t i = 0; i <= WORD_MASK; ++i){
        candidateKeys.insert(i);
    }
    
    printf("Number of candidate keys: %lu\n", candidateKeys.size());
    
    uint64_t aLeft, aRight, bLeft, bRight, FaRight, FbRight, Fx, Fxalpha;
    uint64_t inDiff, outDiff7, outDiff9;
    
    inDiff = 0x1;
    outDiff7 = S(inDiff, 7);
    outDiff9 = S(inDiff, 9);
    
    printf("ind: %llx \n", inDiff);
	printf("outd1: %llx \n", outDiff7);
	printf("outd2: %llx \n", outDiff9);
    
    unsigned int keyCounter = 0;
    unsigned int count = 0;
    int numberOfRounds = 14;
    for(uint64_t x = 0; x <= WORD_MASK; ++x){
        Fx = F(x);
        Fxalpha = F(x ^ inDiff);
        
        for(uint64_t y = 0; y < WORD_MASK; ++y){
            aLeft = x;
            aRight = y;
            bLeft = x ^ inDiff;
            bRight = y ^ Fx ^ Fxalpha;
            
            encrypt(aLeft, aRight, numberOfRounds);
            encrypt(bLeft, bRight, numberOfRounds);
            
            // key recovery
            FaRight = F(aRight);
            FbRight = F(bRight);
            if ( (FaRight ^ FbRight ^ aLeft ^ bLeft) == outDiff7 || (FaRight ^ FbRight ^ aLeft ^ bLeft) == outDiff9 ) { //first filter
                count++;
            
                for(uint64_t keyGuess = 0; keyGuess <= WORD_MASK; ++keyGuess){
                    
                    if ( (F(aLeft^FaRight^keyGuess) ^ F(bLeft^FbRight^keyGuess) ^ aRight ^ bRight) == 0x0 ) {
                        if(candidateKeys.find(keyGuess) != candidateKeys.end()){
                            candidateKeys.erase(keyGuess);
                            keyCounter++;
                        }
                    }
                }//endkeyGuess
                
            }//endfilter
        }
    }
    
    printf("Count %d \n", count);
    printf("Removed %d keys\n", keyCounter);
    printf("Remaining keys: %lu \n", candidateKeys.size());
    
    return 0;
}

