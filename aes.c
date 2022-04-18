#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include "aes.h"
#include "util.h"
#include "const.c"

/*
    TODO
    Inverse cipher
    Make command line
*/

int main(){
    encrypt("3243f6a8885a308d313198a2e0370734", "2b7e151628aed2a6abf7158809cf4f3c"); /* Appendix B example */
    encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f"); /* Appendix C 128-bit example */
    encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617"); /* Appendix C 192-bit example */
    encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); /* Appendix C 256-bit example */
    return 0;
}

void encrypt(char* plaintext, char* keyStr){
    uint8_t *keySchedule, *output;
    int i;
    /* Hardcoded input and key */
    uint8_t* input = malloc(sizeof(uint8_t) * 16);
    stringToBytes(plaintext, input);
    size_t keyBytes = (sizeof(uint8_t)*strlen(keyStr))/2;
    Key key = malloc(keyBytes);
    stringToBytes(keyStr, key);
    size_t keySize = keyBytes * 8; /* Convert bytes to bits */
    /* Create array for key schedule */
    keySchedule = calloc(4 * Nb * (Nr(keySize) + 1), sizeof(uint8_t));
    /* Expand key */
    KeyExpansion(key, keySchedule, keySize);
    /* Run cipher */
    output = Cipher(input, keySchedule, keySize);
    for(i = 0; i < 16; i++){
        printf("%02x", output[i]);
    }
    printf("\n");
    free(input);
    free(key);
    free(keySchedule);
    free(output);
}

void toState(State* state, uint8_t* input){
    int i, j;
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Set value in state array to current byte */
            (*state)[j][i] = *input;
            /* Increment pointer */
            input++;
        }
    }
}

void fromState(State* state, uint8_t* output){
    int i, j;
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Set the output to it's array item */
            *output = (*state)[j][i];
            /* Increment the pointer */
            output++;
        }
    }
}

/*
    AES sub-methods start
*/
void SubBytes(State* state){
    int i, j;
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Get the new value from the S-box */
            uint8_t new = sbox[(*state)[i][j]];
            (*state)[i][j] = new;
        }
    }
}

void ShiftRows(State* state){
    int i, j;
    for(i = 0; i < 4; i++){
        /* The row number is the number of shifts to do */
        uint8_t temp[4];
        for(j = 0; j < Nb; j++){
            temp[((j + Nb) - i) % Nb] = (*state)[i][j];
        }
        /* Copy temp array to state array */
        memcpy((*state)[i], temp, 4);
    }
}

/* Multiplies two bytes in the 2^8 Galois field */
uint8_t galoisMultiply(uint8_t a, uint8_t b){
    uint8_t p = 0;
    int i;
    int carry;
    for(i = 0; i < 8; i++){
        if((b & 1) == 1){
            p ^= a;
        }
        b >>= 1;
        carry = a & 0x80;
        a <<= 1;
        if(carry == 0x80){
            a ^= 0x1b;
        }
    }
    return p;
}

void MixColumns(State* state){
    int c, r;
    for(c = 0; c < Nb; c++){
        uint8_t temp[4];
        temp[0] = galoisMultiply((*state)[0][c], 2) ^ galoisMultiply((*state)[1][c], 3) ^ (*state)[2][c] ^ (*state)[3][c];
        temp[1] = (*state)[0][c] ^ galoisMultiply((*state)[1][c], 2) ^ galoisMultiply((*state)[2][c], 3) ^ (*state)[3][c];
        temp[2] = (*state)[0][c] ^ (*state)[1][c] ^ galoisMultiply((*state)[2][c], 2) ^ galoisMultiply((*state)[3][c], 3);
        temp[3] = galoisMultiply((*state)[0][c], 3) ^ (*state)[1][c] ^ (*state)[2][c] ^ galoisMultiply((*state)[3][c], 2);
        /* Copy temp array to state */
        for(r = 0; r < 4; r++){
            (*state)[r][c] = temp[r];
        }
    }
}

/* Takes a Nb*4 byte round key array and XORs it with the state */
void AddRoundKey(State* state, uint8_t* roundKey){
    int c, r;
    for(c = 0; c < Nb; c++){
        for(r = 0; r < 4; r++){
            /* XOR each column with the round key */
            (*state)[r][c] ^= *roundKey;
            roundKey++;
        }
    }
}

uint8_t* SubWord(uint8_t* a){
    /* Substitute bytes with the sbox */
    int i;
    uint8_t* init = a;
    for(i = 0; i < 4; i++){
        *a = sbox[*a];
        a++;
    }
    return init;
}

uint8_t* RotWord(uint8_t* a){
    /* Rotate array then copy to pointer */
    uint8_t rot[] = {a[1], a[2], a[3], a[0]};
    memcpy(a, rot, 4);
    return a;
}

uint8_t* Rcon(int a){
    /* Gets the round constant array for a value a.
       The first item is from the table, the other
       3 are all 0 */
    uint8_t* word = calloc(4, sizeof(uint8_t));
    word[0] = rcon[a-1];
    return word;
}

uint8_t* xorWords(uint8_t* a, uint8_t* b){
    /* Takes the two pointers to the start of 4 byte words and
       XOR's the words, overwriting the first. Returns a pointer to
       the first byte of the first word */
    int i;
    uint8_t* init = a;
    for(i = 0; i < 4; i++, a++, b++){
        *a ^= *b;
    }
    return init;
}

uint8_t* copyWord(uint8_t* start){
    /* Returns a pointer to a copy of a word */
    int i;
    uint8_t* word = malloc(sizeof(uint8_t) * 4);
    for(i = 0; i < 4; i++, start++){
        word[i] = *start;
    }
    return word;
}

uint8_t* getWord(uint8_t* w, int i){
    /* Takes a word number (w index in spec) and
       returns a pointer to the first of it's 4 bytes */
    return &w[4*i];
}

void KeyExpansion(uint8_t* key, uint8_t* w, size_t keySize){
    int i, j;
    uint8_t *wi, *wk, *temp, *rconval;
    /* Copy the key into the first Nk words of the schedule */
    for(i = 0; i < Nk(keySize); i++){
        for(j = 0; j < Nb; j++){
            w[4*i+j] = key[4*i+j];
        }
    }
    i = Nk(keySize);
    /* Generate Nb * (Nr + 1) additional words for the schedule */
    while(i < Nb * (Nr(keySize) + 1)){
        /* Copy the previous word */
        temp = copyWord(getWord(w, i-1));
        if(i % Nk(keySize) == 0){
            /* If i is divisble by Nk, rotate and substitute the word
               and then xor with Rcon[i/Nk] */
            rconval = Rcon(i/Nk(keySize));
            xorWords(SubWord(RotWord(temp)), rconval);
            free(rconval);
        } else if(Nk(keySize) > 6 && i % Nk(keySize) == 4){
            /* If Nk > 6 and i mod Nk is 4 then just substitute */
            memcpy(temp, SubWord(temp), 4);
        }
        /* Get pointers for the current word and the (i-Nk)th word */
        wi = getWord(w, i);
        wk = getWord(w, i - Nk(keySize));
        /* wi = temp xor wk */
        memcpy(wi, xorWords(temp, wk), 4);
        free(temp);
        i++;
    }
}

/*
    Takes a pointer to the first byte of a 16 byte chunk
    Turns it into a state
    Applies the cipher as described in Figure 5 of the standard
*/
uint8_t* Cipher(uint8_t* input, uint8_t* w, size_t keySize){
    int i;
    uint8_t* output;
    State* state_ptr;
    /* Convert input to state */
    State state = malloc(4 * sizeof(uint8_t*));
    for(i = 0; i < 4; i++){
        state[i] = malloc(Nb * sizeof(uint8_t));
    }
    state_ptr = &state;
    toState(state_ptr, input);
    /* Cipher method */
    AddRoundKey(state_ptr, getWord(w, 0));
    for(i = 1; i < Nr(keySize); i++){
        SubBytes(state_ptr);
        ShiftRows(state_ptr);
        MixColumns(state_ptr);
        AddRoundKey(state_ptr, getWord(w, i*Nb));
    }
    SubBytes(state_ptr);
    ShiftRows(state_ptr);
    AddRoundKey(state_ptr, getWord(w, Nr(keySize)*Nb));
    /* Allocate output and put the state in it */
    output = malloc(sizeof(uint8_t) * 16);
    fromState(state_ptr, output);
    return output;
}