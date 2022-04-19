#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include "aes.h"
#include "util.h"
#include "const.c"

int main(){
    printf("ENCRYPTION:\n");
    encrypt("3243f6a8885a308d313198a2e0370734", "2b7e151628aed2a6abf7158809cf4f3c"); /* Appendix B example */
    encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f"); /* Appendix C 128-bit example */
    encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617"); /* Appendix C 192-bit example */
    encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); /* Appendix C 256-bit example */
    /* Inverse of the above */
    printf("DECRYPTION:\n");
    decrypt("3925841d02dc09fbdc118597196a0b32", "2b7e151628aed2a6abf7158809cf4f3c");
    decrypt("69c4e0d86a7b0430d8cdb78070b4c55a", "000102030405060708090a0b0c0d0e0f");
    decrypt("dda97ca4864cdfe06eaf70a0ec0d7191", "000102030405060708090a0b0c0d0e0f1011121314151617");
    decrypt("8ea2b7ca516745bfeafc49904b496089", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    return 0;
}

void encrypt(char* plaintext, char* keyStr){
    uint8_t *keySchedule, **output;
    int i;
    /* Get input and key */
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
        printf("%02x", (*output)[i]);
    }
    printf("\n");
    free(input);
    free(key);
    free(keySchedule);
    free(*output);
    free(output);
}

void decrypt(char* ciphertext, char* keyStr){
    uint8_t *keySchedule, **output;
    int i;
    /* Get input and key */
    uint8_t* input = malloc(sizeof(uint8_t) * 16);
    stringToBytes(ciphertext, input);
    size_t keyBytes = (sizeof(uint8_t)*strlen(keyStr))/2;
    Key key = malloc(keyBytes);
    stringToBytes(keyStr, key);
    size_t keySize = keyBytes * 8; /* Convert bytes to bits */
    /* Create array for key schedule */
    keySchedule = calloc(4 * Nb * (Nr(keySize) + 1), sizeof(uint8_t));
    /* Expand key */
    KeyExpansion(key, keySchedule, keySize);
    /* Run cipher */
    output = InvCipher(input, keySchedule, keySize);
    for(i = 0; i < 16; i++){
        printf("%02x", (*output)[i]);
    }
    printf("\n");
    free(input);
    free(key);
    free(keySchedule);
    free(*output);
    free(output);
}

State* toState(uint8_t* input){
    int i, j;
    /* Malloc state */
    State* stateptr = malloc(sizeof(State));
    *stateptr = malloc(4 * sizeof(uint8_t*));
    State state = *stateptr;
    for(i = 0; i < 4; i++){
        state[i] = malloc(Nb * sizeof(uint8_t));
    }
    /* Fill state */
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Set value in state array to current byte */
            state[j][i] = *input;
            /* Increment pointer */
            input++;
        }
    }
    return stateptr;
}

uint8_t** fromState(State* state){
    int i, j;
    /* Malloc output */
    uint8_t** outputptr = malloc(sizeof(uint8_t*));
    *outputptr = malloc(sizeof(uint8_t) * 16);
    uint8_t* output = *outputptr;
    /* Fill output */
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Set the output to it's array item */
            *output = (*state)[j][i];
            /* Increment the pointer */
            output++;
        }
    }
    return outputptr;
}

void freeState(State* state){
    int i;
    for(i = 0; i < 4; i++){
        free((*state)[i]);
    }
    free(*state);
    free(state);
}

/*
    AES sub-methods start
*/
void _SubBytes(State* state, const uint8_t* box){
    int i, j;
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Get the new value from the S-box */
            uint8_t new = box[(*state)[i][j]];
            (*state)[i][j] = new;
        }
    }
}

void SubBytes(State* state){
    _SubBytes(state, sbox);
}

void InvSubBytes(State* state){
    _SubBytes(state, isbox);
}

void _ShiftRows(State* state, int multiplier){
    int i, j;
    for(i = 0; i < 4; i++){
        /* The row number is the number of shifts to do */
        uint8_t temp[4];
        for(j = 0; j < Nb; j++){
            /* The multiplier determines whether to do a left or right shift */
            temp[((j + Nb) + (multiplier * i)) % Nb] = (*state)[i][j];
        }
        /* Copy temp array to state array */
        memcpy((*state)[i], temp, 4);
    }
}

void ShiftRows(State* state){
    _ShiftRows(state, -1);
}

void InvShiftRows(State* state){
    _ShiftRows(state, 1);
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

void InvMixColumns(State* state){
    int c, r;
    for(c = 0; c < Nb; c++){
        uint8_t temp[4];
        temp[0] = galoisMultiply((*state)[0][c], 14) ^ galoisMultiply((*state)[1][c], 11) ^ galoisMultiply((*state)[2][c], 13) ^ galoisMultiply((*state)[3][c], 9);
        temp[1] = galoisMultiply((*state)[0][c], 9)  ^ galoisMultiply((*state)[1][c], 14) ^ galoisMultiply((*state)[2][c], 11) ^ galoisMultiply((*state)[3][c], 13);
        temp[2] = galoisMultiply((*state)[0][c], 13) ^ galoisMultiply((*state)[1][c], 9)  ^ galoisMultiply((*state)[2][c], 14) ^ galoisMultiply((*state)[3][c], 11);
        temp[3] = galoisMultiply((*state)[0][c], 11) ^ galoisMultiply((*state)[1][c], 13) ^ galoisMultiply((*state)[2][c], 9)  ^ galoisMultiply((*state)[3][c], 14);
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
    /* Calculates the round constant and returns it in an array */
    uint8_t rcon = 0x8d;
    int i;
    for(i = 0; i < a; i++){
        rcon = ((rcon << 1) ^ (0x11b & - (rcon >> 7)));
    }
    uint8_t* word = calloc(4, sizeof(uint8_t));
    word[0] = rcon;
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
uint8_t** Cipher(uint8_t* input, uint8_t* w, size_t keySize){
    int i;
    uint8_t** output;
    State* state = toState(input);
    /* Cipher method */
    AddRoundKey(state, getWord(w, 0));
    for(i = 1; i < Nr(keySize); i++){
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, getWord(w, i*Nb));
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, getWord(w, Nr(keySize)*Nb));
    /* Allocate output and put the state in it */
    output = fromState(state);
    freeState(state);
    return output;
}

/*
    Follows the inverse cipher alogrithm in figure 12 of the standard
*/
uint8_t** InvCipher(uint8_t* input, uint8_t* w, size_t keySize){
    int i;
    uint8_t** output;
    State* state = toState(input);

    /* Inverse cipher method */
    AddRoundKey(state, getWord(w, Nr(keySize) * Nb));
    for(i = Nr(keySize) - 1; i >= 1; i--){
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, getWord(w, i*Nb));
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, getWord(w, 0));

    output = fromState(state);
    freeState(state);
    return output;
}