#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

/*
    TODO
    Test methods
    Add `free`s
    Make it actually work lol
*/

int main(){
    uint8_t* input = "abcd1234efgh5678";
    uint8_t* key = "stuv9876wxyz5432"; /* 128-bit key */
    size_t keySize = strlen(key) * 8;
    uint8_t keySchedule[Nb * (Nr(keySize) + 1)];
    KeyExpansion(key, keySchedule, keySize);
    uint8_t* output = Cipher(input, keySchedule, keySize);
    printf("%x\n", output);
    return 0;
}

void printState(State* state){
    int i, j;
    for(i = 0; i < 4; i++){
        printf("---------------------\n");
        for(j = 0; j < Nb; j++){
            printf("| %d ", state->array[i][j]);
        }
        printf("|\n");
    }
}

void toState(State* state, uint8_t* input){
    int i, j;
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Set value in state array to current byte */
            state->array[j][i] = *input;
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
            *output = state->array[j][i];
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
            uint8_t new = sbox[state->array[i][j]];
            state->array[i][j] = new;
        }
    }
}

void ShiftRows(State* state){
    int i, j;
    for(i = 0; i < 4; i++){
        /* The row number is the number of shifts to do */
        uint8_t temp[4];
        for(j = 0; j < Nb; j++){
            temp[(j + i) % Nb] = state->array[i][j];
        }
        /* Copy temp array to state array */
        memcpy(state->array[i], temp, 4);
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
        if(carry == 1){
            a ^= 0x1b;
        }
    }
    return p;
}

void MixColumns(State* state){
    int c, r;
    for(c = 0; c < Nb; c++){
        uint8_t temp[4];
        temp[0] = galoisMultiply(state->array[0][c], 2) ^ galoisMultiply(state->array[1][c], 3) ^ state->array[2][c] ^ state->array[3][c];
        temp[1] = state->array[0][c] ^ galoisMultiply(state->array[1][c], 2) ^ galoisMultiply(state->array[2][c], 3) ^ state->array[3][c];
        temp[2] = state->array[0][c] ^ state->array[1][c] ^ galoisMultiply(state->array[2][c], 2) ^ galoisMultiply(state->array[3][c], 3);
        temp[3] = galoisMultiply(state->array[0][c], 3 ^ state->array[1][c] ^ state->array[2][c] ^ galoisMultiply(state->array[3][c], 2));
        /* Copy temp array to state */
        for(r = 0; r < 4; r++){
            state->array[r][c] = temp[r];
        }
    }
}

/* Takes a Nb*4 byte round key array and XORs it with the state */
void AddRoundKey(State* state, uint8_t roundKey){
    int c, r;
    for(c = 0; c < Nb; c++){
        for(r = 0; r < 4; r++){
            /* XOR each column with the round key */
            state->array[r][c] ^= roundKey;
            roundKey++;
        }
    }
}

uint8_t* SubWord(uint8_t* a){
    int i;
    uint8_t* word = malloc(sizeof(uint8_t) * 4);
    for(i = 0; i < 4; i++){
        word[i] = sbox[*a];
        a++;
    }
    return word;
}

uint8_t* RotWord(uint8_t* a){
    uint8_t* word = malloc(sizeof(uint8_t) * 4);
    uint8_t rot[] = {a[1], a[2], a[3], a[0]};
    memcpy(word, rot, 4);
    return word;
}

uint8_t* Rcon(int a){
    uint8_t* word = malloc(sizeof(uint8_t) * 4);
    uint8_t rcon[] = {(a<<1) ^ (0x11b & - (a>>7)), 0, 0, 0};
    memcpy(word, rcon, 4);
    return word;
}

uint8_t* xorWords(uint8_t* a, uint8_t* b){
    int i;
    uint8_t* word = malloc(sizeof(uint8_t) * 4);
    for(i = 0; i < 4; i++){
        word[i] = a[i] ^ b[i];
    }
    return word;
}

uint8_t* getWord(uint8_t* a){
    int i;
    uint8_t* word = malloc(sizeof(uint8_t) * 4);
    for(i = 0; i < 4; i++){
        word[i] = *a;
        a++;
    }
    return word;
}

void KeyExpansion(uint8_t* key, uint8_t* w, size_t keySize){
    int i, j, b;
    uint8_t* wi;
    uint8_t* temp;
    for(i = 0; i < Nk(keySize); i++){
        for(j = 0; j < Nb; j++){
            w[4*i+j] = key[4*i+j];
        }
    }
    i = Nk(keySize);
    while(i < Nb * (Nr(keySize) + 1)){
        temp = getWord(&w[i-1]);
        if(i % Nk(keySize) == 0){
            temp = xorWords(SubWord(RotWord(temp)), Rcon(i/Nk(keySize)));
        } else if(Nk(keySize) > 6 && i % Nk(keySize) == 4){
            temp = SubWord(temp);
        }
        wi = xorWords(getWord(&w[i-Nk(keySize)]), temp);
        for(b = 0; b < 4; b++){
            w[i+b] = wi[b];
        }
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
    /* Convert input to state */
    State state;
    uint8_t statearr[4][4];
    state.array = statearr;
    toState(&state, input);
    /* Cipher method */
    AddRoundKey(&state, w[0]);
    for(i = 1; i < Nr(keySize); i++){
        SubBytes(&state);
        ShiftRows(&state);
        MixColumns(&state);
        AddRoundKey(&state, w[i*Nb]);
    }
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(&state, w[Nr(keySize)*Nb]);
    /* Allocate 16 bytes for output and put the state in it */
    uint8_t* output = malloc(sizeof(uint8_t) * 16);
    fromState(&state, output);
    return output;
}