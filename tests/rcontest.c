#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void printWord(uint8_t* p){
    int i;
    for(i = 0; i < 4; i++){
        printf("%02x ", *p);
        p++;
    }
    putchar('\n');
}

uint8_t* xorWords(uint8_t* a, uint8_t* b){
    /* Takes the two pointers to the start of 4 byte words,
       XOR's the words and returns a pointer to the start of the result */
    int i;
    uint8_t* word = malloc(sizeof(uint8_t) * 4);
    for(i = 0; i < 4; i++, a++, b++){
        word[i] = *a ^ *b;
    }
    return word;
}

uint8_t* Rcon(int a){
    /* rcon = (rcon<<1) ^ (0x11b & -(rcon>>7)); */
    uint8_t rcon = 0x8d;
    int i;
    for(i = 0; i < a; i++){
        rcon = ((rcon << 1) ^ (0x11b & - (rcon >> 7)));
    }
    uint8_t* word = malloc(4*sizeof(uint8_t));
    word[0] = rcon;
    return word;
}

int main(){
    int i;
    for(i = 1; i < 20; i++){
        printWord(Rcon(i));
    }
    return 0;
}