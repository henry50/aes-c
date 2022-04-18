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

int main(){
    uint8_t rcon[] = {1, 0, 0, 0};
    uint8_t word[] = {0x8a, 0x84, 0xeb, 0x01};
    uint8_t* result = xorWords(rcon, word);
    printWord(result);
    return 0;
}