/*
    Utitlies for printing various parts of the program for debugging.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "aes.h"
#include "util.h"

void printState(State* state){
    int i, j;
    for(i = 0; i < 4; i++){
        printf("---------------------\n");
        for(j = 0; j < Nb; j++){
            printf("| %02x ", (*state)[i][j]);
        }
        printf("|\n");
    }
}

void debugState(State* state, char* text){
    printf("%s", text);
    printState(state);
}

void printKeySchedule(uint8_t* array, size_t r){
    int i;
    for(i = 0; i < r; i++){
        printKeyScheduleLine(array, i);
    }
}

void printKeyScheduleLine(uint8_t* array, int i){
    int j;
    printf("w%02d | ", i);
    for(j = 0; j < 4; j++){
        printf("%02x", array[(i*4)+j]);
    }
    printf(" |\n");
}

void keyExpansionDebug(uint8_t* w, int n, uint8_t* i, char* code){
    int j;
    printf("w%02d %s | ", n, code);
    for(j = 0; j < 4; j++, i++){
        printf("%02x", *i);
    }
    printf(" |\n");
}

void printWord(uint8_t* p){
    int i;
    for(i = 0; i < 4; i++){
        printf("%02x ", *p);
        p++;
    }
    putchar('\n');
}