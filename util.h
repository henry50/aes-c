/*
    Functions declarations for util.c
*/
void printState(State* state);
void debugState(State* state, char* text);
void printKeySchedule(uint8_t* array, size_t r);
void printKeyScheduleLine(uint8_t* array, int i);
void keyExpansionDebug(uint8_t* w, int n, uint8_t* i, char* code);
void printWord(uint8_t* p);