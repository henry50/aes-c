
void makeState(State* state, uint8_t* input);
void printState(State* state);
void printKeySchedule(uint8_t* array, size_t r);
void printKeyScheduleLine(uint8_t* array, int i);
void stringToBytes(char* str, uint8_t* bytes);
void debugState(State* state, char* text);