#include <stdio.h>

char string[] = "This is a test string!";

__attribute__((constructor))
void init() {
    printf("puts address: 0x%lx\nstring address: 0x%lx\n", (unsigned int*)&puts, (unsigned int*)&string);
}
