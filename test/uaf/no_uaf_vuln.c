#include <stdlib.h>
#include <stdio.h>

int main() {
    int *ptr = malloc(sizeof(int));
    free(ptr);
    ptr = NULL;

    return 0;
}


