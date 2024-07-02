#include <stdio.h>
#include <stdlib.h>

int main() {
    // Allocazione di memoria per un intero
    int *ptr = (int *)malloc(sizeof(int));
    // Liberiamo la memoria allocata
    free(ptr);

    return 0;
}
