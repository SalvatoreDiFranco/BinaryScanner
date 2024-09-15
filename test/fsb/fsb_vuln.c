#include <stdio.h>

int main(int argc, char *argv[]) {
    char str[20];
    fgets(str, sizeof(str), stdin);  // Uso di fgets per evitare buffer overflow
    printf(argv[1]);  // Vulnerabilità di Format String Bug
    return 0;
}
