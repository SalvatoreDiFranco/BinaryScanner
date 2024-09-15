#include <stdio.h>

int main(int argc, char *argv[]) {
    char str[20];
    fgets(str, sizeof(str), stdin);  // Uso di fgets per evitare buffer overflow
    printf("%s", argv[1]);  // Stampa sicura con stringa di formato
    return 0;
}
