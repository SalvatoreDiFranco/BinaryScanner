#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input);
}

int main() {
    char input[20];
    printf("Inserisci una stringa: ");
    scanf("%s", input);
    vulnerable_function(input);
    printf("Fine del programma.\n");
    return 0;
}
