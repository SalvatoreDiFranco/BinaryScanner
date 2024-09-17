#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

int main() {
    char input[20];
    printf("Inserisci una stringa: ");
    scanf("%19s", input);
    vulnerable_function(input);
    printf("Fine del programma.\n");
    return 0;
}
