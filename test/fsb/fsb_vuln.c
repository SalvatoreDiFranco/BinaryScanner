#include <stdio.h>

void vulnerable_function(char *user_input) {
    printf(user_input);
}

int main() {
    char user_input[100];
    printf("Inserisci una stringa: ");
    fgets(user_input, sizeof(user_input), stdin);
    vulnerable_function(user_input);

    return 0;
}
