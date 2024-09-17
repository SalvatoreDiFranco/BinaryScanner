#include <stdio.h>

void safe_function(char *user_input) {
    printf("%s", user_input);
}

int main() {
    char user_input[100];
    printf("Inserisci una stringa: ");
    fgets(user_input, sizeof(user_input), stdin);
    safe_function(user_input);

    return 0;
}
