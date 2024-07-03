#include <stdio.h>

int main() {
    char buffer[20];
    
    printf("Inserisci il tuo nome: ");
    fgets(buffer, sizeof(buffer), stdin);
    
    printf("Ciao, %s\n", buffer);
    
    return 0;
}
