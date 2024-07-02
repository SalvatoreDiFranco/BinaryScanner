#include <stdio.h>

int main() {
    char buffer[20]; // Definisco un array di caratteri con una dimensione specifica
    
    printf("Inserisci il tuo nome: ");
    fgets(buffer, sizeof(buffer), stdin); // Leggo l'input dell'utente
    
    printf("Ciao, %s\n", buffer); // Stampo l'input
    
    return 0;
}
