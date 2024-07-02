# BinaryScanner

Strumento per la scansione di file binari in formato ELF che individua attraverso l'analisi binaria e l'esecuzione simbolica la presenza di vulnerabilità come buffer overflow, format string, use after free e double free.
Il framework di riferimento è angr, di cui allego la documentazione ufficiale in seguito: https://docs.angr.io/en/latest/

## Struttura della repository
Nella cartella "rules" sono presenti 3 script python ciascuno dei quali è un'implementazione di una regola per individuare una vulnerabilità, fatta eccezione per use after free e double free che sono individuate dalla stessa regola.
Nella cartella "test" sono presenti diversi file eseguibili in linguaggio C e sorgenti che presentano le vulnerabilità da individuare e possono essere utilizzati come test. 

