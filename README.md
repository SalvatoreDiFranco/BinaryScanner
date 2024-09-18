# BinaryScanner

Strumento per la scansione di file binari che individua, attraverso l'analisi binaria e l'esecuzione simbolica, la presenza di vulnerabilità come buffer overflow, format string, use after free e double free.\n
Il framework di riferimento è angr, segue il riferimento alla documentazione ufficiale: https://docs.angr.io/en/latest/

## Struttura della repository
Il file binary_scanner.py è una command line interface per utilizzare il tool.\n
Nella cartella "rules" sono presenti 3 script python ciascuno dei quali è un'implementazione di una regola per individuare una vulnerabilità, fatta eccezione per use after free e double free che sono individuate dalla stessa regola.\n
Nella cartella "test" sono presenti diversi file eseguibili e i corrispondenti sorgenti in linguaggio C che presentano le vulnerabilità da individuare e possono essere utilizzati come test. 
