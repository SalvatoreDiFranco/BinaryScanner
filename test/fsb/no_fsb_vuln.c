#include <stdio.h>

int main(int argc, char *argv[]) {
    char str[20];
    gets(str);
    printf("%s", argv[1]);
    return 0;
}