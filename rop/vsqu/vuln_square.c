#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define NAME_SIZE 0x100

char important_name[NAME_SIZE];

void even_more_vuln() {
    char name[NAME_SIZE];
    register int64_t read_len;

    puts("Hello! What's your name?");
    read_len = read(0, name, NAME_SIZE);
    if (read_len < 0) {
        puts("Error reading input");
        exit(1);
    }
    name[read_len] = 0;
    printf("Nice to meet you %s\n", name);
    puts("I will remember you!");
    memcpy(important_name, name, read_len);
}

void vuln() {
    FILE* files[3] = {stdin, stdout, stderr};
    for (int i = 0; i < 3; i++)
        setvbuf(files[i], NULL, _IONBF, 0);
    even_more_vuln();
}

int main() {
    vuln();
}