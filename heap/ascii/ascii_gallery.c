#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>
#include "art.h"        // => cannot fuzz with docker, this file is not provided

#define MAXPIC 10

typedef struct{
    char *name;
    int artsz;
    char *art;
    uint8_t deletable;
} picture;

int random_fd = -1;
picture *pics[MAXPIC];

void init_random(void){         // never called
    random_fd = open("/dev/urandom", O_RDONLY);
    if (random_fd < 0){
        puts("Failed Initialize random!");
        exit(-1);
    }
}

int rand_int(void){             // never called, so we can 
    int ret;
    read(random_fd, &ret, sizeof(ret));
    return ret;
}

long long get_int(){
    int num;
    char buf[200];                  // <-- maybe 200 digits are a bit too much for a long long int
    read(0, buf, sizeof(buf));
    return atoll(buf);
}

void get_name(char *name, int size){
    char c = 0;
    int i = 0;
    read(0, &c, 1);
    while (c != '\n' && i < size-1){
        name[i] = c;
        read(0, &c, 1);
        ++i;
    }
    name[i] = 0;        // poison null byte?
}

int add_art(char *name, int artsz, char *art, uint8_t deletable){
    for(int i=0; i < MAXPIC; ++i){
        if (pics[i] == NULL){
            pics[i] = malloc(sizeof(picture));
            pics[i]->name = name;
            pics[i]->artsz = artsz;
            pics[i]->art = art;
            pics[i]->deletable = deletable;
            return 1;
        }
    }
    return 0;
}

void new_art(){
    long long nmsize, artsz;
    char *name = malloc(100);
    printf("name> ");
    get_name(name, 100);
    printf("art sz> ");
    artsz = get_int();
    char *art = malloc(artsz);
    read(0, art, artsz);
    if(!add_art(name, artsz, art, 1)){
        free(name);
        free(art);
    }
}

void edit_art(int i){
    int artsz;
    if (pics[i] == NULL){
        puts("This space is blank.");
        return;
    }
    printf("name> ");
    get_name(pics[i]->name, 100);       // if you modify toh (art #0) this gives segmentation fault because it's stored in a non-writable area
    printf("art sz> ");
    artsz = get_int();
    read(0, pics[i]->art, artsz);       // we can write on next chunk if new size > prev size
}

void init_art(){
    add_art("toh", strlen(TOH), TOH, 0);
}

void print_art(int i){
    if (pics[i] == NULL){
        puts("This space was intentionally left blank.");
        return;
    }
    printf("\t***\t [%s] \t***\n", pics[i]->name);
    write(1, pics[i]->art, pics[i]->artsz);
    puts("\n");
}

void list_art(){
    int i;
    for (i = 0; i < MAXPIC; ++i){
        if (pics[i] != NULL){
            printf("%d. %s\n", i, pics[i]->name);
        }
    }
}

void list_and_print(){
    list_art();
    printf("art#> ");
    print_art(get_int());
}

void list_and_edit(){
    list_art();
    printf("art#> ");
    edit_art(get_int());
}

void delete_art(int i){
    if (pics[i] == NULL){
        puts("This space is blank.");
        return;
    }
    printf("%s was deleted\n", pics[i]->name);
    if (pics[i]->deletable){
        free(pics[i]->name);
        free(pics[i]->art);
    }
    free(pics[i]);
    pics[i] = NULL;
}

void list_and_delete(){
    list_art();
    printf("art#> ");
    delete_art(get_int());
}

void menu(){
    puts("");
    puts("**************");
    puts("0. New Art");
    puts("1. Print Art");
    puts("2. Delete Art");
    puts("3. Edit Art");
    puts("4. Exit");
}

int main() {
    int choice;

    setvbuf(stdin, NULL, _IONBF, 0); 
    setvbuf(stdout, NULL, _IONBF, 0); 
    setvbuf(stderr, NULL, _IONBF, 0); 
    init_art();
    while (2){
        menu();
        printf("> ");
        switch(get_int()){
            case 0:
                new_art();
                break;
            case 1:
                list_and_print();
                break;
            case 2:
                list_and_delete();
                break;
            case 3:
                list_and_edit();
                break;
            default:
                exit(0);
        }
    }
}

