#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>

#define PORT 4000
#define MAX_SELLABLE 50000
#define NAME_LEN 31
#define CMD_LEN 5

struct params {
    int fd;
    int argc;
    char **argv;
    char **envp;
};

// TLS
__thread FILE *fdin;
__thread FILE *fdout;
__thread int fd;

char *flag_path;
char *db_file = "db.txt";
char *staging_area = "staging_area.txt";
char *count_file = "count.txt";

/**
 * @brief Eliminates the staging area without applying changes
 */
void rollback() {
    if (remove(staging_area) < 0)
        fprintf(fdout, "Cannot rollback\n");
}

/**
 * @brief Copies the staging area to the database file
 */
void commit() {
    if (rename(staging_area, db_file) < 0)
        fprintf(fdout, "Cannot commit\n");
}

/**
 * @brief Create a staging area file to store the partial changes
 */
void create_staging_area() {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cp %s %s", db_file, staging_area);
    if (system(cmd) < 0)
        fprintf(fdout, "Cannot create staging area\n");
}

void print_menu() {
    fprintf(fdout, "Commands:\n");
    fprintf(fdout, "queue [name]\n");
    fprintf(fdout, "buy [name]\n");
    fprintf(fdout, "> ");
}

/**
 * @brief Returns the length of a file
 */
int file_len(FILE *f) {
    fseek(f, 0, SEEK_END);
    int size = ftell(f);
    fseek(f, 0, SEEK_SET);
    return size;
}

/**
 * @brief Counts the number of lines in a file
 */
int count_lines(char *file) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cp %s %s", db_file, count_file);
    if (system(cmd) < 0) {
        fprintf(fdout, "Cannot create count file\n");
        return -1;
    }
    FILE *f = fopen(file, "r");
    int count = 0;
    char c;
    while ((c = fgetc(f)) != EOF)
        if (c == '\n') count++;
    fclose(f);
    remove(count_file);
    return count;
}

/**
 * @brief Returns the position of a name in the queue
 */
long get_position(char *name, char *db_file) {
    FILE *staging = fopen(staging_area, "r");
    char search[NAME_LEN+2];
    char *buf = malloc(file_len(staging)+1);
    fread(buf, sizeof(char), file_len(staging), staging);
    snprintf(search, sizeof(search), "\n%s\x20", name);
    char *match = strstr(buf, search);
    long pos = match == NULL ? -1 : strtol(match+strlen(name)+1, NULL, 10);
    free(buf);
    fclose(staging);
    return pos;
}

/**
 * @brief Adds a name to the queue appending a line "[name] [position]" to the db file
 */
void queue(char *name) {
    if (access(staging_area, F_OK) == -1) create_staging_area();
    FILE *stage = fopen(staging_area, "r");
    char search[NAME_LEN+2];
    int f_len = file_len(stage);
    char *buf = malloc(f_len+1);
    memset(buf, 0, f_len+1);
    snprintf(search, sizeof(search), "\n%s\x20", name);
    fread(buf, sizeof(char), f_len, stage);
    if (strstr(buf, search) != NULL) {
        fprintf(fdout, "You're already in line\n");
        fclose(stage);
        free(buf);
        return;
    }
    fclose(stage);
    free(buf);
    stage = fopen(staging_area, "a");
    fprintf(stage, "%s ", name);
    fclose(stage);
    int count = count_lines(db_file);
    if (count == -1) {
        rollback();
        return;
    }
    if (access(staging_area, F_OK) == -1) {
        fprintf(fdout, "WTF\n");
        return;
    }
    stage = fopen(staging_area, "a");
    fprintf(stage, "%d\n", count+1);
    fclose(stage);
    commit();
    fprintf(fdout, "You're in line: %d\n", count+1);
}

/**
 * @brief Tries to buy a ticket for a name in the queue
 */
void buy(char *name) {
    if (access(staging_area, F_OK) == -1) create_staging_area();
    int pos = get_position(name, staging_area);
    if (pos <= 0) {
        fprintf(fdout, "You're not in line to buy this ticket\n");
        rollback();
        return;
    }
    if (pos > MAX_SELLABLE) {
        fprintf(fdout, "You arrived too late\n");
        rollback();
        return;
    }
    FILE *flag = fopen(flag_path, "r");
    char flag_buf[1024];
    fread(flag_buf, sizeof(char), sizeof(flag_buf), flag);
    fprintf(fdout, "Here's your ticket!\n\n%s\n", flag_buf);
    fclose(flag);
    commit();
}

void challenge() {
    char cmd[CMD_LEN+1], param[NAME_LEN+1];
    while (1) {
        print_menu();
        if (fscanf(fdin, "%5s %31s", cmd, param) < 2) break; // Here values NAME_LEN and CMD_LEN
        if (strcmp(cmd, "queue") == 0) queue(param);
        else if (strcmp(cmd, "buy") == 0) buy(param);
        else break;
        fprintf(fdout, "\n");
    }
}

void sigpipe_handler(int signum) {
    pthread_exit(NULL);
}

void *run_thread(void *arg) {
    struct params *p = (struct params *)arg;
    fd = p->fd;
    fdin = fdopen(fd, "r");
    fdout = fdopen(fd, "w");
    if (fdin == NULL || fdout == NULL) {
        fprintf(stderr, "Cannot open file descriptors\n");
        exit(1);
    }
    setvbuf(fdin, NULL, _IONBF, 0);
    setvbuf(fdout, NULL, _IONBF, 0);
    challenge();
    close(fd);
    return 0;
}

int main(int argc, char **argv, char **envp) {
    int fd;
    pthread_t thread;
    struct params *p;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    flag_path = getenv("FLAG_PATH");
    if (flag_path == NULL)
        flag_path = "./flag";
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Cannot create socket\n");
        exit(1);
    }
    
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr = {htonl(INADDR_ANY)}
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot bind socket\n");
        exit(1);
    }
    if (listen(fd, 1) < 0) {
        fprintf(stderr, "Cannot listen on socket\n");
        exit(1);
    }
    if (getsockname(fd, (struct sockaddr *)&addr, &(socklen_t){sizeof(addr)}) < 0) {
        fprintf(stderr, "Cannot get socket name\n");
        exit(1);
    }
    printf("Listening on port: %d\n", ntohs(addr.sin_port));
    signal(SIGPIPE, sigpipe_handler);
    while (1) {
        int client_fd = accept(fd, NULL, NULL);
        if (client_fd < 0) {
            fprintf(stderr, "Cannot accept connection\n");
            exit(1);
        }
        p = (struct params *) malloc(sizeof(struct params));
        p->fd = client_fd; 
        p->argc = argc;
        p->argv = argv;
        p->envp = envp;
        pthread_create(&thread, NULL, run_thread, p);
    }
    return 1;
}