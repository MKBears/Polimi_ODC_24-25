#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <errno.h>
#include <stdbool.h>

#define PORT 4000
#define SHAPP_ITERS 1
#define FILENAME_LENGTH 32
#define DOLPHIN "\n"\
"                  \\A.\n"\
"                   YAao,\n"\
"                    Y8888b,\n"\
"                  ,oA8888888b,\n"\
"            ,aaad8888888888888888bo,\n"\
"         ,d888888888888888888888888888b,\n"\
"       ,888888888888888888888888888888888b,\n"\
"      d8888888888888888888888888888888888888,\n"\
"     d888888888888888888888888888888888888888b\n"\
"    d888888P'                    `Y888888888888,\n"\
"    88888P'                    Ybaaaa8888888888l\n"\
"   a8888'                      `Y8888P' `V888888\n"\
" d8888888a          -----------           `Y8888\n"\
"AY/'' `\\Y8b           DOLPHIN               ``Y8b\n"\
"Y'      `YP         -----------                ~~\n"\
"         `'\n\n"

struct Operation;
typedef struct Operation Operation;

void sha512(const unsigned char *buf, unsigned char *hash, size_t len);
void win();
void ls(Operation *op);
void create_file(Operation *op);
void read_file(Operation *op);
void write_file(Operation *op);

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

struct Operation {
    void (*func)(struct Operation *op);
    pthread_mutex_t lock;
    uint16_t os;
    char buf[0x100];
};

Operation manager[4] = {
    {read_file, PTHREAD_MUTEX_INITIALIZER, 0, {0}},
    {write_file, PTHREAD_MUTEX_INITIALIZER, 0, {0}},
    {create_file, PTHREAD_MUTEX_INITIALIZER, 0, {0}},
    {ls, PTHREAD_MUTEX_INITIALIZER, 0, {0}},
};

// Just SHA512-based hash for integrity
void sha512(const unsigned char *buf, unsigned char *hash, size_t len)
{
    SHA512_CTX sha_ctx;
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, buf, len);
    SHA512_Final(hash, &sha_ctx);
}

void win() {
    fprintf(fdout, "I'm feeling fucking Santa Claus, today\n");
    fprintf(fdout, "Anyway, it's only because I'm about to change my life and become a dolphin trainer!\n");
    fprintf(fdout, "Wanna join me on this journey?\n\n");
    // Read the flag
    FILE *flag = fopen(flag_path, "r");
    char flag_buf[1024] = {0};
    fread(flag_buf, sizeof(char), sizeof(flag_buf), flag);
    fprintf(fdout, "%s", flag_buf);
    fclose(flag);
}

bool get_filename(char *buf, size_t size) {
    int len;

    fprintf(fdout, "Enter file name: ");
    if ((len = read(fileno(fdin), buf, size)) <= 0) {
        fprintf(fdout, "Failed to read file name\n");
        return false;
    }
    if (buf[len - 1] == '\n') 
        buf[len - 1] = '\0';
    if (strchr(buf, '/') != NULL) { // Prevent path traversal
        fprintf(fdout, "Invalid file name\n");
        return false;
    }
    return true;
}

void print_menu() {
    fprintf(fdout, "I'm your average file explorer\n");
    fprintf(fdout, "Let me help you with:\n");
    fprintf(fdout, "1. Read a file\n");
    fprintf(fdout, "2. Write files\n");
    fprintf(fdout, "3. Create a file\n");
    fprintf(fdout, "4. List a file\n");
    fprintf(fdout, "5. Exit\n");
    fprintf(fdout, "> ");
}

void ls(Operation *op) {
    // List files in the current directory
    fprintf(fdout, "Files in current directory:\n");
    FILE *fp = popen("ls", "r");
    if (fp == NULL) {
        fprintf(fdout, "Failed to run command\n");
        return;
    }
    char path[1035];
    while (fgets(path, sizeof(path), fp) != NULL) {
        fprintf(fdout, "\t- %s", path);
    }
    pclose(fp);
}

void create_file(Operation *op) {
    char buf[FILENAME_LENGTH] = {0};
    int fd;
    
    if (!get_filename(buf, sizeof(buf)))
        return;
    pthread_mutex_lock(&op->lock);
    fd = open(buf, O_WRONLY | O_CREAT | O_EXCL, 0644);            
    if (fd < 0) 
        if (errno == EEXIST) 
            fprintf(fdout, "File %s already exists, not creating\n", buf);
        else 
            fprintf(fdout, "Failed to create file: %s\n", strerror(errno));
    else {
        close(fd);
        fprintf(fdout, "File %s created successfully\n", buf);
    }
    pthread_mutex_unlock(&op->lock);
}

void read_file(Operation *op) {
    char buf[FILENAME_LENGTH] = {0};
    char c;

    if (!get_filename(buf, sizeof(buf))) 
        return;
    pthread_mutex_lock(&op->lock);
    FILE *fp = fopen(buf, "r");
    if (!fp) {
        fprintf(fdout, "Failed to open file: %s\n", strerror(errno));
        pthread_mutex_unlock(&op->lock);
        return;
    }
    // Reading the file
    while ((c = fgetc(fp)) != EOF && c != '\0' && op->os < sizeof(op->buf) - 1) 
        op->buf[op->os++] = c;
    fprintf(fdout, "Contents of %s:\n", buf);
    fprintf(fdout, "=========================\n");
    fprintf(fdout, "%s\n", op->buf);
    fprintf(fdout, "=========================\n");
    fclose(fp);
    op->os = 0;
    pthread_mutex_unlock(&op->lock);
}

void write_file(Operation *op) {
    char buf[FILENAME_LENGTH] = {0};
    unsigned char hash[SHA512_DIGEST_LENGTH];
    char c;
    uint16_t amount;
    int fd;

    if (!get_filename(buf, sizeof(buf))) 
        return;
    fprintf(fdout, "Enter data length: ");
    if (fscanf(fdin, "%hu%*c", &amount) != 1 || amount > sizeof(op->buf) - 1) {
        fprintf(fdout, "Invalid length\n");
        return;
    }
    fprintf(fdout, "Enter data to write: ");
    pthread_mutex_lock(&op->lock);
    while (amount-- > 0 && (c = fgetc(fdin)) != EOF)
        op->buf[op->os++] = c;
    pthread_mutex_unlock(&op->lock);
    // Compute SHA512 hash of the data
    sha512(op->buf, hash, op->os);
    fprintf(fdout, "SHA512 for integrity: ");
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        fprintf(fdout, "%02x", hash[i]);
    fprintf(fdout, "\n");
    // Write the data to the file
    fd = open(buf, O_WRONLY | O_TRUNC, 0); 
    if (fd < 0) {
        fprintf(fdout, "Failed to open file: %s\n", strerror(errno));
        return;
    }
    if (write(fd, op->buf, op->os) != op->os) {
        fprintf(fdout, "Failed to write data: %s\n", strerror(errno));
        close(fd);
        return;
    }
    fprintf(fdout, "Data written to file %s successfully\n", buf);
    close(fd);
    op->os = 0;
    return;
}

void challenge() {
    unsigned int choice;
    char c;

    fprintf(fdout, DOLPHIN);
    while (1) {
        print_menu();
        choice = 0;
        if (fscanf(fdin, "%u%*c", &choice) != 1) 
            c = fgetc(fdin); // Clear the buffer
        switch (choice) {
            case 1:     // read_file
            case 2:     // write_file
            case 3:     // create_file
            case 4:     // ls
                manager[choice - 1].func(&manager[choice - 1]);
                break;
            case 5:
                fprintf(fdout, "Bye!\n");
                return;
            default:
                fprintf(fdout, "Invalid choice\n");
                break;
        }
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
}

int main(int argc, char **argv, char **envp) {
    int fd;
    pthread_t thread;
    struct params *p;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("Starting dolphin server...\n");
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