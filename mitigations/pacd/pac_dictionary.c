#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#define PORT 4000
#define DICT_SIZE 466
#define KEY_SIZE 0x18
#define STRING_SIZE 0x20

enum dict_type {
    SVAL = 0,
    UIVAL = 1,
    IVAL = 2,
    ULLVAL = 3,
    LLVAL = 4
};

struct dict {
    char key[KEY_SIZE];
    enum dict_type type;
    union {
        char sval[STRING_SIZE];
        unsigned int uival;
        int ival;
        unsigned long long ullval;
        long long llval;
    };
};

// Prototypes
void print_string(struct dict *);
void print_int(struct dict *);
void print_long_long(struct dict *);
void print_unsigned_int(struct dict *);
void print_unsigned_long_long(struct dict *);
void get_string(struct dict*);
void get_int(struct dict*);
void get_long_long(struct dict*);
void get_unsigned_int(struct dict*);
void get_unsigned_long_long(struct dict*);

// Globals
void (*print_functions[5]) = {print_string, print_unsigned_int, print_int, print_unsigned_long_long, print_long_long};
void (*get_functions[5]) = {get_string, get_unsigned_int, get_int, get_unsigned_long_long, get_long_long};
char* flag_path;
struct dict dictionary[DICT_SIZE];
uint8_t key[16];
int c_fd;
FILE *c_stdin;
FILE *c_stdout;

// Function to exit the program
void exit_prog(int exit_val) {
    if (c_stdin != NULL)
        fclose(c_stdin);
    if (c_stdout != NULL)
        fclose(c_stdout);
    close(c_fd);
    exit(exit_val);
}

// Signal handler for SIGCHLD to reap zombie processes
void sigchld_handler(int signo) {
    // Use waitpid in a loop to reap all child processes that have terminated
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// Signal handler for SIGALRM to exit the program
void sigalrm_handler(int signo) {
    fprintf(c_stdout, "Timeout!!!\n");
    exit_prog(1);
}

// Win function
void win() {
  FILE * fp;
  char ch;

  fp = fopen(flag_path, "r");
  if (fp == NULL) {
    fprintf(c_stdout, "Failed to open flag file!\n");
    return;
  }
  write(c_fd, "The flag is: ", 13);
  while((ch = fgetc(fp)) != EOF)
    write(c_fd, &ch, 1);
}

// Function to consume stdin
void consume_stdin() {
    char c;

    while ((c = fgetc(c_stdin)) != '\n' && c != EOF);
}

// Functions to print the values of the dictionary
void print_string (struct dict *entry) {
    fprintf(c_stdout, "Value: %s\n", entry->sval);
}

void print_int (struct dict *entry) {
    fprintf(c_stdout, "Value: %d\n", entry->ival);
}

void print_long_long (struct dict *entry) {
    fprintf(c_stdout, "Value: %lld\n", entry->llval);
}

void print_unsigned_int (struct dict *entry) {
    fprintf(c_stdout, "Value: %u\n", entry->uival);
}

void print_unsigned_long_long (struct dict *entry) {
    fprintf(c_stdout, "Value: %llu\n", entry->ullval);
}

// Functions to get values for the dictionary
void get_string(struct dict *entry) {
    if (read(c_fd, entry->sval, STRING_SIZE - 1) < 0) {
        fprintf(c_stdout, "Failed to read value :/\n");
        return;
    }
}

void get_int(struct dict *entry) {
    if (fscanf(c_stdin, "%d", &entry->ival) != 1) {
        consume_stdin();
        fprintf(c_stdout, "Invalid value!!!\n");
        entry->ival = 0;
        return;
    }
}

void get_long_long(struct dict *entry) {
    if (fscanf(c_stdin,"%lld", &entry->llval) != 1) {
        consume_stdin();
        fprintf(c_stdout, "Invalid value!!!\n");
        entry->llval = 0;
        return;
    }
}

void get_unsigned_int(struct dict *entry) {
    if (fscanf(c_stdin,"%u", &entry->uival) != 1) {
        consume_stdin();
        fprintf(c_stdout, "Invalid value!!!\n");
        entry->uival = 0;
        return;
    }
}

void get_unsigned_long_long(struct dict *entry) {
    if (fscanf(c_stdin,"%llu", &entry->ullval) != 1) {
        consume_stdin();
        fprintf(c_stdout, "Invalid value!!!\n");
        entry->ullval = 0;
        return;
    }
}

// Functions to generate and check signatures
void keygen() {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        exit(1);
    }
    if (read(fd, &key, 16) != 16) {
        perror("read");
        exit(1);
    }
    close(fd);
}

uint16_t get_signature (uint64_t p_ptr) {
    uint8_t *signature;
    uint64_t message = p_ptr;

    signature = HMAC(EVP_md5(), key, 16, (uint8_t*)&message, 6, NULL, NULL);
    if (signature == NULL) {
        fprintf(c_stdout, "Failed to generate signature\n");
        exit_prog(1);
    }
    return ((uint16_t*) signature)[0];
}

uint64_t sign_pointer (uint64_t p_ptr) {
    return ((uint64_t) get_signature(p_ptr)) << 48 | p_ptr;
}

void check_signed_ptr(uint64_t s_ptr) {
    uint16_t signature = s_ptr >> 48;
    uint64_t p_ptr = s_ptr & 0x0000FFFFFFFFFFFF;
    if (signature != get_signature(p_ptr)) {
        fprintf(c_stdout, "*** ERROR: Signature mismatch ***\n");
        exit_prog(1);
    }
}

// Call ptr function, with variadic arguments
void call_ptr(uint64_t s_ptr, struct dict *entry) {
    check_signed_ptr(s_ptr);
    void (*func_ptr)() = (void (*)())(s_ptr & 0x0000FFFFFFFFFFFF);
    func_ptr(entry);
}

// Simple hash function
int get_index(char *key) {
    int result;

    result = 0;
    // Xor all the characters of the key 4 by 4
    for (int i = 0; i < KEY_SIZE; i += 4) {
        result ^= *(int*)(key + i);
    }
    return result;
}

// Main program functions
void print_menu() {
    fprintf(c_stdout, "1. Add entry\n");
    fprintf(c_stdout, "2. Remove entry\n");
    fprintf(c_stdout, "3. Print entry\n");
    fprintf(c_stdout, "4. Exit\n");
}

void add_entry() {
    char tmp_key[KEY_SIZE] = {0};
    enum dict_type type;
    int index;

    fprintf(c_stdout, "Enter key: ");
    if (read(c_fd, tmp_key, KEY_SIZE-1) < 0) {
        fprintf(c_stdout, "Failed to read key :/\n");
        return;
    }
    fprintf(c_stdout, "Enter type (0: string, 1: unsigned int, 2: int, 3: unsigned long long, 4: long long): ");
    if (fscanf(c_stdin,"%u", &type) != 1) {
        consume_stdin();
        fprintf(c_stdout, "Invalid type!!!\n");
        return;
    }
    if (type > 4) {
        fprintf(c_stdout, "Invalid type!!!\n");
        return;
    }
    index = abs(get_index(tmp_key)) % DICT_SIZE;
    fprintf(c_stdout, "Enter value: ");
    call_ptr((uint64_t) get_functions[type], &dictionary[index]);
    strncpy(dictionary[index].key, tmp_key, KEY_SIZE-1);
    dictionary[index].type = type;
    fprintf(c_stdout, "Entry added successfully\n");
}

void remove_entry() {
    char tmp_key[KEY_SIZE] = {0};
    int index;

    fprintf(c_stdout, "Enter key: ");
    if (read(c_fd, tmp_key, KEY_SIZE-1) < 0) {
        fprintf(c_stdout, "Failed to read key :/\n");
        return;
    }
    index = abs(get_index(tmp_key)) % DICT_SIZE;
    if (strncmp(dictionary[index].key, tmp_key, KEY_SIZE-1) != 0) {
        fprintf(c_stdout, "Entry not found!!!\n");
        return;
    }
    memset(&dictionary[index], 0, sizeof(struct dict));
    fprintf(c_stdout, "Entry removed successfully\n");
}

void print_entry() {
    char tmp_key[KEY_SIZE] = {0};
    int index;

    fprintf(c_stdout, "Enter key: ");
    if (read(c_fd, tmp_key, KEY_SIZE-1) < 0) {
        fprintf(c_stdout, "Failed to read key :/\n");
        return;
    }
    index = abs(get_index(tmp_key)) % DICT_SIZE;
    if (strncmp(dictionary[index].key, tmp_key, KEY_SIZE-1) != 0) {
        fprintf(c_stdout, "Entry not found!!!\n");
        return;
    }
    call_ptr((uint64_t) print_functions[dictionary[index].type], &dictionary[index]);
}

void prog() {
    unsigned int choice;

    while (1) {
        print_menu();
        fprintf(c_stdout, "> ");
        if (fscanf(c_stdin,"%u", &choice) != 1) {
            consume_stdin();
            fprintf(c_stdout, "Invalid choice!!!\n");
            continue;
        }
        switch (choice) {
            case 1:
                add_entry();
                break;
            case 2:
                remove_entry();
                break;
            case 3:
                print_entry();
                break;
            case 4:
                fprintf(c_stdout, "See you soon :D\n");
                return;
            default:
                fprintf(c_stdout, "Invalid choice!!!\n");
        }
    }
}

// Forking server
int main() {
    int server_sockfd, client_sockfd;
    int server_len;
    unsigned int client_len;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    const char *timeout_str = getenv("TIMEOUT");
    flag_path = getenv("FLAG_PATH");
    int timeout;

    // Set no buffering for output
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    // Set timeout
    if (timeout_str != NULL) {
        timeout = atoi(timeout_str);
        if (timeout < 0)
            timeout = 10;
    } else
        timeout = 10;
    // Set flag path
    if (flag_path == NULL)
        flag_path = "./flag";
    // Set up SIGCHLD handler
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;  // Automatically restart interrupted system calls
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit_prog(1);
    }
    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd < 0) {
        perror("socket creation failed");
        exit_prog(1);
    }
    // Allow the server to reuse the address/port (optional, but recommended for development/testing)
    int optval = 1;
    if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(server_sockfd);
        exit_prog(1);
    }
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(PORT);
    server_len = sizeof(server_address);
    // Bind the socket and check if the port is already in use
    if (bind(server_sockfd, (struct sockaddr *)&server_address, server_len) < 0) {
        perror("bind failed: port may already be in use");
        close(server_sockfd);
        exit_prog(1);
    }
    /* Create a connection queue, ignore child exit details and wait for
    clients. */
    if (listen(server_sockfd, 5) < 0) {
        perror("listen failed");
        close(server_sockfd);
        exit_prog(1);
    }
    printf("Server listening on port %d\n", PORT);
    printf("Flag is at %s\n", flag_path);
    // Generate key
    keygen();
    // Print the key for debugging
    printf("Key: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", key[i]);
    printf("\n");
    // Sign the dict functions
    for (int i = 0; i < 5; i++) {
        print_functions[i] = (void*) sign_pointer((uint64_t)print_functions[i]);
        get_functions[i] = (void*) sign_pointer((uint64_t)get_functions[i]);
    }
    while(1) {
        /* Accept connection. */
        client_len = sizeof(client_address);
        client_sockfd = accept(server_sockfd,(struct sockaddr *)&client_address, &client_len);
        /* Fork to create a process for this client and perform a test to see
        whether we're the parent or the child. */
        if(fork() == 0) {
            /* If we're the child, we can now read/write to the client on
            client_sockfd. */
            c_fd = client_sockfd;
            c_stdin = fdopen(client_sockfd, "r");
            c_stdout = fdopen(client_sockfd, "w");
            setvbuf(c_stdin, NULL, _IONBF, 0);
            setvbuf(c_stdout, NULL, _IONBF, 0);
            // Registering timeout and its handler
            signal(SIGALRM, sigalrm_handler);
            if (timeout > 0)
                alarm(timeout);
            prog();
            exit_prog(0);
        } else {
            // Parent
            close(client_sockfd);
        }
    }
}