#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>


#define USERS 10
#define NOTES_PER_USER 10
#define CREDS_LEN 0x30


// Structures
typedef struct
{
    char* owner;
    char* note_str;
    unsigned long long length;
    unsigned long long pad;
} note;

typedef struct
{
    size_t in_use;
    note* note_ptr;
} note_overview;

typedef struct
{
    char* name;
    char* password;
    unsigned int index; 
} user;


// Prototypes
// Login menu
void init_buffers();
void create_master_profile();
unsigned int login_menu();
void register_user();
void user_login();
void master_login();
void logged_user();
// User menu
unsigned int user_menu();
unsigned int master_menu();
void master_operations();
void user_operations();
void print_notes(bool is_master);
void delete_note(bool is_master);
void create_note();
void fill_note();
// Utils
char* get_string_of_max(size_t length);
user* get_user_by_name(char* name);

// Global variables
unsigned int users_counter;
unsigned int notes_counter;
user* master;
user* user_array[USERS];
note_overview notes_array[USERS * NOTES_PER_USER];
user* current_user = 0;


int main (int argc, char *argv[])
{
    unsigned int choice;

    init_buffers();
    create_master_profile();
    while (1)
    {
        if (current_user != NULL)
        {
            logged_user();
        }
        choice = login_menu();
        if (choice == 1)
        {
            register_user();
        }
        else if (choice == 2)
        {
            user_login();
        }
        else if (choice == 3)
        {
            master_login();
        }
        else if (choice == 4)
        {
            puts("Bye :)");
            break;
        }
        else
            puts("Invalid option!");
    };
}

void init_buffers()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void create_master_profile()
{
    FILE *f;
    int fsize;

    master = (user*) malloc(sizeof(user));
    master->name = (char*) malloc(20);
    strcpy(master->name, "Master of Notes\x00");
    master->index = 0xFFFFFFFF;
    f = fopen("./password", "rb");
    if (f == NULL) {
        fprintf(stderr, "Error: 'password' file does not exist or cannot be opened.\n");
        exit(EXIT_FAILURE); 
    }
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    master->password = malloc(fsize + 1);
    fread(master->password, fsize, 1, f);
    fclose(f);
    master->password[fsize] = 0;
}

unsigned int login_menu()
{
    unsigned int choice;

    puts("Welcome to Master of Notes!");
    puts("At the moment we have: ");
    puts(" - The one and only Master of notes.");
    printf(" - %u users.\n", users_counter);
    printf(" - %u notes.\n", notes_counter);
    puts("Here is the list of the available operations:");
    puts("1) Register");
    puts("2) User Login");
    puts("3) Master Login");
    puts("4) Quit");
    printf(" > ");
    scanf("%u", &choice);
    return choice;
}

char* get_string_of_max(size_t max_length)
{
    char *str;
    size_t n_read;

    str = (char*) malloc(max_length);
    n_read = read(0, str, (max_length - 1));
    str[n_read] = '\0';
    return str;
}

user* get_user_by_name(char* name)
{
    unsigned int i;

    for (i = 0; i < USERS; i++)
    {
        if (user_array[i] == NULL)
            continue;
        if (strcmp(name, user_array[i]->name) == 0)
        {
            return user_array[i];
        }
    }
    return NULL;
}

void register_user()
{
    unsigned int index, n_read;
    bool found;
    user* new_user;
    user* tmp_user;

    // Looking for available slot
    found = false;
    for (index = 0; index < USERS; index++)
    {
        if (user_array[index] == NULL)
        {
            found = true;
            break;
        }
    }
    if(!found)
    {
        puts("No more space for a new user :(");
        return;
    }
    // Creating the slot
    new_user = (user*) malloc(sizeof(user));
    // Fixing index
    new_user->index = index;
    // Getting name
    printf("Name: ");
    new_user->name = get_string_of_max(CREDS_LEN);
    if (strlen(new_user->name) <= 3)
    {
        puts("Name too short!");
        return;
    }
    // Checking if name does not exist!
    tmp_user = get_user_by_name(new_user->name);
    if (tmp_user)
    {
        puts("Name already taken!");
        return;
    }
    // Getting password
    printf("Password: ");
    new_user->password = get_string_of_max(CREDS_LEN);
    if (strlen(new_user->password) <= 3)
    {
        puts("Password too short!");
        return;
    }
    // Inserting new user
    user_array[index] = new_user;
    users_counter++;
    puts("User created!");
}

void user_login()
{
    unsigned int i;
    char* name_tmp;
    char* password_tmp;
    user* tmp_user;
    bool found;

    printf("Name: ");
    name_tmp = get_string_of_max(CREDS_LEN);
    tmp_user = get_user_by_name(name_tmp);
    free(name_tmp);
    if (!tmp_user)
    {
        puts("User not found!");
        return;
    }
    printf("Password: ");
    password_tmp = get_string_of_max(CREDS_LEN);
    if (strcmp(password_tmp, tmp_user->password))
    {
        puts("Wrong password!");
        free(password_tmp);
        return;
    }
    free(password_tmp);
    current_user = tmp_user;
    puts("Logged in!");
}

void master_login()
{
    char* password_tmp;

    puts("Ohhh one and only, provide me your password.");
    printf("Password: ");
    password_tmp = get_string_of_max(CREDS_LEN);
    if (strcmp(password_tmp, master->password))
    {
        puts("Your not the one >:( Go away!!!");
        free(password_tmp);
        return;
    }
    free(password_tmp);
    current_user = master;
    puts("Welcome milord!");
}

void logged_user()
{
    while (1)
    {
        if (current_user == NULL)
        {
            break;
        }
        if (current_user == master)
            master_operations();
        else
            user_operations();
    };
}

void create_note()
{
    unsigned int user_index;
    unsigned long long note_idx;
    note* tmp_note;

    // Looking for available slot
    user_index = current_user->index;
    printf("Index: ");
    scanf("%llu", &note_idx);
    if (note_idx >= NOTES_PER_USER)
    {
        puts("Index out of bound!");
        return;
    }
    note_idx += (user_index * NOTES_PER_USER);
    if (notes_array[note_idx].in_use)
    {
        puts("Note already in use!");
        return;
    }
    // Creating note
    tmp_note = (note*) malloc(sizeof(note));
    tmp_note->owner = (char*) malloc(CREDS_LEN);
    strcpy(tmp_note->owner, current_user->name);
    printf("Note size: ");
    scanf("%llu", &tmp_note->length);
    if (tmp_note->length > 0x10000)
    {
        puts("Note too big");
        free(tmp_note);
        return;
    }
    tmp_note->note_str = (char*) malloc(tmp_note->length);
    notes_array[note_idx].in_use = 1;
    notes_array[note_idx].note_ptr = tmp_note;
    notes_counter++;
    puts("Note created");
}

void fill_note()
{
    unsigned int user_index;
    unsigned long long note_idx, note_length;
    size_t n_read;
    char* note_str;

    // Looking for available slot
    user_index = current_user->index;
    printf("Index: ");
    scanf("%llu", &note_idx);
    if (note_idx > NOTES_PER_USER)
    {
        puts("Index out of bound!");
        return;
    }
    note_idx += (user_index * NOTES_PER_USER);
    if (!notes_array[note_idx].in_use)
    {
        puts("Note not created yet!");
        return;
    }
    printf("Content: ");
    note_str = notes_array[note_idx].note_ptr->note_str;
    note_length = notes_array[note_idx].note_ptr->length;
    n_read = read(0, note_str, note_length - 1);
    puts("Note filled");
}

void delete_note(bool is_master)
{
    unsigned long long note_idx;

    printf("Index: ");
    scanf("%llu", &note_idx);
    if (!is_master)
    {
        note_idx += (current_user->index * NOTES_PER_USER);
        if (!notes_array[note_idx].in_use)
        {
            puts("Note not in use!");
            return;
        }
        if (strcmp(notes_array[note_idx].note_ptr->owner, current_user->name))
        {
            puts("Not your note!");
            return;
        }
    }
    free(notes_array[note_idx].note_ptr->note_str);
    free(notes_array[note_idx].note_ptr->owner);
    free(notes_array[note_idx].note_ptr);
    notes_array[note_idx].in_use = 0;
    notes_counter--;
}

void print_notes(bool is_master)
{
    unsigned long long start_index, end_index, index;
    note* tmp_note;

    if (is_master)
    {
        start_index = 0;
        end_index = USERS * NOTES_PER_USER;
    }
    else
    {
        start_index = current_user->index * NOTES_PER_USER;
        end_index = (current_user->index + 1) * NOTES_PER_USER;
    }
    puts("Notes:");
    for (index = start_index; index < end_index; index++)
    {
        tmp_note = notes_array[index].note_ptr;
        if (!notes_array[index].in_use)
            continue;
        if (is_master)
            printf("[%3llu] Owner: %s\n      Note: %s\n", index, tmp_note->owner, tmp_note->note_str);
        else
            printf("[%3llu] Note: %s\n", index, tmp_note->note_str);
    }
    printf("\n");
}

void logout()
{
    current_user = NULL;
}

unsigned int master_menu()
{
    unsigned int choice;

    puts("Master menu:");
    puts("1) Print notes.");
    puts("2) Delete note.");
    puts("3) Log out.");
    puts("4) Quit");
    printf(" > ");
    scanf("%u", &choice);
    return choice;
}

unsigned int user_menu()
{
    unsigned int choice;

    puts("User menu:");
    puts("1) Create note.");
    puts("2) Fill note.");
    puts("3) Print notes.");
    puts("4) Delete note.");
    puts("5) Log out.");
    puts("6) Quit");
    printf(" > ");
    scanf("%u", &choice);
    return choice;
}

void master_operations()
{
    unsigned int choice;

    choice = master_menu();
    if (choice == 1)
        print_notes(true);
    else if (choice == 2)
        delete_note(true);
    else if (choice == 3)
        logout();
    else if (choice == 4)
    {
        puts("Bye :)");
        return;
    }
    else
        puts("Invalid option!");        
}

void user_operations()
{
    unsigned int choice;

    choice = user_menu();
    if (choice == 1)
        create_note();
    else if (choice == 2)
        fill_note();
    else if (choice == 3)
        print_notes(false);
    else if (choice == 4)
        delete_note(false);
    else if (choice == 5)
        logout();
    else if (choice == 6)
    {
        puts("Bye :)");
        return;
    }
    else
        puts("Invalid option!");        
}