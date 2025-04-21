#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

////////////////////////////////////////
//              STRUCTS               //
////////////////////////////////////////

#define MAX_PAD_NAME 255
#define MAX_PADULI 32
#define REVIEW_LEN 63

const char INIT_ASCII_ART[] = "\033[44m\n"
"                                                     ___\n"
"                                                  ,o88888\n"
"                                               ,o8888888'\n"
"                         ,:o:o:oooo.        ,8O88Pd8888\"\n"
"                     ,.::.::o:ooooOoOoO. ,oO8O8Pd888'\"\n"
"                   ,.:.::o:ooOoOoOO8O8OOo.8OOPd8O8O\"\n"
"                  , ..:.::o:ooOoOOOO8OOOOo.FdO8O8\"\n"
"                 , ..:.::o:ooOoOO8O888O8O,COCOO\"\n"
"                , . ..:.::o:ooOoOOOO8OOOOCOCO\"\n"
"                 . ..:.::o:ooOoOoOO8O8OCCCC\"o\n"
"                    . ..:.::o:ooooOoCoCCC\"o:o\n"
"                    . ..:.::o:o:,cooooCo\"oo:o:\n"
"                 `   . . ..:.:cocoooo\"'o:o:::'\n"
"                 .`   . ..::ccccoc\"'o:o:o:::'\n"
"                :.:.    ,c:cccc\"':.:.:.:.:.'\n"
"              ..:.:\"'`::::c:\"'..:.:.:.:.:.'\n"
"            ...:.'.:.::::\"'    . . . . .'\n"
"           .. . ....:.\"' `   .  . . ''\n"
"         . . . ....\"'\n"
"         .. . .\"'     -hrr-\n"
"        .\n"
"\033[49m";

typedef struct {
    char name[MAX_PAD_NAME+1];
    float weight;
} Padulo;

typedef struct {
    Padulo* pdlPtr[MAX_PADULI];
    long long size;
} PadulationList;

////////////////////////////////////////
//              GLOBALS               //
////////////////////////////////////////

char rewiew[REVIEW_LEN + 1];

PadulationList padulations;

////////////////////////////////////////
//              FUNCTIONS             //
////////////////////////////////////////

void consumeStdin() {
    char c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void printMenu(){
    puts("------ MENU ------");
    puts("1. Add a padulo");
    puts("2. Subpadulate");
    puts("3. List all paduli");
    puts("4. Leave a review");
    puts("5. Exit");
    puts("------------------");
    puts("");
}

void addPadulo() {
    Padulo* newElement = NULL;
    size_t nameLen;

    if (padulations.size >= MAX_PADULI) {
        puts("Your soul cannot sustain more paduli!");
        puts("There is only one way out of this...");
        puts("You shall have to subpadulate something!");
    } else {
        newElement = (Padulo*)malloc(sizeof(Padulo));
        // Insert the new element at the end of the list
        padulations.pdlPtr[padulations.size] = newElement;
        padulations.size++;
        printf("May god have mercy on your soul! Enter the name of the padulo: ");
        nameLen = read(0, newElement->name, MAX_PAD_NAME);
        if (nameLen < 0) {
            puts("The universe cannot read your padulo...");
            puts("Some padulations are too dark for the stars to see...");
            puts("The void has claimed you...");
            exit(1);
        }
        newElement->name[nameLen] = 0;
        printf("And how much, pray tell, does this padulo weigh?\n> ");
        if (scanf("%f", &newElement->weight) != 1) {
            consumeStdin();
            newElement->weight = -1.0;
        }       
        if (newElement->weight < 0) {
            puts("You have been tampering with the forces of the universe...");
            puts("The stars do not take kindly to such actions...");
            puts("You have been cast into the void...");
            exit(1);
        }
        puts("As it was foretold, you have been padulated!");
    }
    puts("");
}

void subpadulate() {
    long long index;
    long long i;

    puts("It is as shall be, the time has come to subpadulate...");
    if (padulations.size == 0) {
        puts("But alas, you have no paduli to subpadulate...");
        puts("Your luck is as the stars, ever changing...");
    } else {
        puts("The universe is a delicate balance...");
        puts("To subpadulate is to restore harmony...");
        printf("Your soul is burdened by %lld paduli.\nWhich padulo do you wish to be rid of?\n> ", padulations.size); 
        if (scanf("%lld", &index) != 1) {
            consumeStdin();
            puts("The stars tell of your future padulations...");
            printf("But you may only act within the bounds of the present...\n> ");
            return;
        }
        if (index >= padulations.size) {
            puts("The stars tell of your future padulations...");
            printf("But you may only act within the bounds of the present...\n> ");
            return;
        }
        free(padulations.pdlPtr[index]);
        // Shift all elements after the deleted one to the left
        for (i = index; 0 <= i && i < padulations.size - 1; i++) {
            padulations.pdlPtr[i] = padulations.pdlPtr[i + 1];
        }
        padulations.size--;
        puts("The deed is done...");
        puts("Another soul has been padulated...");
    }
    puts("");
}

void listPaduli() {
    long long i;

    puts("You dare gaze upon your own fate?");
    puts("May god have mercy on your soul...");
    if (padulations.size == 0) {
        puts("But alas, you have no paduli to gaze upon...");
        puts("Your luck is as the stars, ever changing...");
    } else {
        puts("The universe is a delicate balance...");
        puts("To list your paduli is to know your own soul...");
        for (i = 0; i < padulations.size; i++) {
            // Little anti-hacker checks
            if (padulations.pdlPtr[i]->weight < 0) {
                puts("You have been tampering with the forces of the universe...");
                puts("The stars do not take kindly to such actions...");
                puts("You have been cast into the void...");
                exit(1);
            }
            // Safe to print
            printf("%lld. %s - %.2f\n", i, padulations.pdlPtr[i]->name, padulations.pdlPtr[i]->weight);
        }
    }
    puts("");
}

void leaveReview() {
    size_t reviewLen;

    puts("This string of bits that is being executed by your CPU has itself been produced by a padulation...");
    puts("The Law of the universe padulated the dev, the dev padulated the compiler, the compiler padulated the binary...");
    puts("And now, the binary padulates you...");
    puts("You may leave a review for the universe... so that it may hear you lament your fate...");
    printf("Enter your review: ");
    reviewLen = read(STDIN_FILENO, rewiew, REVIEW_LEN);
    if (reviewLen < 0) {
        puts("The words you whisper are lost in the void...");
        puts("I'm afraid the universe cannot hear you...");
        puts("The void is once again asking for your soul...");
        exit(1);
    }
    rewiew[reviewLen] = 0;
    puts("Your review has been noted...");
    puts("The stars will remember your words...");
    puts("");
}

int main(int argc, char** argv) {
    int choice = 0;

    // A timely padulation is a good padulation
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts(INIT_ASCII_ART);
    puts("\033[36m");
    puts("In the beginning, there was the void...");
    puts("Once the first spark was lit, the universe was born...");
    puts("The sun padulates the earth, and the earth padulates the moon...");
    puts("The universe lies in a delicate balance, and each of us must bear our own paduli...");
    puts("Keep track of your paduli, or you may risk losing yourself to the void...");
    puts("\033[0m");
    while (1) {
        printMenu();
        printf("Enter your choice: ");
        if (scanf("%d", &choice) != 1) {
            consumeStdin();
            choice = 0;
        }
        switch (choice) {
            case 1:
                addPadulo();
                break;
            case 2:
                subpadulate();
                break;
            case 3:
                listPaduli();
                break;
            case 4:
                leaveReview();
                break;
            case 5:
                puts("Goodbye!");
                return 0;
            default:
                puts("Invalid choice!");
                break;
        }
    }
}