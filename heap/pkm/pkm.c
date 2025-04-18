#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>


struct pkm;

// sizeof(move) = 8 + 8 = 16 = 0x10
typedef struct move
{
	char* name;
	void (*fun)(struct pkm *, struct pkm *);

} move;

#define PKM_NUM 50
#define MOVE_SIZE 10

// sizeof(pkm) = 4 * 8 + 1 + 8 + 8 + 5 * 8 + 10 * sizeof(move) = 11 * 8 + 1 + 10 * 16 = 249 = 0xf9 > 0x80
typedef struct pkm
{
	uint64_t atk;
	uint64_t def;
	uint64_t hp;
	uint64_t max_hp;
	uint8_t status;
	char *name;
	uint64_t IVs[5];
	move moves[MOVE_SIZE];
} pkm;

pkm *pkms[PKM_NUM] = {0};

void clear_stdin();

void tackle(pkm *me, pkm *o){
	int delta = me->atk - o->def;
	if (delta < 0){
		delta = 0;
	}
	o->hp -= delta;
	if (delta > 0){
		printf("[%%] %s loses %d hp\n", o->name, delta);
	}
	else {
		printf("[%%] %s is safe!\n", o->name);
	}
}
move TACKLE = {.name = "Tackle", .fun = tackle};
move M_EMPTY = {.name = NULL, .fun = NULL};

char *UNKNOWN = "PKM";

// [$esp + 0x30] = 0
char *get_string(){
	uint32_t length=0;
	while (length == 0)
	{
		printf("[.] insert length: ");
		if (scanf("%u", &length) != 1)
			clear_stdin();
	}
	char *s = malloc(length);
	uint32_t i = 0;
	for(i = 0; i < length; i++){
		read(STDIN_FILENO, &s[i], 1);
		if(s[i] == '\n'){
			break;
		}
	}
	s[i] = 0;		// <<<<================ PNB
	return s;
}

pkm *new_pkm(){
	pkm *p = malloc(sizeof(pkm));
	p->name = UNKNOWN;
	p->atk = 40;
	p->def = 10;
	p->hp = 100;
	p->max_hp = 100;
	p->moves[0] = TACKLE;
	for(uint8_t i = 0; i < MOVE_SIZE; i++){
		p->moves[i] = M_EMPTY;
	}
	return p;
}

void add_pkm(){
	puts("[*] New PKM!");
	uint8_t i;
	for(i = 0; i < PKM_NUM && pkms[i] != NULL; i++);
	if(i == PKM_NUM){
		puts("[!] No more free slots for pkms");
		return;
	}
	pkms[i] = new_pkm();
	pkms[i]->IVs[0]=i;
}

void print_pkm_list(){
	for(uint8_t i = 0; i < PKM_NUM; i++){
		if (pkms[i]){
			printf("[%d] %s\n",i,pkms[i]->name);
		}
	}
}

uint8_t get_pkm(){
	uint8_t coiche = 0xff;
	do{
		puts("[*] Choose a PKM!");
		print_pkm_list();
		printf("> ");
		if (scanf("%hhu", &coiche) != 1)
			clear_stdin();
	} while (pkms[coiche] == 0 && coiche < PKM_NUM);
	return coiche;
}

void rename_pkm(){
	puts("[*] Rename PKM!");
	uint8_t coiche = get_pkm();
	if (pkms[coiche]->name && pkms[coiche]->name != UNKNOWN){
		free(pkms[coiche]->name);
	}
	pkms[coiche]->name = get_string();

}

void del_pkm(uint8_t index){
	if(pkms[index]){
		if (pkms[index]->name && pkms[index]->name != UNKNOWN){
			free(pkms[index]->name);
		}
		free(pkms[index]);
	}
	pkms[index] = 0;
}

void delete_pkm(){
	puts("[*] Delete PKM!");
	uint8_t coiche = get_pkm();
	del_pkm(coiche);
}

void print_moves(uint8_t p_index){
	pkm *p = pkms[p_index];
	if (p == 0){
		return;
	} 
	for(uint8_t i; i < MOVE_SIZE; i++){
		if(p->moves[i].fun){
			printf("\t(%d) %s\n", i, p->moves[i].name);
		}
	}
}

move *get_move(uint8_t p_index){
	uint8_t coiche = 0xff;
	do{
		puts("[*] Choose a Move!");
		print_moves(p_index);
		printf("> ");
		if (scanf("%hhu", &coiche) != 1)
			clear_stdin();
	} while (pkms[p_index]->moves[coiche].fun == 0 && coiche < MOVE_SIZE);
	//If there is no valid move you are stuck here!
	return &pkms[p_index]->moves[coiche];
}

void death_checker(uint8_t index){
	pkm *p = pkms[index];
	if(p->hp > 0){
		return;
	}
	printf("[!!!] %s fainted!\n", p->name);
	del_pkm(index);
}

void fight_pkm(){
	puts("[*] Fight PKMs!");
	uint8_t p1 = get_pkm();
	move *m = get_move(p1);
	uint8_t p2 = get_pkm();
	printf("[%%] %s uses %s on %s!\n", pkms[p1]->name, m->name, pkms[p2]->name);
	m->fun(pkms[p1], pkms[p2]);
	death_checker(p2);
}

void info_pkm(){
	puts("[*] Info PKMs!");
	pkm *p = pkms[get_pkm()];
	if(p->name){
		printf(" *Name: %s\n", p->name);
	}
	printf(" *ATK:  %ld\n", p->atk);
	printf(" *DEF:  %ld\n", p->def);
	printf(" *HP:   %ld/%ld\n", p->hp, p->max_hp);
	printf(" *Moves:\n");
	for(uint8_t i; i < MOVE_SIZE; i++){
		if(p->moves[i].fun){
			printf("  (%d) %s\n", i, p->moves[i].name);
		}
	}

}

void print_menu(){
	puts("***************");
	puts("0. Add PKM");
	puts("1. Rename PKM");
	puts("2. Kill PKM");
	puts("3. Fight PKM");
	puts("4. Info PKM");
	puts("5. Exit");
	puts("***************");
}

// [$esp + 0x30] = 0
int main(int argc, char ** argv) {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
	uint8_t coiche;

	while(1){
		coiche = 0xff;
		print_menu();
		printf("> ");
		if (scanf("%hhu", &coiche) != 1)
			clear_stdin();
		switch (coiche)
		{
		case 0:
			add_pkm();
			break;
		case 1:
			rename_pkm();
			break;
		case 2:
			delete_pkm();
			break;
		case 3:
			fight_pkm();
			break;
		case 4:
			info_pkm();
			break;
		case 5:
			exit(0);
			break;		
		default:
			puts("[!] Wrong choice!");
			break;
		}
	}
}

void clear_stdin(){
	char c;
	while((c = getchar()) != '\n' && c != EOF);
}