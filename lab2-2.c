#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void nothing_to_see_here() {

	int i, j = 0;

	for (i=0; i<54528; i++) {
		j = j + 1;
	}

}

void sig_handler(int signum) {

	printf("Timeout\n");
	exit(0);

}

void init() {

	alarm(60);
	signal(SIGALRM, sig_handler);

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	chdir(getenv("HOME"));

}

int main() {

	char buff[128];

	init();

	printf("Hello! What's your name?: ");

	gets(buff);

	printf("Nice to meet you %s\n", buff);

	return 0;

}
