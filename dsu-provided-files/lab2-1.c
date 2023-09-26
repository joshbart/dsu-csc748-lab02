#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

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

void win() {

	alarm(0);
	execl("/bin/bash", "/bin/bash", NULL);

}

int main() {

	char buff[64];

	init();

	printf("Hello! What's your name?: ");

	gets(buff);

	printf("Nice to meet you %s!\n", buff);

	return 0;

}
