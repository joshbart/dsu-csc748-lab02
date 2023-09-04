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

int read_nums(int *input) {

	int count, num;

	count = 0;
	while (1) {

		printf("Enter a number: ");
		scanf("%d", &num);

		if (num == -1) {
			break;
		} else {
			input[count++] = num;
		}

	}

	return count;

}

int add_them_up(int *input, int count) {

	int total, i;

	total = 0;
	for (i=0; i<count; i++)
		total += input[i];

	return total;

}

int main() {

	int input[8], count, total = 50004;

	init();

	printf("This one has no silly 'jmp rsp' or 'call rsp' instructions.\n");
	printf("Also, there's no character arrays, or gets() function!\n");
	printf("That means it's totally unhackable.... right? :)\n");
	printf("\n");
	printf("Give me a list of integers and I'll add them up for you!\n");
	printf("Enter negative one (-1) to indicate the end of the list.\n");
	printf("\n");

	count = read_nums(input);

	total = add_them_up(input, count);

	printf("\nThe total is: %d\n", total);

	return 0;

}
