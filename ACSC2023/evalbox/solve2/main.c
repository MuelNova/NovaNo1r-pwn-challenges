#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
	DIR *dp;
	struct dirent *dirp;

	dp = opendir(".");

	while ((dirp = readdir(dp)) != NULL)
		printf("%s\n", dirp->d_name);
	return 0;
}

// musl-gcc main.c -o main -static -Os && strip main