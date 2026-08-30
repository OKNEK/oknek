/* victim.c — deterministic E2E target. Tries to read a credentials file and
 * reports the outcome. Under the oknek shim with a "block" rule, the open
 * must fail with EACCES; without the shim it succeeds. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
	const char *path = (argc > 1) ? argv[1] : "/tmp/oknek_e2e_creds";
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("VICTIM: open(%s) FAILED errno=%d (%s)\n", path, errno, strerror(errno));
		return 7; /* sentinel: blocked */
	}
	char b[64];
	ssize_t n = read(fd, b, sizeof b - 1);
	close(fd);
	if (n < 0) n = 0;
	b[n] = 0;
	printf("VICTIM: open(%s) OK, read %zd bytes\n", path, n);
	return 0; /* allowed */
}
