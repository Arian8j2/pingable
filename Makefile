CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -std=c11 -pedantic

pingable: main.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -f pingable
