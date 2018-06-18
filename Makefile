CFLAGS += -std=c99 -Wall -Wextra -Werror -pedantic -D_DEFAULT_SOURCE
CFLAGS += -O3 -g3

PROGRAM = ubitcoind
SOURCES = $(shell ls *.c)
OBJECTS = $(SOURCES:%.c=%.o)

.PHONY: all clean

all: $(PROGRAM)

clean:
	@rm -f *.o *.d $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	@echo LD $@
	@$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	@echo CC $<
	@$(CC) $(CFLAGS) -o $@ -c $<
	@$(CC) -MF $(@:%.o=%.d) -MM $<

-include *.d
