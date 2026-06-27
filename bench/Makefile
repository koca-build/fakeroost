CC ?= cc
N ?= 48

SRCS := $(addprefix src/t,$(addsuffix .c,$(shell seq 0 $$(($(N) - 1)))))
OBJS := $(SRCS:.c=.o)

all: $(OBJS)

%.o: %.c
	$(CC) -c $< -o $@

clean:
	rm -f src/*.o

.PHONY: all clean
