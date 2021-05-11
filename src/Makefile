CC ?= /usr/bin/cc
CFLAGS += -O3 -march=native -fomit-frame-pointer \
	  -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith
LIBS = -lcrypto -loqs
RM = /bin/rm

LIB = libkop.a
HEADERS = params.h group.h ot.h pet.h common.h randombytes.h
OBJECTS = group.o ot.o pet.o common.o randombytes.o

$(LIB): $(OBJECTS)
	$(AR) -r $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(LIB)
	$(CC) test.c $(CFLAGS) -o $@ $^ -lm $(LIBS) $(LIB)

.PHONY: clean

clean:
	-$(RM) $(OBJECTS)
	-$(RM) $(LIB)
	-$(RM) ./test

