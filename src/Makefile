CC ?= /usr/bin/cc
CFLAGS += -O3 -DNDEBUG -march=native -fomit-frame-pointer \
	  -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith
LIBS = -lcrypto -loqs
RM = /bin/rm
TESTFLAGS = -g -O0 -UNDEBUG -march=native \
	    -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith

LIB = libkop.a
HEADERS = params.h group.h ot.h pet.h common.h randombytes.h
OBJECTS = group.o ot.o pet.o common.o randombytes.o

$(LIB): $(OBJECTS)
	$(AR) -r $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

test: test.c $(LIB)
	$(CC) $(TESTFLAGS) -o $@ $< $(LIB) $(LIBS) $(LIB)

test_speed: test_speed.c group.c ot.c pet.c common.c randombytes.c
	$(CC) $(CFLAGS) -o $@ $^ -lm -lcrypto -loqs

.PHONY: clean

clean:
	-$(RM) $(OBJECTS)
	-$(RM) $(LIB)
	-$(RM) ./test ./test_speed

