CC ?= /usr/bin/cc
CFLAGS += -O3 -DNDEBUG -march=native -fomit-frame-pointer \
	  -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith
LIBS = -lcrypto -loqs
RM = /bin/rm
TESTFLAGS = -g -O0 -UNDEBUG -march=native \
	    -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith

LIB = libkop.a
HEADERS = params.h group.h ot.h pet.h common.h
OBJECTS = group.o ot.o pet.o common.o

$(LIB): $(OBJECTS)
	$(AR) -r $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

test: test.c $(OBJECTS:.o=.c) $(HEADERS)
	$(CC) $(TESTFLAGS) -o $@ $< $(OBJECTS:.o=.c) $(LIBS)

test_speed: test_speed.c $(OBJECTS:.o=.c) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJECTS:.o=.c) -lm $(LIBS)

.PHONY: clean

clean:
	-$(RM) $(OBJECTS)
	-$(RM) $(LIB)
	-$(RM) ./test ./test_speed

