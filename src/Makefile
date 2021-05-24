CC ?= /usr/bin/cc
CFLAGS += -O3 -march=native -fomit-frame-pointer \
	  -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith \
	  -I./xkcp/libXKCP.a.headers $(EXTRAFLAGS)
TESTFLAGS = -gdwarf-4 -O0 -DKOP_DEBUG -march=native \
	    -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith \
	    -I./xkcp/libXKCP.a.headers $(EXTRAFLAGS)
LIBS = -L./xkcp -lXKCP -ldecaf -loqs
RM = /bin/rm
TESTS = test_group test_kem test_ot test_pet test_speed

# TODO: implement a way to automatically compile libXKCP

LIB = libkop.a
HEADERS = pet.h ot.h kem.h group.h ec.h pq.h common.h randombytes.h params.h types.h
OBJECTS = pet.o ot.o kem.o group.o ec.o pq.o common.o randombytes.o

all: $(LIB) $(TESTS)

$(LIB): $(OBJECTS)
	$(AR) -r $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

test_speed: test_speed.c $(OBJECTS:.o=.c) $(HEADERS) ds_benchmark.h
	$(CC) $(CFLAGS) -o $@ $< $(OBJECTS:.o=.c) -lm $(LIBS)

test_%: test_%.c $(OBJECTS:.o=.c) $(HEADERS)
	$(CC) $(TESTFLAGS) -o $@ $< $(OBJECTS:.o=.c) $(LIBS)

.PHONY: clean

clean:
	-$(RM) $(OBJECTS)
	-$(RM) $(LIB)
	-$(RM) $(TESTS)

