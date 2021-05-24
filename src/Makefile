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
HEADERS = pet.h ot.h kem.h kem_ec.h kem_pq.h group.h common.h randombytes.h params.h types.h
OBJECTS = pet.o ot.o kem.o kem_ec.o kem_pq.o group.o common.o randombytes.o

all: $(LIB) $(TESTS)

$(LIB): $(OBJECTS)
	$(AR) -r $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

test_group: test_group.c group.c kem.c common.c randombytes.c \
	group.h common.h kem.h randombytes.h params.h types.h
	$(CC) $(TESTFLAGS) -o $@ $< group.c kem.c kem_ec.c kem_pq.c common.c randombytes.c $(LIBS)

test_kem: test_kem.c kem.c kem_ec.c kem_pq.c common.c randombytes.c \
	kem.h kem_ec.h kem_pq.h common.h randombytes.h params.h types.h
	$(CC) $(TESTFLAGS) -o $@ $< kem.c kem_ec.c kem_pq.c common.c randombytes.c $(LIBS)

test_ot: test_ot.c ot.c kem.c kem_ec.c kem_pq.c group.c common.c randombytes.c \
	ot.h kem.h kem_ec.h kem_pq.h group.h common.h randombytes.h params.h types.h
	$(CC) $(TESTFLAGS) -o $@ $< ot.c kem.c kem_ec.c kem_pq.c group.c common.c randombytes.c $(LIBS)

test_pet: test_pet.c pet.c ot.c kem.c kem_ec.c kem_pq.c group.c common.c randombytes.c \
	pet.h ot.h kem.h kem_ec.h kem_pq.h group.h common.h randombytes.h params.h types.h
	$(CC) $(TESTFLAGS) -o $@ $< pet.c ot.c kem.c kem_ec.c kem_pq.c group.c common.c randombytes.c $(LIBS)

test_speed: test_speed.c $(OBJECTS:.o=.c) $(HEADERS) ds_benchmark.h
	$(CC) $(CFLAGS) -o $@ $< $(OBJECTS:.o=.c) -lm $(LIBS)

.PHONY: clean

clean:
	-$(RM) $(OBJECTS)
	-$(RM) $(LIB)
	-$(RM) $(TESTS)

