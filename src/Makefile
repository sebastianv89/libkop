CC ?= /usr/bin/cc
CFLAGS += -O3 -march=native -fomit-frame-pointer \
	  -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith
LIBS = -lcrypto -loqs
RM = /bin/rm

HEADERS = params.h group.h ot.h pet.h common.h randombytes.h fips202.h
OBJECTS = group.o ot.o pet.o common.o randombytes.o fips202.o 
TESTS = test_common test_group test_ot

example: example.c $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ -lm $(LIBS)

tests: $(TESTS)

test_common: common.c
	$(CC) $(CFLAGS) -DTEST_COMMON=1 -o $@ $^

test_group: group.c randombytes.o fips202.o
	$(CC) $(CFLAGS) -DTEST_GROUP=1 -o $@ $^

test_ot: ot.c group.o common.o randombytes.o fips202.o
	$(CC) $(CFLAGS) -DTEST_OT=1 -o $@ $^ $(LIBS)

test_pet: pet.c ot.o group.o common.o randombytes.o fips202.o
	$(CC) $(CFLAGS) -DTEST_PET=1 -o $@ $^ $(LIBS)

libkop.a: $(OBJECTS)
	$(AR) -r $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-$(RM) -rf *.o *.a
	-$(RM) -rf ./example
	-$(RM) -rf $(TESTS)

