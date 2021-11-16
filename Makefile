
# Set our default programs
CC = gcc
AR = ar
RM = rm -f
DIFF = diff
TAR = tar
FIND = find
INSTALL = install
TCL_PATH = tclsh
TCLTK_PATH = wish
XGETTEXT = xgettext
MSGFMT = msgfmt
CURL_CONFIG = curl-config
GCOV = gcov
STRIP = strip
SPATCH = spatch

AUD_VERSION := "$(shell git describe --abbrev=8 --dirty --always --tags)"
BUILD_DATE  := "$(shell date)"

C_FLAGS = -Wall -Werror

all: bldaudtab aud

t.o: t.c
	$(CC) $(C_FLAGS) -g -c $?

t: t.o sha.o pipe.o
	$(CC) $(C_FLAGS)  -g -o t t.o sha.o pipe.o -lssl -lcrypto -Wl,-Map=aud.map

pipe.o: pipe.c
	$(CC) $(C_FLAGS) -c -O2 pipe.c

sha.o: sha.c sha.h
	$(CC) $(C_FLAGS)  -c -O2 sha.c

shatest.o: shatest.c sha.h
	$(CC) $(C_FLAGS)  -c -O2 shatest.c

shatest: sha.o shatest.o
	$(CC) $(C_FLAGS)  -o shatest sha.o shatest.o -lssl -lcrypto

bldaudtab.o: bldaudtab.c sha.h
	$(CC) $(C_FLAGS) -O2 -c $?

#audtab.h: aud bldaudtab aud.txt
#	./bldaudtab

aud.o: aud.c audtab.h
	$(CC) $(C_FLAGS) -DAUD_VERSION=\"$(AUD_VERSION)\" -DBUILD_DATE=\"$(BUILD_DATE)\"  -c aud.c

bldaudtab: bldaudtab.o sha.o pipe.o
	$(CC) $(C_FLAGS) -o bldaudtab -O2 bldaudtab.o sha.o pipe.o -lssl -lcrypto

aud: aud.o sha.o pipe.o
	$(CC) $(C_FLAGS)  -o aud aud.o sha.o pipe.o -lssl -lcrypto -Wl,-Map=aud.map

audsum.o: audsum.c
	$(CC) $(C_FLAGS) -O2 -c $?

audsum: audsum.o sha.o pipe.o
	$(CC) $(C_FLAGS)  -o audsum audsum.o sha.o pipe.o -lssl -lcrypto -Wl,-Map=aud.map

clean:
	rm -f *.o
	rm -f aud bldaudtab
	rm -f out1 out2
	rm -f ./libs

install:
	rm -f /usr/local/bin/aud
	ln -s `pwd`/aud /usr/local/bin/.

test:
	./audtst.sh
