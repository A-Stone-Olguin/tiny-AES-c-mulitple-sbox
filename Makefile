#CC           = avr-gcc
#CFLAGS       = -Wall -mmcu=atmega16 -Os -Wl,-Map,test.map
#OBJCOPY      = avr-objcopy
CC           = gcc
LD           = gcc
AR           = ar
ARFLAGS      = rcs
CFLAGS       = -Wall -Os -c
LDFLAGS      = -Wall -Os -Wl,-Map,test.map
ifdef AES192
CFLAGS += -DAES192=1
endif
ifdef AES256
CFLAGS += -DAES256=1
endif
ifdef SBOX2
CFLAGS += -DSBOX2=$(SBOX2)
endif
ifdef TIME 
CFLAGS += -DTIME=1
endif
ifdef DEBUG
CFLAGS += -DDEBUG=1
endif

OBJCOPYFLAGS = -j .text -O ihex
OBJCOPY      = objcopy

# include path to AVR library
INCLUDE_PATH = /usr/lib/avr/include
# splint static check
SPLINT       = splint test.c aes.c -I$(INCLUDE_PATH) +charindex -unrecog

default: test.elf

.SILENT:
.PHONY:  lint clean

test.hex : test.elf
	echo copy object-code to new image and format in hex
	$(OBJCOPY) ${OBJCOPYFLAGS} $< $@

test.o : test.c aes.h aes.o
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o  $@ $<

aes.o : aes.c aes.h
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o $@ $<

test.elf : aes.o test.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^

aes.a : aes.o
	echo [AR] $@
	$(AR) $(ARFLAGS) $@ $^

lib : aes.a

time.o : time.c aes.h aes.o 
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o  $@ $< -lm

time.elf : aes.o time.o 
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^ -lm

clean:
	rm -f *.OBJ *.LST *.o *.gch *.out *.hex *.map *.elf *.a

test:
	make clean && make && ./test.elf
	make clean && make AES192=1 && ./test.elf
	make clean && make AES256=1 && ./test.elf

test2:
	make clean && make SBOX2=1 && ./test.elf
	make clean && make AES192=1 SBOX2=1 && ./test.elf
	make clean && make AES256=1 SBOX2=1 && ./test.elf

time:
	make clean && make time.elf && ./time.elf 
	make clean && make time.elf SBOX2=1 && ./time.elf

sbox2_2:
	make clean && make time.elf && ./time.elf 
	make clean && make time.elf SBOX2=1 && ./time.elf
	make clean && make time.elf SBOX2=2 && ./time.elf

debug:
	make clean && make time.elf SBOX2=2 DEBUG=1 && ./time.elf


lint:
	$(call SPLINT)
