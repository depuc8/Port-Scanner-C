CC      = gcc
CFLAGS  = -Wall -Wextra -pedantic -std=c11 -g
TARGET  = portscanner
SRC     = portscanner.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) portscanner.h
	$(CC) $(CFLAGS) -o $@ $(SRC)

clean:
	rm -f $(TARGET)
