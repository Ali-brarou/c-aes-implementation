TARGET = aes
CC = gcc
CFLAGS = -Wall -Wextra -O2

all: $(TARGET)

$(TARGET): main.c aes.c
	gcc main.c aes.c $(CFLAGS) -o $(TARGET)

.PHONY: clean
clean: 
	rm $(TARGET)
