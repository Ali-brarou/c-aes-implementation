TARGET = test_aes
LIB_DIR = lib
TEST_DIR = test

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I$(LIB_DIR)

all: test

test: $(TARGET)
	./$(TARGET)

$(TARGET): $(LIB_DIR)/aes.c $(TEST_DIR)/test.c
	gcc $^ $(CFLAGS) -o $(TARGET)

clean: 
	rm $(TARGET)

.PHONY: all test clean
