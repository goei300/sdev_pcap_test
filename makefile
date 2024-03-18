CC=gcc
CFLAGS=-I./include
LDFLAGS=-lpcap
SRC_DIR=./src
OBJ_DIR=./obj
BIN_DIR=./bin

SOURCES=$(SRC_DIR)/pcap-test.c $(SRC_DIR)/lib/yeobok.c
OBJECTS=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

TARGET=$(BIN_DIR)/pcap-test

all: $(TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)
	
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

