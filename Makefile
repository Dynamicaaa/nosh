CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
OBJ_DIR = obj
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRC))
TARGET = nosh

# Determine platform
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS-specific flags
    LDFLAGS = -lcrypto
    # Check if OpenSSL is installed via Homebrew
    ifneq ($(wildcard /usr/local/opt/openssl),)
        CFLAGS += -I/usr/local/opt/openssl/include
        LDFLAGS += -L/usr/local/opt/openssl/lib
    endif
else
    # Linux and other platforms
    LDFLAGS = -lcrypto
    # Static linking option for Linux, but not for crypto (security reasons)
    # LDFLAGS += -static
endif

all: $(TARGET)

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) -lreadline $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

install:
	@echo "Installing nosh..."
	@echo "Backing up current shell: $$SHELL"
	@echo $$SHELL > $(HOME)/.nosh_backup
	@sudo cp $(TARGET) /usr/local/bin/$(TARGET)
	@echo "/usr/local/bin/$(TARGET)" | sudo tee -a /etc/shells > /dev/null
	@sudo chsh -s /usr/local/bin/$(TARGET) $$USER
	@echo "Installation complete."

uninstall:
	@echo "Uninstalling nosh..."
	@if [ -f $(HOME)/.nosh_backup ]; then \
		ORIGINAL_SHELL=`cat $(HOME)/.nosh_backup`; \
		echo "Restoring original shell: $$ORIGINAL_SHELL"; \
		sudo chsh -s $$ORIGINAL_SHELL $$USER; \
		rm $(HOME)/.nosh_backup; \
	else \
		echo "No backup found. Please restore your shell manually."; \
	fi
	@sudo sed -i.bak '\@/usr/local/bin/$(TARGET)@d' /etc/shells
	@sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstallation complete."

.PHONY: all clean install uninstall
