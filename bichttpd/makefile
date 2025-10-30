# Makefile pour bichttpd - version complète
CC = gcc
CFLAGS = -Wall -Werror
LDLIBS = -ltls
TARGET = ../opt/bichttpd/usr/sbin/bichttpd
SRC = bichttpd.c

$(TARGET): $(SRC)
	mkdir -p ../opt/bichttpd/usr/sbin/
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)
	@echo "Compilé dans: $(TARGET)"

all: $(TARGET)

clean:
	rm -f $(TARGET)
	@echo "Nettoyé: $(TARGET)"

.PHONY: all clean