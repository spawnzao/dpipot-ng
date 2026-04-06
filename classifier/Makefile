CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Wconversion -fPIC \
          -Iinclude \
          -I/usr/local/include/ndpi \
          -I/usr/include/ndpi

LDFLAGS = -lndpi -lpcap -lpthread -lm -lgcrypt

SRCS    = classifier.c server.c
OBJS    = $(SRCS:.c=.o)
TARGET  = classifier

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(OBJS) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/dpipot-classifier
