CC := gcc
CFLAGS := -std=c99 -O0 -Wl,-z,relro,-z,now -fstack-protector -fno-pie -no-pie -Wl,-rpath,. -Wl,--dynamic-linker,./ld-linux-x86-64.so.2

SRCS := main.c
TARGET := painter

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS) -o $@

clean:
	@rm $(TARGET)

