PROGRAM = mutex
LIB = -lpthread -lcrypto
OBJS = mutex.o
TEST_DIR_CONTENT = enc/* dec/*

all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LIB) -o $@

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $^

.PHONY: clean
clean:
	$(RM) $(OBJS) $(PROGRAM) $(TEST_DIR_CONTENT)
