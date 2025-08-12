SUDO ?= sudo

all: sus

sus: sus.o
	$(CC) -o $@ $<
	$(SUDO) chown root:root $@
	$(SUDO) chmod u+s $@

sus.o: sus.c
	$(CC) -o $@ $< -c -g -O1

clean:
	rm -rf sus.o sus
