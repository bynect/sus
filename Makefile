SUDO ?= sudo

all: sus

sus: sus.o
	$(CC) -o $@ $< -lpam -lpam_misc
	$(SUDO) chown root:root $@
	$(SUDO) chmod u+s $@

sus.o: sus.c
	$(CC) -o $@ $< -c -g -O1

clean:
	rm -rf sus.o sus
