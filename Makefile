SUDO ?= sudo

all: sus

sus: sus.o
	$(CC) -o $@ $< -lpam -lpam_misc
	$(SUDO) chown root:root $@
	$(SUDO) chmod u+s $@

sus.o: sus.c
	$(CC) -o $@ $< -c -g -O1

install-pam:
	$(SUDO) cp ./pamconf /etc/pam.d/sus

clean:
	rm -rf sus.o sus
