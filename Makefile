CFLAGS ?= -g -O1 #-DPAM
SUDO ?= sudo

all: sus

sus: sus.o readpassphrase.o
	$(CC) -o $@ $^ -lpam -lpam_misc -lcrypt
	$(SUDO) chown root:root $@
	$(SUDO) chmod u+s $@

%.o: %.c
	$(CC) -o $@ $< -c $(CFLAGS)

install-pam:
	$(SUDO) cp ./pamconf /etc/pam.d/sus

clean:
	rm -rf *.o sus
