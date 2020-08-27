SHELL := /bin/bash # Use bash syntax
cc=g++
MAKE=make
RM=rm
INTERFACE=-I Interface/inc -L Interface/lib
SERVER=ps u | grep "[s]erver" | tr -s ' ' | cut -d ' ' -f2
TERMINAL=gnome-terminal #change to your terminal

#targets .
all: Client/main.cpp Server/main.cpp
	#Optional parameter:
	#	num_cl=<number of client to open>

	#kill previously started servers and clients
	kill -9 $$(ps u | grep "[s]erver" | tr -s ' ' | cut -d ' ' -f2) || true
	kill -9 $$(ps u | grep "[c]lient" | tr -s ' ' | cut -d ' ' -f2) || true

	#compile libraries
	$(cc) -I ./Interface/inc -c Interface/src/interface.cpp -o Interface/obj/interface.o
	ar rcs Interface/lib/libinterface.a Interface/obj/interface.o

	$(cc) $(INTERFACE) Client/main.cpp -linterface -o client -lssl -lcrypto
	$(cc) Server/main.cpp -o server -lssl -lcrypto -pthread
	$(TERMINAL) -e "./server" &
	sleep 1
	$(MAKE) client_target

#another target for client
client_target:
	n=1 ; while [[ $$n -le $(num_cl) ]] ; do \
		echo $$n; \
		$(TERMINAL) -e "./client $$n" & \
		((n = n + 1)) ; \
  done
	#open n=num_cl number of clients, useful for debugging stuff
	done



clean: server client
	$(RM) server
	$(RM) client
	$(RM) Interface/lib/libinterface.a Interface/obj/interface.o
