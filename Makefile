CC = gcc -O3 -Wall -fomit-frame-pointer
P = \033[1;30m>\033[0m>\033[1m>\033[0m
D = \033[1;30m-\033[0m
N = bindprivs

all:
	@echo
	@echo -e "$(P) make build   $(D) build module"
	@echo -e "$(P) make load    $(D) load module"
	@echo -e "$(P) make unload  $(D) unload module"
	@echo -e "$(P) make reload  $(D) reload module"
	@echo -e "$(P) make rebuild $(D) rebuild and reload module"
	@echo -e "$(P) make clean   $(D) clean up"
	@echo

build:	$(N).c $(N).h $(N).conf
	./build-config
	$(CC) -c $(N).c

rebuild:	clean build unload load

reload:	unload load

load:
	insmod $(N).o
	
unload:
	rmmod $(N); true

clean:
	rm -f $(N).o config.h
