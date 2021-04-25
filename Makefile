build:
	g++ -I ./include ./src/* -o ipk-sniffer -lpcap

debug-build:
	g++ -I ./include ./src/* -o ipk-sniffer -lpcap -g

install:
	mv ./ipk-sniffer /usr/bin

uninstall:
	rm  /usr/bin/ipk-sniffer

tar: clean
	tar -cvf xpleva07.tar README Makefile include src manual.pdf

clean:
	rm -f ipk-sniffer
	rm -f xpleva07.tar
