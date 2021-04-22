build:
	g++ -I ./include -I /usr/include/pcap ./src/* -o ipk-sniffer -lpcap

debug-build:
	g++ -I ./include -I /usr/include/pcap ./src/* -o ipk-sniffer -lpcap -g

install:
	mv ./ipk-sniffer /usr/bin

uninstall:
	rm  /usr/bin/ipk-sniffer

tar: clean
	tar -cf xpleva07.tar *

clean:
	rm -f ipk-sniffer
	rm -f xpleva07.tar
