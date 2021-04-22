build:
	g++ -I ./include -I /usr/include/pcap ./src/* -o ipk-sniffer -lpcap

install:
	mv ./ipk-sniffer /usr/bin

uninstall:
	rm  /usr/bin/ipk-sniffer

test:
	cd ./spec/tests && ./tests.sh

clean:
	rm -f ipk-sniffer
