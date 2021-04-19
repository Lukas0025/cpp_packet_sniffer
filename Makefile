build:
	g++ -I ./include -I /usr/include/pcap ./src/* -o ipk-sniffer -lpcap

clean:
	rm -f ipk-sniffer