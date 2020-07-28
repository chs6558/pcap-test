pcap_test : pcap_test.o
	g++ -o pcap_test pcap_test.o -lpcap
pcap_test.o : pcap_test.cpp
	g++ -c pcap_test.cpp -lpcap
clean :
	rm pcap_test *.o
