#include <iostream>
#include <stdlib.h>
#include <fstream>

#include <pcap.h>

#define LINE_LEN 16
#pragma warning(disable:4996)

int main(int argc, char* argv[]){

	pcap_if_t *deviceList, *device;
	pcap_t *fp;

	u_int interfaceNum, i = 0;

	char errBuffer[PCAP_ERRBUF_SIZE];

	struct pcap_pkthdr *header;
	const u_char *pktData;

	std::cout << "pktdump_ex: prints the packets of the network using WinPcap." << std::endl;
    std::cout << "Usage: pktdump_ex [-s source]\n\n"
           "   Examples:\n"
           "      pktdump_ex -s file://c:/temp/file.acp\n"
           "      pktdump_ex -s rpcap://\\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n";

	if(argc < 3){

		std::cout<<"Printing the device List " << std::endl;

		if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &deviceList, errBuffer) == -1){
			std::cerr << "Error In pcap_findalldevs_ex : " << errBuffer << std::endl;
			return -1;
		}
		/* print all device list */
		for(device = deviceList; device; device = device->next){

			std::cout << ++i << ". " << device->name << std::endl;
			(device->description) ? std::cout << " (" << device->description << ")\n" << std::endl : std::cout << " (No description available\n) " << std::endl;

		}

		if(i == 0){
			std::cerr << "No interfaces found! Error! " << std::endl;
			return -1;
		}

		std::cout << "Choose the interface number (1-" << i << "): ";
		scanf_s("%d", &interfaceNum);

		if( interfaceNum < 1 || interfaceNum > i){
			std::cout << "Interface number out of range." << std::endl;

            /* Free the device list */
			pcap_freealldevs(deviceList);
            return -1;
        }

		for(device = deviceList, i = 0; i < interfaceNum -1; device = device->next, i++);

		/* open ther interface */
		/* SnapLength, flags, Read Timeout, Remote authnetication */
	
		if( (fp = pcap_open(device->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, errBuffer)) == NULL){
			std::cerr << "Error opening adapter!" << std::endl;
			return -1;
		}
	}
	else{
		if( (fp = pcap_open(argv[2], 100, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, errBuffer)) == NULL){
			std::cerr << "Error opening adapter(source)!" << std::endl;
			return -1;
		}
	}

	/* Read the packets In realtime */
	int res;
	//std::ofstream writeFile;
	//writeFile.open("output.txt");

	FILE *inFile = fopen("output.txt", "w");
	char buffer[1024];

	while((res = pcap_next_ex(fp, &header, &pktData)) >= 0){
		if(res == 0) continue;

		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
		
		//writeFile << pktData << std::endl;
		fwrite(pktData, 1, header->len, inFile);

		/*
		for(i = 1; (i < header->caplen +1); i++){
			writeFile << pktData[i-1];
			//printf("%.2x", pktData[i-1]);
			if((i%LINE_LEN) == 0) writeFile << std::cout << std::endl;
		}
		
		std::cout << std::endl << std::endl;
		*/
	}

	if(res == -1){
		std::cerr << "Error reading the packets: " <<pcap_geterr(fp) << std::endl;
		return -1;
	}

	//writeFile.close();
	fclose(inFile);
	return 0;
}