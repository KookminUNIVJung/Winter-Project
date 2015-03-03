#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include <string>
#include <list>

#include <pcap.h>

#define OFFSET_SIZE 5
#define WINDOW_SIZE 32

#define PRIME_NUMBER 1048583

#define MASK 0x00000001

unsigned char stringSet[WINDOW_SIZE];
int setFlag = 0;

void preprocessPrime(int *primeSet){

	for(int i = 1; i < WINDOW_SIZE+1; i++){

		unsigned int prime = 1;

		for(int j = 0; j < i; j++){

			prime *= PRIME_NUMBER;
			prime %= 100000;
		}
		primeSet[i-1] = prime;
	}
}
unsigned int rabinHash(unsigned char addChar, int *primeSet){

	stringSet[setFlag] = addChar;

	// 문자 추가후 인덱스 증가(문자의 맨앞이 됨)
	setFlag = (setFlag + 1) & 31;
	
	unsigned int hash = 0;
	
	//라빈 해쉬 계산
	for(int i = 0; i < WINDOW_SIZE; i++)
		hash += (stringSet[ (setFlag + i) & 31 ] * primeSet[ 31 - i ])%100000;

	return hash % 1000000;
	
}


int main(int argc, char* argv[]){

	unsigned int packetCounter = 0;
	const u_char *packet;
	struct pcap_pkthdr header;

	std::list<std::string> List;
	std::list<std::string>::iterator i_list;

	int primeSet[32];
	preprocessPrime(primeSet);
	

	if( argc < 2){
		fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]);
		exit(1);
	}
	

	for(int fnum = 1; fnum < argc; fnum++){

		pcap_t *handle;
		char errBuffer[PCAP_ERRBUF_SIZE];

		
		handle = pcap_open_offline(argv[fnum], errBuffer);
		
		if(handle == NULL){
			fprintf(stderr, "Couldn`t open pcap file %s: %s\n", argv[fnum], errBuffer);
			return(2);
		}
		int totalCount = 0;

		while(packet = pcap_next(handle, &header)){
			totalCount++;
			// 맨 처음 31개를 큐에 넣는다.
			memcpy(stringSet, packet, sizeof(char)*(WINDOW_SIZE-1));
			
			// 원형 큐 인덱스를 맨 뒷 칸으로 한다.
			setFlag = 31;

			unsigned int hash;

			int distinguishFlag = 0;
			int startOffset = 0;

			for(int i = 0; i < header.len; i++)
				printf("%x", packet[i]);

			printf("\n\n");

			for(unsigned int i = 31; i < header.len; i++){

				// 라빈 해쉬 값을 구한다.
				if(distinguishFlag == 0)
					hash = rabinHash(packet[i], primeSet);

				int count = 0;
				
				unsigned int temp = hash;

				for(int k = 0; k < OFFSET_SIZE; k++){
					if((temp & MASK) == 0) count++;
					temp >>= 1;
				}
				
				// 만약 5비트가 0 이라면 
				if(count == OFFSET_SIZE){
					std::string convertString;
					std::string tempString = "";

					for(int j = startOffset; j < i; j++){
						if(packet[j] > 127){
							tempString += packet[j]/16;
							tempString += packet[j] & 15;
						}
						else tempString += packet[j];
					}
				
					List.push_back(tempString);

					memcpy(stringSet, packet+i+1, sizeof(char)*(WINDOW_SIZE-1));
					setFlag = 31;

					startOffset = i;
					i += 31;

					distinguishFlag = 0;

				}else{
					distinguishFlag = 1;
					unsigned int sub = (primeSet[WINDOW_SIZE-1] * stringSet[setFlag])%100000;					 
					if(sub > hash) hash += 100000;
					hash -= sub;
					hash = ((hash%100000) * primeSet[0])%100000;
					hash += packet[i + 1];

					
				/*	std::cout << hash << std::endl;
					std::cout << i << std::endl;
					*/

					stringSet[setFlag] = packet[i + 1];
					setFlag = ( setFlag + 1 ) & 31;
				}
			}
			/*if(totalCount == 100) */break;
		
		
		}

		
		for(i_list = List.begin(); i_list != List.end(); i_list++){
			
			int size = i_list->length();
			unsigned char* str = (unsigned char*)i_list->c_str();

			for(int i = 0 ; i < size; i++){
				printf("%x", (unsigned char)str[i]);
			}
			printf("\n");
		}
		

		//std::cout << List.size() << std::endl;
	}

	return 0;
}
