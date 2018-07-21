
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERENT 14
#define SIZE_4 4
#define SIZE_2 2
#define SIZE_DATA 16

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
	/*ethernet Header*/

	struct info_ether //Total 14byte
	{
		u_char ethernet_desthost[ETHER_ADDR_LEN];//6byte
		u_char ethernet_srchost[ETHER_ADDR_LEN]; //6byte
		u_short ethernet_EtherType;				//2byte
		
	};
	/*IP header*/
	struct info_IP //Total 22byte
	{
		u_char version_header;		//1byte 4bit=version 4bit=headerLength
		u_short Total_length;		//2byte
		u_short Identifier;			//2byte
		u_short Fragment_Offset;		//4bit = flags Total = 2byte
		u_char Time_to_Live;			//1byte
		u_char Protocol;				//1byte
		u_short Header_Checksum;		//2byte
		u_char Source_address[SIZE_4];		//4byte
		u_char Destination_address[SIZE_4];	//4byte
		u_int Option_IP;				//3byte = Option, 1byte = padding
	};
	struct info_TCP //Total 26byte
		{
			u_char source_port[SIZE_2];		//2byte
			u_char destination_port[SIZE_2];//2byte
			u_int sequence_number;	//4byte
			u_int acknowledgment;	//4byte
			u_short Flag; 			//4bit=Hlen, 6bit=reserved, 6bit=Flag
			u_short window;			//2byte
			u_short Checksum; 		//2byte
			u_short urgent_pointer;	//2byte
			u_int TCP_option;		//4byte
		};	

	struct info_data
	{
		u_char Data[SIZE_DATA];
	};

/*
void hextodec(struct info_TCP tcp){
	char front = tcp.source_port[0];
	char reer = tcp.source_port[1];
	
	printf("%c, %c",front,reer);
	//strcat(front,reer);
	//printf("%s\n",front);

}*/

int main(int argc, char* argv[]) {

struct info_ether ethernet;
struct info_IP ip;
struct info_TCP tcp;
struct info_data data;

int packet_number=1;
int srcport;
int destport;
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1]; //dev: interface
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //open 
  
  if (handle == NULL) { //error argv[1] exception
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header; //header
    const u_char* packet;
    
    int index=0;
    int res = pcap_next_ex(handle, &header, &packet); //receive packet return 1 or 0
 	
 	//dest_addr
 	for(int i=0;i<=5;i++){
   	ethernet.ethernet_desthost[i] = packet[index];
   	index++;
	}

	//src_addr
 	for(int i=0;i<=5;i++){
   	ethernet.ethernet_srchost[i] = packet[index];
   	index++;
	}
	
	
	//Type
	ethernet.ethernet_EtherType = packet[index];
	index ++;

	//ethernet-Data
	for(int i=0;i<=1;i++){
		index ++;
	}		
	
	//Version, Total_lenght, TTL etc
	for(int i=0;i<=7;i++){
		index ++;
	}

	//protocol
	ip.Protocol = packet[index];
	if(ip.Protocol!=0x6) continue;
	index++;

	//Header Checksum
	for(int i=0;i<=1;i++){
		index ++;
	}

	//Source IP
	for(int i=0;i<=3;i++){
   	ip.Source_address[i] = packet[index];
   	index++;
	}


	//Destination IP
	for(int i=0;i<=3;i++){
   	ip.Destination_address[i] = packet[index];
   	index++;
	}


	//Source Port
	for(int i=0;i<=1;i++){
		tcp.source_port[i] = packet[index];
		index ++;
	}

	srcport=int(tcp.source_port[0])*256+int(tcp.source_port[1]);
	
	
	//Destination Port
	for(int i=0;i<=1;i++){
		tcp.destination_port[i] = packet[index];
		index ++;
	}

	destport=int(tcp.destination_port[0])*256+int(tcp.destination_port[1]);

	//before data
	for(int i=0;i<=15;i++){
		index++;
	}

	//payload
	for(int i=0;i<=15;i++){
		data.Data[i] = packet[index];
		index ++;
	}
	fprintf(stderr,"---------------------------------------------------------------------\n");

	fprintf(stderr,"TCP Packet Number	= %d\n",packet_number);

	fprintf(stderr,"--------------------------L2------------------------------------------\n");

	fprintf(stderr,"Destination_address	= %0.2x : %0.2x : %0.2x : %0.2x : %0.2x : %0.2x\n", ethernet.ethernet_desthost[0], ethernet.ethernet_desthost[1], ethernet.ethernet_desthost[2], ethernet.ethernet_desthost[3], ethernet.ethernet_desthost[4], ethernet.ethernet_desthost[5]);	

	fprintf(stderr,"Source_address		= %0.2x : %0.2x : %0.2x : %0.2x : %0.2x : %0.2x\n", ethernet.ethernet_srchost[0], ethernet.ethernet_srchost[1], ethernet.ethernet_srchost[2], ethernet.ethernet_srchost[3], ethernet.ethernet_srchost[4], ethernet.ethernet_srchost[5]);	

	fprintf(stderr,"ethernet_EtherType	= %0.4x	 TCP\n",ethernet.ethernet_EtherType);

	fprintf(stderr,"--------------------------L3-----------------------------------------\n");

	fprintf(stderr,"Protocol		= %d\n",ip.Protocol);

	fprintf(stderr,"src IP_address		= %d.%d.%d.%d\n",ip.Source_address[0],ip.Source_address[1],ip.Source_address[2],ip.Source_address[3]);

	fprintf(stderr,"dest IP_address		= %d.%d.%d.%d\n",ip.Destination_address[0],ip.Destination_address[1],ip.Destination_address[2],ip.Destination_address[3]);

	fprintf(stderr,"--------------------------L4-----------------------------------------\n");

	fprintf(stderr,"source_port		= %d\n",srcport);

	fprintf(stderr,"destination_port	= %d\n",destport);

	fprintf(stderr,"--------------------------L7-----------------------------------------\n");

	fprintf(stderr,"data			= %0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x,%0.2x\n",data.Data[0],data.Data[1],data.Data[2],data.Data[3],data.Data[4],data.Data[5],data.Data[6],data.Data[7],data.Data[8],data.Data[9],data.Data[10],data.Data[11],data.Data[12],data.Data[13],data.Data[14],data.Data[15]);

	fprintf(stderr,"---------------------------------------------------------------------\n");

	fprintf(stderr,"\n\n\n");

	packet_number++;
	
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //fprintf(stderr,"%u bytes captured\n", header->caplen); //output byte
  }

  pcap_close(handle);
  return 0;
}

