#include <stdint.h>
#include <sys/types.h>
/* pcap include */
#include "pcap.h"

//#define MAX_RULES 10

struct ipt_entry {
	char *chain;
  	char *targert;
	struct ipt_match *match;
};

struct ipt_match {
  	char *name;
  	char *src;
  	char *dst;
  	int port;
};

// This are the structs used for IPtables rules
// They use chars because they are a single byte

/* What do we need in a firewall rule ?
- ip source
- ip dest
- port
*/

// Are we going to consider chains ?
//
// First implementation will be :


struct rule {
	char *src;
	char *dst;
	int port;
	struct rule *next;
};

// Or

struct rule_v1 {
	char *src;
	char *dst;
	int port;
	char * proto; //in order to be able to distinguish between protocols
	
};

//How do we define a ruleset ?
/*To define a ruleset we are going to use the YAML format
 * A sample ruleset and grammar will be provided the format would be something like this. 
 *
 */
// How do we store it ?
// Working  with C we can use linked lists to minimize code and maximize processing speed

// we need to build a JSON parser to convert rules to C code to embed it in the compiled data
// Considering that we know at compile time the number of rules that we have to embed, and we can cicle trough the array of rules
//
// So we can store them like this: 
// array : {rule_v1, rule_v1, rule_v1, etc}

struct rule_v1 ruleset[MAX_RULES];

// In the firewall we will process every packet in the input chain and check it against every rule in the ruleset
// We need to do this as fast as possible
//
//
// Do we actually need to return the eReturn ?

// packet to process * pxIPPacket

/* Packet structure is as follows :
 *
 * */

#include "pack_struct_start.h"
typedef struct xIP_HEADER
{
    uint8_t ucVersionHeaderLength;        /**< The version field + internet header length 0 + 1 =  1 */
    uint8_t ucDifferentiatedServicesCode; /**< Differentiated services code point + ECN   1 + 1 =  2 */
    uint16_t usLength;                    /**< Entire Packet size, ex. Ethernet header.   2 + 2 =  4 */
    uint16_t usIdentification;            /**< Identification field                       4 + 2 =  6 */
    uint16_t usFragmentOffset;            /**< Fragment flags and fragment offset         6 + 2 =  8 */
    uint8_t ucTimeToLive;                 /**< Time to live field                         8 + 1 =  9 */
    uint8_t ucProtocol;                   /**< Protocol used in the IP-datagram           9 + 1 = 10 */
    uint16_t usHeaderChecksum;            /**< Checksum of the IP-header                 10 + 2 = 12 */
    uint32_t ulSourceIPAddress;           /**< IP address of the source                  12 + 4 = 16 */
    uint32_t ulDestinationIPAddress;      /**< IP address of the destination             16 + 4 = 20 */
};

// The xIP_PACKET is structured as follows

#include "pack_struct_start.h"

typedef struct xIP_PACKET
{
    EthernetHeader_t xEthernetHeader;
    IPHeader_t xIPHeader;
}xIP_PACKET;

/*Main body for packet processing v0.0
 *
 * */


// Lets say that we already have the ruleset inizialized (TODO create JSON to custom struct parser)

//ifdef run only if compiled with firewall support enabled the global
//#if ( ipconfigENABLE_FW != 0)
	// enter firewall processing function we are in the IP task so no need to create another ( for the time being)


/*for ( int i= 0; i<MAX_RULES; i++) {
     
	if packet.IPHeader_t.ucProtocol.
		     }

bool h_IsIPAddrMatch(packetIn * pxIPPacket /*remove and addd directly the header , u16_t portNumber){
	uint16_t portNumber;
	uint8_t proto = packetIn->xIPHeader->ucProtocol; /*could be better to reduce pointer calls 
	if ((proto == ipPROTOCOL_UDP) && ( proto == ipPROTOCOL_TCP) ){ //sort between all valid protocols 
	// Perform comparision in assembly to further speed up operations -> problem for portability ( back to C)
	/*Inline assembly
		usPort = (usPortNumber & 0xFFFF);
		__asm__("cmp " pxIPHeader->ulDestinationPort ", %[port]" : : [port] "r" (usPort)); //this is not portable discarded
*/
struct rule {
    uint32_t src;    // Source IP address in network byte order
    uint32_t dst;    // Destination IP address in network byte order
    uint16_t port;   // Port number in network byte order
    uint8_t proto;   // 2-bit mask representing protocol type 
    //uint8_t action;  // 2 bit ( could be scaled to more) mask to represent the action : can be "DROP" "NO ACTION" "REDIRECT" -> mapping should be 00:0:NO ACTION, 01:1:DROP, 10:10:REDIRECT
    uint8_t action;
};



/*void writeToPcap(struct rule ruleset[], int num_rules, pxIPPacket_t *pxPacket) {

                // No match found, append the packet to the pcap file
                pcap_tpcapHandle;
                pcap_dumper_t *pcapDumper;
                char pcapFilename[] = "packets.pcap"; // Specify the output file name for the pcap file

                char errbuf[PCAP_ERRBUF_SIZE];
                pcapHandle = pcap_open_dead(DLT_EN10MB, 65535); // Open a pcap handle for writing
                if (pcapHandle == NULL) {
                    fprintf(stderr, "Error opening pcap handle: %s\n", errbuf);
                    return false;
                }
                pcapDumper = pcap_dump_open_append(pcapHandle, pcapFilename); // Open the pcap dump file in append mode
                if (pcapDumper == NULL) {
                    fprintf(stderr, "Error opening pcap dump file\n");
                    pcap_close(pcapHandle);
                    return false;
                }

                struct pcap_pkthdr pcapHeader;
                pcapHeader.ts.tv_sec = 0; // Set the timestamp to zero or provide the actual timestamp
                pcapHeader.ts.tv_usec = 0;
                pcapHeader.caplen = sizeof(pxIPPacket_t); // Set the captured length to the size of the packet
                pcapHeader.len = sizeof(pxIPPacket_t); // Set the actual length to the size of the packet

                pcap_dump((u_char )pcapDumper, &pcapHeader, (const u_char)*pxPacket); // Write the packet to the pcap file

                // Close pcap dump file and handle
                pcap_dump_close(pcapDumper);
                pcap_close(pcapHandle);

}
*/
void writeToPcapL3(IPHeader_t * pxIPHeader /*same name should be passed*/){
        FILE *file = fopen("packets.txt", "a");
        if (file == NULL) {
            printf("Error in opening packets.txt file.\n");
            return;
        }
        fprintf(file," (L3): %s %s %s \n", pxIPHeader->IPulSourceIPAddress, pxIPHeader->ulDestinationIPAddress , pxIPHeader->ucProtocol);
        fclose(file);
        return 0;
}
void writeToPcapL4(IPHeader_t * xIPHeader, uint16_t usSourcePort, uint16_t usDestinationPort){
        FILE *file = fopen("packets.txt", "a");
        if (file == NULL) {
            printf("Error in opening packets.txt file.\n");
            return;
        }
        fprintf(file,"(L3 and L4): %s %s %s %s %s\n", xIPHeader->IPulSourceIPAddress, xIPHeader->ulDestinationIPAddress , xIPHeader->ucProtocol, usSourcePort, usDestinationPort);
        fclose(file);
        return 0;
}

uint8_t checkPacketAgainstRules(struct rule ruleset[], int num_rules, xIP_Packet *pxpacket, NetworkBufferDescriptor_t * pxNetworkBuffer) {	//collapse all checks in one function ( fast enough?)
    switch(pxpacket->xipheader.ucprotocol){
        case ipPROTOCOL_UDP:
                const UDPPacket_t * pxUDPPacket = ( ( UDPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer );
                const UDPHeader_t * pxUDPHeader = &( pxUDPPacket->xUDPHeader );
                return checkPacketsWithPorts(ruleset, num_rules, pxpacket, pxUDPHeader->usSourcePort, pxUDPHeader->usDestinationPort);
            break;
        case ipPROTOCOL_TCP:
                const ProtocolHeaders_t *pxProtocolHeaders = ( ( ProtocolHeaders_t * ) &( pxNetworkBuffer->pucEthernetBuffer[ ipSIZE_OF_ETH_HEADER + uxIPHeaderSizePacket( pxNetworkBuffer ) ] ) );
                return checkPacketsWithPorts(ruleset, num_rules, pxpacket, pxProtocolHeaders->xTCPHeader.usSourcePort, pxProtocolHeaders->xTCPHeader.usDestinationPort);
            break;
        default: return checkIPs(ruleset, num_rules, pxpacket);
    }
    
}

uint8_t checkIPs(struct rule ruleset[], int num_rules, xIP_Packet *pxpacket){
    int i;
    for (i = 0; i < num_rules; i++) {
        if (pxpacket->xipheader.ulsourceipaddress == ruleset[i].src &&
            pxpacket->xipheader.uldestinationipaddress == ruleset[i].dst &&
            //pxpacket->usport == htons(ruleset[i].port) && // convert port to network byte order
            (pxpacket->xipheader.ucprotocol & ruleset[i].proto) != 0) {
            return ruleset[i].action; // match found execute corresponding action on the packet
        }
    }
    return 0; // no match found being this a block list we just let the packet trough
};

uint8_t checkPacketsWithPorts(struct rule ruleset[], int num_rules, IPHeader_t * xIPHeader  , uint16_t usSourcePort, uint16_t usDestinationPort) {	//collapse all checks in one function ( fast enough?)
    /* parameter TCP = pxIPHeader, usLocalPort, usRemotePort*/
    /* parameter udp = ((const IPHeader_t * ) & (pxUDPPacket->xIPHeader)), pxUDPHeader->usSourcePort, pxUDPHeader->usDestinationPort*/
    int i;
    for (i = 0; i < num_rules; i++) {
        if (xIPHeader->ulSourceIPAddress == ruleset[i].src &&
            xIPHeader->ulDestinationIPAddress == ruleset[i].dst &&
            //usSourcePort == ruleset[i].srcport &&
            usDestinationPort == ruleset[i].port &&
            //pxpacket->usport == htons(ruleset[i].port) && // convert port to network byte order
            (xIPHeader->ucProtocol & ruleset[i].proto) != 0) {
            return ruleset[i].action; // match found execute corresponding action on the packet
        }
    }

    return 0; // no match found being this a block list we just let the packet trough
};

uint8_t checkL4ports(struct rule ruleset[], int num_rules, uint16_t usSourcePort, uint16_t usDestinationPort) {	//collapse all checks in one function ( fast enough?)
    int i;
    for (i = 0; i < num_rules; i++) {
        if (//usSourcePort == ruleset[i].srcport &&
            usDestinationPort == ruleset[i].port) {
            return ruleset[i].action; // match found execute corresponding action on the pport, info at L4.
        }
    }

    return 0; // no match found being this a block list we just let the packet trough
};





