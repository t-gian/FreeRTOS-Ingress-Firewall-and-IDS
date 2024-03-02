#ifndef __RULE_SET_FIREWALL_
#define __RULE_SET_FIREWALL_ 1

  #include <stdlib.h>

  #define NOR 3

  //A Firewall rule structure
  typedef struct rule {
      uint32_t src;  // Source IP address in network byte order
      uint32_t dst;  // Destination IP address in network byte order
      uint16_t port_src; // Source port number in network byte order
      uint16_t port_dst; // Destination port number in network byte order
      uint8_t proto; // 2-bit mask representing protocol type
      uint8_t action; //action to do with packets from the source ip 0 >> accept packets 1 >> reject packets
  }Rule;

  //Current ruleset loaded in the firewall
  Rule ruleset[NOR] = {
      {846899392, 175810752, 51200, 53775, 17, 0 },
      {24815808, 175810752, 51200, 8448, 6, 0 },
      {24815808, 175810752, 0, 0, 1, 0 },
  };

#endif
