#!/usr/bin/env python3

import yaml
import numpy as np

#Max rules allowed
MAX_RULES = 50

#Output file
FILE_TO_GEN="rules.h"

#Input File
RULES_YAML="rules.yaml"

#Decimal base
DEC_BASE=10

#ip to freeRTOS format
def ip_freeRTOS_int(ip):
    if not( ip and not ip.isspace() ):
        print("WARNING: found invalid ip in the rules, exiting...")
        exit(1)
    _oct_arr = np.array(str(ip).split("."),dtype=int)
    return (_oct_arr[3] << 24) | (_oct_arr[2] << 16) | (_oct_arr[1] << 8) | (_oct_arr[0])

#port to FreeRTOS format
def port_freeRTOS_int(port):
    if port == "ANY":
        return np.array(0).astype(np.ushort)
    if not port:
        print("WARNING: found invalid port in the rules, exiting...")
        exit(2)
    return  np.array( ( ( port ) << 8 ) | ( ( port ) >> 8 ) ).astype(np.ushort)

#generate the lines of C code
def generate_c_code_lines(ruleset):

    nor = len(ruleset)

    #crop the rules at MAX_RULES
    if nor > MAX_RULES:
        print(f"Too many rules! capping at {MAX_RULES}...")
        del ruleset[(MAX_RULES-nor):]
        nor = MAX_RULES

    c_code_lines = f"#ifndef __RULE_SET_FIREWALL_\n"
    c_code_lines += f"#define __RULE_SET_FIREWALL_ 1\n\n"
    c_code_lines += f"  #include <stdlib.h>\n\n"
    c_code_lines += f"  #define NOR {nor}\n\n"
    c_code_lines += f"  //A Firewall rule structure\n"
    c_code_lines += f"  typedef struct rule {{\n"
    c_code_lines += f"      uint32_t src;  // Source IP address in network byte order\n"
    c_code_lines += f"      uint32_t dst;  // Destination IP address in network byte order\n"
    c_code_lines += f"      uint16_t port_src; // Source port number in network byte order\n"
    c_code_lines += f"      uint16_t port_dst; // Destination port number in network byte order\n"
    c_code_lines += f"      uint8_t proto; // 2-bit mask representing protocol type\n"
    c_code_lines += f"      uint8_t action; //action to do with packets from the source ip 0 >> accept packets 1 >> reject packets\n"
    c_code_lines += f"  }}Rule;\n\n"
    c_code_lines += f"  //Current ruleset loaded in the firewall\n"
    c_code_lines += f"  Rule ruleset[NOR] = {{\n"

    print("### Converting to FreeRTOS's ipv4 and port format...")
    for idx,rule in enumerate(ruleset):
        src = ip_freeRTOS_int(rule['source'])
        dst = ip_freeRTOS_int(rule['destination'])
        pSrc = port_freeRTOS_int(rule['port_source'])
        pDst = port_freeRTOS_int(rule['port_destination'])
        print(f"## Rule {idx}:\n# Source: {rule['source']}:{rule['port_source']} >> {src}:{pSrc}\n# Destination: {rule['destination']}:{rule['port_destination']} >> {dst}:{pDst}")
        c_code_lines += f"      {{{src}, {dst}, {pSrc}, {pDst}, {rule['protocol']}, {rule['action']} }},\n"

    c_code_lines += f"  }};\n\n"
    c_code_lines += f"#endif\n"

    return c_code_lines

#write to the file
def write_to_file(c_code_lines):
    with open(FILE_TO_GEN, "w") as file:
            file.write(c_code_lines)

def main():
    print("### Computing rules...")
    with open(RULES_YAML, "r") as file:
        ruleset = yaml.safe_load(file)

    write_to_file(generate_c_code_lines(ruleset['ruleset']))
    print("### Compute finished!")

if __name__ == "__main__":
    main()
