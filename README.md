# FreeRTOS: Ingress Firewall design and Integration with IDS

In PART_4/report_latex a .pdf report explaining in depth the Project is present.

## PART 1
- Installation instructions for QEMU, compile from source and target compile options
- Installation instructions for ARM compiler and ARM version of GBD
- Both for Windows and Debian based distros
- Requirements for the next parts : 
    - working installation of QEMU
    - working installation of Wireshark
    - working installation of python with pip installed
    - libvirt base install

## PART 2
- Scheduling and memory demos
- Launch the "dLauncher.sh" this while prompt for the selection of the demo to run, after the demo are lauched to execute the next demo simply stop the execution and relaunch the script

## PART 3
- Firewall implementation
- The modified code is in "PART_3/FreeRTOS/FreeRTOS-Plus/Source/FreeRTOS-Plus-TCP/source" the file added is "rules.h" and the file modified is "FreeRTOS_IP.c"
- The demo is located in "PART_3/FreeRTOS/FreeRTOS-Plus/Demo/FreeRTOS_Plus_TCP_Echo_Qemu_mps2/" this starts the TCP/IP stack and looks for a TCP echo server. The FreeRTOS instance uses the "virbr0" network bridge to comunicate with the host and has a statically assigned address (192.168.122.10).
- The rules for the demo firewall can be found in YAML format in : "PART_3/Resources" where the rule injection script is located "rulegen.py" this will use the YAML file and inject the created C structs in the rules.h file mentioned earlier
- To run the fully automated demo just launch the "fireDemoLauncher.sh" this will ask the user if it needs the virbr0 bridge created, after that it will ask if the user needs the virtual python env to be created ( this is required for the rulegen.py and the pcap.py conversion python scrypt and also for the packet generation utility (scapy) )
- The rejected packets are parsed from a log file to create a .pcap file produced by the pcap.py script.
- Then follow the on-screen instructions and at the end of the demo wireshark will automatically open and display the rejected packets by the Ingress Firewall.

## PART 4
- Extra: Integration with Snort IDS
