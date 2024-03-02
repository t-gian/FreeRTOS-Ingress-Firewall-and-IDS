#!/bin/bash

## Functions

chk_dependency(){
	if [ $# -lt 1 ]; then
		return 2  #err
	else
		if ! type "$1" &>/dev/null; then
			echo "## FATAL: please install $1 and try again!"
			return 1  #not found
		else
			return 0  #found
		fi
	fi
}

chk_demo_str(){
    # Ensure the subfolder exists
    if [[ ! -d "./FreeRTOS/FreeRTOS-Plus/Demo/FreeRTOS_Plus_TCP_Echo_Qemu_mps2" ]]; then
        text=$(echo "\n## Error: Subfolder 'FreeRTOS/FreeRTOS-Plus/Demo/FreeRTOS_Plus_TCP_Echo_Qemu_mps2'"\
        "not found in the script directory.\n"\
        "\n## Please check the folder names and structure!")
        printf "$text"
        return 1
    fi

    # Change directory, handling potential spaces
    cd "./FreeRTOS/FreeRTOS-Plus/Demo/FreeRTOS_Plus_TCP_Echo_Qemu_mps2" || {
        echo "## Error: Could not change directory. Check folder permissions and accessibility."
        return 1
    }
}

chk_con_exist(){
	if [ $# -lt 1 ]; then
		return 1 #err
	elif ! type "$1" > /dev/null; then
		return 2 #not found
	else
		return 0 #found
	fi
}

find_con(){

    chk_con_exist konsole

    if [ $? -eq 0 ]; then
        echo "konsole -e"
        return 0
    fi

    chk_con_exist gnome-terminal

    if [ $? -eq 0 ]; then
        echo "gnome-terminal -- sh -c"
        return 0
    fi

    chk_con_exist xterm

    if [ $? -eq 0 ]; then
        echo "xterm -e"
        return 0
    fi

    return 1

}

choice_demo_launch(){

    printf "## BUILD SUCCESS!\n## Press 'Y' to continue or any other key to exit...\n\n"
    read -n 1 -r -p ">> " answer
    echo ""

    if [[ "$answer" =~ ^[yY]$ ]]; then
        printf "\n\n## Launching...\n"
        return 0
    else
        printf "\n\n## Aborting...\n"
        return 1
    fi
}

do_launch_qemu(){
    if [ $# -lt 1 ]; then
        echo "## FATAL: invalid script directory in input, cannot launch QEMU."
		return 1  #err
    fi

    sudo qemu-system-arm -machine mps2-an385 -cpu cortex-m3 -kernel ./build/freertos_tcp_mps2_demo.axf -netdev bridge,id=mynet0,br=virbr0 -net nic,netdev=mynet0,macaddr=52:54:00:12:34:AD,model=lan9118 -object filter-dump,id=tap_dump,netdev=mynet0,file=/tmp/qemu_tap_dump -nographic -serial stdio  -monitor none -semihosting -semihosting-config enable=on,target=native > "$1/out.log" &

    if [ $? -ne 0 ]; then
        return 1
    fi

    echo $! #save pid
}

build_the_demo(){

    if [ $# -lt 1 ]; then
        echo "## FATAL: invalid script directory in input."
		return 1  #err
    fi

	printf "## Building the Demo...\n"

	mlog="$1/build_log.txt"
	make clean &> $mlog
	make &>> $mlog

	if [ $? -eq 0 ]; then

		rm $mlog	#logs of make not needed

		choice_demo_launch

		if [ $? -ne 0 ]; then
            return 1
        fi

	else

		echo "## FATAL ERROR: errors building the demo, see build_log.txt"
	fi
}

prepare_scapy(){

    echo "#!/bin/bash">tscapy.sh

    echo "sc1=\"send(IP(dst=\\\"192.168.122.10\\\",src=\\\"192.168.122.50\\\")/UDP(dport=4050,sport=200)/Raw(load=\\\"abc\\\"), iface=\\\"virbr0\\\")\"">>tscapy.sh
    echo "sc2=\"send(IP(dst=\\\"192.168.122.10\\\",src=\\\"192.168.122.1\\\")/TCP(dport=33,sport=200), iface=\\\"virbr0\\\")\"">>tscapy.sh
    echo "sc3=\"send(IP(dst=\\\"192.168.122.10\\\",src=\\\"192.168.122.1\\\")/ICMP(), iface=\\\"virbr0\\\")\"">>tscapy.sh
    echo "sc4=\"send(IP(dst=\\\"192.168.122.10\\\",src=\\\"192.168.122.50\\\")/UDP(dport=3050,sport=200)/Raw(load=\\\"def\\\"), iface=\\\"virbr0\\\")\"">>tscapy.sh
    echo "sc5=\"send(IP(dst=\\\"192.168.122.10\\\",src=\\\"192.168.122.1\\\")/TCP(dport=6968,sport=200), iface=\\\"virbr0\\\")\"">>tscapy.sh
    echo "sc6=\"send(IP(dst=\\\"192.168.122.10\\\",src=\\\"192.168.122.50\\\")/ICMP(), iface=\\\"virbr0\\\")\"">>tscapy.sh

    echo "echo \$sc1 | \$(sudo -E net-env/bin/python net-env/bin/scapy)" >>tscapy.sh
    echo "echo \$sc2 | \$(sudo -E net-env/bin/python net-env/bin/scapy)" >>tscapy.sh
    echo "echo \$sc3 | \$(sudo -E net-env/bin/python net-env/bin/scapy)" >>tscapy.sh
    echo "echo \$sc4 | \$(sudo -E net-env/bin/python net-env/bin/scapy)" >>tscapy.sh
    echo "echo \$sc5 | \$(sudo -E net-env/bin/python net-env/bin/scapy)" >>tscapy.sh
    echo "echo \$sc6 | \$(sudo -E net-env/bin/python net-env/bin/scapy)" >>tscapy.sh

}

## PART 0: dep check

if [ "$EUID" -ne 0 ]; then
    text=$(echo "\nFATAL: you need to run this script as root,"\
    " you simply use:\n\n"\
    "   sudo -E ./fireDemoLauncher.sh\n\n")
    printf "$text"
    exit 1
fi

clear

printf "##### Checking dependencies...\n"

chk_dependency "make"


if [ $? -ne 0 ]; then
	exit 1
fi

chk_dependency "qemu-system-arm"

if [ $? -ne 0 ]; then
	exit 2
fi

chk_dependency "nano"

if [ $? -ne 0 ]; then
	exit 3
fi

chk_dependency "python3"

if [ $? -ne 0 ]; then
	exit 4
fi

printf "##### dependencies OK!\n"


## PART 1 : we prepare the ruleset
cd Resources

printf "##### Preparing the rules for the firewall...\n"

echo "### Opening the rule editing mode..."

nano rules.yaml # A >> Editing of the rules

echo "### End editing!"

python3 rulegen.py # B >> Generation of the rules

echo "### Injecting the rules..."

# C >> Replacement of the old ruleset with the new one
rm ../FreeRTOS/FreeRTOS-Plus/Source/FreeRTOS-Plus-TCP/source/rules.h
mv rules.h ../FreeRTOS/FreeRTOS-Plus/Source/FreeRTOS-Plus-TCP/source/

echo "### Rules injected!"

cd ..

printf "##### Rules OK!\n"

## End PART 1

## PART 2: Launching the demo

printf "##### Executing the compile and launch of the demo...\n"

script_dir=$(pwd) # A >> Save the script launch directory

chk_demo_str # B >> Check the demo structure

if [ $? -ne 0 ]; then
	exit 5
fi

build_the_demo $script_dir # Launch the demo

if [ $? -ne 0 ]; then
	exit 6
fi

qpid=$(do_launch_qemu $script_dir)

if [ $? -ne 0 ]; then
    echo $qpid
    echo "## FATAL: something went wrong launching the demo"
    exit 7
fi

sleep 10 #wait for QEMU to be ready

printf "##### Demo OK! \n"

## End PART 2

## PART 3: launching scapy

printf "##### Launching Scapy...\n"

cd $script_dir
cd ../PART_4

usr_con=$(find_con)

if [ $? -ne 0 ]; then
	echo "## FATAL: did not find a compatible console, you'll need to manually launch scapy."
else
    prepare_scapy
    sudo -E $usr_con "bash tscapy.sh"
    sleep 5
    rm tscapy.sh
fi

printf "##### Scapy OK!\n"

sleep 5

## End PART 3

## PART 4: QEMU kill and Result analyze

printf "##### Stopping QEMU...\n"

kill -9 $qpid

printf "##### Fetching results...\n"

./net-env/bin/python3 pcap.py

if [ $? -ne 0 ]; then
    printf "## FATAL: Could NOT compute the pcap! aborting...\n"
	exit 8
fi

sleep 2

wireshark -R "!tcp.srcport == 5000 && !tcp.analysis.retransmission" output.pcap


## End PART 4
