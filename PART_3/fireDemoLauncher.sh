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

setup_bridge(){
    sudo systemctl status libvirtd | grep "inactive" && (
        echo "# Found libvirtd disabled, enabling it..."
        sudo systemctl start libvirtd.service

        if [ $? -ne 0 ]; then
            echo "## FATAL: could not enable libvirtd, do so manually and relaunch."
            return 1
        fi

    )

    ip addr show virbr0 | grep "192.168.122.1" || (

        sudo virsh net-start --network default

        if [ $? -ne 0 ]; then
            echo "## FATAL: could not setup the bridge! do so manually and relaunch"
            return 1
        fi
    )
}

setup_qemu_bh(){

    if [ ! -d "/etc/qemu" ]; then
        sudo mkdir "/etc/qemu"
    fi

    fqemu="/etc/qemu/bridge.conf"

    if [ ! -f "$fqemu" ]; then
        sudo touch "$fqemu"
    fi

    cat "/etc/qemu/bridge.conf" | grep "allow virbr0" || (
        sudo echo "allow virbr0" >> $fqemu
    )

    sudo chown root:kvm /etc/qemu/bridge.conf
    sudo chmod 0660 /etc/qemu/bridge.conf
    sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper

    sysnet="/etc/sysctl.conf"
    if [ ! -f "$sysnet" ]; then
        sudo touch "$sysnet"
        sudo echo "net.ipv4.ip_forward = 1" > $sysnet
    fi

    cat $sysnet | grep "net.ipv4.ip_forward = 1" || (
        text=$(echo "# FATAL: you need to setup the forward in you sysctl.conf!\n"\
            "edit \n\n"\
            "/etc/sysctl.conf\n\n"\
            "and add\n\n"\
            "net.ipv4.ip_forward = 1")
        printf $text
    )
}

setup_py_venv(){

    vdir="net-env"

    if [ -d $vdir ]; then
        rm -rf $vdir
    fi

    python -m venv net-env

    source net-env/bin/activate

    pip3 install scapy
    pip3 install dpkt
    pip3 install numpy

    deactivate

    return $?
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
        echo "konsole --noclose -e"
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
        printf "\n## Launching...\n"
        return 0
    else
        printf "\n## Aborting...\n"
        return 1
    fi
}

do_choice(){

    echo ""
    read -n 1 -r -p ">> " answer
    echo ""

    if [[ "$answer" =~ ^[yY]$ ]]; then
        return 0
    else
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

    echo "echo \$sc1 | \$(sudo -E python net-env/bin/scapy)" >> tscapy.sh
    echo "echo \$sc2 | \$(sudo -E python net-env/bin/scapy)" >> tscapy.sh
    echo "echo \$sc3 | \$(sudo -E python net-env/bin/scapy)" >> tscapy.sh
    echo "echo \$sc4 | \$(sudo -E python net-env/bin/scapy)" >> tscapy.sh
    echo "echo \$sc5 | \$(sudo -E python net-env/bin/scapy)" >> tscapy.sh
    echo "echo \$sc6 | \$(sudo -E python net-env/bin/scapy)" >> tscapy.sh

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

echo "## Checking the bridge..."

chk_dependency "virsh"

if [ $? -ne 0 ]; then
	exit 5
fi

chk_dependency "dnsmasq"

if [ $? -ne 0 ]; then
	exit 6
fi

chk_dependency "arm-none-eabi-gcc"

if [ $? -ne 0 ]; then
	exit 7
fi

echo "## Do you want to setup the bridge? (y >> yes | any other char >> no)"
do_choice

if [ $? -eq 0 ]; then
	res=$(setup_bridge)

    if [ $? -ne 0 ]; then
        echo "$res"
        exit 8
    fi

    res=$(setup_qemu_bh)

    if [ $? -ne 0 ]; then
        echo "$res"
        exit 9
    fi

    echo "## Bridge OK!"
fi

echo "## Do you want to setup py env? (y >> yes | any other char >> no)"
do_choice

if [ $? -eq 0 ]; then

    printf "## Setting up py venv, this may take a while...\n"

    cd ../PART_4

    setup_py_venv

    if [ $? -ne 0 ]; then
        printf "## FATAL: could not setup python venv!\n"
        exit 10
    fi

    cd ../PART_3

    echo "## py virtual env OK!"
fi

printf "##### dependencies OK!\n"

## PART 1 : we prepare the ruleset
cd Resources

printf "##### Preparing the rules for the firewall...\n"

echo "### Opening the rule editing mode..."

nano rules.yaml # A >> Editing of the rules

echo "### End editing!"

python3 rulegen.py # B >> Generation of the rules

if [ $? -ne 0 ]; then
    echo "## FATAL: could not create the rules! aborting..."
	exit 11
fi

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
	exit 12
fi

build_the_demo $script_dir # Launch the demo

if [ $? -ne 0 ]; then
	exit 13
fi

qpid=$(do_launch_qemu $script_dir)

if [ $? -ne 0 ]; then
    echo $qpid
    echo "## FATAL: something went wrong launching the demo"
    exit 14
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
    source net-env/bin/activate
    prepare_scapy
    sudo -E $usr_con "bash tscapy.sh"
    if [ $? -ne 0 ]; then
        printf "##### Scapy FAIL! aborting...\n"
        exit 15
    fi
    sleep 5
    rm tscapy.sh
fi

printf "##### Scapy OK!\n"

## End PART 3

## PART 4: QEMU kill and Result analyze

printf "##### Stopping QEMU...\n"

kill -9 $qpid

printf "##### Fetching results...\n"

python3 pcap.py
deactivate

if [ $? -ne 0 ]; then
    printf "## FATAL: Could NOT compute the pcap! aborting...\n"
	exit 16
fi

sleep 2

wireshark -R "!tcp.srcport == 5000 && !tcp.analysis.retransmission" output.pcap


## End PART 4
