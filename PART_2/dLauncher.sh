#!/bin/bash

chk_dependency(){
	if [ $# -lt 1 ]; then
		return 2  #err
	else
		if ! type "$1" &>/dev/null; then
			echo ">> FATAL: please install $1 and try again!"
			return 1  #not found
		else
			return 0  #found
		fi
	fi
}

build_the_demo(){

	printf "\n>> Building the Demo...\n"

	log_path="../../../../../../build_log.txt"
	make clean &> $log_path
	make &>> $log_path

	if [ $? -eq 0 ]; then

		rm $log_path	#logs of make not needed

		printf "\n>> SUCCESS!\n>> Attempting to launch QEMU...\n"

		qemu-system-arm -machine mps2-an385 -cpu cortex-m3 -m 16M -kernel ./output/RTOSDemo.out -monitor none -nographic -serial stdio

	else

		echo ">> FATAL ERROR: errors building the demo, see build_log.txt"
	fi
}

chk_dependency "dialog"


if [ $? -ne 0 ]; then
	exit 1
fi

chk_dependency "make"

if [ $? -ne 0 ]; then
	exit 2
fi

chk_dependency "qemu-system-arm"

if [ $? -ne 0 ]; then
	exit 3
fi

cmd=(dialog --keep-tite --menu "Which demo do I start?" 10 40 10)

options=(1 "Memory Allocation Demo"
         2 "Dynamic Priority Demo"
         3 "Simple Scheduling Demo")

choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)

clear

case $choices in
  1)
    echo "# Starting the Memory Allocation Demo..."
    cd ./Memory_Allocation_Demo/FreeRTOS/Demo/CORTEX_MPS2_QEMU_MEM_DEMO/build/gcc/;;
  2)
    echo "# Starting the Dynamic Priority Demo"
    cd ./Dynamic_Priority_Demo/FreeRTOS/Demo/CORTEX_MPS2_QEMU_SCHEDULING/build/gcc;;
  3)
    echo "# Starting the Simple Scheduling Demo"
    cd ./Simple_Scheduling_Demo/FreeRTOS/Demo/CORTEX_MPS2_QEMU_SCHEDULING/build/gcc;;
  *)
    exit 0 ;;
esac

build_the_demo
