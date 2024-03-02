#!/bin/bash

# Get the script's execution location (including spaces)
script_dir="$(realpath "$(dirname "$0")")"

# Ensure the subfolder exists
if [[ ! -d "$script_dir/FreeRTOS/FreeRTOS-Plus/Demo/FreeRTOS_Plus_TCP_Echo_Qemu_mps2" ]]; then
  echo "Error: Subfolder 'FreeRTOS/FreeRTOS-Plus/Demo/FreeRTOS_Plus_TCP_Echo_Qemu_mps2' not found in the script directory."
  echo "Please check the folder names and structure."
  exit 1
fi

# Change directory, handling potential spaces
cd "$script_dir/FreeRTOS/FreeRTOS-Plus/Demo/FreeRTOS_Plus_TCP_Echo_Qemu_mps2" || {
  echo "Error: Could not change directory. Check folder permissions and accessibility."
  exit 1
}

# Execute the "make" command
make --quiet

# Optionally display the output of "make" (uncomment if desired)
#make | tee make_output.log

echo "Finished executing 'make' in the FreeRTOS subfolder."

echo "Now launch in another terminal netcat nc -l 5000"

echo "Press 'Y' to continue or any other key to exit."
read -n 1 -r -p "" answer

if [[ "$answer" =~ ^[yY]$ ]]; then
  echo "You entered 'Y'. Proceeding..."
  # Your commands to execute upon Y input go here
  sudo qemu-system-arm -machine mps2-an385 -cpu cortex-m3 -kernel ./build/freertos_tcp_mps2_demo.axf -netdev bridge,id=mynet0,br=virbr0 -net nic,netdev=mynet0,macaddr=52:54:00:12:34:AD,model=lan9118 -object filter-dump,id=tap_dump,netdev=mynet0,file=/tmp/qemu_tap_dump -nographic -serial stdio  -monitor none -semihosting -semihosting-config enable=on,target=native > "$script_dir/out.log"

  #Out log to folder PART_4 >
else
  echo "You didn't enter 'Y'. Exiting..."
  exit 0
fi





