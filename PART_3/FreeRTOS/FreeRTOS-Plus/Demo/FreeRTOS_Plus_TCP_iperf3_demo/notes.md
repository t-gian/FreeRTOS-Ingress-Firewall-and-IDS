qemu-system-arm \ 
-machine mps2-an385 \
-cpu cortex-m3 \ 
-kernel [path-to]/RTOSDemo.out -monitor none -nographic -serial stdio -s -S
