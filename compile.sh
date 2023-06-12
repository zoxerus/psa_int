rm ./simple_switch.bc
rm ./simple_switch.c
rm ./simple_switch.o

make -f ~/p4/p4c/backends/ebpf/runtime/kernel.mk BPFOBJ=simple_switch.o P4FILE=simple_switch.p4 ARGS="-DPSA_PORT_RECIRCULATE=2" P4ARGS="--Wdisable=unused" psa
