
CLANG = clang
CLANGPP = clang++

all:
	${CLANG} --static stub.c stub_base.c ../fuzzer/fuzzer_mutite.c ../fuzzer/fuzzer_device_table.c ../fuzzer/device_register_data.c -o stub -I../kvm_hypercall -I../fuzzer
	${CLANG} --static try_pwn.c stub_base.c ../fuzzer/fuzzer_mutite.c ../fuzzer/fuzzer_device_table.c ../fuzzer/device_register_data.c -o try_pwn -I../kvm_hypercall -I../fuzzer

clean:
	rm -rf stub
	rm -rf try_pwn

