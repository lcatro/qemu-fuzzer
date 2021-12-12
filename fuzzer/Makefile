
all:
	clang++ -g -fsanitize=address fuzzer.cc fuzzer_mutite.c fuzzer_device_table.c device_register_data.c -o fuzzer -I../kvm_hypercall -I../instrument -pthread

clean:
	rm -rf fuzzer

