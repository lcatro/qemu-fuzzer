
#ifndef __FUZZER_MUTITE_H__
#define __FUZZER_MUTITE_H__

#define RANDOM_FUZZING_READ_WRITE_RANGE  0x2
#define RANDOM_FUZZING_ENTRY_RANGE       0x2
#define RANDOM_FUZZING_SIZE_RANGE        0x8

#ifdef __x86_64__
#define RANDOM_FUZZING_RANDOM_RANGE  0xFFFFFFFFFFFFFFFF
typedef uint64_t memory_address;
#else
#define RANDOM_FUZZING_RANDOM_RANGE  0xFFFFFFFF
typedef uint32_t memory_address;
#endif

#define RANDOM_FUZZING_READ          0x00
#define RANDOM_FUZZING_WRITE         0x01
#define RANDOM_FUZZING_ENTRY_MMIO    0x00
#define RANDOM_FUZZING_ENTRY_PORTIO  0x01
#define RANDOM_FUZZING_ENTRY_DMA     0x02
#define RANDOM_FUZZING_ENTRY_VMCALL  0x03

#define GET_FUZZ_ENTRY(FUZZ_METHOD)        ((FUZZ_METHOD & 0xF))
#define GET_FUZZ_IO(FUZZ_METHOD)           ((FUZZ_METHOD & 0xF0) >> 4)
#define GET_FUZZ_OFFSET(FUZZ_METHOD)       ((FUZZ_METHOD & 0xFFFFFF00) >> 8)
#define SET_FUZZ_ENTRY(FUZZ_METHOD,VALUE)  (FUZZ_METHOD |= ((VALUE & 0xF)))
#define SET_FUZZ_IO(FUZZ_METHOD,VALUE)     (FUZZ_METHOD |= ((VALUE & 0xF) << 4))
#define SET_FUZZ_OFFSET(FUZZ_METHOD,VALUE) (FUZZ_METHOD |= ((VALUE & 0xFFFFFF) << 8))


typedef struct {
    int random_fuzzing_method;
    int random_fuzzing_size;
    int random_fuzzing_r1;
    int random_fuzzing_r2;
} fuzz_data;


void  init_random(void);
fuzz_data* fuzz_random_data_maker(int data_size);
fuzz_data* fuzz_random_data_maker_by_device_register_map(device_register* device_register_map,int device_register_map_count);
char* data_maker_block(int data_size,int data_random1,int data_random2);
uint_t data_maker_number(int data_size,int data_random1,int data_random2);

#endif
