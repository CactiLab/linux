// GL [CODE_CRED] +
#ifndef _LINUX_CRED_SIGN_H
#define _LINUX_CRED_SIGN_H

#ifdef CONFIG_ARM64_PTR_AUTH_CRED_PROTECT

/**
 * get_pac_bytes - Calculate pointer authentication code using ARMv8.3a PACGA instruction
 * 
 * @field_pointer The pointer to the input data
 * @field_size The size of the data in byte, greater than 0
 * @xm The initial value for context of PACGA instruction
 * 
 * This function is only for get_cred_sac, don't call it anywhere else.
 * 
 * Let the token "xn" be the input data for PACGA, xn is 64 bits.
 * If field_size is 8, the data is 64 bits, perfect for PACGA.
 * If field_size is less than 8, pad 0 for the most significant bits of xn.
 * If field_size is greater than 8, use PACGA multiple times, 8 bytes by 8 bytees.
 * In this case, the initial context is xm, the context for the next PACGA would be 
 * the result of the previous PACGA instruction.
 * 
 * Return pointer authentication code in 64 bits. The higher 32 bits are the PAC,
 * the lower 32 bits will always be 0. This is the raw data calculated by PACGA.
*/
static inline __attribute__((always_inline)) u_int64_t get_pac_bytes(const void *field_pointer, size_t field_size, u_int64_t xm) {
	if (field_size <= 0) {
		return 0;
	}

	/* For copying data byte by byte */
	char *field = (char *) field_pointer;
	/* Loop control variable */
	size_t total_chunk_size = 0;
	/* Final result */
	u_int64_t xd;
	/* Input data for PACGA */
	u_int64_t xn;
	/* Temporary variable */
	u_int64_t t;

	/* The number of loop is ceil(field_size / 8) */
	while (total_chunk_size < field_size) {
		size_t current_chunk_size = (field_size - total_chunk_size >= 8) ? 8 : field_size - total_chunk_size;
		xn = 0L;

		/* copy data to the variable xn */
		int i = 0;
		for (; i < current_chunk_size; ++i) {
			t = (u_int64_t) (*(field + i));
			xn |= t << (8 * i);
		}

		/* PACGA instruction is for ARMv8.3a
		 * variable xn and xm will be the input operators for PACGA
		 * variable xd takes the result
		 */
		asm volatile(
			"PACGA %[out], %[val], %[context]\n\t"
			: [out] "=r" (xd)
			: [val] "r" (xn), [context] "r" (xm)
			:
		);
		// printk(KERN_INFO "---------------------\n");
		// printk(KERN_INFO "xn = %lx, xm = %lx, xd = %lx\n", xn, xm, xd);
		// printk(KERN_INFO "---------------------\n");
		total_chunk_size += 8;
		field += 8;
		xm = xd;
	}
	return xd;
}

#endif

#endif
//-----