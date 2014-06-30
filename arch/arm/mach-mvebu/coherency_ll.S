/*
 * Coherency fabric: low level functions
 *
 * Copyright (C) 2012 Marvell
 *
 * Gregory CLEMENT <gregory.clement@free-electrons.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 *
 * This file implements the assembly function to add a CPU to the
 * coherency fabric. This function is called by each of the secondary
 * CPUs during their early boot in an SMP kernel, this why this
 * function have to callable from assembly. It can also be called by a
 * primary CPU from C code during its boot.
 */

#include <linux/linkage.h>
#define ARMADA_XP_CFB_CTL_REG_OFFSET 0x0
#define ARMADA_XP_CFB_CFG_REG_OFFSET 0x4

#include <asm/assembler.h>

	.text
<<<<<<< HEAD
=======
/* Returns the coherency base address in r1 (r0 is untouched) */
ENTRY(ll_get_coherency_base)
	mrc	p15, 0, r1, c1, c0, 0
	tst	r1, #CR_M @ Check MMU bit enabled
	bne	1f

	/*
	 * MMU is disabled, use the physical address of the coherency
	 * base address.
	 */
	adr	r1, 3f
	ldr	r3, [r1]
	ldr	r1, [r1, r3]
	b	2f
1:
	/*
	 * MMU is enabled, use the virtual address of the coherency
	 * base address.
	 */
	ldr	r1, =coherency_base
	ldr	r1, [r1]
2:
	ret	lr
ENDPROC(ll_get_coherency_base)

>>>>>>> 6ebbf2ce437b... ARM: convert all "mov.* pc, reg" to "bx reg" for ARMv6+
/*
 * r0: Coherency fabric base register address
 * r1: HW CPU id
 */
<<<<<<< HEAD
ENTRY(ll_set_cpu_coherent)
	/* Create bit by cpu index */
	mov	r3, #(1 << 24)
	lsl	r1, r3, r1
ARM_BE8(rev	r1, r1)

	/* Add CPU to SMP group - Atomic */
	add	r3, r0, #ARMADA_XP_CFB_CTL_REG_OFFSET
1:
	ldrex	r2, [r3]
	orr	r2, r2, r1
	strex 	r0, r2, [r3]
	cmp	r0, #0
	bne 1b

	/* Enable coherency on CPU - Atomic */
	add	r3, r3, #ARMADA_XP_CFB_CFG_REG_OFFSET
1:
	ldrex	r2, [r3]
	orr	r2, r2, r1
	strex	r0, r2, [r3]
	cmp	r0, #0
	bne 1b
=======
ENTRY(ll_get_coherency_cpumask)
	mrc	15, 0, r3, cr0, cr0, 5
	and	r3, r3, #15
	mov	r2, #(1 << 24)
	lsl	r3, r2, r3
ARM_BE8(rev	r3, r3)
	ret	lr
ENDPROC(ll_get_coherency_cpumask)

/*
 * ll_add_cpu_to_smp_group(), ll_enable_coherency() and
 * ll_disable_coherency() use the strex/ldrex instructions while the
 * MMU can be disabled. The Armada XP SoC has an exclusive monitor
 * that tracks transactions to Device and/or SO memory and thanks to
 * that, exclusive transactions are functional even when the MMU is
 * disabled.
 */

ENTRY(ll_add_cpu_to_smp_group)
	/*
	 * As r0 is not modified by ll_get_coherency_base() and
	 * ll_get_coherency_cpumask(), we use it to temporarly save lr
	 * and avoid it being modified by the branch and link
	 * calls. This function is used very early in the secondary
	 * CPU boot, and no stack is available at this point.
	 */
	mov 	r0, lr
	bl	ll_get_coherency_base
	bl	ll_get_coherency_cpumask
	mov 	lr, r0
	add	r0, r1, #ARMADA_XP_CFB_CFG_REG_OFFSET
1:
	ldrex	r2, [r0]
	orr	r2, r2, r3
	strex	r1, r2, [r0]
	cmp	r1, #0
	bne	1b
	ret	lr
ENDPROC(ll_add_cpu_to_smp_group)

ENTRY(ll_enable_coherency)
	/*
	 * As r0 is not modified by ll_get_coherency_base() and
	 * ll_get_coherency_cpumask(), we use it to temporarly save lr
	 * and avoid it being modified by the branch and link
	 * calls. This function is used very early in the secondary
	 * CPU boot, and no stack is available at this point.
	 */
	mov r0, lr
	bl	ll_get_coherency_base
	bl	ll_get_coherency_cpumask
	mov lr, r0
	add	r0, r1, #ARMADA_XP_CFB_CTL_REG_OFFSET
1:
	ldrex	r2, [r0]
	orr	r2, r2, r3
	strex	r1, r2, [r0]
	cmp	r1, #0
	bne	1b
	dsb
	mov	r0, #0
	ret	lr
ENDPROC(ll_enable_coherency)
>>>>>>> 6ebbf2ce437b... ARM: convert all "mov.* pc, reg" to "bx reg" for ARMv6+

	dsb
<<<<<<< HEAD
=======
	ret	lr
ENDPROC(ll_disable_coherency)
>>>>>>> 6ebbf2ce437b... ARM: convert all "mov.* pc, reg" to "bx reg" for ARMv6+

	mov	r0, #0
	mov	pc, lr
ENDPROC(ll_set_cpu_coherent)
