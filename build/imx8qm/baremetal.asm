
/home/carlos/thesis/wrkdir/src/bao-baremetal-guest/build/imx8qm/baremetal.elf:     file format elf64-littleaarch64


Disassembly of section .start:

0000000080200000 <_start>:
#define GENERIC_TIMER_CNTCTL_CNTDIF0_OFFSET  (0x20)

.section .start, "ax"
.global _start
_start:
    mrs x0, MPIDR_EL1
    80200000:	d53800a0 	mrs	x0, mpidr_el1
    and x0, x0, MPIDR_CPU_MASK
    80200004:	92401c00 	and	x0, x0, #0xff
     * Check current exception level. If in:
     *     - el0 or el3, stop
     *     - el1, proceed
     *     - el2, jump to el1
     */
    mrs x1, currentEL
    80200008:	d5384241 	mrs	x1, currentel
    lsr x1, x1, 2
    8020000c:	d342fc21 	lsr	x1, x1, #2
    cmp x1, 0
    80200010:	f100003f 	cmp	x1, #0x0
    b.eq .
    80200014:	54000000 	b.eq	80200014 <_start+0x14>  // b.none
    cmp x1, 3
    80200018:	f1000c3f 	cmp	x1, #0x3
    b.eq .
    8020001c:	54000000 	b.eq	8020001c <_start+0x1c>  // b.none
    cmp x1, 1
    80200020:	f100043f 	cmp	x1, #0x1
    b.eq _enter_el1
    80200024:	54000220 	b.eq	80200068 <_enter_el1>  // b.none
    mrs x1, mpidr_el1
    80200028:	d53800a1 	mrs	x1, mpidr_el1
    msr vmpidr_el2, x1
    8020002c:	d51c00a1 	msr	vmpidr_el2, x1
    mov x1, 0
    80200030:	d2800001 	mov	x1, #0x0                   	// #0
#ifndef MPU
    // VTCR_EL2.MSA bit enables VMSA in Armv8-R which is RES1 in Armv8-A
    orr x1, x1, (1 << 31) 
    80200034:	b2610021 	orr	x1, x1, #0x80000000
#endif
    msr vtcr_el2, x1
    80200038:	d51c2141 	msr	vtcr_el2, x1
#if GIC_VERSION == GICV3
    mov x1, 0x9
    8020003c:	d2800121 	mov	x1, #0x9                   	// #9
    msr icc_sre_el2, x1
    80200040:	d51cc9a1 	msr	icc_sre_el2, x1
    str w2, [x1, GENERIC_TIMER_CNTCTL_CNTCR_OFFSET]
    ldr w2, [x1, GENERIC_TIMER_CNTCTL_CNTDIF0_OFFSET]
    msr cntfrq_el0, x2
#endif

    adr x1, _exception_vector
    80200044:	1000fde1 	adr	x1, 80202000 <_exception_vector>
    msr	VBAR_EL2, x1
    80200048:	d51cc001 	msr	vbar_el2, x1
    mov x1, SPSR_EL1t | SPSR_F | SPSR_I | SPSR_A | SPSR_D
    8020004c:	d2807881 	mov	x1, #0x3c4                 	// #964
    msr spsr_el2, x1
    80200050:	d51c4001 	msr	spsr_el2, x1
    mov x1, HCR_RW_BIT
    80200054:	d2b00001 	mov	x1, #0x80000000            	// #2147483648
    msr hcr_el2, x1
    80200058:	d51c1101 	msr	hcr_el2, x1
    adr x1, _enter_el1
    8020005c:	10000061 	adr	x1, 80200068 <_enter_el1>
    msr elr_el2, x1
    80200060:	d51c4021 	msr	elr_el2, x1
    eret
    80200064:	d69f03e0 	eret

0000000080200068 <_enter_el1>:

_enter_el1:
    adr x1, _exception_vector
    80200068:	1000fcc1 	adr	x1, 80202000 <_exception_vector>
    msr	VBAR_EL1, x1
    8020006c:	d518c001 	msr	vbar_el1, x1

    ldr x1, =MAIR_EL1_DFLT
    80200070:	58000541 	ldr	x1, 80200118 <clear+0x18>
    msr	MAIR_EL1, x1
    80200074:	d518a201 	msr	mair_el1, x1

    // Enable floating point
    mov x1, #(3 << 20)
    80200078:	d2a00601 	mov	x1, #0x300000              	// #3145728
    msr CPACR_EL1, x1
    8020007c:	d5181041 	msr	cpacr_el1, x1
    ldr x1, =(SCTLR_RES1 | SCTLR_C | SCTLR_I | SCTLR_M )
    msr sctlr_el1, x1

#else 

    ldr x1, =0x0000000000802510
    80200080:	58000501 	ldr	x1, 80200120 <clear+0x20>
    msr TCR_EL1, x1
    80200084:	d5182041 	msr	tcr_el1, x1

    adr x1, root_page_table
    80200088:	100b7bc1 	adr	x1, 80217000 <root_page_table>
    msr TTBR0_EL1, x1
    8020008c:	d5182001 	msr	ttbr0_el1, x1

    //TODO: invalidate caches, bp, .. ?

    tlbi	vmalle1
    80200090:	d508871f 	tlbi	vmalle1
	dsb	nsh
    80200094:	d503379f 	dsb	nsh
	isb
    80200098:	d5033fdf 	isb

    ldr x1, =(SCTLR_RES1 | SCTLR_M | SCTLR_C | SCTLR_I)
    8020009c:	58000461 	ldr	x1, 80200128 <clear+0x28>
    msr SCTLR_EL1, x1
    802000a0:	d5181001 	msr	sctlr_el1, x1

    tlbi	vmalle1
    802000a4:	d508871f 	tlbi	vmalle1
	dsb	nsh
    802000a8:	d503379f 	dsb	nsh
	isb
    802000ac:	d5033fdf 	isb
#endif

    cbnz x0, 1f
    802000b0:	b50000e0 	cbnz	x0, 802000cc <_enter_el1+0x64>

    ldr x16, =__bss_start 
    802000b4:	580003f0 	ldr	x16, 80200130 <clear+0x30>
    ldr x17, =__bss_end   
    802000b8:	58000411 	ldr	x17, 80200138 <clear+0x38>
    bl  clear
    802000bc:	94000011 	bl	80200100 <clear>
    .align 3
wait_flag:
    .dword 0x0
    .popsection

    adr x1, wait_flag
    802000c0:	10087c01 	adr	x1, 80211040 <wait_flag>
    mov x2, #1
    802000c4:	d2800022 	mov	x2, #0x1                   	// #1
    str x2, [x1]
    802000c8:	f9000022 	str	x2, [x1]

1:
    adr x1, wait_flag
    802000cc:	10087ba1 	adr	x1, 80211040 <wait_flag>
    ldr x2, [x1]
    802000d0:	f9400022 	ldr	x2, [x1]
    cbz x2, 1b
    802000d4:	b4ffffc2 	cbz	x2, 802000cc <_enter_el1+0x64>

    mov x3, #SPSel_SP							
    802000d8:	d2800023 	mov	x3, #0x1                   	// #1
	msr SPSEL, x3	
    802000dc:	d5184203 	msr	spsel, x3

    adr x1, _stack_base
    802000e0:	10401e01 	adr	x1, 802804a0 <_stack_base>
    ldr x2, =STACK_SIZE
    802000e4:	580002e2 	ldr	x2, 80200140 <clear+0x40>
    add x1, x1, x2
    802000e8:	8b020021 	add	x1, x1, x2
#ifndef SINGLE_CORE
    madd x1, x0, x2, x1
    802000ec:	9b020401 	madd	x1, x0, x2, x1
#endif
    mov sp, x1
    802000f0:	9100003f 	mov	sp, x1
   
    //TODO: other c runtime init (ctors, etc...)

    b _init
    802000f4:	14000244 	b	80200a04 <_init>
    b _exit
    802000f8:	14000232 	b	802009c0 <_exit>

00000000802000fc <psci_wake_up>:

.global psci_wake_up
psci_wake_up:
    b .
    802000fc:	14000000 	b	802000fc <psci_wake_up>

0000000080200100 <clear>:

 .func clear
clear:
2:
	cmp	x16, x17			
    80200100:	eb11021f 	cmp	x16, x17
	b.ge 1f				
    80200104:	5400006a 	b.ge	80200110 <clear+0x10>  // b.tcont
	str	xzr, [x16], #8	
    80200108:	f800861f 	str	xzr, [x16], #8
	b	2b				
    8020010c:	17fffffd 	b	80200100 <clear>
1:
	ret
    80200110:	d65f03c0 	ret
    80200114:	00000000 	udf	#0
    80200118:	0004ff00 	.word	0x0004ff00
    8020011c:	00000000 	.word	0x00000000
    80200120:	00802510 	.word	0x00802510
    80200124:	00000000 	.word	0x00000000
    80200128:	30c51835 	.word	0x30c51835
    8020012c:	00000000 	.word	0x00000000
    80200130:	80220000 	.word	0x80220000
    80200134:	00000000 	.word	0x00000000
    80200138:	80280498 	.word	0x80280498
    8020013c:	00000000 	.word	0x00000000
    80200140:	00004000 	.word	0x00004000
    80200144:	00000000 	.word	0x00000000

Disassembly of section .text:

0000000080200800 <irq_set_handler>:
#include <irq.h>

irq_handler_t irq_handlers[IRQ_NUM]; 

void irq_set_handler(unsigned id, irq_handler_t handler){
    if(id < IRQ_NUM)
    80200800:	710ffc1f 	cmp	w0, #0x3ff
    80200804:	540000a8 	b.hi	80200818 <irq_set_handler+0x18>  // b.pmore
        irq_handlers[id] = handler;
    80200808:	90000102 	adrp	x2, 80220000 <irq_handlers>
    8020080c:	91000042 	add	x2, x2, #0x0
    80200810:	f8205841 	str	x1, [x2, w0, uxtw #3]
    else if (id == IRQ_LPI_MIN)
        irq_handlers[250] = handler;    //Aleatory id just for test measurements
}
    80200814:	d65f03c0 	ret
    else if (id == IRQ_LPI_MIN)
    80200818:	7140081f 	cmp	w0, #0x2, lsl #12
    8020081c:	54ffffc1 	b.ne	80200814 <irq_set_handler+0x14>  // b.any
        irq_handlers[250] = handler;    //Aleatory id just for test measurements
    80200820:	90000100 	adrp	x0, 80220000 <irq_handlers>
    80200824:	f903e801 	str	x1, [x0, #2000]
}
    80200828:	d65f03c0 	ret
    8020082c:	d503201f 	nop

0000000080200830 <irq_handle>:

void irq_handle(unsigned id){
    if(id < IRQ_NUM && irq_handlers[id] != NULL)
    80200830:	90000102 	adrp	x2, 80220000 <irq_handlers>
void irq_handle(unsigned id){
    80200834:	2a0003e1 	mov	w1, w0
    if(id < IRQ_NUM && irq_handlers[id] != NULL)
    80200838:	91000042 	add	x2, x2, #0x0
    8020083c:	710ffc1f 	cmp	w0, #0x3ff
    80200840:	540000a8 	b.hi	80200854 <irq_handle+0x24>  // b.pmore
    80200844:	f8615843 	ldr	x3, [x2, w1, uxtw #3]
    80200848:	b4000063 	cbz	x3, 80200854 <irq_handle+0x24>
        irq_handlers[id](id);
    8020084c:	aa0303f0 	mov	x16, x3
    80200850:	d61f0200 	br	x16
    else{
        irq_handlers[250](id);
    80200854:	f943e842 	ldr	x2, [x2, #2000]
    80200858:	2a0103e0 	mov	w0, w1
    8020085c:	aa0203f0 	mov	x16, x2
    80200860:	d61f0200 	br	x16
	...

0000000080200870 <_read>:
#include <cpu.h>
#include <fences.h>
#include <wfi.h>

int _read(int file, char *ptr, int len)
{
    80200870:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80200874:	910003fd 	mov	x29, sp
    80200878:	f90013f5 	str	x21, [sp, #32]
    8020087c:	2a0203f5 	mov	w21, w2
    int i;
    for (i = 0; i < len; ++i)
    80200880:	7100005f 	cmp	w2, #0x0
    80200884:	5400014d 	b.le	802008ac <_read+0x3c>
    80200888:	a90153f3 	stp	x19, x20, [sp, #16]
    8020088c:	aa0103f3 	mov	x19, x1
    80200890:	8b22c034 	add	x20, x1, w2, sxtw
    80200894:	d503201f 	nop
    {
        ptr[i] = uart_getchar();
    80200898:	9400007a 	bl	80200a80 <uart_getchar>
    8020089c:	38001660 	strb	w0, [x19], #1
    for (i = 0; i < len; ++i)
    802008a0:	eb14027f 	cmp	x19, x20
    802008a4:	54ffffa1 	b.ne	80200898 <_read+0x28>  // b.any
    802008a8:	a94153f3 	ldp	x19, x20, [sp, #16]
    }

    return len;
}
    802008ac:	2a1503e0 	mov	w0, w21
    802008b0:	f94013f5 	ldr	x21, [sp, #32]
    802008b4:	a8c37bfd 	ldp	x29, x30, [sp], #48
    802008b8:	d65f03c0 	ret
    802008bc:	d503201f 	nop

00000000802008c0 <_write>:

int _write(int file, char *ptr, int len)
{
    802008c0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    802008c4:	910003fd 	mov	x29, sp
    802008c8:	a90153f3 	stp	x19, x20, [sp, #16]
    802008cc:	8b22c034 	add	x20, x1, w2, sxtw
    802008d0:	f90013f5 	str	x21, [sp, #32]
    802008d4:	2a0203f5 	mov	w21, w2
    int i;
    for (i = 0; i < len; ++i)
    802008d8:	7100005f 	cmp	w2, #0x0
    802008dc:	5400022d 	b.le	80200920 <_write+0x60>
    802008e0:	aa0103f3 	mov	x19, x1
    802008e4:	14000005 	b	802008f8 <_write+0x38>
    802008e8:	91000673 	add	x19, x19, #0x1
    {
        if (ptr[i] == '\n')
        {
            uart_putc('\r');
        }
        uart_putc(ptr[i]);
    802008ec:	94000061 	bl	80200a70 <uart_putc>
    for (i = 0; i < len; ++i)
    802008f0:	eb14027f 	cmp	x19, x20
    802008f4:	54000160 	b.eq	80200920 <_write+0x60>  // b.none
        if (ptr[i] == '\n')
    802008f8:	39400260 	ldrb	w0, [x19]
    802008fc:	7100281f 	cmp	w0, #0xa
    80200900:	54ffff41 	b.ne	802008e8 <_write+0x28>  // b.any
            uart_putc('\r');
    80200904:	528001a0 	mov	w0, #0xd                   	// #13
    80200908:	9400005a 	bl	80200a70 <uart_putc>
        uart_putc(ptr[i]);
    8020090c:	39400260 	ldrb	w0, [x19]
    for (i = 0; i < len; ++i)
    80200910:	91000673 	add	x19, x19, #0x1
        uart_putc(ptr[i]);
    80200914:	94000057 	bl	80200a70 <uart_putc>
    for (i = 0; i < len; ++i)
    80200918:	eb14027f 	cmp	x19, x20
    8020091c:	54fffee1 	b.ne	802008f8 <_write+0x38>  // b.any
    }

    return len;
}
    80200920:	a94153f3 	ldp	x19, x20, [sp, #16]
    80200924:	2a1503e0 	mov	w0, w21
    80200928:	f94013f5 	ldr	x21, [sp, #32]
    8020092c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80200930:	d65f03c0 	ret

0000000080200934 <_lseek>:

int _lseek(int file, int ptr, int dir)
{
    80200934:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80200938:	910003fd 	mov	x29, sp
    errno = ESPIPE;
    8020093c:	940007b1 	bl	80202800 <__errno>
    80200940:	aa0003e1 	mov	x1, x0
    80200944:	528003a2 	mov	w2, #0x1d                  	// #29
    return -1;
}
    80200948:	12800000 	mov	w0, #0xffffffff            	// #-1
    errno = ESPIPE;
    8020094c:	b9000022 	str	w2, [x1]
}
    80200950:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80200954:	d65f03c0 	ret
    80200958:	d503201f 	nop
    8020095c:	d503201f 	nop

0000000080200960 <_close>:

int _close(int file)
{
    return -1;
}
    80200960:	12800000 	mov	w0, #0xffffffff            	// #-1
    80200964:	d65f03c0 	ret
    80200968:	d503201f 	nop
    8020096c:	d503201f 	nop

0000000080200970 <_fstat>:

int _fstat(int file, struct stat *st)
{
    st->st_mode = S_IFCHR;
    80200970:	52840002 	mov	w2, #0x2000                	// #8192
    return 0;
}
    80200974:	52800000 	mov	w0, #0x0                   	// #0
    st->st_mode = S_IFCHR;
    80200978:	b9000422 	str	w2, [x1, #4]
}
    8020097c:	d65f03c0 	ret

0000000080200980 <_isatty>:

int _isatty(int fd)
{
    80200980:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80200984:	910003fd 	mov	x29, sp
    errno = ENOTTY;
    80200988:	9400079e 	bl	80202800 <__errno>
    8020098c:	aa0003e1 	mov	x1, x0
    80200990:	52800322 	mov	w2, #0x19                  	// #25
    return 0;
}
    80200994:	52800000 	mov	w0, #0x0                   	// #0
    errno = ENOTTY;
    80200998:	b9000022 	str	w2, [x1]
}
    8020099c:	a8c17bfd 	ldp	x29, x30, [sp], #16
    802009a0:	d65f03c0 	ret

00000000802009a4 <_sbrk>:

void* _sbrk(int increment)
{
    extern char _heap_base;
    static char* heap_end = &_heap_base;
    char* current_heap_end = heap_end;
    802009a4:	b0000082 	adrp	x2, 80211000 <__mprec_tens+0x180>
{
    802009a8:	2a0003e1 	mov	w1, w0
    char* current_heap_end = heap_end;
    802009ac:	f9401040 	ldr	x0, [x2, #32]
    heap_end += increment;
    802009b0:	8b21c001 	add	x1, x0, w1, sxtw
    802009b4:	f9001041 	str	x1, [x2, #32]
    return current_heap_end;
}
    802009b8:	d65f03c0 	ret
    802009bc:	d503201f 	nop

00000000802009c0 <_exit>:
    DMB(ishld);
}

static inline void fence_ord()
{
    DMB(ish);
    802009c0:	d5033bbf 	dmb	ish
    802009c4:	d503201f 	nop
#ifndef WFI_H
#define WFI_H

static inline void wfi(){
    asm volatile("wfi\n\t" ::: "memory");
    802009c8:	d503207f 	wfi

void _exit(int return_value)
{
    fence_ord();
    while (1) {
    802009cc:	17ffffff 	b	802009c8 <_exit+0x8>

00000000802009d0 <_getpid>:
}

int _getpid(void)
{
  return 1;
}
    802009d0:	52800020 	mov	w0, #0x1                   	// #1
    802009d4:	d65f03c0 	ret
    802009d8:	d503201f 	nop
    802009dc:	d503201f 	nop

00000000802009e0 <_kill>:

int _kill(int pid, int sig)
{
    802009e0:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    802009e4:	910003fd 	mov	x29, sp
    errno = EINVAL;
    802009e8:	94000786 	bl	80202800 <__errno>
    802009ec:	aa0003e1 	mov	x1, x0
    802009f0:	528002c2 	mov	w2, #0x16                  	// #22
    return -1;
}
    802009f4:	12800000 	mov	w0, #0xffffffff            	// #-1
    errno = EINVAL;
    802009f8:	b9000022 	str	w2, [x1]
}
    802009fc:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80200a00:	d65f03c0 	ret

0000000080200a04 <_init>:

static bool init_done = false;
static spinlock_t init_lock = SPINLOCK_INITVAL;

__attribute__((weak))
void _init(){
    80200a04:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
static inline void spin_lock(spinlock_t* lock){

    uint32_t const ONE = 1;
    spinlock_t tmp;

    asm volatile (
    80200a08:	d0000100 	adrp	x0, 80222000 <init_lock>
    80200a0c:	52800021 	mov	w1, #0x1                   	// #1
    80200a10:	910003fd 	mov	x29, sp
    80200a14:	f9000bf3 	str	x19, [sp, #16]
    80200a18:	91000013 	add	x19, x0, #0x0
    80200a1c:	885ffe62 	ldaxr	w2, [x19]
    80200a20:	35ffffe2 	cbnz	w2, 80200a1c <_init+0x18>
    80200a24:	88027e61 	stxr	w2, w1, [x19]
    80200a28:	35ffffa2 	cbnz	w2, 80200a1c <_init+0x18>

    spin_lock(&init_lock);
    if(!init_done) {
    80200a2c:	39401260 	ldrb	w0, [x19, #4]
    80200a30:	b9002fe2 	str	w2, [sp, #44]
    80200a34:	360000a0 	tbz	w0, #0, 80200a48 <_init+0x44>

}

static inline void spin_unlock(spinlock_t* lock){

    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80200a38:	889ffe7f 	stlr	wzr, [x19]
        init_done = true;
        uart_init();
    }
    spin_unlock(&init_lock);
    
    arch_init();
    80200a3c:	9400003d 	bl	80200b30 <arch_init>

    int ret = main();
    80200a40:	94000514 	bl	80201e90 <main>
    _exit(ret);
    80200a44:	97ffffdf 	bl	802009c0 <_exit>
        init_done = true;
    80200a48:	39001261 	strb	w1, [x19, #4]
        uart_init();
    80200a4c:	94000005 	bl	80200a60 <uart_init>
    80200a50:	17fffffa 	b	80200a38 <_init+0x34>
	...

0000000080200a60 <uart_init>:
#include <nxp_uart.h>

volatile struct lpuart * const uart = UART_ADDR;

void uart_init(){
   nxp_uart_init(uart);
    80200a60:	d2ab40c0 	mov	x0, #0x5a060000            	// #1510342656
    80200a64:	14000013 	b	80200ab0 <nxp_uart_init>
    80200a68:	d503201f 	nop
    80200a6c:	d503201f 	nop

0000000080200a70 <uart_putc>:
}

void uart_putc(char c){
    nxp_uart_putc(uart, c);
    80200a70:	2a0003e1 	mov	w1, w0
    80200a74:	d2ab40c0 	mov	x0, #0x5a060000            	// #1510342656
    80200a78:	14000017 	b	80200ad4 <nxp_uart_putc>
    80200a7c:	d503201f 	nop

0000000080200a80 <uart_getchar>:
}

char uart_getchar(){
    return nxp_uart_getchar(uart);
    80200a80:	d2ab40c0 	mov	x0, #0x5a060000            	// #1510342656
    80200a84:	1400001b 	b	80200af0 <nxp_uart_getchar>
    80200a88:	d503201f 	nop
    80200a8c:	d503201f 	nop

0000000080200a90 <uart_enable_rxirq>:
}

void uart_enable_rxirq(){
    nxp_uart_enable_rxirq(uart);
    80200a90:	d2ab40c0 	mov	x0, #0x5a060000            	// #1510342656
    80200a94:	1400001b 	b	80200b00 <nxp_uart_enable_rxirq>
    80200a98:	d503201f 	nop
    80200a9c:	d503201f 	nop

0000000080200aa0 <uart_clear_rxirq>:
}

void uart_clear_rxirq(){
    nxp_uart_clear_rxirq(uart);
    80200aa0:	d2ab40c0 	mov	x0, #0x5a060000            	// #1510342656
    80200aa4:	1400001b 	b	80200b10 <nxp_uart_clear_rxirq>
	...

0000000080200ab0 <nxp_uart_init>:
#include <nxp_uart.h>

void nxp_uart_init(volatile struct lpuart *uart){
   
    //reset
    uart->global &= ~LPUART_GLOBAL_RST_BIT; 
    80200ab0:	b9400801 	ldr	w1, [x0, #8]

    // assumes 80 MHz source clock
    uart->baud = LPUART_BAUD_80MHZ_115200;
    80200ab4:	52801143 	mov	w3, #0x8a                  	// #138
    80200ab8:	72a08043 	movk	w3, #0x402, lsl #16
   
    //enable TX and RX 
    uart->ctrl = LPUART_CTRL_TE_BIT | LPUART_CTRL_RE_BIT; 
    80200abc:	52a00182 	mov	w2, #0xc0000               	// #786432
    uart->global &= ~LPUART_GLOBAL_RST_BIT; 
    80200ac0:	121e7821 	and	w1, w1, #0xfffffffd
    80200ac4:	b9000801 	str	w1, [x0, #8]
    uart->baud = LPUART_BAUD_80MHZ_115200;
    80200ac8:	b9001003 	str	w3, [x0, #16]
    uart->ctrl = LPUART_CTRL_TE_BIT | LPUART_CTRL_RE_BIT; 
    80200acc:	b9001802 	str	w2, [x0, #24]
}
    80200ad0:	d65f03c0 	ret

0000000080200ad4 <nxp_uart_putc>:

void nxp_uart_putc(volatile struct lpuart *uart, char c){
    80200ad4:	12001c21 	and	w1, w1, #0xff
    while(!(uart->stat & LPUART_STAT_TDRE_BIT));
    80200ad8:	b9401402 	ldr	w2, [x0, #20]
    80200adc:	36bfffe2 	tbz	w2, #23, 80200ad8 <nxp_uart_putc+0x4>
    uart->data = c;
    80200ae0:	b9001c01 	str	w1, [x0, #28]
}
    80200ae4:	d65f03c0 	ret
    80200ae8:	d503201f 	nop
    80200aec:	d503201f 	nop

0000000080200af0 <nxp_uart_getchar>:

char nxp_uart_getchar(volatile struct lpuart *uart){
    return uart->data;
    80200af0:	b9401c00 	ldr	w0, [x0, #28]
}
    80200af4:	d65f03c0 	ret
    80200af8:	d503201f 	nop
    80200afc:	d503201f 	nop

0000000080200b00 <nxp_uart_enable_rxirq>:

void nxp_uart_enable_rxirq(volatile struct lpuart *uart){
    uart->ctrl |= LPUART_CTRL_RIE_BIT;
    80200b00:	b9401801 	ldr	w1, [x0, #24]
    80200b04:	320b0021 	orr	w1, w1, #0x200000
    80200b08:	b9001801 	str	w1, [x0, #24]
}
    80200b0c:	d65f03c0 	ret

0000000080200b10 <nxp_uart_clear_rxirq>:
    return uart->data;
    80200b10:	b9401c01 	ldr	w1, [x0, #28]

void nxp_uart_clear_rxirq(volatile struct lpuart *uart){
    (void) nxp_uart_getchar(uart);
    uart->stat |= LPUART_STAT_OR_BIT;
    80200b14:	b9401401 	ldr	w1, [x0, #20]
    80200b18:	320d0021 	orr	w1, w1, #0x80000
    80200b1c:	b9001401 	str	w1, [x0, #20]
    80200b20:	d65f03c0 	ret
	...

0000000080200b30 <arch_init>:
#include <sysregs.h>

void _start();

__attribute__((weak))
void arch_init(){
    80200b30:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80200b34:	910003fd 	mov	x29, sp
    80200b38:	a90153f3 	stp	x19, x20, [sp, #16]
SYSREG_GEN_ACCESSORS(clidr_el1);
SYSREG_GEN_ACCESSORS(csselr_el1);
SYSREG_GEN_ACCESSORS(ccsidr_el1);
SYSREG_GEN_ACCESSORS(ccsidr2_el1);
SYSREG_GEN_ACCESSORS(ctr_el0);
SYSREG_GEN_ACCESSORS(mpidr_el1);
    80200b3c:	d53800b3 	mrs	x19, mpidr_el1
    unsigned long cpuid = get_cpuid();
    gic_init();
    80200b40:	940000dc 	bl	80200eb0 <gic_init>
#include <core.h>
#include <sysregs.h>

static inline unsigned long get_cpuid(){
    unsigned long cpuid = sysreg_mpidr_el1_read();
    return cpuid & MPIDR_CPU_MASK;
    80200b44:	92401e73 	and	x19, x19, #0xff
SYSREG_GEN_ACCESSORS(ttbr0_el1);
SYSREG_GEN_ACCESSORS(mair_el1);
SYSREG_GEN_ACCESSORS(cptr_el1);
SYSREG_GEN_ACCESSORS(id_aa64mmfr0_el1);
SYSREG_GEN_ACCESSORS(tpidr_el1);
SYSREG_GEN_ACCESSORS(cntfrq_el0);
    80200b48:	d53be001 	mrs	x1, cntfrq_el0
    TIMER_FREQ = sysreg_cntfrq_el0_read();
    80200b4c:	d0000100 	adrp	x0, 80222000 <init_lock>
SYSREG_GEN_ACCESSORS(cntv_ctl_el0);
    80200b50:	d2800034 	mov	x20, #0x1                   	// #1
    80200b54:	f9000401 	str	x1, [x0, #8]
    80200b58:	d51be334 	msr	cntv_ctl_el0, x20
    sysreg_cntv_ctl_el0_write(1);

#if !(defined(SINGLE_CORE) || defined(NO_FIRMWARE))
    if(cpuid == 0){
    80200b5c:	b50001b3 	cbnz	x19, 80200b90 <arch_init+0x60>
    80200b60:	f90013f5 	str	x21, [sp, #32]
    80200b64:	90000015 	adrp	x21, 80200000 <_start>
    80200b68:	910002b5 	add	x21, x21, #0x0
        size_t i = 0;
        int ret = PSCI_E_SUCCESS;
        do {
            if(i == cpuid) continue;
    80200b6c:	f100027f 	cmp	x19, #0x0
            ret = psci_cpu_on(i, (uintptr_t) _start, 0);
    80200b70:	aa1503e1 	mov	x1, x21
    80200b74:	9a941273 	csel	x19, x19, x20, ne	// ne = any
    80200b78:	d2800002 	mov	x2, #0x0                   	// #0
    80200b7c:	aa1303e0 	mov	x0, x19
        } while(i++, ret == PSCI_E_SUCCESS);
    80200b80:	91000673 	add	x19, x19, #0x1
            ret = psci_cpu_on(i, (uintptr_t) _start, 0);
    80200b84:	9400001f 	bl	80200c00 <psci_cpu_on>
        } while(i++, ret == PSCI_E_SUCCESS);
    80200b88:	34ffff20 	cbz	w0, 80200b6c <arch_init+0x3c>
    80200b8c:	f94013f5 	ldr	x21, [sp, #32]
static inline void arm_at_s12e1w(uintptr_t vaddr) {
     asm volatile("at s12e1w, %0" ::"r"(vaddr));
}

static inline void arm_unmask_irq() {
    asm volatile("MSR   DAIFClr, #2\n\t");
    80200b90:	d50342ff 	msr	daifclr, #0x2
    }
#endif
    arm_unmask_irq();
}
    80200b94:	a94153f3 	ldp	x19, x20, [sp, #16]
    80200b98:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80200b9c:	d65f03c0 	ret

0000000080200ba0 <smc_call>:
	register unsigned long r0 asm("r0") = x0;
	register unsigned long r1 asm("r1") = x1;
	register unsigned long r2 asm("r2") = x2;
	register unsigned long r3 asm("r3") = x3;

    asm volatile(
    80200ba0:	d4000003 	smc	#0x0
			: "=r" (r0)
			: "r" (r0), "r" (r1), "r" (r2)
			: "r3");

	return r0;
}
    80200ba4:	d65f03c0 	ret
    80200ba8:	d503201f 	nop
    80200bac:	d503201f 	nop

0000000080200bb0 <psci_version>:
	register unsigned long r0 asm("r0") = x0;
    80200bb0:	d2b08000 	mov	x0, #0x84000000            	// #2214592512
	register unsigned long r1 asm("r1") = x1;
    80200bb4:	d2800001 	mov	x1, #0x0                   	// #0
	register unsigned long r2 asm("r2") = x2;
    80200bb8:	d2800002 	mov	x2, #0x0                   	// #0
    asm volatile(
    80200bbc:	d4000003 	smc	#0x0
--------------------------------- */

int32_t psci_version(void)
{
    return smc_call(PSCI_VERSION, 0, 0, 0);
}
    80200bc0:	d65f03c0 	ret

0000000080200bc4 <psci_cpu_suspend>:


int32_t psci_cpu_suspend(uint32_t power_state, uintptr_t entrypoint, 
                    unsigned long context_id)
{
    80200bc4:	2a0003e3 	mov	w3, w0
	register unsigned long r0 asm("r0") = x0;
    80200bc8:	d2800020 	mov	x0, #0x1                   	// #1
{
    80200bcc:	aa0103e2 	mov	x2, x1
	register unsigned long r0 asm("r0") = x0;
    80200bd0:	f2b88000 	movk	x0, #0xc400, lsl #16
	register unsigned long r1 asm("r1") = x1;
    80200bd4:	2a0303e1 	mov	w1, w3
    asm volatile(
    80200bd8:	d4000003 	smc	#0x0
    return smc_call(PSCI_CPU_SUSPEND, power_state, entrypoint, context_id);
}
    80200bdc:	d65f03c0 	ret

0000000080200be0 <psci_cpu_off>:
	register unsigned long r0 asm("r0") = x0;
    80200be0:	d2800040 	mov	x0, #0x2                   	// #2
	register unsigned long r1 asm("r1") = x1;
    80200be4:	d2800001 	mov	x1, #0x0                   	// #0
	register unsigned long r0 asm("r0") = x0;
    80200be8:	f2b08000 	movk	x0, #0x8400, lsl #16
	register unsigned long r2 asm("r2") = x2;
    80200bec:	d2800002 	mov	x2, #0x0                   	// #0
    asm volatile(
    80200bf0:	d4000003 	smc	#0x0

int32_t psci_cpu_off(void)
{
    return smc_call(PSCI_CPU_OFF, 0, 0, 0);
}
    80200bf4:	d65f03c0 	ret
    80200bf8:	d503201f 	nop
    80200bfc:	d503201f 	nop

0000000080200c00 <psci_cpu_on>:

int32_t psci_cpu_on(unsigned long target_cpu, uintptr_t entrypoint, 
                    unsigned long context_id)
{
    80200c00:	aa0003e3 	mov	x3, x0
	register unsigned long r0 asm("r0") = x0;
    80200c04:	d2800060 	mov	x0, #0x3                   	// #3
{
    80200c08:	aa0103e2 	mov	x2, x1
	register unsigned long r0 asm("r0") = x0;
    80200c0c:	f2b88000 	movk	x0, #0xc400, lsl #16
	register unsigned long r1 asm("r1") = x1;
    80200c10:	aa0303e1 	mov	x1, x3
    asm volatile(
    80200c14:	d4000003 	smc	#0x0
    return smc_call(PSCI_CPU_ON, target_cpu, entrypoint, context_id);
}
    80200c18:	d65f03c0 	ret
    80200c1c:	d503201f 	nop

0000000080200c20 <psci_affinity_info>:

int32_t psci_affinity_info(unsigned long target_affinity, 
                            uint32_t lowest_affinity_level)
{
    80200c20:	aa0003e3 	mov	x3, x0
	register unsigned long r0 asm("r0") = x0;
    80200c24:	d2800080 	mov	x0, #0x4                   	// #4
{
    80200c28:	2a0103e2 	mov	w2, w1
	register unsigned long r0 asm("r0") = x0;
    80200c2c:	f2b88000 	movk	x0, #0xc400, lsl #16
	register unsigned long r1 asm("r1") = x1;
    80200c30:	aa0303e1 	mov	x1, x3
    asm volatile(
    80200c34:	d4000003 	smc	#0x0
    return smc_call(PSCI_AFFINITY_INFO, target_affinity, 
                    lowest_affinity_level, 0);
}
    80200c38:	d65f03c0 	ret
    80200c3c:	00000000 	udf	#0

0000000080200c40 <irq_enable>:

#ifndef GIC_VERSION
#error "GIC_VERSION not defined for this platform"
#endif

void irq_enable(unsigned id) {
    80200c40:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
   gic_set_enable(id, true); 
    80200c44:	52800021 	mov	w1, #0x1                   	// #1
void irq_enable(unsigned id) {
    80200c48:	910003fd 	mov	x29, sp
    80200c4c:	f9000bf3 	str	x19, [sp, #16]
   gic_set_enable(id, true); 
    80200c50:	2a0003f3 	mov	w19, w0
    80200c54:	aa1303e0 	mov	x0, x19
    80200c58:	94000326 	bl	802018f0 <gic_set_enable>
SYSREG_GEN_ACCESSORS(mpidr_el1);
    80200c5c:	d53800a1 	mrs	x1, mpidr_el1
   if(GIC_VERSION == GICV2) {
       gic_set_trgt(id, gic_get_trgt(id) | (1 << get_cpuid()));
   } else {
       gic_set_route(id, get_cpuid());
    80200c60:	aa1303e0 	mov	x0, x19
    80200c64:	92401c21 	and	x1, x1, #0xff
   }
}
    80200c68:	f9400bf3 	ldr	x19, [sp, #16]
    80200c6c:	a8c27bfd 	ldp	x29, x30, [sp], #32
       gic_set_route(id, get_cpuid());
    80200c70:	14000314 	b	802018c0 <gic_set_route>

0000000080200c74 <irq_set_prio>:

void irq_set_prio(unsigned id, unsigned prio){
    gic_set_prio(id, (uint8_t) prio);
    80200c74:	2a0003e0 	mov	w0, w0
    80200c78:	140002ce 	b	802017b0 <gic_set_prio>
    80200c7c:	d503201f 	nop

0000000080200c80 <irq_send_ipi>:
}

void irq_send_ipi(unsigned long target_cpu_mask) {
    80200c80:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80200c84:	910003fd 	mov	x29, sp
    80200c88:	a90153f3 	stp	x19, x20, [sp, #16]
    80200c8c:	aa0003f4 	mov	x20, x0
    80200c90:	d2800013 	mov	x19, #0x0                   	// #0
    80200c94:	14000004 	b	80200ca4 <irq_send_ipi+0x24>
    for(int i = 0; i < sizeof(target_cpu_mask)*8; i++) {
    80200c98:	91000673 	add	x19, x19, #0x1
    80200c9c:	f101027f 	cmp	x19, #0x40
    80200ca0:	54000120 	b.eq	80200cc4 <irq_send_ipi+0x44>  // b.none
        if(target_cpu_mask & (1ull << i)) {
    80200ca4:	9ad32681 	lsr	x1, x20, x19
    80200ca8:	3607ff81 	tbz	w1, #0, 80200c98 <irq_send_ipi+0x18>
            gic_send_sgi(i, IPI_IRQ_ID);
    80200cac:	aa1303e0 	mov	x0, x19
    80200cb0:	d2800001 	mov	x1, #0x0                   	// #0
    for(int i = 0; i < sizeof(target_cpu_mask)*8; i++) {
    80200cb4:	91000673 	add	x19, x19, #0x1
            gic_send_sgi(i, IPI_IRQ_ID);
    80200cb8:	940002b7 	bl	80201794 <gic_send_sgi>
    for(int i = 0; i < sizeof(target_cpu_mask)*8; i++) {
    80200cbc:	f101027f 	cmp	x19, #0x40
    80200cc0:	54ffff21 	b.ne	80200ca4 <irq_send_ipi+0x24>  // b.any
        }
    }
}
    80200cc4:	a94153f3 	ldp	x19, x20, [sp, #16]
    80200cc8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80200ccc:	d65f03c0 	ret

0000000080200cd0 <timer_set>:
SYSREG_GEN_ACCESSORS(cntvct_el0);
    80200cd0:	d53be041 	mrs	x1, cntvct_el0
unsigned long TIMER_FREQ;

void timer_set(uint64_t n)
{
    uint64_t current = sysreg_cntvct_el0_read();
    sysreg_cntv_cval_el0_write(current + n);
    80200cd4:	8b010000 	add	x0, x0, x1
SYSREG_GEN_ACCESSORS(cntv_cval_el0);
    80200cd8:	d51be340 	msr	cntv_cval_el0, x0
}
    80200cdc:	d65f03c0 	ret

0000000080200ce0 <timer_get>:
SYSREG_GEN_ACCESSORS(cntvct_el0);
    80200ce0:	d53be040 	mrs	x0, cntvct_el0

uint64_t timer_get()
{
    uint64_t time = sysreg_cntvct_el0_read();
    return time; // assumes plat_freq = 100MHz
}
    80200ce4:	d65f03c0 	ret
	...

0000000080200cf0 <gic_num_irqs>:


inline unsigned long gic_num_irqs()
{
    uint32_t itlinenumber =
        bit_extract(gicd->TYPER, GICD_TYPER_ITLN_OFF, GICD_TYPER_ITLN_LEN);
    80200cf0:	b0000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
    80200cf4:	f9401400 	ldr	x0, [x0, #40]
    80200cf8:	b9400400 	ldr	w0, [x0, #4]
    return 32 * itlinenumber + 1;
    80200cfc:	d37b1000 	ubfiz	x0, x0, #5, #5
}
    80200d00:	91000400 	add	x0, x0, #0x1
    80200d04:	d65f03c0 	ret
    80200d08:	d503201f 	nop
    80200d0c:	d503201f 	nop

0000000080200d10 <gic_cpu_init>:
SYSREG_GEN_ACCESSORS(icc_sre_el1);
    80200d10:	d538cca0 	mrs	x0, icc_sre_el1
//    }
//}

void gic_cpu_init()
{
    sysreg_icc_sre_el1_write(sysreg_icc_sre_el1_read() | ICC_SRE_SRE_BIT);
    80200d14:	b2400000 	orr	x0, x0, #0x1
    80200d18:	d518cca0 	msr	icc_sre_el1, x0
    ISB();
    80200d1c:	d5033fdf 	isb
    gicd->CTLR |= (1ull << 6);
    80200d20:	b0000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
    80200d24:	9100a002 	add	x2, x0, #0x28
    80200d28:	f9401401 	ldr	x1, [x0, #40]
    gicr[get_cpuid()].WAKER &= ~GICR_ProcessorSleep_BIT;
    80200d2c:	f9400442 	ldr	x2, [x2, #8]
    gicd->CTLR |= (1ull << 6);
    80200d30:	b9400020 	ldr	w0, [x1]
    80200d34:	321a0000 	orr	w0, w0, #0x40
    80200d38:	b9000020 	str	w0, [x1]
SYSREG_GEN_ACCESSORS(mpidr_el1);
    80200d3c:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].WAKER &= ~GICR_ProcessorSleep_BIT;
    80200d40:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200d44:	8b000040 	add	x0, x2, x0
    80200d48:	b9401401 	ldr	w1, [x0, #20]
    80200d4c:	121e7821 	and	w1, w1, #0xfffffffd
    80200d50:	b9001401 	str	w1, [x0, #20]
    while(gicr[get_cpuid()].WAKER & GICR_ChildrenASleep_BIT) { }
    80200d54:	d503201f 	nop
    80200d58:	d53800a0 	mrs	x0, mpidr_el1
    80200d5c:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200d60:	8b000040 	add	x0, x2, x0
    80200d64:	b9401400 	ldr	w0, [x0, #20]
    80200d68:	3717ff80 	tbnz	w0, #2, 80200d58 <gic_cpu_init+0x48>
    80200d6c:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].IGROUPR0 = -1;
    80200d70:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200d74:	12800003 	mov	w3, #0xffffffff            	// #-1
    80200d78:	8b000040 	add	x0, x2, x0
    80200d7c:	91404000 	add	x0, x0, #0x10, lsl #12
    80200d80:	b9008003 	str	w3, [x0, #128]
    80200d84:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].ICENABLER0 = -1;
    80200d88:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200d8c:	8b000040 	add	x0, x2, x0
    80200d90:	91404000 	add	x0, x0, #0x10, lsl #12
    80200d94:	b9018003 	str	w3, [x0, #384]
    80200d98:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].ICPENDR0 = -1;
    80200d9c:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200da0:	8b000040 	add	x0, x2, x0
    80200da4:	91404000 	add	x0, x0, #0x10, lsl #12
    80200da8:	b9028003 	str	w3, [x0, #640]
    80200dac:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].ICACTIVER0 = -1;
    80200db0:	d36f1c00 	ubfiz	x0, x0, #17, #8
    for (int i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
    80200db4:	52800001 	mov	w1, #0x0                   	// #0
    gicr[get_cpuid()].ICACTIVER0 = -1;
    80200db8:	8b000040 	add	x0, x2, x0
    80200dbc:	91404000 	add	x0, x0, #0x10, lsl #12
    80200dc0:	b9038003 	str	w3, [x0, #896]
    for (int i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
    80200dc4:	d503201f 	nop
    80200dc8:	d53800a0 	mrs	x0, mpidr_el1
        gicr[get_cpuid()].IPRIORITYR[i] = -1;
    80200dcc:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200dd0:	8b000040 	add	x0, x2, x0
    80200dd4:	8b21c800 	add	x0, x0, w1, sxtw #2
    for (int i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
    80200dd8:	11000421 	add	w1, w1, #0x1
        gicr[get_cpuid()].IPRIORITYR[i] = -1;
    80200ddc:	91404000 	add	x0, x0, #0x10, lsl #12
    80200de0:	b9040003 	str	w3, [x0, #1024]
    for (int i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
    80200de4:	7100203f 	cmp	w1, #0x8
    80200de8:	54ffff01 	b.ne	80200dc8 <gic_cpu_init+0xb8>  // b.any
SYSREG_GEN_ACCESSORS(icc_pmr_el1);
    80200dec:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    80200df0:	d5184600 	msr	icc_pmr_el1, x0
SYSREG_GEN_ACCESSORS(icc_ctlr_el1);
    80200df4:	d2800020 	mov	x0, #0x1                   	// #1
    80200df8:	d518cc80 	msr	icc_ctlr_el1, x0
SYSREG_GEN_ACCESSORS(icc_igrpen1_el1);
    80200dfc:	d518cce0 	msr	icc_igrpen1_el1, x0
    gicr_init();
    gicc_init();
}
    80200e00:	d65f03c0 	ret

0000000080200e04 <gicd_init>:
        bit_extract(gicd->TYPER, GICD_TYPER_ITLN_OFF, GICD_TYPER_ITLN_LEN);
    80200e04:	b0000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
void gicd_init()
{
    size_t int_num = gic_num_irqs();

    /* Bring distributor to known state */
    for (int i = GIC_NUM_PRIVINT_REGS; i < GIC_NUM_INT_REGS(int_num); i++) {
    80200e08:	52800022 	mov	w2, #0x1                   	// #1
        gicd->IGROUPR[i] = -1;
    80200e0c:	12800001 	mov	w1, #0xffffffff            	// #-1
        bit_extract(gicd->TYPER, GICD_TYPER_ITLN_OFF, GICD_TYPER_ITLN_LEN);
    80200e10:	f9401403 	ldr	x3, [x0, #40]
    80200e14:	b9400460 	ldr	w0, [x3, #4]
    return 32 * itlinenumber + 1;
    80200e18:	d37b1000 	ubfiz	x0, x0, #5, #5
    80200e1c:	91000405 	add	x5, x0, #0x1
    for (int i = GIC_NUM_PRIVINT_REGS; i < GIC_NUM_INT_REGS(int_num); i++) {
    80200e20:	d345fc00 	lsr	x0, x0, #5
    80200e24:	2a0003e4 	mov	w4, w0
    80200e28:	f100041f 	cmp	x0, #0x1
    80200e2c:	54000389 	b.ls	80200e9c <gicd_init+0x98>  // b.plast
        gicd->IGROUPR[i] = -1;
    80200e30:	8b22c860 	add	x0, x3, w2, sxtw #2
    for (int i = GIC_NUM_PRIVINT_REGS; i < GIC_NUM_INT_REGS(int_num); i++) {
    80200e34:	11000442 	add	w2, w2, #0x1
        gicd->IGROUPR[i] = -1;
    80200e38:	b9008001 	str	w1, [x0, #128]
        /**
         * Make sure all interrupts are not enabled, non pending,
         * non active.
         */
        gicd->ICENABLER[i] = -1;
    80200e3c:	b9018001 	str	w1, [x0, #384]
        gicd->ICPENDR[i] = -1;
    80200e40:	b9028001 	str	w1, [x0, #640]
        gicd->ICACTIVER[i] = -1;
    80200e44:	b9038001 	str	w1, [x0, #896]
    for (int i = GIC_NUM_PRIVINT_REGS; i < GIC_NUM_INT_REGS(int_num); i++) {
    80200e48:	6b02009f 	cmp	w4, w2
    80200e4c:	54ffff21 	b.ne	80200e30 <gicd_init+0x2c>  // b.any
    }

    /* All interrupts have lowest priority possible by default */
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_PRIO_REGS(int_num); i++)
    80200e50:	d342fca4 	lsr	x4, x5, #2
    80200e54:	f1020cbf 	cmp	x5, #0x83
    80200e58:	54000229 	b.ls	80200e9c <gicd_init+0x98>  // b.plast
    80200e5c:	52800400 	mov	w0, #0x20                  	// #32
        gicd->IPRIORITYR[i] = -1;
    80200e60:	12800005 	mov	w5, #0xffffffff            	// #-1
    80200e64:	d503201f 	nop
    80200e68:	8b20c861 	add	x1, x3, w0, sxtw #2
    80200e6c:	2a0003e2 	mov	w2, w0
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_PRIO_REGS(int_num); i++)
    80200e70:	11000400 	add	w0, w0, #0x1
        gicd->IPRIORITYR[i] = -1;
    80200e74:	b9040025 	str	w5, [x1, #1024]
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_PRIO_REGS(int_num); i++)
    80200e78:	6b00009f 	cmp	w4, w0
    80200e7c:	54ffff61 	b.ne	80200e68 <gicd_init+0x64>  // b.any

    /* No CPU targets for any interrupt by default */
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_TARGET_REGS(int_num); i++)
    80200e80:	52800400 	mov	w0, #0x20                  	// #32
    80200e84:	d503201f 	nop
        gicd->ITARGETSR[i] = 0;
    80200e88:	8b20c864 	add	x4, x3, w0, sxtw #2
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_TARGET_REGS(int_num); i++)
    80200e8c:	6b00005f 	cmp	w2, w0
    80200e90:	11000400 	add	w0, w0, #0x1
        gicd->ITARGETSR[i] = 0;
    80200e94:	b908009f 	str	wzr, [x4, #2048]
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_TARGET_REGS(int_num); i++)
    80200e98:	54ffff81 	b.ne	80200e88 <gicd_init+0x84>  // b.any
    /* ICFGR are platform dependent, lets leave them as is */

    /* No need to setup gicd->NSACR as all interrupts are  setup to group 1 */

    /* Enable distributor and affinity routing */
    gicd->CTLR |= GICD_CTLR_ARE_NS_BIT | GICD_CTLR_ENA_BIT;
    80200e9c:	b9400060 	ldr	w0, [x3]
    80200ea0:	52800241 	mov	w1, #0x12                  	// #18
    80200ea4:	2a010000 	orr	w0, w0, w1
    80200ea8:	b9000060 	str	w0, [x3]
}
    80200eac:	d65f03c0 	ret

0000000080200eb0 <gic_init>:

void gic_init()
{
    80200eb0:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80200eb4:	910003fd 	mov	x29, sp
    gic_cpu_init();
    80200eb8:	97ffff96 	bl	80200d10 <gic_cpu_init>
SYSREG_GEN_ACCESSORS(mpidr_el1);
    80200ebc:	d53800a0 	mrs	x0, mpidr_el1

    if (get_cpuid() == 0) {
    80200ec0:	72001c1f 	tst	w0, #0xff
    80200ec4:	54000060 	b.eq	80200ed0 <gic_init+0x20>  // b.none
        gicd_init();
        its_init(); /*Alloc tables and map lpis*/
        printf("Baremetal: GIC init\n");
    }

}
    80200ec8:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80200ecc:	d65f03c0 	ret
        gicd_init();
    80200ed0:	97ffffcd 	bl	80200e04 <gicd_init>
        its_init(); /*Alloc tables and map lpis*/
    80200ed4:	9400038f 	bl	80201d10 <its_init>
}
    80200ed8:	a8c17bfd 	ldp	x29, x30, [sp], #16
        printf("Baremetal: GIC init\n");
    80200edc:	90000080 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80200ee0:	910e2000 	add	x0, x0, #0x388
    80200ee4:	140006c3 	b	802029f0 <puts>
    80200ee8:	d503201f 	nop
    80200eec:	d503201f 	nop

0000000080200ef0 <gic_handle>:

void gic_handle()
{
    80200ef0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80200ef4:	910003fd 	mov	x29, sp
    80200ef8:	a90153f3 	stp	x19, x20, [sp, #16]
SYSREG_GEN_ACCESSORS(icc_iar1_el1);
    80200efc:	d538cc14 	mrs	x20, icc_iar1_el1
    unsigned long ack = sysreg_icc_iar1_el1_read();
    unsigned long id = ack & ((1UL << 24) -1);
    80200f00:	92405e93 	and	x19, x20, #0xffffff

    printf("IRQ received with id %d\n",id);
    80200f04:	90000080 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80200f08:	aa1303e1 	mov	x1, x19
    80200f0c:	910e8000 	add	x0, x0, #0x3a0
    80200f10:	9400065c 	bl	80202880 <printf>

    if (id >= 1022 && id != 8192) return;
    80200f14:	f10ff67f 	cmp	x19, #0x3fd
    80200f18:	d2840000 	mov	x0, #0x2000                	// #8192
    80200f1c:	fa408264 	ccmp	x19, x0, #0x4, hi	// hi = pmore
    80200f20:	54000081 	b.ne	80200f30 <gic_handle+0x40>  // b.any

    irq_handle(id);
    80200f24:	2a1303e0 	mov	w0, w19
    80200f28:	97fffe42 	bl	80200830 <irq_handle>
SYSREG_GEN_ACCESSORS(icc_eoir1_el1);
    80200f2c:	d518cc34 	msr	icc_eoir1_el1, x20

    sysreg_icc_eoir1_el1_write(ack);
    //sysreg_icc_dir_el1_write(ack);
}
    80200f30:	a94153f3 	ldp	x19, x20, [sp, #16]
    80200f34:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80200f38:	d65f03c0 	ret
    80200f3c:	d503201f 	nop

0000000080200f40 <gicd_get_prio>:

unsigned long gicd_get_prio(unsigned long int_id)
{
    80200f40:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    80200f44:	d37df002 	lsl	x2, x0, #3
    asm volatile (
    80200f48:	d0000101 	adrp	x1, 80222000 <init_lock>
    80200f4c:	52800023 	mov	w3, #0x1                   	// #1
    80200f50:	91004024 	add	x4, x1, #0x10
    80200f54:	d342f000 	ubfx	x0, x0, #2, #59
    80200f58:	885ffc85 	ldaxr	w5, [x4]
    80200f5c:	35ffffe5 	cbnz	w5, 80200f58 <gicd_get_prio+0x18>
    80200f60:	88057c83 	stxr	w5, w3, [x4]
    80200f64:	35ffffa5 	cbnz	w5, 80200f58 <gicd_get_prio+0x18>
    unsigned long off = GIC_PRIO_OFF(int_id);

    spin_lock(&gicd_lock);

    unsigned long prio =
        gicd->IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    80200f68:	b0000081 	adrp	x1, 80211000 <__mprec_tens+0x180>
    80200f6c:	b9000fe5 	str	w5, [sp, #12]
    unsigned long off = GIC_PRIO_OFF(int_id);
    80200f70:	927d0442 	and	x2, x2, #0x18
        gicd->IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    80200f74:	f9401421 	ldr	x1, [x1, #40]
    80200f78:	8b000820 	add	x0, x1, x0, lsl #2
    80200f7c:	b9440003 	ldr	w3, [x0, #1024]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80200f80:	889ffc9f 	stlr	wzr, [x4]
    80200f84:	92800001 	mov	x1, #0xffffffffffffffff    	// #-1
    80200f88:	11002044 	add	w4, w2, #0x8
    80200f8c:	aa0103e0 	mov	x0, x1
    80200f90:	1ac22463 	lsr	w3, w3, w2
    80200f94:	9ac22021 	lsl	x1, x1, x2
    unsigned long prio =
    80200f98:	8a030021 	and	x1, x1, x3
        gicd->IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    80200f9c:	9ac42000 	lsl	x0, x0, x4

    spin_unlock(&gicd_lock);

    return prio;
}
    80200fa0:	8a200020 	bic	x0, x1, x0
    80200fa4:	910043ff 	add	sp, sp, #0x10
    80200fa8:	d65f03c0 	ret
    80200fac:	d503201f 	nop

0000000080200fb0 <gicd_set_icfgr>:

void gicd_set_icfgr(unsigned long int_id, uint8_t cfg)
{
    80200fb0:	d10043ff 	sub	sp, sp, #0x10
    asm volatile (
    80200fb4:	d0000102 	adrp	x2, 80222000 <init_lock>
    80200fb8:	12001c21 	and	w1, w1, #0xff
    80200fbc:	52800023 	mov	w3, #0x1                   	// #1
    80200fc0:	91004044 	add	x4, x2, #0x10
    80200fc4:	885ffc85 	ldaxr	w5, [x4]
    80200fc8:	35ffffe5 	cbnz	w5, 80200fc4 <gicd_set_icfgr+0x14>
    80200fcc:	88057c83 	stxr	w5, w3, [x4]
    80200fd0:	35ffffa5 	cbnz	w5, 80200fc4 <gicd_set_icfgr+0x14>

    unsigned long reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    unsigned long off = (int_id * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8);
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;

    gicd->ICFGR[reg_ind] = (gicd->ICFGR[reg_ind] & ~mask) | ((cfg << off) & mask);
    80200fd4:	b0000083 	adrp	x3, 80211000 <__mprec_tens+0x180>
    80200fd8:	b9000fe5 	str	w5, [sp, #12]
    unsigned long reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    80200fdc:	d344f802 	ubfx	x2, x0, #4, #59
    unsigned long off = (int_id * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8);
    80200fe0:	d37f0c00 	ubfiz	x0, x0, #1, #4
    gicd->ICFGR[reg_ind] = (gicd->ICFGR[reg_ind] & ~mask) | ((cfg << off) & mask);
    80200fe4:	f9401465 	ldr	x5, [x3, #40]
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;
    80200fe8:	52800063 	mov	w3, #0x3                   	// #3
    80200fec:	1ac02063 	lsl	w3, w3, w0
    gicd->ICFGR[reg_ind] = (gicd->ICFGR[reg_ind] & ~mask) | ((cfg << off) & mask);
    80200ff0:	1ac02021 	lsl	w1, w1, w0
    80200ff4:	8b0208a0 	add	x0, x5, x2, lsl #2
    80200ff8:	b94c0002 	ldr	w2, [x0, #3072]
    80200ffc:	4a020021 	eor	w1, w1, w2
    80201000:	0a030021 	and	w1, w1, w3
    80201004:	4a020021 	eor	w1, w1, w2
    80201008:	b90c0001 	str	w1, [x0, #3072]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    8020100c:	889ffc9f 	stlr	wzr, [x4]

    spin_unlock(&gicd_lock);
}
    80201010:	910043ff 	add	sp, sp, #0x10
    80201014:	d65f03c0 	ret
    80201018:	d503201f 	nop
    8020101c:	d503201f 	nop

0000000080201020 <gicd_set_prio>:

void gicd_set_prio(unsigned long int_id, uint8_t prio)
{
    80201020:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    80201024:	d37df002 	lsl	x2, x0, #3
    asm volatile (
    80201028:	b0000103 	adrp	x3, 80222000 <init_lock>
{
    8020102c:	12001c21 	and	w1, w1, #0xff
    80201030:	52800024 	mov	w4, #0x1                   	// #1
    unsigned long off = GIC_PRIO_OFF(int_id);
    80201034:	d37d0400 	ubfiz	x0, x0, #3, #2
    80201038:	91004065 	add	x5, x3, #0x10
    8020103c:	885ffca6 	ldaxr	w6, [x5]
    80201040:	35ffffe6 	cbnz	w6, 8020103c <gicd_set_prio+0x1c>
    80201044:	88067ca4 	stxr	w6, w4, [x5]
    80201048:	35ffffa6 	cbnz	w6, 8020103c <gicd_set_prio+0x1c>
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);

    spin_lock(&gicd_lock);

    gicd->IPRIORITYR[reg_ind] =
        (gicd->IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    8020104c:	90000083 	adrp	x3, 80211000 <__mprec_tens+0x180>
    80201050:	b9000fe6 	str	w6, [sp, #12]
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    80201054:	d345fc42 	lsr	x2, x2, #5
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    80201058:	11002007 	add	w7, w0, #0x8
    8020105c:	f9401466 	ldr	x6, [x3, #40]
    80201060:	92800003 	mov	x3, #0xffffffffffffffff    	// #-1
    80201064:	aa0303e4 	mov	x4, x3
        (gicd->IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    80201068:	1ac02021 	lsl	w1, w1, w0
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    8020106c:	9ac72063 	lsl	x3, x3, x7
    80201070:	8b0208c2 	add	x2, x6, x2, lsl #2
    80201074:	9ac02084 	lsl	x4, x4, x0
    80201078:	8a230083 	bic	x3, x4, x3
        (gicd->IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    8020107c:	b9440040 	ldr	w0, [x2, #1024]
    80201080:	4a000021 	eor	w1, w1, w0
    80201084:	0a030021 	and	w1, w1, w3
    80201088:	4a000021 	eor	w1, w1, w0
    gicd->IPRIORITYR[reg_ind] =
    8020108c:	b9040041 	str	w1, [x2, #1024]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201090:	889ffcbf 	stlr	wzr, [x5]

    spin_unlock(&gicd_lock);
}
    80201094:	910043ff 	add	sp, sp, #0x10
    80201098:	d65f03c0 	ret
    8020109c:	d503201f 	nop

00000000802010a0 <gicd_get_state>:

enum int_state gicd_get_state(unsigned long int_id)
{
    unsigned long reg_ind = GIC_INT_REG(int_id);
    unsigned long mask = GIC_INT_MASK(int_id);
    802010a0:	52800022 	mov	w2, #0x1                   	// #1
{
    802010a4:	d10043ff 	sub	sp, sp, #0x10
    asm volatile (
    802010a8:	b0000101 	adrp	x1, 80222000 <init_lock>
    unsigned long mask = GIC_INT_MASK(int_id);
    802010ac:	1ac02043 	lsl	w3, w2, w0
    802010b0:	91004024 	add	x4, x1, #0x10
    802010b4:	885ffc85 	ldaxr	w5, [x4]
    802010b8:	35ffffe5 	cbnz	w5, 802010b4 <gicd_get_state+0x14>
    802010bc:	88057c82 	stxr	w5, w2, [x4]
    802010c0:	35ffffa5 	cbnz	w5, 802010b4 <gicd_get_state+0x14>

    spin_lock(&gicd_lock);

    enum int_state pend = (gicd->ISPENDR[reg_ind] & mask) ? PEND : 0;
    802010c4:	90000081 	adrp	x1, 80211000 <__mprec_tens+0x180>
    unsigned long reg_ind = GIC_INT_REG(int_id);
    802010c8:	d345fc00 	lsr	x0, x0, #5
    802010cc:	b9000fe5 	str	w5, [sp, #12]
    enum int_state pend = (gicd->ISPENDR[reg_ind] & mask) ? PEND : 0;
    802010d0:	f9401421 	ldr	x1, [x1, #40]
    802010d4:	8b000820 	add	x0, x1, x0, lsl #2
    802010d8:	b9420002 	ldr	w2, [x0, #512]
    enum int_state act = (gicd->ISACTIVER[reg_ind] & mask) ? ACT : 0;
    802010dc:	b9430000 	ldr	w0, [x0, #768]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802010e0:	889ffc9f 	stlr	wzr, [x4]
    802010e4:	6a00007f 	tst	w3, w0
    802010e8:	1a9f07e1 	cset	w1, ne	// ne = any
    enum int_state pend = (gicd->ISPENDR[reg_ind] & mask) ? PEND : 0;
    802010ec:	6a02007f 	tst	w3, w2
    802010f0:	1a9f07e0 	cset	w0, ne	// ne = any

    spin_unlock(&gicd_lock);

    return pend | act;
}
    802010f4:	910043ff 	add	sp, sp, #0x10
    802010f8:	2a010400 	orr	w0, w0, w1, lsl #1
    802010fc:	d65f03c0 	ret

0000000080201100 <gicd_set_act>:
    asm volatile (
    80201100:	b0000102 	adrp	x2, 80222000 <init_lock>

    spin_unlock(&gicd_lock);
}

void gicd_set_act(unsigned long int_id, bool act)
{
    80201104:	d10043ff 	sub	sp, sp, #0x10
    80201108:	12001c21 	and	w1, w1, #0xff
    unsigned long reg_ind = GIC_INT_REG(int_id);
    8020110c:	d345fc04 	lsr	x4, x0, #5
    80201110:	91004046 	add	x6, x2, #0x10
    80201114:	52800023 	mov	w3, #0x1                   	// #1
    80201118:	885ffcc5 	ldaxr	w5, [x6]
    8020111c:	35ffffe5 	cbnz	w5, 80201118 <gicd_set_act+0x18>
    80201120:	88057cc3 	stxr	w5, w3, [x6]
    80201124:	35ffffa5 	cbnz	w5, 80201118 <gicd_set_act+0x18>

    spin_lock(&gicd_lock);

    if (act) {
        gicd->ISACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    80201128:	1ac02063 	lsl	w3, w3, w0
    8020112c:	90000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
    80201130:	b9000fe5 	str	w5, [sp, #12]
    80201134:	f9401400 	ldr	x0, [x0, #40]
    80201138:	8b040804 	add	x4, x0, x4, lsl #2
    if (act) {
    8020113c:	360000c1 	tbz	w1, #0, 80201154 <gicd_set_act+0x54>
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201140:	91004042 	add	x2, x2, #0x10
        gicd->ISACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    80201144:	b9030083 	str	w3, [x4, #768]
    80201148:	889ffc5f 	stlr	wzr, [x2]
    } else {
        gicd->ICACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    }

    spin_unlock(&gicd_lock);
}
    8020114c:	910043ff 	add	sp, sp, #0x10
    80201150:	d65f03c0 	ret
    80201154:	91004042 	add	x2, x2, #0x10
        gicd->ICACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    80201158:	b9038083 	str	w3, [x4, #896]
    8020115c:	889ffc5f 	stlr	wzr, [x2]
}
    80201160:	910043ff 	add	sp, sp, #0x10
    80201164:	d65f03c0 	ret
    80201168:	d503201f 	nop
    8020116c:	d503201f 	nop

0000000080201170 <gicd_set_state>:

void gicd_set_state(unsigned long int_id, enum int_state state)
{
    80201170:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80201174:	2a0103e8 	mov	w8, w1
    80201178:	aa0003e7 	mov	x7, x0
    8020117c:	910003fd 	mov	x29, sp
    gicd_set_act(int_id, state & ACT);
    80201180:	d3410501 	ubfx	x1, x8, #1, #1
    80201184:	97ffffdf 	bl	80201100 <gicd_set_act>
    asm volatile (
    80201188:	b0000100 	adrp	x0, 80222000 <init_lock>
    gicd_set_pend(int_id, state & PEND);
    8020118c:	12000108 	and	w8, w8, #0x1
    80201190:	91004003 	add	x3, x0, #0x10
    80201194:	52800021 	mov	w1, #0x1                   	// #1
    80201198:	885ffc62 	ldaxr	w2, [x3]
    8020119c:	35ffffe2 	cbnz	w2, 80201198 <gicd_set_state+0x28>
    802011a0:	88027c61 	stxr	w2, w1, [x3]
    802011a4:	35ffffa2 	cbnz	w2, 80201198 <gicd_set_state+0x28>
    802011a8:	b9001fe2 	str	w2, [sp, #28]
    if (gic_is_sgi(int_id)) {
    802011ac:	f1003cff 	cmp	x7, #0xf
    802011b0:	540001e8 	b.hi	802011ec <gicd_set_state+0x7c>  // b.pmore
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011b4:	90000083 	adrp	x3, 80211000 <__mprec_tens+0x180>
        unsigned long reg_ind = GICD_SGI_REG(int_id);
    802011b8:	d342fce2 	lsr	x2, x7, #2
        unsigned long off = GICD_SGI_OFF(int_id);
    802011bc:	d37d04e7 	ubfiz	x7, x7, #3, #2
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011c0:	f9401463 	ldr	x3, [x3, #40]
        if (pend) {
    802011c4:	34000348 	cbz	w8, 8020122c <gicd_set_state+0xbc>
SYSREG_GEN_ACCESSORS(mpidr_el1);
    802011c8:	d53800a4 	mrs	x4, mpidr_el1
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011cc:	8b020862 	add	x2, x3, x2, lsl #2
    802011d0:	0b2400e3 	add	w3, w7, w4, uxtb
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802011d4:	91004000 	add	x0, x0, #0x10
    802011d8:	1ac32021 	lsl	w1, w1, w3
    802011dc:	b90f2041 	str	w1, [x2, #3872]
    802011e0:	889ffc1f 	stlr	wzr, [x0]
}
    802011e4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802011e8:	d65f03c0 	ret
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011ec:	90000082 	adrp	x2, 80211000 <__mprec_tens+0x180>
            gicd->ISPENDR[reg_ind] = GIC_INT_MASK(int_id);
    802011f0:	1ac72021 	lsl	w1, w1, w7
        unsigned long reg_ind = GIC_INT_REG(int_id);
    802011f4:	d345fce7 	lsr	x7, x7, #5
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011f8:	f9401442 	ldr	x2, [x2, #40]
            gicd->ISPENDR[reg_ind] = GIC_INT_MASK(int_id);
    802011fc:	8b070847 	add	x7, x2, x7, lsl #2
        if (pend) {
    80201200:	350000c8 	cbnz	w8, 80201218 <gicd_set_state+0xa8>
    80201204:	91004000 	add	x0, x0, #0x10
            gicd->ICPENDR[reg_ind] = GIC_INT_MASK(int_id);
    80201208:	b90280e1 	str	w1, [x7, #640]
    8020120c:	889ffc1f 	stlr	wzr, [x0]
}
    80201210:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80201214:	d65f03c0 	ret
    80201218:	91004000 	add	x0, x0, #0x10
            gicd->ISPENDR[reg_ind] = GIC_INT_MASK(int_id);
    8020121c:	b90200e1 	str	w1, [x7, #512]
    80201220:	889ffc1f 	stlr	wzr, [x0]
}
    80201224:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80201228:	d65f03c0 	ret
            gicd->CPENDSGIR[reg_ind] = BIT_MASK(off, 8);
    8020122c:	8b020862 	add	x2, x3, x2, lsl #2
    80201230:	110020e4 	add	w4, w7, #0x8
    80201234:	d2800023 	mov	x3, #0x1                   	// #1
    80201238:	92800001 	mov	x1, #0xffffffffffffffff    	// #-1
    8020123c:	9ac72063 	lsl	x3, x3, x7
    80201240:	4b0303e3 	neg	w3, w3
    80201244:	9ac42021 	lsl	x1, x1, x4
    80201248:	91004000 	add	x0, x0, #0x10
    8020124c:	0a210061 	bic	w1, w3, w1
    80201250:	b90f1041 	str	w1, [x2, #3856]
    80201254:	889ffc1f 	stlr	wzr, [x0]
}
    80201258:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020125c:	d65f03c0 	ret

0000000080201260 <gicd_set_trgt>:

void gicd_set_trgt(unsigned long int_id, uint8_t trgt)
{
    80201260:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_TARGET_REG(int_id);
    80201264:	d37df004 	lsl	x4, x0, #3
    asm volatile (
    80201268:	b0000102 	adrp	x2, 80222000 <init_lock>
{
    8020126c:	12001c21 	and	w1, w1, #0xff
    80201270:	52800023 	mov	w3, #0x1                   	// #1
    unsigned long off = GIC_TARGET_OFF(int_id);
    80201274:	d37d0400 	ubfiz	x0, x0, #3, #2
    80201278:	91004046 	add	x6, x2, #0x10
    8020127c:	885ffcc5 	ldaxr	w5, [x6]
    80201280:	35ffffe5 	cbnz	w5, 8020127c <gicd_set_trgt+0x1c>
    80201284:	88057cc3 	stxr	w5, w3, [x6]
    80201288:	35ffffa5 	cbnz	w5, 8020127c <gicd_set_trgt+0x1c>
    uint32_t mask = BIT_MASK(off, GIC_TARGET_BITS);

    spin_lock(&gicd_lock);

    gicd->ITARGETSR[reg_ind] =
        (gicd->ITARGETSR[reg_ind] & ~mask) | ((trgt << off) & mask);
    8020128c:	90000083 	adrp	x3, 80211000 <__mprec_tens+0x180>
    80201290:	b9000fe5 	str	w5, [sp, #12]
    unsigned long reg_ind = GIC_TARGET_REG(int_id);
    80201294:	d345fc84 	lsr	x4, x4, #5
    uint32_t mask = BIT_MASK(off, GIC_TARGET_BITS);
    80201298:	d2800022 	mov	x2, #0x1                   	// #1
    8020129c:	f9401465 	ldr	x5, [x3, #40]
    802012a0:	9ac02042 	lsl	x2, x2, x0
        (gicd->ITARGETSR[reg_ind] & ~mask) | ((trgt << off) & mask);
    802012a4:	1ac02021 	lsl	w1, w1, w0
    uint32_t mask = BIT_MASK(off, GIC_TARGET_BITS);
    802012a8:	11002000 	add	w0, w0, #0x8
    802012ac:	4b0203e3 	neg	w3, w2
    802012b0:	92800002 	mov	x2, #0xffffffffffffffff    	// #-1
    802012b4:	8b0408a4 	add	x4, x5, x4, lsl #2
    802012b8:	9ac02040 	lsl	x0, x2, x0
        (gicd->ITARGETSR[reg_ind] & ~mask) | ((trgt << off) & mask);
    802012bc:	b9480085 	ldr	w5, [x4, #2048]
    802012c0:	4a050021 	eor	w1, w1, w5
    802012c4:	0a010062 	and	w2, w3, w1
    802012c8:	0a200040 	bic	w0, w2, w0
    802012cc:	4a050000 	eor	w0, w0, w5
    gicd->ITARGETSR[reg_ind] =
    802012d0:	b9080080 	str	w0, [x4, #2048]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802012d4:	889ffcdf 	stlr	wzr, [x6]

    spin_unlock(&gicd_lock);
}
    802012d8:	910043ff 	add	sp, sp, #0x10
    802012dc:	d65f03c0 	ret

00000000802012e0 <gicd_set_route>:

void gicd_set_route(unsigned long int_id, unsigned long trgt)
{
    if (gic_is_priv(int_id)) return;
    802012e0:	f1007c1f 	cmp	x0, #0x1f
    802012e4:	54000129 	b.ls	80201308 <gicd_set_route+0x28>  // b.plast
     * syndrome register. Bao has no support for its emulation. Therefore 
     * we perform the 64-bit access explicitly as two 32-bit stores.
     */

    uint64_t _trgt = trgt;
    volatile uint32_t *irouter = (uint32_t*) &gicd->IROUTER[int_id];
    802012e8:	90000082 	adrp	x2, 80211000 <__mprec_tens+0x180>
    802012ec:	91300000 	add	x0, x0, #0xc00
    irouter[0] = _trgt;
    irouter[1] = (_trgt >> 32);
    802012f0:	d360fc24 	lsr	x4, x1, #32
    volatile uint32_t *irouter = (uint32_t*) &gicd->IROUTER[int_id];
    802012f4:	f9401442 	ldr	x2, [x2, #40]
    802012f8:	d37df000 	lsl	x0, x0, #3
    802012fc:	8b000043 	add	x3, x2, x0
    irouter[0] = _trgt;
    80201300:	b8206841 	str	w1, [x2, x0]
    irouter[1] = (_trgt >> 32);
    80201304:	b9000464 	str	w4, [x3, #4]
}
    80201308:	d65f03c0 	ret
    8020130c:	d503201f 	nop

0000000080201310 <gicd_set_enable>:

void gicd_set_enable(unsigned long int_id, bool en)
{
    unsigned long bit = GIC_INT_MASK(int_id);
    80201310:	52800023 	mov	w3, #0x1                   	// #1
    asm volatile (
    80201314:	b0000102 	adrp	x2, 80222000 <init_lock>
    80201318:	1ac02064 	lsl	w4, w3, w0
{
    8020131c:	d10043ff 	sub	sp, sp, #0x10
    80201320:	12001c21 	and	w1, w1, #0xff

    unsigned long reg_ind = GIC_INT_REG(int_id);
    80201324:	d345fc00 	lsr	x0, x0, #5
    80201328:	91004046 	add	x6, x2, #0x10
    8020132c:	885ffcc5 	ldaxr	w5, [x6]
    80201330:	35ffffe5 	cbnz	w5, 8020132c <gicd_set_enable+0x1c>
    80201334:	88057cc3 	stxr	w5, w3, [x6]
    80201338:	35ffffa5 	cbnz	w5, 8020132c <gicd_set_enable+0x1c>
    8020133c:	b9000fe5 	str	w5, [sp, #12]
    spin_lock(&gicd_lock);
    if (en)
    80201340:	36000121 	tbz	w1, #0, 80201364 <gicd_set_enable+0x54>
        gicd->ISENABLER[reg_ind] = bit;
    80201344:	90000081 	adrp	x1, 80211000 <__mprec_tens+0x180>
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201348:	91004042 	add	x2, x2, #0x10
    8020134c:	f9401421 	ldr	x1, [x1, #40]
    80201350:	8b000820 	add	x0, x1, x0, lsl #2
    80201354:	b9010004 	str	w4, [x0, #256]
    80201358:	889ffc5f 	stlr	wzr, [x2]
    else
        gicd->ICENABLER[reg_ind] = bit;
    spin_unlock(&gicd_lock);
}
    8020135c:	910043ff 	add	sp, sp, #0x10
    80201360:	d65f03c0 	ret
        gicd->ICENABLER[reg_ind] = bit;
    80201364:	90000081 	adrp	x1, 80211000 <__mprec_tens+0x180>
    80201368:	91004042 	add	x2, x2, #0x10
    8020136c:	f9401421 	ldr	x1, [x1, #40]
    80201370:	8b000820 	add	x0, x1, x0, lsl #2
    80201374:	b9018004 	str	w4, [x0, #384]
    80201378:	889ffc5f 	stlr	wzr, [x2]
}
    8020137c:	910043ff 	add	sp, sp, #0x10
    80201380:	d65f03c0 	ret

0000000080201384 <gicr_set_prio>:
    asm volatile (
    80201384:	b0000103 	adrp	x3, 80222000 <init_lock>
    80201388:	91004063 	add	x3, x3, #0x10

void gicr_set_prio(unsigned long int_id, uint8_t prio, uint32_t gicr_id)
{
    8020138c:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    80201390:	d37df004 	lsl	x4, x0, #3
{
    80201394:	12001c21 	and	w1, w1, #0xff
    unsigned long off = GIC_PRIO_OFF(int_id);
    80201398:	d37d0400 	ubfiz	x0, x0, #3, #2
    8020139c:	52800025 	mov	w5, #0x1                   	// #1
    802013a0:	91001067 	add	x7, x3, #0x4
    802013a4:	885ffce6 	ldaxr	w6, [x7]
    802013a8:	35ffffe6 	cbnz	w6, 802013a4 <gicr_set_prio+0x20>
    802013ac:	88067ce5 	stxr	w6, w5, [x7]
    802013b0:	35ffffa6 	cbnz	w6, 802013a4 <gicr_set_prio+0x20>
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    802013b4:	d345fc84 	lsr	x4, x4, #5
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);

    spin_lock(&gicr_lock);

    gicr[gicr_id].IPRIORITYR[reg_ind] =
        (gicr[gicr_id].IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    802013b8:	90000085 	adrp	x5, 80211000 <__mprec_tens+0x180>
    802013bc:	b9000fe6 	str	w6, [sp, #12]
    gicr[gicr_id].IPRIORITYR[reg_ind] =
    802013c0:	52a00048 	mov	w8, #0x20000               	// #131072
    802013c4:	d37ef486 	lsl	x6, x4, #2
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    802013c8:	11002007 	add	w7, w0, #0x8
    802013cc:	f94018a4 	ldr	x4, [x5, #48]
    802013d0:	92800005 	mov	x5, #0xffffffffffffffff    	// #-1
    802013d4:	9ba81842 	umaddl	x2, w2, w8, x6
    802013d8:	aa0503e6 	mov	x6, x5
        (gicr[gicr_id].IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    802013dc:	1ac02021 	lsl	w1, w1, w0
    802013e0:	8b020082 	add	x2, x4, x2
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    802013e4:	9ac020c6 	lsl	x6, x6, x0
        (gicr[gicr_id].IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    802013e8:	91404042 	add	x2, x2, #0x10, lsl #12
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    802013ec:	9ac720a5 	lsl	x5, x5, x7
    802013f0:	8a2500c5 	bic	x5, x6, x5
        (gicr[gicr_id].IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    802013f4:	b9440040 	ldr	w0, [x2, #1024]
    802013f8:	4a000021 	eor	w1, w1, w0
    802013fc:	0a050021 	and	w1, w1, w5
    80201400:	4a000021 	eor	w1, w1, w0
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201404:	91001060 	add	x0, x3, #0x4
    gicr[gicr_id].IPRIORITYR[reg_ind] =
    80201408:	b9040041 	str	w1, [x2, #1024]
    8020140c:	889ffc1f 	stlr	wzr, [x0]

    spin_unlock(&gicr_lock);
}
    80201410:	910043ff 	add	sp, sp, #0x10
    80201414:	d65f03c0 	ret
    80201418:	d503201f 	nop
    8020141c:	d503201f 	nop

0000000080201420 <gicr_get_prio>:
    asm volatile (
    80201420:	b0000102 	adrp	x2, 80222000 <init_lock>
    80201424:	91004042 	add	x2, x2, #0x10

unsigned long gicr_get_prio(unsigned long int_id, uint32_t gicr_id)
{
    80201428:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    8020142c:	d37df003 	lsl	x3, x0, #3
    80201430:	52800024 	mov	w4, #0x1                   	// #1
    80201434:	d342f000 	ubfx	x0, x0, #2, #59
    80201438:	91001046 	add	x6, x2, #0x4
    8020143c:	885ffcc5 	ldaxr	w5, [x6]
    80201440:	35ffffe5 	cbnz	w5, 8020143c <gicr_get_prio+0x1c>
    80201444:	88057cc4 	stxr	w5, w4, [x6]
    80201448:	35ffffa5 	cbnz	w5, 8020143c <gicr_get_prio+0x1c>
    unsigned long off = GIC_PRIO_OFF(int_id);

    spin_lock(&gicr_lock);

    unsigned long prio =
        gicr[gicr_id].IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    8020144c:	90000084 	adrp	x4, 80211000 <__mprec_tens+0x180>
    80201450:	d36f7c21 	ubfiz	x1, x1, #17, #32
    80201454:	91401000 	add	x0, x0, #0x4, lsl #12
    80201458:	b9000fe5 	str	w5, [sp, #12]
    8020145c:	f9401884 	ldr	x4, [x4, #48]
    unsigned long off = GIC_PRIO_OFF(int_id);
    80201460:	927d0463 	and	x3, x3, #0x18
        gicr[gicr_id].IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    80201464:	8b010081 	add	x1, x4, x1
    80201468:	8b000820 	add	x0, x1, x0, lsl #2
    8020146c:	b9440000 	ldr	w0, [x0, #1024]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201470:	889ffcdf 	stlr	wzr, [x6]
    80201474:	92800001 	mov	x1, #0xffffffffffffffff    	// #-1
    80201478:	1ac32402 	lsr	w2, w0, w3
    8020147c:	11002064 	add	w4, w3, #0x8
    80201480:	aa0103e0 	mov	x0, x1
    80201484:	9ac32021 	lsl	x1, x1, x3
    unsigned long prio =
    80201488:	8a020021 	and	x1, x1, x2
        gicr[gicr_id].IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    8020148c:	9ac42000 	lsl	x0, x0, x4

    spin_unlock(&gicr_lock);

    return prio;
}
    80201490:	8a200020 	bic	x0, x1, x0
    80201494:	910043ff 	add	sp, sp, #0x10
    80201498:	d65f03c0 	ret
    8020149c:	d503201f 	nop

00000000802014a0 <gicr_set_icfgr>:
    asm volatile (
    802014a0:	b0000103 	adrp	x3, 80222000 <init_lock>
    802014a4:	91004063 	add	x3, x3, #0x10

void gicr_set_icfgr(unsigned long int_id, uint8_t cfg, uint32_t gicr_id)
{
    802014a8:	d10043ff 	sub	sp, sp, #0x10
    802014ac:	12001c21 	and	w1, w1, #0xff
    802014b0:	91001065 	add	x5, x3, #0x4
    802014b4:	52800024 	mov	w4, #0x1                   	// #1
    802014b8:	885ffca6 	ldaxr	w6, [x5]
    802014bc:	35ffffe6 	cbnz	w6, 802014b8 <gicr_set_icfgr+0x18>
    802014c0:	88067ca4 	stxr	w6, w4, [x5]
    802014c4:	35ffffa6 	cbnz	w6, 802014b8 <gicr_set_icfgr+0x18>
    spin_lock(&gicr_lock);

    unsigned long reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    unsigned long off = (int_id * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8);
    802014c8:	d37f0c05 	ubfiz	x5, x0, #1, #4
    unsigned long reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    802014cc:	d37ff800 	lsl	x0, x0, #1
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;

    if (reg_ind == 0) {
    802014d0:	f1007c1f 	cmp	x0, #0x1f
        gicr[gicr_id].ICFGR0 =
            (gicr[gicr_id].ICFGR0 & ~mask) | ((cfg << off) & mask);
    802014d4:	90000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
    802014d8:	d36f7c42 	ubfiz	x2, x2, #17, #32
    802014dc:	b9000fe6 	str	w6, [sp, #12]
    802014e0:	f9401800 	ldr	x0, [x0, #48]
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;
    802014e4:	52800064 	mov	w4, #0x3                   	// #3
            (gicr[gicr_id].ICFGR0 & ~mask) | ((cfg << off) & mask);
    802014e8:	1ac52021 	lsl	w1, w1, w5
    802014ec:	8b020000 	add	x0, x0, x2
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;
    802014f0:	1ac52084 	lsl	w4, w4, w5
            (gicr[gicr_id].ICFGR0 & ~mask) | ((cfg << off) & mask);
    802014f4:	91404000 	add	x0, x0, #0x10, lsl #12
    if (reg_ind == 0) {
    802014f8:	54000148 	b.hi	80201520 <gicr_set_icfgr+0x80>  // b.pmore
            (gicr[gicr_id].ICFGR0 & ~mask) | ((cfg << off) & mask);
    802014fc:	b94c0002 	ldr	w2, [x0, #3072]
    80201500:	4a010041 	eor	w1, w2, w1
    80201504:	0a040021 	and	w1, w1, w4
    80201508:	4a020021 	eor	w1, w1, w2
        gicr[gicr_id].ICFGR0 =
    8020150c:	b90c0001 	str	w1, [x0, #3072]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201510:	91001060 	add	x0, x3, #0x4
    80201514:	889ffc1f 	stlr	wzr, [x0]
        gicr[gicr_id].ICFGR1 =
            (gicr[gicr_id].ICFGR1 & ~mask) | ((cfg << off) & mask);
    }

    spin_unlock(&gicr_lock);
}
    80201518:	910043ff 	add	sp, sp, #0x10
    8020151c:	d65f03c0 	ret
            (gicr[gicr_id].ICFGR1 & ~mask) | ((cfg << off) & mask);
    80201520:	b94c0402 	ldr	w2, [x0, #3076]
    80201524:	4a010041 	eor	w1, w2, w1
    80201528:	0a040021 	and	w1, w1, w4
    8020152c:	4a020021 	eor	w1, w1, w2
        gicr[gicr_id].ICFGR1 =
    80201530:	b90c0401 	str	w1, [x0, #3076]
    80201534:	91001060 	add	x0, x3, #0x4
    80201538:	889ffc1f 	stlr	wzr, [x0]
}
    8020153c:	910043ff 	add	sp, sp, #0x10
    80201540:	d65f03c0 	ret

0000000080201544 <gicr_get_state>:

enum int_state gicr_get_state(unsigned long int_id, uint32_t gicr_id)
{
    unsigned long mask = GIC_INT_MASK(int_id);
    80201544:	52800023 	mov	w3, #0x1                   	// #1
    asm volatile (
    80201548:	b0000102 	adrp	x2, 80222000 <init_lock>
    8020154c:	91004042 	add	x2, x2, #0x10
{
    80201550:	d10043ff 	sub	sp, sp, #0x10
    unsigned long mask = GIC_INT_MASK(int_id);
    80201554:	1ac02064 	lsl	w4, w3, w0
    80201558:	91001040 	add	x0, x2, #0x4
    8020155c:	885ffc05 	ldaxr	w5, [x0]
    80201560:	35ffffe5 	cbnz	w5, 8020155c <gicr_get_state+0x18>
    80201564:	88057c03 	stxr	w5, w3, [x0]
    80201568:	35ffffa5 	cbnz	w5, 8020155c <gicr_get_state+0x18>

    spin_lock(&gicr_lock);

    enum int_state pend = (gicr[gicr_id].ISPENDR0 & mask) ? PEND : 0;
    8020156c:	90000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
    80201570:	d36f7c23 	ubfiz	x3, x1, #17, #32
    80201574:	b9000fe5 	str	w5, [sp, #12]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201578:	91001042 	add	x2, x2, #0x4
    8020157c:	f9401801 	ldr	x1, [x0, #48]
    80201580:	8b030021 	add	x1, x1, x3
    80201584:	91404021 	add	x1, x1, #0x10, lsl #12
    80201588:	b9420020 	ldr	w0, [x1, #512]
    enum int_state act = (gicr[gicr_id].ISACTIVER0 & mask) ? ACT : 0;
    8020158c:	b9430021 	ldr	w1, [x1, #768]
    80201590:	889ffc5f 	stlr	wzr, [x2]
    80201594:	6a01009f 	tst	w4, w1
    80201598:	1a9f07e1 	cset	w1, ne	// ne = any
    enum int_state pend = (gicr[gicr_id].ISPENDR0 & mask) ? PEND : 0;
    8020159c:	6a00009f 	tst	w4, w0
    802015a0:	1a9f07e0 	cset	w0, ne	// ne = any

    spin_unlock(&gicr_lock);

    return pend | act;
}
    802015a4:	910043ff 	add	sp, sp, #0x10
    802015a8:	2a010400 	orr	w0, w0, w1, lsl #1
    802015ac:	d65f03c0 	ret

00000000802015b0 <gicr_set_act>:
    asm volatile (
    802015b0:	b0000103 	adrp	x3, 80222000 <init_lock>
    802015b4:	91004063 	add	x3, x3, #0x10
    }
    spin_unlock(&gicr_lock);
}

void gicr_set_act(unsigned long int_id, bool act, uint32_t gicr_id)
{
    802015b8:	d10043ff 	sub	sp, sp, #0x10
    802015bc:	12001c21 	and	w1, w1, #0xff
    802015c0:	91001066 	add	x6, x3, #0x4
    802015c4:	52800024 	mov	w4, #0x1                   	// #1
    802015c8:	885ffcc5 	ldaxr	w5, [x6]
    802015cc:	35ffffe5 	cbnz	w5, 802015c8 <gicr_set_act+0x18>
    802015d0:	88057cc4 	stxr	w5, w4, [x6]
    802015d4:	35ffffa5 	cbnz	w5, 802015c8 <gicr_set_act+0x18>
    spin_lock(&gicr_lock);

    if (act) {
        gicr[gicr_id].ISACTIVER0 = GIC_INT_MASK(int_id);
    802015d8:	1ac02084 	lsl	w4, w4, w0
    802015dc:	90000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
    802015e0:	d36f7c42 	ubfiz	x2, x2, #17, #32
    802015e4:	b9000fe5 	str	w5, [sp, #12]
    802015e8:	f9401800 	ldr	x0, [x0, #48]
    802015ec:	8b020000 	add	x0, x0, x2
    802015f0:	91404000 	add	x0, x0, #0x10, lsl #12
    if (act) {
    802015f4:	360000c1 	tbz	w1, #0, 8020160c <gicr_set_act+0x5c>
        gicr[gicr_id].ISACTIVER0 = GIC_INT_MASK(int_id);
    802015f8:	b9030004 	str	w4, [x0, #768]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802015fc:	91001060 	add	x0, x3, #0x4
    80201600:	889ffc1f 	stlr	wzr, [x0]
    } else {
        gicr[gicr_id].ICACTIVER0 = GIC_INT_MASK(int_id);
    }

    spin_unlock(&gicr_lock);
}
    80201604:	910043ff 	add	sp, sp, #0x10
    80201608:	d65f03c0 	ret
        gicr[gicr_id].ICACTIVER0 = GIC_INT_MASK(int_id);
    8020160c:	b9038004 	str	w4, [x0, #896]
    80201610:	91001060 	add	x0, x3, #0x4
    80201614:	889ffc1f 	stlr	wzr, [x0]
}
    80201618:	910043ff 	add	sp, sp, #0x10
    8020161c:	d65f03c0 	ret

0000000080201620 <gicr_set_state>:

void gicr_set_state(unsigned long int_id, enum int_state state, uint32_t gicr_id)
{
    80201620:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80201624:	2a0103e8 	mov	w8, w1
    80201628:	aa0003e9 	mov	x9, x0
    8020162c:	910003fd 	mov	x29, sp
    gicr_set_act(int_id, state & ACT, gicr_id);
    80201630:	d3410501 	ubfx	x1, x8, #1, #1
{
    80201634:	2a0203e7 	mov	w7, w2
    gicr_set_act(int_id, state & ACT, gicr_id);
    80201638:	97ffffde 	bl	802015b0 <gicr_set_act>
    asm volatile (
    8020163c:	b0000103 	adrp	x3, 80222000 <init_lock>
    80201640:	91004063 	add	x3, x3, #0x10
    80201644:	91001061 	add	x1, x3, #0x4
    80201648:	52800024 	mov	w4, #0x1                   	// #1
    8020164c:	885ffc20 	ldaxr	w0, [x1]
    80201650:	35ffffe0 	cbnz	w0, 8020164c <gicr_set_state+0x2c>
    80201654:	88007c24 	stxr	w0, w4, [x1]
    80201658:	35ffffa0 	cbnz	w0, 8020164c <gicr_set_state+0x2c>
    8020165c:	b9001fe0 	str	w0, [sp, #28]
        gicr[gicr_id].ISPENDR0 = (1U) << (int_id);
    80201660:	90000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
    80201664:	d36f7ce7 	ubfiz	x7, x7, #17, #32
    80201668:	1ac92084 	lsl	w4, w4, w9
    8020166c:	f9401800 	ldr	x0, [x0, #48]
    80201670:	8b070000 	add	x0, x0, x7
    80201674:	91404000 	add	x0, x0, #0x10, lsl #12
    if (pend) {
    80201678:	360000c8 	tbz	w8, #0, 80201690 <gicr_set_state+0x70>
        gicr[gicr_id].ISPENDR0 = (1U) << (int_id);
    8020167c:	b9020004 	str	w4, [x0, #512]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201680:	91001060 	add	x0, x3, #0x4
    80201684:	889ffc1f 	stlr	wzr, [x0]
    gicr_set_pend(int_id, state & PEND, gicr_id);
}
    80201688:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020168c:	d65f03c0 	ret
        gicr[gicr_id].ICPENDR0 = (1U) << (int_id);
    80201690:	b9028004 	str	w4, [x0, #640]
    80201694:	91001060 	add	x0, x3, #0x4
    80201698:	889ffc1f 	stlr	wzr, [x0]
}
    8020169c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802016a0:	d65f03c0 	ret

00000000802016a4 <gicr_set_trgt>:
    asm volatile (
    802016a4:	b0000100 	adrp	x0, 80222000 <init_lock>
    802016a8:	91004000 	add	x0, x0, #0x10

void gicr_set_trgt(unsigned long int_id, uint8_t trgt, uint32_t gicr_id)
{
    802016ac:	d10043ff 	sub	sp, sp, #0x10
    802016b0:	52800021 	mov	w1, #0x1                   	// #1
    802016b4:	91001003 	add	x3, x0, #0x4
    802016b8:	885ffc62 	ldaxr	w2, [x3]
    802016bc:	35ffffe2 	cbnz	w2, 802016b8 <gicr_set_trgt+0x14>
    802016c0:	88027c61 	stxr	w2, w1, [x3]
    802016c4:	35ffffa2 	cbnz	w2, 802016b8 <gicr_set_trgt+0x14>
    802016c8:	b9000fe2 	str	w2, [sp, #12]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802016cc:	889ffc7f 	stlr	wzr, [x3]
    spin_lock(&gicr_lock);

    spin_unlock(&gicr_lock);
}
    802016d0:	910043ff 	add	sp, sp, #0x10
    802016d4:	d65f03c0 	ret
    802016d8:	d503201f 	nop
    802016dc:	d503201f 	nop

00000000802016e0 <gicr_set_route>:

void gicr_set_route(unsigned long int_id, uint8_t trgt, uint32_t gicr_id)
    802016e0:	b0000100 	adrp	x0, 80222000 <init_lock>
    802016e4:	91004000 	add	x0, x0, #0x10
    802016e8:	d10043ff 	sub	sp, sp, #0x10
    802016ec:	52800021 	mov	w1, #0x1                   	// #1
    802016f0:	91001003 	add	x3, x0, #0x4
    802016f4:	885ffc62 	ldaxr	w2, [x3]
    802016f8:	35ffffe2 	cbnz	w2, 802016f4 <gicr_set_route+0x14>
    802016fc:	88027c61 	stxr	w2, w1, [x3]
    80201700:	35ffffa2 	cbnz	w2, 802016f4 <gicr_set_route+0x14>
    80201704:	b9000fe2 	str	w2, [sp, #12]
    80201708:	889ffc7f 	stlr	wzr, [x3]
    8020170c:	910043ff 	add	sp, sp, #0x10
    80201710:	d65f03c0 	ret

0000000080201714 <gicr_set_enable>:
    gicr_set_trgt(int_id, trgt, gicr_id);
}

void gicr_set_enable(unsigned long int_id, bool en, uint32_t gicr_id)
{
    unsigned long bit = GIC_INT_MASK(int_id);
    80201714:	52800024 	mov	w4, #0x1                   	// #1
    asm volatile (
    80201718:	b0000103 	adrp	x3, 80222000 <init_lock>
    8020171c:	91004063 	add	x3, x3, #0x10
{
    80201720:	d10043ff 	sub	sp, sp, #0x10
    80201724:	12001c21 	and	w1, w1, #0xff
    80201728:	91001066 	add	x6, x3, #0x4
    unsigned long bit = GIC_INT_MASK(int_id);
    8020172c:	1ac02080 	lsl	w0, w4, w0
    80201730:	885ffcc5 	ldaxr	w5, [x6]
    80201734:	35ffffe5 	cbnz	w5, 80201730 <gicr_set_enable+0x1c>
    80201738:	88057cc4 	stxr	w5, w4, [x6]
    8020173c:	35ffffa5 	cbnz	w5, 80201730 <gicr_set_enable+0x1c>
    80201740:	b9000fe5 	str	w5, [sp, #12]

    spin_lock(&gicr_lock);
    if (en)
        gicr[gicr_id].ISENABLER0 = bit;
    80201744:	d36f7c42 	ubfiz	x2, x2, #17, #32
    if (en)
    80201748:	36000141 	tbz	w1, #0, 80201770 <gicr_set_enable+0x5c>
        gicr[gicr_id].ISENABLER0 = bit;
    8020174c:	90000081 	adrp	x1, 80211000 <__mprec_tens+0x180>
    80201750:	f9401821 	ldr	x1, [x1, #48]
    80201754:	8b020021 	add	x1, x1, x2
    80201758:	91404021 	add	x1, x1, #0x10, lsl #12
    8020175c:	b9010020 	str	w0, [x1, #256]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201760:	91001060 	add	x0, x3, #0x4
    80201764:	889ffc1f 	stlr	wzr, [x0]
    else
        gicr[gicr_id].ICENABLER0 = bit;
    spin_unlock(&gicr_lock);
}
    80201768:	910043ff 	add	sp, sp, #0x10
    8020176c:	d65f03c0 	ret
        gicr[gicr_id].ICENABLER0 = bit;
    80201770:	90000081 	adrp	x1, 80211000 <__mprec_tens+0x180>
    80201774:	f9401821 	ldr	x1, [x1, #48]
    80201778:	8b020021 	add	x1, x1, x2
    8020177c:	91404021 	add	x1, x1, #0x10, lsl #12
    80201780:	b9018020 	str	w0, [x1, #384]
    80201784:	91001060 	add	x0, x3, #0x4
    80201788:	889ffc1f 	stlr	wzr, [x0]
}
    8020178c:	910043ff 	add	sp, sp, #0x10
    80201790:	d65f03c0 	ret

0000000080201794 <gic_send_sgi>:
    else return false;
}

void gic_send_sgi(unsigned long cpu_target, unsigned long sgi_num)
{
    if (sgi_num >= GIC_MAX_SGIS) return;
    80201794:	f1003c3f 	cmp	x1, #0xf
    80201798:	540000a8 	b.hi	802017ac <gic_send_sgi+0x18>  // b.pmore
    
    unsigned long sgi = (1UL << (cpu_target & 0xffull)) | (sgi_num << 24);
    8020179c:	d2800022 	mov	x2, #0x1                   	// #1
    802017a0:	9ac02040 	lsl	x0, x2, x0
    802017a4:	aa016001 	orr	x1, x0, x1, lsl #24
SYSREG_GEN_ACCESSORS(icc_sgi1r_el1);
    802017a8:	d518cba1 	msr	icc_sgi1r_el1, x1
    sysreg_icc_sgi1r_el1_write(sgi); 
}
    802017ac:	d65f03c0 	ret

00000000802017b0 <gic_set_prio>:
    if (int_id > 32 && int_id < 1025) return true;
    802017b0:	d1008402 	sub	x2, x0, #0x21

void gic_set_prio(unsigned long int_id, uint8_t prio)
{
    802017b4:	12001c21 	and	w1, w1, #0xff
    if (int_id > 32 && int_id < 1025) return true;
    802017b8:	f10f7c5f 	cmp	x2, #0x3df
    802017bc:	54000048 	b.hi	802017c4 <gic_set_prio+0x14>  // b.pmore
    if (irq_in_gicd(int_id)) {
        return gicd_set_prio(int_id, prio);
    802017c0:	17fffe18 	b	80201020 <gicd_set_prio>
SYSREG_GEN_ACCESSORS(mpidr_el1);
    802017c4:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_prio(int_id, prio, get_cpuid());
    802017c8:	12001c42 	and	w2, w2, #0xff
    802017cc:	17fffeee 	b	80201384 <gicr_set_prio>

00000000802017d0 <gic_get_prio>:
    if (int_id > 32 && int_id < 1025) return true;
    802017d0:	d1008401 	sub	x1, x0, #0x21
    802017d4:	f10f7c3f 	cmp	x1, #0x3df
    802017d8:	54000048 	b.hi	802017e0 <gic_get_prio+0x10>  // b.pmore
}

unsigned long gic_get_prio(unsigned long int_id)
{
    if (irq_in_gicd(int_id)) {
        return gicd_get_prio(int_id);
    802017dc:	17fffdd9 	b	80200f40 <gicd_get_prio>
    802017e0:	d53800a1 	mrs	x1, mpidr_el1
    } else {
        return gicr_get_prio(int_id, get_cpuid());
    802017e4:	12001c21 	and	w1, w1, #0xff
    802017e8:	17ffff0e 	b	80201420 <gicr_get_prio>
    802017ec:	d503201f 	nop

00000000802017f0 <gic_set_icfgr>:
    if (int_id > 32 && int_id < 1025) return true;
    802017f0:	d1008402 	sub	x2, x0, #0x21
    }
}

void gic_set_icfgr(unsigned long int_id, uint8_t cfg)
{
    802017f4:	12001c21 	and	w1, w1, #0xff
    if (int_id > 32 && int_id < 1025) return true;
    802017f8:	f10f7c5f 	cmp	x2, #0x3df
    802017fc:	54000048 	b.hi	80201804 <gic_set_icfgr+0x14>  // b.pmore
    if (irq_in_gicd(int_id)) {
        return gicd_set_icfgr(int_id, cfg);
    80201800:	17fffdec 	b	80200fb0 <gicd_set_icfgr>
    80201804:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_icfgr(int_id, cfg, get_cpuid());
    80201808:	12001c42 	and	w2, w2, #0xff
    8020180c:	17ffff25 	b	802014a0 <gicr_set_icfgr>

0000000080201810 <gic_get_state>:
    if (int_id > 32 && int_id < 1025) return true;
    80201810:	d1008401 	sub	x1, x0, #0x21
    80201814:	f10f7c3f 	cmp	x1, #0x3df
    80201818:	54000048 	b.hi	80201820 <gic_get_state+0x10>  // b.pmore
}

enum int_state gic_get_state(unsigned long int_id)
{
    if (irq_in_gicd(int_id)) {
        return gicd_get_state(int_id);
    8020181c:	17fffe21 	b	802010a0 <gicd_get_state>
    80201820:	d53800a1 	mrs	x1, mpidr_el1
    } else {
        return gicr_get_state(int_id, get_cpuid());
    80201824:	12001c21 	and	w1, w1, #0xff
    80201828:	17ffff47 	b	80201544 <gicr_get_state>
    8020182c:	d503201f 	nop

0000000080201830 <gic_set_act>:
    if (int_id > 32 && int_id < 1025) return true;
    80201830:	d1008402 	sub	x2, x0, #0x21
        return gicr_set_pend(int_id, pend, get_cpuid());
    }
}

void gic_set_act(unsigned long int_id, bool act)
{
    80201834:	12001c21 	and	w1, w1, #0xff
    if (int_id > 32 && int_id < 1025) return true;
    80201838:	f10f7c5f 	cmp	x2, #0x3df
    8020183c:	54000048 	b.hi	80201844 <gic_set_act+0x14>  // b.pmore
    if (irq_in_gicd(int_id)) {
        return gicd_set_act(int_id, act);
    80201840:	17fffe30 	b	80201100 <gicd_set_act>
    80201844:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_act(int_id, act, get_cpuid());
    80201848:	12001c42 	and	w2, w2, #0xff
    8020184c:	17ffff59 	b	802015b0 <gicr_set_act>

0000000080201850 <gic_set_state>:
    if (int_id > 32 && int_id < 1025) return true;
    80201850:	d1008402 	sub	x2, x0, #0x21
    80201854:	f10f7c5f 	cmp	x2, #0x3df
    80201858:	54000048 	b.hi	80201860 <gic_set_state+0x10>  // b.pmore
}

void gic_set_state(unsigned long int_id, enum int_state state)
{
    if (irq_in_gicd(int_id)) {
        return gicd_set_state(int_id, state);
    8020185c:	17fffe45 	b	80201170 <gicd_set_state>
    80201860:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_state(int_id, state, get_cpuid());
    80201864:	12001c42 	and	w2, w2, #0xff
    80201868:	17ffff6e 	b	80201620 <gicr_set_state>
    8020186c:	d503201f 	nop

0000000080201870 <gic_set_trgt>:
    if (int_id > 32 && int_id < 1025) return true;
    80201870:	d1008402 	sub	x2, x0, #0x21
    80201874:	f10f7c5f 	cmp	x2, #0x3df
    80201878:	54000068 	b.hi	80201884 <gic_set_trgt+0x14>  // b.pmore
    8020187c:	12001c21 	and	w1, w1, #0xff
}

void gic_set_trgt(unsigned long int_id, uint8_t trgt)
{
    if (irq_in_gicd(int_id)) {
        return gicd_set_trgt(int_id, trgt);
    80201880:	17fffe78 	b	80201260 <gicd_set_trgt>
{
    80201884:	d10043ff 	sub	sp, sp, #0x10
    80201888:	d53800a0 	mrs	x0, mpidr_el1
    asm volatile (
    8020188c:	b0000100 	adrp	x0, 80222000 <init_lock>
    80201890:	91004000 	add	x0, x0, #0x10
    80201894:	52800021 	mov	w1, #0x1                   	// #1
    80201898:	91001003 	add	x3, x0, #0x4
    8020189c:	885ffc62 	ldaxr	w2, [x3]
    802018a0:	35ffffe2 	cbnz	w2, 8020189c <gic_set_trgt+0x2c>
    802018a4:	88027c61 	stxr	w2, w1, [x3]
    802018a8:	35ffffa2 	cbnz	w2, 8020189c <gic_set_trgt+0x2c>
    802018ac:	b9000fe2 	str	w2, [sp, #12]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802018b0:	889ffc7f 	stlr	wzr, [x3]
    } else {
        return gicr_set_trgt(int_id, trgt, get_cpuid());
    }
}
    802018b4:	910043ff 	add	sp, sp, #0x10
    802018b8:	d65f03c0 	ret
    802018bc:	d503201f 	nop

00000000802018c0 <gic_set_route>:
    if (gic_is_priv(int_id)) return;
    802018c0:	f1007c1f 	cmp	x0, #0x1f
    802018c4:	54000129 	b.ls	802018e8 <gic_set_route+0x28>  // b.plast
    volatile uint32_t *irouter = (uint32_t*) &gicd->IROUTER[int_id];
    802018c8:	90000082 	adrp	x2, 80211000 <__mprec_tens+0x180>
    802018cc:	91300000 	add	x0, x0, #0xc00
    irouter[1] = (_trgt >> 32);
    802018d0:	d360fc24 	lsr	x4, x1, #32
    volatile uint32_t *irouter = (uint32_t*) &gicd->IROUTER[int_id];
    802018d4:	f9401442 	ldr	x2, [x2, #40]
    802018d8:	d37df000 	lsl	x0, x0, #3
    802018dc:	8b000043 	add	x3, x2, x0
    irouter[0] = _trgt;
    802018e0:	b8206841 	str	w1, [x2, x0]
    irouter[1] = (_trgt >> 32);
    802018e4:	b9000464 	str	w4, [x3, #4]

void gic_set_route(unsigned long int_id, unsigned long trgt)
{
    return gicd_set_route(int_id, trgt);
}
    802018e8:	d65f03c0 	ret
    802018ec:	d503201f 	nop

00000000802018f0 <gic_set_enable>:
    if (int_id > 32 && int_id < 1025) return true;
    802018f0:	d1008402 	sub	x2, x0, #0x21

void gic_set_enable(unsigned long int_id, bool en)
{
    802018f4:	12001c21 	and	w1, w1, #0xff
    if (int_id > 32 && int_id < 1025) return true;
    802018f8:	f10f7c5f 	cmp	x2, #0x3df
    802018fc:	54000048 	b.hi	80201904 <gic_set_enable+0x14>  // b.pmore
    if (irq_in_gicd(int_id)) {
        return gicd_set_enable(int_id, en);
    80201900:	17fffe84 	b	80201310 <gicd_set_enable>
    80201904:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_enable(int_id, en, get_cpuid());
    80201908:	12001c42 	and	w2, w2, #0xff
    8020190c:	17ffff82 	b	80201714 <gicr_set_enable>

0000000080201910 <gicr_set_propbaser>:
}

/*LPI support*/
void gicr_set_propbaser(uint64_t propbaser,uint8_t rdist_id)
{
    gicr[rdist_id].PROPBASER = propbaser;
    80201910:	90000082 	adrp	x2, 80211000 <__mprec_tens+0x180>
    80201914:	d36f1c21 	ubfiz	x1, x1, #17, #8
    80201918:	f9401842 	ldr	x2, [x2, #48]
    8020191c:	8b010042 	add	x2, x2, x1
    80201920:	f9003840 	str	x0, [x2, #112]
}
    80201924:	d65f03c0 	ret
    80201928:	d503201f 	nop
    8020192c:	d503201f 	nop

0000000080201930 <gicr_set_pendbaser>:

void gicr_set_pendbaser(uint64_t pendbaser,uint8_t rdist_id)
{
    gicr[rdist_id].PENDBASER = pendbaser;
    80201930:	90000082 	adrp	x2, 80211000 <__mprec_tens+0x180>
    80201934:	d36f1c21 	ubfiz	x1, x1, #17, #8
    80201938:	f9401842 	ldr	x2, [x2, #48]
    8020193c:	8b010042 	add	x2, x2, x1
    80201940:	f9003c40 	str	x0, [x2, #120]
}
    80201944:	d65f03c0 	ret
    80201948:	d503201f 	nop
    8020194c:	d503201f 	nop

0000000080201950 <gicr_disable_lpi>:

void gicr_disable_lpi(uint8_t rdist_id)
{
    gicr[rdist_id].CTLR &= ~0x1; 
    80201950:	90000081 	adrp	x1, 80211000 <__mprec_tens+0x180>
    80201954:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80201958:	f9401822 	ldr	x2, [x1, #48]
    8020195c:	b8606841 	ldr	w1, [x2, x0]
    80201960:	121f7821 	and	w1, w1, #0xfffffffe
    80201964:	b8206841 	str	w1, [x2, x0]
}
    80201968:	d65f03c0 	ret
    8020196c:	d503201f 	nop

0000000080201970 <gicr_enable_lpi>:

void gicr_enable_lpi(uint8_t rdist_id)
{
    gicr[rdist_id].CTLR |= 0x1;
    80201970:	90000081 	adrp	x1, 80211000 <__mprec_tens+0x180>
    80201974:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80201978:	f9401822 	ldr	x2, [x1, #48]
    8020197c:	b8606841 	ldr	w1, [x2, x0]
    80201980:	32000021 	orr	w1, w1, #0x1
    80201984:	b8206841 	str	w1, [x2, x0]
}
    80201988:	d65f03c0 	ret
    8020198c:	00000000 	udf	#0

0000000080201990 <its_send_mapc>:
/* Command Generation*/

void its_send_mapc(){

    /*Point to the next cmd in the cmd queue*/
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201990:	f0000160 	adrp	x0, 80230000 <its>
    80201994:	91000002 	add	x2, x0, #0x0

    /*MAP Coll ID 0 to redistributor 0*/

    its_cmd->cmd[0] = 0x09;
    80201998:	d2800124 	mov	x4, #0x9                   	// #9
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x8000000000000000;
    8020199c:	d2f00003 	mov	x3, #0x8000000000000000    	// #-9223372036854775808
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    802019a0:	f9400001 	ldr	x1, [x0]
    802019a4:	b9402842 	ldr	w2, [x2, #40]
    802019a8:	8b010040 	add	x0, x2, x1
    its_cmd->cmd[0] = 0x09;
    802019ac:	f8216844 	str	x4, [x2, x1]
    its_cmd->cmd[2] = 0x8000000000000000;
    802019b0:	a9008c1f 	stp	xzr, x3, [x0, #8]
    its_cmd->cmd[3] = 0x00;
    802019b4:	f9000c1f 	str	xzr, [x0, #24]


}
    802019b8:	d65f03c0 	ret
    802019bc:	d503201f 	nop

00000000802019c0 <its_send_invall>:

void its_send_invall(){

    /*Point to the next cmd in the cmd qeueu*/
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    802019c0:	f0000160 	adrp	x0, 80230000 <its>
    802019c4:	91000002 	add	x2, x0, #0x0

    its_cmd->cmd[0] = 0x0d;
    802019c8:	d28001a3 	mov	x3, #0xd                   	// #13
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    802019cc:	f9400001 	ldr	x1, [x0]
    802019d0:	b9402842 	ldr	w2, [x2, #40]
    802019d4:	8b010040 	add	x0, x2, x1
    its_cmd->cmd[0] = 0x0d;
    802019d8:	f8216843 	str	x3, [x2, x1]
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    802019dc:	a900fc1f 	stp	xzr, xzr, [x0, #8]
    its_cmd->cmd[3] = 0x00;
    802019e0:	f9000c1f 	str	xzr, [x0, #24]

}
    802019e4:	d65f03c0 	ret
    802019e8:	d503201f 	nop
    802019ec:	d503201f 	nop

00000000802019f0 <its_send_int>:

void its_send_int(){
    /*Point to the next cmd in the cmd qeueu*/
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    802019f0:	f0000160 	adrp	x0, 80230000 <its>
    802019f4:	91000002 	add	x2, x0, #0x0

    /*Generate lpi associated to the eventID 0 and device ID 0*/

    its_cmd->cmd[0] = 0x03;
    802019f8:	d2800063 	mov	x3, #0x3                   	// #3
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    802019fc:	f9400001 	ldr	x1, [x0]
    80201a00:	b9402842 	ldr	w2, [x2, #40]
    80201a04:	8b010040 	add	x0, x2, x1
    its_cmd->cmd[0] = 0x03;
    80201a08:	f8216843 	str	x3, [x2, x1]
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    80201a0c:	a900fc1f 	stp	xzr, xzr, [x0, #8]
    its_cmd->cmd[3] = 0x00;
    80201a10:	f9000c1f 	str	xzr, [x0, #24]

}
    80201a14:	d65f03c0 	ret
    80201a18:	d503201f 	nop
    80201a1c:	d503201f 	nop

0000000080201a20 <its_send_sync>:

void its_send_sync(){

    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a20:	f0000160 	adrp	x0, 80230000 <its>
    80201a24:	91000002 	add	x2, x0, #0x0

    /*Sync redistributor 0*/

    its_cmd->cmd[0] = 0x05;
    80201a28:	d28000a3 	mov	x3, #0x5                   	// #5
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a2c:	f9400001 	ldr	x1, [x0]
    80201a30:	b9402842 	ldr	w2, [x2, #40]
    80201a34:	8b010040 	add	x0, x2, x1
    its_cmd->cmd[0] = 0x05;
    80201a38:	f8216843 	str	x3, [x2, x1]
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    80201a3c:	a900fc1f 	stp	xzr, xzr, [x0, #8]
    its_cmd->cmd[3] = 0x00;
    80201a40:	f9000c1f 	str	xzr, [x0, #24]

}
    80201a44:	d65f03c0 	ret
    80201a48:	d503201f 	nop
    80201a4c:	d503201f 	nop

0000000080201a50 <its_send_mapd>:

void its_send_mapd(){

    uint64_t itt_addr = (uint64_t)its.itt_table;
    80201a50:	f0000161 	adrp	x1, 80230000 <its>
    80201a54:	91000020 	add	x0, x1, #0x0
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);

    /*Map device id 0 to ITT address*/

    its_cmd->cmd[0] = 0x08;
    80201a58:	d2800105 	mov	x5, #0x8                   	// #8
    its_cmd->cmd[1] = 0x01;       /*1 bit size*/
    80201a5c:	d2800024 	mov	x4, #0x1                   	// #1
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a60:	f9400022 	ldr	x2, [x1]
    80201a64:	b9402803 	ldr	w3, [x0, #40]
    uint64_t itt_addr = (uint64_t)its.itt_table;
    80201a68:	f9400801 	ldr	x1, [x0, #16]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a6c:	8b020060 	add	x0, x3, x2
    its_cmd->cmd[0] = 0x08;
    80201a70:	f8226865 	str	x5, [x3, x2]
    its_cmd->cmd[2] = (1ULL << 63) | itt_addr;        /*Verify alignment*/
    80201a74:	b2410021 	orr	x1, x1, #0x8000000000000000
    80201a78:	a9008404 	stp	x4, x1, [x0, #8]
    its_cmd->cmd[3] = 0x00;
    80201a7c:	f9000c1f 	str	xzr, [x0, #24]

}
    80201a80:	d65f03c0 	ret

0000000080201a84 <its_send_mapti>:

void its_send_mapti(){

    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a84:	f0000160 	adrp	x0, 80230000 <its>
    80201a88:	91000002 	add	x2, x0, #0x0

    its_cmd->cmd[0] = 0x0a;
    80201a8c:	d2800144 	mov	x4, #0xa                   	// #10
    its_cmd->cmd[1] = 0x200000000000;       /*8192 pINTID*/
    80201a90:	d2c40003 	mov	x3, #0x200000000000        	// #35184372088832
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a94:	f9400001 	ldr	x1, [x0]
    80201a98:	b9402842 	ldr	w2, [x2, #40]
    80201a9c:	8b010040 	add	x0, x2, x1
    its_cmd->cmd[0] = 0x0a;
    80201aa0:	f8216844 	str	x4, [x2, x1]
    its_cmd->cmd[2] = 0x00;                 /*Coll ID 0*/
    80201aa4:	a900fc03 	stp	x3, xzr, [x0, #8]
    its_cmd->cmd[3] = 0x00;
    80201aa8:	f9000c1f 	str	xzr, [x0, #24]



}
    80201aac:	d65f03c0 	ret

0000000080201ab0 <its_send_inv>:

void its_send_inv(){
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201ab0:	f0000160 	adrp	x0, 80230000 <its>
    80201ab4:	91000002 	add	x2, x0, #0x0

    /*Cache consistent with LPI tables held in memory*/

    its_cmd->cmd[0] = 0x0c;
    80201ab8:	d2800183 	mov	x3, #0xc                   	// #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201abc:	f9400001 	ldr	x1, [x0]
    80201ac0:	b9402842 	ldr	w2, [x2, #40]
    80201ac4:	8b010040 	add	x0, x2, x1
    its_cmd->cmd[0] = 0x0c;
    80201ac8:	f8216843 	str	x3, [x2, x1]
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    80201acc:	a900fc1f 	stp	xzr, xzr, [x0, #8]
    its_cmd->cmd[3] = 0x00;
    80201ad0:	f9000c1f 	str	xzr, [x0, #24]
}
    80201ad4:	d65f03c0 	ret
    80201ad8:	d503201f 	nop
    80201adc:	d503201f 	nop

0000000080201ae0 <its_cpu_init_collections>:
void its_cpu_init_collections(){

    /*Bind the Collection ID with the target redistributor*/
    /*For this configuration, collection ID 0 is hardwired to redistributor 0*/

    cmd_off = gits->CWRITER;
    80201ae0:	90000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201ae4:	f0000162 	adrp	x2, 80230000 <its>
    its_cmd->cmd[0] = 0x09;
    80201ae8:	d2800126 	mov	x6, #0x9                   	// #9
    its_cmd->cmd[2] = 0x8000000000000000;
    80201aec:	d2f0000e 	mov	x14, #0x8000000000000000    	// #-9223372036854775808
    cmd_off = gits->CWRITER;
    80201af0:	f9401c05 	ldr	x5, [x0, #56]
    its_cmd->cmd[0] = 0x05;
    80201af4:	d28000a8 	mov	x8, #0x5                   	// #5
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201af8:	f9400041 	ldr	x1, [x2]
    80201afc:	91000044 	add	x4, x2, #0x0
    cmd_off = gits->CWRITER;
    80201b00:	f94044a0 	ldr	x0, [x5, #136]
    its_cmd->cmd[0] = 0x0d;
    80201b04:	d28001ac 	mov	x12, #0xd                   	// #13
    its_send_mapc();
    cmd_off += 0x20;
    80201b08:	1100800d 	add	w13, w0, #0x20
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b0c:	11008003 	add	w3, w0, #0x20
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b10:	8b204027 	add	x7, x1, w0, uxtw
    its_cmd->cmd[0] = 0x09;
    80201b14:	f8204826 	str	x6, [x1, w0, uxtw]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b18:	8b010063 	add	x3, x3, x1

    //flush


    /*Increment CWRITTER*/
    gits->CWRITER = cmd_off;
    80201b1c:	11010009 	add	w9, w0, #0x40
    cmd_off += 0x20;
    80201b20:	1101000b 	add	w11, w0, #0x40
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b24:	8b010126 	add	x6, x9, x1
    its_cmd->cmd[2] = 0x8000000000000000;
    80201b28:	a900b8ff 	stp	xzr, x14, [x7, #8]

    its_send_invall();
    cmd_off += 0x20;
    80201b2c:	1101800a 	add	w10, w0, #0x60
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b30:	11018002 	add	w2, w0, #0x60
    its_cmd->cmd[3] = 0x00;
    80201b34:	f9000cff 	str	xzr, [x7, #24]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b38:	8b010042 	add	x2, x2, x1
    its_cmd->cmd[0] = 0x05;
    80201b3c:	f82d4828 	str	x8, [x1, w13, uxtw]
    its_send_sync();
    cmd_off += 0x20;
    80201b40:	11020007 	add	w7, w0, #0x80
    its_cmd->cmd[2] = 0x00;
    80201b44:	a900fc7f 	stp	xzr, xzr, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201b48:	f9000c7f 	str	xzr, [x3, #24]
    gits->CWRITER = cmd_off;
    80201b4c:	f90044a9 	str	x9, [x5, #136]
    its_cmd->cmd[0] = 0x0d;
    80201b50:	f82b482c 	str	x12, [x1, w11, uxtw]
    its_cmd->cmd[2] = 0x00;
    80201b54:	a900fcdf 	stp	xzr, xzr, [x6, #8]
    its_cmd->cmd[3] = 0x00;
    80201b58:	f9000cdf 	str	xzr, [x6, #24]
    its_cmd->cmd[0] = 0x05;
    80201b5c:	f82a4828 	str	x8, [x1, w10, uxtw]
    its_cmd->cmd[2] = 0x00;
    80201b60:	a900fc5f 	stp	xzr, xzr, [x2, #8]
    its_cmd->cmd[3] = 0x00;
    80201b64:	f9000c5f 	str	xzr, [x2, #24]
    cmd_off += 0x20;
    80201b68:	b9002887 	str	w7, [x4, #40]

    gits->CWRITER = cmd_off;
    80201b6c:	f90044a7 	str	x7, [x5, #136]

}
    80201b70:	d65f03c0 	ret

0000000080201b74 <its_cpu_init>:


int its_cpu_init(void)
{
    80201b74:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80201b78:	910003fd 	mov	x29, sp
    int ret;

    /*UPDATE Collection table*/
	its_cpu_init_collections();
    80201b7c:	97ffffd9 	bl	80201ae0 <its_cpu_init_collections>

	return 0;
}
    80201b80:	52800000 	mov	w0, #0x0                   	// #0
    80201b84:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80201b88:	d65f03c0 	ret
    80201b8c:	d503201f 	nop

0000000080201b90 <its_device_init>:

/*
    Device specific initialization
*/

int its_device_init(){
    80201b90:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    its_cmd->cmd[0] = 0x08;
    80201b94:	d2800105 	mov	x5, #0x8                   	// #8
    its_cmd->cmd[1] = 0x01;       /*1 bit size*/
    80201b98:	d2800023 	mov	x3, #0x1                   	// #1
int its_device_init(){
    80201b9c:	910003fd 	mov	x29, sp
    80201ba0:	a9025bf5 	stp	x21, x22, [sp, #32]

    /*Map the itt_addr to the device_ID in device table*/
    cmd_off = gits->CWRITER;
    80201ba4:	90000096 	adrp	x22, 80211000 <__mprec_tens+0x180>
    its_cmd->cmd[0] = 0x0a;
    80201ba8:	d280014b 	mov	x11, #0xa                   	// #10
    cmd_off = gits->CWRITER;
    80201bac:	f9401ec4 	ldr	x4, [x22, #56]
int its_device_init(){
    80201bb0:	a90153f3 	stp	x19, x20, [sp, #16]
    uint64_t itt_addr = (uint64_t)its.itt_table;
    80201bb4:	f0000174 	adrp	x20, 80230000 <its>
    80201bb8:	91000293 	add	x19, x20, #0x0
    its_cmd->cmd[1] = 0x200000000000;       /*8192 pINTID*/
    80201bbc:	d2c4000a 	mov	x10, #0x200000000000        	// #35184372088832
    cmd_off = gits->CWRITER;
    80201bc0:	f9404480 	ldr	x0, [x4, #136]
    its_cmd->cmd[0] = 0x05;
    80201bc4:	d28000b5 	mov	x21, #0x5                   	// #5
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201bc8:	f9400282 	ldr	x2, [x20]
    its_send_mapd();
    //its_send_sync(); // ???
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;
    80201bcc:	11008007 	add	w7, w0, #0x20
    uint64_t itt_addr = (uint64_t)its.itt_table;
    80201bd0:	f9400a66 	ldr	x6, [x19, #16]
    cmd_off += 0x20;
    80201bd4:	11008008 	add	w8, w0, #0x20
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201bd8:	8b204041 	add	x1, x2, w0, uxtw
    its_cmd->cmd[0] = 0x08;
    80201bdc:	f8204845 	str	x5, [x2, w0, uxtw]
    its_cmd->cmd[2] = (1ULL << 63) | itt_addr;        /*Verify alignment*/
    80201be0:	b24100c6 	orr	x6, x6, #0x8000000000000000
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201be4:	8b0200e5 	add	x5, x7, x2

    /*Map the eventID and deviceID to collection ID int the itt table*/
    its_send_mapti();
    cmd_off += 0x20;
    80201be8:	11010009 	add	w9, w0, #0x40
    its_cmd->cmd[2] = (1ULL << 63) | itt_addr;        /*Verify alignment*/
    80201bec:	a9009823 	stp	x3, x6, [x1, #8]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201bf0:	11010003 	add	w3, w0, #0x40
    80201bf4:	8b020063 	add	x3, x3, x2
    its_cmd->cmd[3] = 0x00;
    80201bf8:	f9000c3f 	str	xzr, [x1, #24]
    its_send_sync();
    cmd_off += 0x20;
    80201bfc:	11018001 	add	w1, w0, #0x60
    gits->CWRITER = cmd_off;
    80201c00:	f9004487 	str	x7, [x4, #136]
    its.prop_table[pINTID - 8192] = val;
    80201c04:	12800bc7 	mov	w7, #0xffffffa1            	// #-95
    80201c08:	f9400e66 	ldr	x6, [x19, #24]
    its_cmd->cmd[0] = 0x0a;
    80201c0c:	f828484b 	str	x11, [x2, w8, uxtw]
    its_cmd->cmd[2] = 0x00;                 /*Coll ID 0*/
    80201c10:	a900fcaa 	stp	x10, xzr, [x5, #8]

    gits->CWRITER = cmd_off;
    80201c14:	2a0103e8 	mov	w8, w1
    printf("Value of prop 0 is 0x%x\n",its.prop_table[0]);
    80201c18:	f0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    its_cmd->cmd[3] = 0x00;
    80201c1c:	f9000cbf 	str	xzr, [x5, #24]
    printf("Value of prop 0 is 0x%x\n",its.prop_table[0]);
    80201c20:	910f0000 	add	x0, x0, #0x3c0
    its_cmd->cmd[0] = 0x05;
    80201c24:	f8294855 	str	x21, [x2, w9, uxtw]
    its_cmd->cmd[2] = 0x00;
    80201c28:	a900fc7f 	stp	xzr, xzr, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201c2c:	f9000c7f 	str	xzr, [x3, #24]
    cmd_off += 0x20;
    80201c30:	b9002a61 	str	w1, [x19, #40]
    gits->CWRITER = cmd_off;
    80201c34:	f9004488 	str	x8, [x4, #136]
    its.prop_table[pINTID - 8192] = val;
    80201c38:	390000c7 	strb	w7, [x6]
    printf("Value of prop 0 is 0x%x\n",its.prop_table[0]);
    80201c3c:	f9400e61 	ldr	x1, [x19, #24]
    80201c40:	39400021 	ldrb	w1, [x1]
    80201c44:	9400030f 	bl	80202880 <printf>
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201c48:	f9400283 	ldr	x3, [x20]
    its_cmd->cmd[0] = 0x0c;
    80201c4c:	d2800181 	mov	x1, #0xc                   	// #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201c50:	b9402a60 	ldr	w0, [x19, #40]
    its_send_inv();
    cmd_off += 0x20;
    its_send_sync();    //all the ITS operations globally observed
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;
    80201c54:	f9401ec5 	ldr	x5, [x22, #56]
    cmd_off += 0x20;
    80201c58:	11008007 	add	w7, w0, #0x20
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201c5c:	8b204064 	add	x4, x3, w0, uxtw
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201c60:	11008002 	add	w2, w0, #0x20
    its_cmd->cmd[0] = 0x0c;
    80201c64:	f8204861 	str	x1, [x3, w0, uxtw]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201c68:	8b030042 	add	x2, x2, x3
    cmd_off += 0x20;
    80201c6c:	11010006 	add	w6, w0, #0x40

    return 0;
}
    80201c70:	52800000 	mov	w0, #0x0                   	// #0
    its_cmd->cmd[2] = 0x00;
    80201c74:	a900fc9f 	stp	xzr, xzr, [x4, #8]
    its_cmd->cmd[3] = 0x00;
    80201c78:	f9000c9f 	str	xzr, [x4, #24]
    its_cmd->cmd[0] = 0x05;
    80201c7c:	f8274875 	str	x21, [x3, w7, uxtw]
}
    80201c80:	a9425bf5 	ldp	x21, x22, [sp, #32]
    its_cmd->cmd[2] = 0x00;
    80201c84:	a900fc5f 	stp	xzr, xzr, [x2, #8]
    its_cmd->cmd[3] = 0x00;
    80201c88:	f9000c5f 	str	xzr, [x2, #24]
    cmd_off += 0x20;
    80201c8c:	b9002a66 	str	w6, [x19, #40]
    gits->CWRITER = cmd_off;
    80201c90:	f90044a6 	str	x6, [x5, #136]
}
    80201c94:	a94153f3 	ldp	x19, x20, [sp, #16]
    80201c98:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80201c9c:	d65f03c0 	ret

0000000080201ca0 <its_trigger_lpi>:

void its_trigger_lpi(){
    cmd_off = gits->CWRITER;
    80201ca0:	90000080 	adrp	x0, 80211000 <__mprec_tens+0x180>
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201ca4:	f0000165 	adrp	x5, 80230000 <its>
    its_cmd->cmd[0] = 0x03;
    80201ca8:	d2800062 	mov	x2, #0x3                   	// #3
    cmd_off = gits->CWRITER;
    80201cac:	f9401c00 	ldr	x0, [x0, #56]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201cb0:	f94000a6 	ldr	x6, [x5]
    cmd_off = gits->CWRITER;
    80201cb4:	f9404403 	ldr	x3, [x0, #136]
    its_send_int();
    cmd_off += 0x20;
    80201cb8:	11008067 	add	w7, w3, #0x20
    gits->CWRITER = cmd_off;
    80201cbc:	11008064 	add	w4, w3, #0x20
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201cc0:	8b2340c1 	add	x1, x6, w3, uxtw
    its_cmd->cmd[0] = 0x03;
    80201cc4:	f82348c2 	str	x2, [x6, w3, uxtw]
    its_cmd->cmd[2] = 0x00;
    80201cc8:	a900fc3f 	stp	xzr, xzr, [x1, #8]
    its_cmd->cmd[3] = 0x00;
    80201ccc:	f9000c3f 	str	xzr, [x1, #24]
    gits->CWRITER = cmd_off;
    80201cd0:	f9004404 	str	x4, [x0, #136]

    while(gits->CREADR != gits->CWRITER);
    80201cd4:	d503201f 	nop
    80201cd8:	f9404802 	ldr	x2, [x0, #144]
    80201cdc:	f9404401 	ldr	x1, [x0, #136]
    80201ce0:	eb01005f 	cmp	x2, x1
    80201ce4:	54ffffa1 	b.ne	80201cd8 <its_trigger_lpi+0x38>  // b.any
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201ce8:	8b060081 	add	x1, x4, x6

    its_send_sync();
    cmd_off += 0x20;
    80201cec:	910000a5 	add	x5, x5, #0x0
    its_cmd->cmd[0] = 0x05;
    80201cf0:	d28000a2 	mov	x2, #0x5                   	// #5
    80201cf4:	f82748c2 	str	x2, [x6, w7, uxtw]
    cmd_off += 0x20;
    80201cf8:	11010062 	add	w2, w3, #0x40
    its_cmd->cmd[2] = 0x00;
    80201cfc:	a900fc3f 	stp	xzr, xzr, [x1, #8]
    its_cmd->cmd[3] = 0x00;
    80201d00:	f9000c3f 	str	xzr, [x1, #24]
    cmd_off += 0x20;
    80201d04:	b90028a2 	str	w2, [x5, #40]

    gits->CWRITER = cmd_off;
    80201d08:	f9004402 	str	x2, [x0, #136]
}
    80201d0c:	d65f03c0 	ret

0000000080201d10 <its_init>:

int its_init(void){
    80201d10:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!

    int err;

    /*store table addrs in its data structure*/
    its.cmd_queue = (uint64_t)cmd_queue;
    its.device_table = device_table;
    80201d14:	f00002e5 	adrp	x5, 80260000 <device_table>
    its.itt_table = itt_table;
    80201d18:	f0000264 	adrp	x4, 80250000 <itt_table>
int its_init(void){
    80201d1c:	910003fd 	mov	x29, sp
    its.device_table = device_table;
    80201d20:	910000a5 	add	x5, x5, #0x0
    its.itt_table = itt_table;
    80201d24:	91000084 	add	x4, x4, #0x0
    its.prop_table = prop_table;
    80201d28:	f0000203 	adrp	x3, 80244000 <prop_table>
    its.pend_table = pend_table;
    80201d2c:	f00001e2 	adrp	x2, 80240000 <pend_table>
    its.prop_table = prop_table;
    80201d30:	91000063 	add	x3, x3, #0x0
    its.pend_table = pend_table;
    80201d34:	91000042 	add	x2, x2, #0x0
int its_init(void){
    80201d38:	a90153f3 	stp	x19, x20, [sp, #16]
    gits->CTLR &= 0xfffe;
    80201d3c:	90000094 	adrp	x20, 80211000 <__mprec_tens+0x180>
    its.cmd_queue = (uint64_t)cmd_queue;
    80201d40:	f0000361 	adrp	x1, 80270000 <cmd_queue>
int its_init(void){
    80201d44:	f90013f5 	str	x21, [sp, #32]
    its.cmd_queue = (uint64_t)cmd_queue;
    80201d48:	f0000175 	adrp	x21, 80230000 <its>
    80201d4c:	910002b3 	add	x19, x21, #0x0
    80201d50:	91000021 	add	x1, x1, #0x0

    printf("Value of cmd queue addr is 0x%lx",its.cmd_queue);
    80201d54:	f0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80201d58:	910f8000 	add	x0, x0, #0x3e0
    its.device_table = device_table;
    80201d5c:	a9001661 	stp	x1, x5, [x19]
    its.prop_table = prop_table;
    80201d60:	a9010e64 	stp	x4, x3, [x19, #16]
    its.pend_table = pend_table;
    80201d64:	f9001262 	str	x2, [x19, #32]
    printf("Value of cmd queue addr is 0x%lx",its.cmd_queue);
    80201d68:	940002c6 	bl	80202880 <printf>
    gits->CTLR &= 0xfffe;
    80201d6c:	f9401e82 	ldr	x2, [x20, #56]
    gicr_disable_lpi(0);
    80201d70:	52800000 	mov	w0, #0x0                   	// #0
    gits->CTLR &= 0xfffe;
    80201d74:	b9400041 	ldr	w1, [x2]
    80201d78:	121f3821 	and	w1, w1, #0xfffe
    80201d7c:	b9000041 	str	w1, [x2]
    gicr_disable_lpi(0);
    80201d80:	97fffef4 	bl	80201950 <gicr_disable_lpi>
    gits->CBASER = (uint64_t)its.cmd_queue | GITS_BASER_InnerShareable | GITS_BASER_RaWaWb | 0xf;
    80201d84:	f9401e83 	ldr	x3, [x20, #56]
    80201d88:	d28081e1 	mov	x1, #0x40f                 	// #1039
    80201d8c:	f94002a0 	ldr	x0, [x21]
    80201d90:	f2e70001 	movk	x1, #0x3800, lsl #48
            gits->BASER[index] = (uint64_t)its.itt_table | GITS_BASER_InnerShareable | GITS_BASER_RaWaWb;
    80201d94:	f9400a65 	ldr	x5, [x19, #16]
    gits->CBASER = (uint64_t)its.cmd_queue | GITS_BASER_InnerShareable | GITS_BASER_RaWaWb | 0xf;
    80201d98:	aa010000 	orr	x0, x0, x1
    80201d9c:	f9004060 	str	x0, [x3, #128]
            gits->BASER[index] = (uint64_t)its.itt_table | GITS_BASER_InnerShareable | GITS_BASER_RaWaWb;
    80201da0:	d1003c22 	sub	x2, x1, #0xf
    80201da4:	aa0200a5 	orr	x5, x5, x2
        if(bit_extract(gits->BASER[index], GITS_BASER_TYPE_OFF, GITS_BASER_TYPE_LEN) == 0x1) //Equal device table type
    80201da8:	d2e02004 	mov	x4, #0x100000000000000     	// #72057594037927936
    gits->CBASER |= 1ULL << 63; //add valid
    80201dac:	f9404061 	ldr	x1, [x3, #128]
    for (size_t index = 0; index < 8; index++) {
    80201db0:	d2800000 	mov	x0, #0x0                   	// #0
    gits->CBASER |= 1ULL << 63; //add valid
    80201db4:	b2410021 	orr	x1, x1, #0x8000000000000000
    80201db8:	f9004061 	str	x1, [x3, #128]
    for (size_t index = 0; index < 8; index++) {
    80201dbc:	d503201f 	nop
    80201dc0:	8b000c62 	add	x2, x3, x0, lsl #3
    80201dc4:	91000400 	add	x0, x0, #0x1
        if(bit_extract(gits->BASER[index], GITS_BASER_TYPE_OFF, GITS_BASER_TYPE_LEN) == 0x1) //Equal device table type
    80201dc8:	f9408041 	ldr	x1, [x2, #256]
    80201dcc:	92480821 	and	x1, x1, #0x700000000000000
    80201dd0:	eb04003f 	cmp	x1, x4
    80201dd4:	540000a1 	b.ne	80201de8 <its_init+0xd8>  // b.any
            gits->BASER[index] = (uint64_t)its.itt_table | GITS_BASER_InnerShareable | GITS_BASER_RaWaWb;
    80201dd8:	f9008045 	str	x5, [x2, #256]
            gits->BASER[index] |= (1ULL << 63);  //set valid bit
    80201ddc:	f9408041 	ldr	x1, [x2, #256]
    80201de0:	b2410021 	orr	x1, x1, #0x8000000000000000
    80201de4:	f9008041 	str	x1, [x2, #256]
    for (size_t index = 0; index < 8; index++) {
    80201de8:	f100201f 	cmp	x0, #0x8
    80201dec:	54fffea1 	b.ne	80201dc0 <its_init+0xb0>  // b.any
    propbaser = (uint64_t)its.prop_table | GICR_PROPBASER_InnerShareable | GICR_PROPBASER_RaWaWb | lpi_id_bits;
    80201df0:	f9400e62 	ldr	x2, [x19, #24]
    gicr_set_propbaser(propbaser,0);
    80201df4:	52800001 	mov	w1, #0x0                   	// #0
    propbaser = (uint64_t)its.prop_table | GICR_PROPBASER_InnerShareable | GICR_PROPBASER_RaWaWb | lpi_id_bits;
    80201df8:	d280f1e0 	mov	x0, #0x78f                 	// #1935
    gicr_set_propbaser(propbaser,0);
    80201dfc:	aa000040 	orr	x0, x2, x0
    80201e00:	97fffec4 	bl	80201910 <gicr_set_propbaser>
    uint64_t pendbaser = (uint64_t)its.pend_table | GICR_PROPBASER_InnerShareable | GICR_PROPBASER_RaWaWb;
    80201e04:	f9401260 	ldr	x0, [x19, #32]
    gicr_set_pendbaser(pendbaser,0);
    80201e08:	52800001 	mov	w1, #0x0                   	// #0
    80201e0c:	b2790c00 	orr	x0, x0, #0x780
    80201e10:	97fffec8 	bl	80201930 <gicr_set_pendbaser>
    gicr_enable_lpi(0);
    80201e14:	52800000 	mov	w0, #0x0                   	// #0
    80201e18:	97fffed6 	bl	80201970 <gicr_enable_lpi>
    gits->CTLR |= 0x1;
    80201e1c:	f9401e81 	ldr	x1, [x20, #56]
    *ptr = 0x2;
    80201e20:	d2980002 	mov	x2, #0xc000                	// #49152
    80201e24:	f2aa3442 	movk	x2, #0x51a2, lsl #16
    80201e28:	52800043 	mov	w3, #0x2                   	// #2
    gits->CTLR |= 0x1;
    80201e2c:	b9400020 	ldr	w0, [x1]
    80201e30:	32000000 	orr	w0, w0, #0x1
    80201e34:	b9000020 	str	w0, [x1]
    *ptr = 0x2;
    80201e38:	b9000043 	str	w3, [x2]
	its_cpu_init_collections();
    80201e3c:	97ffff29 	bl	80201ae0 <its_cpu_init_collections>
    err = its_cpu_init();
    if(err)
        return err;


    err = its_device_init();
    80201e40:	97ffff54 	bl	80201b90 <its_device_init>
    if(err)
    80201e44:	340000a0 	cbz	w0, 80201e58 <its_init+0x148>
    // printf("Value of trkpidr is 0x%x",*ptr);
    // ptr++;
    // printf("Value of trkvidr is 0x%x",*ptr);

    printf("ITS initialization finished\n");
    80201e48:	a94153f3 	ldp	x19, x20, [sp, #16]
    80201e4c:	f94013f5 	ldr	x21, [sp, #32]
    80201e50:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80201e54:	d65f03c0 	ret
    80201e58:	a94153f3 	ldp	x19, x20, [sp, #16]
    printf("ITS initialization finished\n");
    80201e5c:	f0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80201e60:	f94013f5 	ldr	x21, [sp, #32]
    printf("ITS initialization finished\n");
    80201e64:	91102000 	add	x0, x0, #0x408
    80201e68:	a8c37bfd 	ldp	x29, x30, [sp], #48
    printf("ITS initialization finished\n");
    80201e6c:	140002e1 	b	802029f0 <puts>

0000000080201e70 <lpi_handler>:
//     }
//     return NULL;
// }


void lpi_handler(unsigned id){
    80201e70:	2a0003e1 	mov	w1, w0
    80201e74:	d53800a2 	mrs	x2, mpidr_el1
    printf("LPI %d received by cpu%d: %s\n",id, get_cpuid(), __func__);
    80201e78:	f0000063 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    80201e7c:	92401c42 	and	x2, x2, #0xff
    80201e80:	91200063 	add	x3, x3, #0x800
    80201e84:	f0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80201e88:	9110a000 	add	x0, x0, #0x428
    80201e8c:	1400027d 	b	80202880 <printf>

0000000080201e90 <main>:
}

void main(void){
    80201e90:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    80201e94:	910003fd 	mov	x29, sp
    80201e98:	a90153f3 	stp	x19, x20, [sp, #16]
    80201e9c:	d53800a0 	mrs	x0, mpidr_el1
    80201ea0:	f00003f4 	adrp	x20, 80280000 <gits_lock>
    80201ea4:	91001293 	add	x19, x20, #0x4

    static volatile bool master_done = false;

    if(cpu_is_master()){
    80201ea8:	72001c1f 	tst	w0, #0xff
    80201eac:	54000260 	b.eq	80201ef8 <main+0x68>  // b.none
        //spin_unlock(&print_lock);   

        master_done = true;
    }

    while(!master_done);
    80201eb0:	39401260 	ldrb	w0, [x19, #4]
    80201eb4:	3607ffe0 	tbz	w0, #0, 80201eb0 <main+0x20>
    asm volatile (
    80201eb8:	52800020 	mov	w0, #0x1                   	// #1
    80201ebc:	91001282 	add	x2, x20, #0x4
    80201ec0:	885ffc41 	ldaxr	w1, [x2]
    80201ec4:	35ffffe1 	cbnz	w1, 80201ec0 <main+0x30>
    80201ec8:	88017c40 	stxr	w1, w0, [x2]
    80201ecc:	35ffffa1 	cbnz	w1, 80201ec0 <main+0x30>
    80201ed0:	b9003fe1 	str	w1, [sp, #60]
    80201ed4:	d53800a1 	mrs	x1, mpidr_el1
    spin_lock(&print_lock);
    printf("cpu %d up\n", get_cpuid());
    80201ed8:	f0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80201edc:	92401c21 	and	x1, x1, #0xff
    80201ee0:	91132000 	add	x0, x0, #0x4c8
    80201ee4:	94000267 	bl	80202880 <printf>
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201ee8:	889ffe7f 	stlr	wzr, [x19]
    80201eec:	d503201f 	nop
    80201ef0:	d503207f 	wfi
    spin_unlock(&print_lock);

    while(1) wfi();
    80201ef4:	17ffffff 	b	80201ef0 <main+0x60>
    asm volatile (
    80201ef8:	f90013f5 	str	x21, [sp, #32]
    80201efc:	52800035 	mov	w21, #0x1                   	// #1
    80201f00:	885ffe61 	ldaxr	w1, [x19]
    80201f04:	35ffffe1 	cbnz	w1, 80201f00 <main+0x70>
    80201f08:	88017e75 	stxr	w1, w21, [x19]
    80201f0c:	35ffffa1 	cbnz	w1, 80201f00 <main+0x70>
         printf("Bao bare-metal test guest1\n");
    80201f10:	f0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80201f14:	91112000 	add	x0, x0, #0x448
    80201f18:	b9003be1 	str	w1, [sp, #56]
    80201f1c:	940002b5 	bl	802029f0 <puts>
         printf("Bao bare-metal test guest2\n");
    80201f20:	f0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80201f24:	9111a000 	add	x0, x0, #0x468
    80201f28:	940002b2 	bl	802029f0 <puts>
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201f2c:	889ffe7f 	stlr	wzr, [x19]
        irq_set_handler(8192, lpi_handler);
    80201f30:	90000001 	adrp	x1, 80201000 <gicd_set_icfgr+0x50>
    80201f34:	9139c021 	add	x1, x1, #0xe70
    80201f38:	52840000 	mov	w0, #0x2000                	// #8192
    80201f3c:	97fffa31 	bl	80200800 <irq_set_handler>
        printf("Baremetal: Before trigger LPI\n");
    80201f40:	f0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80201f44:	91122000 	add	x0, x0, #0x488
    80201f48:	940002aa 	bl	802029f0 <puts>
        its_trigger_lpi();
    80201f4c:	97ffff55 	bl	80201ca0 <its_trigger_lpi>
        printf("Baremetal: After trigger LPI\n");
    80201f50:	f0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80201f54:	9112a000 	add	x0, x0, #0x4a8
    80201f58:	940002a6 	bl	802029f0 <puts>
        master_done = true;
    80201f5c:	39001275 	strb	w21, [x19, #4]
    80201f60:	f94013f5 	ldr	x21, [sp, #32]
    80201f64:	17ffffd3 	b	80201eb0 <main+0x20>
	...

0000000080202000 <_exception_vector>:
/* 
 * EL1 with SP0
 */  
.balign ENTRY_SIZE
curr_el_sp0_sync:        
    b	.
    80202000:	14000000 	b	80202000 <_exception_vector>
    80202004:	d503201f 	nop
    80202008:	d503201f 	nop
    8020200c:	d503201f 	nop
    80202010:	d503201f 	nop
    80202014:	d503201f 	nop
    80202018:	d503201f 	nop
    8020201c:	d503201f 	nop
    80202020:	d503201f 	nop
    80202024:	d503201f 	nop
    80202028:	d503201f 	nop
    8020202c:	d503201f 	nop
    80202030:	d503201f 	nop
    80202034:	d503201f 	nop
    80202038:	d503201f 	nop
    8020203c:	d503201f 	nop
    80202040:	d503201f 	nop
    80202044:	d503201f 	nop
    80202048:	d503201f 	nop
    8020204c:	d503201f 	nop
    80202050:	d503201f 	nop
    80202054:	d503201f 	nop
    80202058:	d503201f 	nop
    8020205c:	d503201f 	nop
    80202060:	d503201f 	nop
    80202064:	d503201f 	nop
    80202068:	d503201f 	nop
    8020206c:	d503201f 	nop
    80202070:	d503201f 	nop
    80202074:	d503201f 	nop
    80202078:	d503201f 	nop
    8020207c:	d503201f 	nop

0000000080202080 <curr_el_sp0_irq>:
.balign ENTRY_SIZE
curr_el_sp0_irq:  
    b   .
    80202080:	14000000 	b	80202080 <curr_el_sp0_irq>
    80202084:	d503201f 	nop
    80202088:	d503201f 	nop
    8020208c:	d503201f 	nop
    80202090:	d503201f 	nop
    80202094:	d503201f 	nop
    80202098:	d503201f 	nop
    8020209c:	d503201f 	nop
    802020a0:	d503201f 	nop
    802020a4:	d503201f 	nop
    802020a8:	d503201f 	nop
    802020ac:	d503201f 	nop
    802020b0:	d503201f 	nop
    802020b4:	d503201f 	nop
    802020b8:	d503201f 	nop
    802020bc:	d503201f 	nop
    802020c0:	d503201f 	nop
    802020c4:	d503201f 	nop
    802020c8:	d503201f 	nop
    802020cc:	d503201f 	nop
    802020d0:	d503201f 	nop
    802020d4:	d503201f 	nop
    802020d8:	d503201f 	nop
    802020dc:	d503201f 	nop
    802020e0:	d503201f 	nop
    802020e4:	d503201f 	nop
    802020e8:	d503201f 	nop
    802020ec:	d503201f 	nop
    802020f0:	d503201f 	nop
    802020f4:	d503201f 	nop
    802020f8:	d503201f 	nop
    802020fc:	d503201f 	nop

0000000080202100 <curr_el_sp0_fiq>:
.balign ENTRY_SIZE
curr_el_sp0_fiq:         
    b	.
    80202100:	14000000 	b	80202100 <curr_el_sp0_fiq>
    80202104:	d503201f 	nop
    80202108:	d503201f 	nop
    8020210c:	d503201f 	nop
    80202110:	d503201f 	nop
    80202114:	d503201f 	nop
    80202118:	d503201f 	nop
    8020211c:	d503201f 	nop
    80202120:	d503201f 	nop
    80202124:	d503201f 	nop
    80202128:	d503201f 	nop
    8020212c:	d503201f 	nop
    80202130:	d503201f 	nop
    80202134:	d503201f 	nop
    80202138:	d503201f 	nop
    8020213c:	d503201f 	nop
    80202140:	d503201f 	nop
    80202144:	d503201f 	nop
    80202148:	d503201f 	nop
    8020214c:	d503201f 	nop
    80202150:	d503201f 	nop
    80202154:	d503201f 	nop
    80202158:	d503201f 	nop
    8020215c:	d503201f 	nop
    80202160:	d503201f 	nop
    80202164:	d503201f 	nop
    80202168:	d503201f 	nop
    8020216c:	d503201f 	nop
    80202170:	d503201f 	nop
    80202174:	d503201f 	nop
    80202178:	d503201f 	nop
    8020217c:	d503201f 	nop

0000000080202180 <curr_el_sp0_serror>:
.balign ENTRY_SIZE
curr_el_sp0_serror:      
    b	.
    80202180:	14000000 	b	80202180 <curr_el_sp0_serror>
    80202184:	d503201f 	nop
    80202188:	d503201f 	nop
    8020218c:	d503201f 	nop
    80202190:	d503201f 	nop
    80202194:	d503201f 	nop
    80202198:	d503201f 	nop
    8020219c:	d503201f 	nop
    802021a0:	d503201f 	nop
    802021a4:	d503201f 	nop
    802021a8:	d503201f 	nop
    802021ac:	d503201f 	nop
    802021b0:	d503201f 	nop
    802021b4:	d503201f 	nop
    802021b8:	d503201f 	nop
    802021bc:	d503201f 	nop
    802021c0:	d503201f 	nop
    802021c4:	d503201f 	nop
    802021c8:	d503201f 	nop
    802021cc:	d503201f 	nop
    802021d0:	d503201f 	nop
    802021d4:	d503201f 	nop
    802021d8:	d503201f 	nop
    802021dc:	d503201f 	nop
    802021e0:	d503201f 	nop
    802021e4:	d503201f 	nop
    802021e8:	d503201f 	nop
    802021ec:	d503201f 	nop
    802021f0:	d503201f 	nop
    802021f4:	d503201f 	nop
    802021f8:	d503201f 	nop
    802021fc:	d503201f 	nop

0000000080202200 <curr_el_spx_sync>:
/* 
 * EL1 with SPx
 */  
.balign ENTRY_SIZE  
curr_el_spx_sync:        
    b	.
    80202200:	14000000 	b	80202200 <curr_el_spx_sync>
    80202204:	d503201f 	nop
    80202208:	d503201f 	nop
    8020220c:	d503201f 	nop
    80202210:	d503201f 	nop
    80202214:	d503201f 	nop
    80202218:	d503201f 	nop
    8020221c:	d503201f 	nop
    80202220:	d503201f 	nop
    80202224:	d503201f 	nop
    80202228:	d503201f 	nop
    8020222c:	d503201f 	nop
    80202230:	d503201f 	nop
    80202234:	d503201f 	nop
    80202238:	d503201f 	nop
    8020223c:	d503201f 	nop
    80202240:	d503201f 	nop
    80202244:	d503201f 	nop
    80202248:	d503201f 	nop
    8020224c:	d503201f 	nop
    80202250:	d503201f 	nop
    80202254:	d503201f 	nop
    80202258:	d503201f 	nop
    8020225c:	d503201f 	nop
    80202260:	d503201f 	nop
    80202264:	d503201f 	nop
    80202268:	d503201f 	nop
    8020226c:	d503201f 	nop
    80202270:	d503201f 	nop
    80202274:	d503201f 	nop
    80202278:	d503201f 	nop
    8020227c:	d503201f 	nop

0000000080202280 <curr_el_spx_irq>:
.balign ENTRY_SIZE
curr_el_spx_irq:       
    SAVE_REGS
    80202280:	d102c3ff 	sub	sp, sp, #0xb0
    80202284:	a90007e0 	stp	x0, x1, [sp]
    80202288:	a9010fe2 	stp	x2, x3, [sp, #16]
    8020228c:	a90217e4 	stp	x4, x5, [sp, #32]
    80202290:	a9031fe6 	stp	x6, x7, [sp, #48]
    80202294:	a90427e8 	stp	x8, x9, [sp, #64]
    80202298:	a9052fea 	stp	x10, x11, [sp, #80]
    8020229c:	a90637ec 	stp	x12, x13, [sp, #96]
    802022a0:	a9073fee 	stp	x14, x15, [sp, #112]
    802022a4:	a90847f0 	stp	x16, x17, [sp, #128]
    802022a8:	a9094ff2 	stp	x18, x19, [sp, #144]
    802022ac:	a90a7bfd 	stp	x29, x30, [sp, #160]
    bl	gic_handle
    802022b0:	97fffb10 	bl	80200ef0 <gic_handle>
    RESTORE_REGS
    802022b4:	a94007e0 	ldp	x0, x1, [sp]
    802022b8:	a9410fe2 	ldp	x2, x3, [sp, #16]
    802022bc:	a94217e4 	ldp	x4, x5, [sp, #32]
    802022c0:	a9431fe6 	ldp	x6, x7, [sp, #48]
    802022c4:	a94427e8 	ldp	x8, x9, [sp, #64]
    802022c8:	a9452fea 	ldp	x10, x11, [sp, #80]
    802022cc:	a94637ec 	ldp	x12, x13, [sp, #96]
    802022d0:	a9473fee 	ldp	x14, x15, [sp, #112]
    802022d4:	a94847f0 	ldp	x16, x17, [sp, #128]
    802022d8:	a9494ff2 	ldp	x18, x19, [sp, #144]
    802022dc:	a94a7bfd 	ldp	x29, x30, [sp, #160]
    802022e0:	9102c3ff 	add	sp, sp, #0xb0
    eret
    802022e4:	d69f03e0 	eret
    802022e8:	d503201f 	nop
    802022ec:	d503201f 	nop
    802022f0:	d503201f 	nop
    802022f4:	d503201f 	nop
    802022f8:	d503201f 	nop
    802022fc:	d503201f 	nop

0000000080202300 <curr_el_spx_fiq>:
.balign ENTRY_SIZE
curr_el_spx_fiq:         
    SAVE_REGS
    80202300:	d102c3ff 	sub	sp, sp, #0xb0
    80202304:	a90007e0 	stp	x0, x1, [sp]
    80202308:	a9010fe2 	stp	x2, x3, [sp, #16]
    8020230c:	a90217e4 	stp	x4, x5, [sp, #32]
    80202310:	a9031fe6 	stp	x6, x7, [sp, #48]
    80202314:	a90427e8 	stp	x8, x9, [sp, #64]
    80202318:	a9052fea 	stp	x10, x11, [sp, #80]
    8020231c:	a90637ec 	stp	x12, x13, [sp, #96]
    80202320:	a9073fee 	stp	x14, x15, [sp, #112]
    80202324:	a90847f0 	stp	x16, x17, [sp, #128]
    80202328:	a9094ff2 	stp	x18, x19, [sp, #144]
    8020232c:	a90a7bfd 	stp	x29, x30, [sp, #160]
    bl	gic_handle
    80202330:	97fffaf0 	bl	80200ef0 <gic_handle>
    RESTORE_REGS
    80202334:	a94007e0 	ldp	x0, x1, [sp]
    80202338:	a9410fe2 	ldp	x2, x3, [sp, #16]
    8020233c:	a94217e4 	ldp	x4, x5, [sp, #32]
    80202340:	a9431fe6 	ldp	x6, x7, [sp, #48]
    80202344:	a94427e8 	ldp	x8, x9, [sp, #64]
    80202348:	a9452fea 	ldp	x10, x11, [sp, #80]
    8020234c:	a94637ec 	ldp	x12, x13, [sp, #96]
    80202350:	a9473fee 	ldp	x14, x15, [sp, #112]
    80202354:	a94847f0 	ldp	x16, x17, [sp, #128]
    80202358:	a9494ff2 	ldp	x18, x19, [sp, #144]
    8020235c:	a94a7bfd 	ldp	x29, x30, [sp, #160]
    80202360:	9102c3ff 	add	sp, sp, #0xb0
    eret
    80202364:	d69f03e0 	eret
    80202368:	d503201f 	nop
    8020236c:	d503201f 	nop
    80202370:	d503201f 	nop
    80202374:	d503201f 	nop
    80202378:	d503201f 	nop
    8020237c:	d503201f 	nop

0000000080202380 <curr_el_spx_serror>:
.balign ENTRY_SIZE
curr_el_spx_serror:      
    b	.         
    80202380:	14000000 	b	80202380 <curr_el_spx_serror>
    80202384:	d503201f 	nop
    80202388:	d503201f 	nop
    8020238c:	d503201f 	nop
    80202390:	d503201f 	nop
    80202394:	d503201f 	nop
    80202398:	d503201f 	nop
    8020239c:	d503201f 	nop
    802023a0:	d503201f 	nop
    802023a4:	d503201f 	nop
    802023a8:	d503201f 	nop
    802023ac:	d503201f 	nop
    802023b0:	d503201f 	nop
    802023b4:	d503201f 	nop
    802023b8:	d503201f 	nop
    802023bc:	d503201f 	nop
    802023c0:	d503201f 	nop
    802023c4:	d503201f 	nop
    802023c8:	d503201f 	nop
    802023cc:	d503201f 	nop
    802023d0:	d503201f 	nop
    802023d4:	d503201f 	nop
    802023d8:	d503201f 	nop
    802023dc:	d503201f 	nop
    802023e0:	d503201f 	nop
    802023e4:	d503201f 	nop
    802023e8:	d503201f 	nop
    802023ec:	d503201f 	nop
    802023f0:	d503201f 	nop
    802023f4:	d503201f 	nop
    802023f8:	d503201f 	nop
    802023fc:	d503201f 	nop

0000000080202400 <lower_el_aarch64_sync>:
 * Lower EL using AArch64
 */  

.balign ENTRY_SIZE
lower_el_aarch64_sync:
    b .
    80202400:	14000000 	b	80202400 <lower_el_aarch64_sync>
    80202404:	d503201f 	nop
    80202408:	d503201f 	nop
    8020240c:	d503201f 	nop
    80202410:	d503201f 	nop
    80202414:	d503201f 	nop
    80202418:	d503201f 	nop
    8020241c:	d503201f 	nop
    80202420:	d503201f 	nop
    80202424:	d503201f 	nop
    80202428:	d503201f 	nop
    8020242c:	d503201f 	nop
    80202430:	d503201f 	nop
    80202434:	d503201f 	nop
    80202438:	d503201f 	nop
    8020243c:	d503201f 	nop
    80202440:	d503201f 	nop
    80202444:	d503201f 	nop
    80202448:	d503201f 	nop
    8020244c:	d503201f 	nop
    80202450:	d503201f 	nop
    80202454:	d503201f 	nop
    80202458:	d503201f 	nop
    8020245c:	d503201f 	nop
    80202460:	d503201f 	nop
    80202464:	d503201f 	nop
    80202468:	d503201f 	nop
    8020246c:	d503201f 	nop
    80202470:	d503201f 	nop
    80202474:	d503201f 	nop
    80202478:	d503201f 	nop
    8020247c:	d503201f 	nop

0000000080202480 <lower_el_aarch64_irq>:
.balign ENTRY_SIZE
lower_el_aarch64_irq:    
    b .
    80202480:	14000000 	b	80202480 <lower_el_aarch64_irq>
    80202484:	d503201f 	nop
    80202488:	d503201f 	nop
    8020248c:	d503201f 	nop
    80202490:	d503201f 	nop
    80202494:	d503201f 	nop
    80202498:	d503201f 	nop
    8020249c:	d503201f 	nop
    802024a0:	d503201f 	nop
    802024a4:	d503201f 	nop
    802024a8:	d503201f 	nop
    802024ac:	d503201f 	nop
    802024b0:	d503201f 	nop
    802024b4:	d503201f 	nop
    802024b8:	d503201f 	nop
    802024bc:	d503201f 	nop
    802024c0:	d503201f 	nop
    802024c4:	d503201f 	nop
    802024c8:	d503201f 	nop
    802024cc:	d503201f 	nop
    802024d0:	d503201f 	nop
    802024d4:	d503201f 	nop
    802024d8:	d503201f 	nop
    802024dc:	d503201f 	nop
    802024e0:	d503201f 	nop
    802024e4:	d503201f 	nop
    802024e8:	d503201f 	nop
    802024ec:	d503201f 	nop
    802024f0:	d503201f 	nop
    802024f4:	d503201f 	nop
    802024f8:	d503201f 	nop
    802024fc:	d503201f 	nop

0000000080202500 <lower_el_aarch64_fiq>:
.balign ENTRY_SIZE
lower_el_aarch64_fiq:    
    b	.
    80202500:	14000000 	b	80202500 <lower_el_aarch64_fiq>
    80202504:	d503201f 	nop
    80202508:	d503201f 	nop
    8020250c:	d503201f 	nop
    80202510:	d503201f 	nop
    80202514:	d503201f 	nop
    80202518:	d503201f 	nop
    8020251c:	d503201f 	nop
    80202520:	d503201f 	nop
    80202524:	d503201f 	nop
    80202528:	d503201f 	nop
    8020252c:	d503201f 	nop
    80202530:	d503201f 	nop
    80202534:	d503201f 	nop
    80202538:	d503201f 	nop
    8020253c:	d503201f 	nop
    80202540:	d503201f 	nop
    80202544:	d503201f 	nop
    80202548:	d503201f 	nop
    8020254c:	d503201f 	nop
    80202550:	d503201f 	nop
    80202554:	d503201f 	nop
    80202558:	d503201f 	nop
    8020255c:	d503201f 	nop
    80202560:	d503201f 	nop
    80202564:	d503201f 	nop
    80202568:	d503201f 	nop
    8020256c:	d503201f 	nop
    80202570:	d503201f 	nop
    80202574:	d503201f 	nop
    80202578:	d503201f 	nop
    8020257c:	d503201f 	nop

0000000080202580 <lower_el_aarch64_serror>:
.balign ENTRY_SIZE
lower_el_aarch64_serror: 
    b	.          
    80202580:	14000000 	b	80202580 <lower_el_aarch64_serror>
    80202584:	d503201f 	nop
    80202588:	d503201f 	nop
    8020258c:	d503201f 	nop
    80202590:	d503201f 	nop
    80202594:	d503201f 	nop
    80202598:	d503201f 	nop
    8020259c:	d503201f 	nop
    802025a0:	d503201f 	nop
    802025a4:	d503201f 	nop
    802025a8:	d503201f 	nop
    802025ac:	d503201f 	nop
    802025b0:	d503201f 	nop
    802025b4:	d503201f 	nop
    802025b8:	d503201f 	nop
    802025bc:	d503201f 	nop
    802025c0:	d503201f 	nop
    802025c4:	d503201f 	nop
    802025c8:	d503201f 	nop
    802025cc:	d503201f 	nop
    802025d0:	d503201f 	nop
    802025d4:	d503201f 	nop
    802025d8:	d503201f 	nop
    802025dc:	d503201f 	nop
    802025e0:	d503201f 	nop
    802025e4:	d503201f 	nop
    802025e8:	d503201f 	nop
    802025ec:	d503201f 	nop
    802025f0:	d503201f 	nop
    802025f4:	d503201f 	nop
    802025f8:	d503201f 	nop
    802025fc:	d503201f 	nop

0000000080202600 <lower_el_aarch32_sync>:
/* 
 * Lower EL using AArch32
 */  
.balign ENTRY_SIZE   
lower_el_aarch32_sync:   
    b	.
    80202600:	14000000 	b	80202600 <lower_el_aarch32_sync>
    80202604:	d503201f 	nop
    80202608:	d503201f 	nop
    8020260c:	d503201f 	nop
    80202610:	d503201f 	nop
    80202614:	d503201f 	nop
    80202618:	d503201f 	nop
    8020261c:	d503201f 	nop
    80202620:	d503201f 	nop
    80202624:	d503201f 	nop
    80202628:	d503201f 	nop
    8020262c:	d503201f 	nop
    80202630:	d503201f 	nop
    80202634:	d503201f 	nop
    80202638:	d503201f 	nop
    8020263c:	d503201f 	nop
    80202640:	d503201f 	nop
    80202644:	d503201f 	nop
    80202648:	d503201f 	nop
    8020264c:	d503201f 	nop
    80202650:	d503201f 	nop
    80202654:	d503201f 	nop
    80202658:	d503201f 	nop
    8020265c:	d503201f 	nop
    80202660:	d503201f 	nop
    80202664:	d503201f 	nop
    80202668:	d503201f 	nop
    8020266c:	d503201f 	nop
    80202670:	d503201f 	nop
    80202674:	d503201f 	nop
    80202678:	d503201f 	nop
    8020267c:	d503201f 	nop

0000000080202680 <lower_el_aarch32_irq>:
.balign ENTRY_SIZE
lower_el_aarch32_irq:    
    b	.
    80202680:	14000000 	b	80202680 <lower_el_aarch32_irq>
    80202684:	d503201f 	nop
    80202688:	d503201f 	nop
    8020268c:	d503201f 	nop
    80202690:	d503201f 	nop
    80202694:	d503201f 	nop
    80202698:	d503201f 	nop
    8020269c:	d503201f 	nop
    802026a0:	d503201f 	nop
    802026a4:	d503201f 	nop
    802026a8:	d503201f 	nop
    802026ac:	d503201f 	nop
    802026b0:	d503201f 	nop
    802026b4:	d503201f 	nop
    802026b8:	d503201f 	nop
    802026bc:	d503201f 	nop
    802026c0:	d503201f 	nop
    802026c4:	d503201f 	nop
    802026c8:	d503201f 	nop
    802026cc:	d503201f 	nop
    802026d0:	d503201f 	nop
    802026d4:	d503201f 	nop
    802026d8:	d503201f 	nop
    802026dc:	d503201f 	nop
    802026e0:	d503201f 	nop
    802026e4:	d503201f 	nop
    802026e8:	d503201f 	nop
    802026ec:	d503201f 	nop
    802026f0:	d503201f 	nop
    802026f4:	d503201f 	nop
    802026f8:	d503201f 	nop
    802026fc:	d503201f 	nop

0000000080202700 <lower_el_aarch32_fiq>:
.balign ENTRY_SIZE
lower_el_aarch32_fiq:    
    b	.
    80202700:	14000000 	b	80202700 <lower_el_aarch32_fiq>
    80202704:	d503201f 	nop
    80202708:	d503201f 	nop
    8020270c:	d503201f 	nop
    80202710:	d503201f 	nop
    80202714:	d503201f 	nop
    80202718:	d503201f 	nop
    8020271c:	d503201f 	nop
    80202720:	d503201f 	nop
    80202724:	d503201f 	nop
    80202728:	d503201f 	nop
    8020272c:	d503201f 	nop
    80202730:	d503201f 	nop
    80202734:	d503201f 	nop
    80202738:	d503201f 	nop
    8020273c:	d503201f 	nop
    80202740:	d503201f 	nop
    80202744:	d503201f 	nop
    80202748:	d503201f 	nop
    8020274c:	d503201f 	nop
    80202750:	d503201f 	nop
    80202754:	d503201f 	nop
    80202758:	d503201f 	nop
    8020275c:	d503201f 	nop
    80202760:	d503201f 	nop
    80202764:	d503201f 	nop
    80202768:	d503201f 	nop
    8020276c:	d503201f 	nop
    80202770:	d503201f 	nop
    80202774:	d503201f 	nop
    80202778:	d503201f 	nop
    8020277c:	d503201f 	nop

0000000080202780 <lower_el_aarch32_serror>:
.balign ENTRY_SIZE
lower_el_aarch32_serror: 
    b	.
    80202780:	14000000 	b	80202780 <lower_el_aarch32_serror>
    80202784:	d503201f 	nop
    80202788:	d503201f 	nop
    8020278c:	d503201f 	nop
    80202790:	d503201f 	nop
    80202794:	d503201f 	nop
    80202798:	d503201f 	nop
    8020279c:	d503201f 	nop
    802027a0:	d503201f 	nop
    802027a4:	d503201f 	nop
    802027a8:	d503201f 	nop
    802027ac:	d503201f 	nop
    802027b0:	d503201f 	nop
    802027b4:	d503201f 	nop
    802027b8:	d503201f 	nop
    802027bc:	d503201f 	nop
    802027c0:	d503201f 	nop
    802027c4:	d503201f 	nop
    802027c8:	d503201f 	nop
    802027cc:	d503201f 	nop
    802027d0:	d503201f 	nop
    802027d4:	d503201f 	nop
    802027d8:	d503201f 	nop
    802027dc:	d503201f 	nop
    802027e0:	d503201f 	nop
    802027e4:	d503201f 	nop
    802027e8:	d503201f 	nop
    802027ec:	d503201f 	nop
    802027f0:	d503201f 	nop
    802027f4:	d503201f 	nop
    802027f8:	d503201f 	nop
    802027fc:	d503201f 	nop

0000000080202800 <__errno>:
    80202800:	f0000060 	adrp	x0, 80211000 <__mprec_tens+0x180>
    80202804:	f9402400 	ldr	x0, [x0, #72]
    80202808:	d65f03c0 	ret
    8020280c:	00000000 	udf	#0

0000000080202810 <_printf_r>:
    80202810:	a9b07bfd 	stp	x29, x30, [sp, #-256]!
    80202814:	128005e9 	mov	w9, #0xffffffd0            	// #-48
    80202818:	12800fe8 	mov	w8, #0xffffff80            	// #-128
    8020281c:	910003fd 	mov	x29, sp
    80202820:	910343ea 	add	x10, sp, #0xd0
    80202824:	910403eb 	add	x11, sp, #0x100
    80202828:	a9032feb 	stp	x11, x11, [sp, #48]
    8020282c:	f90023ea 	str	x10, [sp, #64]
    80202830:	290923e9 	stp	w9, w8, [sp, #72]
    80202834:	3d8017e0 	str	q0, [sp, #80]
    80202838:	ad41c3e0 	ldp	q0, q16, [sp, #48]
    8020283c:	3d801be1 	str	q1, [sp, #96]
    80202840:	3d801fe2 	str	q2, [sp, #112]
    80202844:	3d8023e3 	str	q3, [sp, #128]
    80202848:	3d8027e4 	str	q4, [sp, #144]
    8020284c:	3d802be5 	str	q5, [sp, #160]
    80202850:	3d802fe6 	str	q6, [sp, #176]
    80202854:	3d8033e7 	str	q7, [sp, #192]
    80202858:	a90d0fe2 	stp	x2, x3, [sp, #208]
    8020285c:	aa0103e2 	mov	x2, x1
    80202860:	910043e3 	add	x3, sp, #0x10
    80202864:	a90e17e4 	stp	x4, x5, [sp, #224]
    80202868:	a90f1fe6 	stp	x6, x7, [sp, #240]
    8020286c:	ad00c3e0 	stp	q0, q16, [sp, #16]
    80202870:	f9400801 	ldr	x1, [x0, #16]
    80202874:	940003e3 	bl	80203800 <_vfprintf_r>
    80202878:	a8d07bfd 	ldp	x29, x30, [sp], #256
    8020287c:	d65f03c0 	ret

0000000080202880 <printf>:
    80202880:	a9af7bfd 	stp	x29, x30, [sp, #-272]!
    80202884:	128006eb 	mov	w11, #0xffffffc8            	// #-56
    80202888:	12800fea 	mov	w10, #0xffffff80            	// #-128
    8020288c:	910003fd 	mov	x29, sp
    80202890:	910343ec 	add	x12, sp, #0xd0
    80202894:	910443e8 	add	x8, sp, #0x110
    80202898:	f0000069 	adrp	x9, 80211000 <__mprec_tens+0x180>
    8020289c:	a90323e8 	stp	x8, x8, [sp, #48]
    802028a0:	aa0003e8 	mov	x8, x0
    802028a4:	f90023ec 	str	x12, [sp, #64]
    802028a8:	29092beb 	stp	w11, w10, [sp, #72]
    802028ac:	f9402520 	ldr	x0, [x9, #72]
    802028b0:	3d8017e0 	str	q0, [sp, #80]
    802028b4:	ad41c3e0 	ldp	q0, q16, [sp, #48]
    802028b8:	3d801be1 	str	q1, [sp, #96]
    802028bc:	3d801fe2 	str	q2, [sp, #112]
    802028c0:	3d8023e3 	str	q3, [sp, #128]
    802028c4:	3d8027e4 	str	q4, [sp, #144]
    802028c8:	3d802be5 	str	q5, [sp, #160]
    802028cc:	3d802fe6 	str	q6, [sp, #176]
    802028d0:	3d8033e7 	str	q7, [sp, #192]
    802028d4:	a90d8be1 	stp	x1, x2, [sp, #216]
    802028d8:	aa0803e2 	mov	x2, x8
    802028dc:	a90e93e3 	stp	x3, x4, [sp, #232]
    802028e0:	910043e3 	add	x3, sp, #0x10
    802028e4:	a90f9be5 	stp	x5, x6, [sp, #248]
    802028e8:	f90087e7 	str	x7, [sp, #264]
    802028ec:	ad00c3e0 	stp	q0, q16, [sp, #16]
    802028f0:	f9400801 	ldr	x1, [x0, #16]
    802028f4:	940003c3 	bl	80203800 <_vfprintf_r>
    802028f8:	a8d17bfd 	ldp	x29, x30, [sp], #272
    802028fc:	d65f03c0 	ret

0000000080202900 <_puts_r>:
    80202900:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    80202904:	910003fd 	mov	x29, sp
    80202908:	a90153f3 	stp	x19, x20, [sp, #16]
    8020290c:	aa0003f4 	mov	x20, x0
    80202910:	aa0103f3 	mov	x19, x1
    80202914:	aa0103e0 	mov	x0, x1
    80202918:	940001fa 	bl	80203100 <strlen>
    8020291c:	f9402682 	ldr	x2, [x20, #72]
    80202920:	91000404 	add	x4, x0, #0x1
    80202924:	910103e6 	add	x6, sp, #0x40
    80202928:	d0000061 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020292c:	d2800023 	mov	x3, #0x1                   	// #1
    80202930:	91136021 	add	x1, x1, #0x4d8
    80202934:	52800045 	mov	w5, #0x2                   	// #2
    80202938:	f90017e6 	str	x6, [sp, #40]
    8020293c:	b90033e5 	str	w5, [sp, #48]
    80202940:	a903cfe4 	stp	x4, x19, [sp, #56]
    80202944:	a90487e0 	stp	x0, x1, [sp, #72]
    80202948:	f9002fe3 	str	x3, [sp, #88]
    8020294c:	f9400a93 	ldr	x19, [x20, #16]
    80202950:	b4000482 	cbz	x2, 802029e0 <_puts_r+0xe0>
    80202954:	b940b261 	ldr	w1, [x19, #176]
    80202958:	79c02260 	ldrsh	w0, [x19, #16]
    8020295c:	37000041 	tbnz	w1, #0, 80202964 <_puts_r+0x64>
    80202960:	36480380 	tbz	w0, #9, 802029d0 <_puts_r+0xd0>
    80202964:	376800c0 	tbnz	w0, #13, 8020297c <_puts_r+0x7c>
    80202968:	b940b261 	ldr	w1, [x19, #176]
    8020296c:	32130000 	orr	w0, w0, #0x2000
    80202970:	79002260 	strh	w0, [x19, #16]
    80202974:	12127820 	and	w0, w1, #0xffffdfff
    80202978:	b900b260 	str	w0, [x19, #176]
    8020297c:	aa1403e0 	mov	x0, x20
    80202980:	aa1303e1 	mov	x1, x19
    80202984:	9100a3e2 	add	x2, sp, #0x28
    80202988:	9400022a 	bl	80203230 <__sfvwrite_r>
    8020298c:	b940b261 	ldr	w1, [x19, #176]
    80202990:	7100001f 	cmp	w0, #0x0
    80202994:	52800154 	mov	w20, #0xa                   	// #10
    80202998:	5a9f0294 	csinv	w20, w20, wzr, eq	// eq = none
    8020299c:	37000061 	tbnz	w1, #0, 802029a8 <_puts_r+0xa8>
    802029a0:	79402260 	ldrh	w0, [x19, #16]
    802029a4:	364800a0 	tbz	w0, #9, 802029b8 <_puts_r+0xb8>
    802029a8:	2a1403e0 	mov	w0, w20
    802029ac:	a94153f3 	ldp	x19, x20, [sp, #16]
    802029b0:	a8c67bfd 	ldp	x29, x30, [sp], #96
    802029b4:	d65f03c0 	ret
    802029b8:	f9405260 	ldr	x0, [x19, #160]
    802029bc:	94001a91 	bl	80209400 <__retarget_lock_release_recursive>
    802029c0:	2a1403e0 	mov	w0, w20
    802029c4:	a94153f3 	ldp	x19, x20, [sp, #16]
    802029c8:	a8c67bfd 	ldp	x29, x30, [sp], #96
    802029cc:	d65f03c0 	ret
    802029d0:	f9405260 	ldr	x0, [x19, #160]
    802029d4:	94001a7b 	bl	802093c0 <__retarget_lock_acquire_recursive>
    802029d8:	79c02260 	ldrsh	w0, [x19, #16]
    802029dc:	17ffffe2 	b	80202964 <_puts_r+0x64>
    802029e0:	aa1403e0 	mov	x0, x20
    802029e4:	940000fb 	bl	80202dd0 <__sinit>
    802029e8:	17ffffdb 	b	80202954 <_puts_r+0x54>
    802029ec:	00000000 	udf	#0

00000000802029f0 <puts>:
    802029f0:	f0000062 	adrp	x2, 80211000 <__mprec_tens+0x180>
    802029f4:	aa0003e1 	mov	x1, x0
    802029f8:	f9402440 	ldr	x0, [x2, #72]
    802029fc:	17ffffc1 	b	80202900 <_puts_r>

0000000080202a00 <stdio_exit_handler>:
    80202a00:	f0000062 	adrp	x2, 80211000 <__mprec_tens+0x180>
    80202a04:	90000041 	adrp	x1, 8020a000 <_setlocale_r+0x310>
    80202a08:	9106a042 	add	x2, x2, #0x1a8
    80202a0c:	91040021 	add	x1, x1, #0x100
    80202a10:	f0000060 	adrp	x0, 80211000 <__mprec_tens+0x180>
    80202a14:	91014000 	add	x0, x0, #0x50
    80202a18:	1400033a 	b	80203700 <_fwalk_sglue>
    80202a1c:	00000000 	udf	#0

0000000080202a20 <cleanup_stdio>:
    80202a20:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80202a24:	d00003e2 	adrp	x2, 80280000 <gits_lock>
    80202a28:	91004042 	add	x2, x2, #0x10
    80202a2c:	910003fd 	mov	x29, sp
    80202a30:	f9400401 	ldr	x1, [x0, #8]
    80202a34:	f9000bf3 	str	x19, [sp, #16]
    80202a38:	aa0003f3 	mov	x19, x0
    80202a3c:	eb02003f 	cmp	x1, x2
    80202a40:	54000040 	b.eq	80202a48 <cleanup_stdio+0x28>  // b.none
    80202a44:	94001daf 	bl	8020a100 <_fclose_r>
    80202a48:	f9400a61 	ldr	x1, [x19, #16]
    80202a4c:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202a50:	91032000 	add	x0, x0, #0xc8
    80202a54:	eb00003f 	cmp	x1, x0
    80202a58:	54000060 	b.eq	80202a64 <cleanup_stdio+0x44>  // b.none
    80202a5c:	aa1303e0 	mov	x0, x19
    80202a60:	94001da8 	bl	8020a100 <_fclose_r>
    80202a64:	f9400e61 	ldr	x1, [x19, #24]
    80202a68:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202a6c:	91060000 	add	x0, x0, #0x180
    80202a70:	eb00003f 	cmp	x1, x0
    80202a74:	540000a0 	b.eq	80202a88 <cleanup_stdio+0x68>  // b.none
    80202a78:	aa1303e0 	mov	x0, x19
    80202a7c:	f9400bf3 	ldr	x19, [sp, #16]
    80202a80:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80202a84:	14001d9f 	b	8020a100 <_fclose_r>
    80202a88:	f9400bf3 	ldr	x19, [sp, #16]
    80202a8c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80202a90:	d65f03c0 	ret
	...

0000000080202aa0 <__fp_lock>:
    80202aa0:	b940b020 	ldr	w0, [x1, #176]
    80202aa4:	37000060 	tbnz	w0, #0, 80202ab0 <__fp_lock+0x10>
    80202aa8:	79402020 	ldrh	w0, [x1, #16]
    80202aac:	36480060 	tbz	w0, #9, 80202ab8 <__fp_lock+0x18>
    80202ab0:	52800000 	mov	w0, #0x0                   	// #0
    80202ab4:	d65f03c0 	ret
    80202ab8:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80202abc:	910003fd 	mov	x29, sp
    80202ac0:	f9405020 	ldr	x0, [x1, #160]
    80202ac4:	94001a3f 	bl	802093c0 <__retarget_lock_acquire_recursive>
    80202ac8:	52800000 	mov	w0, #0x0                   	// #0
    80202acc:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80202ad0:	d65f03c0 	ret
	...

0000000080202ae0 <__fp_unlock>:
    80202ae0:	b940b020 	ldr	w0, [x1, #176]
    80202ae4:	37000060 	tbnz	w0, #0, 80202af0 <__fp_unlock+0x10>
    80202ae8:	79402020 	ldrh	w0, [x1, #16]
    80202aec:	36480060 	tbz	w0, #9, 80202af8 <__fp_unlock+0x18>
    80202af0:	52800000 	mov	w0, #0x0                   	// #0
    80202af4:	d65f03c0 	ret
    80202af8:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80202afc:	910003fd 	mov	x29, sp
    80202b00:	f9405020 	ldr	x0, [x1, #160]
    80202b04:	94001a3f 	bl	80209400 <__retarget_lock_release_recursive>
    80202b08:	52800000 	mov	w0, #0x0                   	// #0
    80202b0c:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80202b10:	d65f03c0 	ret
	...

0000000080202b20 <global_stdio_init.part.0>:
    80202b20:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    80202b24:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202b28:	d00003e2 	adrp	x2, 80280000 <gits_lock>
    80202b2c:	910003fd 	mov	x29, sp
    80202b30:	a90153f3 	stp	x19, x20, [sp, #16]
    80202b34:	91004013 	add	x19, x0, #0x10
    80202b38:	52800083 	mov	w3, #0x4                   	// #4
    80202b3c:	90000001 	adrp	x1, 80202000 <_exception_vector>
    80202b40:	91280021 	add	x1, x1, #0xa00
    80202b44:	f9011c41 	str	x1, [x2, #568]
    80202b48:	d2800102 	mov	x2, #0x8                   	// #8
    80202b4c:	52800001 	mov	w1, #0x0                   	// #0
    80202b50:	a9025bf5 	stp	x21, x22, [sp, #32]
    80202b54:	b0000014 	adrp	x20, 80203000 <__sread+0x30>
    80202b58:	f9001bf7 	str	x23, [sp, #48]
    80202b5c:	9103c294 	add	x20, x20, #0xf0
    80202b60:	f900081f 	str	xzr, [x0, #16]
    80202b64:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202b68:	9102e000 	add	x0, x0, #0xb8
    80202b6c:	f900067f 	str	xzr, [x19, #8]
    80202b70:	b9001263 	str	w3, [x19, #16]
    80202b74:	b0000016 	adrp	x22, 80203000 <__sread+0x30>
    80202b78:	f9000e7f 	str	xzr, [x19, #24]
    80202b7c:	9100c2d6 	add	x22, x22, #0x30
    80202b80:	b900227f 	str	wzr, [x19, #32]
    80202b84:	b0000015 	adrp	x21, 80203000 <__sread+0x30>
    80202b88:	b9002a7f 	str	wzr, [x19, #40]
    80202b8c:	910282b5 	add	x21, x21, #0xa0
    80202b90:	b900b27f 	str	wzr, [x19, #176]
    80202b94:	940000cb 	bl	80202ec0 <memset>
    80202b98:	90000017 	adrp	x23, 80202000 <_exception_vector>
    80202b9c:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202ba0:	913f42f7 	add	x23, x23, #0xfd0
    80202ba4:	9102c000 	add	x0, x0, #0xb0
    80202ba8:	a9035e73 	stp	x19, x23, [x19, #48]
    80202bac:	a9045676 	stp	x22, x21, [x19, #64]
    80202bb0:	f9002a74 	str	x20, [x19, #80]
    80202bb4:	940019f3 	bl	80209380 <__retarget_lock_init_recursive>
    80202bb8:	52800123 	mov	w3, #0x9                   	// #9
    80202bbc:	d2800102 	mov	x2, #0x8                   	// #8
    80202bc0:	72a00023 	movk	w3, #0x1, lsl #16
    80202bc4:	52800001 	mov	w1, #0x0                   	// #0
    80202bc8:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202bcc:	9105c000 	add	x0, x0, #0x170
    80202bd0:	f9005e7f 	str	xzr, [x19, #184]
    80202bd4:	f900627f 	str	xzr, [x19, #192]
    80202bd8:	b900ca63 	str	w3, [x19, #200]
    80202bdc:	f9006a7f 	str	xzr, [x19, #208]
    80202be0:	b900da7f 	str	wzr, [x19, #216]
    80202be4:	b900e27f 	str	wzr, [x19, #224]
    80202be8:	b9016a7f 	str	wzr, [x19, #360]
    80202bec:	940000b5 	bl	80202ec0 <memset>
    80202bf0:	d00003e1 	adrp	x1, 80280000 <gits_lock>
    80202bf4:	91032021 	add	x1, x1, #0xc8
    80202bf8:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202bfc:	9105a000 	add	x0, x0, #0x168
    80202c00:	a90ede61 	stp	x1, x23, [x19, #232]
    80202c04:	a90fd676 	stp	x22, x21, [x19, #248]
    80202c08:	f9008674 	str	x20, [x19, #264]
    80202c0c:	940019dd 	bl	80209380 <__retarget_lock_init_recursive>
    80202c10:	52800243 	mov	w3, #0x12                  	// #18
    80202c14:	d2800102 	mov	x2, #0x8                   	// #8
    80202c18:	72a00043 	movk	w3, #0x2, lsl #16
    80202c1c:	52800001 	mov	w1, #0x0                   	// #0
    80202c20:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202c24:	9108a000 	add	x0, x0, #0x228
    80202c28:	f900ba7f 	str	xzr, [x19, #368]
    80202c2c:	f900be7f 	str	xzr, [x19, #376]
    80202c30:	b9018263 	str	w3, [x19, #384]
    80202c34:	f900c67f 	str	xzr, [x19, #392]
    80202c38:	b901927f 	str	wzr, [x19, #400]
    80202c3c:	b9019a7f 	str	wzr, [x19, #408]
    80202c40:	b902227f 	str	wzr, [x19, #544]
    80202c44:	9400009f 	bl	80202ec0 <memset>
    80202c48:	d00003e1 	adrp	x1, 80280000 <gits_lock>
    80202c4c:	91060021 	add	x1, x1, #0x180
    80202c50:	a91a5e61 	stp	x1, x23, [x19, #416]
    80202c54:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202c58:	91088000 	add	x0, x0, #0x220
    80202c5c:	a91b5676 	stp	x22, x21, [x19, #432]
    80202c60:	f900e274 	str	x20, [x19, #448]
    80202c64:	a94153f3 	ldp	x19, x20, [sp, #16]
    80202c68:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80202c6c:	f9401bf7 	ldr	x23, [sp, #48]
    80202c70:	a8c47bfd 	ldp	x29, x30, [sp], #64
    80202c74:	140019c3 	b	80209380 <__retarget_lock_init_recursive>
	...

0000000080202c80 <__sfp>:
    80202c80:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    80202c84:	910003fd 	mov	x29, sp
    80202c88:	a9025bf5 	stp	x21, x22, [sp, #32]
    80202c8c:	d00003f5 	adrp	x21, 80280000 <gits_lock>
    80202c90:	910ae2b5 	add	x21, x21, #0x2b8
    80202c94:	aa0003f6 	mov	x22, x0
    80202c98:	aa1503e0 	mov	x0, x21
    80202c9c:	a90153f3 	stp	x19, x20, [sp, #16]
    80202ca0:	f9001bf7 	str	x23, [sp, #48]
    80202ca4:	940019c7 	bl	802093c0 <__retarget_lock_acquire_recursive>
    80202ca8:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202cac:	f9411c00 	ldr	x0, [x0, #568]
    80202cb0:	b40007a0 	cbz	x0, 80202da4 <__sfp+0x124>
    80202cb4:	f0000074 	adrp	x20, 80211000 <__mprec_tens+0x180>
    80202cb8:	9106a294 	add	x20, x20, #0x1a8
    80202cbc:	52801717 	mov	w23, #0xb8                  	// #184
    80202cc0:	b9400a82 	ldr	w2, [x20, #8]
    80202cc4:	f9400a93 	ldr	x19, [x20, #16]
    80202cc8:	7100005f 	cmp	w2, #0x0
    80202ccc:	5400044d 	b.le	80202d54 <__sfp+0xd4>
    80202cd0:	9bb74c42 	umaddl	x2, w2, w23, x19
    80202cd4:	14000004 	b	80202ce4 <__sfp+0x64>
    80202cd8:	9102e273 	add	x19, x19, #0xb8
    80202cdc:	eb13005f 	cmp	x2, x19
    80202ce0:	540003a0 	b.eq	80202d54 <__sfp+0xd4>  // b.none
    80202ce4:	79c02261 	ldrsh	w1, [x19, #16]
    80202ce8:	35ffff81 	cbnz	w1, 80202cd8 <__sfp+0x58>
    80202cec:	129fffc0 	mov	w0, #0xffff0001            	// #-65535
    80202cf0:	b9001260 	str	w0, [x19, #16]
    80202cf4:	b900b27f 	str	wzr, [x19, #176]
    80202cf8:	91028260 	add	x0, x19, #0xa0
    80202cfc:	940019a1 	bl	80209380 <__retarget_lock_init_recursive>
    80202d00:	aa1503e0 	mov	x0, x21
    80202d04:	940019bf 	bl	80209400 <__retarget_lock_release_recursive>
    80202d08:	f900027f 	str	xzr, [x19]
    80202d0c:	9102a260 	add	x0, x19, #0xa8
    80202d10:	f900067f 	str	xzr, [x19, #8]
    80202d14:	d2800102 	mov	x2, #0x8                   	// #8
    80202d18:	f9000e7f 	str	xzr, [x19, #24]
    80202d1c:	52800001 	mov	w1, #0x0                   	// #0
    80202d20:	b900227f 	str	wzr, [x19, #32]
    80202d24:	b9002a7f 	str	wzr, [x19, #40]
    80202d28:	94000066 	bl	80202ec0 <memset>
    80202d2c:	f9002e7f 	str	xzr, [x19, #88]
    80202d30:	b900627f 	str	wzr, [x19, #96]
    80202d34:	f9003e7f 	str	xzr, [x19, #120]
    80202d38:	b900827f 	str	wzr, [x19, #128]
    80202d3c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80202d40:	aa1303e0 	mov	x0, x19
    80202d44:	a94153f3 	ldp	x19, x20, [sp, #16]
    80202d48:	f9401bf7 	ldr	x23, [sp, #48]
    80202d4c:	a8c47bfd 	ldp	x29, x30, [sp], #64
    80202d50:	d65f03c0 	ret
    80202d54:	f9400293 	ldr	x19, [x20]
    80202d58:	b4000073 	cbz	x19, 80202d64 <__sfp+0xe4>
    80202d5c:	aa1303f4 	mov	x20, x19
    80202d60:	17ffffd8 	b	80202cc0 <__sfp+0x40>
    80202d64:	aa1603e0 	mov	x0, x22
    80202d68:	d2805f01 	mov	x1, #0x2f8                 	// #760
    80202d6c:	94001735 	bl	80208a40 <_malloc_r>
    80202d70:	aa0003f3 	mov	x19, x0
    80202d74:	b40001c0 	cbz	x0, 80202dac <__sfp+0x12c>
    80202d78:	91006000 	add	x0, x0, #0x18
    80202d7c:	52800081 	mov	w1, #0x4                   	// #4
    80202d80:	f900027f 	str	xzr, [x19]
    80202d84:	d2805c02 	mov	x2, #0x2e0                 	// #736
    80202d88:	b9000a61 	str	w1, [x19, #8]
    80202d8c:	52800001 	mov	w1, #0x0                   	// #0
    80202d90:	f9000a60 	str	x0, [x19, #16]
    80202d94:	9400004b 	bl	80202ec0 <memset>
    80202d98:	f9000293 	str	x19, [x20]
    80202d9c:	aa1303f4 	mov	x20, x19
    80202da0:	17ffffc8 	b	80202cc0 <__sfp+0x40>
    80202da4:	97ffff5f 	bl	80202b20 <global_stdio_init.part.0>
    80202da8:	17ffffc3 	b	80202cb4 <__sfp+0x34>
    80202dac:	f900029f 	str	xzr, [x20]
    80202db0:	aa1503e0 	mov	x0, x21
    80202db4:	94001993 	bl	80209400 <__retarget_lock_release_recursive>
    80202db8:	52800180 	mov	w0, #0xc                   	// #12
    80202dbc:	b90002c0 	str	w0, [x22]
    80202dc0:	17ffffdf 	b	80202d3c <__sfp+0xbc>
	...

0000000080202dd0 <__sinit>:
    80202dd0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80202dd4:	910003fd 	mov	x29, sp
    80202dd8:	a90153f3 	stp	x19, x20, [sp, #16]
    80202ddc:	aa0003f4 	mov	x20, x0
    80202de0:	d00003f3 	adrp	x19, 80280000 <gits_lock>
    80202de4:	910ae273 	add	x19, x19, #0x2b8
    80202de8:	aa1303e0 	mov	x0, x19
    80202dec:	94001975 	bl	802093c0 <__retarget_lock_acquire_recursive>
    80202df0:	f9402680 	ldr	x0, [x20, #72]
    80202df4:	b50000e0 	cbnz	x0, 80202e10 <__sinit+0x40>
    80202df8:	d00003e1 	adrp	x1, 80280000 <gits_lock>
    80202dfc:	90000000 	adrp	x0, 80202000 <_exception_vector>
    80202e00:	91288000 	add	x0, x0, #0xa20
    80202e04:	f9002680 	str	x0, [x20, #72]
    80202e08:	f9411c20 	ldr	x0, [x1, #568]
    80202e0c:	b40000a0 	cbz	x0, 80202e20 <__sinit+0x50>
    80202e10:	aa1303e0 	mov	x0, x19
    80202e14:	a94153f3 	ldp	x19, x20, [sp, #16]
    80202e18:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80202e1c:	14001979 	b	80209400 <__retarget_lock_release_recursive>
    80202e20:	97ffff40 	bl	80202b20 <global_stdio_init.part.0>
    80202e24:	aa1303e0 	mov	x0, x19
    80202e28:	a94153f3 	ldp	x19, x20, [sp, #16]
    80202e2c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80202e30:	14001974 	b	80209400 <__retarget_lock_release_recursive>
	...

0000000080202e40 <__sfp_lock_acquire>:
    80202e40:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202e44:	910ae000 	add	x0, x0, #0x2b8
    80202e48:	1400195e 	b	802093c0 <__retarget_lock_acquire_recursive>
    80202e4c:	00000000 	udf	#0

0000000080202e50 <__sfp_lock_release>:
    80202e50:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202e54:	910ae000 	add	x0, x0, #0x2b8
    80202e58:	1400196a 	b	80209400 <__retarget_lock_release_recursive>
    80202e5c:	00000000 	udf	#0

0000000080202e60 <__fp_lock_all>:
    80202e60:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80202e64:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202e68:	910ae000 	add	x0, x0, #0x2b8
    80202e6c:	910003fd 	mov	x29, sp
    80202e70:	94001954 	bl	802093c0 <__retarget_lock_acquire_recursive>
    80202e74:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80202e78:	f0000062 	adrp	x2, 80211000 <__mprec_tens+0x180>
    80202e7c:	90000001 	adrp	x1, 80202000 <_exception_vector>
    80202e80:	9106a042 	add	x2, x2, #0x1a8
    80202e84:	912a8021 	add	x1, x1, #0xaa0
    80202e88:	d2800000 	mov	x0, #0x0                   	// #0
    80202e8c:	1400021d 	b	80203700 <_fwalk_sglue>

0000000080202e90 <__fp_unlock_all>:
    80202e90:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80202e94:	f0000062 	adrp	x2, 80211000 <__mprec_tens+0x180>
    80202e98:	90000001 	adrp	x1, 80202000 <_exception_vector>
    80202e9c:	910003fd 	mov	x29, sp
    80202ea0:	9106a042 	add	x2, x2, #0x1a8
    80202ea4:	912b8021 	add	x1, x1, #0xae0
    80202ea8:	d2800000 	mov	x0, #0x0                   	// #0
    80202eac:	94000215 	bl	80203700 <_fwalk_sglue>
    80202eb0:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80202eb4:	d00003e0 	adrp	x0, 80280000 <gits_lock>
    80202eb8:	910ae000 	add	x0, x0, #0x2b8
    80202ebc:	14001951 	b	80209400 <__retarget_lock_release_recursive>

0000000080202ec0 <memset>:
    80202ec0:	d503245f 	bti	c
    80202ec4:	4e010c20 	dup	v0.16b, w1
    80202ec8:	8b020004 	add	x4, x0, x2
    80202ecc:	f101805f 	cmp	x2, #0x60
    80202ed0:	54000388 	b.hi	80202f40 <memset+0x80>  // b.pmore
    80202ed4:	f100405f 	cmp	x2, #0x10
    80202ed8:	540001e2 	b.cs	80202f14 <memset+0x54>  // b.hs, b.nlast
    80202edc:	4e083c01 	mov	x1, v0.d[0]
    80202ee0:	36180082 	tbz	w2, #3, 80202ef0 <memset+0x30>
    80202ee4:	f9000001 	str	x1, [x0]
    80202ee8:	f81f8081 	stur	x1, [x4, #-8]
    80202eec:	d65f03c0 	ret
    80202ef0:	36100082 	tbz	w2, #2, 80202f00 <memset+0x40>
    80202ef4:	b9000001 	str	w1, [x0]
    80202ef8:	b81fc081 	stur	w1, [x4, #-4]
    80202efc:	d65f03c0 	ret
    80202f00:	b4000082 	cbz	x2, 80202f10 <memset+0x50>
    80202f04:	39000001 	strb	w1, [x0]
    80202f08:	36080042 	tbz	w2, #1, 80202f10 <memset+0x50>
    80202f0c:	781fe081 	sturh	w1, [x4, #-2]
    80202f10:	d65f03c0 	ret
    80202f14:	3d800000 	str	q0, [x0]
    80202f18:	373000c2 	tbnz	w2, #6, 80202f30 <memset+0x70>
    80202f1c:	3c9f0080 	stur	q0, [x4, #-16]
    80202f20:	36280062 	tbz	w2, #5, 80202f2c <memset+0x6c>
    80202f24:	3d800400 	str	q0, [x0, #16]
    80202f28:	3c9e0080 	stur	q0, [x4, #-32]
    80202f2c:	d65f03c0 	ret
    80202f30:	3d800400 	str	q0, [x0, #16]
    80202f34:	ad010000 	stp	q0, q0, [x0, #32]
    80202f38:	ad3f0080 	stp	q0, q0, [x4, #-32]
    80202f3c:	d65f03c0 	ret
    80202f40:	12001c21 	and	w1, w1, #0xff
    80202f44:	927cec03 	and	x3, x0, #0xfffffffffffffff0
    80202f48:	3d800000 	str	q0, [x0]
    80202f4c:	f102805f 	cmp	x2, #0xa0
    80202f50:	7a402820 	ccmp	w1, #0x0, #0x0, cs	// cs = hs, nlast
    80202f54:	54000241 	b.ne	80202f9c <memset+0xdc>  // b.any
    80202f58:	d53b00e5 	mrs	x5, dczid_el0
    80202f5c:	924010a5 	and	x5, x5, #0x1f
    80202f60:	f10010bf 	cmp	x5, #0x4
    80202f64:	540001c1 	b.ne	80202f9c <memset+0xdc>  // b.any
    80202f68:	3d800460 	str	q0, [x3, #16]
    80202f6c:	ad010060 	stp	q0, q0, [x3, #32]
    80202f70:	927ae463 	and	x3, x3, #0xffffffffffffffc0
    80202f74:	cb030082 	sub	x2, x4, x3
    80202f78:	d1020042 	sub	x2, x2, #0x80
    80202f7c:	d503201f 	nop
    80202f80:	91010063 	add	x3, x3, #0x40
    80202f84:	d50b7423 	dc	zva, x3
    80202f88:	f1010042 	subs	x2, x2, #0x40
    80202f8c:	54ffffa8 	b.hi	80202f80 <memset+0xc0>  // b.pmore
    80202f90:	ad3e0080 	stp	q0, q0, [x4, #-64]
    80202f94:	ad3f0080 	stp	q0, q0, [x4, #-32]
    80202f98:	d65f03c0 	ret
    80202f9c:	cb030082 	sub	x2, x4, x3
    80202fa0:	d1004063 	sub	x3, x3, #0x10
    80202fa4:	d1014042 	sub	x2, x2, #0x50
    80202fa8:	ad010060 	stp	q0, q0, [x3, #32]
    80202fac:	ad820060 	stp	q0, q0, [x3, #64]!
    80202fb0:	f1010042 	subs	x2, x2, #0x40
    80202fb4:	54ffffa8 	b.hi	80202fa8 <memset+0xe8>  // b.pmore
    80202fb8:	ad3e0080 	stp	q0, q0, [x4, #-64]
    80202fbc:	ad3f0080 	stp	q0, q0, [x4, #-32]
    80202fc0:	d65f03c0 	ret
	...

0000000080202fd0 <__sread>:
    80202fd0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80202fd4:	93407c63 	sxtw	x3, w3
    80202fd8:	910003fd 	mov	x29, sp
    80202fdc:	f9000bf3 	str	x19, [sp, #16]
    80202fe0:	aa0103f3 	mov	x19, x1
    80202fe4:	79c02421 	ldrsh	w1, [x1, #18]
    80202fe8:	94002822 	bl	8020d070 <_read_r>
    80202fec:	b7f800e0 	tbnz	x0, #63, 80203008 <__sread+0x38>
    80202ff0:	f9404a61 	ldr	x1, [x19, #144]
    80202ff4:	8b000021 	add	x1, x1, x0
    80202ff8:	f9004a61 	str	x1, [x19, #144]
    80202ffc:	f9400bf3 	ldr	x19, [sp, #16]
    80203000:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80203004:	d65f03c0 	ret
    80203008:	79402261 	ldrh	w1, [x19, #16]
    8020300c:	12137821 	and	w1, w1, #0xffffefff
    80203010:	79002261 	strh	w1, [x19, #16]
    80203014:	f9400bf3 	ldr	x19, [sp, #16]
    80203018:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020301c:	d65f03c0 	ret

0000000080203020 <__seofread>:
    80203020:	52800000 	mov	w0, #0x0                   	// #0
    80203024:	d65f03c0 	ret
	...

0000000080203030 <__swrite>:
    80203030:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80203034:	910003fd 	mov	x29, sp
    80203038:	79c02024 	ldrsh	w4, [x1, #16]
    8020303c:	a90153f3 	stp	x19, x20, [sp, #16]
    80203040:	aa0103f3 	mov	x19, x1
    80203044:	aa0003f4 	mov	x20, x0
    80203048:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020304c:	aa0203f5 	mov	x21, x2
    80203050:	2a0303f6 	mov	w22, w3
    80203054:	37400184 	tbnz	w4, #8, 80203084 <__swrite+0x54>
    80203058:	79c02661 	ldrsh	w1, [x19, #18]
    8020305c:	12137884 	and	w4, w4, #0xffffefff
    80203060:	79002264 	strh	w4, [x19, #16]
    80203064:	93407ec3 	sxtw	x3, w22
    80203068:	aa1503e2 	mov	x2, x21
    8020306c:	aa1403e0 	mov	x0, x20
    80203070:	940001cc 	bl	802037a0 <_write_r>
    80203074:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203078:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020307c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80203080:	d65f03c0 	ret
    80203084:	79c02421 	ldrsh	w1, [x1, #18]
    80203088:	52800043 	mov	w3, #0x2                   	// #2
    8020308c:	d2800002 	mov	x2, #0x0                   	// #0
    80203090:	940027e0 	bl	8020d010 <_lseek_r>
    80203094:	79c02264 	ldrsh	w4, [x19, #16]
    80203098:	17fffff0 	b	80203058 <__swrite+0x28>
    8020309c:	00000000 	udf	#0

00000000802030a0 <__sseek>:
    802030a0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    802030a4:	910003fd 	mov	x29, sp
    802030a8:	f9000bf3 	str	x19, [sp, #16]
    802030ac:	aa0103f3 	mov	x19, x1
    802030b0:	79c02421 	ldrsh	w1, [x1, #18]
    802030b4:	940027d7 	bl	8020d010 <_lseek_r>
    802030b8:	79c02261 	ldrsh	w1, [x19, #16]
    802030bc:	b100041f 	cmn	x0, #0x1
    802030c0:	540000e0 	b.eq	802030dc <__sseek+0x3c>  // b.none
    802030c4:	32140021 	orr	w1, w1, #0x1000
    802030c8:	79002261 	strh	w1, [x19, #16]
    802030cc:	f9004a60 	str	x0, [x19, #144]
    802030d0:	f9400bf3 	ldr	x19, [sp, #16]
    802030d4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802030d8:	d65f03c0 	ret
    802030dc:	12137821 	and	w1, w1, #0xffffefff
    802030e0:	79002261 	strh	w1, [x19, #16]
    802030e4:	f9400bf3 	ldr	x19, [sp, #16]
    802030e8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802030ec:	d65f03c0 	ret

00000000802030f0 <__sclose>:
    802030f0:	79c02421 	ldrsh	w1, [x1, #18]
    802030f4:	140022df 	b	8020bc70 <_close_r>
	...

0000000080203100 <strlen>:
    80203100:	d503245f 	bti	c
    80203104:	92402c04 	and	x4, x0, #0xfff
    80203108:	f13f809f 	cmp	x4, #0xfe0
    8020310c:	540006c8 	b.hi	802031e4 <strlen+0xe4>  // b.pmore
    80203110:	a9400c02 	ldp	x2, x3, [x0]
    80203114:	b200c3e8 	mov	x8, #0x101010101010101     	// #72340172838076673
    80203118:	cb080044 	sub	x4, x2, x8
    8020311c:	b200d845 	orr	x5, x2, #0x7f7f7f7f7f7f7f7f
    80203120:	cb080066 	sub	x6, x3, x8
    80203124:	b200d867 	orr	x7, x3, #0x7f7f7f7f7f7f7f7f
    80203128:	ea250084 	bics	x4, x4, x5
    8020312c:	8a2700c5 	bic	x5, x6, x7
    80203130:	fa4008a0 	ccmp	x5, #0x0, #0x0, eq	// eq = none
    80203134:	54000100 	b.eq	80203154 <strlen+0x54>  // b.none
    80203138:	9a853084 	csel	x4, x4, x5, cc	// cc = lo, ul, last
    8020313c:	d2800100 	mov	x0, #0x8                   	// #8
    80203140:	dac00c84 	rev	x4, x4
    80203144:	9a8033e0 	csel	x0, xzr, x0, cc	// cc = lo, ul, last
    80203148:	dac01084 	clz	x4, x4
    8020314c:	8b440c00 	add	x0, x0, x4, lsr #3
    80203150:	d65f03c0 	ret
    80203154:	a9410c02 	ldp	x2, x3, [x0, #16]
    80203158:	cb080044 	sub	x4, x2, x8
    8020315c:	b200d845 	orr	x5, x2, #0x7f7f7f7f7f7f7f7f
    80203160:	cb080066 	sub	x6, x3, x8
    80203164:	b200d867 	orr	x7, x3, #0x7f7f7f7f7f7f7f7f
    80203168:	ea250084 	bics	x4, x4, x5
    8020316c:	8a2700c5 	bic	x5, x6, x7
    80203170:	fa4008a0 	ccmp	x5, #0x0, #0x0, eq	// eq = none
    80203174:	54000140 	b.eq	8020319c <strlen+0x9c>  // b.none
    80203178:	9a853084 	csel	x4, x4, x5, cc	// cc = lo, ul, last
    8020317c:	d2800300 	mov	x0, #0x18                  	// #24
    80203180:	dac00c84 	rev	x4, x4
    80203184:	d2800206 	mov	x6, #0x10                  	// #16
    80203188:	dac01084 	clz	x4, x4
    8020318c:	9a8030c0 	csel	x0, x6, x0, cc	// cc = lo, ul, last
    80203190:	8b440c00 	add	x0, x0, x4, lsr #3
    80203194:	d65f03c0 	ret
    80203198:	d503201f 	nop
    8020319c:	927be801 	and	x1, x0, #0xffffffffffffffe0
    802031a0:	adc10821 	ldp	q1, q2, [x1, #32]!
    802031a4:	6e22ac20 	uminp	v0.16b, v1.16b, v2.16b
    802031a8:	6e20ac00 	uminp	v0.16b, v0.16b, v0.16b
    802031ac:	0e209800 	cmeq	v0.8b, v0.8b, #0
    802031b0:	9e660003 	fmov	x3, d0
    802031b4:	b4ffff63 	cbz	x3, 802031a0 <strlen+0xa0>
    802031b8:	4e209820 	cmeq	v0.16b, v1.16b, #0
    802031bc:	cb000020 	sub	x0, x1, x0
    802031c0:	35000063 	cbnz	w3, 802031cc <strlen+0xcc>
    802031c4:	4e209840 	cmeq	v0.16b, v2.16b, #0
    802031c8:	91004000 	add	x0, x0, #0x10
    802031cc:	0f0c8400 	shrn	v0.8b, v0.8h, #4
    802031d0:	9e660003 	fmov	x3, d0
    802031d4:	dac00063 	rbit	x3, x3
    802031d8:	dac01062 	clz	x2, x3
    802031dc:	8b420800 	add	x0, x0, x2, lsr #2
    802031e0:	d65f03c0 	ret
    802031e4:	927be801 	and	x1, x0, #0xffffffffffffffe0
    802031e8:	52818062 	mov	w2, #0xc03                 	// #3075
    802031ec:	72b80602 	movk	w2, #0xc030, lsl #16
    802031f0:	4c40a021 	ld1	{v1.16b-v2.16b}, [x1]
    802031f4:	4e040c40 	dup	v0.4s, w2
    802031f8:	4e209821 	cmeq	v1.16b, v1.16b, #0
    802031fc:	4e209842 	cmeq	v2.16b, v2.16b, #0
    80203200:	4e201c21 	and	v1.16b, v1.16b, v0.16b
    80203204:	4e201c42 	and	v2.16b, v2.16b, v0.16b
    80203208:	4e22bc20 	addp	v0.16b, v1.16b, v2.16b
    8020320c:	4e20bc00 	addp	v0.16b, v0.16b, v0.16b
    80203210:	9e660003 	fmov	x3, d0
    80203214:	d37ff804 	lsl	x4, x0, #1
    80203218:	9ac42463 	lsr	x3, x3, x4
    8020321c:	b4fffc23 	cbz	x3, 802031a0 <strlen+0xa0>
    80203220:	dac00063 	rbit	x3, x3
    80203224:	dac01060 	clz	x0, x3
    80203228:	d341fc00 	lsr	x0, x0, #1
    8020322c:	d65f03c0 	ret

0000000080203230 <__sfvwrite_r>:
    80203230:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    80203234:	910003fd 	mov	x29, sp
    80203238:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020323c:	aa0003f5 	mov	x21, x0
    80203240:	f9400840 	ldr	x0, [x2, #16]
    80203244:	b4000ac0 	cbz	x0, 8020339c <__sfvwrite_r+0x16c>
    80203248:	79c02025 	ldrsh	w5, [x1, #16]
    8020324c:	a90153f3 	stp	x19, x20, [sp, #16]
    80203250:	aa0103f3 	mov	x19, x1
    80203254:	a90573fb 	stp	x27, x28, [sp, #80]
    80203258:	aa0203fb 	mov	x27, x2
    8020325c:	36180a85 	tbz	w5, #3, 802033ac <__sfvwrite_r+0x17c>
    80203260:	f9400c20 	ldr	x0, [x1, #24]
    80203264:	b4000a40 	cbz	x0, 802033ac <__sfvwrite_r+0x17c>
    80203268:	a90363f7 	stp	x23, x24, [sp, #48]
    8020326c:	f9400374 	ldr	x20, [x27]
    80203270:	360803e5 	tbz	w5, #1, 802032ec <__sfvwrite_r+0xbc>
    80203274:	f9401a61 	ldr	x1, [x19, #48]
    80203278:	d2800017 	mov	x23, #0x0                   	// #0
    8020327c:	f9402264 	ldr	x4, [x19, #64]
    80203280:	d2800016 	mov	x22, #0x0                   	// #0
    80203284:	b27653f8 	mov	x24, #0x7ffffc00            	// #2147482624
    80203288:	eb1802df 	cmp	x22, x24
    8020328c:	aa1703e2 	mov	x2, x23
    80203290:	9a9892c3 	csel	x3, x22, x24, ls	// ls = plast
    80203294:	aa1503e0 	mov	x0, x21
    80203298:	b4000256 	cbz	x22, 802032e0 <__sfvwrite_r+0xb0>
    8020329c:	d63f0080 	blr	x4
    802032a0:	7100001f 	cmp	w0, #0x0
    802032a4:	5400216d 	b.le	802036d0 <__sfvwrite_r+0x4a0>
    802032a8:	f9400b61 	ldr	x1, [x27, #16]
    802032ac:	93407c00 	sxtw	x0, w0
    802032b0:	8b0002f7 	add	x23, x23, x0
    802032b4:	cb0002d6 	sub	x22, x22, x0
    802032b8:	cb000020 	sub	x0, x1, x0
    802032bc:	f9000b60 	str	x0, [x27, #16]
    802032c0:	b40020c0 	cbz	x0, 802036d8 <__sfvwrite_r+0x4a8>
    802032c4:	eb1802df 	cmp	x22, x24
    802032c8:	aa1703e2 	mov	x2, x23
    802032cc:	f9401a61 	ldr	x1, [x19, #48]
    802032d0:	9a9892c3 	csel	x3, x22, x24, ls	// ls = plast
    802032d4:	f9402264 	ldr	x4, [x19, #64]
    802032d8:	aa1503e0 	mov	x0, x21
    802032dc:	b5fffe16 	cbnz	x22, 8020329c <__sfvwrite_r+0x6c>
    802032e0:	a9405a97 	ldp	x23, x22, [x20]
    802032e4:	91004294 	add	x20, x20, #0x10
    802032e8:	17ffffe8 	b	80203288 <__sfvwrite_r+0x58>
    802032ec:	a9046bf9 	stp	x25, x26, [sp, #64]
    802032f0:	36000a65 	tbz	w5, #0, 8020343c <__sfvwrite_r+0x20c>
    802032f4:	52800018 	mov	w24, #0x0                   	// #0
    802032f8:	52800000 	mov	w0, #0x0                   	// #0
    802032fc:	d280001a 	mov	x26, #0x0                   	// #0
    80203300:	d2800019 	mov	x25, #0x0                   	// #0
    80203304:	d503201f 	nop
    80203308:	b40007f9 	cbz	x25, 80203404 <__sfvwrite_r+0x1d4>
    8020330c:	34000860 	cbz	w0, 80203418 <__sfvwrite_r+0x1e8>
    80203310:	f9400260 	ldr	x0, [x19]
    80203314:	93407f17 	sxtw	x23, w24
    80203318:	f9400e61 	ldr	x1, [x19, #24]
    8020331c:	eb1902ff 	cmp	x23, x25
    80203320:	b9400e76 	ldr	w22, [x19, #12]
    80203324:	9a9992f7 	csel	x23, x23, x25, ls	// ls = plast
    80203328:	b9402263 	ldr	w3, [x19, #32]
    8020332c:	eb01001f 	cmp	x0, x1
    80203330:	0b160076 	add	w22, w3, w22
    80203334:	7a5682e4 	ccmp	w23, w22, #0x4, hi	// hi = pmore
    80203338:	540019ac 	b.gt	8020366c <__sfvwrite_r+0x43c>
    8020333c:	6b17007f 	cmp	w3, w23
    80203340:	540017ec 	b.gt	8020363c <__sfvwrite_r+0x40c>
    80203344:	f9401a61 	ldr	x1, [x19, #48]
    80203348:	aa1a03e2 	mov	x2, x26
    8020334c:	f9402264 	ldr	x4, [x19, #64]
    80203350:	aa1503e0 	mov	x0, x21
    80203354:	d63f0080 	blr	x4
    80203358:	2a0003f6 	mov	w22, w0
    8020335c:	7100001f 	cmp	w0, #0x0
    80203360:	540003cd 	b.le	802033d8 <__sfvwrite_r+0x1a8>
    80203364:	6b160318 	subs	w24, w24, w22
    80203368:	52800020 	mov	w0, #0x1                   	// #1
    8020336c:	540002e0 	b.eq	802033c8 <__sfvwrite_r+0x198>  // b.none
    80203370:	f9400b61 	ldr	x1, [x27, #16]
    80203374:	93407ed6 	sxtw	x22, w22
    80203378:	8b16035a 	add	x26, x26, x22
    8020337c:	cb160339 	sub	x25, x25, x22
    80203380:	cb160021 	sub	x1, x1, x22
    80203384:	f9000b61 	str	x1, [x27, #16]
    80203388:	b5fffc01 	cbnz	x1, 80203308 <__sfvwrite_r+0xd8>
    8020338c:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203390:	a94363f7 	ldp	x23, x24, [sp, #48]
    80203394:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80203398:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020339c:	52800000 	mov	w0, #0x0                   	// #0
    802033a0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    802033a4:	a8c67bfd 	ldp	x29, x30, [sp], #96
    802033a8:	d65f03c0 	ret
    802033ac:	aa1303e1 	mov	x1, x19
    802033b0:	aa1503e0 	mov	x0, x21
    802033b4:	94001beb 	bl	8020a360 <__swsetup_r>
    802033b8:	350001a0 	cbnz	w0, 802033ec <__sfvwrite_r+0x1bc>
    802033bc:	79c02265 	ldrsh	w5, [x19, #16]
    802033c0:	a90363f7 	stp	x23, x24, [sp, #48]
    802033c4:	17ffffaa 	b	8020326c <__sfvwrite_r+0x3c>
    802033c8:	aa1303e1 	mov	x1, x19
    802033cc:	aa1503e0 	mov	x0, x21
    802033d0:	940022e8 	bl	8020bf70 <_fflush_r>
    802033d4:	34fffce0 	cbz	w0, 80203370 <__sfvwrite_r+0x140>
    802033d8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    802033dc:	79c02260 	ldrsh	w0, [x19, #16]
    802033e0:	a94363f7 	ldp	x23, x24, [sp, #48]
    802033e4:	321a0000 	orr	w0, w0, #0x40
    802033e8:	79002260 	strh	w0, [x19, #16]
    802033ec:	a94153f3 	ldp	x19, x20, [sp, #16]
    802033f0:	12800000 	mov	w0, #0xffffffff            	// #-1
    802033f4:	a9425bf5 	ldp	x21, x22, [sp, #32]
    802033f8:	a94573fb 	ldp	x27, x28, [sp, #80]
    802033fc:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80203400:	d65f03c0 	ret
    80203404:	f9400699 	ldr	x25, [x20, #8]
    80203408:	aa1403e0 	mov	x0, x20
    8020340c:	91004294 	add	x20, x20, #0x10
    80203410:	b4ffffb9 	cbz	x25, 80203404 <__sfvwrite_r+0x1d4>
    80203414:	f940001a 	ldr	x26, [x0]
    80203418:	aa1903e2 	mov	x2, x25
    8020341c:	aa1a03e0 	mov	x0, x26
    80203420:	52800141 	mov	w1, #0xa                   	// #10
    80203424:	94001b97 	bl	8020a280 <memchr>
    80203428:	91000418 	add	x24, x0, #0x1
    8020342c:	f100001f 	cmp	x0, #0x0
    80203430:	cb1a0318 	sub	x24, x24, x26
    80203434:	1a991718 	csinc	w24, w24, w25, ne	// ne = any
    80203438:	17ffffb6 	b	80203310 <__sfvwrite_r+0xe0>
    8020343c:	f9400264 	ldr	x4, [x19]
    80203440:	d280001c 	mov	x28, #0x0                   	// #0
    80203444:	b9400e61 	ldr	w1, [x19, #12]
    80203448:	d280001a 	mov	x26, #0x0                   	// #0
    8020344c:	d503201f 	nop
    80203450:	aa0403e0 	mov	x0, x4
    80203454:	2a0103f8 	mov	w24, w1
    80203458:	b40003fa 	cbz	x26, 802034d4 <__sfvwrite_r+0x2a4>
    8020345c:	36480425 	tbz	w5, #9, 802034e0 <__sfvwrite_r+0x2b0>
    80203460:	93407c37 	sxtw	x23, w1
    80203464:	eb1a02ff 	cmp	x23, x26
    80203468:	540008c9 	b.ls	80203580 <__sfvwrite_r+0x350>  // b.plast
    8020346c:	93407f41 	sxtw	x1, w26
    80203470:	aa0103f9 	mov	x25, x1
    80203474:	aa0403e0 	mov	x0, x4
    80203478:	aa0103f7 	mov	x23, x1
    8020347c:	2a1a03f8 	mov	w24, w26
    80203480:	aa1c03e1 	mov	x1, x28
    80203484:	aa1703e2 	mov	x2, x23
    80203488:	94001c7e 	bl	8020a680 <memcpy>
    8020348c:	f9400264 	ldr	x4, [x19]
    80203490:	b9400e61 	ldr	w1, [x19, #12]
    80203494:	8b170084 	add	x4, x4, x23
    80203498:	f9000264 	str	x4, [x19]
    8020349c:	4b180021 	sub	w1, w1, w24
    802034a0:	b9000e61 	str	w1, [x19, #12]
    802034a4:	f9400b60 	ldr	x0, [x27, #16]
    802034a8:	8b19039c 	add	x28, x28, x25
    802034ac:	cb19035a 	sub	x26, x26, x25
    802034b0:	cb190000 	sub	x0, x0, x25
    802034b4:	f9000b60 	str	x0, [x27, #16]
    802034b8:	b4fff6a0 	cbz	x0, 8020338c <__sfvwrite_r+0x15c>
    802034bc:	f9400264 	ldr	x4, [x19]
    802034c0:	b9400e61 	ldr	w1, [x19, #12]
    802034c4:	79c02265 	ldrsh	w5, [x19, #16]
    802034c8:	aa0403e0 	mov	x0, x4
    802034cc:	2a0103f8 	mov	w24, w1
    802034d0:	b5fffc7a 	cbnz	x26, 8020345c <__sfvwrite_r+0x22c>
    802034d4:	a9406a9c 	ldp	x28, x26, [x20]
    802034d8:	91004294 	add	x20, x20, #0x10
    802034dc:	17ffffdd 	b	80203450 <__sfvwrite_r+0x220>
    802034e0:	f9400e60 	ldr	x0, [x19, #24]
    802034e4:	eb04001f 	cmp	x0, x4
    802034e8:	54000243 	b.cc	80203530 <__sfvwrite_r+0x300>  // b.lo, b.ul, b.last
    802034ec:	b9402265 	ldr	w5, [x19, #32]
    802034f0:	eb25c35f 	cmp	x26, w5, sxtw
    802034f4:	540001e3 	b.cc	80203530 <__sfvwrite_r+0x300>  // b.lo, b.ul, b.last
    802034f8:	b2407be0 	mov	x0, #0x7fffffff            	// #2147483647
    802034fc:	eb00035f 	cmp	x26, x0
    80203500:	9a809343 	csel	x3, x26, x0, ls	// ls = plast
    80203504:	aa1c03e2 	mov	x2, x28
    80203508:	f9401a61 	ldr	x1, [x19, #48]
    8020350c:	aa1503e0 	mov	x0, x21
    80203510:	1ac50c63 	sdiv	w3, w3, w5
    80203514:	f9402264 	ldr	x4, [x19, #64]
    80203518:	1b057c63 	mul	w3, w3, w5
    8020351c:	d63f0080 	blr	x4
    80203520:	7100001f 	cmp	w0, #0x0
    80203524:	54fff5ad 	b.le	802033d8 <__sfvwrite_r+0x1a8>
    80203528:	93407c19 	sxtw	x25, w0
    8020352c:	17ffffde 	b	802034a4 <__sfvwrite_r+0x274>
    80203530:	93407c23 	sxtw	x3, w1
    80203534:	aa0403e0 	mov	x0, x4
    80203538:	eb1a007f 	cmp	x3, x26
    8020353c:	aa1c03e1 	mov	x1, x28
    80203540:	9a9a9078 	csel	x24, x3, x26, ls	// ls = plast
    80203544:	93407f19 	sxtw	x25, w24
    80203548:	aa1903e2 	mov	x2, x25
    8020354c:	94001c4d 	bl	8020a680 <memcpy>
    80203550:	f9400264 	ldr	x4, [x19]
    80203554:	b9400e61 	ldr	w1, [x19, #12]
    80203558:	8b190084 	add	x4, x4, x25
    8020355c:	f9000264 	str	x4, [x19]
    80203560:	4b180021 	sub	w1, w1, w24
    80203564:	b9000e61 	str	w1, [x19, #12]
    80203568:	35fff9e1 	cbnz	w1, 802034a4 <__sfvwrite_r+0x274>
    8020356c:	aa1303e1 	mov	x1, x19
    80203570:	aa1503e0 	mov	x0, x21
    80203574:	9400227f 	bl	8020bf70 <_fflush_r>
    80203578:	34fff960 	cbz	w0, 802034a4 <__sfvwrite_r+0x274>
    8020357c:	17ffff97 	b	802033d8 <__sfvwrite_r+0x1a8>
    80203580:	93407f59 	sxtw	x25, w26
    80203584:	52809001 	mov	w1, #0x480                 	// #1152
    80203588:	6a0100bf 	tst	w5, w1
    8020358c:	54fff7a0 	b.eq	80203480 <__sfvwrite_r+0x250>  // b.none
    80203590:	b9402266 	ldr	w6, [x19, #32]
    80203594:	f9400e61 	ldr	x1, [x19, #24]
    80203598:	0b0604c6 	add	w6, w6, w6, lsl #1
    8020359c:	cb010099 	sub	x25, x4, x1
    802035a0:	0b467cc6 	add	w6, w6, w6, lsr #31
    802035a4:	93407f36 	sxtw	x22, w25
    802035a8:	13017cd7 	asr	w23, w6, #1
    802035ac:	910006c0 	add	x0, x22, #0x1
    802035b0:	8b1a0000 	add	x0, x0, x26
    802035b4:	93407ee2 	sxtw	x2, w23
    802035b8:	eb00005f 	cmp	x2, x0
    802035bc:	54000082 	b.cs	802035cc <__sfvwrite_r+0x39c>  // b.hs, b.nlast
    802035c0:	11000726 	add	w6, w25, #0x1
    802035c4:	0b1a00d7 	add	w23, w6, w26
    802035c8:	93407ee2 	sxtw	x2, w23
    802035cc:	36500685 	tbz	w5, #10, 8020369c <__sfvwrite_r+0x46c>
    802035d0:	aa0203e1 	mov	x1, x2
    802035d4:	aa1503e0 	mov	x0, x21
    802035d8:	9400151a 	bl	80208a40 <_malloc_r>
    802035dc:	aa0003f8 	mov	x24, x0
    802035e0:	b4000840 	cbz	x0, 802036e8 <__sfvwrite_r+0x4b8>
    802035e4:	f9400e61 	ldr	x1, [x19, #24]
    802035e8:	aa1603e2 	mov	x2, x22
    802035ec:	94001c25 	bl	8020a680 <memcpy>
    802035f0:	79402260 	ldrh	w0, [x19, #16]
    802035f4:	12809001 	mov	w1, #0xfffffb7f            	// #-1153
    802035f8:	0a010000 	and	w0, w0, w1
    802035fc:	32190000 	orr	w0, w0, #0x80
    80203600:	79002260 	strh	w0, [x19, #16]
    80203604:	8b160300 	add	x0, x24, x22
    80203608:	4b1902e4 	sub	w4, w23, w25
    8020360c:	93407f59 	sxtw	x25, w26
    80203610:	f9000260 	str	x0, [x19]
    80203614:	b9000e64 	str	w4, [x19, #12]
    80203618:	aa1903e1 	mov	x1, x25
    8020361c:	f9000e78 	str	x24, [x19, #24]
    80203620:	aa0003e4 	mov	x4, x0
    80203624:	b9002277 	str	w23, [x19, #32]
    80203628:	2a1a03f8 	mov	w24, w26
    8020362c:	eb1a033f 	cmp	x25, x26
    80203630:	54fff208 	b.hi	80203470 <__sfvwrite_r+0x240>  // b.pmore
    80203634:	aa1903f7 	mov	x23, x25
    80203638:	17ffff92 	b	80203480 <__sfvwrite_r+0x250>
    8020363c:	93407efc 	sxtw	x28, w23
    80203640:	aa1a03e1 	mov	x1, x26
    80203644:	aa1c03e2 	mov	x2, x28
    80203648:	94001c0e 	bl	8020a680 <memcpy>
    8020364c:	f9400260 	ldr	x0, [x19]
    80203650:	2a1703f6 	mov	w22, w23
    80203654:	b9400e61 	ldr	w1, [x19, #12]
    80203658:	8b1c0000 	add	x0, x0, x28
    8020365c:	f9000260 	str	x0, [x19]
    80203660:	4b170021 	sub	w1, w1, w23
    80203664:	b9000e61 	str	w1, [x19, #12]
    80203668:	17ffff3f 	b	80203364 <__sfvwrite_r+0x134>
    8020366c:	93407ed7 	sxtw	x23, w22
    80203670:	aa1a03e1 	mov	x1, x26
    80203674:	aa1703e2 	mov	x2, x23
    80203678:	94001c02 	bl	8020a680 <memcpy>
    8020367c:	f9400262 	ldr	x2, [x19]
    80203680:	aa1303e1 	mov	x1, x19
    80203684:	aa1503e0 	mov	x0, x21
    80203688:	8b170042 	add	x2, x2, x23
    8020368c:	f9000262 	str	x2, [x19]
    80203690:	94002238 	bl	8020bf70 <_fflush_r>
    80203694:	34ffe680 	cbz	w0, 80203364 <__sfvwrite_r+0x134>
    80203698:	17ffff50 	b	802033d8 <__sfvwrite_r+0x1a8>
    8020369c:	aa1503e0 	mov	x0, x21
    802036a0:	940022b4 	bl	8020c170 <_realloc_r>
    802036a4:	aa0003f8 	mov	x24, x0
    802036a8:	b5fffae0 	cbnz	x0, 80203604 <__sfvwrite_r+0x3d4>
    802036ac:	f9400e61 	ldr	x1, [x19, #24]
    802036b0:	aa1503e0 	mov	x0, x21
    802036b4:	94002453 	bl	8020c800 <_free_r>
    802036b8:	79c02260 	ldrsh	w0, [x19, #16]
    802036bc:	52800181 	mov	w1, #0xc                   	// #12
    802036c0:	a9446bf9 	ldp	x25, x26, [sp, #64]
    802036c4:	12187800 	and	w0, w0, #0xffffff7f
    802036c8:	b90002a1 	str	w1, [x21]
    802036cc:	17ffff45 	b	802033e0 <__sfvwrite_r+0x1b0>
    802036d0:	79c02260 	ldrsh	w0, [x19, #16]
    802036d4:	17ffff43 	b	802033e0 <__sfvwrite_r+0x1b0>
    802036d8:	a94153f3 	ldp	x19, x20, [sp, #16]
    802036dc:	a94363f7 	ldp	x23, x24, [sp, #48]
    802036e0:	a94573fb 	ldp	x27, x28, [sp, #80]
    802036e4:	17ffff2e 	b	8020339c <__sfvwrite_r+0x16c>
    802036e8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    802036ec:	52800181 	mov	w1, #0xc                   	// #12
    802036f0:	79c02260 	ldrsh	w0, [x19, #16]
    802036f4:	b90002a1 	str	w1, [x21]
    802036f8:	17ffff3a 	b	802033e0 <__sfvwrite_r+0x1b0>
    802036fc:	00000000 	udf	#0

0000000080203700 <_fwalk_sglue>:
    80203700:	a9bb7bfd 	stp	x29, x30, [sp, #-80]!
    80203704:	910003fd 	mov	x29, sp
    80203708:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020370c:	aa0203f6 	mov	x22, x2
    80203710:	52800015 	mov	w21, #0x0                   	// #0
    80203714:	a90363f7 	stp	x23, x24, [sp, #48]
    80203718:	aa0003f7 	mov	x23, x0
    8020371c:	aa0103f8 	mov	x24, x1
    80203720:	a90153f3 	stp	x19, x20, [sp, #16]
    80203724:	f90023f9 	str	x25, [sp, #64]
    80203728:	52801719 	mov	w25, #0xb8                  	// #184
    8020372c:	d503201f 	nop
    80203730:	b9400ad4 	ldr	w20, [x22, #8]
    80203734:	f9400ad3 	ldr	x19, [x22, #16]
    80203738:	7100029f 	cmp	w20, #0x0
    8020373c:	5400020d 	b.le	8020377c <_fwalk_sglue+0x7c>
    80203740:	9bb94e94 	umaddl	x20, w20, w25, x19
    80203744:	d503201f 	nop
    80203748:	79402263 	ldrh	w3, [x19, #16]
    8020374c:	7100047f 	cmp	w3, #0x1
    80203750:	54000109 	b.ls	80203770 <_fwalk_sglue+0x70>  // b.plast
    80203754:	79c02663 	ldrsh	w3, [x19, #18]
    80203758:	aa1303e1 	mov	x1, x19
    8020375c:	aa1703e0 	mov	x0, x23
    80203760:	3100047f 	cmn	w3, #0x1
    80203764:	54000060 	b.eq	80203770 <_fwalk_sglue+0x70>  // b.none
    80203768:	d63f0300 	blr	x24
    8020376c:	2a0002b5 	orr	w21, w21, w0
    80203770:	9102e273 	add	x19, x19, #0xb8
    80203774:	eb14027f 	cmp	x19, x20
    80203778:	54fffe81 	b.ne	80203748 <_fwalk_sglue+0x48>  // b.any
    8020377c:	f94002d6 	ldr	x22, [x22]
    80203780:	b5fffd96 	cbnz	x22, 80203730 <_fwalk_sglue+0x30>
    80203784:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203788:	2a1503e0 	mov	w0, w21
    8020378c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80203790:	a94363f7 	ldp	x23, x24, [sp, #48]
    80203794:	f94023f9 	ldr	x25, [sp, #64]
    80203798:	a8c57bfd 	ldp	x29, x30, [sp], #80
    8020379c:	d65f03c0 	ret

00000000802037a0 <_write_r>:
    802037a0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    802037a4:	910003fd 	mov	x29, sp
    802037a8:	a90153f3 	stp	x19, x20, [sp, #16]
    802037ac:	b00003f4 	adrp	x20, 80280000 <gits_lock>
    802037b0:	aa0003f3 	mov	x19, x0
    802037b4:	2a0103e0 	mov	w0, w1
    802037b8:	aa0203e1 	mov	x1, x2
    802037bc:	b9048a9f 	str	wzr, [x20, #1160]
    802037c0:	aa0303e2 	mov	x2, x3
    802037c4:	97fff43f 	bl	802008c0 <_write>
    802037c8:	93407c01 	sxtw	x1, w0
    802037cc:	3100041f 	cmn	w0, #0x1
    802037d0:	540000a0 	b.eq	802037e4 <_write_r+0x44>  // b.none
    802037d4:	a94153f3 	ldp	x19, x20, [sp, #16]
    802037d8:	aa0103e0 	mov	x0, x1
    802037dc:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802037e0:	d65f03c0 	ret
    802037e4:	b9448a80 	ldr	w0, [x20, #1160]
    802037e8:	34ffff60 	cbz	w0, 802037d4 <_write_r+0x34>
    802037ec:	b9000260 	str	w0, [x19]
    802037f0:	aa0103e0 	mov	x0, x1
    802037f4:	a94153f3 	ldp	x19, x20, [sp, #16]
    802037f8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802037fc:	d65f03c0 	ret

0000000080203800 <_vfprintf_r>:
    80203800:	d10a43ff 	sub	sp, sp, #0x290
    80203804:	a9007bfd 	stp	x29, x30, [sp]
    80203808:	910003fd 	mov	x29, sp
    8020380c:	a9025bf5 	stp	x21, x22, [sp, #32]
    80203810:	aa0103f5 	mov	x21, x1
    80203814:	f9400061 	ldr	x1, [x3]
    80203818:	f9003fe1 	str	x1, [sp, #120]
    8020381c:	f9400461 	ldr	x1, [x3, #8]
    80203820:	f90053e1 	str	x1, [sp, #160]
    80203824:	f9400861 	ldr	x1, [x3, #16]
    80203828:	f90087e1 	str	x1, [sp, #264]
    8020382c:	b9401861 	ldr	w1, [x3, #24]
    80203830:	b90093e1 	str	w1, [sp, #144]
    80203834:	b9401c61 	ldr	w1, [x3, #28]
    80203838:	a90153f3 	stp	x19, x20, [sp, #16]
    8020383c:	aa0303f4 	mov	x20, x3
    80203840:	aa0003f3 	mov	x19, x0
    80203844:	a90363f7 	stp	x23, x24, [sp, #48]
    80203848:	aa0203f7 	mov	x23, x2
    8020384c:	b900f7e1 	str	w1, [sp, #244]
    80203850:	94001a24 	bl	8020a0e0 <_localeconv_r>
    80203854:	f9400000 	ldr	x0, [x0]
    80203858:	f9005be0 	str	x0, [sp, #176]
    8020385c:	97fffe29 	bl	80203100 <strlen>
    80203860:	f90057e0 	str	x0, [sp, #168]
    80203864:	d2800102 	mov	x2, #0x8                   	// #8
    80203868:	9105e3e0 	add	x0, sp, #0x178
    8020386c:	52800001 	mov	w1, #0x0                   	// #0
    80203870:	97fffd94 	bl	80202ec0 <memset>
    80203874:	b4000073 	cbz	x19, 80203880 <_vfprintf_r+0x80>
    80203878:	f9402660 	ldr	x0, [x19, #72]
    8020387c:	b400cb40 	cbz	x0, 802051e4 <_vfprintf_r+0x19e4>
    80203880:	b940b2a1 	ldr	w1, [x21, #176]
    80203884:	79c022a0 	ldrsh	w0, [x21, #16]
    80203888:	37000041 	tbnz	w1, #0, 80203890 <_vfprintf_r+0x90>
    8020388c:	3648a2e0 	tbz	w0, #9, 80204ce8 <_vfprintf_r+0x14e8>
    80203890:	376800c0 	tbnz	w0, #13, 802038a8 <_vfprintf_r+0xa8>
    80203894:	b940b2a1 	ldr	w1, [x21, #176]
    80203898:	32130000 	orr	w0, w0, #0x2000
    8020389c:	790022a0 	strh	w0, [x21, #16]
    802038a0:	12127821 	and	w1, w1, #0xffffdfff
    802038a4:	b900b2a1 	str	w1, [x21, #176]
    802038a8:	361805e0 	tbz	w0, #3, 80203964 <_vfprintf_r+0x164>
    802038ac:	f9400ea1 	ldr	x1, [x21, #24]
    802038b0:	b40005a1 	cbz	x1, 80203964 <_vfprintf_r+0x164>
    802038b4:	52800341 	mov	w1, #0x1a                  	// #26
    802038b8:	0a010001 	and	w1, w0, w1
    802038bc:	7100283f 	cmp	w1, #0xa
    802038c0:	54000640 	b.eq	80203988 <_vfprintf_r+0x188>  // b.none
    802038c4:	910843f6 	add	x22, sp, #0x210
    802038c8:	6d0627e8 	stp	d8, d9, [sp, #96]
    802038cc:	2f00e408 	movi	d8, #0x0
    802038d0:	d0000074 	adrp	x20, 80211000 <__mprec_tens+0x180>
    802038d4:	aa1703ea 	mov	x10, x23
    802038d8:	912b4294 	add	x20, x20, #0xad0
    802038dc:	a90573fb 	stp	x27, x28, [sp, #80]
    802038e0:	aa1603fc 	mov	x28, x22
    802038e4:	b0000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    802038e8:	91203000 	add	x0, x0, #0x80c
    802038ec:	a9046bf9 	stp	x25, x26, [sp, #64]
    802038f0:	b90077ff 	str	wzr, [sp, #116]
    802038f4:	f90043e0 	str	x0, [sp, #128]
    802038f8:	b90097ff 	str	wzr, [sp, #148]
    802038fc:	a90e7fff 	stp	xzr, xzr, [sp, #224]
    80203900:	b900f3ff 	str	wzr, [sp, #240]
    80203904:	a90fffff 	stp	xzr, xzr, [sp, #248]
    80203908:	f900cbf6 	str	x22, [sp, #400]
    8020390c:	b9019bff 	str	wzr, [sp, #408]
    80203910:	f900d3ff 	str	xzr, [sp, #416]
    80203914:	aa0a03f7 	mov	x23, x10
    80203918:	aa0a03f8 	mov	x24, x10
    8020391c:	d503201f 	nop
    80203920:	f9407699 	ldr	x25, [x20, #232]
    80203924:	940019df 	bl	8020a0a0 <__locale_mb_cur_max>
    80203928:	9105e3e4 	add	x4, sp, #0x178
    8020392c:	93407c03 	sxtw	x3, w0
    80203930:	aa1703e2 	mov	x2, x23
    80203934:	9105b3e1 	add	x1, sp, #0x16c
    80203938:	aa1303e0 	mov	x0, x19
    8020393c:	d63f0320 	blr	x25
    80203940:	7100001f 	cmp	w0, #0x0
    80203944:	34000580 	cbz	w0, 802039f4 <_vfprintf_r+0x1f4>
    80203948:	5400048b 	b.lt	802039d8 <_vfprintf_r+0x1d8>  // b.tstop
    8020394c:	b9416fe1 	ldr	w1, [sp, #364]
    80203950:	7100943f 	cmp	w1, #0x25
    80203954:	540039a0 	b.eq	80204088 <_vfprintf_r+0x888>  // b.none
    80203958:	93407c00 	sxtw	x0, w0
    8020395c:	8b0002f7 	add	x23, x23, x0
    80203960:	17fffff0 	b	80203920 <_vfprintf_r+0x120>
    80203964:	aa1503e1 	mov	x1, x21
    80203968:	aa1303e0 	mov	x0, x19
    8020396c:	94001a7d 	bl	8020a360 <__swsetup_r>
    80203970:	35014ee0 	cbnz	w0, 8020634c <_vfprintf_r+0x2b4c>
    80203974:	79c022a0 	ldrsh	w0, [x21, #16]
    80203978:	52800341 	mov	w1, #0x1a                  	// #26
    8020397c:	0a010001 	and	w1, w0, w1
    80203980:	7100283f 	cmp	w1, #0xa
    80203984:	54fffa01 	b.ne	802038c4 <_vfprintf_r+0xc4>  // b.any
    80203988:	79c026a1 	ldrsh	w1, [x21, #18]
    8020398c:	37fff9c1 	tbnz	w1, #31, 802038c4 <_vfprintf_r+0xc4>
    80203990:	b940b2a1 	ldr	w1, [x21, #176]
    80203994:	37000041 	tbnz	w1, #0, 8020399c <_vfprintf_r+0x19c>
    80203998:	364918c0 	tbz	w0, #9, 80205cb0 <_vfprintf_r+0x24b0>
    8020399c:	ad400680 	ldp	q0, q1, [x20]
    802039a0:	aa1703e2 	mov	x2, x23
    802039a4:	aa1503e1 	mov	x1, x21
    802039a8:	9104c3e3 	add	x3, sp, #0x130
    802039ac:	aa1303e0 	mov	x0, x19
    802039b0:	ad0987e0 	stp	q0, q1, [sp, #304]
    802039b4:	94000c5f 	bl	80206b30 <__sbprintf>
    802039b8:	b90077e0 	str	w0, [sp, #116]
    802039bc:	a9407bfd 	ldp	x29, x30, [sp]
    802039c0:	a94153f3 	ldp	x19, x20, [sp, #16]
    802039c4:	a9425bf5 	ldp	x21, x22, [sp, #32]
    802039c8:	a94363f7 	ldp	x23, x24, [sp, #48]
    802039cc:	b94077e0 	ldr	w0, [sp, #116]
    802039d0:	910a43ff 	add	sp, sp, #0x290
    802039d4:	d65f03c0 	ret
    802039d8:	9105e3e0 	add	x0, sp, #0x178
    802039dc:	d2800102 	mov	x2, #0x8                   	// #8
    802039e0:	52800001 	mov	w1, #0x0                   	// #0
    802039e4:	97fffd37 	bl	80202ec0 <memset>
    802039e8:	d2800020 	mov	x0, #0x1                   	// #1
    802039ec:	8b0002f7 	add	x23, x23, x0
    802039f0:	17ffffcc 	b	80203920 <_vfprintf_r+0x120>
    802039f4:	2a0003fa 	mov	w26, w0
    802039f8:	cb1802e0 	sub	x0, x23, x24
    802039fc:	aa1803ea 	mov	x10, x24
    80203a00:	2a0003fb 	mov	w27, w0
    80203a04:	3400e3a0 	cbz	w0, 80205678 <_vfprintf_r+0x1e78>
    80203a08:	f940d3e2 	ldr	x2, [sp, #416]
    80203a0c:	93407f61 	sxtw	x1, w27
    80203a10:	b9419be0 	ldr	w0, [sp, #408]
    80203a14:	8b010042 	add	x2, x2, x1
    80203a18:	a900078a 	stp	x10, x1, [x28]
    80203a1c:	11000400 	add	w0, w0, #0x1
    80203a20:	b9019be0 	str	w0, [sp, #408]
    80203a24:	9100439c 	add	x28, x28, #0x10
    80203a28:	f900d3e2 	str	x2, [sp, #416]
    80203a2c:	71001c1f 	cmp	w0, #0x7
    80203a30:	5400452c 	b.gt	802042d4 <_vfprintf_r+0xad4>
    80203a34:	b94077e0 	ldr	w0, [sp, #116]
    80203a38:	0b1b0000 	add	w0, w0, w27
    80203a3c:	b90077e0 	str	w0, [sp, #116]
    80203a40:	3400e1da 	cbz	w26, 80205678 <_vfprintf_r+0x1e78>
    80203a44:	910006ea 	add	x10, x23, #0x1
    80203a48:	394006e8 	ldrb	w8, [x23, #1]
    80203a4c:	12800007 	mov	w7, #0xffffffff            	// #-1
    80203a50:	5280000b 	mov	w11, #0x0                   	// #0
    80203a54:	52800009 	mov	w9, #0x0                   	// #0
    80203a58:	2a0b03f8 	mov	w24, w11
    80203a5c:	2a0903f7 	mov	w23, w9
    80203a60:	2a0703f9 	mov	w25, w7
    80203a64:	aa0a03fa 	mov	x26, x10
    80203a68:	39057fff 	strb	wzr, [sp, #351]
    80203a6c:	9100075a 	add	x26, x26, #0x1
    80203a70:	51008100 	sub	w0, w8, #0x20
    80203a74:	7101681f 	cmp	w0, #0x5a
    80203a78:	540000c8 	b.hi	80203a90 <_vfprintf_r+0x290>  // b.pmore
    80203a7c:	f94043e1 	ldr	x1, [sp, #128]
    80203a80:	78605820 	ldrh	w0, [x1, w0, uxtw #1]
    80203a84:	10000061 	adr	x1, 80203a90 <_vfprintf_r+0x290>
    80203a88:	8b20a820 	add	x0, x1, w0, sxth #2
    80203a8c:	d61f0000 	br	x0
    80203a90:	2a1703e9 	mov	w9, w23
    80203a94:	2a1803eb 	mov	w11, w24
    80203a98:	aa1a03ea 	mov	x10, x26
    80203a9c:	3400dee8 	cbz	w8, 80205678 <_vfprintf_r+0x1e78>
    80203aa0:	5280003a 	mov	w26, #0x1                   	// #1
    80203aa4:	9106a3fb 	add	x27, sp, #0x1a8
    80203aa8:	2a1a03f7 	mov	w23, w26
    80203aac:	52800001 	mov	w1, #0x0                   	// #0
    80203ab0:	d2800019 	mov	x25, #0x0                   	// #0
    80203ab4:	52800007 	mov	w7, #0x0                   	// #0
    80203ab8:	52800018 	mov	w24, #0x0                   	// #0
    80203abc:	b9008bff 	str	wzr, [sp, #136]
    80203ac0:	b9009bff 	str	wzr, [sp, #152]
    80203ac4:	39057fff 	strb	wzr, [sp, #351]
    80203ac8:	3906a3e8 	strb	w8, [sp, #424]
    80203acc:	d503201f 	nop
    80203ad0:	721f0132 	ands	w18, w9, #0x2
    80203ad4:	11000b42 	add	w2, w26, #0x2
    80203ad8:	f940d3e0 	ldr	x0, [sp, #416]
    80203adc:	1a9a105a 	csel	w26, w2, w26, ne	// ne = any
    80203ae0:	5280108e 	mov	w14, #0x84                  	// #132
    80203ae4:	6a0e012e 	ands	w14, w9, w14
    80203ae8:	54000081 	b.ne	80203af8 <_vfprintf_r+0x2f8>  // b.any
    80203aec:	4b1a0164 	sub	w4, w11, w26
    80203af0:	7100009f 	cmp	w4, #0x0
    80203af4:	54001a6c 	b.gt	80203e40 <_vfprintf_r+0x640>
    80203af8:	340001a1 	cbz	w1, 80203b2c <_vfprintf_r+0x32c>
    80203afc:	b9419be1 	ldr	w1, [sp, #408]
    80203b00:	91057fe2 	add	x2, sp, #0x15f
    80203b04:	91000400 	add	x0, x0, #0x1
    80203b08:	f9000382 	str	x2, [x28]
    80203b0c:	11000421 	add	w1, w1, #0x1
    80203b10:	d2800022 	mov	x2, #0x1                   	// #1
    80203b14:	f9000782 	str	x2, [x28, #8]
    80203b18:	9100439c 	add	x28, x28, #0x10
    80203b1c:	b9019be1 	str	w1, [sp, #408]
    80203b20:	f900d3e0 	str	x0, [sp, #416]
    80203b24:	71001c3f 	cmp	w1, #0x7
    80203b28:	54003e4c 	b.gt	802042f0 <_vfprintf_r+0xaf0>
    80203b2c:	340001b2 	cbz	w18, 80203b60 <_vfprintf_r+0x360>
    80203b30:	b9419be1 	ldr	w1, [sp, #408]
    80203b34:	910583e2 	add	x2, sp, #0x160
    80203b38:	91000800 	add	x0, x0, #0x2
    80203b3c:	f9000382 	str	x2, [x28]
    80203b40:	11000421 	add	w1, w1, #0x1
    80203b44:	d2800042 	mov	x2, #0x2                   	// #2
    80203b48:	f9000782 	str	x2, [x28, #8]
    80203b4c:	9100439c 	add	x28, x28, #0x10
    80203b50:	b9019be1 	str	w1, [sp, #408]
    80203b54:	f900d3e0 	str	x0, [sp, #416]
    80203b58:	71001c3f 	cmp	w1, #0x7
    80203b5c:	5400730c 	b.gt	802049bc <_vfprintf_r+0x11bc>
    80203b60:	710201df 	cmp	w14, #0x80
    80203b64:	540029e0 	b.eq	802040a0 <_vfprintf_r+0x8a0>  // b.none
    80203b68:	4b1700e7 	sub	w7, w7, w23
    80203b6c:	710000ff 	cmp	w7, #0x0
    80203b70:	5400050c 	b.gt	80203c10 <_vfprintf_r+0x410>
    80203b74:	37400e29 	tbnz	w9, #8, 80203d38 <_vfprintf_r+0x538>
    80203b78:	b9419be1 	ldr	w1, [sp, #408]
    80203b7c:	93407eec 	sxtw	x12, w23
    80203b80:	8b0c0000 	add	x0, x0, x12
    80203b84:	a900339b 	stp	x27, x12, [x28]
    80203b88:	11000421 	add	w1, w1, #0x1
    80203b8c:	b9019be1 	str	w1, [sp, #408]
    80203b90:	f900d3e0 	str	x0, [sp, #416]
    80203b94:	71001c3f 	cmp	w1, #0x7
    80203b98:	5400224c 	b.gt	80203fe0 <_vfprintf_r+0x7e0>
    80203b9c:	9100439c 	add	x28, x28, #0x10
    80203ba0:	36100089 	tbz	w9, #2, 80203bb0 <_vfprintf_r+0x3b0>
    80203ba4:	4b1a0177 	sub	w23, w11, w26
    80203ba8:	710002ff 	cmp	w23, #0x0
    80203bac:	5400730c 	b.gt	80204a0c <_vfprintf_r+0x120c>
    80203bb0:	b94077e1 	ldr	w1, [sp, #116]
    80203bb4:	6b1a017f 	cmp	w11, w26
    80203bb8:	1a9aa163 	csel	w3, w11, w26, ge	// ge = tcont
    80203bbc:	0b030021 	add	w1, w1, w3
    80203bc0:	b90077e1 	str	w1, [sp, #116]
    80203bc4:	b5002300 	cbnz	x0, 80204024 <_vfprintf_r+0x824>
    80203bc8:	b9019bff 	str	wzr, [sp, #408]
    80203bcc:	b40000d9 	cbz	x25, 80203be4 <_vfprintf_r+0x3e4>
    80203bd0:	aa1903e1 	mov	x1, x25
    80203bd4:	aa1303e0 	mov	x0, x19
    80203bd8:	f90047ea 	str	x10, [sp, #136]
    80203bdc:	94002309 	bl	8020c800 <_free_r>
    80203be0:	f94047ea 	ldr	x10, [sp, #136]
    80203be4:	aa1603fc 	mov	x28, x22
    80203be8:	17ffff4b 	b	80203914 <_vfprintf_r+0x114>
    80203bec:	5100c100 	sub	w0, w8, #0x30
    80203bf0:	52800018 	mov	w24, #0x0                   	// #0
    80203bf4:	38401748 	ldrb	w8, [x26], #1
    80203bf8:	0b180b0b 	add	w11, w24, w24, lsl #2
    80203bfc:	0b0b0418 	add	w24, w0, w11, lsl #1
    80203c00:	5100c100 	sub	w0, w8, #0x30
    80203c04:	7100241f 	cmp	w0, #0x9
    80203c08:	54ffff69 	b.ls	80203bf4 <_vfprintf_r+0x3f4>  // b.plast
    80203c0c:	17ffff99 	b	80203a70 <_vfprintf_r+0x270>
    80203c10:	b0000064 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80203c14:	b9419be1 	ldr	w1, [sp, #408]
    80203c18:	91234084 	add	x4, x4, #0x8d0
    80203c1c:	710040ff 	cmp	w7, #0x10
    80203c20:	5400058d 	b.le	80203cd0 <_vfprintf_r+0x4d0>
    80203c24:	aa1c03e2 	mov	x2, x28
    80203c28:	d280020d 	mov	x13, #0x10                  	// #16
    80203c2c:	aa0a03fc 	mov	x28, x10
    80203c30:	b900bbe9 	str	w9, [sp, #184]
    80203c34:	b900c3e8 	str	w8, [sp, #192]
    80203c38:	b900cbeb 	str	w11, [sp, #200]
    80203c3c:	b900d3f7 	str	w23, [sp, #208]
    80203c40:	2a0703f7 	mov	w23, w7
    80203c44:	b900dbf8 	str	w24, [sp, #216]
    80203c48:	aa0403f8 	mov	x24, x4
    80203c4c:	14000004 	b	80203c5c <_vfprintf_r+0x45c>
    80203c50:	510042f7 	sub	w23, w23, #0x10
    80203c54:	710042ff 	cmp	w23, #0x10
    80203c58:	540002ad 	b.le	80203cac <_vfprintf_r+0x4ac>
    80203c5c:	91004000 	add	x0, x0, #0x10
    80203c60:	11000421 	add	w1, w1, #0x1
    80203c64:	a9003458 	stp	x24, x13, [x2]
    80203c68:	91004042 	add	x2, x2, #0x10
    80203c6c:	b9019be1 	str	w1, [sp, #408]
    80203c70:	f900d3e0 	str	x0, [sp, #416]
    80203c74:	71001c3f 	cmp	w1, #0x7
    80203c78:	54fffecd 	b.le	80203c50 <_vfprintf_r+0x450>
    80203c7c:	910643e2 	add	x2, sp, #0x190
    80203c80:	aa1503e1 	mov	x1, x21
    80203c84:	aa1303e0 	mov	x0, x19
    80203c88:	94000c1a 	bl	80206cf0 <__sprint_r>
    80203c8c:	35001da0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80203c90:	510042f7 	sub	w23, w23, #0x10
    80203c94:	b9419be1 	ldr	w1, [sp, #408]
    80203c98:	f940d3e0 	ldr	x0, [sp, #416]
    80203c9c:	aa1603e2 	mov	x2, x22
    80203ca0:	d280020d 	mov	x13, #0x10                  	// #16
    80203ca4:	710042ff 	cmp	w23, #0x10
    80203ca8:	54fffdac 	b.gt	80203c5c <_vfprintf_r+0x45c>
    80203cac:	2a1703e7 	mov	w7, w23
    80203cb0:	aa1803e4 	mov	x4, x24
    80203cb4:	b940bbe9 	ldr	w9, [sp, #184]
    80203cb8:	aa1c03ea 	mov	x10, x28
    80203cbc:	b940c3e8 	ldr	w8, [sp, #192]
    80203cc0:	aa0203fc 	mov	x28, x2
    80203cc4:	b940cbeb 	ldr	w11, [sp, #200]
    80203cc8:	b940d3f7 	ldr	w23, [sp, #208]
    80203ccc:	b940dbf8 	ldr	w24, [sp, #216]
    80203cd0:	93407ce7 	sxtw	x7, w7
    80203cd4:	11000421 	add	w1, w1, #0x1
    80203cd8:	8b070000 	add	x0, x0, x7
    80203cdc:	a9001f84 	stp	x4, x7, [x28]
    80203ce0:	9100439c 	add	x28, x28, #0x10
    80203ce4:	b9019be1 	str	w1, [sp, #408]
    80203ce8:	f900d3e0 	str	x0, [sp, #416]
    80203cec:	71001c3f 	cmp	w1, #0x7
    80203cf0:	54fff42d 	b.le	80203b74 <_vfprintf_r+0x374>
    80203cf4:	910643e2 	add	x2, sp, #0x190
    80203cf8:	aa1503e1 	mov	x1, x21
    80203cfc:	aa1303e0 	mov	x0, x19
    80203d00:	b900bbe9 	str	w9, [sp, #184]
    80203d04:	b900c3e8 	str	w8, [sp, #192]
    80203d08:	b900cbeb 	str	w11, [sp, #200]
    80203d0c:	f9006bea 	str	x10, [sp, #208]
    80203d10:	94000bf8 	bl	80206cf0 <__sprint_r>
    80203d14:	35001960 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80203d18:	b940bbe9 	ldr	w9, [sp, #184]
    80203d1c:	aa1603fc 	mov	x28, x22
    80203d20:	f9406bea 	ldr	x10, [sp, #208]
    80203d24:	f940d3e0 	ldr	x0, [sp, #416]
    80203d28:	b940c3e8 	ldr	w8, [sp, #192]
    80203d2c:	b940cbeb 	ldr	w11, [sp, #200]
    80203d30:	3647f249 	tbz	w9, #8, 80203b78 <_vfprintf_r+0x378>
    80203d34:	d503201f 	nop
    80203d38:	7101951f 	cmp	w8, #0x65
    80203d3c:	5400252d 	b.le	802041e0 <_vfprintf_r+0x9e0>
    80203d40:	1e602108 	fcmp	d8, #0.0
    80203d44:	54001001 	b.ne	80203f44 <_vfprintf_r+0x744>  // b.any
    80203d48:	b9419be1 	ldr	w1, [sp, #408]
    80203d4c:	91000400 	add	x0, x0, #0x1
    80203d50:	b0000062 	adrp	x2, 80210000 <__trunctfdf2+0xc0>
    80203d54:	d2800024 	mov	x4, #0x1                   	// #1
    80203d58:	9114e042 	add	x2, x2, #0x538
    80203d5c:	11000421 	add	w1, w1, #0x1
    80203d60:	a9001382 	stp	x2, x4, [x28]
    80203d64:	9100439c 	add	x28, x28, #0x10
    80203d68:	b9019be1 	str	w1, [sp, #408]
    80203d6c:	f900d3e0 	str	x0, [sp, #416]
    80203d70:	71001c3f 	cmp	w1, #0x7
    80203d74:	5400b08c 	b.gt	80205384 <_vfprintf_r+0x1b84>
    80203d78:	b94097e2 	ldr	w2, [sp, #148]
    80203d7c:	b9416be1 	ldr	w1, [sp, #360]
    80203d80:	6b02003f 	cmp	w1, w2
    80203d84:	54007baa 	b.ge	80204cf8 <_vfprintf_r+0x14f8>  // b.tcont
    80203d88:	a94a8fe2 	ldp	x2, x3, [sp, #168]
    80203d8c:	a9000b83 	stp	x3, x2, [x28]
    80203d90:	b9419be1 	ldr	w1, [sp, #408]
    80203d94:	9100439c 	add	x28, x28, #0x10
    80203d98:	11000421 	add	w1, w1, #0x1
    80203d9c:	b9019be1 	str	w1, [sp, #408]
    80203da0:	8b020000 	add	x0, x0, x2
    80203da4:	f900d3e0 	str	x0, [sp, #416]
    80203da8:	71001c3f 	cmp	w1, #0x7
    80203dac:	540088ec 	b.gt	80204ec8 <_vfprintf_r+0x16c8>
    80203db0:	b94097e1 	ldr	w1, [sp, #148]
    80203db4:	51000437 	sub	w23, w1, #0x1
    80203db8:	710002ff 	cmp	w23, #0x0
    80203dbc:	54ffef2d 	b.le	80203ba0 <_vfprintf_r+0x3a0>
    80203dc0:	b0000064 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80203dc4:	b9419be1 	ldr	w1, [sp, #408]
    80203dc8:	91234084 	add	x4, x4, #0x8d0
    80203dcc:	710042ff 	cmp	w23, #0x10
    80203dd0:	5400bc4d 	b.le	80205558 <_vfprintf_r+0x1d58>
    80203dd4:	aa1c03e2 	mov	x2, x28
    80203dd8:	aa0403f8 	mov	x24, x4
    80203ddc:	aa0a03fc 	mov	x28, x10
    80203de0:	d280021b 	mov	x27, #0x10                  	// #16
    80203de4:	b9008be9 	str	w9, [sp, #136]
    80203de8:	b9009beb 	str	w11, [sp, #152]
    80203dec:	14000004 	b	80203dfc <_vfprintf_r+0x5fc>
    80203df0:	510042f7 	sub	w23, w23, #0x10
    80203df4:	710042ff 	cmp	w23, #0x10
    80203df8:	5400ba6d 	b.le	80205544 <_vfprintf_r+0x1d44>
    80203dfc:	91004000 	add	x0, x0, #0x10
    80203e00:	11000421 	add	w1, w1, #0x1
    80203e04:	a9006c58 	stp	x24, x27, [x2]
    80203e08:	91004042 	add	x2, x2, #0x10
    80203e0c:	b9019be1 	str	w1, [sp, #408]
    80203e10:	f900d3e0 	str	x0, [sp, #416]
    80203e14:	71001c3f 	cmp	w1, #0x7
    80203e18:	54fffecd 	b.le	80203df0 <_vfprintf_r+0x5f0>
    80203e1c:	910643e2 	add	x2, sp, #0x190
    80203e20:	aa1503e1 	mov	x1, x21
    80203e24:	aa1303e0 	mov	x0, x19
    80203e28:	94000bb2 	bl	80206cf0 <__sprint_r>
    80203e2c:	350010a0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80203e30:	f940d3e0 	ldr	x0, [sp, #416]
    80203e34:	aa1603e2 	mov	x2, x22
    80203e38:	b9419be1 	ldr	w1, [sp, #408]
    80203e3c:	17ffffed 	b	80203df0 <_vfprintf_r+0x5f0>
    80203e40:	b000006d 	adrp	x13, 80210000 <__trunctfdf2+0xc0>
    80203e44:	b9419be1 	ldr	w1, [sp, #408]
    80203e48:	912381ad 	add	x13, x13, #0x8e0
    80203e4c:	7100409f 	cmp	w4, #0x10
    80203e50:	5400064d 	b.le	80203f18 <_vfprintf_r+0x718>
    80203e54:	aa1c03e2 	mov	x2, x28
    80203e58:	d280020f 	mov	x15, #0x10                  	// #16
    80203e5c:	aa0a03fc 	mov	x28, x10
    80203e60:	b900bbf2 	str	w18, [sp, #184]
    80203e64:	b900c3ee 	str	w14, [sp, #192]
    80203e68:	b900cbe9 	str	w9, [sp, #200]
    80203e6c:	b900d3e8 	str	w8, [sp, #208]
    80203e70:	b900dbeb 	str	w11, [sp, #216]
    80203e74:	b90113e7 	str	w7, [sp, #272]
    80203e78:	b9011bf7 	str	w23, [sp, #280]
    80203e7c:	2a0403f7 	mov	w23, w4
    80203e80:	b90123f8 	str	w24, [sp, #288]
    80203e84:	aa0d03f8 	mov	x24, x13
    80203e88:	14000004 	b	80203e98 <_vfprintf_r+0x698>
    80203e8c:	510042f7 	sub	w23, w23, #0x10
    80203e90:	710042ff 	cmp	w23, #0x10
    80203e94:	540002ad 	b.le	80203ee8 <_vfprintf_r+0x6e8>
    80203e98:	91004000 	add	x0, x0, #0x10
    80203e9c:	11000421 	add	w1, w1, #0x1
    80203ea0:	a9003c58 	stp	x24, x15, [x2]
    80203ea4:	91004042 	add	x2, x2, #0x10
    80203ea8:	b9019be1 	str	w1, [sp, #408]
    80203eac:	f900d3e0 	str	x0, [sp, #416]
    80203eb0:	71001c3f 	cmp	w1, #0x7
    80203eb4:	54fffecd 	b.le	80203e8c <_vfprintf_r+0x68c>
    80203eb8:	910643e2 	add	x2, sp, #0x190
    80203ebc:	aa1503e1 	mov	x1, x21
    80203ec0:	aa1303e0 	mov	x0, x19
    80203ec4:	94000b8b 	bl	80206cf0 <__sprint_r>
    80203ec8:	35000bc0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80203ecc:	510042f7 	sub	w23, w23, #0x10
    80203ed0:	b9419be1 	ldr	w1, [sp, #408]
    80203ed4:	f940d3e0 	ldr	x0, [sp, #416]
    80203ed8:	aa1603e2 	mov	x2, x22
    80203edc:	d280020f 	mov	x15, #0x10                  	// #16
    80203ee0:	710042ff 	cmp	w23, #0x10
    80203ee4:	54fffdac 	b.gt	80203e98 <_vfprintf_r+0x698>
    80203ee8:	2a1703e4 	mov	w4, w23
    80203eec:	aa1803ed 	mov	x13, x24
    80203ef0:	b940bbf2 	ldr	w18, [sp, #184]
    80203ef4:	aa1c03ea 	mov	x10, x28
    80203ef8:	b940c3ee 	ldr	w14, [sp, #192]
    80203efc:	aa0203fc 	mov	x28, x2
    80203f00:	b940cbe9 	ldr	w9, [sp, #200]
    80203f04:	b940d3e8 	ldr	w8, [sp, #208]
    80203f08:	b940dbeb 	ldr	w11, [sp, #216]
    80203f0c:	b94113e7 	ldr	w7, [sp, #272]
    80203f10:	b9411bf7 	ldr	w23, [sp, #280]
    80203f14:	b94123f8 	ldr	w24, [sp, #288]
    80203f18:	93407c84 	sxtw	x4, w4
    80203f1c:	11000421 	add	w1, w1, #0x1
    80203f20:	8b040000 	add	x0, x0, x4
    80203f24:	a900138d 	stp	x13, x4, [x28]
    80203f28:	b9019be1 	str	w1, [sp, #408]
    80203f2c:	f900d3e0 	str	x0, [sp, #416]
    80203f30:	71001c3f 	cmp	w1, #0x7
    80203f34:	540092ac 	b.gt	80205188 <_vfprintf_r+0x1988>
    80203f38:	39457fe1 	ldrb	w1, [sp, #351]
    80203f3c:	9100439c 	add	x28, x28, #0x10
    80203f40:	17fffeee 	b	80203af8 <_vfprintf_r+0x2f8>
    80203f44:	b9416be2 	ldr	w2, [sp, #360]
    80203f48:	7100005f 	cmp	w2, #0x0
    80203f4c:	54005e4c 	b.gt	80204b14 <_vfprintf_r+0x1314>
    80203f50:	b9419be1 	ldr	w1, [sp, #408]
    80203f54:	91000400 	add	x0, x0, #0x1
    80203f58:	b0000064 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80203f5c:	d2800027 	mov	x7, #0x1                   	// #1
    80203f60:	9114e084 	add	x4, x4, #0x538
    80203f64:	11000421 	add	w1, w1, #0x1
    80203f68:	a9001f84 	stp	x4, x7, [x28]
    80203f6c:	9100439c 	add	x28, x28, #0x10
    80203f70:	b9019be1 	str	w1, [sp, #408]
    80203f74:	f900d3e0 	str	x0, [sp, #416]
    80203f78:	71001c3f 	cmp	w1, #0x7
    80203f7c:	540107cc 	b.gt	80206074 <_vfprintf_r+0x2874>
    80203f80:	b94097e1 	ldr	w1, [sp, #148]
    80203f84:	2a020021 	orr	w1, w1, w2
    80203f88:	3400d761 	cbz	w1, 80205a74 <_vfprintf_r+0x2274>
    80203f8c:	a94a93e3 	ldp	x3, x4, [sp, #168]
    80203f90:	a9000f84 	stp	x4, x3, [x28]
    80203f94:	b9419be1 	ldr	w1, [sp, #408]
    80203f98:	91004386 	add	x6, x28, #0x10
    80203f9c:	11000421 	add	w1, w1, #0x1
    80203fa0:	b9019be1 	str	w1, [sp, #408]
    80203fa4:	8b000060 	add	x0, x3, x0
    80203fa8:	f900d3e0 	str	x0, [sp, #416]
    80203fac:	71001c3f 	cmp	w1, #0x7
    80203fb0:	5400d78c 	b.gt	80205aa0 <_vfprintf_r+0x22a0>
    80203fb4:	37f91e42 	tbnz	w2, #31, 8020637c <_vfprintf_r+0x2b7c>
    80203fb8:	b98097e2 	ldrsw	x2, [sp, #148]
    80203fbc:	11000421 	add	w1, w1, #0x1
    80203fc0:	a90008db 	stp	x27, x2, [x6]
    80203fc4:	910040dc 	add	x28, x6, #0x10
    80203fc8:	8b000040 	add	x0, x2, x0
    80203fcc:	b9019be1 	str	w1, [sp, #408]
    80203fd0:	f900d3e0 	str	x0, [sp, #416]
    80203fd4:	71001c3f 	cmp	w1, #0x7
    80203fd8:	54ffde4d 	b.le	80203ba0 <_vfprintf_r+0x3a0>
    80203fdc:	d503201f 	nop
    80203fe0:	910643e2 	add	x2, sp, #0x190
    80203fe4:	aa1503e1 	mov	x1, x21
    80203fe8:	aa1303e0 	mov	x0, x19
    80203fec:	b9008be9 	str	w9, [sp, #136]
    80203ff0:	b9009beb 	str	w11, [sp, #152]
    80203ff4:	f9005fea 	str	x10, [sp, #184]
    80203ff8:	94000b3e 	bl	80206cf0 <__sprint_r>
    80203ffc:	35000220 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204000:	f9405fea 	ldr	x10, [sp, #184]
    80204004:	aa1603fc 	mov	x28, x22
    80204008:	f940d3e0 	ldr	x0, [sp, #416]
    8020400c:	b9408be9 	ldr	w9, [sp, #136]
    80204010:	b9409beb 	ldr	w11, [sp, #152]
    80204014:	17fffee3 	b	80203ba0 <_vfprintf_r+0x3a0>
    80204018:	39400348 	ldrb	w8, [x26]
    8020401c:	321c02f7 	orr	w23, w23, #0x10
    80204020:	17fffe93 	b	80203a6c <_vfprintf_r+0x26c>
    80204024:	910643e2 	add	x2, sp, #0x190
    80204028:	aa1503e1 	mov	x1, x21
    8020402c:	aa1303e0 	mov	x0, x19
    80204030:	f90047ea 	str	x10, [sp, #136]
    80204034:	94000b2f 	bl	80206cf0 <__sprint_r>
    80204038:	f94047ea 	ldr	x10, [sp, #136]
    8020403c:	34ffdc60 	cbz	w0, 80203bc8 <_vfprintf_r+0x3c8>
    80204040:	aa1903e1 	mov	x1, x25
    80204044:	b4000061 	cbz	x1, 80204050 <_vfprintf_r+0x850>
    80204048:	aa1303e0 	mov	x0, x19
    8020404c:	940021ed 	bl	8020c800 <_free_r>
    80204050:	79c022a0 	ldrsh	w0, [x21, #16]
    80204054:	b940b2a1 	ldr	w1, [x21, #176]
    80204058:	36001781 	tbz	w1, #0, 80204348 <_vfprintf_r+0xb48>
    8020405c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80204060:	a94573fb 	ldp	x27, x28, [sp, #80]
    80204064:	6d4627e8 	ldp	d8, d9, [sp, #96]
    80204068:	373117e0 	tbnz	w0, #6, 80206364 <_vfprintf_r+0x2b64>
    8020406c:	a9407bfd 	ldp	x29, x30, [sp]
    80204070:	a94153f3 	ldp	x19, x20, [sp, #16]
    80204074:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80204078:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020407c:	b94077e0 	ldr	w0, [sp, #116]
    80204080:	910a43ff 	add	sp, sp, #0x290
    80204084:	d65f03c0 	ret
    80204088:	2a0003fa 	mov	w26, w0
    8020408c:	cb1802e0 	sub	x0, x23, x24
    80204090:	aa1803ea 	mov	x10, x24
    80204094:	2a0003fb 	mov	w27, w0
    80204098:	34ffcd60 	cbz	w0, 80203a44 <_vfprintf_r+0x244>
    8020409c:	17fffe5b 	b	80203a08 <_vfprintf_r+0x208>
    802040a0:	4b1a016d 	sub	w13, w11, w26
    802040a4:	710001bf 	cmp	w13, #0x0
    802040a8:	54ffd60d 	b.le	80203b68 <_vfprintf_r+0x368>
    802040ac:	90000064 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    802040b0:	b9419be1 	ldr	w1, [sp, #408]
    802040b4:	91234084 	add	x4, x4, #0x8d0
    802040b8:	710041bf 	cmp	w13, #0x10
    802040bc:	540005cd 	b.le	80204174 <_vfprintf_r+0x974>
    802040c0:	aa1c03e2 	mov	x2, x28
    802040c4:	d280020e 	mov	x14, #0x10                  	// #16
    802040c8:	aa0a03fc 	mov	x28, x10
    802040cc:	b900bbe9 	str	w9, [sp, #184]
    802040d0:	b900c3e8 	str	w8, [sp, #192]
    802040d4:	b900cbeb 	str	w11, [sp, #200]
    802040d8:	b900d3e7 	str	w7, [sp, #208]
    802040dc:	b900dbf7 	str	w23, [sp, #216]
    802040e0:	2a0d03f7 	mov	w23, w13
    802040e4:	b90113f8 	str	w24, [sp, #272]
    802040e8:	aa0403f8 	mov	x24, x4
    802040ec:	14000004 	b	802040fc <_vfprintf_r+0x8fc>
    802040f0:	510042f7 	sub	w23, w23, #0x10
    802040f4:	710042ff 	cmp	w23, #0x10
    802040f8:	540002ad 	b.le	8020414c <_vfprintf_r+0x94c>
    802040fc:	91004000 	add	x0, x0, #0x10
    80204100:	11000421 	add	w1, w1, #0x1
    80204104:	a9003858 	stp	x24, x14, [x2]
    80204108:	91004042 	add	x2, x2, #0x10
    8020410c:	b9019be1 	str	w1, [sp, #408]
    80204110:	f900d3e0 	str	x0, [sp, #416]
    80204114:	71001c3f 	cmp	w1, #0x7
    80204118:	54fffecd 	b.le	802040f0 <_vfprintf_r+0x8f0>
    8020411c:	910643e2 	add	x2, sp, #0x190
    80204120:	aa1503e1 	mov	x1, x21
    80204124:	aa1303e0 	mov	x0, x19
    80204128:	94000af2 	bl	80206cf0 <__sprint_r>
    8020412c:	35fff8a0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204130:	510042f7 	sub	w23, w23, #0x10
    80204134:	b9419be1 	ldr	w1, [sp, #408]
    80204138:	f940d3e0 	ldr	x0, [sp, #416]
    8020413c:	aa1603e2 	mov	x2, x22
    80204140:	d280020e 	mov	x14, #0x10                  	// #16
    80204144:	710042ff 	cmp	w23, #0x10
    80204148:	54fffdac 	b.gt	802040fc <_vfprintf_r+0x8fc>
    8020414c:	2a1703ed 	mov	w13, w23
    80204150:	aa1803e4 	mov	x4, x24
    80204154:	b940bbe9 	ldr	w9, [sp, #184]
    80204158:	aa1c03ea 	mov	x10, x28
    8020415c:	b940c3e8 	ldr	w8, [sp, #192]
    80204160:	aa0203fc 	mov	x28, x2
    80204164:	b940cbeb 	ldr	w11, [sp, #200]
    80204168:	b940d3e7 	ldr	w7, [sp, #208]
    8020416c:	b940dbf7 	ldr	w23, [sp, #216]
    80204170:	b94113f8 	ldr	w24, [sp, #272]
    80204174:	93407dad 	sxtw	x13, w13
    80204178:	11000421 	add	w1, w1, #0x1
    8020417c:	8b0d0000 	add	x0, x0, x13
    80204180:	a9003784 	stp	x4, x13, [x28]
    80204184:	9100439c 	add	x28, x28, #0x10
    80204188:	b9019be1 	str	w1, [sp, #408]
    8020418c:	f900d3e0 	str	x0, [sp, #416]
    80204190:	71001c3f 	cmp	w1, #0x7
    80204194:	54ffcead 	b.le	80203b68 <_vfprintf_r+0x368>
    80204198:	910643e2 	add	x2, sp, #0x190
    8020419c:	aa1503e1 	mov	x1, x21
    802041a0:	aa1303e0 	mov	x0, x19
    802041a4:	b900bbe9 	str	w9, [sp, #184]
    802041a8:	b900c3e8 	str	w8, [sp, #192]
    802041ac:	b900cbeb 	str	w11, [sp, #200]
    802041b0:	b900d3e7 	str	w7, [sp, #208]
    802041b4:	f9006fea 	str	x10, [sp, #216]
    802041b8:	94000ace 	bl	80206cf0 <__sprint_r>
    802041bc:	35fff420 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    802041c0:	f9406fea 	ldr	x10, [sp, #216]
    802041c4:	aa1603fc 	mov	x28, x22
    802041c8:	f940d3e0 	ldr	x0, [sp, #416]
    802041cc:	b940bbe9 	ldr	w9, [sp, #184]
    802041d0:	b940c3e8 	ldr	w8, [sp, #192]
    802041d4:	b940cbeb 	ldr	w11, [sp, #200]
    802041d8:	b940d3e7 	ldr	w7, [sp, #208]
    802041dc:	17fffe63 	b	80203b68 <_vfprintf_r+0x368>
    802041e0:	b9419be1 	ldr	w1, [sp, #408]
    802041e4:	91000400 	add	x0, x0, #0x1
    802041e8:	b94097e3 	ldr	w3, [sp, #148]
    802041ec:	91004382 	add	x2, x28, #0x10
    802041f0:	11000421 	add	w1, w1, #0x1
    802041f4:	7100047f 	cmp	w3, #0x1
    802041f8:	5400118d 	b.le	80204428 <_vfprintf_r+0xc28>
    802041fc:	d2800024 	mov	x4, #0x1                   	// #1
    80204200:	a900139b 	stp	x27, x4, [x28]
    80204204:	b9019be1 	str	w1, [sp, #408]
    80204208:	f900d3e0 	str	x0, [sp, #416]
    8020420c:	71001c3f 	cmp	w1, #0x7
    80204210:	5400528c 	b.gt	80204c60 <_vfprintf_r+0x1460>
    80204214:	a94a93e3 	ldp	x3, x4, [sp, #168]
    80204218:	11000421 	add	w1, w1, #0x1
    8020421c:	a9000c44 	stp	x4, x3, [x2]
    80204220:	91004042 	add	x2, x2, #0x10
    80204224:	b9019be1 	str	w1, [sp, #408]
    80204228:	8b030000 	add	x0, x0, x3
    8020422c:	f900d3e0 	str	x0, [sp, #416]
    80204230:	71001c3f 	cmp	w1, #0x7
    80204234:	5400534c 	b.gt	80204c9c <_vfprintf_r+0x149c>
    80204238:	1e602108 	fcmp	d8, #0.0
    8020423c:	b94097e3 	ldr	w3, [sp, #148]
    80204240:	51000477 	sub	w23, w3, #0x1
    80204244:	540011e0 	b.eq	80204480 <_vfprintf_r+0xc80>  // b.none
    80204248:	93407ef7 	sxtw	x23, w23
    8020424c:	11000421 	add	w1, w1, #0x1
    80204250:	8b170000 	add	x0, x0, x23
    80204254:	b9019be1 	str	w1, [sp, #408]
    80204258:	f900d3e0 	str	x0, [sp, #416]
    8020425c:	91000765 	add	x5, x27, #0x1
    80204260:	f9000045 	str	x5, [x2]
    80204264:	f9000457 	str	x23, [x2, #8]
    80204268:	71001c3f 	cmp	w1, #0x7
    8020426c:	5400610c 	b.gt	80204e8c <_vfprintf_r+0x168c>
    80204270:	91004042 	add	x2, x2, #0x10
    80204274:	b980f3e4 	ldrsw	x4, [sp, #240]
    80204278:	11000421 	add	w1, w1, #0x1
    8020427c:	9105c3e5 	add	x5, sp, #0x170
    80204280:	a9001045 	stp	x5, x4, [x2]
    80204284:	8b000080 	add	x0, x4, x0
    80204288:	b9019be1 	str	w1, [sp, #408]
    8020428c:	9100405c 	add	x28, x2, #0x10
    80204290:	f900d3e0 	str	x0, [sp, #416]
    80204294:	71001c3f 	cmp	w1, #0x7
    80204298:	54ffc84d 	b.le	80203ba0 <_vfprintf_r+0x3a0>
    8020429c:	910643e2 	add	x2, sp, #0x190
    802042a0:	aa1503e1 	mov	x1, x21
    802042a4:	aa1303e0 	mov	x0, x19
    802042a8:	b9008be9 	str	w9, [sp, #136]
    802042ac:	b9009beb 	str	w11, [sp, #152]
    802042b0:	f9005fea 	str	x10, [sp, #184]
    802042b4:	94000a8f 	bl	80206cf0 <__sprint_r>
    802042b8:	35ffec40 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    802042bc:	f9405fea 	ldr	x10, [sp, #184]
    802042c0:	aa1603fc 	mov	x28, x22
    802042c4:	f940d3e0 	ldr	x0, [sp, #416]
    802042c8:	b9408be9 	ldr	w9, [sp, #136]
    802042cc:	b9409beb 	ldr	w11, [sp, #152]
    802042d0:	17fffe34 	b	80203ba0 <_vfprintf_r+0x3a0>
    802042d4:	910643e2 	add	x2, sp, #0x190
    802042d8:	aa1503e1 	mov	x1, x21
    802042dc:	aa1303e0 	mov	x0, x19
    802042e0:	94000a84 	bl	80206cf0 <__sprint_r>
    802042e4:	35ffeb60 	cbnz	w0, 80204050 <_vfprintf_r+0x850>
    802042e8:	aa1603fc 	mov	x28, x22
    802042ec:	17fffdd2 	b	80203a34 <_vfprintf_r+0x234>
    802042f0:	910643e2 	add	x2, sp, #0x190
    802042f4:	aa1503e1 	mov	x1, x21
    802042f8:	aa1303e0 	mov	x0, x19
    802042fc:	b900bbf2 	str	w18, [sp, #184]
    80204300:	b900c3ee 	str	w14, [sp, #192]
    80204304:	b900cbe9 	str	w9, [sp, #200]
    80204308:	b900d3e8 	str	w8, [sp, #208]
    8020430c:	b900dbeb 	str	w11, [sp, #216]
    80204310:	b90113e7 	str	w7, [sp, #272]
    80204314:	f9008fea 	str	x10, [sp, #280]
    80204318:	94000a76 	bl	80206cf0 <__sprint_r>
    8020431c:	35ffe920 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204320:	f9408fea 	ldr	x10, [sp, #280]
    80204324:	aa1603fc 	mov	x28, x22
    80204328:	f940d3e0 	ldr	x0, [sp, #416]
    8020432c:	b940bbf2 	ldr	w18, [sp, #184]
    80204330:	b940c3ee 	ldr	w14, [sp, #192]
    80204334:	b940cbe9 	ldr	w9, [sp, #200]
    80204338:	b940d3e8 	ldr	w8, [sp, #208]
    8020433c:	b940dbeb 	ldr	w11, [sp, #216]
    80204340:	b94113e7 	ldr	w7, [sp, #272]
    80204344:	17fffdfa 	b	80203b2c <_vfprintf_r+0x32c>
    80204348:	374fe8a0 	tbnz	w0, #9, 8020405c <_vfprintf_r+0x85c>
    8020434c:	f94052a0 	ldr	x0, [x21, #160]
    80204350:	9400142c 	bl	80209400 <__retarget_lock_release_recursive>
    80204354:	79c022a0 	ldrsh	w0, [x21, #16]
    80204358:	17ffff41 	b	8020405c <_vfprintf_r+0x85c>
    8020435c:	b940f7e0 	ldr	w0, [sp, #244]
    80204360:	2a1703e9 	mov	w9, w23
    80204364:	2a1803eb 	mov	w11, w24
    80204368:	2a1903e7 	mov	w7, w25
    8020436c:	aa1a03ea 	mov	x10, x26
    80204370:	36184c89 	tbz	w9, #3, 80204d00 <_vfprintf_r+0x1500>
    80204374:	37f8d200 	tbnz	w0, #31, 80205db4 <_vfprintf_r+0x25b4>
    80204378:	f9403fe0 	ldr	x0, [sp, #120]
    8020437c:	91003c00 	add	x0, x0, #0xf
    80204380:	927cec00 	and	x0, x0, #0xfffffffffffffff0
    80204384:	91004001 	add	x1, x0, #0x10
    80204388:	f9003fe1 	str	x1, [sp, #120]
    8020438c:	3dc00000 	ldr	q0, [x0]
    80204390:	b9008be9 	str	w9, [sp, #136]
    80204394:	b9009be8 	str	w8, [sp, #152]
    80204398:	b900bbeb 	str	w11, [sp, #184]
    8020439c:	b900c3e7 	str	w7, [sp, #192]
    802043a0:	f90067ea 	str	x10, [sp, #200]
    802043a4:	94002ee7 	bl	8020ff40 <__trunctfdf2>
    802043a8:	f94067ea 	ldr	x10, [sp, #200]
    802043ac:	1e604008 	fmov	d8, d0
    802043b0:	b9408be9 	ldr	w9, [sp, #136]
    802043b4:	b9409be8 	ldr	w8, [sp, #152]
    802043b8:	b940bbeb 	ldr	w11, [sp, #184]
    802043bc:	b940c3e7 	ldr	w7, [sp, #192]
    802043c0:	1e60c100 	fabs	d0, d8
    802043c4:	92f00200 	mov	x0, #0x7fefffffffffffff    	// #9218868437227405311
    802043c8:	9e670001 	fmov	d1, x0
    802043cc:	1e612000 	fcmp	d0, d1
    802043d0:	5400710d 	b.le	802051f0 <_vfprintf_r+0x19f0>
    802043d4:	1e602118 	fcmpe	d8, #0.0
    802043d8:	5400ce64 	b.mi	80205da4 <_vfprintf_r+0x25a4>  // b.first
    802043dc:	39457fe1 	ldrb	w1, [sp, #351]
    802043e0:	90000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    802043e4:	90000065 	adrp	x5, 80210000 <__trunctfdf2+0xc0>
    802043e8:	71011d1f 	cmp	w8, #0x47
    802043ec:	91138000 	add	x0, x0, #0x4e0
    802043f0:	9113a0a5 	add	x5, x5, #0x4e8
    802043f4:	b9008bff 	str	wzr, [sp, #136]
    802043f8:	5280007a 	mov	w26, #0x3                   	// #3
    802043fc:	b9009bff 	str	wzr, [sp, #152]
    80204400:	12187929 	and	w9, w9, #0xffffff7f
    80204404:	9a80c0bb 	csel	x27, x5, x0, gt
    80204408:	2a1a03f7 	mov	w23, w26
    8020440c:	d2800019 	mov	x25, #0x0                   	// #0
    80204410:	52800007 	mov	w7, #0x0                   	// #0
    80204414:	52800018 	mov	w24, #0x0                   	// #0
    80204418:	34ffb5c1 	cbz	w1, 80203ad0 <_vfprintf_r+0x2d0>
    8020441c:	d503201f 	nop
    80204420:	1100075a 	add	w26, w26, #0x1
    80204424:	17fffdab 	b	80203ad0 <_vfprintf_r+0x2d0>
    80204428:	3707eea9 	tbnz	w9, #0, 802041fc <_vfprintf_r+0x9fc>
    8020442c:	d2800024 	mov	x4, #0x1                   	// #1
    80204430:	a900139b 	stp	x27, x4, [x28]
    80204434:	b9019be1 	str	w1, [sp, #408]
    80204438:	f900d3e0 	str	x0, [sp, #416]
    8020443c:	71001c3f 	cmp	w1, #0x7
    80204440:	54fff1ad 	b.le	80204274 <_vfprintf_r+0xa74>
    80204444:	910643e2 	add	x2, sp, #0x190
    80204448:	aa1503e1 	mov	x1, x21
    8020444c:	aa1303e0 	mov	x0, x19
    80204450:	b9008be9 	str	w9, [sp, #136]
    80204454:	b9009beb 	str	w11, [sp, #152]
    80204458:	f9005fea 	str	x10, [sp, #184]
    8020445c:	94000a25 	bl	80206cf0 <__sprint_r>
    80204460:	35ffdf00 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204464:	f9405fea 	ldr	x10, [sp, #184]
    80204468:	aa1603e2 	mov	x2, x22
    8020446c:	f940d3e0 	ldr	x0, [sp, #416]
    80204470:	b9408be9 	ldr	w9, [sp, #136]
    80204474:	b9409beb 	ldr	w11, [sp, #152]
    80204478:	b9419be1 	ldr	w1, [sp, #408]
    8020447c:	17ffff7e 	b	80204274 <_vfprintf_r+0xa74>
    80204480:	b94097e3 	ldr	w3, [sp, #148]
    80204484:	7100047f 	cmp	w3, #0x1
    80204488:	54ffef6d 	b.le	80204274 <_vfprintf_r+0xa74>
    8020448c:	90000064 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80204490:	91234084 	add	x4, x4, #0x8d0
    80204494:	7100447f 	cmp	w3, #0x11
    80204498:	54004e8d 	b.le	80204e68 <_vfprintf_r+0x1668>
    8020449c:	2a0b03fc 	mov	w28, w11
    802044a0:	aa0403f8 	mov	x24, x4
    802044a4:	d280021b 	mov	x27, #0x10                  	// #16
    802044a8:	b9008be9 	str	w9, [sp, #136]
    802044ac:	f9004fea 	str	x10, [sp, #152]
    802044b0:	14000004 	b	802044c0 <_vfprintf_r+0xcc0>
    802044b4:	510042f7 	sub	w23, w23, #0x10
    802044b8:	710042ff 	cmp	w23, #0x10
    802044bc:	54004ced 	b.le	80204e58 <_vfprintf_r+0x1658>
    802044c0:	91004000 	add	x0, x0, #0x10
    802044c4:	11000421 	add	w1, w1, #0x1
    802044c8:	a9006c58 	stp	x24, x27, [x2]
    802044cc:	91004042 	add	x2, x2, #0x10
    802044d0:	b9019be1 	str	w1, [sp, #408]
    802044d4:	f900d3e0 	str	x0, [sp, #416]
    802044d8:	71001c3f 	cmp	w1, #0x7
    802044dc:	54fffecd 	b.le	802044b4 <_vfprintf_r+0xcb4>
    802044e0:	910643e2 	add	x2, sp, #0x190
    802044e4:	aa1503e1 	mov	x1, x21
    802044e8:	aa1303e0 	mov	x0, x19
    802044ec:	94000a01 	bl	80206cf0 <__sprint_r>
    802044f0:	35ffda80 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    802044f4:	f940d3e0 	ldr	x0, [sp, #416]
    802044f8:	aa1603e2 	mov	x2, x22
    802044fc:	b9419be1 	ldr	w1, [sp, #408]
    80204500:	17ffffed 	b	802044b4 <_vfprintf_r+0xcb4>
    80204504:	2a1703e9 	mov	w9, w23
    80204508:	2a1803eb 	mov	w11, w24
    8020450c:	aa1a03ea 	mov	x10, x26
    80204510:	71010d1f 	cmp	w8, #0x43
    80204514:	540054e0 	b.eq	80204fb0 <_vfprintf_r+0x17b0>  // b.none
    80204518:	372054c9 	tbnz	w9, #4, 80204fb0 <_vfprintf_r+0x17b0>
    8020451c:	b94093e0 	ldr	w0, [sp, #144]
    80204520:	37f8e1e0 	tbnz	w0, #31, 8020615c <_vfprintf_r+0x295c>
    80204524:	f9403fe0 	ldr	x0, [sp, #120]
    80204528:	91002c01 	add	x1, x0, #0xb
    8020452c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204530:	f9003fe1 	str	x1, [sp, #120]
    80204534:	b9400000 	ldr	w0, [x0]
    80204538:	5280003a 	mov	w26, #0x1                   	// #1
    8020453c:	9106a3f8 	add	x24, sp, #0x1a8
    80204540:	2a1a03f7 	mov	w23, w26
    80204544:	3906a3e0 	strb	w0, [sp, #424]
    80204548:	aa1803fb 	mov	x27, x24
    8020454c:	52800001 	mov	w1, #0x0                   	// #0
    80204550:	d2800019 	mov	x25, #0x0                   	// #0
    80204554:	52800007 	mov	w7, #0x0                   	// #0
    80204558:	52800018 	mov	w24, #0x0                   	// #0
    8020455c:	b9008bff 	str	wzr, [sp, #136]
    80204560:	b9009bff 	str	wzr, [sp, #152]
    80204564:	39057fff 	strb	wzr, [sp, #351]
    80204568:	17fffd5a 	b	80203ad0 <_vfprintf_r+0x2d0>
    8020456c:	b94093e0 	ldr	w0, [sp, #144]
    80204570:	2a1703e9 	mov	w9, w23
    80204574:	2a1803eb 	mov	w11, w24
    80204578:	2a1903e7 	mov	w7, w25
    8020457c:	aa1a03ea 	mov	x10, x26
    80204580:	37f84460 	tbnz	w0, #31, 80204e0c <_vfprintf_r+0x160c>
    80204584:	f9403fe0 	ldr	x0, [sp, #120]
    80204588:	91003c01 	add	x1, x0, #0xf
    8020458c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204590:	f9003fe1 	str	x1, [sp, #120]
    80204594:	f940001b 	ldr	x27, [x0]
    80204598:	39057fff 	strb	wzr, [sp, #351]
    8020459c:	b400841b 	cbz	x27, 8020561c <_vfprintf_r+0x1e1c>
    802045a0:	71014d1f 	cmp	w8, #0x53
    802045a4:	540070c0 	b.eq	802053bc <_vfprintf_r+0x1bbc>  // b.none
    802045a8:	121c0138 	and	w24, w9, #0x10
    802045ac:	37207089 	tbnz	w9, #4, 802053bc <_vfprintf_r+0x1bbc>
    802045b0:	37f8b247 	tbnz	w7, #31, 80205bf8 <_vfprintf_r+0x23f8>
    802045b4:	93407ce2 	sxtw	x2, w7
    802045b8:	aa1b03e0 	mov	x0, x27
    802045bc:	52800001 	mov	w1, #0x0                   	// #0
    802045c0:	b9008be7 	str	w7, [sp, #136]
    802045c4:	b9009be9 	str	w9, [sp, #152]
    802045c8:	b900bbeb 	str	w11, [sp, #184]
    802045cc:	f90063ea 	str	x10, [sp, #192]
    802045d0:	9400172c 	bl	8020a280 <memchr>
    802045d4:	f94063ea 	ldr	x10, [sp, #192]
    802045d8:	aa0003f9 	mov	x25, x0
    802045dc:	b9408be7 	ldr	w7, [sp, #136]
    802045e0:	b9409be9 	ldr	w9, [sp, #152]
    802045e4:	b940bbeb 	ldr	w11, [sp, #184]
    802045e8:	b4011040 	cbz	x0, 802067f0 <_vfprintf_r+0x2ff0>
    802045ec:	39457fe1 	ldrb	w1, [sp, #351]
    802045f0:	cb1b0003 	sub	x3, x0, x27
    802045f4:	b9008bff 	str	wzr, [sp, #136]
    802045f8:	7100007f 	cmp	w3, #0x0
    802045fc:	b9009bff 	str	wzr, [sp, #152]
    80204600:	2a0303f7 	mov	w23, w3
    80204604:	1a9fa07a 	csel	w26, w3, wzr, ge	// ge = tcont
    80204608:	52800007 	mov	w7, #0x0                   	// #0
    8020460c:	d2800019 	mov	x25, #0x0                   	// #0
    80204610:	52800e68 	mov	w8, #0x73                  	// #115
    80204614:	34ffa5e1 	cbz	w1, 80203ad0 <_vfprintf_r+0x2d0>
    80204618:	17ffff82 	b	80204420 <_vfprintf_r+0xc20>
    8020461c:	4b1803f8 	neg	w24, w24
    80204620:	f9003fe0 	str	x0, [sp, #120]
    80204624:	39400348 	ldrb	w8, [x26]
    80204628:	321e02f7 	orr	w23, w23, #0x4
    8020462c:	17fffd10 	b	80203a6c <_vfprintf_r+0x26c>
    80204630:	aa1a03e1 	mov	x1, x26
    80204634:	38401428 	ldrb	w8, [x1], #1
    80204638:	7100a91f 	cmp	w8, #0x2a
    8020463c:	54011cc0 	b.eq	802069d4 <_vfprintf_r+0x31d4>  // b.none
    80204640:	5100c100 	sub	w0, w8, #0x30
    80204644:	aa0103fa 	mov	x26, x1
    80204648:	52800007 	mov	w7, #0x0                   	// #0
    8020464c:	52800019 	mov	w25, #0x0                   	// #0
    80204650:	7100241f 	cmp	w0, #0x9
    80204654:	54ffa0e8 	b.hi	80203a70 <_vfprintf_r+0x270>  // b.pmore
    80204658:	38401428 	ldrb	w8, [x1], #1
    8020465c:	0b0708e7 	add	w7, w7, w7, lsl #2
    80204660:	0b070407 	add	w7, w0, w7, lsl #1
    80204664:	5100c100 	sub	w0, w8, #0x30
    80204668:	7100241f 	cmp	w0, #0x9
    8020466c:	54ffff69 	b.ls	80204658 <_vfprintf_r+0xe58>  // b.plast
    80204670:	710000ff 	cmp	w7, #0x0
    80204674:	aa0103fa 	mov	x26, x1
    80204678:	5a9fa0f9 	csinv	w25, w7, wzr, ge	// ge = tcont
    8020467c:	17fffcfd 	b	80203a70 <_vfprintf_r+0x270>
    80204680:	52800560 	mov	w0, #0x2b                  	// #43
    80204684:	39400348 	ldrb	w8, [x26]
    80204688:	39057fe0 	strb	w0, [sp, #351]
    8020468c:	17fffcf8 	b	80203a6c <_vfprintf_r+0x26c>
    80204690:	b94093e0 	ldr	w0, [sp, #144]
    80204694:	37f83d00 	tbnz	w0, #31, 80204e34 <_vfprintf_r+0x1634>
    80204698:	f9403fe0 	ldr	x0, [sp, #120]
    8020469c:	91002c00 	add	x0, x0, #0xb
    802046a0:	927df000 	and	x0, x0, #0xfffffffffffffff8
    802046a4:	f9403fe1 	ldr	x1, [sp, #120]
    802046a8:	b9400038 	ldr	w24, [x1]
    802046ac:	37fffb98 	tbnz	w24, #31, 8020461c <_vfprintf_r+0xe1c>
    802046b0:	39400348 	ldrb	w8, [x26]
    802046b4:	f9003fe0 	str	x0, [sp, #120]
    802046b8:	17fffced 	b	80203a6c <_vfprintf_r+0x26c>
    802046bc:	aa1303e0 	mov	x0, x19
    802046c0:	94001688 	bl	8020a0e0 <_localeconv_r>
    802046c4:	f9400400 	ldr	x0, [x0, #8]
    802046c8:	f90077e0 	str	x0, [sp, #232]
    802046cc:	97fffa8d 	bl	80203100 <strlen>
    802046d0:	aa0003e1 	mov	x1, x0
    802046d4:	aa0103fb 	mov	x27, x1
    802046d8:	aa1303e0 	mov	x0, x19
    802046dc:	f90083e1 	str	x1, [sp, #256]
    802046e0:	94001680 	bl	8020a0e0 <_localeconv_r>
    802046e4:	f9400800 	ldr	x0, [x0, #16]
    802046e8:	f9007fe0 	str	x0, [sp, #248]
    802046ec:	f100037f 	cmp	x27, #0x0
    802046f0:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
    802046f4:	54003420 	b.eq	80204d78 <_vfprintf_r+0x1578>  // b.none
    802046f8:	39400001 	ldrb	w1, [x0]
    802046fc:	321602e0 	orr	w0, w23, #0x400
    80204700:	39400348 	ldrb	w8, [x26]
    80204704:	7100003f 	cmp	w1, #0x0
    80204708:	1a971017 	csel	w23, w0, w23, ne	// ne = any
    8020470c:	17fffcd8 	b	80203a6c <_vfprintf_r+0x26c>
    80204710:	39400348 	ldrb	w8, [x26]
    80204714:	320002f7 	orr	w23, w23, #0x1
    80204718:	17fffcd5 	b	80203a6c <_vfprintf_r+0x26c>
    8020471c:	39457fe0 	ldrb	w0, [sp, #351]
    80204720:	39400348 	ldrb	w8, [x26]
    80204724:	35ff9a40 	cbnz	w0, 80203a6c <_vfprintf_r+0x26c>
    80204728:	52800400 	mov	w0, #0x20                  	// #32
    8020472c:	39057fe0 	strb	w0, [sp, #351]
    80204730:	17fffccf 	b	80203a6c <_vfprintf_r+0x26c>
    80204734:	2a1803eb 	mov	w11, w24
    80204738:	2a1903e7 	mov	w7, w25
    8020473c:	aa1a03ea 	mov	x10, x26
    80204740:	321c02e9 	orr	w9, w23, #0x10
    80204744:	b94093e0 	ldr	w0, [sp, #144]
    80204748:	37280049 	tbnz	w9, #5, 80204750 <_vfprintf_r+0xf50>
    8020474c:	36203329 	tbz	w9, #4, 80204db0 <_vfprintf_r+0x15b0>
    80204750:	37f84f40 	tbnz	w0, #31, 80205138 <_vfprintf_r+0x1938>
    80204754:	f9403fe0 	ldr	x0, [sp, #120]
    80204758:	91003c01 	add	x1, x0, #0xf
    8020475c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204760:	f9003fe1 	str	x1, [sp, #120]
    80204764:	f9400000 	ldr	x0, [x0]
    80204768:	1215793a 	and	w26, w9, #0xfffffbff
    8020476c:	52800001 	mov	w1, #0x0                   	// #0
    80204770:	52800002 	mov	w2, #0x0                   	// #0
    80204774:	39057fe2 	strb	w2, [sp, #351]
    80204778:	37f80e27 	tbnz	w7, #31, 8020493c <_vfprintf_r+0x113c>
    8020477c:	f100001f 	cmp	x0, #0x0
    80204780:	12187b49 	and	w9, w26, #0xffffff7f
    80204784:	7a4008e0 	ccmp	w7, #0x0, #0x0, eq	// eq = none
    80204788:	54000d81 	b.ne	80204938 <_vfprintf_r+0x1138>  // b.any
    8020478c:	35000c81 	cbnz	w1, 8020491c <_vfprintf_r+0x111c>
    80204790:	12000357 	and	w23, w26, #0x1
    80204794:	36001bba 	tbz	w26, #0, 80204b08 <_vfprintf_r+0x1308>
    80204798:	91082ffb 	add	x27, sp, #0x20b
    8020479c:	52800600 	mov	w0, #0x30                  	// #48
    802047a0:	52800007 	mov	w7, #0x0                   	// #0
    802047a4:	39082fe0 	strb	w0, [sp, #523]
    802047a8:	39457fe1 	ldrb	w1, [sp, #351]
    802047ac:	6b1700ff 	cmp	w7, w23
    802047b0:	b9008bff 	str	wzr, [sp, #136]
    802047b4:	1a97a0fa 	csel	w26, w7, w23, ge	// ge = tcont
    802047b8:	b9009bff 	str	wzr, [sp, #152]
    802047bc:	d2800019 	mov	x25, #0x0                   	// #0
    802047c0:	52800018 	mov	w24, #0x0                   	// #0
    802047c4:	34ff9861 	cbz	w1, 80203ad0 <_vfprintf_r+0x2d0>
    802047c8:	17ffff16 	b	80204420 <_vfprintf_r+0xc20>
    802047cc:	39400348 	ldrb	w8, [x26]
    802047d0:	321d02f7 	orr	w23, w23, #0x8
    802047d4:	17fffca6 	b	80203a6c <_vfprintf_r+0x26c>
    802047d8:	aa1a03ea 	mov	x10, x26
    802047dc:	2a1803eb 	mov	w11, w24
    802047e0:	2a1903e7 	mov	w7, w25
    802047e4:	321c02fa 	orr	w26, w23, #0x10
    802047e8:	b94093e0 	ldr	w0, [sp, #144]
    802047ec:	3728005a 	tbnz	w26, #5, 802047f4 <_vfprintf_r+0xff4>
    802047f0:	3620297a 	tbz	w26, #4, 80204d1c <_vfprintf_r+0x151c>
    802047f4:	37f848e0 	tbnz	w0, #31, 80205110 <_vfprintf_r+0x1910>
    802047f8:	f9403fe0 	ldr	x0, [sp, #120]
    802047fc:	91003c01 	add	x1, x0, #0xf
    80204800:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204804:	f9003fe1 	str	x1, [sp, #120]
    80204808:	f9400000 	ldr	x0, [x0]
    8020480c:	52800021 	mov	w1, #0x1                   	// #1
    80204810:	17ffffd8 	b	80204770 <_vfprintf_r+0xf70>
    80204814:	39400348 	ldrb	w8, [x26]
    80204818:	7101b11f 	cmp	w8, #0x6c
    8020481c:	54003720 	b.eq	80204f00 <_vfprintf_r+0x1700>  // b.none
    80204820:	321c02f7 	orr	w23, w23, #0x10
    80204824:	17fffc92 	b	80203a6c <_vfprintf_r+0x26c>
    80204828:	39400348 	ldrb	w8, [x26]
    8020482c:	7101a11f 	cmp	w8, #0x68
    80204830:	54003700 	b.eq	80204f10 <_vfprintf_r+0x1710>  // b.none
    80204834:	321a02f7 	orr	w23, w23, #0x40
    80204838:	17fffc8d 	b	80203a6c <_vfprintf_r+0x26c>
    8020483c:	39400348 	ldrb	w8, [x26]
    80204840:	321b02f7 	orr	w23, w23, #0x20
    80204844:	17fffc8a 	b	80203a6c <_vfprintf_r+0x26c>
    80204848:	b94093e0 	ldr	w0, [sp, #144]
    8020484c:	2a1703e9 	mov	w9, w23
    80204850:	2a1803eb 	mov	w11, w24
    80204854:	2a1903e7 	mov	w7, w25
    80204858:	aa1a03ea 	mov	x10, x26
    8020485c:	37f82c40 	tbnz	w0, #31, 80204de4 <_vfprintf_r+0x15e4>
    80204860:	f9403fe0 	ldr	x0, [sp, #120]
    80204864:	91003c01 	add	x1, x0, #0xf
    80204868:	927df021 	and	x1, x1, #0xfffffffffffffff8
    8020486c:	f9003fe1 	str	x1, [sp, #120]
    80204870:	f9400000 	ldr	x0, [x0]
    80204874:	528f0602 	mov	w2, #0x7830                	// #30768
    80204878:	90000063 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020487c:	321f013a 	orr	w26, w9, #0x2
    80204880:	91140063 	add	x3, x3, #0x500
    80204884:	52800041 	mov	w1, #0x2                   	// #2
    80204888:	52800f08 	mov	w8, #0x78                  	// #120
    8020488c:	f90073e3 	str	x3, [sp, #224]
    80204890:	7902c3e2 	strh	w2, [sp, #352]
    80204894:	17ffffb7 	b	80204770 <_vfprintf_r+0xf70>
    80204898:	b94093e0 	ldr	w0, [sp, #144]
    8020489c:	2a1703e9 	mov	w9, w23
    802048a0:	aa1a03ea 	mov	x10, x26
    802048a4:	362826e9 	tbz	w9, #5, 80204d80 <_vfprintf_r+0x1580>
    802048a8:	37f86d40 	tbnz	w0, #31, 80205650 <_vfprintf_r+0x1e50>
    802048ac:	f9403fe0 	ldr	x0, [sp, #120]
    802048b0:	91003c01 	add	x1, x0, #0xf
    802048b4:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802048b8:	f9003fe1 	str	x1, [sp, #120]
    802048bc:	f9400000 	ldr	x0, [x0]
    802048c0:	b98077e1 	ldrsw	x1, [sp, #116]
    802048c4:	f9000001 	str	x1, [x0]
    802048c8:	17fffc13 	b	80203914 <_vfprintf_r+0x114>
    802048cc:	2a1803eb 	mov	w11, w24
    802048d0:	2a1903e7 	mov	w7, w25
    802048d4:	aa1a03ea 	mov	x10, x26
    802048d8:	321c02e9 	orr	w9, w23, #0x10
    802048dc:	b94093e0 	ldr	w0, [sp, #144]
    802048e0:	37280049 	tbnz	w9, #5, 802048e8 <_vfprintf_r+0x10e8>
    802048e4:	362022e9 	tbz	w9, #4, 80204d40 <_vfprintf_r+0x1540>
    802048e8:	37f843c0 	tbnz	w0, #31, 80205160 <_vfprintf_r+0x1960>
    802048ec:	f9403fe0 	ldr	x0, [sp, #120]
    802048f0:	91003c01 	add	x1, x0, #0xf
    802048f4:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802048f8:	f9003fe1 	str	x1, [sp, #120]
    802048fc:	f9400001 	ldr	x1, [x0]
    80204900:	aa0103e0 	mov	x0, x1
    80204904:	b7f82301 	tbnz	x1, #63, 80204d64 <_vfprintf_r+0x1564>
    80204908:	37f80ee7 	tbnz	w7, #31, 80204ae4 <_vfprintf_r+0x12e4>
    8020490c:	f100001f 	cmp	x0, #0x0
    80204910:	12187929 	and	w9, w9, #0xffffff7f
    80204914:	7a4008e0 	ccmp	w7, #0x0, #0x0, eq	// eq = none
    80204918:	54000e61 	b.ne	80204ae4 <_vfprintf_r+0x12e4>  // b.any
    8020491c:	910833fb 	add	x27, sp, #0x20c
    80204920:	52800007 	mov	w7, #0x0                   	// #0
    80204924:	52800017 	mov	w23, #0x0                   	// #0
    80204928:	17ffffa0 	b	802047a8 <_vfprintf_r+0xfa8>
    8020492c:	39400348 	ldrb	w8, [x26]
    80204930:	321902f7 	orr	w23, w23, #0x80
    80204934:	17fffc4e 	b	80203a6c <_vfprintf_r+0x26c>
    80204938:	2a0903fa 	mov	w26, w9
    8020493c:	7100043f 	cmp	w1, #0x1
    80204940:	54000d40 	b.eq	80204ae8 <_vfprintf_r+0x12e8>  // b.none
    80204944:	910833f7 	add	x23, sp, #0x20c
    80204948:	aa1703fb 	mov	x27, x23
    8020494c:	7100083f 	cmp	w1, #0x2
    80204950:	54000141 	b.ne	80204978 <_vfprintf_r+0x1178>  // b.any
    80204954:	f94073e2 	ldr	x2, [sp, #224]
    80204958:	92400c01 	and	x1, x0, #0xf
    8020495c:	d344fc00 	lsr	x0, x0, #4
    80204960:	38616841 	ldrb	w1, [x2, x1]
    80204964:	381fff61 	strb	w1, [x27, #-1]!
    80204968:	b5ffff80 	cbnz	x0, 80204958 <_vfprintf_r+0x1158>
    8020496c:	4b1b02f7 	sub	w23, w23, w27
    80204970:	2a1a03e9 	mov	w9, w26
    80204974:	17ffff8d 	b	802047a8 <_vfprintf_r+0xfa8>
    80204978:	12000801 	and	w1, w0, #0x7
    8020497c:	aa1b03e2 	mov	x2, x27
    80204980:	1100c021 	add	w1, w1, #0x30
    80204984:	381fff61 	strb	w1, [x27, #-1]!
    80204988:	d343fc00 	lsr	x0, x0, #3
    8020498c:	b5ffff60 	cbnz	x0, 80204978 <_vfprintf_r+0x1178>
    80204990:	7100c03f 	cmp	w1, #0x30
    80204994:	1a9f07e0 	cset	w0, ne	// ne = any
    80204998:	6a00035f 	tst	w26, w0
    8020499c:	54fffe80 	b.eq	8020496c <_vfprintf_r+0x116c>  // b.none
    802049a0:	d1000842 	sub	x2, x2, #0x2
    802049a4:	52800600 	mov	w0, #0x30                  	// #48
    802049a8:	2a1a03e9 	mov	w9, w26
    802049ac:	4b0202f7 	sub	w23, w23, w2
    802049b0:	381ff360 	sturb	w0, [x27, #-1]
    802049b4:	aa0203fb 	mov	x27, x2
    802049b8:	17ffff7c 	b	802047a8 <_vfprintf_r+0xfa8>
    802049bc:	910643e2 	add	x2, sp, #0x190
    802049c0:	aa1503e1 	mov	x1, x21
    802049c4:	aa1303e0 	mov	x0, x19
    802049c8:	b900bbee 	str	w14, [sp, #184]
    802049cc:	b900c3e9 	str	w9, [sp, #192]
    802049d0:	b900cbe8 	str	w8, [sp, #200]
    802049d4:	b900d3eb 	str	w11, [sp, #208]
    802049d8:	b900dbe7 	str	w7, [sp, #216]
    802049dc:	f9008bea 	str	x10, [sp, #272]
    802049e0:	940008c4 	bl	80206cf0 <__sprint_r>
    802049e4:	35ffb2e0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    802049e8:	f9408bea 	ldr	x10, [sp, #272]
    802049ec:	aa1603fc 	mov	x28, x22
    802049f0:	f940d3e0 	ldr	x0, [sp, #416]
    802049f4:	b940bbee 	ldr	w14, [sp, #184]
    802049f8:	b940c3e9 	ldr	w9, [sp, #192]
    802049fc:	b940cbe8 	ldr	w8, [sp, #200]
    80204a00:	b940d3eb 	ldr	w11, [sp, #208]
    80204a04:	b940dbe7 	ldr	w7, [sp, #216]
    80204a08:	17fffc56 	b	80203b60 <_vfprintf_r+0x360>
    80204a0c:	9000006d 	adrp	x13, 80210000 <__trunctfdf2+0xc0>
    80204a10:	b9419be1 	ldr	w1, [sp, #408]
    80204a14:	912381ad 	add	x13, x13, #0x8e0
    80204a18:	710042ff 	cmp	w23, #0x10
    80204a1c:	540003ed 	b.le	80204a98 <_vfprintf_r+0x1298>
    80204a20:	aa0d03f8 	mov	x24, x13
    80204a24:	d280021b 	mov	x27, #0x10                  	// #16
    80204a28:	b9008beb 	str	w11, [sp, #136]
    80204a2c:	f9004fea 	str	x10, [sp, #152]
    80204a30:	14000004 	b	80204a40 <_vfprintf_r+0x1240>
    80204a34:	510042f7 	sub	w23, w23, #0x10
    80204a38:	710042ff 	cmp	w23, #0x10
    80204a3c:	5400028d 	b.le	80204a8c <_vfprintf_r+0x128c>
    80204a40:	91004000 	add	x0, x0, #0x10
    80204a44:	11000421 	add	w1, w1, #0x1
    80204a48:	a9006f98 	stp	x24, x27, [x28]
    80204a4c:	9100439c 	add	x28, x28, #0x10
    80204a50:	b9019be1 	str	w1, [sp, #408]
    80204a54:	f900d3e0 	str	x0, [sp, #416]
    80204a58:	71001c3f 	cmp	w1, #0x7
    80204a5c:	54fffecd 	b.le	80204a34 <_vfprintf_r+0x1234>
    80204a60:	910643e2 	add	x2, sp, #0x190
    80204a64:	aa1503e1 	mov	x1, x21
    80204a68:	aa1303e0 	mov	x0, x19
    80204a6c:	940008a1 	bl	80206cf0 <__sprint_r>
    80204a70:	35ffae80 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204a74:	510042f7 	sub	w23, w23, #0x10
    80204a78:	b9419be1 	ldr	w1, [sp, #408]
    80204a7c:	f940d3e0 	ldr	x0, [sp, #416]
    80204a80:	aa1603fc 	mov	x28, x22
    80204a84:	710042ff 	cmp	w23, #0x10
    80204a88:	54fffdcc 	b.gt	80204a40 <_vfprintf_r+0x1240>
    80204a8c:	f9404fea 	ldr	x10, [sp, #152]
    80204a90:	aa1803ed 	mov	x13, x24
    80204a94:	b9408beb 	ldr	w11, [sp, #136]
    80204a98:	93407ef7 	sxtw	x23, w23
    80204a9c:	11000421 	add	w1, w1, #0x1
    80204aa0:	8b170000 	add	x0, x0, x23
    80204aa4:	a9005f8d 	stp	x13, x23, [x28]
    80204aa8:	b9019be1 	str	w1, [sp, #408]
    80204aac:	f900d3e0 	str	x0, [sp, #416]
    80204ab0:	71001c3f 	cmp	w1, #0x7
    80204ab4:	54ff87ed 	b.le	80203bb0 <_vfprintf_r+0x3b0>
    80204ab8:	910643e2 	add	x2, sp, #0x190
    80204abc:	aa1503e1 	mov	x1, x21
    80204ac0:	aa1303e0 	mov	x0, x19
    80204ac4:	b9008beb 	str	w11, [sp, #136]
    80204ac8:	f9004fea 	str	x10, [sp, #152]
    80204acc:	94000889 	bl	80206cf0 <__sprint_r>
    80204ad0:	35ffab80 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204ad4:	f9404fea 	ldr	x10, [sp, #152]
    80204ad8:	f940d3e0 	ldr	x0, [sp, #416]
    80204adc:	b9408beb 	ldr	w11, [sp, #136]
    80204ae0:	17fffc34 	b	80203bb0 <_vfprintf_r+0x3b0>
    80204ae4:	2a0903fa 	mov	w26, w9
    80204ae8:	f100241f 	cmp	x0, #0x9
    80204aec:	540054a8 	b.hi	80205580 <_vfprintf_r+0x1d80>  // b.pmore
    80204af0:	1100c000 	add	w0, w0, #0x30
    80204af4:	2a1a03e9 	mov	w9, w26
    80204af8:	91082ffb 	add	x27, sp, #0x20b
    80204afc:	52800037 	mov	w23, #0x1                   	// #1
    80204b00:	39082fe0 	strb	w0, [sp, #523]
    80204b04:	17ffff29 	b	802047a8 <_vfprintf_r+0xfa8>
    80204b08:	910833fb 	add	x27, sp, #0x20c
    80204b0c:	52800007 	mov	w7, #0x0                   	// #0
    80204b10:	17ffff26 	b	802047a8 <_vfprintf_r+0xfa8>
    80204b14:	b94097e1 	ldr	w1, [sp, #148]
    80204b18:	6b01031f 	cmp	w24, w1
    80204b1c:	1a81d317 	csel	w23, w24, w1, le
    80204b20:	93407c2c 	sxtw	x12, w1
    80204b24:	710002ff 	cmp	w23, #0x0
    80204b28:	5400016d 	b.le	80204b54 <_vfprintf_r+0x1354>
    80204b2c:	b9419be1 	ldr	w1, [sp, #408]
    80204b30:	93407ee2 	sxtw	x2, w23
    80204b34:	8b020000 	add	x0, x0, x2
    80204b38:	a9000b9b 	stp	x27, x2, [x28]
    80204b3c:	11000421 	add	w1, w1, #0x1
    80204b40:	b9019be1 	str	w1, [sp, #408]
    80204b44:	9100439c 	add	x28, x28, #0x10
    80204b48:	f900d3e0 	str	x0, [sp, #416]
    80204b4c:	71001c3f 	cmp	w1, #0x7
    80204b50:	5400b3cc 	b.gt	802061c8 <_vfprintf_r+0x29c8>
    80204b54:	710002ff 	cmp	w23, #0x0
    80204b58:	1a9fa2e4 	csel	w4, w23, wzr, ge	// ge = tcont
    80204b5c:	4b040317 	sub	w23, w24, w4
    80204b60:	710002ff 	cmp	w23, #0x0
    80204b64:	5400594c 	b.gt	8020568c <_vfprintf_r+0x1e8c>
    80204b68:	8b38c368 	add	x8, x27, w24, sxtw
    80204b6c:	37509509 	tbnz	w9, #10, 80205e0c <_vfprintf_r+0x260c>
    80204b70:	b94097e1 	ldr	w1, [sp, #148]
    80204b74:	b9416bf7 	ldr	w23, [sp, #360]
    80204b78:	6b0102ff 	cmp	w23, w1
    80204b7c:	5400266b 	b.lt	80205048 <_vfprintf_r+0x1848>  // b.tstop
    80204b80:	37002649 	tbnz	w9, #0, 80205048 <_vfprintf_r+0x1848>
    80204b84:	b94097e1 	ldr	w1, [sp, #148]
    80204b88:	8b0c037b 	add	x27, x27, x12
    80204b8c:	cb08037b 	sub	x27, x27, x8
    80204b90:	4b170037 	sub	w23, w1, w23
    80204b94:	6b1b02ff 	cmp	w23, w27
    80204b98:	1a9bb2fb 	csel	w27, w23, w27, lt	// lt = tstop
    80204b9c:	7100037f 	cmp	w27, #0x0
    80204ba0:	5400016d 	b.le	80204bcc <_vfprintf_r+0x13cc>
    80204ba4:	b9419be1 	ldr	w1, [sp, #408]
    80204ba8:	93407f62 	sxtw	x2, w27
    80204bac:	8b020000 	add	x0, x0, x2
    80204bb0:	a9000b88 	stp	x8, x2, [x28]
    80204bb4:	11000421 	add	w1, w1, #0x1
    80204bb8:	b9019be1 	str	w1, [sp, #408]
    80204bbc:	9100439c 	add	x28, x28, #0x10
    80204bc0:	f900d3e0 	str	x0, [sp, #416]
    80204bc4:	71001c3f 	cmp	w1, #0x7
    80204bc8:	5400b6ec 	b.gt	802062a4 <_vfprintf_r+0x2aa4>
    80204bcc:	7100037f 	cmp	w27, #0x0
    80204bd0:	1a9fa37b 	csel	w27, w27, wzr, ge	// ge = tcont
    80204bd4:	4b1b02f7 	sub	w23, w23, w27
    80204bd8:	710002ff 	cmp	w23, #0x0
    80204bdc:	54ff7e2d 	b.le	80203ba0 <_vfprintf_r+0x3a0>
    80204be0:	90000064 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80204be4:	b9419be1 	ldr	w1, [sp, #408]
    80204be8:	91234084 	add	x4, x4, #0x8d0
    80204bec:	710042ff 	cmp	w23, #0x10
    80204bf0:	54004b4d 	b.le	80205558 <_vfprintf_r+0x1d58>
    80204bf4:	aa1c03e2 	mov	x2, x28
    80204bf8:	aa0403f8 	mov	x24, x4
    80204bfc:	aa0a03fc 	mov	x28, x10
    80204c00:	d280021b 	mov	x27, #0x10                  	// #16
    80204c04:	b9008be9 	str	w9, [sp, #136]
    80204c08:	b9009beb 	str	w11, [sp, #152]
    80204c0c:	14000004 	b	80204c1c <_vfprintf_r+0x141c>
    80204c10:	510042f7 	sub	w23, w23, #0x10
    80204c14:	710042ff 	cmp	w23, #0x10
    80204c18:	5400496d 	b.le	80205544 <_vfprintf_r+0x1d44>
    80204c1c:	91004000 	add	x0, x0, #0x10
    80204c20:	11000421 	add	w1, w1, #0x1
    80204c24:	a9006c58 	stp	x24, x27, [x2]
    80204c28:	91004042 	add	x2, x2, #0x10
    80204c2c:	b9019be1 	str	w1, [sp, #408]
    80204c30:	f900d3e0 	str	x0, [sp, #416]
    80204c34:	71001c3f 	cmp	w1, #0x7
    80204c38:	54fffecd 	b.le	80204c10 <_vfprintf_r+0x1410>
    80204c3c:	910643e2 	add	x2, sp, #0x190
    80204c40:	aa1503e1 	mov	x1, x21
    80204c44:	aa1303e0 	mov	x0, x19
    80204c48:	9400082a 	bl	80206cf0 <__sprint_r>
    80204c4c:	35ff9fa0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204c50:	f940d3e0 	ldr	x0, [sp, #416]
    80204c54:	aa1603e2 	mov	x2, x22
    80204c58:	b9419be1 	ldr	w1, [sp, #408]
    80204c5c:	17ffffed 	b	80204c10 <_vfprintf_r+0x1410>
    80204c60:	910643e2 	add	x2, sp, #0x190
    80204c64:	aa1503e1 	mov	x1, x21
    80204c68:	aa1303e0 	mov	x0, x19
    80204c6c:	b9008be9 	str	w9, [sp, #136]
    80204c70:	b9009beb 	str	w11, [sp, #152]
    80204c74:	f9005fea 	str	x10, [sp, #184]
    80204c78:	9400081e 	bl	80206cf0 <__sprint_r>
    80204c7c:	35ff9e20 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204c80:	f9405fea 	ldr	x10, [sp, #184]
    80204c84:	aa1603e2 	mov	x2, x22
    80204c88:	f940d3e0 	ldr	x0, [sp, #416]
    80204c8c:	b9408be9 	ldr	w9, [sp, #136]
    80204c90:	b9409beb 	ldr	w11, [sp, #152]
    80204c94:	b9419be1 	ldr	w1, [sp, #408]
    80204c98:	17fffd5f 	b	80204214 <_vfprintf_r+0xa14>
    80204c9c:	910643e2 	add	x2, sp, #0x190
    80204ca0:	aa1503e1 	mov	x1, x21
    80204ca4:	aa1303e0 	mov	x0, x19
    80204ca8:	b9008be9 	str	w9, [sp, #136]
    80204cac:	b9009beb 	str	w11, [sp, #152]
    80204cb0:	f9005fea 	str	x10, [sp, #184]
    80204cb4:	9400080f 	bl	80206cf0 <__sprint_r>
    80204cb8:	35ff9c40 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204cbc:	1e602108 	fcmp	d8, #0.0
    80204cc0:	b94097e3 	ldr	w3, [sp, #148]
    80204cc4:	f9405fea 	ldr	x10, [sp, #184]
    80204cc8:	aa1603e2 	mov	x2, x22
    80204ccc:	f940d3e0 	ldr	x0, [sp, #416]
    80204cd0:	51000477 	sub	w23, w3, #0x1
    80204cd4:	b9408be9 	ldr	w9, [sp, #136]
    80204cd8:	b9409beb 	ldr	w11, [sp, #152]
    80204cdc:	b9419be1 	ldr	w1, [sp, #408]
    80204ce0:	54ffbd00 	b.eq	80204480 <_vfprintf_r+0xc80>  // b.none
    80204ce4:	17fffd59 	b	80204248 <_vfprintf_r+0xa48>
    80204ce8:	f94052a0 	ldr	x0, [x21, #160]
    80204cec:	940011b5 	bl	802093c0 <__retarget_lock_acquire_recursive>
    80204cf0:	79c022a0 	ldrsh	w0, [x21, #16]
    80204cf4:	17fffae7 	b	80203890 <_vfprintf_r+0x90>
    80204cf8:	36077549 	tbz	w9, #0, 80203ba0 <_vfprintf_r+0x3a0>
    80204cfc:	17fffc23 	b	80203d88 <_vfprintf_r+0x588>
    80204d00:	37f88700 	tbnz	w0, #31, 80205de0 <_vfprintf_r+0x25e0>
    80204d04:	f9403fe0 	ldr	x0, [sp, #120]
    80204d08:	91003c01 	add	x1, x0, #0xf
    80204d0c:	fd400008 	ldr	d8, [x0]
    80204d10:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204d14:	f9003fe1 	str	x1, [sp, #120]
    80204d18:	17fffdaa 	b	802043c0 <_vfprintf_r+0xbc0>
    80204d1c:	36304ffa 	tbz	w26, #6, 80205718 <_vfprintf_r+0x1f18>
    80204d20:	37f87920 	tbnz	w0, #31, 80205c44 <_vfprintf_r+0x2444>
    80204d24:	f9403fe0 	ldr	x0, [sp, #120]
    80204d28:	91002c01 	add	x1, x0, #0xb
    80204d2c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204d30:	f9003fe1 	str	x1, [sp, #120]
    80204d34:	79400000 	ldrh	w0, [x0]
    80204d38:	52800021 	mov	w1, #0x1                   	// #1
    80204d3c:	17fffe8d 	b	80204770 <_vfprintf_r+0xf70>
    80204d40:	36305509 	tbz	w9, #6, 802057e0 <_vfprintf_r+0x1fe0>
    80204d44:	37f87260 	tbnz	w0, #31, 80205b90 <_vfprintf_r+0x2390>
    80204d48:	f9403fe0 	ldr	x0, [sp, #120]
    80204d4c:	91002c01 	add	x1, x0, #0xb
    80204d50:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204d54:	f9003fe1 	str	x1, [sp, #120]
    80204d58:	79800000 	ldrsh	x0, [x0]
    80204d5c:	aa0003e1 	mov	x1, x0
    80204d60:	b6ffdd41 	tbz	x1, #63, 80204908 <_vfprintf_r+0x1108>
    80204d64:	cb0003e0 	neg	x0, x0
    80204d68:	2a0903fa 	mov	w26, w9
    80204d6c:	528005a2 	mov	w2, #0x2d                  	// #45
    80204d70:	52800021 	mov	w1, #0x1                   	// #1
    80204d74:	17fffe80 	b	80204774 <_vfprintf_r+0xf74>
    80204d78:	39400348 	ldrb	w8, [x26]
    80204d7c:	17fffb3c 	b	80203a6c <_vfprintf_r+0x26c>
    80204d80:	3727d949 	tbnz	w9, #4, 802048a8 <_vfprintf_r+0x10a8>
    80204d84:	37306b89 	tbnz	w9, #6, 80205af4 <_vfprintf_r+0x22f4>
    80204d88:	3648bba9 	tbz	w9, #9, 802064fc <_vfprintf_r+0x2cfc>
    80204d8c:	37f8d6e0 	tbnz	w0, #31, 80206868 <_vfprintf_r+0x3068>
    80204d90:	f9403fe0 	ldr	x0, [sp, #120]
    80204d94:	91003c01 	add	x1, x0, #0xf
    80204d98:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204d9c:	f9003fe1 	str	x1, [sp, #120]
    80204da0:	f9400000 	ldr	x0, [x0]
    80204da4:	3941d3e1 	ldrb	w1, [sp, #116]
    80204da8:	39000001 	strb	w1, [x0]
    80204dac:	17fffada 	b	80203914 <_vfprintf_r+0x114>
    80204db0:	36304c69 	tbz	w9, #6, 8020573c <_vfprintf_r+0x1f3c>
    80204db4:	37f870c0 	tbnz	w0, #31, 80205bcc <_vfprintf_r+0x23cc>
    80204db8:	f9403fe0 	ldr	x0, [sp, #120]
    80204dbc:	91002c01 	add	x1, x0, #0xb
    80204dc0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204dc4:	79400000 	ldrh	w0, [x0]
    80204dc8:	f9003fe1 	str	x1, [sp, #120]
    80204dcc:	17fffe67 	b	80204768 <_vfprintf_r+0xf68>
    80204dd0:	2a1703e9 	mov	w9, w23
    80204dd4:	2a1803eb 	mov	w11, w24
    80204dd8:	2a1903e7 	mov	w7, w25
    80204ddc:	aa1a03ea 	mov	x10, x26
    80204de0:	17fffebf 	b	802048dc <_vfprintf_r+0x10dc>
    80204de4:	b94093e0 	ldr	w0, [sp, #144]
    80204de8:	11002001 	add	w1, w0, #0x8
    80204dec:	7100003f 	cmp	w1, #0x0
    80204df0:	54009e2d 	b.le	802061b4 <_vfprintf_r+0x29b4>
    80204df4:	f9403fe0 	ldr	x0, [sp, #120]
    80204df8:	b90093e1 	str	w1, [sp, #144]
    80204dfc:	91003c02 	add	x2, x0, #0xf
    80204e00:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80204e04:	f9003fe1 	str	x1, [sp, #120]
    80204e08:	17fffe9a 	b	80204870 <_vfprintf_r+0x1070>
    80204e0c:	b94093e0 	ldr	w0, [sp, #144]
    80204e10:	11002001 	add	w1, w0, #0x8
    80204e14:	7100003f 	cmp	w1, #0x0
    80204e18:	54009c4d 	b.le	802061a0 <_vfprintf_r+0x29a0>
    80204e1c:	f9403fe0 	ldr	x0, [sp, #120]
    80204e20:	b90093e1 	str	w1, [sp, #144]
    80204e24:	91003c02 	add	x2, x0, #0xf
    80204e28:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80204e2c:	f9003fe1 	str	x1, [sp, #120]
    80204e30:	17fffdd9 	b	80204594 <_vfprintf_r+0xd94>
    80204e34:	b94093e0 	ldr	w0, [sp, #144]
    80204e38:	11002001 	add	w1, w0, #0x8
    80204e3c:	7100003f 	cmp	w1, #0x0
    80204e40:	54009a2d 	b.le	80206184 <_vfprintf_r+0x2984>
    80204e44:	f9403fe0 	ldr	x0, [sp, #120]
    80204e48:	b90093e1 	str	w1, [sp, #144]
    80204e4c:	91002c00 	add	x0, x0, #0xb
    80204e50:	927df000 	and	x0, x0, #0xfffffffffffffff8
    80204e54:	17fffe14 	b	802046a4 <_vfprintf_r+0xea4>
    80204e58:	f9404fea 	ldr	x10, [sp, #152]
    80204e5c:	2a1c03eb 	mov	w11, w28
    80204e60:	b9408be9 	ldr	w9, [sp, #136]
    80204e64:	aa1803e4 	mov	x4, x24
    80204e68:	93407ef7 	sxtw	x23, w23
    80204e6c:	11000421 	add	w1, w1, #0x1
    80204e70:	8b170000 	add	x0, x0, x23
    80204e74:	b9019be1 	str	w1, [sp, #408]
    80204e78:	f900d3e0 	str	x0, [sp, #416]
    80204e7c:	f9000044 	str	x4, [x2]
    80204e80:	f9000457 	str	x23, [x2, #8]
    80204e84:	71001c3f 	cmp	w1, #0x7
    80204e88:	54ff9f4d 	b.le	80204270 <_vfprintf_r+0xa70>
    80204e8c:	910643e2 	add	x2, sp, #0x190
    80204e90:	aa1503e1 	mov	x1, x21
    80204e94:	aa1303e0 	mov	x0, x19
    80204e98:	b9008be9 	str	w9, [sp, #136]
    80204e9c:	b9009beb 	str	w11, [sp, #152]
    80204ea0:	f9005fea 	str	x10, [sp, #184]
    80204ea4:	94000793 	bl	80206cf0 <__sprint_r>
    80204ea8:	35ff8cc0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204eac:	f9405fea 	ldr	x10, [sp, #184]
    80204eb0:	aa1603e2 	mov	x2, x22
    80204eb4:	f940d3e0 	ldr	x0, [sp, #416]
    80204eb8:	b9408be9 	ldr	w9, [sp, #136]
    80204ebc:	b9409beb 	ldr	w11, [sp, #152]
    80204ec0:	b9419be1 	ldr	w1, [sp, #408]
    80204ec4:	17fffcec 	b	80204274 <_vfprintf_r+0xa74>
    80204ec8:	910643e2 	add	x2, sp, #0x190
    80204ecc:	aa1503e1 	mov	x1, x21
    80204ed0:	aa1303e0 	mov	x0, x19
    80204ed4:	b9008be9 	str	w9, [sp, #136]
    80204ed8:	b9009beb 	str	w11, [sp, #152]
    80204edc:	f9005fea 	str	x10, [sp, #184]
    80204ee0:	94000784 	bl	80206cf0 <__sprint_r>
    80204ee4:	35ff8ae0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80204ee8:	f9405fea 	ldr	x10, [sp, #184]
    80204eec:	aa1603fc 	mov	x28, x22
    80204ef0:	f940d3e0 	ldr	x0, [sp, #416]
    80204ef4:	b9408be9 	ldr	w9, [sp, #136]
    80204ef8:	b9409beb 	ldr	w11, [sp, #152]
    80204efc:	17fffbad 	b	80203db0 <_vfprintf_r+0x5b0>
    80204f00:	39400748 	ldrb	w8, [x26, #1]
    80204f04:	321b02f7 	orr	w23, w23, #0x20
    80204f08:	9100075a 	add	x26, x26, #0x1
    80204f0c:	17fffad8 	b	80203a6c <_vfprintf_r+0x26c>
    80204f10:	39400748 	ldrb	w8, [x26, #1]
    80204f14:	321702f7 	orr	w23, w23, #0x200
    80204f18:	9100075a 	add	x26, x26, #0x1
    80204f1c:	17fffad4 	b	80203a6c <_vfprintf_r+0x26c>
    80204f20:	aa1a03ea 	mov	x10, x26
    80204f24:	2a1803eb 	mov	w11, w24
    80204f28:	2a1903e7 	mov	w7, w25
    80204f2c:	2a1703fa 	mov	w26, w23
    80204f30:	17fffe2e 	b	802047e8 <_vfprintf_r+0xfe8>
    80204f34:	2a1703e9 	mov	w9, w23
    80204f38:	2a1803eb 	mov	w11, w24
    80204f3c:	2a1903e7 	mov	w7, w25
    80204f40:	aa1a03ea 	mov	x10, x26
    80204f44:	90000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80204f48:	91146000 	add	x0, x0, #0x518
    80204f4c:	f90073e0 	str	x0, [sp, #224]
    80204f50:	b94093e0 	ldr	w0, [sp, #144]
    80204f54:	37280b09 	tbnz	w9, #5, 802050b4 <_vfprintf_r+0x18b4>
    80204f58:	37200ae9 	tbnz	w9, #4, 802050b4 <_vfprintf_r+0x18b4>
    80204f5c:	36304149 	tbz	w9, #6, 80205784 <_vfprintf_r+0x1f84>
    80204f60:	37f86860 	tbnz	w0, #31, 80205c6c <_vfprintf_r+0x246c>
    80204f64:	f9403fe0 	ldr	x0, [sp, #120]
    80204f68:	91002c01 	add	x1, x0, #0xb
    80204f6c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204f70:	79400000 	ldrh	w0, [x0]
    80204f74:	f9003fe1 	str	x1, [sp, #120]
    80204f78:	14000055 	b	802050cc <_vfprintf_r+0x18cc>
    80204f7c:	90000060 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80204f80:	2a1703e9 	mov	w9, w23
    80204f84:	91140000 	add	x0, x0, #0x500
    80204f88:	2a1803eb 	mov	w11, w24
    80204f8c:	2a1903e7 	mov	w7, w25
    80204f90:	aa1a03ea 	mov	x10, x26
    80204f94:	f90073e0 	str	x0, [sp, #224]
    80204f98:	17ffffee 	b	80204f50 <_vfprintf_r+0x1750>
    80204f9c:	2a1703e9 	mov	w9, w23
    80204fa0:	2a1803eb 	mov	w11, w24
    80204fa4:	2a1903e7 	mov	w7, w25
    80204fa8:	aa1a03ea 	mov	x10, x26
    80204fac:	17fffde6 	b	80204744 <_vfprintf_r+0xf44>
    80204fb0:	910623e0 	add	x0, sp, #0x188
    80204fb4:	d2800102 	mov	x2, #0x8                   	// #8
    80204fb8:	52800001 	mov	w1, #0x0                   	// #0
    80204fbc:	b9008be9 	str	w9, [sp, #136]
    80204fc0:	b9009be8 	str	w8, [sp, #152]
    80204fc4:	b900bbeb 	str	w11, [sp, #184]
    80204fc8:	f90063ea 	str	x10, [sp, #192]
    80204fcc:	97fff7bd 	bl	80202ec0 <memset>
    80204fd0:	b94093e0 	ldr	w0, [sp, #144]
    80204fd4:	f94063ea 	ldr	x10, [sp, #192]
    80204fd8:	b9408be9 	ldr	w9, [sp, #136]
    80204fdc:	b9409be8 	ldr	w8, [sp, #152]
    80204fe0:	b940bbeb 	ldr	w11, [sp, #184]
    80204fe4:	37f83ea0 	tbnz	w0, #31, 802057b8 <_vfprintf_r+0x1fb8>
    80204fe8:	f9403fe0 	ldr	x0, [sp, #120]
    80204fec:	91002c01 	add	x1, x0, #0xb
    80204ff0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204ff4:	f9003fe1 	str	x1, [sp, #120]
    80204ff8:	b9400002 	ldr	w2, [x0]
    80204ffc:	9106a3f8 	add	x24, sp, #0x1a8
    80205000:	910623e3 	add	x3, sp, #0x188
    80205004:	aa1803e1 	mov	x1, x24
    80205008:	aa1303e0 	mov	x0, x19
    8020500c:	b9008be9 	str	w9, [sp, #136]
    80205010:	b9009be8 	str	w8, [sp, #152]
    80205014:	b900bbeb 	str	w11, [sp, #184]
    80205018:	f90063ea 	str	x10, [sp, #192]
    8020501c:	94001089 	bl	80209240 <_wcrtomb_r>
    80205020:	f94063ea 	ldr	x10, [sp, #192]
    80205024:	2a0003f7 	mov	w23, w0
    80205028:	b9408be9 	ldr	w9, [sp, #136]
    8020502c:	3100041f 	cmn	w0, #0x1
    80205030:	b9409be8 	ldr	w8, [sp, #152]
    80205034:	b940bbeb 	ldr	w11, [sp, #184]
    80205038:	5400c9a0 	b.eq	8020696c <_vfprintf_r+0x316c>  // b.none
    8020503c:	7100001f 	cmp	w0, #0x0
    80205040:	1a9fa01a 	csel	w26, w0, wzr, ge	// ge = tcont
    80205044:	17fffd41 	b	80204548 <_vfprintf_r+0xd48>
    80205048:	a94a8fe2 	ldp	x2, x3, [sp, #168]
    8020504c:	a9000b83 	stp	x3, x2, [x28]
    80205050:	b9419be1 	ldr	w1, [sp, #408]
    80205054:	9100439c 	add	x28, x28, #0x10
    80205058:	11000421 	add	w1, w1, #0x1
    8020505c:	b9019be1 	str	w1, [sp, #408]
    80205060:	8b020000 	add	x0, x0, x2
    80205064:	f900d3e0 	str	x0, [sp, #416]
    80205068:	71001c3f 	cmp	w1, #0x7
    8020506c:	54ffd8cd 	b.le	80204b84 <_vfprintf_r+0x1384>
    80205070:	910643e2 	add	x2, sp, #0x190
    80205074:	aa1503e1 	mov	x1, x21
    80205078:	aa1303e0 	mov	x0, x19
    8020507c:	f90047ec 	str	x12, [sp, #136]
    80205080:	b9009be9 	str	w9, [sp, #152]
    80205084:	b900bbeb 	str	w11, [sp, #184]
    80205088:	a90c2be8 	stp	x8, x10, [sp, #192]
    8020508c:	94000719 	bl	80206cf0 <__sprint_r>
    80205090:	35ff7d80 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80205094:	f94047ec 	ldr	x12, [sp, #136]
    80205098:	aa1603fc 	mov	x28, x22
    8020509c:	a94c2be8 	ldp	x8, x10, [sp, #192]
    802050a0:	f940d3e0 	ldr	x0, [sp, #416]
    802050a4:	b9409be9 	ldr	w9, [sp, #152]
    802050a8:	b940bbeb 	ldr	w11, [sp, #184]
    802050ac:	b9416bf7 	ldr	w23, [sp, #360]
    802050b0:	17fffeb5 	b	80204b84 <_vfprintf_r+0x1384>
    802050b4:	37f801a0 	tbnz	w0, #31, 802050e8 <_vfprintf_r+0x18e8>
    802050b8:	f9403fe0 	ldr	x0, [sp, #120]
    802050bc:	91003c01 	add	x1, x0, #0xf
    802050c0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802050c4:	f9003fe1 	str	x1, [sp, #120]
    802050c8:	f9400000 	ldr	x0, [x0]
    802050cc:	f100001f 	cmp	x0, #0x0
    802050d0:	1a9f07e1 	cset	w1, ne	// ne = any
    802050d4:	6a01013f 	tst	w9, w1
    802050d8:	540014c1 	b.ne	80205370 <_vfprintf_r+0x1b70>  // b.any
    802050dc:	1215793a 	and	w26, w9, #0xfffffbff
    802050e0:	52800041 	mov	w1, #0x2                   	// #2
    802050e4:	17fffda3 	b	80204770 <_vfprintf_r+0xf70>
    802050e8:	b94093e0 	ldr	w0, [sp, #144]
    802050ec:	11002001 	add	w1, w0, #0x8
    802050f0:	7100003f 	cmp	w1, #0x0
    802050f4:	5400388d 	b.le	80205804 <_vfprintf_r+0x2004>
    802050f8:	f9403fe0 	ldr	x0, [sp, #120]
    802050fc:	b90093e1 	str	w1, [sp, #144]
    80205100:	91003c02 	add	x2, x0, #0xf
    80205104:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205108:	f9003fe1 	str	x1, [sp, #120]
    8020510c:	17ffffef 	b	802050c8 <_vfprintf_r+0x18c8>
    80205110:	b94093e0 	ldr	w0, [sp, #144]
    80205114:	11002001 	add	w1, w0, #0x8
    80205118:	7100003f 	cmp	w1, #0x0
    8020511c:	540032ad 	b.le	80205770 <_vfprintf_r+0x1f70>
    80205120:	f9403fe0 	ldr	x0, [sp, #120]
    80205124:	b90093e1 	str	w1, [sp, #144]
    80205128:	91003c02 	add	x2, x0, #0xf
    8020512c:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205130:	f9003fe1 	str	x1, [sp, #120]
    80205134:	17fffdb5 	b	80204808 <_vfprintf_r+0x1008>
    80205138:	b94093e0 	ldr	w0, [sp, #144]
    8020513c:	11002001 	add	w1, w0, #0x8
    80205140:	7100003f 	cmp	w1, #0x0
    80205144:	5400330d 	b.le	802057a4 <_vfprintf_r+0x1fa4>
    80205148:	f9403fe0 	ldr	x0, [sp, #120]
    8020514c:	b90093e1 	str	w1, [sp, #144]
    80205150:	91003c02 	add	x2, x0, #0xf
    80205154:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205158:	f9003fe1 	str	x1, [sp, #120]
    8020515c:	17fffd82 	b	80204764 <_vfprintf_r+0xf64>
    80205160:	b94093e0 	ldr	w0, [sp, #144]
    80205164:	11002001 	add	w1, w0, #0x8
    80205168:	7100003f 	cmp	w1, #0x0
    8020516c:	54002f8d 	b.le	8020575c <_vfprintf_r+0x1f5c>
    80205170:	f9403fe0 	ldr	x0, [sp, #120]
    80205174:	b90093e1 	str	w1, [sp, #144]
    80205178:	91003c02 	add	x2, x0, #0xf
    8020517c:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205180:	f9003fe1 	str	x1, [sp, #120]
    80205184:	17fffdde 	b	802048fc <_vfprintf_r+0x10fc>
    80205188:	910643e2 	add	x2, sp, #0x190
    8020518c:	aa1503e1 	mov	x1, x21
    80205190:	aa1303e0 	mov	x0, x19
    80205194:	b900bbf2 	str	w18, [sp, #184]
    80205198:	b900c3ee 	str	w14, [sp, #192]
    8020519c:	b900cbe9 	str	w9, [sp, #200]
    802051a0:	b900d3e8 	str	w8, [sp, #208]
    802051a4:	b900dbeb 	str	w11, [sp, #216]
    802051a8:	b90113e7 	str	w7, [sp, #272]
    802051ac:	f9008fea 	str	x10, [sp, #280]
    802051b0:	940006d0 	bl	80206cf0 <__sprint_r>
    802051b4:	35ff7460 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    802051b8:	f9408fea 	ldr	x10, [sp, #280]
    802051bc:	aa1603fc 	mov	x28, x22
    802051c0:	f940d3e0 	ldr	x0, [sp, #416]
    802051c4:	39457fe1 	ldrb	w1, [sp, #351]
    802051c8:	b940bbf2 	ldr	w18, [sp, #184]
    802051cc:	b940c3ee 	ldr	w14, [sp, #192]
    802051d0:	b940cbe9 	ldr	w9, [sp, #200]
    802051d4:	b940d3e8 	ldr	w8, [sp, #208]
    802051d8:	b940dbeb 	ldr	w11, [sp, #216]
    802051dc:	b94113e7 	ldr	w7, [sp, #272]
    802051e0:	17fffa46 	b	80203af8 <_vfprintf_r+0x2f8>
    802051e4:	aa1303e0 	mov	x0, x19
    802051e8:	97fff6fa 	bl	80202dd0 <__sinit>
    802051ec:	17fff9a5 	b	80203880 <_vfprintf_r+0x80>
    802051f0:	1e682100 	fcmp	d8, d8
    802051f4:	54009ce6 	b.vs	80206590 <_vfprintf_r+0x2d90>
    802051f8:	121a7917 	and	w23, w8, #0xffffffdf
    802051fc:	710106ff 	cmp	w23, #0x41
    80205200:	540030c1 	b.ne	80205818 <_vfprintf_r+0x2018>  // b.any
    80205204:	52800f01 	mov	w1, #0x78                  	// #120
    80205208:	7101851f 	cmp	w8, #0x61
    8020520c:	52800b00 	mov	w0, #0x58                  	// #88
    80205210:	1a811000 	csel	w0, w0, w1, ne	// ne = any
    80205214:	52800601 	mov	w1, #0x30                  	// #48
    80205218:	390583e1 	strb	w1, [sp, #352]
    8020521c:	390587e0 	strb	w0, [sp, #353]
    80205220:	9106a3fb 	add	x27, sp, #0x1a8
    80205224:	d2800019 	mov	x25, #0x0                   	// #0
    80205228:	71018cff 	cmp	w7, #0x63
    8020522c:	540054ec 	b.gt	80205cc8 <_vfprintf_r+0x24c8>
    80205230:	9e660100 	fmov	x0, d8
    80205234:	d360fc00 	lsr	x0, x0, #32
    80205238:	36f85420 	tbz	w0, #31, 80205cbc <_vfprintf_r+0x24bc>
    8020523c:	1e614100 	fneg	d0, d8
    80205240:	528005a0 	mov	w0, #0x2d                  	// #45
    80205244:	b900bbe0 	str	w0, [sp, #184]
    80205248:	9105a3e0 	add	x0, sp, #0x168
    8020524c:	b9008be9 	str	w9, [sp, #136]
    80205250:	2912afe8 	stp	w8, w11, [sp, #148]
    80205254:	f90063ea 	str	x10, [sp, #192]
    80205258:	b900f3e7 	str	w7, [sp, #240]
    8020525c:	94001ba5 	bl	8020c0f0 <frexp>
    80205260:	1e681001 	fmov	d1, #1.250000000000000000e-01
    80205264:	b9408be9 	ldr	w9, [sp, #136]
    80205268:	f94063ea 	ldr	x10, [sp, #192]
    8020526c:	1e610801 	fmul	d1, d0, d1
    80205270:	2952afe8 	ldp	w8, w11, [sp, #148]
    80205274:	b940f3e7 	ldr	w7, [sp, #240]
    80205278:	1e602028 	fcmp	d1, #0.0
    8020527c:	54000061 	b.ne	80205288 <_vfprintf_r+0x1a88>  // b.any
    80205280:	52800020 	mov	w0, #0x1                   	// #1
    80205284:	b9016be0 	str	w0, [sp, #360]
    80205288:	2a0703e3 	mov	w3, w7
    8020528c:	7101851f 	cmp	w8, #0x61
    80205290:	91000463 	add	x3, x3, #0x1
    80205294:	f0000040 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80205298:	f0000042 	adrp	x2, 80210000 <__trunctfdf2+0xc0>
    8020529c:	91140000 	add	x0, x0, #0x500
    802052a0:	91146042 	add	x2, x2, #0x518
    802052a4:	8b030363 	add	x3, x27, x3
    802052a8:	9a801042 	csel	x2, x2, x0, ne	// ne = any
    802052ac:	1e661002 	fmov	d2, #1.600000000000000000e+01
    802052b0:	aa1b03e0 	mov	x0, x27
    802052b4:	14000003 	b	802052c0 <_vfprintf_r+0x1ac0>
    802052b8:	1e602028 	fcmp	d1, #0.0
    802052bc:	54009920 	b.eq	802065e0 <_vfprintf_r+0x2de0>  // b.none
    802052c0:	1e620821 	fmul	d1, d1, d2
    802052c4:	aa0003ec 	mov	x12, x0
    802052c8:	1e780021 	fcvtzs	w1, d1
    802052cc:	1e620020 	scvtf	d0, w1
    802052d0:	3861c844 	ldrb	w4, [x2, w1, sxtw]
    802052d4:	38001404 	strb	w4, [x0], #1
    802052d8:	1e603821 	fsub	d1, d1, d0
    802052dc:	eb00007f 	cmp	x3, x0
    802052e0:	54fffec1 	b.ne	802052b8 <_vfprintf_r+0x1ab8>  // b.any
    802052e4:	1e6c1000 	fmov	d0, #5.000000000000000000e-01
    802052e8:	1e602030 	fcmpe	d1, d0
    802052ec:	5400008c 	b.gt	802052fc <_vfprintf_r+0x1afc>
    802052f0:	1e602020 	fcmp	d1, d0
    802052f4:	540002a1 	b.ne	80205348 <_vfprintf_r+0x1b48>  // b.any
    802052f8:	36000281 	tbz	w1, #0, 80205348 <_vfprintf_r+0x1b48>
    802052fc:	f900c7ec 	str	x12, [sp, #392]
    80205300:	aa0003e1 	mov	x1, x0
    80205304:	39403c44 	ldrb	w4, [x2, #15]
    80205308:	385ff003 	ldurb	w3, [x0, #-1]
    8020530c:	6b04007f 	cmp	w3, w4
    80205310:	54000121 	b.ne	80205334 <_vfprintf_r+0x1b34>  // b.any
    80205314:	52800607 	mov	w7, #0x30                  	// #48
    80205318:	381ff027 	sturb	w7, [x1, #-1]
    8020531c:	f940c7e1 	ldr	x1, [sp, #392]
    80205320:	d1000423 	sub	x3, x1, #0x1
    80205324:	f900c7e3 	str	x3, [sp, #392]
    80205328:	385ff023 	ldurb	w3, [x1, #-1]
    8020532c:	6b03009f 	cmp	w4, w3
    80205330:	54ffff40 	b.eq	80205318 <_vfprintf_r+0x1b18>  // b.none
    80205334:	11000464 	add	w4, w3, #0x1
    80205338:	12001c84 	and	w4, w4, #0xff
    8020533c:	7100e47f 	cmp	w3, #0x39
    80205340:	54004e80 	b.eq	80205d10 <_vfprintf_r+0x2510>  // b.none
    80205344:	381ff024 	sturb	w4, [x1, #-1]
    80205348:	b9416bf8 	ldr	w24, [sp, #360]
    8020534c:	4b1b0000 	sub	w0, w0, w27
    80205350:	11003d01 	add	w1, w8, #0xf
    80205354:	321f0129 	orr	w9, w9, #0x2
    80205358:	12001c21 	and	w1, w1, #0xff
    8020535c:	52800022 	mov	w2, #0x1                   	// #1
    80205360:	b90097e0 	str	w0, [sp, #148]
    80205364:	51000700 	sub	w0, w24, #0x1
    80205368:	b9016be0 	str	w0, [sp, #360]
    8020536c:	14000167 	b	80205908 <_vfprintf_r+0x2108>
    80205370:	52800601 	mov	w1, #0x30                  	// #48
    80205374:	321f0129 	orr	w9, w9, #0x2
    80205378:	390583e1 	strb	w1, [sp, #352]
    8020537c:	390587e8 	strb	w8, [sp, #353]
    80205380:	17ffff57 	b	802050dc <_vfprintf_r+0x18dc>
    80205384:	910643e2 	add	x2, sp, #0x190
    80205388:	aa1503e1 	mov	x1, x21
    8020538c:	aa1303e0 	mov	x0, x19
    80205390:	b9008be9 	str	w9, [sp, #136]
    80205394:	b9009beb 	str	w11, [sp, #152]
    80205398:	f9005fea 	str	x10, [sp, #184]
    8020539c:	94000655 	bl	80206cf0 <__sprint_r>
    802053a0:	35ff6500 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    802053a4:	f9405fea 	ldr	x10, [sp, #184]
    802053a8:	aa1603fc 	mov	x28, x22
    802053ac:	f940d3e0 	ldr	x0, [sp, #416]
    802053b0:	b9408be9 	ldr	w9, [sp, #136]
    802053b4:	b9409beb 	ldr	w11, [sp, #152]
    802053b8:	17fffa70 	b	80203d78 <_vfprintf_r+0x578>
    802053bc:	910603e0 	add	x0, sp, #0x180
    802053c0:	d2800102 	mov	x2, #0x8                   	// #8
    802053c4:	52800001 	mov	w1, #0x0                   	// #0
    802053c8:	b9008be9 	str	w9, [sp, #136]
    802053cc:	b9009be8 	str	w8, [sp, #152]
    802053d0:	b900bbeb 	str	w11, [sp, #184]
    802053d4:	b900c3e7 	str	w7, [sp, #192]
    802053d8:	f90067ea 	str	x10, [sp, #200]
    802053dc:	f900c7fb 	str	x27, [sp, #392]
    802053e0:	97fff6b8 	bl	80202ec0 <memset>
    802053e4:	b940c3e7 	ldr	w7, [sp, #192]
    802053e8:	f94067ea 	ldr	x10, [sp, #200]
    802053ec:	b9408be9 	ldr	w9, [sp, #136]
    802053f0:	b9409be8 	ldr	w8, [sp, #152]
    802053f4:	b940bbeb 	ldr	w11, [sp, #184]
    802053f8:	37f84b07 	tbnz	w7, #31, 80205d58 <_vfprintf_r+0x2558>
    802053fc:	d2800018 	mov	x24, #0x0                   	// #0
    80205400:	52800017 	mov	w23, #0x0                   	// #0
    80205404:	2a0803fa 	mov	w26, w8
    80205408:	2a0703f9 	mov	w25, w7
    8020540c:	f90047f5 	str	x21, [sp, #136]
    80205410:	2a1703f5 	mov	w21, w23
    80205414:	aa1803f7 	mov	x23, x24
    80205418:	aa0a03f8 	mov	x24, x10
    8020541c:	b9009be9 	str	w9, [sp, #152]
    80205420:	b900bbeb 	str	w11, [sp, #184]
    80205424:	1400000d 	b	80205458 <_vfprintf_r+0x1c58>
    80205428:	910603e3 	add	x3, sp, #0x180
    8020542c:	9106a3e1 	add	x1, sp, #0x1a8
    80205430:	aa1303e0 	mov	x0, x19
    80205434:	94000f83 	bl	80209240 <_wcrtomb_r>
    80205438:	3100041f 	cmn	w0, #0x1
    8020543c:	54008520 	b.eq	802064e0 <_vfprintf_r+0x2ce0>  // b.none
    80205440:	0b0002a0 	add	w0, w21, w0
    80205444:	6b19001f 	cmp	w0, w25
    80205448:	540000ec 	b.gt	80205464 <_vfprintf_r+0x1c64>
    8020544c:	910012f7 	add	x23, x23, #0x4
    80205450:	54009320 	b.eq	802066b4 <_vfprintf_r+0x2eb4>  // b.none
    80205454:	2a0003f5 	mov	w21, w0
    80205458:	f940c7e0 	ldr	x0, [sp, #392]
    8020545c:	b8776802 	ldr	w2, [x0, x23]
    80205460:	35fffe42 	cbnz	w2, 80205428 <_vfprintf_r+0x1c28>
    80205464:	2a1503f7 	mov	w23, w21
    80205468:	b9409be9 	ldr	w9, [sp, #152]
    8020546c:	f94047f5 	ldr	x21, [sp, #136]
    80205470:	2a1a03e8 	mov	w8, w26
    80205474:	b940bbeb 	ldr	w11, [sp, #184]
    80205478:	aa1803ea 	mov	x10, x24
    8020547c:	340063f7 	cbz	w23, 802060f8 <_vfprintf_r+0x28f8>
    80205480:	71018eff 	cmp	w23, #0x63
    80205484:	5400776d 	b.le	80206370 <_vfprintf_r+0x2b70>
    80205488:	110006e1 	add	w1, w23, #0x1
    8020548c:	aa1303e0 	mov	x0, x19
    80205490:	b9008be9 	str	w9, [sp, #136]
    80205494:	93407c21 	sxtw	x1, w1
    80205498:	b9009be8 	str	w8, [sp, #152]
    8020549c:	b900bbeb 	str	w11, [sp, #184]
    802054a0:	f90063ea 	str	x10, [sp, #192]
    802054a4:	94000d67 	bl	80208a40 <_malloc_r>
    802054a8:	f94063ea 	ldr	x10, [sp, #192]
    802054ac:	aa0003fb 	mov	x27, x0
    802054b0:	b9408be9 	ldr	w9, [sp, #136]
    802054b4:	b9409be8 	ldr	w8, [sp, #152]
    802054b8:	b940bbeb 	ldr	w11, [sp, #184]
    802054bc:	b400b000 	cbz	x0, 80206abc <_vfprintf_r+0x32bc>
    802054c0:	aa0003f9 	mov	x25, x0
    802054c4:	d2800102 	mov	x2, #0x8                   	// #8
    802054c8:	52800001 	mov	w1, #0x0                   	// #0
    802054cc:	910603e0 	add	x0, sp, #0x180
    802054d0:	b9008be9 	str	w9, [sp, #136]
    802054d4:	b9009be8 	str	w8, [sp, #152]
    802054d8:	b900bbeb 	str	w11, [sp, #184]
    802054dc:	f90063ea 	str	x10, [sp, #192]
    802054e0:	97fff678 	bl	80202ec0 <memset>
    802054e4:	93407ee0 	sxtw	x0, w23
    802054e8:	910603e4 	add	x4, sp, #0x180
    802054ec:	aa0003f8 	mov	x24, x0
    802054f0:	aa0003e3 	mov	x3, x0
    802054f4:	910623e2 	add	x2, sp, #0x188
    802054f8:	aa1b03e1 	mov	x1, x27
    802054fc:	aa1303e0 	mov	x0, x19
    80205500:	940014f4 	bl	8020a8d0 <_wcsrtombs_r>
    80205504:	f94063ea 	ldr	x10, [sp, #192]
    80205508:	eb00031f 	cmp	x24, x0
    8020550c:	b9408be9 	ldr	w9, [sp, #136]
    80205510:	b9409be8 	ldr	w8, [sp, #152]
    80205514:	b940bbeb 	ldr	w11, [sp, #184]
    80205518:	5400ac81 	b.ne	80206aa8 <_vfprintf_r+0x32a8>  // b.any
    8020551c:	3837cb7f 	strb	wzr, [x27, w23, sxtw]
    80205520:	710002ff 	cmp	w23, #0x0
    80205524:	b9008bff 	str	wzr, [sp, #136]
    80205528:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    8020552c:	39457fe1 	ldrb	w1, [sp, #351]
    80205530:	52800007 	mov	w7, #0x0                   	// #0
    80205534:	b9009bff 	str	wzr, [sp, #152]
    80205538:	52800018 	mov	w24, #0x0                   	// #0
    8020553c:	34ff2ca1 	cbz	w1, 80203ad0 <_vfprintf_r+0x2d0>
    80205540:	17fffbb8 	b	80204420 <_vfprintf_r+0xc20>
    80205544:	b9408be9 	ldr	w9, [sp, #136]
    80205548:	aa1c03ea 	mov	x10, x28
    8020554c:	b9409beb 	ldr	w11, [sp, #152]
    80205550:	aa0203fc 	mov	x28, x2
    80205554:	aa1803e4 	mov	x4, x24
    80205558:	93407ef7 	sxtw	x23, w23
    8020555c:	11000421 	add	w1, w1, #0x1
    80205560:	8b170000 	add	x0, x0, x23
    80205564:	b9019be1 	str	w1, [sp, #408]
    80205568:	f900d3e0 	str	x0, [sp, #416]
    8020556c:	a9005f84 	stp	x4, x23, [x28]
    80205570:	71001c3f 	cmp	w1, #0x7
    80205574:	54ff536c 	b.gt	80203fe0 <_vfprintf_r+0x7e0>
    80205578:	9100439c 	add	x28, x28, #0x10
    8020557c:	17fff989 	b	80203ba0 <_vfprintf_r+0x3a0>
    80205580:	910833f7 	add	x23, sp, #0x20c
    80205584:	12160343 	and	w3, w26, #0x400
    80205588:	b202e7f8 	mov	x24, #0xcccccccccccccccc    	// #-3689348814741910324
    8020558c:	aa1703e2 	mov	x2, x23
    80205590:	aa1703e4 	mov	x4, x23
    80205594:	52800005 	mov	w5, #0x0                   	// #0
    80205598:	aa1303f7 	mov	x23, x19
    8020559c:	f29999b8 	movk	x24, #0xcccd
    802055a0:	2a0303f3 	mov	w19, w3
    802055a4:	aa1503e3 	mov	x3, x21
    802055a8:	f9407ff5 	ldr	x21, [sp, #248]
    802055ac:	14000007 	b	802055c8 <_vfprintf_r+0x1dc8>
    802055b0:	9bd87c19 	umulh	x25, x0, x24
    802055b4:	d343ff39 	lsr	x25, x25, #3
    802055b8:	f100241f 	cmp	x0, #0x9
    802055bc:	54000249 	b.ls	80205604 <_vfprintf_r+0x1e04>  // b.plast
    802055c0:	aa1903e0 	mov	x0, x25
    802055c4:	aa1b03e2 	mov	x2, x27
    802055c8:	9bd87c19 	umulh	x25, x0, x24
    802055cc:	110004a5 	add	w5, w5, #0x1
    802055d0:	d100045b 	sub	x27, x2, #0x1
    802055d4:	d343ff39 	lsr	x25, x25, #3
    802055d8:	8b190b21 	add	x1, x25, x25, lsl #2
    802055dc:	cb010401 	sub	x1, x0, x1, lsl #1
    802055e0:	1100c021 	add	w1, w1, #0x30
    802055e4:	381ff041 	sturb	w1, [x2, #-1]
    802055e8:	34fffe53 	cbz	w19, 802055b0 <_vfprintf_r+0x1db0>
    802055ec:	394002a1 	ldrb	w1, [x21]
    802055f0:	7103fc3f 	cmp	w1, #0xff
    802055f4:	7a451020 	ccmp	w1, w5, #0x0, ne	// ne = any
    802055f8:	54fffdc1 	b.ne	802055b0 <_vfprintf_r+0x1db0>  // b.any
    802055fc:	f100241f 	cmp	x0, #0x9
    80205600:	54006268 	b.hi	8020624c <_vfprintf_r+0x2a4c>  // b.pmore
    80205604:	aa1703f3 	mov	x19, x23
    80205608:	aa0403f7 	mov	x23, x4
    8020560c:	b90097e5 	str	w5, [sp, #148]
    80205610:	f9007ff5 	str	x21, [sp, #248]
    80205614:	aa0303f5 	mov	x21, x3
    80205618:	17fffcd5 	b	8020496c <_vfprintf_r+0x116c>
    8020561c:	710018ff 	cmp	w7, #0x6
    80205620:	528000c3 	mov	w3, #0x6                   	// #6
    80205624:	1a8390fa 	csel	w26, w7, w3, ls	// ls = plast
    80205628:	f0000045 	adrp	x5, 80210000 <__trunctfdf2+0xc0>
    8020562c:	2a1a03f7 	mov	w23, w26
    80205630:	9114c0bb 	add	x27, x5, #0x530
    80205634:	d2800019 	mov	x25, #0x0                   	// #0
    80205638:	52800001 	mov	w1, #0x0                   	// #0
    8020563c:	52800007 	mov	w7, #0x0                   	// #0
    80205640:	52800018 	mov	w24, #0x0                   	// #0
    80205644:	b9008bff 	str	wzr, [sp, #136]
    80205648:	b9009bff 	str	wzr, [sp, #152]
    8020564c:	17fff921 	b	80203ad0 <_vfprintf_r+0x2d0>
    80205650:	b94093e0 	ldr	w0, [sp, #144]
    80205654:	11002001 	add	w1, w0, #0x8
    80205658:	7100003f 	cmp	w1, #0x0
    8020565c:	5400242d 	b.le	80205ae0 <_vfprintf_r+0x22e0>
    80205660:	f9403fe0 	ldr	x0, [sp, #120]
    80205664:	b90093e1 	str	w1, [sp, #144]
    80205668:	91003c02 	add	x2, x0, #0xf
    8020566c:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205670:	f9003fe1 	str	x1, [sp, #120]
    80205674:	17fffc92 	b	802048bc <_vfprintf_r+0x10bc>
    80205678:	f940d3e0 	ldr	x0, [sp, #416]
    8020567c:	b50030e0 	cbnz	x0, 80205c98 <_vfprintf_r+0x2498>
    80205680:	79c022a0 	ldrsh	w0, [x21, #16]
    80205684:	b9019bff 	str	wzr, [sp, #408]
    80205688:	17fffa73 	b	80204054 <_vfprintf_r+0x854>
    8020568c:	f0000044 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80205690:	b9419be1 	ldr	w1, [sp, #408]
    80205694:	91234084 	add	x4, x4, #0x8d0
    80205698:	710042ff 	cmp	w23, #0x10
    8020569c:	54001bad 	b.le	80205a10 <_vfprintf_r+0x2210>
    802056a0:	aa1c03e2 	mov	x2, x28
    802056a4:	d2800208 	mov	x8, #0x10                  	// #16
    802056a8:	aa0a03fc 	mov	x28, x10
    802056ac:	f9005fec 	str	x12, [sp, #184]
    802056b0:	b900c3e9 	str	w9, [sp, #192]
    802056b4:	b900cbeb 	str	w11, [sp, #200]
    802056b8:	b900d3f8 	str	w24, [sp, #208]
    802056bc:	aa0403f8 	mov	x24, x4
    802056c0:	14000004 	b	802056d0 <_vfprintf_r+0x1ed0>
    802056c4:	510042f7 	sub	w23, w23, #0x10
    802056c8:	710042ff 	cmp	w23, #0x10
    802056cc:	5400194d 	b.le	802059f4 <_vfprintf_r+0x21f4>
    802056d0:	91004000 	add	x0, x0, #0x10
    802056d4:	11000421 	add	w1, w1, #0x1
    802056d8:	a9002058 	stp	x24, x8, [x2]
    802056dc:	91004042 	add	x2, x2, #0x10
    802056e0:	b9019be1 	str	w1, [sp, #408]
    802056e4:	f900d3e0 	str	x0, [sp, #416]
    802056e8:	71001c3f 	cmp	w1, #0x7
    802056ec:	54fffecd 	b.le	802056c4 <_vfprintf_r+0x1ec4>
    802056f0:	910643e2 	add	x2, sp, #0x190
    802056f4:	aa1503e1 	mov	x1, x21
    802056f8:	aa1303e0 	mov	x0, x19
    802056fc:	9400057d 	bl	80206cf0 <__sprint_r>
    80205700:	35ff4a00 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80205704:	f940d3e0 	ldr	x0, [sp, #416]
    80205708:	aa1603e2 	mov	x2, x22
    8020570c:	b9419be1 	ldr	w1, [sp, #408]
    80205710:	d2800208 	mov	x8, #0x10                  	// #16
    80205714:	17ffffec 	b	802056c4 <_vfprintf_r+0x1ec4>
    80205718:	364820fa 	tbz	w26, #9, 80205b34 <_vfprintf_r+0x2334>
    8020571c:	37f88040 	tbnz	w0, #31, 80206724 <_vfprintf_r+0x2f24>
    80205720:	f9403fe0 	ldr	x0, [sp, #120]
    80205724:	91002c01 	add	x1, x0, #0xb
    80205728:	927df021 	and	x1, x1, #0xfffffffffffffff8
    8020572c:	f9003fe1 	str	x1, [sp, #120]
    80205730:	39400000 	ldrb	w0, [x0]
    80205734:	52800021 	mov	w1, #0x1                   	// #1
    80205738:	17fffc0e 	b	80204770 <_vfprintf_r+0xf70>
    8020573c:	364820c9 	tbz	w9, #9, 80205b54 <_vfprintf_r+0x2354>
    80205740:	37f87c80 	tbnz	w0, #31, 802066d0 <_vfprintf_r+0x2ed0>
    80205744:	f9403fe0 	ldr	x0, [sp, #120]
    80205748:	91002c01 	add	x1, x0, #0xb
    8020574c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205750:	39400000 	ldrb	w0, [x0]
    80205754:	f9003fe1 	str	x1, [sp, #120]
    80205758:	17fffc04 	b	80204768 <_vfprintf_r+0xf68>
    8020575c:	f94053e2 	ldr	x2, [sp, #160]
    80205760:	b94093e0 	ldr	w0, [sp, #144]
    80205764:	b90093e1 	str	w1, [sp, #144]
    80205768:	8b20c040 	add	x0, x2, w0, sxtw
    8020576c:	17fffc64 	b	802048fc <_vfprintf_r+0x10fc>
    80205770:	f94053e2 	ldr	x2, [sp, #160]
    80205774:	b94093e0 	ldr	w0, [sp, #144]
    80205778:	b90093e1 	str	w1, [sp, #144]
    8020577c:	8b20c040 	add	x0, x2, w0, sxtw
    80205780:	17fffc22 	b	80204808 <_vfprintf_r+0x1008>
    80205784:	36481ca9 	tbz	w9, #9, 80205b18 <_vfprintf_r+0x2318>
    80205788:	37f86ee0 	tbnz	w0, #31, 80206564 <_vfprintf_r+0x2d64>
    8020578c:	f9403fe0 	ldr	x0, [sp, #120]
    80205790:	91002c01 	add	x1, x0, #0xb
    80205794:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205798:	39400000 	ldrb	w0, [x0]
    8020579c:	f9003fe1 	str	x1, [sp, #120]
    802057a0:	17fffe4b 	b	802050cc <_vfprintf_r+0x18cc>
    802057a4:	f94053e2 	ldr	x2, [sp, #160]
    802057a8:	b94093e0 	ldr	w0, [sp, #144]
    802057ac:	b90093e1 	str	w1, [sp, #144]
    802057b0:	8b20c040 	add	x0, x2, w0, sxtw
    802057b4:	17fffbec 	b	80204764 <_vfprintf_r+0xf64>
    802057b8:	b94093e0 	ldr	w0, [sp, #144]
    802057bc:	11002001 	add	w1, w0, #0x8
    802057c0:	7100003f 	cmp	w1, #0x0
    802057c4:	54001fad 	b.le	80205bb8 <_vfprintf_r+0x23b8>
    802057c8:	f9403fe0 	ldr	x0, [sp, #120]
    802057cc:	b90093e1 	str	w1, [sp, #144]
    802057d0:	91002c02 	add	x2, x0, #0xb
    802057d4:	927df041 	and	x1, x2, #0xfffffffffffffff8
    802057d8:	f9003fe1 	str	x1, [sp, #120]
    802057dc:	17fffe07 	b	80204ff8 <_vfprintf_r+0x17f8>
    802057e0:	36481c89 	tbz	w9, #9, 80205b70 <_vfprintf_r+0x2370>
    802057e4:	37f87dc0 	tbnz	w0, #31, 8020679c <_vfprintf_r+0x2f9c>
    802057e8:	f9403fe0 	ldr	x0, [sp, #120]
    802057ec:	91002c01 	add	x1, x0, #0xb
    802057f0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802057f4:	f9003fe1 	str	x1, [sp, #120]
    802057f8:	39800000 	ldrsb	x0, [x0]
    802057fc:	aa0003e1 	mov	x1, x0
    80205800:	17fffc41 	b	80204904 <_vfprintf_r+0x1104>
    80205804:	f94053e2 	ldr	x2, [sp, #160]
    80205808:	b94093e0 	ldr	w0, [sp, #144]
    8020580c:	b90093e1 	str	w1, [sp, #144]
    80205810:	8b20c040 	add	x0, x2, w0, sxtw
    80205814:	17fffe2d 	b	802050c8 <_vfprintf_r+0x18c8>
    80205818:	310004ff 	cmn	w7, #0x1
    8020581c:	54002760 	b.eq	80205d08 <_vfprintf_r+0x2508>  // b.none
    80205820:	71011eff 	cmp	w23, #0x47
    80205824:	7a4008e0 	ccmp	w7, #0x0, #0x0, eq	// eq = none
    80205828:	1a9f14e7 	csinc	w7, w7, wzr, ne	// ne = any
    8020582c:	9e660100 	fmov	x0, d8
    80205830:	32180139 	orr	w25, w9, #0x100
    80205834:	d360fc00 	lsr	x0, x0, #32
    80205838:	37f879e0 	tbnz	w0, #31, 80206774 <_vfprintf_r+0x2f74>
    8020583c:	1e604109 	fmov	d9, d8
    80205840:	b900bbff 	str	wzr, [sp, #184]
    80205844:	2912a3e9 	stp	w9, w8, [sp, #148]
    80205848:	1e604120 	fmov	d0, d9
    8020584c:	b900c3eb 	str	w11, [sp, #192]
    80205850:	f90067ea 	str	x10, [sp, #200]
    80205854:	71011aff 	cmp	w23, #0x46
    80205858:	540042c1 	b.ne	802060b0 <_vfprintf_r+0x28b0>  // b.any
    8020585c:	2a0703e2 	mov	w2, w7
    80205860:	52800061 	mov	w1, #0x3                   	// #3
    80205864:	910623e5 	add	x5, sp, #0x188
    80205868:	910603e4 	add	x4, sp, #0x180
    8020586c:	9105a3e3 	add	x3, sp, #0x168
    80205870:	aa1303e0 	mov	x0, x19
    80205874:	b9008be7 	str	w7, [sp, #136]
    80205878:	94001492 	bl	8020aac0 <_dtoa_r>
    8020587c:	b9408be7 	ldr	w7, [sp, #136]
    80205880:	aa0003fb 	mov	x27, x0
    80205884:	39400001 	ldrb	w1, [x0]
    80205888:	f94067ea 	ldr	x10, [sp, #200]
    8020588c:	7100c03f 	cmp	w1, #0x30
    80205890:	2952a3e9 	ldp	w9, w8, [sp, #148]
    80205894:	8b27c000 	add	x0, x0, w7, sxtw
    80205898:	b940c3eb 	ldr	w11, [sp, #192]
    8020589c:	54005240 	b.eq	802062e4 <_vfprintf_r+0x2ae4>  // b.none
    802058a0:	b9416be1 	ldr	w1, [sp, #360]
    802058a4:	8b21c001 	add	x1, x0, w1, sxtw
    802058a8:	1e602128 	fcmp	d9, #0.0
    802058ac:	54004f60 	b.eq	80206298 <_vfprintf_r+0x2a98>  // b.none
    802058b0:	f940c7e0 	ldr	x0, [sp, #392]
    802058b4:	52800603 	mov	w3, #0x30                  	// #48
    802058b8:	eb00003f 	cmp	x1, x0
    802058bc:	540000e9 	b.ls	802058d8 <_vfprintf_r+0x20d8>  // b.plast
    802058c0:	91000402 	add	x2, x0, #0x1
    802058c4:	f900c7e2 	str	x2, [sp, #392]
    802058c8:	39000003 	strb	w3, [x0]
    802058cc:	f940c7e0 	ldr	x0, [sp, #392]
    802058d0:	eb00003f 	cmp	x1, x0
    802058d4:	54ffff68 	b.hi	802058c0 <_vfprintf_r+0x20c0>  // b.pmore
    802058d8:	b9416bf8 	ldr	w24, [sp, #360]
    802058dc:	cb1b0000 	sub	x0, x0, x27
    802058e0:	b90097e0 	str	w0, [sp, #148]
    802058e4:	71011eff 	cmp	w23, #0x47
    802058e8:	54002200 	b.eq	80205d28 <_vfprintf_r+0x2528>  // b.none
    802058ec:	51000700 	sub	w0, w24, #0x1
    802058f0:	71011aff 	cmp	w23, #0x46
    802058f4:	54005040 	b.eq	802062fc <_vfprintf_r+0x2afc>  // b.none
    802058f8:	12001d01 	and	w1, w8, #0xff
    802058fc:	52800002 	mov	w2, #0x0                   	// #0
    80205900:	d2800019 	mov	x25, #0x0                   	// #0
    80205904:	b9016be0 	str	w0, [sp, #360]
    80205908:	3905c3e1 	strb	w1, [sp, #368]
    8020590c:	52800561 	mov	w1, #0x2b                  	// #43
    80205910:	36f80080 	tbz	w0, #31, 80205920 <_vfprintf_r+0x2120>
    80205914:	52800020 	mov	w0, #0x1                   	// #1
    80205918:	4b180000 	sub	w0, w0, w24
    8020591c:	528005a1 	mov	w1, #0x2d                  	// #45
    80205920:	3905c7e1 	strb	w1, [sp, #369]
    80205924:	7100241f 	cmp	w0, #0x9
    80205928:	54005bcd 	b.le	802064a0 <_vfprintf_r+0x2ca0>
    8020592c:	91063fec 	add	x12, sp, #0x18f
    80205930:	529999ad 	mov	w13, #0xcccd                	// #52429
    80205934:	aa0c03e4 	mov	x4, x12
    80205938:	72b9998d 	movk	w13, #0xcccc, lsl #16
    8020593c:	9bad7c02 	umull	x2, w0, w13
    80205940:	aa0403e3 	mov	x3, x4
    80205944:	2a0003e5 	mov	w5, w0
    80205948:	d1000484 	sub	x4, x4, #0x1
    8020594c:	d363fc42 	lsr	x2, x2, #35
    80205950:	0b020841 	add	w1, w2, w2, lsl #2
    80205954:	4b010401 	sub	w1, w0, w1, lsl #1
    80205958:	2a0203e0 	mov	w0, w2
    8020595c:	1100c021 	add	w1, w1, #0x30
    80205960:	381ff061 	sturb	w1, [x3, #-1]
    80205964:	71018cbf 	cmp	w5, #0x63
    80205968:	54fffeac 	b.gt	8020593c <_vfprintf_r+0x213c>
    8020596c:	1100c040 	add	w0, w2, #0x30
    80205970:	381ff080 	sturb	w0, [x4, #-1]
    80205974:	d1000860 	sub	x0, x3, #0x2
    80205978:	eb0c001f 	cmp	x0, x12
    8020597c:	54007e82 	b.cs	8020694c <_vfprintf_r+0x314c>  // b.hs, b.nlast
    80205980:	9105cbe1 	add	x1, sp, #0x172
    80205984:	38401402 	ldrb	w2, [x0], #1
    80205988:	38001422 	strb	w2, [x1], #1
    8020598c:	eb0c001f 	cmp	x0, x12
    80205990:	54ffffa1 	b.ne	80205984 <_vfprintf_r+0x2184>  // b.any
    80205994:	910a43e0 	add	x0, sp, #0x290
    80205998:	cb030003 	sub	x3, x0, x3
    8020599c:	5103f460 	sub	w0, w3, #0xfd
    802059a0:	b900f3e0 	str	w0, [sp, #240]
    802059a4:	b94097e0 	ldr	w0, [sp, #148]
    802059a8:	b940f3e1 	ldr	w1, [sp, #240]
    802059ac:	0b010017 	add	w23, w0, w1
    802059b0:	7100041f 	cmp	w0, #0x1
    802059b4:	54005b6d 	b.le	80206520 <_vfprintf_r+0x2d20>
    802059b8:	b940abe0 	ldr	w0, [sp, #168]
    802059bc:	0b0002f7 	add	w23, w23, w0
    802059c0:	12157929 	and	w9, w9, #0xfffffbff
    802059c4:	710002ff 	cmp	w23, #0x0
    802059c8:	32180129 	orr	w9, w9, #0x100
    802059cc:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    802059d0:	52800018 	mov	w24, #0x0                   	// #0
    802059d4:	b9008bff 	str	wzr, [sp, #136]
    802059d8:	b9009bff 	str	wzr, [sp, #152]
    802059dc:	b940bbe0 	ldr	w0, [sp, #184]
    802059e0:	35001b00 	cbnz	w0, 80205d40 <_vfprintf_r+0x2540>
    802059e4:	39457fe1 	ldrb	w1, [sp, #351]
    802059e8:	52800007 	mov	w7, #0x0                   	// #0
    802059ec:	34ff0721 	cbz	w1, 80203ad0 <_vfprintf_r+0x2d0>
    802059f0:	17fffa8c 	b	80204420 <_vfprintf_r+0xc20>
    802059f4:	f9405fec 	ldr	x12, [sp, #184]
    802059f8:	aa1803e4 	mov	x4, x24
    802059fc:	b940c3e9 	ldr	w9, [sp, #192]
    80205a00:	aa1c03ea 	mov	x10, x28
    80205a04:	b940cbeb 	ldr	w11, [sp, #200]
    80205a08:	aa0203fc 	mov	x28, x2
    80205a0c:	b940d3f8 	ldr	w24, [sp, #208]
    80205a10:	93407ee7 	sxtw	x7, w23
    80205a14:	11000421 	add	w1, w1, #0x1
    80205a18:	8b070000 	add	x0, x0, x7
    80205a1c:	a9001f84 	stp	x4, x7, [x28]
    80205a20:	9100439c 	add	x28, x28, #0x10
    80205a24:	b9019be1 	str	w1, [sp, #408]
    80205a28:	f900d3e0 	str	x0, [sp, #416]
    80205a2c:	71001c3f 	cmp	w1, #0x7
    80205a30:	54ff89cd 	b.le	80204b68 <_vfprintf_r+0x1368>
    80205a34:	910643e2 	add	x2, sp, #0x190
    80205a38:	aa1503e1 	mov	x1, x21
    80205a3c:	aa1303e0 	mov	x0, x19
    80205a40:	f9005fec 	str	x12, [sp, #184]
    80205a44:	b900c3e9 	str	w9, [sp, #192]
    80205a48:	b900cbeb 	str	w11, [sp, #200]
    80205a4c:	f9006bea 	str	x10, [sp, #208]
    80205a50:	940004a8 	bl	80206cf0 <__sprint_r>
    80205a54:	35ff2f60 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80205a58:	f9405fec 	ldr	x12, [sp, #184]
    80205a5c:	aa1603fc 	mov	x28, x22
    80205a60:	f9406bea 	ldr	x10, [sp, #208]
    80205a64:	f940d3e0 	ldr	x0, [sp, #416]
    80205a68:	b940c3e9 	ldr	w9, [sp, #192]
    80205a6c:	b940cbeb 	ldr	w11, [sp, #200]
    80205a70:	17fffc3e 	b	80204b68 <_vfprintf_r+0x1368>
    80205a74:	36070969 	tbz	w9, #0, 80203ba0 <_vfprintf_r+0x3a0>
    80205a78:	a94a8fe2 	ldp	x2, x3, [sp, #168]
    80205a7c:	a9000b83 	stp	x3, x2, [x28]
    80205a80:	b9419be1 	ldr	w1, [sp, #408]
    80205a84:	91004386 	add	x6, x28, #0x10
    80205a88:	11000421 	add	w1, w1, #0x1
    80205a8c:	b9019be1 	str	w1, [sp, #408]
    80205a90:	8b000040 	add	x0, x2, x0
    80205a94:	f900d3e0 	str	x0, [sp, #416]
    80205a98:	71001c3f 	cmp	w1, #0x7
    80205a9c:	54ff28ed 	b.le	80203fb8 <_vfprintf_r+0x7b8>
    80205aa0:	910643e2 	add	x2, sp, #0x190
    80205aa4:	aa1503e1 	mov	x1, x21
    80205aa8:	aa1303e0 	mov	x0, x19
    80205aac:	b9008be9 	str	w9, [sp, #136]
    80205ab0:	b9009beb 	str	w11, [sp, #152]
    80205ab4:	f9005fea 	str	x10, [sp, #184]
    80205ab8:	9400048e 	bl	80206cf0 <__sprint_r>
    80205abc:	35ff2c20 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80205ac0:	f9405fea 	ldr	x10, [sp, #184]
    80205ac4:	aa1603e6 	mov	x6, x22
    80205ac8:	f940d3e0 	ldr	x0, [sp, #416]
    80205acc:	b9408be9 	ldr	w9, [sp, #136]
    80205ad0:	b9409beb 	ldr	w11, [sp, #152]
    80205ad4:	b9416be2 	ldr	w2, [sp, #360]
    80205ad8:	b9419be1 	ldr	w1, [sp, #408]
    80205adc:	17fff936 	b	80203fb4 <_vfprintf_r+0x7b4>
    80205ae0:	f94053e2 	ldr	x2, [sp, #160]
    80205ae4:	b94093e0 	ldr	w0, [sp, #144]
    80205ae8:	b90093e1 	str	w1, [sp, #144]
    80205aec:	8b20c040 	add	x0, x2, w0, sxtw
    80205af0:	17fffb73 	b	802048bc <_vfprintf_r+0x10bc>
    80205af4:	37f862c0 	tbnz	w0, #31, 8020674c <_vfprintf_r+0x2f4c>
    80205af8:	f9403fe0 	ldr	x0, [sp, #120]
    80205afc:	91003c01 	add	x1, x0, #0xf
    80205b00:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205b04:	f9003fe1 	str	x1, [sp, #120]
    80205b08:	f9400000 	ldr	x0, [x0]
    80205b0c:	7940ebe1 	ldrh	w1, [sp, #116]
    80205b10:	79000001 	strh	w1, [x0]
    80205b14:	17fff780 	b	80203914 <_vfprintf_r+0x114>
    80205b18:	37f867e0 	tbnz	w0, #31, 80206814 <_vfprintf_r+0x3014>
    80205b1c:	f9403fe0 	ldr	x0, [sp, #120]
    80205b20:	91002c01 	add	x1, x0, #0xb
    80205b24:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205b28:	b9400000 	ldr	w0, [x0]
    80205b2c:	f9003fe1 	str	x1, [sp, #120]
    80205b30:	17fffd67 	b	802050cc <_vfprintf_r+0x18cc>
    80205b34:	37f85040 	tbnz	w0, #31, 8020653c <_vfprintf_r+0x2d3c>
    80205b38:	f9403fe0 	ldr	x0, [sp, #120]
    80205b3c:	91002c01 	add	x1, x0, #0xb
    80205b40:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205b44:	f9003fe1 	str	x1, [sp, #120]
    80205b48:	b9400000 	ldr	w0, [x0]
    80205b4c:	52800021 	mov	w1, #0x1                   	// #1
    80205b50:	17fffb08 	b	80204770 <_vfprintf_r+0xf70>
    80205b54:	37f86380 	tbnz	w0, #31, 802067c4 <_vfprintf_r+0x2fc4>
    80205b58:	f9403fe0 	ldr	x0, [sp, #120]
    80205b5c:	91002c01 	add	x1, x0, #0xb
    80205b60:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205b64:	b9400000 	ldr	w0, [x0]
    80205b68:	f9003fe1 	str	x1, [sp, #120]
    80205b6c:	17fffaff 	b	80204768 <_vfprintf_r+0xf68>
    80205b70:	37f85c60 	tbnz	w0, #31, 802066fc <_vfprintf_r+0x2efc>
    80205b74:	f9403fe0 	ldr	x0, [sp, #120]
    80205b78:	91002c01 	add	x1, x0, #0xb
    80205b7c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205b80:	f9003fe1 	str	x1, [sp, #120]
    80205b84:	b9800000 	ldrsw	x0, [x0]
    80205b88:	aa0003e1 	mov	x1, x0
    80205b8c:	17fffb5e 	b	80204904 <_vfprintf_r+0x1104>
    80205b90:	b94093e0 	ldr	w0, [sp, #144]
    80205b94:	11002001 	add	w1, w0, #0x8
    80205b98:	7100003f 	cmp	w1, #0x0
    80205b9c:	5400518d 	b.le	802065cc <_vfprintf_r+0x2dcc>
    80205ba0:	f9403fe0 	ldr	x0, [sp, #120]
    80205ba4:	b90093e1 	str	w1, [sp, #144]
    80205ba8:	91002c02 	add	x2, x0, #0xb
    80205bac:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205bb0:	f9003fe1 	str	x1, [sp, #120]
    80205bb4:	17fffc69 	b	80204d58 <_vfprintf_r+0x1558>
    80205bb8:	f94053e2 	ldr	x2, [sp, #160]
    80205bbc:	b94093e0 	ldr	w0, [sp, #144]
    80205bc0:	b90093e1 	str	w1, [sp, #144]
    80205bc4:	8b20c040 	add	x0, x2, w0, sxtw
    80205bc8:	17fffd0c 	b	80204ff8 <_vfprintf_r+0x17f8>
    80205bcc:	b94093e0 	ldr	w0, [sp, #144]
    80205bd0:	11002001 	add	w1, w0, #0x8
    80205bd4:	7100003f 	cmp	w1, #0x0
    80205bd8:	54005d6d 	b.le	80206784 <_vfprintf_r+0x2f84>
    80205bdc:	f9403fe0 	ldr	x0, [sp, #120]
    80205be0:	b90093e1 	str	w1, [sp, #144]
    80205be4:	91002c02 	add	x2, x0, #0xb
    80205be8:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205bec:	79400000 	ldrh	w0, [x0]
    80205bf0:	f9003fe1 	str	x1, [sp, #120]
    80205bf4:	17fffadd 	b	80204768 <_vfprintf_r+0xf68>
    80205bf8:	aa1b03e0 	mov	x0, x27
    80205bfc:	b900bbe9 	str	w9, [sp, #184]
    80205c00:	b900c3eb 	str	w11, [sp, #192]
    80205c04:	d2800019 	mov	x25, #0x0                   	// #0
    80205c08:	f90067ea 	str	x10, [sp, #200]
    80205c0c:	97fff53d 	bl	80203100 <strlen>
    80205c10:	39457fe1 	ldrb	w1, [sp, #351]
    80205c14:	7100001f 	cmp	w0, #0x0
    80205c18:	b9008bff 	str	wzr, [sp, #136]
    80205c1c:	2a0003f7 	mov	w23, w0
    80205c20:	b9009bff 	str	wzr, [sp, #152]
    80205c24:	1a9fa01a 	csel	w26, w0, wzr, ge	// ge = tcont
    80205c28:	f94067ea 	ldr	x10, [sp, #200]
    80205c2c:	52800007 	mov	w7, #0x0                   	// #0
    80205c30:	b940bbe9 	ldr	w9, [sp, #184]
    80205c34:	52800e68 	mov	w8, #0x73                  	// #115
    80205c38:	b940c3eb 	ldr	w11, [sp, #192]
    80205c3c:	34fef4a1 	cbz	w1, 80203ad0 <_vfprintf_r+0x2d0>
    80205c40:	17fff9f8 	b	80204420 <_vfprintf_r+0xc20>
    80205c44:	b94093e0 	ldr	w0, [sp, #144]
    80205c48:	11002001 	add	w1, w0, #0x8
    80205c4c:	7100003f 	cmp	w1, #0x0
    80205c50:	54004dcd 	b.le	80206608 <_vfprintf_r+0x2e08>
    80205c54:	f9403fe0 	ldr	x0, [sp, #120]
    80205c58:	b90093e1 	str	w1, [sp, #144]
    80205c5c:	91002c02 	add	x2, x0, #0xb
    80205c60:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205c64:	f9003fe1 	str	x1, [sp, #120]
    80205c68:	17fffc33 	b	80204d34 <_vfprintf_r+0x1534>
    80205c6c:	b94093e0 	ldr	w0, [sp, #144]
    80205c70:	11002001 	add	w1, w0, #0x8
    80205c74:	7100003f 	cmp	w1, #0x0
    80205c78:	540049ed 	b.le	802065b4 <_vfprintf_r+0x2db4>
    80205c7c:	f9403fe0 	ldr	x0, [sp, #120]
    80205c80:	b90093e1 	str	w1, [sp, #144]
    80205c84:	91002c02 	add	x2, x0, #0xb
    80205c88:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205c8c:	79400000 	ldrh	w0, [x0]
    80205c90:	f9003fe1 	str	x1, [sp, #120]
    80205c94:	17fffd0e 	b	802050cc <_vfprintf_r+0x18cc>
    80205c98:	aa1303e0 	mov	x0, x19
    80205c9c:	910643e2 	add	x2, sp, #0x190
    80205ca0:	aa1503e1 	mov	x1, x21
    80205ca4:	94000413 	bl	80206cf0 <__sprint_r>
    80205ca8:	34ffcec0 	cbz	w0, 80205680 <_vfprintf_r+0x1e80>
    80205cac:	17fff8e9 	b	80204050 <_vfprintf_r+0x850>
    80205cb0:	f94052a0 	ldr	x0, [x21, #160]
    80205cb4:	94000dd3 	bl	80209400 <__retarget_lock_release_recursive>
    80205cb8:	17fff739 	b	8020399c <_vfprintf_r+0x19c>
    80205cbc:	1e604100 	fmov	d0, d8
    80205cc0:	b900bbff 	str	wzr, [sp, #184]
    80205cc4:	17fffd61 	b	80205248 <_vfprintf_r+0x1a48>
    80205cc8:	110004e1 	add	w1, w7, #0x1
    80205ccc:	aa1303e0 	mov	x0, x19
    80205cd0:	b9008be7 	str	w7, [sp, #136]
    80205cd4:	93407c21 	sxtw	x1, w1
    80205cd8:	2912a3e9 	stp	w9, w8, [sp, #148]
    80205cdc:	f9005fea 	str	x10, [sp, #184]
    80205ce0:	b900f3eb 	str	w11, [sp, #240]
    80205ce4:	94000b57 	bl	80208a40 <_malloc_r>
    80205ce8:	f9405fea 	ldr	x10, [sp, #184]
    80205cec:	aa0003fb 	mov	x27, x0
    80205cf0:	b9408be7 	ldr	w7, [sp, #136]
    80205cf4:	2952a3e9 	ldp	w9, w8, [sp, #148]
    80205cf8:	b940f3eb 	ldr	w11, [sp, #240]
    80205cfc:	b4006380 	cbz	x0, 8020696c <_vfprintf_r+0x316c>
    80205d00:	aa0003f9 	mov	x25, x0
    80205d04:	17fffd4b 	b	80205230 <_vfprintf_r+0x1a30>
    80205d08:	528000c7 	mov	w7, #0x6                   	// #6
    80205d0c:	17fffec8 	b	8020582c <_vfprintf_r+0x202c>
    80205d10:	39402844 	ldrb	w4, [x2, #10]
    80205d14:	17fffd8c 	b	80205344 <_vfprintf_r+0x1b44>
    80205d18:	f940c7e0 	ldr	x0, [sp, #392]
    80205d1c:	b9416bf8 	ldr	w24, [sp, #360]
    80205d20:	cb1b0000 	sub	x0, x0, x27
    80205d24:	b90097e0 	str	w0, [sp, #148]
    80205d28:	6b07031f 	cmp	w24, w7
    80205d2c:	3a43db01 	ccmn	w24, #0x3, #0x1, le
    80205d30:	540017ea 	b.ge	8020602c <_vfprintf_r+0x282c>  // b.tcont
    80205d34:	51000908 	sub	w8, w8, #0x2
    80205d38:	51000700 	sub	w0, w24, #0x1
    80205d3c:	17fffeef 	b	802058f8 <_vfprintf_r+0x20f8>
    80205d40:	528005a0 	mov	w0, #0x2d                  	// #45
    80205d44:	1100075a 	add	w26, w26, #0x1
    80205d48:	528005a1 	mov	w1, #0x2d                  	// #45
    80205d4c:	52800007 	mov	w7, #0x0                   	// #0
    80205d50:	39057fe0 	strb	w0, [sp, #351]
    80205d54:	17fff75f 	b	80203ad0 <_vfprintf_r+0x2d0>
    80205d58:	910603e4 	add	x4, sp, #0x180
    80205d5c:	910623e2 	add	x2, sp, #0x188
    80205d60:	aa1303e0 	mov	x0, x19
    80205d64:	d2800003 	mov	x3, #0x0                   	// #0
    80205d68:	d2800001 	mov	x1, #0x0                   	// #0
    80205d6c:	b9008be9 	str	w9, [sp, #136]
    80205d70:	b9009be8 	str	w8, [sp, #152]
    80205d74:	b900bbeb 	str	w11, [sp, #184]
    80205d78:	f90063ea 	str	x10, [sp, #192]
    80205d7c:	940012d5 	bl	8020a8d0 <_wcsrtombs_r>
    80205d80:	f94063ea 	ldr	x10, [sp, #192]
    80205d84:	2a0003f7 	mov	w23, w0
    80205d88:	b9408be9 	ldr	w9, [sp, #136]
    80205d8c:	3100041f 	cmn	w0, #0x1
    80205d90:	b9409be8 	ldr	w8, [sp, #152]
    80205d94:	b940bbeb 	ldr	w11, [sp, #184]
    80205d98:	54006920 	b.eq	80206abc <_vfprintf_r+0x32bc>  // b.none
    80205d9c:	f900c7fb 	str	x27, [sp, #392]
    80205da0:	17fffdb7 	b	8020547c <_vfprintf_r+0x1c7c>
    80205da4:	528005a0 	mov	w0, #0x2d                  	// #45
    80205da8:	528005a1 	mov	w1, #0x2d                  	// #45
    80205dac:	39057fe0 	strb	w0, [sp, #351]
    80205db0:	17fff98c 	b	802043e0 <_vfprintf_r+0xbe0>
    80205db4:	b940f7e0 	ldr	w0, [sp, #244]
    80205db8:	11004001 	add	w1, w0, #0x10
    80205dbc:	7100003f 	cmp	w1, #0x0
    80205dc0:	5400386d 	b.le	802064cc <_vfprintf_r+0x2ccc>
    80205dc4:	f9403fe0 	ldr	x0, [sp, #120]
    80205dc8:	b900f7e1 	str	w1, [sp, #244]
    80205dcc:	91003c00 	add	x0, x0, #0xf
    80205dd0:	927cec00 	and	x0, x0, #0xfffffffffffffff0
    80205dd4:	91004001 	add	x1, x0, #0x10
    80205dd8:	f9003fe1 	str	x1, [sp, #120]
    80205ddc:	17fff96c 	b	8020438c <_vfprintf_r+0xb8c>
    80205de0:	b940f7e0 	ldr	w0, [sp, #244]
    80205de4:	11004001 	add	w1, w0, #0x10
    80205de8:	7100003f 	cmp	w1, #0x0
    80205dec:	540034ed 	b.le	80206488 <_vfprintf_r+0x2c88>
    80205df0:	f9403fe0 	ldr	x0, [sp, #120]
    80205df4:	b900f7e1 	str	w1, [sp, #244]
    80205df8:	91003c02 	add	x2, x0, #0xf
    80205dfc:	fd400008 	ldr	d8, [x0]
    80205e00:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205e04:	f9003fe1 	str	x1, [sp, #120]
    80205e08:	17fff96e 	b	802043c0 <_vfprintf_r+0xbc0>
    80205e0c:	b9408be1 	ldr	w1, [sp, #136]
    80205e10:	7100003f 	cmp	w1, #0x0
    80205e14:	b9409be1 	ldr	w1, [sp, #152]
    80205e18:	7a40d820 	ccmp	w1, #0x0, #0x0, le
    80205e1c:	5400660d 	b.le	80206adc <_vfprintf_r+0x32dc>
    80205e20:	8b0c036d 	add	x13, x27, x12
    80205e24:	aa1c03e2 	mov	x2, x28
    80205e28:	f0000044 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80205e2c:	2a0103fc 	mov	w28, w1
    80205e30:	91234084 	add	x4, x4, #0x8d0
    80205e34:	aa0d03f8 	mov	x24, x13
    80205e38:	d2800217 	mov	x23, #0x10                  	// #16
    80205e3c:	f9004ff3 	str	x19, [sp, #152]
    80205e40:	f9005ff9 	str	x25, [sp, #184]
    80205e44:	aa0803f9 	mov	x25, x8
    80205e48:	f9006fec 	str	x12, [sp, #216]
    80205e4c:	b90113e9 	str	w9, [sp, #272]
    80205e50:	f9008ffb 	str	x27, [sp, #280]
    80205e54:	b90123eb 	str	w11, [sp, #288]
    80205e58:	b90127fa 	str	w26, [sp, #292]
    80205e5c:	a94febfb 	ldp	x27, x26, [sp, #248]
    80205e60:	f90097ea 	str	x10, [sp, #296]
    80205e64:	14000028 	b	80205f04 <_vfprintf_r+0x2704>
    80205e68:	5100079c 	sub	w28, w28, #0x1
    80205e6c:	b9419be1 	ldr	w1, [sp, #408]
    80205e70:	8b1a0000 	add	x0, x0, x26
    80205e74:	f94077e3 	ldr	x3, [sp, #232]
    80205e78:	11000421 	add	w1, w1, #0x1
    80205e7c:	a9006843 	stp	x3, x26, [x2]
    80205e80:	91004042 	add	x2, x2, #0x10
    80205e84:	b9019be1 	str	w1, [sp, #408]
    80205e88:	f900d3e0 	str	x0, [sp, #416]
    80205e8c:	71001c3f 	cmp	w1, #0x7
    80205e90:	5400086c 	b.gt	80205f9c <_vfprintf_r+0x279c>
    80205e94:	39400361 	ldrb	w1, [x27]
    80205e98:	cb190305 	sub	x5, x24, x25
    80205e9c:	aa1803e3 	mov	x3, x24
    80205ea0:	6b05003f 	cmp	w1, w5
    80205ea4:	1a85b033 	csel	w19, w1, w5, lt	// lt = tstop
    80205ea8:	7100027f 	cmp	w19, #0x0
    80205eac:	5400018d 	b.le	80205edc <_vfprintf_r+0x26dc>
    80205eb0:	b9419be1 	ldr	w1, [sp, #408]
    80205eb4:	93407e6a 	sxtw	x10, w19
    80205eb8:	8b0a0000 	add	x0, x0, x10
    80205ebc:	a9002859 	stp	x25, x10, [x2]
    80205ec0:	11000421 	add	w1, w1, #0x1
    80205ec4:	b9019be1 	str	w1, [sp, #408]
    80205ec8:	f900d3e0 	str	x0, [sp, #416]
    80205ecc:	71001c3f 	cmp	w1, #0x7
    80205ed0:	5400094c 	b.gt	80205ff8 <_vfprintf_r+0x27f8>
    80205ed4:	39400361 	ldrb	w1, [x27]
    80205ed8:	91004042 	add	x2, x2, #0x10
    80205edc:	7100027f 	cmp	w19, #0x0
    80205ee0:	1a9fa265 	csel	w5, w19, wzr, ge	// ge = tcont
    80205ee4:	4b050033 	sub	w19, w1, w5
    80205ee8:	7100027f 	cmp	w19, #0x0
    80205eec:	540001ac 	b.gt	80205f20 <_vfprintf_r+0x2720>
    80205ef0:	b9408be5 	ldr	w5, [sp, #136]
    80205ef4:	8b210339 	add	x25, x25, w1, uxtb
    80205ef8:	710000bf 	cmp	w5, #0x0
    80205efc:	7a40db80 	ccmp	w28, #0x0, #0x0, le
    80205f00:	54004d8d 	b.le	802068b0 <_vfprintf_r+0x30b0>
    80205f04:	7100039f 	cmp	w28, #0x0
    80205f08:	54fffb0c 	b.gt	80205e68 <_vfprintf_r+0x2668>
    80205f0c:	b9408be1 	ldr	w1, [sp, #136]
    80205f10:	d100077b 	sub	x27, x27, #0x1
    80205f14:	51000421 	sub	w1, w1, #0x1
    80205f18:	b9008be1 	str	w1, [sp, #136]
    80205f1c:	17ffffd4 	b	80205e6c <_vfprintf_r+0x266c>
    80205f20:	f000004a 	adrp	x10, 80210000 <__trunctfdf2+0xc0>
    80205f24:	b9419be1 	ldr	w1, [sp, #408]
    80205f28:	9123414a 	add	x10, x10, #0x8d0
    80205f2c:	7100427f 	cmp	w19, #0x10
    80205f30:	540004ed 	b.le	80205fcc <_vfprintf_r+0x27cc>
    80205f34:	a90c13e3 	stp	x3, x4, [sp, #192]
    80205f38:	f9006bf8 	str	x24, [sp, #208]
    80205f3c:	f9404ff8 	ldr	x24, [sp, #152]
    80205f40:	14000004 	b	80205f50 <_vfprintf_r+0x2750>
    80205f44:	51004273 	sub	w19, w19, #0x10
    80205f48:	7100427f 	cmp	w19, #0x10
    80205f4c:	540003cd 	b.le	80205fc4 <_vfprintf_r+0x27c4>
    80205f50:	91004000 	add	x0, x0, #0x10
    80205f54:	11000421 	add	w1, w1, #0x1
    80205f58:	a9005c44 	stp	x4, x23, [x2]
    80205f5c:	91004042 	add	x2, x2, #0x10
    80205f60:	b9019be1 	str	w1, [sp, #408]
    80205f64:	f900d3e0 	str	x0, [sp, #416]
    80205f68:	71001c3f 	cmp	w1, #0x7
    80205f6c:	54fffecd 	b.le	80205f44 <_vfprintf_r+0x2744>
    80205f70:	910643e2 	add	x2, sp, #0x190
    80205f74:	aa1503e1 	mov	x1, x21
    80205f78:	aa1803e0 	mov	x0, x24
    80205f7c:	9400035d 	bl	80206cf0 <__sprint_r>
    80205f80:	350015e0 	cbnz	w0, 8020623c <_vfprintf_r+0x2a3c>
    80205f84:	f940d3e0 	ldr	x0, [sp, #416]
    80205f88:	f0000043 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    80205f8c:	b9419be1 	ldr	w1, [sp, #408]
    80205f90:	aa1603e2 	mov	x2, x22
    80205f94:	91234064 	add	x4, x3, #0x8d0
    80205f98:	17ffffeb 	b	80205f44 <_vfprintf_r+0x2744>
    80205f9c:	f9404fe0 	ldr	x0, [sp, #152]
    80205fa0:	910643e2 	add	x2, sp, #0x190
    80205fa4:	aa1503e1 	mov	x1, x21
    80205fa8:	94000352 	bl	80206cf0 <__sprint_r>
    80205fac:	35005620 	cbnz	w0, 80206a70 <_vfprintf_r+0x3270>
    80205fb0:	f940d3e0 	ldr	x0, [sp, #416]
    80205fb4:	f0000041 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80205fb8:	aa1603e2 	mov	x2, x22
    80205fbc:	91234024 	add	x4, x1, #0x8d0
    80205fc0:	17ffffb5 	b	80205e94 <_vfprintf_r+0x2694>
    80205fc4:	a94c2be3 	ldp	x3, x10, [sp, #192]
    80205fc8:	f9406bf8 	ldr	x24, [sp, #208]
    80205fcc:	93407e65 	sxtw	x5, w19
    80205fd0:	11000421 	add	w1, w1, #0x1
    80205fd4:	8b050000 	add	x0, x0, x5
    80205fd8:	a900144a 	stp	x10, x5, [x2]
    80205fdc:	b9019be1 	str	w1, [sp, #408]
    80205fe0:	f900d3e0 	str	x0, [sp, #416]
    80205fe4:	71001c3f 	cmp	w1, #0x7
    80205fe8:	5400110c 	b.gt	80206208 <_vfprintf_r+0x2a08>
    80205fec:	39400361 	ldrb	w1, [x27]
    80205ff0:	91004042 	add	x2, x2, #0x10
    80205ff4:	17ffffbf 	b	80205ef0 <_vfprintf_r+0x26f0>
    80205ff8:	f9404fe0 	ldr	x0, [sp, #152]
    80205ffc:	910643e2 	add	x2, sp, #0x190
    80206000:	aa1503e1 	mov	x1, x21
    80206004:	f90063f8 	str	x24, [sp, #192]
    80206008:	9400033a 	bl	80206cf0 <__sprint_r>
    8020600c:	35005320 	cbnz	w0, 80206a70 <_vfprintf_r+0x3270>
    80206010:	f94063e3 	ldr	x3, [sp, #192]
    80206014:	d0000044 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80206018:	f940d3e0 	ldr	x0, [sp, #416]
    8020601c:	aa1603e2 	mov	x2, x22
    80206020:	39400361 	ldrb	w1, [x27]
    80206024:	91234084 	add	x4, x4, #0x8d0
    80206028:	17ffffad 	b	80205edc <_vfprintf_r+0x26dc>
    8020602c:	b94097e1 	ldr	w1, [sp, #148]
    80206030:	6b01031f 	cmp	w24, w1
    80206034:	540017ab 	b.lt	80206328 <_vfprintf_r+0x2b28>  // b.tstop
    80206038:	b940abe0 	ldr	w0, [sp, #168]
    8020603c:	f240013f 	tst	x9, #0x1
    80206040:	0b00030c 	add	w12, w24, w0
    80206044:	1a981197 	csel	w23, w12, w24, ne	// ne = any
    80206048:	36500069 	tbz	w9, #10, 80206054 <_vfprintf_r+0x2854>
    8020604c:	7100031f 	cmp	w24, #0x0
    80206050:	54002f0c 	b.gt	80206630 <_vfprintf_r+0x2e30>
    80206054:	710002ff 	cmp	w23, #0x0
    80206058:	52800ce8 	mov	w8, #0x67                  	// #103
    8020605c:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    80206060:	2a1903e9 	mov	w9, w25
    80206064:	d2800019 	mov	x25, #0x0                   	// #0
    80206068:	b9008bff 	str	wzr, [sp, #136]
    8020606c:	b9009bff 	str	wzr, [sp, #152]
    80206070:	17fffe5b 	b	802059dc <_vfprintf_r+0x21dc>
    80206074:	910643e2 	add	x2, sp, #0x190
    80206078:	aa1503e1 	mov	x1, x21
    8020607c:	aa1303e0 	mov	x0, x19
    80206080:	b9008be9 	str	w9, [sp, #136]
    80206084:	b9009beb 	str	w11, [sp, #152]
    80206088:	f9005fea 	str	x10, [sp, #184]
    8020608c:	94000319 	bl	80206cf0 <__sprint_r>
    80206090:	35fefd80 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    80206094:	f9405fea 	ldr	x10, [sp, #184]
    80206098:	aa1603fc 	mov	x28, x22
    8020609c:	f940d3e0 	ldr	x0, [sp, #416]
    802060a0:	b9408be9 	ldr	w9, [sp, #136]
    802060a4:	b9409beb 	ldr	w11, [sp, #152]
    802060a8:	b9416be2 	ldr	w2, [sp, #360]
    802060ac:	17fff7b5 	b	80203f80 <_vfprintf_r+0x780>
    802060b0:	710116ff 	cmp	w23, #0x45
    802060b4:	54000341 	b.ne	8020611c <_vfprintf_r+0x291c>  // b.any
    802060b8:	110004f8 	add	w24, w7, #0x1
    802060bc:	52800041 	mov	w1, #0x2                   	// #2
    802060c0:	2a1803e2 	mov	w2, w24
    802060c4:	910623e5 	add	x5, sp, #0x188
    802060c8:	910603e4 	add	x4, sp, #0x180
    802060cc:	9105a3e3 	add	x3, sp, #0x168
    802060d0:	aa1303e0 	mov	x0, x19
    802060d4:	b9008be7 	str	w7, [sp, #136]
    802060d8:	9400127a 	bl	8020aac0 <_dtoa_r>
    802060dc:	aa0003fb 	mov	x27, x0
    802060e0:	f94067ea 	ldr	x10, [sp, #200]
    802060e4:	8b38c001 	add	x1, x0, w24, sxtw
    802060e8:	b9408be7 	ldr	w7, [sp, #136]
    802060ec:	2952a3e9 	ldp	w9, w8, [sp, #148]
    802060f0:	b940c3eb 	ldr	w11, [sp, #192]
    802060f4:	17fffded 	b	802058a8 <_vfprintf_r+0x20a8>
    802060f8:	39457fe1 	ldrb	w1, [sp, #351]
    802060fc:	5280001a 	mov	w26, #0x0                   	// #0
    80206100:	b9008bff 	str	wzr, [sp, #136]
    80206104:	52800007 	mov	w7, #0x0                   	// #0
    80206108:	b9009bff 	str	wzr, [sp, #152]
    8020610c:	52800018 	mov	w24, #0x0                   	// #0
    80206110:	d2800019 	mov	x25, #0x0                   	// #0
    80206114:	34fecde1 	cbz	w1, 80203ad0 <_vfprintf_r+0x2d0>
    80206118:	17fff8c2 	b	80204420 <_vfprintf_r+0xc20>
    8020611c:	2a0703e2 	mov	w2, w7
    80206120:	910623e5 	add	x5, sp, #0x188
    80206124:	910603e4 	add	x4, sp, #0x180
    80206128:	9105a3e3 	add	x3, sp, #0x168
    8020612c:	aa1303e0 	mov	x0, x19
    80206130:	52800041 	mov	w1, #0x2                   	// #2
    80206134:	b9008be7 	str	w7, [sp, #136]
    80206138:	94001262 	bl	8020aac0 <_dtoa_r>
    8020613c:	2952a3e9 	ldp	w9, w8, [sp, #148]
    80206140:	aa0003fb 	mov	x27, x0
    80206144:	f94067ea 	ldr	x10, [sp, #200]
    80206148:	b9408be7 	ldr	w7, [sp, #136]
    8020614c:	b940c3eb 	ldr	w11, [sp, #192]
    80206150:	3607de49 	tbz	w9, #0, 80205d18 <_vfprintf_r+0x2518>
    80206154:	8b27c361 	add	x1, x27, w7, sxtw
    80206158:	17fffdd4 	b	802058a8 <_vfprintf_r+0x20a8>
    8020615c:	b94093e0 	ldr	w0, [sp, #144]
    80206160:	11002001 	add	w1, w0, #0x8
    80206164:	7100003f 	cmp	w1, #0x0
    80206168:	54001e0d 	b.le	80206528 <_vfprintf_r+0x2d28>
    8020616c:	f9403fe0 	ldr	x0, [sp, #120]
    80206170:	b90093e1 	str	w1, [sp, #144]
    80206174:	91002c02 	add	x2, x0, #0xb
    80206178:	927df041 	and	x1, x2, #0xfffffffffffffff8
    8020617c:	f9003fe1 	str	x1, [sp, #120]
    80206180:	17fff8ed 	b	80204534 <_vfprintf_r+0xd34>
    80206184:	f94053e2 	ldr	x2, [sp, #160]
    80206188:	b94093e0 	ldr	w0, [sp, #144]
    8020618c:	b90093e1 	str	w1, [sp, #144]
    80206190:	8b20c042 	add	x2, x2, w0, sxtw
    80206194:	f9403fe0 	ldr	x0, [sp, #120]
    80206198:	f9003fe2 	str	x2, [sp, #120]
    8020619c:	17fff942 	b	802046a4 <_vfprintf_r+0xea4>
    802061a0:	f94053e2 	ldr	x2, [sp, #160]
    802061a4:	b94093e0 	ldr	w0, [sp, #144]
    802061a8:	b90093e1 	str	w1, [sp, #144]
    802061ac:	8b20c040 	add	x0, x2, w0, sxtw
    802061b0:	17fff8f9 	b	80204594 <_vfprintf_r+0xd94>
    802061b4:	f94053e2 	ldr	x2, [sp, #160]
    802061b8:	b94093e0 	ldr	w0, [sp, #144]
    802061bc:	b90093e1 	str	w1, [sp, #144]
    802061c0:	8b20c040 	add	x0, x2, w0, sxtw
    802061c4:	17fff9ab 	b	80204870 <_vfprintf_r+0x1070>
    802061c8:	910643e2 	add	x2, sp, #0x190
    802061cc:	aa1503e1 	mov	x1, x21
    802061d0:	aa1303e0 	mov	x0, x19
    802061d4:	f9005fec 	str	x12, [sp, #184]
    802061d8:	b900c3e9 	str	w9, [sp, #192]
    802061dc:	b900cbeb 	str	w11, [sp, #200]
    802061e0:	f9006bea 	str	x10, [sp, #208]
    802061e4:	940002c3 	bl	80206cf0 <__sprint_r>
    802061e8:	35fef2c0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    802061ec:	f9405fec 	ldr	x12, [sp, #184]
    802061f0:	aa1603fc 	mov	x28, x22
    802061f4:	f9406bea 	ldr	x10, [sp, #208]
    802061f8:	f940d3e0 	ldr	x0, [sp, #416]
    802061fc:	b940c3e9 	ldr	w9, [sp, #192]
    80206200:	b940cbeb 	ldr	w11, [sp, #200]
    80206204:	17fffa54 	b	80204b54 <_vfprintf_r+0x1354>
    80206208:	f9404fe0 	ldr	x0, [sp, #152]
    8020620c:	910643e2 	add	x2, sp, #0x190
    80206210:	aa1503e1 	mov	x1, x21
    80206214:	f90063e3 	str	x3, [sp, #192]
    80206218:	940002b6 	bl	80206cf0 <__sprint_r>
    8020621c:	350042a0 	cbnz	w0, 80206a70 <_vfprintf_r+0x3270>
    80206220:	f94063e3 	ldr	x3, [sp, #192]
    80206224:	d0000044 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80206228:	f940d3e0 	ldr	x0, [sp, #416]
    8020622c:	aa1603e2 	mov	x2, x22
    80206230:	39400361 	ldrb	w1, [x27]
    80206234:	91234084 	add	x4, x4, #0x8d0
    80206238:	17ffff2e 	b	80205ef0 <_vfprintf_r+0x26f0>
    8020623c:	f9405fe1 	ldr	x1, [sp, #184]
    80206240:	aa1803f3 	mov	x19, x24
    80206244:	b5fef021 	cbnz	x1, 80204048 <_vfprintf_r+0x848>
    80206248:	17fff782 	b	80204050 <_vfprintf_r+0x850>
    8020624c:	f94077e1 	ldr	x1, [sp, #232]
    80206250:	b9008be8 	str	w8, [sp, #136]
    80206254:	f94083e0 	ldr	x0, [sp, #256]
    80206258:	29129feb 	stp	w11, w7, [sp, #148]
    8020625c:	a90babe3 	stp	x3, x10, [sp, #184]
    80206260:	cb00037b 	sub	x27, x27, x0
    80206264:	aa0003e2 	mov	x2, x0
    80206268:	aa1b03e0 	mov	x0, x27
    8020626c:	f90067e4 	str	x4, [sp, #200]
    80206270:	94001b1c 	bl	8020cee0 <strncpy>
    80206274:	394006a0 	ldrb	w0, [x21, #1]
    80206278:	52800005 	mov	w5, #0x0                   	// #0
    8020627c:	a94babe3 	ldp	x3, x10, [sp, #184]
    80206280:	7100001f 	cmp	w0, #0x0
    80206284:	f94067e4 	ldr	x4, [sp, #200]
    80206288:	9a9506b5 	cinc	x21, x21, ne	// ne = any
    8020628c:	b9408be8 	ldr	w8, [sp, #136]
    80206290:	29529feb 	ldp	w11, w7, [sp, #148]
    80206294:	17fffccb 	b	802055c0 <_vfprintf_r+0x1dc0>
    80206298:	b9416bf8 	ldr	w24, [sp, #360]
    8020629c:	aa0103e0 	mov	x0, x1
    802062a0:	17fffd8f 	b	802058dc <_vfprintf_r+0x20dc>
    802062a4:	910643e2 	add	x2, sp, #0x190
    802062a8:	aa1503e1 	mov	x1, x21
    802062ac:	aa1303e0 	mov	x0, x19
    802062b0:	b9008be9 	str	w9, [sp, #136]
    802062b4:	b9009beb 	str	w11, [sp, #152]
    802062b8:	f9005fea 	str	x10, [sp, #184]
    802062bc:	9400028d 	bl	80206cf0 <__sprint_r>
    802062c0:	35feec00 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    802062c4:	2952afe1 	ldp	w1, w11, [sp, #148]
    802062c8:	aa1603fc 	mov	x28, x22
    802062cc:	b9416bf7 	ldr	w23, [sp, #360]
    802062d0:	f9405fea 	ldr	x10, [sp, #184]
    802062d4:	4b170037 	sub	w23, w1, w23
    802062d8:	f940d3e0 	ldr	x0, [sp, #416]
    802062dc:	b9408be9 	ldr	w9, [sp, #136]
    802062e0:	17fffa3b 	b	80204bcc <_vfprintf_r+0x13cc>
    802062e4:	1e602128 	fcmp	d9, #0.0
    802062e8:	54003141 	b.ne	80206910 <_vfprintf_r+0x3110>  // b.any
    802062ec:	b9416bf8 	ldr	w24, [sp, #360]
    802062f0:	8b38c000 	add	x0, x0, w24, sxtw
    802062f4:	4b1b0000 	sub	w0, w0, w27
    802062f8:	b90097e0 	str	w0, [sp, #148]
    802062fc:	12000120 	and	w0, w9, #0x1
    80206300:	2a070000 	orr	w0, w0, w7
    80206304:	7100031f 	cmp	w24, #0x0
    80206308:	540033ad 	b.le	8020697c <_vfprintf_r+0x317c>
    8020630c:	35001880 	cbnz	w0, 8020661c <_vfprintf_r+0x2e1c>
    80206310:	2a1803f7 	mov	w23, w24
    80206314:	52800cc8 	mov	w8, #0x66                  	// #102
    80206318:	375018e9 	tbnz	w9, #10, 80206634 <_vfprintf_r+0x2e34>
    8020631c:	710002ff 	cmp	w23, #0x0
    80206320:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    80206324:	17ffff4f 	b	80206060 <_vfprintf_r+0x2860>
    80206328:	b940abe1 	ldr	w1, [sp, #168]
    8020632c:	52800ce8 	mov	w8, #0x67                  	// #103
    80206330:	0b000037 	add	w23, w1, w0
    80206334:	7100031f 	cmp	w24, #0x0
    80206338:	54ffff0c 	b.gt	80206318 <_vfprintf_r+0x2b18>
    8020633c:	4b1802ec 	sub	w12, w23, w24
    80206340:	31000597 	adds	w23, w12, #0x1
    80206344:	1a9f52fa 	csel	w26, w23, wzr, pl	// pl = nfrst
    80206348:	17ffff46 	b	80206060 <_vfprintf_r+0x2860>
    8020634c:	b940b2a0 	ldr	w0, [x21, #176]
    80206350:	370000a0 	tbnz	w0, #0, 80206364 <_vfprintf_r+0x2b64>
    80206354:	794022a0 	ldrh	w0, [x21, #16]
    80206358:	37480060 	tbnz	w0, #9, 80206364 <_vfprintf_r+0x2b64>
    8020635c:	f94052a0 	ldr	x0, [x21, #160]
    80206360:	94000c28 	bl	80209400 <__retarget_lock_release_recursive>
    80206364:	12800000 	mov	w0, #0xffffffff            	// #-1
    80206368:	b90077e0 	str	w0, [sp, #116]
    8020636c:	17fff740 	b	8020406c <_vfprintf_r+0x86c>
    80206370:	9106a3fb 	add	x27, sp, #0x1a8
    80206374:	d2800019 	mov	x25, #0x0                   	// #0
    80206378:	17fffc53 	b	802054c4 <_vfprintf_r+0x1cc4>
    8020637c:	d0000044 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    80206380:	4b0203f7 	neg	w23, w2
    80206384:	91234084 	add	x4, x4, #0x8d0
    80206388:	3100405f 	cmn	w2, #0x10
    8020638c:	540004ea 	b.ge	80206428 <_vfprintf_r+0x2c28>  // b.tcont
    80206390:	aa1503e2 	mov	x2, x21
    80206394:	2a0903fc 	mov	w28, w9
    80206398:	2a1703f5 	mov	w21, w23
    8020639c:	d2800218 	mov	x24, #0x10                  	// #16
    802063a0:	aa0203f7 	mov	x23, x2
    802063a4:	f90047f9 	str	x25, [sp, #136]
    802063a8:	aa0403f9 	mov	x25, x4
    802063ac:	b9009beb 	str	w11, [sp, #152]
    802063b0:	f9005fea 	str	x10, [sp, #184]
    802063b4:	14000004 	b	802063c4 <_vfprintf_r+0x2bc4>
    802063b8:	510042b5 	sub	w21, w21, #0x10
    802063bc:	710042bf 	cmp	w21, #0x10
    802063c0:	5400024d 	b.le	80206408 <_vfprintf_r+0x2c08>
    802063c4:	91004000 	add	x0, x0, #0x10
    802063c8:	11000421 	add	w1, w1, #0x1
    802063cc:	a90060d9 	stp	x25, x24, [x6]
    802063d0:	910040c6 	add	x6, x6, #0x10
    802063d4:	b9019be1 	str	w1, [sp, #408]
    802063d8:	f900d3e0 	str	x0, [sp, #416]
    802063dc:	71001c3f 	cmp	w1, #0x7
    802063e0:	54fffecd 	b.le	802063b8 <_vfprintf_r+0x2bb8>
    802063e4:	910643e2 	add	x2, sp, #0x190
    802063e8:	aa1703e1 	mov	x1, x23
    802063ec:	aa1303e0 	mov	x0, x19
    802063f0:	94000240 	bl	80206cf0 <__sprint_r>
    802063f4:	35002560 	cbnz	w0, 802068a0 <_vfprintf_r+0x30a0>
    802063f8:	f940d3e0 	ldr	x0, [sp, #416]
    802063fc:	aa1603e6 	mov	x6, x22
    80206400:	b9419be1 	ldr	w1, [sp, #408]
    80206404:	17ffffed 	b	802063b8 <_vfprintf_r+0x2bb8>
    80206408:	f9405fea 	ldr	x10, [sp, #184]
    8020640c:	aa1703e2 	mov	x2, x23
    80206410:	aa1903e4 	mov	x4, x25
    80206414:	b9409beb 	ldr	w11, [sp, #152]
    80206418:	f94047f9 	ldr	x25, [sp, #136]
    8020641c:	2a1503f7 	mov	w23, w21
    80206420:	2a1c03e9 	mov	w9, w28
    80206424:	aa0203f5 	mov	x21, x2
    80206428:	93407ef7 	sxtw	x23, w23
    8020642c:	11000421 	add	w1, w1, #0x1
    80206430:	8b170000 	add	x0, x0, x23
    80206434:	a9005cc4 	stp	x4, x23, [x6]
    80206438:	910040c6 	add	x6, x6, #0x10
    8020643c:	b9019be1 	str	w1, [sp, #408]
    80206440:	f900d3e0 	str	x0, [sp, #416]
    80206444:	71001c3f 	cmp	w1, #0x7
    80206448:	54fedb8d 	b.le	80203fb8 <_vfprintf_r+0x7b8>
    8020644c:	910643e2 	add	x2, sp, #0x190
    80206450:	aa1503e1 	mov	x1, x21
    80206454:	aa1303e0 	mov	x0, x19
    80206458:	b9008be9 	str	w9, [sp, #136]
    8020645c:	b9009beb 	str	w11, [sp, #152]
    80206460:	f9005fea 	str	x10, [sp, #184]
    80206464:	94000223 	bl	80206cf0 <__sprint_r>
    80206468:	35fedec0 	cbnz	w0, 80204040 <_vfprintf_r+0x840>
    8020646c:	f9405fea 	ldr	x10, [sp, #184]
    80206470:	aa1603e6 	mov	x6, x22
    80206474:	f940d3e0 	ldr	x0, [sp, #416]
    80206478:	b9408be9 	ldr	w9, [sp, #136]
    8020647c:	b9409beb 	ldr	w11, [sp, #152]
    80206480:	b9419be1 	ldr	w1, [sp, #408]
    80206484:	17fff6cd 	b	80203fb8 <_vfprintf_r+0x7b8>
    80206488:	f94087e2 	ldr	x2, [sp, #264]
    8020648c:	b940f7e0 	ldr	w0, [sp, #244]
    80206490:	b900f7e1 	str	w1, [sp, #244]
    80206494:	8b20c040 	add	x0, x2, w0, sxtw
    80206498:	fd400008 	ldr	d8, [x0]
    8020649c:	17fff7c9 	b	802043c0 <_vfprintf_r+0xbc0>
    802064a0:	9105cbe1 	add	x1, sp, #0x172
    802064a4:	35000082 	cbnz	w2, 802064b4 <_vfprintf_r+0x2cb4>
    802064a8:	9105cfe1 	add	x1, sp, #0x173
    802064ac:	52800602 	mov	w2, #0x30                  	// #48
    802064b0:	3905cbe2 	strb	w2, [sp, #370]
    802064b4:	1100c000 	add	w0, w0, #0x30
    802064b8:	38001420 	strb	w0, [x1], #1
    802064bc:	9105c3e2 	add	x2, sp, #0x170
    802064c0:	4b020020 	sub	w0, w1, w2
    802064c4:	b900f3e0 	str	w0, [sp, #240]
    802064c8:	17fffd37 	b	802059a4 <_vfprintf_r+0x21a4>
    802064cc:	f94087e2 	ldr	x2, [sp, #264]
    802064d0:	b940f7e0 	ldr	w0, [sp, #244]
    802064d4:	b900f7e1 	str	w1, [sp, #244]
    802064d8:	8b20c040 	add	x0, x2, w0, sxtw
    802064dc:	17fff7ac 	b	8020438c <_vfprintf_r+0xb8c>
    802064e0:	f94047f5 	ldr	x21, [sp, #136]
    802064e4:	d2800001 	mov	x1, #0x0                   	// #0
    802064e8:	79c022a0 	ldrsh	w0, [x21, #16]
    802064ec:	321a0000 	orr	w0, w0, #0x40
    802064f0:	790022a0 	strh	w0, [x21, #16]
    802064f4:	b5fedaa1 	cbnz	x1, 80204048 <_vfprintf_r+0x848>
    802064f8:	17fff6d6 	b	80204050 <_vfprintf_r+0x850>
    802064fc:	37f81a20 	tbnz	w0, #31, 80206840 <_vfprintf_r+0x3040>
    80206500:	f9403fe0 	ldr	x0, [sp, #120]
    80206504:	91003c01 	add	x1, x0, #0xf
    80206508:	927df021 	and	x1, x1, #0xfffffffffffffff8
    8020650c:	f9003fe1 	str	x1, [sp, #120]
    80206510:	f9400000 	ldr	x0, [x0]
    80206514:	b94077e1 	ldr	w1, [sp, #116]
    80206518:	b9000001 	str	w1, [x0]
    8020651c:	17fff4fe 	b	80203914 <_vfprintf_r+0x114>
    80206520:	3607a509 	tbz	w9, #0, 802059c0 <_vfprintf_r+0x21c0>
    80206524:	17fffd25 	b	802059b8 <_vfprintf_r+0x21b8>
    80206528:	f94053e2 	ldr	x2, [sp, #160]
    8020652c:	b94093e0 	ldr	w0, [sp, #144]
    80206530:	b90093e1 	str	w1, [sp, #144]
    80206534:	8b20c040 	add	x0, x2, w0, sxtw
    80206538:	17fff7ff 	b	80204534 <_vfprintf_r+0xd34>
    8020653c:	b94093e0 	ldr	w0, [sp, #144]
    80206540:	11002001 	add	w1, w0, #0x8
    80206544:	7100003f 	cmp	w1, #0x0
    80206548:	54001ecd 	b.le	80206920 <_vfprintf_r+0x3120>
    8020654c:	f9403fe0 	ldr	x0, [sp, #120]
    80206550:	b90093e1 	str	w1, [sp, #144]
    80206554:	91002c02 	add	x2, x0, #0xb
    80206558:	927df041 	and	x1, x2, #0xfffffffffffffff8
    8020655c:	f9003fe1 	str	x1, [sp, #120]
    80206560:	17fffd7a 	b	80205b48 <_vfprintf_r+0x2348>
    80206564:	b94093e0 	ldr	w0, [sp, #144]
    80206568:	11002001 	add	w1, w0, #0x8
    8020656c:	7100003f 	cmp	w1, #0x0
    80206570:	54001e2d 	b.le	80206934 <_vfprintf_r+0x3134>
    80206574:	f9403fe0 	ldr	x0, [sp, #120]
    80206578:	b90093e1 	str	w1, [sp, #144]
    8020657c:	91002c02 	add	x2, x0, #0xb
    80206580:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206584:	39400000 	ldrb	w0, [x0]
    80206588:	f9003fe1 	str	x1, [sp, #120]
    8020658c:	17fffad0 	b	802050cc <_vfprintf_r+0x18cc>
    80206590:	9e660100 	fmov	x0, d8
    80206594:	b7f817e0 	tbnz	x0, #63, 80206890 <_vfprintf_r+0x3090>
    80206598:	39457fe1 	ldrb	w1, [sp, #351]
    8020659c:	d0000040 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    802065a0:	d0000045 	adrp	x5, 80210000 <__trunctfdf2+0xc0>
    802065a4:	71011d1f 	cmp	w8, #0x47
    802065a8:	9113c000 	add	x0, x0, #0x4f0
    802065ac:	9113e0a5 	add	x5, x5, #0x4f8
    802065b0:	17fff791 	b	802043f4 <_vfprintf_r+0xbf4>
    802065b4:	f94053e2 	ldr	x2, [sp, #160]
    802065b8:	b94093e0 	ldr	w0, [sp, #144]
    802065bc:	b90093e1 	str	w1, [sp, #144]
    802065c0:	8b20c040 	add	x0, x2, w0, sxtw
    802065c4:	79400000 	ldrh	w0, [x0]
    802065c8:	17fffac1 	b	802050cc <_vfprintf_r+0x18cc>
    802065cc:	f94053e2 	ldr	x2, [sp, #160]
    802065d0:	b94093e0 	ldr	w0, [sp, #144]
    802065d4:	b90093e1 	str	w1, [sp, #144]
    802065d8:	8b20c040 	add	x0, x2, w0, sxtw
    802065dc:	17fff9df 	b	80204d58 <_vfprintf_r+0x1558>
    802065e0:	0b1b00e1 	add	w1, w7, w27
    802065e4:	52800603 	mov	w3, #0x30                  	// #48
    802065e8:	4b000021 	sub	w1, w1, w0
    802065ec:	11000422 	add	w2, w1, #0x1
    802065f0:	8b22c002 	add	x2, x0, w2, sxtw
    802065f4:	37ff6aa1 	tbnz	w1, #31, 80205348 <_vfprintf_r+0x1b48>
    802065f8:	38001403 	strb	w3, [x0], #1
    802065fc:	eb00005f 	cmp	x2, x0
    80206600:	54ffffc1 	b.ne	802065f8 <_vfprintf_r+0x2df8>  // b.any
    80206604:	17fffb51 	b	80205348 <_vfprintf_r+0x1b48>
    80206608:	f94053e2 	ldr	x2, [sp, #160]
    8020660c:	b94093e0 	ldr	w0, [sp, #144]
    80206610:	b90093e1 	str	w1, [sp, #144]
    80206614:	8b20c040 	add	x0, x2, w0, sxtw
    80206618:	17fff9c7 	b	80204d34 <_vfprintf_r+0x1534>
    8020661c:	b940abe0 	ldr	w0, [sp, #168]
    80206620:	52800cc8 	mov	w8, #0x66                  	// #102
    80206624:	0b0000ec 	add	w12, w7, w0
    80206628:	0b180197 	add	w23, w12, w24
    8020662c:	17ffff3b 	b	80206318 <_vfprintf_r+0x2b18>
    80206630:	52800ce8 	mov	w8, #0x67                  	// #103
    80206634:	f9407fe1 	ldr	x1, [sp, #248]
    80206638:	39400020 	ldrb	w0, [x1]
    8020663c:	7103fc1f 	cmp	w0, #0xff
    80206640:	54002480 	b.eq	80206ad0 <_vfprintf_r+0x32d0>  // b.none
    80206644:	52800003 	mov	w3, #0x0                   	// #0
    80206648:	52800002 	mov	w2, #0x0                   	// #0
    8020664c:	14000005 	b	80206660 <_vfprintf_r+0x2e60>
    80206650:	11000442 	add	w2, w2, #0x1
    80206654:	91000421 	add	x1, x1, #0x1
    80206658:	7103fc1f 	cmp	w0, #0xff
    8020665c:	54000120 	b.eq	80206680 <_vfprintf_r+0x2e80>  // b.none
    80206660:	6b18001f 	cmp	w0, w24
    80206664:	540000ea 	b.ge	80206680 <_vfprintf_r+0x2e80>  // b.tcont
    80206668:	4b000318 	sub	w24, w24, w0
    8020666c:	39400420 	ldrb	w0, [x1, #1]
    80206670:	35ffff00 	cbnz	w0, 80206650 <_vfprintf_r+0x2e50>
    80206674:	39400020 	ldrb	w0, [x1]
    80206678:	11000463 	add	w3, w3, #0x1
    8020667c:	17fffff7 	b	80206658 <_vfprintf_r+0x2e58>
    80206680:	b9008be2 	str	w2, [sp, #136]
    80206684:	b9009be3 	str	w3, [sp, #152]
    80206688:	f9007fe1 	str	x1, [sp, #248]
    8020668c:	b9408be1 	ldr	w1, [sp, #136]
    80206690:	2a1903e9 	mov	w9, w25
    80206694:	b9409be0 	ldr	w0, [sp, #152]
    80206698:	d2800019 	mov	x25, #0x0                   	// #0
    8020669c:	0b010000 	add	w0, w0, w1
    802066a0:	b94103e1 	ldr	w1, [sp, #256]
    802066a4:	1b015c17 	madd	w23, w0, w1, w23
    802066a8:	710002ff 	cmp	w23, #0x0
    802066ac:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    802066b0:	17fffccb 	b	802059dc <_vfprintf_r+0x21dc>
    802066b4:	f94047f5 	ldr	x21, [sp, #136]
    802066b8:	2a1a03e8 	mov	w8, w26
    802066bc:	b9409be9 	ldr	w9, [sp, #152]
    802066c0:	aa1803ea 	mov	x10, x24
    802066c4:	b940bbeb 	ldr	w11, [sp, #184]
    802066c8:	2a1903f7 	mov	w23, w25
    802066cc:	17fffb6c 	b	8020547c <_vfprintf_r+0x1c7c>
    802066d0:	b94093e0 	ldr	w0, [sp, #144]
    802066d4:	11002001 	add	w1, w0, #0x8
    802066d8:	7100003f 	cmp	w1, #0x0
    802066dc:	5400166d 	b.le	802069a8 <_vfprintf_r+0x31a8>
    802066e0:	f9403fe0 	ldr	x0, [sp, #120]
    802066e4:	b90093e1 	str	w1, [sp, #144]
    802066e8:	91002c02 	add	x2, x0, #0xb
    802066ec:	927df041 	and	x1, x2, #0xfffffffffffffff8
    802066f0:	39400000 	ldrb	w0, [x0]
    802066f4:	f9003fe1 	str	x1, [sp, #120]
    802066f8:	17fff81c 	b	80204768 <_vfprintf_r+0xf68>
    802066fc:	b94093e0 	ldr	w0, [sp, #144]
    80206700:	11002001 	add	w1, w0, #0x8
    80206704:	7100003f 	cmp	w1, #0x0
    80206708:	540015cd 	b.le	802069c0 <_vfprintf_r+0x31c0>
    8020670c:	f9403fe0 	ldr	x0, [sp, #120]
    80206710:	b90093e1 	str	w1, [sp, #144]
    80206714:	91002c02 	add	x2, x0, #0xb
    80206718:	927df041 	and	x1, x2, #0xfffffffffffffff8
    8020671c:	f9003fe1 	str	x1, [sp, #120]
    80206720:	17fffd19 	b	80205b84 <_vfprintf_r+0x2384>
    80206724:	b94093e0 	ldr	w0, [sp, #144]
    80206728:	11002001 	add	w1, w0, #0x8
    8020672c:	7100003f 	cmp	w1, #0x0
    80206730:	54000e6d 	b.le	802068fc <_vfprintf_r+0x30fc>
    80206734:	f9403fe0 	ldr	x0, [sp, #120]
    80206738:	b90093e1 	str	w1, [sp, #144]
    8020673c:	91002c02 	add	x2, x0, #0xb
    80206740:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206744:	f9003fe1 	str	x1, [sp, #120]
    80206748:	17fffbfa 	b	80205730 <_vfprintf_r+0x1f30>
    8020674c:	b94093e0 	ldr	w0, [sp, #144]
    80206750:	11002001 	add	w1, w0, #0x8
    80206754:	7100003f 	cmp	w1, #0x0
    80206758:	540015ad 	b.le	80206a0c <_vfprintf_r+0x320c>
    8020675c:	f9403fe0 	ldr	x0, [sp, #120]
    80206760:	b90093e1 	str	w1, [sp, #144]
    80206764:	91003c02 	add	x2, x0, #0xf
    80206768:	927df041 	and	x1, x2, #0xfffffffffffffff8
    8020676c:	f9003fe1 	str	x1, [sp, #120]
    80206770:	17fffce6 	b	80205b08 <_vfprintf_r+0x2308>
    80206774:	528005a0 	mov	w0, #0x2d                  	// #45
    80206778:	1e614109 	fneg	d9, d8
    8020677c:	b900bbe0 	str	w0, [sp, #184]
    80206780:	17fffc31 	b	80205844 <_vfprintf_r+0x2044>
    80206784:	f94053e2 	ldr	x2, [sp, #160]
    80206788:	b94093e0 	ldr	w0, [sp, #144]
    8020678c:	b90093e1 	str	w1, [sp, #144]
    80206790:	8b20c040 	add	x0, x2, w0, sxtw
    80206794:	79400000 	ldrh	w0, [x0]
    80206798:	17fff7f4 	b	80204768 <_vfprintf_r+0xf68>
    8020679c:	b94093e0 	ldr	w0, [sp, #144]
    802067a0:	11002001 	add	w1, w0, #0x8
    802067a4:	7100003f 	cmp	w1, #0x0
    802067a8:	54000a0d 	b.le	802068e8 <_vfprintf_r+0x30e8>
    802067ac:	f9403fe0 	ldr	x0, [sp, #120]
    802067b0:	b90093e1 	str	w1, [sp, #144]
    802067b4:	91002c02 	add	x2, x0, #0xb
    802067b8:	927df041 	and	x1, x2, #0xfffffffffffffff8
    802067bc:	f9003fe1 	str	x1, [sp, #120]
    802067c0:	17fffc0e 	b	802057f8 <_vfprintf_r+0x1ff8>
    802067c4:	b94093e0 	ldr	w0, [sp, #144]
    802067c8:	11002001 	add	w1, w0, #0x8
    802067cc:	7100003f 	cmp	w1, #0x0
    802067d0:	5400128d 	b.le	80206a20 <_vfprintf_r+0x3220>
    802067d4:	f9403fe0 	ldr	x0, [sp, #120]
    802067d8:	b90093e1 	str	w1, [sp, #144]
    802067dc:	91002c02 	add	x2, x0, #0xb
    802067e0:	927df041 	and	x1, x2, #0xfffffffffffffff8
    802067e4:	b9400000 	ldr	w0, [x0]
    802067e8:	f9003fe1 	str	x1, [sp, #120]
    802067ec:	17fff7df 	b	80204768 <_vfprintf_r+0xf68>
    802067f0:	39457fe1 	ldrb	w1, [sp, #351]
    802067f4:	2a0703fa 	mov	w26, w7
    802067f8:	b9008bff 	str	wzr, [sp, #136]
    802067fc:	2a0703f7 	mov	w23, w7
    80206800:	b9009bff 	str	wzr, [sp, #152]
    80206804:	52800007 	mov	w7, #0x0                   	// #0
    80206808:	52800e68 	mov	w8, #0x73                  	// #115
    8020680c:	34fe9621 	cbz	w1, 80203ad0 <_vfprintf_r+0x2d0>
    80206810:	17fff704 	b	80204420 <_vfprintf_r+0xc20>
    80206814:	b94093e0 	ldr	w0, [sp, #144]
    80206818:	11002001 	add	w1, w0, #0x8
    8020681c:	7100003f 	cmp	w1, #0x0
    80206820:	540011cd 	b.le	80206a58 <_vfprintf_r+0x3258>
    80206824:	f9403fe0 	ldr	x0, [sp, #120]
    80206828:	b90093e1 	str	w1, [sp, #144]
    8020682c:	91002c02 	add	x2, x0, #0xb
    80206830:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206834:	b9400000 	ldr	w0, [x0]
    80206838:	f9003fe1 	str	x1, [sp, #120]
    8020683c:	17fffa24 	b	802050cc <_vfprintf_r+0x18cc>
    80206840:	b94093e0 	ldr	w0, [sp, #144]
    80206844:	11002001 	add	w1, w0, #0x8
    80206848:	7100003f 	cmp	w1, #0x0
    8020684c:	5400086d 	b.le	80206958 <_vfprintf_r+0x3158>
    80206850:	f9403fe0 	ldr	x0, [sp, #120]
    80206854:	b90093e1 	str	w1, [sp, #144]
    80206858:	91003c02 	add	x2, x0, #0xf
    8020685c:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206860:	f9003fe1 	str	x1, [sp, #120]
    80206864:	17ffff2b 	b	80206510 <_vfprintf_r+0x2d10>
    80206868:	b94093e0 	ldr	w0, [sp, #144]
    8020686c:	11002001 	add	w1, w0, #0x8
    80206870:	7100003f 	cmp	w1, #0x0
    80206874:	5400106d 	b.le	80206a80 <_vfprintf_r+0x3280>
    80206878:	f9403fe0 	ldr	x0, [sp, #120]
    8020687c:	b90093e1 	str	w1, [sp, #144]
    80206880:	91003c02 	add	x2, x0, #0xf
    80206884:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206888:	f9003fe1 	str	x1, [sp, #120]
    8020688c:	17fff945 	b	80204da0 <_vfprintf_r+0x15a0>
    80206890:	528005a0 	mov	w0, #0x2d                  	// #45
    80206894:	528005a1 	mov	w1, #0x2d                  	// #45
    80206898:	39057fe0 	strb	w0, [sp, #351]
    8020689c:	17ffff40 	b	8020659c <_vfprintf_r+0x2d9c>
    802068a0:	f94047e1 	ldr	x1, [sp, #136]
    802068a4:	aa1703f5 	mov	x21, x23
    802068a8:	b5febd01 	cbnz	x1, 80204048 <_vfprintf_r+0x848>
    802068ac:	17fff5e9 	b	80204050 <_vfprintf_r+0x850>
    802068b0:	f9404ff3 	ldr	x19, [sp, #152]
    802068b4:	aa1903e8 	mov	x8, x25
    802068b8:	f9405ff9 	ldr	x25, [sp, #184]
    802068bc:	f9007ffb 	str	x27, [sp, #248]
    802068c0:	f9406fec 	ldr	x12, [sp, #216]
    802068c4:	aa0203fc 	mov	x28, x2
    802068c8:	f9408ffb 	ldr	x27, [sp, #280]
    802068cc:	f94097ea 	ldr	x10, [sp, #296]
    802068d0:	b94113e9 	ldr	w9, [sp, #272]
    802068d4:	b94123eb 	ldr	w11, [sp, #288]
    802068d8:	b94127fa 	ldr	w26, [sp, #292]
    802068dc:	eb03011f 	cmp	x8, x3
    802068e0:	9a839108 	csel	x8, x8, x3, ls	// ls = plast
    802068e4:	17fff8a3 	b	80204b70 <_vfprintf_r+0x1370>
    802068e8:	f94053e2 	ldr	x2, [sp, #160]
    802068ec:	b94093e0 	ldr	w0, [sp, #144]
    802068f0:	b90093e1 	str	w1, [sp, #144]
    802068f4:	8b20c040 	add	x0, x2, w0, sxtw
    802068f8:	17fffbc0 	b	802057f8 <_vfprintf_r+0x1ff8>
    802068fc:	f94053e2 	ldr	x2, [sp, #160]
    80206900:	b94093e0 	ldr	w0, [sp, #144]
    80206904:	b90093e1 	str	w1, [sp, #144]
    80206908:	8b20c040 	add	x0, x2, w0, sxtw
    8020690c:	17fffb89 	b	80205730 <_vfprintf_r+0x1f30>
    80206910:	52800021 	mov	w1, #0x1                   	// #1
    80206914:	4b070021 	sub	w1, w1, w7
    80206918:	b9016be1 	str	w1, [sp, #360]
    8020691c:	17fffbe2 	b	802058a4 <_vfprintf_r+0x20a4>
    80206920:	f94053e2 	ldr	x2, [sp, #160]
    80206924:	b94093e0 	ldr	w0, [sp, #144]
    80206928:	b90093e1 	str	w1, [sp, #144]
    8020692c:	8b20c040 	add	x0, x2, w0, sxtw
    80206930:	17fffc86 	b	80205b48 <_vfprintf_r+0x2348>
    80206934:	f94053e2 	ldr	x2, [sp, #160]
    80206938:	b94093e0 	ldr	w0, [sp, #144]
    8020693c:	b90093e1 	str	w1, [sp, #144]
    80206940:	8b20c040 	add	x0, x2, w0, sxtw
    80206944:	39400000 	ldrb	w0, [x0]
    80206948:	17fff9e1 	b	802050cc <_vfprintf_r+0x18cc>
    8020694c:	52800040 	mov	w0, #0x2                   	// #2
    80206950:	b900f3e0 	str	w0, [sp, #240]
    80206954:	17fffc14 	b	802059a4 <_vfprintf_r+0x21a4>
    80206958:	f94053e2 	ldr	x2, [sp, #160]
    8020695c:	b94093e0 	ldr	w0, [sp, #144]
    80206960:	b90093e1 	str	w1, [sp, #144]
    80206964:	8b20c040 	add	x0, x2, w0, sxtw
    80206968:	17fffeea 	b	80206510 <_vfprintf_r+0x2d10>
    8020696c:	79c022a0 	ldrsh	w0, [x21, #16]
    80206970:	321a0000 	orr	w0, w0, #0x40
    80206974:	790022a0 	strh	w0, [x21, #16]
    80206978:	17fff5b7 	b	80204054 <_vfprintf_r+0x854>
    8020697c:	350000a0 	cbnz	w0, 80206990 <_vfprintf_r+0x3190>
    80206980:	5280003a 	mov	w26, #0x1                   	// #1
    80206984:	52800cc8 	mov	w8, #0x66                  	// #102
    80206988:	2a1a03f7 	mov	w23, w26
    8020698c:	17fffdb5 	b	80206060 <_vfprintf_r+0x2860>
    80206990:	b940abe0 	ldr	w0, [sp, #168]
    80206994:	52800cc8 	mov	w8, #0x66                  	// #102
    80206998:	1100040c 	add	w12, w0, #0x1
    8020699c:	2b070197 	adds	w23, w12, w7
    802069a0:	1a9f52fa 	csel	w26, w23, wzr, pl	// pl = nfrst
    802069a4:	17fffdaf 	b	80206060 <_vfprintf_r+0x2860>
    802069a8:	f94053e2 	ldr	x2, [sp, #160]
    802069ac:	b94093e0 	ldr	w0, [sp, #144]
    802069b0:	b90093e1 	str	w1, [sp, #144]
    802069b4:	8b20c040 	add	x0, x2, w0, sxtw
    802069b8:	39400000 	ldrb	w0, [x0]
    802069bc:	17fff76b 	b	80204768 <_vfprintf_r+0xf68>
    802069c0:	f94053e2 	ldr	x2, [sp, #160]
    802069c4:	b94093e0 	ldr	w0, [sp, #144]
    802069c8:	b90093e1 	str	w1, [sp, #144]
    802069cc:	8b20c040 	add	x0, x2, w0, sxtw
    802069d0:	17fffc6d 	b	80205b84 <_vfprintf_r+0x2384>
    802069d4:	b94093e2 	ldr	w2, [sp, #144]
    802069d8:	37f80302 	tbnz	w2, #31, 80206a38 <_vfprintf_r+0x3238>
    802069dc:	f9403fe0 	ldr	x0, [sp, #120]
    802069e0:	91002c00 	add	x0, x0, #0xb
    802069e4:	927df000 	and	x0, x0, #0xfffffffffffffff8
    802069e8:	f9403fe3 	ldr	x3, [sp, #120]
    802069ec:	f9003fe0 	str	x0, [sp, #120]
    802069f0:	39400748 	ldrb	w8, [x26, #1]
    802069f4:	aa0103fa 	mov	x26, x1
    802069f8:	b90093e2 	str	w2, [sp, #144]
    802069fc:	b9400067 	ldr	w7, [x3]
    80206a00:	710000ff 	cmp	w7, #0x0
    80206a04:	5a9fa0f9 	csinv	w25, w7, wzr, ge	// ge = tcont
    80206a08:	17fff419 	b	80203a6c <_vfprintf_r+0x26c>
    80206a0c:	f94053e2 	ldr	x2, [sp, #160]
    80206a10:	b94093e0 	ldr	w0, [sp, #144]
    80206a14:	b90093e1 	str	w1, [sp, #144]
    80206a18:	8b20c040 	add	x0, x2, w0, sxtw
    80206a1c:	17fffc3b 	b	80205b08 <_vfprintf_r+0x2308>
    80206a20:	f94053e2 	ldr	x2, [sp, #160]
    80206a24:	b94093e0 	ldr	w0, [sp, #144]
    80206a28:	b90093e1 	str	w1, [sp, #144]
    80206a2c:	8b20c040 	add	x0, x2, w0, sxtw
    80206a30:	b9400000 	ldr	w0, [x0]
    80206a34:	17fff74d 	b	80204768 <_vfprintf_r+0xf68>
    80206a38:	b94093e0 	ldr	w0, [sp, #144]
    80206a3c:	11002002 	add	w2, w0, #0x8
    80206a40:	f9403fe0 	ldr	x0, [sp, #120]
    80206a44:	7100005f 	cmp	w2, #0x0
    80206a48:	5400026d 	b.le	80206a94 <_vfprintf_r+0x3294>
    80206a4c:	91002c00 	add	x0, x0, #0xb
    80206a50:	927df000 	and	x0, x0, #0xfffffffffffffff8
    80206a54:	17ffffe5 	b	802069e8 <_vfprintf_r+0x31e8>
    80206a58:	f94053e2 	ldr	x2, [sp, #160]
    80206a5c:	b94093e0 	ldr	w0, [sp, #144]
    80206a60:	b90093e1 	str	w1, [sp, #144]
    80206a64:	8b20c040 	add	x0, x2, w0, sxtw
    80206a68:	b9400000 	ldr	w0, [x0]
    80206a6c:	17fff998 	b	802050cc <_vfprintf_r+0x18cc>
    80206a70:	f9405fe1 	ldr	x1, [sp, #184]
    80206a74:	f9404ff3 	ldr	x19, [sp, #152]
    80206a78:	b5feae81 	cbnz	x1, 80204048 <_vfprintf_r+0x848>
    80206a7c:	17fff575 	b	80204050 <_vfprintf_r+0x850>
    80206a80:	f94053e2 	ldr	x2, [sp, #160]
    80206a84:	b94093e0 	ldr	w0, [sp, #144]
    80206a88:	b90093e1 	str	w1, [sp, #144]
    80206a8c:	8b20c040 	add	x0, x2, w0, sxtw
    80206a90:	17fff8c4 	b	80204da0 <_vfprintf_r+0x15a0>
    80206a94:	f94053e4 	ldr	x4, [sp, #160]
    80206a98:	b94093e3 	ldr	w3, [sp, #144]
    80206a9c:	8b23c083 	add	x3, x4, w3, sxtw
    80206aa0:	f9003fe3 	str	x3, [sp, #120]
    80206aa4:	17ffffd1 	b	802069e8 <_vfprintf_r+0x31e8>
    80206aa8:	79c022a0 	ldrsh	w0, [x21, #16]
    80206aac:	aa1903e1 	mov	x1, x25
    80206ab0:	321a0000 	orr	w0, w0, #0x40
    80206ab4:	790022a0 	strh	w0, [x21, #16]
    80206ab8:	17fffe8f 	b	802064f4 <_vfprintf_r+0x2cf4>
    80206abc:	79c022a0 	ldrsh	w0, [x21, #16]
    80206ac0:	d2800001 	mov	x1, #0x0                   	// #0
    80206ac4:	321a0000 	orr	w0, w0, #0x40
    80206ac8:	790022a0 	strh	w0, [x21, #16]
    80206acc:	17fffe8a 	b	802064f4 <_vfprintf_r+0x2cf4>
    80206ad0:	b9008bff 	str	wzr, [sp, #136]
    80206ad4:	b9009bff 	str	wzr, [sp, #152]
    80206ad8:	17fffeed 	b	8020668c <_vfprintf_r+0x2e8c>
    80206adc:	8b0c0363 	add	x3, x27, x12
    80206ae0:	17ffff7f 	b	802068dc <_vfprintf_r+0x30dc>
	...

0000000080206af0 <vfprintf>:
    80206af0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80206af4:	f0000044 	adrp	x4, 80211000 <__mprec_tens+0x180>
    80206af8:	aa0003e3 	mov	x3, x0
    80206afc:	910003fd 	mov	x29, sp
    80206b00:	ad400440 	ldp	q0, q1, [x2]
    80206b04:	aa0103e2 	mov	x2, x1
    80206b08:	f9402480 	ldr	x0, [x4, #72]
    80206b0c:	aa0303e1 	mov	x1, x3
    80206b10:	910043e3 	add	x3, sp, #0x10
    80206b14:	ad0087e0 	stp	q0, q1, [sp, #16]
    80206b18:	97fff33a 	bl	80203800 <_vfprintf_r>
    80206b1c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80206b20:	d65f03c0 	ret
	...

0000000080206b30 <__sbprintf>:
    80206b30:	d11443ff 	sub	sp, sp, #0x510
    80206b34:	a9007bfd 	stp	x29, x30, [sp]
    80206b38:	910003fd 	mov	x29, sp
    80206b3c:	a90153f3 	stp	x19, x20, [sp, #16]
    80206b40:	aa0103f3 	mov	x19, x1
    80206b44:	79402021 	ldrh	w1, [x1, #16]
    80206b48:	aa0303f4 	mov	x20, x3
    80206b4c:	910443e3 	add	x3, sp, #0x110
    80206b50:	f9401a66 	ldr	x6, [x19, #48]
    80206b54:	121e7821 	and	w1, w1, #0xfffffffd
    80206b58:	f9402265 	ldr	x5, [x19, #64]
    80206b5c:	a9025bf5 	stp	x21, x22, [sp, #32]
    80206b60:	79402667 	ldrh	w7, [x19, #18]
    80206b64:	b940b264 	ldr	w4, [x19, #176]
    80206b68:	aa0203f6 	mov	x22, x2
    80206b6c:	52808002 	mov	w2, #0x400                 	// #1024
    80206b70:	aa0003f5 	mov	x21, x0
    80206b74:	9103e3e0 	add	x0, sp, #0xf8
    80206b78:	f9002fe3 	str	x3, [sp, #88]
    80206b7c:	b90067e2 	str	w2, [sp, #100]
    80206b80:	7900d3e1 	strh	w1, [sp, #104]
    80206b84:	7900d7e7 	strh	w7, [sp, #106]
    80206b88:	f9003be3 	str	x3, [sp, #112]
    80206b8c:	b9007be2 	str	w2, [sp, #120]
    80206b90:	b90083ff 	str	wzr, [sp, #128]
    80206b94:	f90047e6 	str	x6, [sp, #136]
    80206b98:	f9004fe5 	str	x5, [sp, #152]
    80206b9c:	b9010be4 	str	w4, [sp, #264]
    80206ba0:	940009f8 	bl	80209380 <__retarget_lock_init_recursive>
    80206ba4:	ad400680 	ldp	q0, q1, [x20]
    80206ba8:	aa1603e2 	mov	x2, x22
    80206bac:	9100c3e3 	add	x3, sp, #0x30
    80206bb0:	910163e1 	add	x1, sp, #0x58
    80206bb4:	aa1503e0 	mov	x0, x21
    80206bb8:	ad0187e0 	stp	q0, q1, [sp, #48]
    80206bbc:	97fff311 	bl	80203800 <_vfprintf_r>
    80206bc0:	2a0003f4 	mov	w20, w0
    80206bc4:	37f800c0 	tbnz	w0, #31, 80206bdc <__sbprintf+0xac>
    80206bc8:	910163e1 	add	x1, sp, #0x58
    80206bcc:	aa1503e0 	mov	x0, x21
    80206bd0:	940014e8 	bl	8020bf70 <_fflush_r>
    80206bd4:	7100001f 	cmp	w0, #0x0
    80206bd8:	5a9f0294 	csinv	w20, w20, wzr, eq	// eq = none
    80206bdc:	7940d3e0 	ldrh	w0, [sp, #104]
    80206be0:	36300080 	tbz	w0, #6, 80206bf0 <__sbprintf+0xc0>
    80206be4:	79402260 	ldrh	w0, [x19, #16]
    80206be8:	321a0000 	orr	w0, w0, #0x40
    80206bec:	79002260 	strh	w0, [x19, #16]
    80206bf0:	f9407fe0 	ldr	x0, [sp, #248]
    80206bf4:	940009eb 	bl	802093a0 <__retarget_lock_close_recursive>
    80206bf8:	a9407bfd 	ldp	x29, x30, [sp]
    80206bfc:	2a1403e0 	mov	w0, w20
    80206c00:	a94153f3 	ldp	x19, x20, [sp, #16]
    80206c04:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80206c08:	911443ff 	add	sp, sp, #0x510
    80206c0c:	d65f03c0 	ret

0000000080206c10 <__sprint_r.part.0>:
    80206c10:	a9bb7bfd 	stp	x29, x30, [sp, #-80]!
    80206c14:	910003fd 	mov	x29, sp
    80206c18:	b940b023 	ldr	w3, [x1, #176]
    80206c1c:	a90363f7 	stp	x23, x24, [sp, #48]
    80206c20:	aa0203f8 	mov	x24, x2
    80206c24:	36680563 	tbz	w3, #13, 80206cd0 <__sprint_r.part.0+0xc0>
    80206c28:	a9025bf5 	stp	x21, x22, [sp, #32]
    80206c2c:	aa0003f5 	mov	x21, x0
    80206c30:	f9400840 	ldr	x0, [x2, #16]
    80206c34:	a90153f3 	stp	x19, x20, [sp, #16]
    80206c38:	aa0103f4 	mov	x20, x1
    80206c3c:	a9046bf9 	stp	x25, x26, [sp, #64]
    80206c40:	f940005a 	ldr	x26, [x2]
    80206c44:	b40003c0 	cbz	x0, 80206cbc <__sprint_r.part.0+0xac>
    80206c48:	a9406756 	ldp	x22, x25, [x26]
    80206c4c:	d342ff39 	lsr	x25, x25, #2
    80206c50:	2a1903f7 	mov	w23, w25
    80206c54:	7100033f 	cmp	w25, #0x0
    80206c58:	540002ad 	b.le	80206cac <__sprint_r.part.0+0x9c>
    80206c5c:	d2800013 	mov	x19, #0x0                   	// #0
    80206c60:	14000003 	b	80206c6c <__sprint_r.part.0+0x5c>
    80206c64:	6b1302ff 	cmp	w23, w19
    80206c68:	5400020d 	b.le	80206ca8 <__sprint_r.part.0+0x98>
    80206c6c:	b8737ac1 	ldr	w1, [x22, x19, lsl #2]
    80206c70:	aa1403e2 	mov	x2, x20
    80206c74:	aa1503e0 	mov	x0, x21
    80206c78:	91000673 	add	x19, x19, #0x1
    80206c7c:	94001a35 	bl	8020d550 <_fputwc_r>
    80206c80:	3100041f 	cmn	w0, #0x1
    80206c84:	54ffff01 	b.ne	80206c64 <__sprint_r.part.0+0x54>  // b.any
    80206c88:	a94153f3 	ldp	x19, x20, [sp, #16]
    80206c8c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80206c90:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80206c94:	b9000b1f 	str	wzr, [x24, #8]
    80206c98:	f9000b1f 	str	xzr, [x24, #16]
    80206c9c:	a94363f7 	ldp	x23, x24, [sp, #48]
    80206ca0:	a8c57bfd 	ldp	x29, x30, [sp], #80
    80206ca4:	d65f03c0 	ret
    80206ca8:	f9400b00 	ldr	x0, [x24, #16]
    80206cac:	cb39c800 	sub	x0, x0, w25, sxtw #2
    80206cb0:	f9000b00 	str	x0, [x24, #16]
    80206cb4:	9100435a 	add	x26, x26, #0x10
    80206cb8:	b5fffc80 	cbnz	x0, 80206c48 <__sprint_r.part.0+0x38>
    80206cbc:	a94153f3 	ldp	x19, x20, [sp, #16]
    80206cc0:	52800000 	mov	w0, #0x0                   	// #0
    80206cc4:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80206cc8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80206ccc:	17fffff2 	b	80206c94 <__sprint_r.part.0+0x84>
    80206cd0:	97fff158 	bl	80203230 <__sfvwrite_r>
    80206cd4:	b9000b1f 	str	wzr, [x24, #8]
    80206cd8:	f9000b1f 	str	xzr, [x24, #16]
    80206cdc:	a94363f7 	ldp	x23, x24, [sp, #48]
    80206ce0:	a8c57bfd 	ldp	x29, x30, [sp], #80
    80206ce4:	d65f03c0 	ret
	...

0000000080206cf0 <__sprint_r>:
    80206cf0:	f9400844 	ldr	x4, [x2, #16]
    80206cf4:	b4000044 	cbz	x4, 80206cfc <__sprint_r+0xc>
    80206cf8:	17ffffc6 	b	80206c10 <__sprint_r.part.0>
    80206cfc:	52800000 	mov	w0, #0x0                   	// #0
    80206d00:	b900085f 	str	wzr, [x2, #8]
    80206d04:	d65f03c0 	ret
	...

0000000080206d10 <_vfiprintf_r>:
    80206d10:	d10883ff 	sub	sp, sp, #0x220
    80206d14:	a9007bfd 	stp	x29, x30, [sp]
    80206d18:	910003fd 	mov	x29, sp
    80206d1c:	a90153f3 	stp	x19, x20, [sp, #16]
    80206d20:	aa0003f3 	mov	x19, x0
    80206d24:	aa0303f4 	mov	x20, x3
    80206d28:	a90363f7 	stp	x23, x24, [sp, #48]
    80206d2c:	a9400077 	ldp	x23, x0, [x3]
    80206d30:	a9025bf5 	stp	x21, x22, [sp, #32]
    80206d34:	aa0103f5 	mov	x21, x1
    80206d38:	b9401861 	ldr	w1, [x3, #24]
    80206d3c:	a9046bf9 	stp	x25, x26, [sp, #64]
    80206d40:	aa0203f9 	mov	x25, x2
    80206d44:	d2800102 	mov	x2, #0x8                   	// #8
    80206d48:	f90043e0 	str	x0, [sp, #128]
    80206d4c:	910423e0 	add	x0, sp, #0x108
    80206d50:	b900c3e1 	str	w1, [sp, #192]
    80206d54:	52800001 	mov	w1, #0x0                   	// #0
    80206d58:	97fff05a 	bl	80202ec0 <memset>
    80206d5c:	b4000073 	cbz	x19, 80206d68 <_vfiprintf_r+0x58>
    80206d60:	f9402660 	ldr	x0, [x19, #72]
    80206d64:	b4009ac0 	cbz	x0, 802080bc <_vfiprintf_r+0x13ac>
    80206d68:	b940b2a1 	ldr	w1, [x21, #176]
    80206d6c:	79c022a0 	ldrsh	w0, [x21, #16]
    80206d70:	37000041 	tbnz	w1, #0, 80206d78 <_vfiprintf_r+0x68>
    80206d74:	36487720 	tbz	w0, #9, 80207c58 <_vfiprintf_r+0xf48>
    80206d78:	376800c0 	tbnz	w0, #13, 80206d90 <_vfiprintf_r+0x80>
    80206d7c:	b940b2a1 	ldr	w1, [x21, #176]
    80206d80:	32130000 	orr	w0, w0, #0x2000
    80206d84:	790022a0 	strh	w0, [x21, #16]
    80206d88:	12127821 	and	w1, w1, #0xffffdfff
    80206d8c:	b900b2a1 	str	w1, [x21, #176]
    80206d90:	361804e0 	tbz	w0, #3, 80206e2c <_vfiprintf_r+0x11c>
    80206d94:	f9400ea1 	ldr	x1, [x21, #24]
    80206d98:	b40004a1 	cbz	x1, 80206e2c <_vfiprintf_r+0x11c>
    80206d9c:	52800341 	mov	w1, #0x1a                  	// #26
    80206da0:	0a010001 	and	w1, w0, w1
    80206da4:	7100283f 	cmp	w1, #0xa
    80206da8:	54000540 	b.eq	80206e50 <_vfiprintf_r+0x140>  // b.none
    80206dac:	910683f6 	add	x22, sp, #0x1a0
    80206db0:	f0000054 	adrp	x20, 80211000 <__mprec_tens+0x180>
    80206db4:	912b4294 	add	x20, x20, #0xad0
    80206db8:	a90573fb 	stp	x27, x28, [sp, #80]
    80206dbc:	aa1603fb 	mov	x27, x22
    80206dc0:	d0000040 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80206dc4:	9123c000 	add	x0, x0, #0x8f0
    80206dc8:	b9006fff 	str	wzr, [sp, #108]
    80206dcc:	f9003fe0 	str	x0, [sp, #120]
    80206dd0:	a90a7fff 	stp	xzr, xzr, [sp, #160]
    80206dd4:	a90b7fff 	stp	xzr, xzr, [sp, #176]
    80206dd8:	f90093f6 	str	x22, [sp, #288]
    80206ddc:	b9012bff 	str	wzr, [sp, #296]
    80206de0:	f9009bff 	str	xzr, [sp, #304]
    80206de4:	aa1903fc 	mov	x28, x25
    80206de8:	f9407698 	ldr	x24, [x20, #232]
    80206dec:	94000cad 	bl	8020a0a0 <__locale_mb_cur_max>
    80206df0:	910423e4 	add	x4, sp, #0x108
    80206df4:	93407c03 	sxtw	x3, w0
    80206df8:	aa1c03e2 	mov	x2, x28
    80206dfc:	910413e1 	add	x1, sp, #0x104
    80206e00:	aa1303e0 	mov	x0, x19
    80206e04:	d63f0300 	blr	x24
    80206e08:	7100001f 	cmp	w0, #0x0
    80206e0c:	340005a0 	cbz	w0, 80206ec0 <_vfiprintf_r+0x1b0>
    80206e10:	540004ab 	b.lt	80206ea4 <_vfiprintf_r+0x194>  // b.tstop
    80206e14:	b94107e1 	ldr	w1, [sp, #260]
    80206e18:	7100943f 	cmp	w1, #0x25
    80206e1c:	54001be0 	b.eq	80207198 <_vfiprintf_r+0x488>  // b.none
    80206e20:	93407c00 	sxtw	x0, w0
    80206e24:	8b00039c 	add	x28, x28, x0
    80206e28:	17fffff0 	b	80206de8 <_vfiprintf_r+0xd8>
    80206e2c:	aa1503e1 	mov	x1, x21
    80206e30:	aa1303e0 	mov	x0, x19
    80206e34:	94000d4b 	bl	8020a360 <__swsetup_r>
    80206e38:	3500b8a0 	cbnz	w0, 8020854c <_vfiprintf_r+0x183c>
    80206e3c:	79c022a0 	ldrsh	w0, [x21, #16]
    80206e40:	52800341 	mov	w1, #0x1a                  	// #26
    80206e44:	0a010001 	and	w1, w0, w1
    80206e48:	7100283f 	cmp	w1, #0xa
    80206e4c:	54fffb01 	b.ne	80206dac <_vfiprintf_r+0x9c>  // b.any
    80206e50:	79c026a1 	ldrsh	w1, [x21, #18]
    80206e54:	37fffac1 	tbnz	w1, #31, 80206dac <_vfiprintf_r+0x9c>
    80206e58:	b940b2a1 	ldr	w1, [x21, #176]
    80206e5c:	37000041 	tbnz	w1, #0, 80206e64 <_vfiprintf_r+0x154>
    80206e60:	3648ae00 	tbz	w0, #9, 80208420 <_vfiprintf_r+0x1710>
    80206e64:	ad400680 	ldp	q0, q1, [x20]
    80206e68:	aa1903e2 	mov	x2, x25
    80206e6c:	aa1503e1 	mov	x1, x21
    80206e70:	910343e3 	add	x3, sp, #0xd0
    80206e74:	aa1303e0 	mov	x0, x19
    80206e78:	ad0687e0 	stp	q0, q1, [sp, #208]
    80206e7c:	940006b9 	bl	80208960 <__sbprintf>
    80206e80:	b9006fe0 	str	w0, [sp, #108]
    80206e84:	a9407bfd 	ldp	x29, x30, [sp]
    80206e88:	a94153f3 	ldp	x19, x20, [sp, #16]
    80206e8c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80206e90:	a94363f7 	ldp	x23, x24, [sp, #48]
    80206e94:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80206e98:	b9406fe0 	ldr	w0, [sp, #108]
    80206e9c:	910883ff 	add	sp, sp, #0x220
    80206ea0:	d65f03c0 	ret
    80206ea4:	910423e0 	add	x0, sp, #0x108
    80206ea8:	d2800102 	mov	x2, #0x8                   	// #8
    80206eac:	52800001 	mov	w1, #0x0                   	// #0
    80206eb0:	97fff004 	bl	80202ec0 <memset>
    80206eb4:	d2800020 	mov	x0, #0x1                   	// #1
    80206eb8:	8b00039c 	add	x28, x28, x0
    80206ebc:	17ffffcb 	b	80206de8 <_vfiprintf_r+0xd8>
    80206ec0:	2a0003f8 	mov	w24, w0
    80206ec4:	cb190380 	sub	x0, x28, x25
    80206ec8:	2a0003fa 	mov	w26, w0
    80206ecc:	340091e0 	cbz	w0, 80208108 <_vfiprintf_r+0x13f8>
    80206ed0:	f9409be2 	ldr	x2, [sp, #304]
    80206ed4:	93407f41 	sxtw	x1, w26
    80206ed8:	b9412be0 	ldr	w0, [sp, #296]
    80206edc:	8b020022 	add	x2, x1, x2
    80206ee0:	a9000779 	stp	x25, x1, [x27]
    80206ee4:	11000400 	add	w0, w0, #0x1
    80206ee8:	b9012be0 	str	w0, [sp, #296]
    80206eec:	9100437b 	add	x27, x27, #0x10
    80206ef0:	f9009be2 	str	x2, [sp, #304]
    80206ef4:	71001c1f 	cmp	w0, #0x7
    80206ef8:	5400010d 	b.le	80206f18 <_vfiprintf_r+0x208>
    80206efc:	b40066a2 	cbz	x2, 80207bd0 <_vfiprintf_r+0xec0>
    80206f00:	910483e2 	add	x2, sp, #0x120
    80206f04:	aa1503e1 	mov	x1, x21
    80206f08:	aa1303e0 	mov	x0, x19
    80206f0c:	97ffff41 	bl	80206c10 <__sprint_r.part.0>
    80206f10:	35000420 	cbnz	w0, 80206f94 <_vfiprintf_r+0x284>
    80206f14:	aa1603fb 	mov	x27, x22
    80206f18:	b9406fe0 	ldr	w0, [sp, #108]
    80206f1c:	0b1a0000 	add	w0, w0, w26
    80206f20:	b9006fe0 	str	w0, [sp, #108]
    80206f24:	34008f38 	cbz	w24, 80208108 <_vfiprintf_r+0x13f8>
    80206f28:	39400780 	ldrb	w0, [x28, #1]
    80206f2c:	91000799 	add	x25, x28, #0x1
    80206f30:	12800003 	mov	w3, #0xffffffff            	// #-1
    80206f34:	52800008 	mov	w8, #0x0                   	// #0
    80206f38:	2a0303fc 	mov	w28, w3
    80206f3c:	2a0803fa 	mov	w26, w8
    80206f40:	52800018 	mov	w24, #0x0                   	// #0
    80206f44:	3903ffff 	strb	wzr, [sp, #255]
    80206f48:	91000739 	add	x25, x25, #0x1
    80206f4c:	51008001 	sub	w1, w0, #0x20
    80206f50:	7101683f 	cmp	w1, #0x5a
    80206f54:	540003a8 	b.hi	80206fc8 <_vfiprintf_r+0x2b8>  // b.pmore
    80206f58:	f9403fe2 	ldr	x2, [sp, #120]
    80206f5c:	78615841 	ldrh	w1, [x2, w1, uxtw #1]
    80206f60:	10000062 	adr	x2, 80206f6c <_vfiprintf_r+0x25c>
    80206f64:	8b21a841 	add	x1, x2, w1, sxth #2
    80206f68:	d61f0020 	br	x1
    80206f6c:	910483e2 	add	x2, sp, #0x120
    80206f70:	aa1503e1 	mov	x1, x21
    80206f74:	aa1303e0 	mov	x0, x19
    80206f78:	97ffff26 	bl	80206c10 <__sprint_r.part.0>
    80206f7c:	34000e60 	cbz	w0, 80207148 <_vfiprintf_r+0x438>
    80206f80:	f9403be0 	ldr	x0, [sp, #112]
    80206f84:	b4000080 	cbz	x0, 80206f94 <_vfiprintf_r+0x284>
    80206f88:	f9403be1 	ldr	x1, [sp, #112]
    80206f8c:	aa1303e0 	mov	x0, x19
    80206f90:	9400161c 	bl	8020c800 <_free_r>
    80206f94:	79c022a0 	ldrsh	w0, [x21, #16]
    80206f98:	b940b2a1 	ldr	w1, [x21, #176]
    80206f9c:	36003b81 	tbz	w1, #0, 8020770c <_vfiprintf_r+0x9fc>
    80206fa0:	a94573fb 	ldp	x27, x28, [sp, #80]
    80206fa4:	3730ae00 	tbnz	w0, #6, 80208564 <_vfiprintf_r+0x1854>
    80206fa8:	a9407bfd 	ldp	x29, x30, [sp]
    80206fac:	a94153f3 	ldp	x19, x20, [sp, #16]
    80206fb0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80206fb4:	a94363f7 	ldp	x23, x24, [sp, #48]
    80206fb8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80206fbc:	b9406fe0 	ldr	w0, [sp, #108]
    80206fc0:	910883ff 	add	sp, sp, #0x220
    80206fc4:	d65f03c0 	ret
    80206fc8:	2a1a03e8 	mov	w8, w26
    80206fcc:	340089e0 	cbz	w0, 80208108 <_vfiprintf_r+0x13f8>
    80206fd0:	52800024 	mov	w4, #0x1                   	// #1
    80206fd4:	9104e3fc 	add	x28, sp, #0x138
    80206fd8:	2a0403fa 	mov	w26, w4
    80206fdc:	3903ffff 	strb	wzr, [sp, #255]
    80206fe0:	3904e3e0 	strb	w0, [sp, #312]
    80206fe4:	52800003 	mov	w3, #0x0                   	// #0
    80206fe8:	5280000d 	mov	w13, #0x0                   	// #0
    80206fec:	f9003bff 	str	xzr, [sp, #112]
    80206ff0:	b9412be1 	ldr	w1, [sp, #296]
    80206ff4:	5280108c 	mov	w12, #0x84                  	// #132
    80206ff8:	f9409be0 	ldr	x0, [sp, #304]
    80206ffc:	11000422 	add	w2, w1, #0x1
    80207000:	6a0c030c 	ands	w12, w24, w12
    80207004:	2a0203eb 	mov	w11, w2
    80207008:	54000081 	b.ne	80207018 <_vfiprintf_r+0x308>  // b.any
    8020700c:	4b04010a 	sub	w10, w8, w4
    80207010:	7100015f 	cmp	w10, #0x0
    80207014:	5400252c 	b.gt	802074b8 <_vfiprintf_r+0x7a8>
    80207018:	3943ffe2 	ldrb	w2, [sp, #255]
    8020701c:	340001a2 	cbz	w2, 80207050 <_vfiprintf_r+0x340>
    80207020:	9103ffe1 	add	x1, sp, #0xff
    80207024:	91000400 	add	x0, x0, #0x1
    80207028:	f9000361 	str	x1, [x27]
    8020702c:	d2800021 	mov	x1, #0x1                   	// #1
    80207030:	f9000761 	str	x1, [x27, #8]
    80207034:	b9012beb 	str	w11, [sp, #296]
    80207038:	f9009be0 	str	x0, [sp, #304]
    8020703c:	71001d7f 	cmp	w11, #0x7
    80207040:	54001fec 	b.gt	8020743c <_vfiprintf_r+0x72c>
    80207044:	2a0b03e1 	mov	w1, w11
    80207048:	9100437b 	add	x27, x27, #0x10
    8020704c:	1100056b 	add	w11, w11, #0x1
    80207050:	3400038d 	cbz	w13, 802070c0 <_vfiprintf_r+0x3b0>
    80207054:	91000800 	add	x0, x0, #0x2
    80207058:	910403e2 	add	x2, sp, #0x100
    8020705c:	d2800041 	mov	x1, #0x2                   	// #2
    80207060:	a9000762 	stp	x2, x1, [x27]
    80207064:	b9012beb 	str	w11, [sp, #296]
    80207068:	f9009be0 	str	x0, [sp, #304]
    8020706c:	71001d7f 	cmp	w11, #0x7
    80207070:	540021cd 	b.le	802074a8 <_vfiprintf_r+0x798>
    80207074:	b4005ba0 	cbz	x0, 80207be8 <_vfiprintf_r+0xed8>
    80207078:	910483e2 	add	x2, sp, #0x120
    8020707c:	aa1503e1 	mov	x1, x21
    80207080:	aa1303e0 	mov	x0, x19
    80207084:	b9008bec 	str	w12, [sp, #136]
    80207088:	b90093e8 	str	w8, [sp, #144]
    8020708c:	b9009be3 	str	w3, [sp, #152]
    80207090:	b900c7e4 	str	w4, [sp, #196]
    80207094:	97fffedf 	bl	80206c10 <__sprint_r.part.0>
    80207098:	35fff740 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    8020709c:	b9412be1 	ldr	w1, [sp, #296]
    802070a0:	aa1603fb 	mov	x27, x22
    802070a4:	f9409be0 	ldr	x0, [sp, #304]
    802070a8:	1100042b 	add	w11, w1, #0x1
    802070ac:	b9408bec 	ldr	w12, [sp, #136]
    802070b0:	b94093e8 	ldr	w8, [sp, #144]
    802070b4:	b9409be3 	ldr	w3, [sp, #152]
    802070b8:	b940c7e4 	ldr	w4, [sp, #196]
    802070bc:	d503201f 	nop
    802070c0:	7102019f 	cmp	w12, #0x80
    802070c4:	54000860 	b.eq	802071d0 <_vfiprintf_r+0x4c0>  // b.none
    802070c8:	4b1a0063 	sub	w3, w3, w26
    802070cc:	7100007f 	cmp	w3, #0x0
    802070d0:	5400120c 	b.gt	80207310 <_vfiprintf_r+0x600>
    802070d4:	93407f49 	sxtw	x9, w26
    802070d8:	a900277c 	stp	x28, x9, [x27]
    802070dc:	8b090000 	add	x0, x0, x9
    802070e0:	b9012beb 	str	w11, [sp, #296]
    802070e4:	f9009be0 	str	x0, [sp, #304]
    802070e8:	71001d7f 	cmp	w11, #0x7
    802070ec:	540006ed 	b.le	802071c8 <_vfiprintf_r+0x4b8>
    802070f0:	b40026c0 	cbz	x0, 802075c8 <_vfiprintf_r+0x8b8>
    802070f4:	910483e2 	add	x2, sp, #0x120
    802070f8:	aa1503e1 	mov	x1, x21
    802070fc:	aa1303e0 	mov	x0, x19
    80207100:	b9008be8 	str	w8, [sp, #136]
    80207104:	b90093e4 	str	w4, [sp, #144]
    80207108:	97fffec2 	bl	80206c10 <__sprint_r.part.0>
    8020710c:	35fff3a0 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    80207110:	f9409be0 	ldr	x0, [sp, #304]
    80207114:	aa1603fb 	mov	x27, x22
    80207118:	b9408be8 	ldr	w8, [sp, #136]
    8020711c:	b94093e4 	ldr	w4, [sp, #144]
    80207120:	36100098 	tbz	w24, #2, 80207130 <_vfiprintf_r+0x420>
    80207124:	4b040118 	sub	w24, w8, w4
    80207128:	7100031f 	cmp	w24, #0x0
    8020712c:	540025ac 	b.gt	802075e0 <_vfiprintf_r+0x8d0>
    80207130:	b9406fe1 	ldr	w1, [sp, #108]
    80207134:	6b04011f 	cmp	w8, w4
    80207138:	1a84a104 	csel	w4, w8, w4, ge	// ge = tcont
    8020713c:	0b040021 	add	w1, w1, w4
    80207140:	b9006fe1 	str	w1, [sp, #108]
    80207144:	b5fff140 	cbnz	x0, 80206f6c <_vfiprintf_r+0x25c>
    80207148:	f9403be0 	ldr	x0, [sp, #112]
    8020714c:	b9012bff 	str	wzr, [sp, #296]
    80207150:	b4000080 	cbz	x0, 80207160 <_vfiprintf_r+0x450>
    80207154:	aa0003e1 	mov	x1, x0
    80207158:	aa1303e0 	mov	x0, x19
    8020715c:	940015a9 	bl	8020c800 <_free_r>
    80207160:	aa1603fb 	mov	x27, x22
    80207164:	17ffff20 	b	80206de4 <_vfiprintf_r+0xd4>
    80207168:	5100c001 	sub	w1, w0, #0x30
    8020716c:	5280001a 	mov	w26, #0x0                   	// #0
    80207170:	38401720 	ldrb	w0, [x25], #1
    80207174:	0b1a0b48 	add	w8, w26, w26, lsl #2
    80207178:	0b08043a 	add	w26, w1, w8, lsl #1
    8020717c:	5100c001 	sub	w1, w0, #0x30
    80207180:	7100243f 	cmp	w1, #0x9
    80207184:	54ffff69 	b.ls	80207170 <_vfiprintf_r+0x460>  // b.plast
    80207188:	17ffff71 	b	80206f4c <_vfiprintf_r+0x23c>
    8020718c:	39400320 	ldrb	w0, [x25]
    80207190:	321c0318 	orr	w24, w24, #0x10
    80207194:	17ffff6d 	b	80206f48 <_vfiprintf_r+0x238>
    80207198:	2a0003f8 	mov	w24, w0
    8020719c:	cb190380 	sub	x0, x28, x25
    802071a0:	2a0003fa 	mov	w26, w0
    802071a4:	34ffec20 	cbz	w0, 80206f28 <_vfiprintf_r+0x218>
    802071a8:	17ffff4a 	b	80206ed0 <_vfiprintf_r+0x1c0>
    802071ac:	aa1603fb 	mov	x27, x22
    802071b0:	93407f40 	sxtw	x0, w26
    802071b4:	52800021 	mov	w1, #0x1                   	// #1
    802071b8:	b9012be1 	str	w1, [sp, #296]
    802071bc:	f9009be0 	str	x0, [sp, #304]
    802071c0:	a91a03fc 	stp	x28, x0, [sp, #416]
    802071c4:	d503201f 	nop
    802071c8:	9100437b 	add	x27, x27, #0x10
    802071cc:	17ffffd5 	b	80207120 <_vfiprintf_r+0x410>
    802071d0:	4b04010c 	sub	w12, w8, w4
    802071d4:	7100019f 	cmp	w12, #0x0
    802071d8:	54fff78d 	b.le	802070c8 <_vfiprintf_r+0x3b8>
    802071dc:	7100419f 	cmp	w12, #0x10
    802071e0:	54009aed 	b.le	8020853c <_vfiprintf_r+0x182c>
    802071e4:	b000004a 	adrp	x10, 80210000 <__trunctfdf2+0xc0>
    802071e8:	9126c14a 	add	x10, x10, #0x9b0
    802071ec:	d280020b 	mov	x11, #0x10                  	// #16
    802071f0:	b9008bf8 	str	w24, [sp, #136]
    802071f4:	aa0a03f8 	mov	x24, x10
    802071f8:	b90093e8 	str	w8, [sp, #144]
    802071fc:	b9009be3 	str	w3, [sp, #152]
    80207200:	aa1b03e3 	mov	x3, x27
    80207204:	aa1903fb 	mov	x27, x25
    80207208:	aa1703f9 	mov	x25, x23
    8020720c:	2a0c03f7 	mov	w23, w12
    80207210:	b900c7e4 	str	w4, [sp, #196]
    80207214:	14000007 	b	80207230 <_vfiprintf_r+0x520>
    80207218:	1100082d 	add	w13, w1, #0x2
    8020721c:	91004063 	add	x3, x3, #0x10
    80207220:	2a0203e1 	mov	w1, w2
    80207224:	510042f7 	sub	w23, w23, #0x10
    80207228:	710042ff 	cmp	w23, #0x10
    8020722c:	540002cd 	b.le	80207284 <_vfiprintf_r+0x574>
    80207230:	91004000 	add	x0, x0, #0x10
    80207234:	11000422 	add	w2, w1, #0x1
    80207238:	a9002c78 	stp	x24, x11, [x3]
    8020723c:	b9012be2 	str	w2, [sp, #296]
    80207240:	f9009be0 	str	x0, [sp, #304]
    80207244:	71001c5f 	cmp	w2, #0x7
    80207248:	54fffe8d 	b.le	80207218 <_vfiprintf_r+0x508>
    8020724c:	b4004a80 	cbz	x0, 80207b9c <_vfiprintf_r+0xe8c>
    80207250:	910483e2 	add	x2, sp, #0x120
    80207254:	aa1503e1 	mov	x1, x21
    80207258:	aa1303e0 	mov	x0, x19
    8020725c:	97fffe6d 	bl	80206c10 <__sprint_r.part.0>
    80207260:	35ffe900 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    80207264:	b9412be1 	ldr	w1, [sp, #296]
    80207268:	510042f7 	sub	w23, w23, #0x10
    8020726c:	f9409be0 	ldr	x0, [sp, #304]
    80207270:	aa1603e3 	mov	x3, x22
    80207274:	1100042d 	add	w13, w1, #0x1
    80207278:	d280020b 	mov	x11, #0x10                  	// #16
    8020727c:	710042ff 	cmp	w23, #0x10
    80207280:	54fffd8c 	b.gt	80207230 <_vfiprintf_r+0x520>
    80207284:	2a1703ec 	mov	w12, w23
    80207288:	aa1803ea 	mov	x10, x24
    8020728c:	aa1903f7 	mov	x23, x25
    80207290:	b9408bf8 	ldr	w24, [sp, #136]
    80207294:	aa1b03f9 	mov	x25, x27
    80207298:	b94093e8 	ldr	w8, [sp, #144]
    8020729c:	aa0303fb 	mov	x27, x3
    802072a0:	b940c7e4 	ldr	w4, [sp, #196]
    802072a4:	b9409be3 	ldr	w3, [sp, #152]
    802072a8:	93407d81 	sxtw	x1, w12
    802072ac:	a900076a 	stp	x10, x1, [x27]
    802072b0:	8b010000 	add	x0, x0, x1
    802072b4:	b9012bed 	str	w13, [sp, #296]
    802072b8:	f9009be0 	str	x0, [sp, #304]
    802072bc:	71001dbf 	cmp	w13, #0x7
    802072c0:	54004d4d 	b.le	80207c68 <_vfiprintf_r+0xf58>
    802072c4:	b4007f20 	cbz	x0, 802082a8 <_vfiprintf_r+0x1598>
    802072c8:	910483e2 	add	x2, sp, #0x120
    802072cc:	aa1503e1 	mov	x1, x21
    802072d0:	aa1303e0 	mov	x0, x19
    802072d4:	b9008be8 	str	w8, [sp, #136]
    802072d8:	b90093e3 	str	w3, [sp, #144]
    802072dc:	b9009be4 	str	w4, [sp, #152]
    802072e0:	97fffe4c 	bl	80206c10 <__sprint_r.part.0>
    802072e4:	35ffe4e0 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    802072e8:	b94093e3 	ldr	w3, [sp, #144]
    802072ec:	aa1603fb 	mov	x27, x22
    802072f0:	b9412be1 	ldr	w1, [sp, #296]
    802072f4:	4b1a0063 	sub	w3, w3, w26
    802072f8:	b9408be8 	ldr	w8, [sp, #136]
    802072fc:	f9409be0 	ldr	x0, [sp, #304]
    80207300:	1100042b 	add	w11, w1, #0x1
    80207304:	b9409be4 	ldr	w4, [sp, #152]
    80207308:	7100007f 	cmp	w3, #0x0
    8020730c:	54ffee4d 	b.le	802070d4 <_vfiprintf_r+0x3c4>
    80207310:	b000004a 	adrp	x10, 80210000 <__trunctfdf2+0xc0>
    80207314:	9126c14a 	add	x10, x10, #0x9b0
    80207318:	7100407f 	cmp	w3, #0x10
    8020731c:	540005cd 	b.le	802073d4 <_vfiprintf_r+0x6c4>
    80207320:	d280020c 	mov	x12, #0x10                  	// #16
    80207324:	b9008bf8 	str	w24, [sp, #136]
    80207328:	aa0a03f8 	mov	x24, x10
    8020732c:	b90093e8 	str	w8, [sp, #144]
    80207330:	b9009be4 	str	w4, [sp, #152]
    80207334:	aa1b03e4 	mov	x4, x27
    80207338:	aa1903fb 	mov	x27, x25
    8020733c:	aa1703f9 	mov	x25, x23
    80207340:	2a0303f7 	mov	w23, w3
    80207344:	14000007 	b	80207360 <_vfiprintf_r+0x650>
    80207348:	1100082b 	add	w11, w1, #0x2
    8020734c:	91004084 	add	x4, x4, #0x10
    80207350:	2a0203e1 	mov	w1, w2
    80207354:	510042f7 	sub	w23, w23, #0x10
    80207358:	710042ff 	cmp	w23, #0x10
    8020735c:	540002cd 	b.le	802073b4 <_vfiprintf_r+0x6a4>
    80207360:	91004000 	add	x0, x0, #0x10
    80207364:	11000422 	add	w2, w1, #0x1
    80207368:	a9003098 	stp	x24, x12, [x4]
    8020736c:	b9012be2 	str	w2, [sp, #296]
    80207370:	f9009be0 	str	x0, [sp, #304]
    80207374:	71001c5f 	cmp	w2, #0x7
    80207378:	54fffe8d 	b.le	80207348 <_vfiprintf_r+0x638>
    8020737c:	b4000580 	cbz	x0, 8020742c <_vfiprintf_r+0x71c>
    80207380:	910483e2 	add	x2, sp, #0x120
    80207384:	aa1503e1 	mov	x1, x21
    80207388:	aa1303e0 	mov	x0, x19
    8020738c:	97fffe21 	bl	80206c10 <__sprint_r.part.0>
    80207390:	35ffdf80 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    80207394:	b9412be1 	ldr	w1, [sp, #296]
    80207398:	510042f7 	sub	w23, w23, #0x10
    8020739c:	f9409be0 	ldr	x0, [sp, #304]
    802073a0:	aa1603e4 	mov	x4, x22
    802073a4:	1100042b 	add	w11, w1, #0x1
    802073a8:	d280020c 	mov	x12, #0x10                  	// #16
    802073ac:	710042ff 	cmp	w23, #0x10
    802073b0:	54fffd8c 	b.gt	80207360 <_vfiprintf_r+0x650>
    802073b4:	2a1703e3 	mov	w3, w23
    802073b8:	aa1803ea 	mov	x10, x24
    802073bc:	aa1903f7 	mov	x23, x25
    802073c0:	b9408bf8 	ldr	w24, [sp, #136]
    802073c4:	aa1b03f9 	mov	x25, x27
    802073c8:	b94093e8 	ldr	w8, [sp, #144]
    802073cc:	aa0403fb 	mov	x27, x4
    802073d0:	b9409be4 	ldr	w4, [sp, #152]
    802073d4:	93407c63 	sxtw	x3, w3
    802073d8:	a9000f6a 	stp	x10, x3, [x27]
    802073dc:	8b030000 	add	x0, x0, x3
    802073e0:	b9012beb 	str	w11, [sp, #296]
    802073e4:	f9009be0 	str	x0, [sp, #304]
    802073e8:	71001d7f 	cmp	w11, #0x7
    802073ec:	540018ad 	b.le	80207700 <_vfiprintf_r+0x9f0>
    802073f0:	b4ffede0 	cbz	x0, 802071ac <_vfiprintf_r+0x49c>
    802073f4:	910483e2 	add	x2, sp, #0x120
    802073f8:	aa1503e1 	mov	x1, x21
    802073fc:	aa1303e0 	mov	x0, x19
    80207400:	b9008be8 	str	w8, [sp, #136]
    80207404:	b90093e4 	str	w4, [sp, #144]
    80207408:	97fffe02 	bl	80206c10 <__sprint_r.part.0>
    8020740c:	35ffdba0 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    80207410:	b9412beb 	ldr	w11, [sp, #296]
    80207414:	aa1603fb 	mov	x27, x22
    80207418:	f9409be0 	ldr	x0, [sp, #304]
    8020741c:	1100056b 	add	w11, w11, #0x1
    80207420:	b9408be8 	ldr	w8, [sp, #136]
    80207424:	b94093e4 	ldr	w4, [sp, #144]
    80207428:	17ffff2b 	b	802070d4 <_vfiprintf_r+0x3c4>
    8020742c:	aa1603e4 	mov	x4, x22
    80207430:	5280002b 	mov	w11, #0x1                   	// #1
    80207434:	52800001 	mov	w1, #0x0                   	// #0
    80207438:	17ffffc7 	b	80207354 <_vfiprintf_r+0x644>
    8020743c:	b4000260 	cbz	x0, 80207488 <_vfiprintf_r+0x778>
    80207440:	910483e2 	add	x2, sp, #0x120
    80207444:	aa1503e1 	mov	x1, x21
    80207448:	aa1303e0 	mov	x0, x19
    8020744c:	b9008bed 	str	w13, [sp, #136]
    80207450:	b90093ec 	str	w12, [sp, #144]
    80207454:	b9009be8 	str	w8, [sp, #152]
    80207458:	291893e3 	stp	w3, w4, [sp, #196]
    8020745c:	97fffded 	bl	80206c10 <__sprint_r.part.0>
    80207460:	35ffd900 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    80207464:	b9412be1 	ldr	w1, [sp, #296]
    80207468:	aa1603fb 	mov	x27, x22
    8020746c:	f9409be0 	ldr	x0, [sp, #304]
    80207470:	1100042b 	add	w11, w1, #0x1
    80207474:	b9408bed 	ldr	w13, [sp, #136]
    80207478:	b94093ec 	ldr	w12, [sp, #144]
    8020747c:	b9409be8 	ldr	w8, [sp, #152]
    80207480:	295893e3 	ldp	w3, w4, [sp, #196]
    80207484:	17fffef3 	b	80207050 <_vfiprintf_r+0x340>
    80207488:	340042ad 	cbz	w13, 80207cdc <_vfiprintf_r+0xfcc>
    8020748c:	910403e0 	add	x0, sp, #0x100
    80207490:	d2800041 	mov	x1, #0x2                   	// #2
    80207494:	aa1603fb 	mov	x27, x22
    80207498:	a91a07e0 	stp	x0, x1, [sp, #416]
    8020749c:	aa0103e0 	mov	x0, x1
    802074a0:	5280002b 	mov	w11, #0x1                   	// #1
    802074a4:	d503201f 	nop
    802074a8:	2a0b03e1 	mov	w1, w11
    802074ac:	9100437b 	add	x27, x27, #0x10
    802074b0:	1100056b 	add	w11, w11, #0x1
    802074b4:	17ffff03 	b	802070c0 <_vfiprintf_r+0x3b0>
    802074b8:	7100415f 	cmp	w10, #0x10
    802074bc:	540081ad 	b.le	802084f0 <_vfiprintf_r+0x17e0>
    802074c0:	b000004b 	adrp	x11, 80210000 <__trunctfdf2+0xc0>
    802074c4:	9127016b 	add	x11, x11, #0x9c0
    802074c8:	d280020e 	mov	x14, #0x10                  	// #16
    802074cc:	b9008bf8 	str	w24, [sp, #136]
    802074d0:	aa0b03f8 	mov	x24, x11
    802074d4:	b90093ed 	str	w13, [sp, #144]
    802074d8:	b9009bec 	str	w12, [sp, #152]
    802074dc:	29188fe8 	stp	w8, w3, [sp, #196]
    802074e0:	aa1b03e3 	mov	x3, x27
    802074e4:	aa1903fb 	mov	x27, x25
    802074e8:	aa1703f9 	mov	x25, x23
    802074ec:	2a0a03f7 	mov	w23, w10
    802074f0:	b900cfe4 	str	w4, [sp, #204]
    802074f4:	14000008 	b	80207514 <_vfiprintf_r+0x804>
    802074f8:	1100082f 	add	w15, w1, #0x2
    802074fc:	91004063 	add	x3, x3, #0x10
    80207500:	2a0203e1 	mov	w1, w2
    80207504:	510042f7 	sub	w23, w23, #0x10
    80207508:	710042ff 	cmp	w23, #0x10
    8020750c:	540002cd 	b.le	80207564 <_vfiprintf_r+0x854>
    80207510:	11000422 	add	w2, w1, #0x1
    80207514:	91004000 	add	x0, x0, #0x10
    80207518:	a9003878 	stp	x24, x14, [x3]
    8020751c:	b9012be2 	str	w2, [sp, #296]
    80207520:	f9009be0 	str	x0, [sp, #304]
    80207524:	71001c5f 	cmp	w2, #0x7
    80207528:	54fffe8d 	b.le	802074f8 <_vfiprintf_r+0x7e8>
    8020752c:	b4000460 	cbz	x0, 802075b8 <_vfiprintf_r+0x8a8>
    80207530:	910483e2 	add	x2, sp, #0x120
    80207534:	aa1503e1 	mov	x1, x21
    80207538:	aa1303e0 	mov	x0, x19
    8020753c:	97fffdb5 	bl	80206c10 <__sprint_r.part.0>
    80207540:	35ffd200 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    80207544:	b9412be1 	ldr	w1, [sp, #296]
    80207548:	510042f7 	sub	w23, w23, #0x10
    8020754c:	f9409be0 	ldr	x0, [sp, #304]
    80207550:	aa1603e3 	mov	x3, x22
    80207554:	1100042f 	add	w15, w1, #0x1
    80207558:	d280020e 	mov	x14, #0x10                  	// #16
    8020755c:	710042ff 	cmp	w23, #0x10
    80207560:	54fffd8c 	b.gt	80207510 <_vfiprintf_r+0x800>
    80207564:	2a1703ea 	mov	w10, w23
    80207568:	aa1803eb 	mov	x11, x24
    8020756c:	aa1903f7 	mov	x23, x25
    80207570:	b9408bf8 	ldr	w24, [sp, #136]
    80207574:	aa1b03f9 	mov	x25, x27
    80207578:	b94093ed 	ldr	w13, [sp, #144]
    8020757c:	aa0303fb 	mov	x27, x3
    80207580:	b9409bec 	ldr	w12, [sp, #152]
    80207584:	29588fe8 	ldp	w8, w3, [sp, #196]
    80207588:	b940cfe4 	ldr	w4, [sp, #204]
    8020758c:	93407d4a 	sxtw	x10, w10
    80207590:	a9002b6b 	stp	x11, x10, [x27]
    80207594:	8b0a0000 	add	x0, x0, x10
    80207598:	b9012bef 	str	w15, [sp, #296]
    8020759c:	f9009be0 	str	x0, [sp, #304]
    802075a0:	71001dff 	cmp	w15, #0x7
    802075a4:	5400334c 	b.gt	80207c0c <_vfiprintf_r+0xefc>
    802075a8:	9100437b 	add	x27, x27, #0x10
    802075ac:	110005eb 	add	w11, w15, #0x1
    802075b0:	2a0f03e1 	mov	w1, w15
    802075b4:	17fffe99 	b	80207018 <_vfiprintf_r+0x308>
    802075b8:	aa1603e3 	mov	x3, x22
    802075bc:	52800001 	mov	w1, #0x0                   	// #0
    802075c0:	5280002f 	mov	w15, #0x1                   	// #1
    802075c4:	17ffffd0 	b	80207504 <_vfiprintf_r+0x7f4>
    802075c8:	b9012bff 	str	wzr, [sp, #296]
    802075cc:	361008f8 	tbz	w24, #2, 802076e8 <_vfiprintf_r+0x9d8>
    802075d0:	4b040118 	sub	w24, w8, w4
    802075d4:	7100031f 	cmp	w24, #0x0
    802075d8:	5400088d 	b.le	802076e8 <_vfiprintf_r+0x9d8>
    802075dc:	aa1603fb 	mov	x27, x22
    802075e0:	b9412be2 	ldr	w2, [sp, #296]
    802075e4:	7100431f 	cmp	w24, #0x10
    802075e8:	540078cd 	b.le	80208500 <_vfiprintf_r+0x17f0>
    802075ec:	b000004b 	adrp	x11, 80210000 <__trunctfdf2+0xc0>
    802075f0:	9127016b 	add	x11, x11, #0x9c0
    802075f4:	2a0803fc 	mov	w28, w8
    802075f8:	d280021a 	mov	x26, #0x10                  	// #16
    802075fc:	b9008be4 	str	w4, [sp, #136]
    80207600:	f9004bf7 	str	x23, [sp, #144]
    80207604:	2a1803f7 	mov	w23, w24
    80207608:	aa0b03f8 	mov	x24, x11
    8020760c:	14000007 	b	80207628 <_vfiprintf_r+0x918>
    80207610:	11000846 	add	w6, w2, #0x2
    80207614:	9100437b 	add	x27, x27, #0x10
    80207618:	2a0103e2 	mov	w2, w1
    8020761c:	510042f7 	sub	w23, w23, #0x10
    80207620:	710042ff 	cmp	w23, #0x10
    80207624:	540002ad 	b.le	80207678 <_vfiprintf_r+0x968>
    80207628:	91004000 	add	x0, x0, #0x10
    8020762c:	11000441 	add	w1, w2, #0x1
    80207630:	a9006b78 	stp	x24, x26, [x27]
    80207634:	b9012be1 	str	w1, [sp, #296]
    80207638:	f9009be0 	str	x0, [sp, #304]
    8020763c:	71001c3f 	cmp	w1, #0x7
    80207640:	54fffe8d 	b.le	80207610 <_vfiprintf_r+0x900>
    80207644:	b40004a0 	cbz	x0, 802076d8 <_vfiprintf_r+0x9c8>
    80207648:	910483e2 	add	x2, sp, #0x120
    8020764c:	aa1503e1 	mov	x1, x21
    80207650:	aa1303e0 	mov	x0, x19
    80207654:	97fffd6f 	bl	80206c10 <__sprint_r.part.0>
    80207658:	35ffc940 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    8020765c:	b9412be2 	ldr	w2, [sp, #296]
    80207660:	510042f7 	sub	w23, w23, #0x10
    80207664:	f9409be0 	ldr	x0, [sp, #304]
    80207668:	aa1603fb 	mov	x27, x22
    8020766c:	11000446 	add	w6, w2, #0x1
    80207670:	710042ff 	cmp	w23, #0x10
    80207674:	54fffdac 	b.gt	80207628 <_vfiprintf_r+0x918>
    80207678:	aa1803eb 	mov	x11, x24
    8020767c:	b9408be4 	ldr	w4, [sp, #136]
    80207680:	2a1703f8 	mov	w24, w23
    80207684:	2a1c03e8 	mov	w8, w28
    80207688:	f9404bf7 	ldr	x23, [sp, #144]
    8020768c:	93407f03 	sxtw	x3, w24
    80207690:	8b030000 	add	x0, x0, x3
    80207694:	a9000f6b 	stp	x11, x3, [x27]
    80207698:	b9012be6 	str	w6, [sp, #296]
    8020769c:	f9009be0 	str	x0, [sp, #304]
    802076a0:	71001cdf 	cmp	w6, #0x7
    802076a4:	54ffd46d 	b.le	80207130 <_vfiprintf_r+0x420>
    802076a8:	b4000200 	cbz	x0, 802076e8 <_vfiprintf_r+0x9d8>
    802076ac:	910483e2 	add	x2, sp, #0x120
    802076b0:	aa1503e1 	mov	x1, x21
    802076b4:	aa1303e0 	mov	x0, x19
    802076b8:	b9008be8 	str	w8, [sp, #136]
    802076bc:	b90093e4 	str	w4, [sp, #144]
    802076c0:	97fffd54 	bl	80206c10 <__sprint_r.part.0>
    802076c4:	35ffc5e0 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    802076c8:	f9409be0 	ldr	x0, [sp, #304]
    802076cc:	b9408be8 	ldr	w8, [sp, #136]
    802076d0:	b94093e4 	ldr	w4, [sp, #144]
    802076d4:	17fffe97 	b	80207130 <_vfiprintf_r+0x420>
    802076d8:	aa1603fb 	mov	x27, x22
    802076dc:	52800026 	mov	w6, #0x1                   	// #1
    802076e0:	52800002 	mov	w2, #0x0                   	// #0
    802076e4:	17ffffce 	b	8020761c <_vfiprintf_r+0x90c>
    802076e8:	b9406fe0 	ldr	w0, [sp, #108]
    802076ec:	6b04011f 	cmp	w8, w4
    802076f0:	1a84a104 	csel	w4, w8, w4, ge	// ge = tcont
    802076f4:	0b040000 	add	w0, w0, w4
    802076f8:	b9006fe0 	str	w0, [sp, #108]
    802076fc:	17fffe93 	b	80207148 <_vfiprintf_r+0x438>
    80207700:	9100437b 	add	x27, x27, #0x10
    80207704:	1100056b 	add	w11, w11, #0x1
    80207708:	17fffe73 	b	802070d4 <_vfiprintf_r+0x3c4>
    8020770c:	374fc4a0 	tbnz	w0, #9, 80206fa0 <_vfiprintf_r+0x290>
    80207710:	f94052a0 	ldr	x0, [x21, #160]
    80207714:	9400073b 	bl	80209400 <__retarget_lock_release_recursive>
    80207718:	79c022a0 	ldrsh	w0, [x21, #16]
    8020771c:	17fffe21 	b	80206fa0 <_vfiprintf_r+0x290>
    80207720:	b940c3e1 	ldr	w1, [sp, #192]
    80207724:	2a1a03e8 	mov	w8, w26
    80207728:	2a1c03e3 	mov	w3, w28
    8020772c:	37f82f61 	tbnz	w1, #31, 80207d18 <_vfiprintf_r+0x1008>
    80207730:	91003ee1 	add	x1, x23, #0xf
    80207734:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80207738:	f90047e1 	str	x1, [sp, #136]
    8020773c:	f94002fc 	ldr	x28, [x23]
    80207740:	3903ffff 	strb	wzr, [sp, #255]
    80207744:	b4004d3c 	cbz	x28, 802080e8 <_vfiprintf_r+0x13d8>
    80207748:	71014c1f 	cmp	w0, #0x53
    8020774c:	54003e60 	b.eq	80207f18 <_vfiprintf_r+0x1208>  // b.none
    80207750:	37203e58 	tbnz	w24, #4, 80207f18 <_vfiprintf_r+0x1208>
    80207754:	37f86bc3 	tbnz	w3, #31, 802084cc <_vfiprintf_r+0x17bc>
    80207758:	93407c62 	sxtw	x2, w3
    8020775c:	aa1c03e0 	mov	x0, x28
    80207760:	52800001 	mov	w1, #0x0                   	// #0
    80207764:	b90093e3 	str	w3, [sp, #144]
    80207768:	b9009be8 	str	w8, [sp, #152]
    8020776c:	94000ac5 	bl	8020a280 <memchr>
    80207770:	f9003be0 	str	x0, [sp, #112]
    80207774:	b94093e3 	ldr	w3, [sp, #144]
    80207778:	b9409be8 	ldr	w8, [sp, #152]
    8020777c:	b4006580 	cbz	x0, 8020842c <_vfiprintf_r+0x171c>
    80207780:	cb1c0004 	sub	x4, x0, x28
    80207784:	f9003bff 	str	xzr, [sp, #112]
    80207788:	7100009f 	cmp	w4, #0x0
    8020778c:	2a0403fa 	mov	w26, w4
    80207790:	1a9fa084 	csel	w4, w4, wzr, ge	// ge = tcont
    80207794:	140002ac 	b	80208244 <_vfiprintf_r+0x1534>
    80207798:	2a1a03e8 	mov	w8, w26
    8020779c:	71010c1f 	cmp	w0, #0x43
    802077a0:	54000040 	b.eq	802077a8 <_vfiprintf_r+0xa98>  // b.none
    802077a4:	36202df8 	tbz	w24, #4, 80207d60 <_vfiprintf_r+0x1050>
    802077a8:	910463e0 	add	x0, sp, #0x118
    802077ac:	d2800102 	mov	x2, #0x8                   	// #8
    802077b0:	52800001 	mov	w1, #0x0                   	// #0
    802077b4:	b90073e8 	str	w8, [sp, #112]
    802077b8:	97ffedc2 	bl	80202ec0 <memset>
    802077bc:	b940c3e0 	ldr	w0, [sp, #192]
    802077c0:	b94073e8 	ldr	w8, [sp, #112]
    802077c4:	37f85100 	tbnz	w0, #31, 802081e4 <_vfiprintf_r+0x14d4>
    802077c8:	91002ee1 	add	x1, x23, #0xb
    802077cc:	aa1703e0 	mov	x0, x23
    802077d0:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802077d4:	b9400002 	ldr	w2, [x0]
    802077d8:	9104e3fc 	add	x28, sp, #0x138
    802077dc:	910463e3 	add	x3, sp, #0x118
    802077e0:	aa1c03e1 	mov	x1, x28
    802077e4:	aa1303e0 	mov	x0, x19
    802077e8:	b90073e8 	str	w8, [sp, #112]
    802077ec:	94000695 	bl	80209240 <_wcrtomb_r>
    802077f0:	2a0003fa 	mov	w26, w0
    802077f4:	b94073e8 	ldr	w8, [sp, #112]
    802077f8:	3100041f 	cmn	w0, #0x1
    802077fc:	54008320 	b.eq	80208860 <_vfiprintf_r+0x1b50>  // b.none
    80207800:	7100001f 	cmp	w0, #0x0
    80207804:	3903ffff 	strb	wzr, [sp, #255]
    80207808:	1a9fa004 	csel	w4, w0, wzr, ge	// ge = tcont
    8020780c:	17fffdf6 	b	80206fe4 <_vfiprintf_r+0x2d4>
    80207810:	4b1a03fa 	neg	w26, w26
    80207814:	aa0003f7 	mov	x23, x0
    80207818:	39400320 	ldrb	w0, [x25]
    8020781c:	321e0318 	orr	w24, w24, #0x4
    80207820:	17fffdca 	b	80206f48 <_vfiprintf_r+0x238>
    80207824:	52800560 	mov	w0, #0x2b                  	// #43
    80207828:	3903ffe0 	strb	w0, [sp, #255]
    8020782c:	39400320 	ldrb	w0, [x25]
    80207830:	17fffdc6 	b	80206f48 <_vfiprintf_r+0x238>
    80207834:	39400320 	ldrb	w0, [x25]
    80207838:	32190318 	orr	w24, w24, #0x80
    8020783c:	17fffdc3 	b	80206f48 <_vfiprintf_r+0x238>
    80207840:	aa1903e2 	mov	x2, x25
    80207844:	38401440 	ldrb	w0, [x2], #1
    80207848:	7100a81f 	cmp	w0, #0x2a
    8020784c:	54007b40 	b.eq	802087b4 <_vfiprintf_r+0x1aa4>  // b.none
    80207850:	5100c001 	sub	w1, w0, #0x30
    80207854:	aa0203f9 	mov	x25, x2
    80207858:	52800003 	mov	w3, #0x0                   	// #0
    8020785c:	5280001c 	mov	w28, #0x0                   	// #0
    80207860:	7100243f 	cmp	w1, #0x9
    80207864:	54ffb748 	b.hi	80206f4c <_vfiprintf_r+0x23c>  // b.pmore
    80207868:	38401440 	ldrb	w0, [x2], #1
    8020786c:	0b030863 	add	w3, w3, w3, lsl #2
    80207870:	0b030423 	add	w3, w1, w3, lsl #1
    80207874:	5100c001 	sub	w1, w0, #0x30
    80207878:	7100243f 	cmp	w1, #0x9
    8020787c:	54ffff69 	b.ls	80207868 <_vfiprintf_r+0xb58>  // b.plast
    80207880:	7100007f 	cmp	w3, #0x0
    80207884:	aa0203f9 	mov	x25, x2
    80207888:	5a9fa07c 	csinv	w28, w3, wzr, ge	// ge = tcont
    8020788c:	17fffdb0 	b	80206f4c <_vfiprintf_r+0x23c>
    80207890:	b940c3e0 	ldr	w0, [sp, #192]
    80207894:	37f82320 	tbnz	w0, #31, 80207cf8 <_vfiprintf_r+0xfe8>
    80207898:	91002ee0 	add	x0, x23, #0xb
    8020789c:	927df000 	and	x0, x0, #0xfffffffffffffff8
    802078a0:	b94002fa 	ldr	w26, [x23]
    802078a4:	37fffb7a 	tbnz	w26, #31, 80207810 <_vfiprintf_r+0xb00>
    802078a8:	aa0003f7 	mov	x23, x0
    802078ac:	39400320 	ldrb	w0, [x25]
    802078b0:	17fffda6 	b	80206f48 <_vfiprintf_r+0x238>
    802078b4:	aa1303e0 	mov	x0, x19
    802078b8:	94000a0a 	bl	8020a0e0 <_localeconv_r>
    802078bc:	f9400400 	ldr	x0, [x0, #8]
    802078c0:	f9005fe0 	str	x0, [sp, #184]
    802078c4:	97ffee0f 	bl	80203100 <strlen>
    802078c8:	aa0003e1 	mov	x1, x0
    802078cc:	aa1303e0 	mov	x0, x19
    802078d0:	f90057e1 	str	x1, [sp, #168]
    802078d4:	94000a03 	bl	8020a0e0 <_localeconv_r>
    802078d8:	f94057e1 	ldr	x1, [sp, #168]
    802078dc:	f9400800 	ldr	x0, [x0, #16]
    802078e0:	f9005be0 	str	x0, [sp, #176]
    802078e4:	f100003f 	cmp	x1, #0x0
    802078e8:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
    802078ec:	54001c60 	b.eq	80207c78 <_vfiprintf_r+0xf68>  // b.none
    802078f0:	39400000 	ldrb	w0, [x0]
    802078f4:	32160301 	orr	w1, w24, #0x400
    802078f8:	7100001f 	cmp	w0, #0x0
    802078fc:	39400320 	ldrb	w0, [x25]
    80207900:	1a981038 	csel	w24, w1, w24, ne	// ne = any
    80207904:	17fffd91 	b	80206f48 <_vfiprintf_r+0x238>
    80207908:	39400320 	ldrb	w0, [x25]
    8020790c:	32000318 	orr	w24, w24, #0x1
    80207910:	17fffd8e 	b	80206f48 <_vfiprintf_r+0x238>
    80207914:	3943ffe1 	ldrb	w1, [sp, #255]
    80207918:	39400320 	ldrb	w0, [x25]
    8020791c:	35ffb161 	cbnz	w1, 80206f48 <_vfiprintf_r+0x238>
    80207920:	52800401 	mov	w1, #0x20                  	// #32
    80207924:	3903ffe1 	strb	w1, [sp, #255]
    80207928:	17fffd88 	b	80206f48 <_vfiprintf_r+0x238>
    8020792c:	2a1a03e8 	mov	w8, w26
    80207930:	2a1c03e3 	mov	w3, w28
    80207934:	321c0318 	orr	w24, w24, #0x10
    80207938:	b940c3e0 	ldr	w0, [sp, #192]
    8020793c:	37280058 	tbnz	w24, #5, 80207944 <_vfiprintf_r+0xc34>
    80207940:	36201b18 	tbz	w24, #4, 80207ca0 <_vfiprintf_r+0xf90>
    80207944:	37f82ce0 	tbnz	w0, #31, 80207ee0 <_vfiprintf_r+0x11d0>
    80207948:	91003ee1 	add	x1, x23, #0xf
    8020794c:	aa1703e0 	mov	x0, x23
    80207950:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207954:	f9400001 	ldr	x1, [x0]
    80207958:	12157b04 	and	w4, w24, #0xfffffbff
    8020795c:	52800000 	mov	w0, #0x0                   	// #0
    80207960:	52800002 	mov	w2, #0x0                   	// #0
    80207964:	3903ffe2 	strb	w2, [sp, #255]
    80207968:	37f80da3 	tbnz	w3, #31, 80207b1c <_vfiprintf_r+0xe0c>
    8020796c:	f100003f 	cmp	x1, #0x0
    80207970:	12187898 	and	w24, w4, #0xffffff7f
    80207974:	7a400860 	ccmp	w3, #0x0, #0x0, eq	// eq = none
    80207978:	54000d01 	b.ne	80207b18 <_vfiprintf_r+0xe08>  // b.any
    8020797c:	35000620 	cbnz	w0, 80207a40 <_vfiprintf_r+0xd30>
    80207980:	1200009a 	and	w26, w4, #0x1
    80207984:	360012c4 	tbz	w4, #0, 80207bdc <_vfiprintf_r+0xecc>
    80207988:	91066ffc 	add	x28, sp, #0x19b
    8020798c:	52800600 	mov	w0, #0x30                  	// #48
    80207990:	52800003 	mov	w3, #0x0                   	// #0
    80207994:	39066fe0 	strb	w0, [sp, #411]
    80207998:	3943ffe0 	ldrb	w0, [sp, #255]
    8020799c:	6b1a007f 	cmp	w3, w26
    802079a0:	f9003bff 	str	xzr, [sp, #112]
    802079a4:	1a9aa064 	csel	w4, w3, w26, ge	// ge = tcont
    802079a8:	34000040 	cbz	w0, 802079b0 <_vfiprintf_r+0xca0>
    802079ac:	11000484 	add	w4, w4, #0x1
    802079b0:	121f030d 	and	w13, w24, #0x2
    802079b4:	360fb1f8 	tbz	w24, #1, 80206ff0 <_vfiprintf_r+0x2e0>
    802079b8:	11000884 	add	w4, w4, #0x2
    802079bc:	5280004d 	mov	w13, #0x2                   	// #2
    802079c0:	17fffd8c 	b	80206ff0 <_vfiprintf_r+0x2e0>
    802079c4:	2a1a03e8 	mov	w8, w26
    802079c8:	2a1c03e3 	mov	w3, w28
    802079cc:	321c0304 	orr	w4, w24, #0x10
    802079d0:	b940c3e0 	ldr	w0, [sp, #192]
    802079d4:	37280044 	tbnz	w4, #5, 802079dc <_vfiprintf_r+0xccc>
    802079d8:	36201544 	tbz	w4, #4, 80207c80 <_vfiprintf_r+0xf70>
    802079dc:	37f82700 	tbnz	w0, #31, 80207ebc <_vfiprintf_r+0x11ac>
    802079e0:	91003ee1 	add	x1, x23, #0xf
    802079e4:	aa1703e0 	mov	x0, x23
    802079e8:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802079ec:	f9400001 	ldr	x1, [x0]
    802079f0:	52800020 	mov	w0, #0x1                   	// #1
    802079f4:	17ffffdb 	b	80207960 <_vfiprintf_r+0xc50>
    802079f8:	2a1a03e8 	mov	w8, w26
    802079fc:	2a1c03e3 	mov	w3, w28
    80207a00:	321c0318 	orr	w24, w24, #0x10
    80207a04:	b940c3e0 	ldr	w0, [sp, #192]
    80207a08:	37280058 	tbnz	w24, #5, 80207a10 <_vfiprintf_r+0xd00>
    80207a0c:	36201598 	tbz	w24, #4, 80207cbc <_vfiprintf_r+0xfac>
    80207a10:	37f82440 	tbnz	w0, #31, 80207e98 <_vfiprintf_r+0x1188>
    80207a14:	91003ee1 	add	x1, x23, #0xf
    80207a18:	aa1703e0 	mov	x0, x23
    80207a1c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207a20:	f9400000 	ldr	x0, [x0]
    80207a24:	aa0003e1 	mov	x1, x0
    80207a28:	b7f80e80 	tbnz	x0, #63, 80207bf8 <_vfiprintf_r+0xee8>
    80207a2c:	7100007f 	cmp	w3, #0x0
    80207a30:	54000beb 	b.lt	80207bac <_vfiprintf_r+0xe9c>  // b.tstop
    80207a34:	12187b18 	and	w24, w24, #0xffffff7f
    80207a38:	fa400820 	ccmp	x1, #0x0, #0x0, eq	// eq = none
    80207a3c:	54000b81 	b.ne	80207bac <_vfiprintf_r+0xe9c>  // b.any
    80207a40:	910673fc 	add	x28, sp, #0x19c
    80207a44:	52800003 	mov	w3, #0x0                   	// #0
    80207a48:	5280001a 	mov	w26, #0x0                   	// #0
    80207a4c:	17ffffd3 	b	80207998 <_vfiprintf_r+0xc88>
    80207a50:	b940c3e0 	ldr	w0, [sp, #192]
    80207a54:	37280198 	tbnz	w24, #5, 80207a84 <_vfiprintf_r+0xd74>
    80207a58:	37200178 	tbnz	w24, #4, 80207a84 <_vfiprintf_r+0xd74>
    80207a5c:	373042f8 	tbnz	w24, #6, 802082b8 <_vfiprintf_r+0x15a8>
    80207a60:	36486138 	tbz	w24, #9, 80208684 <_vfiprintf_r+0x1974>
    80207a64:	37f86960 	tbnz	w0, #31, 80208790 <_vfiprintf_r+0x1a80>
    80207a68:	91003ee1 	add	x1, x23, #0xf
    80207a6c:	aa1703e0 	mov	x0, x23
    80207a70:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207a74:	f9400000 	ldr	x0, [x0]
    80207a78:	3941b3e1 	ldrb	w1, [sp, #108]
    80207a7c:	39000001 	strb	w1, [x0]
    80207a80:	17fffcd9 	b	80206de4 <_vfiprintf_r+0xd4>
    80207a84:	37f81860 	tbnz	w0, #31, 80207d90 <_vfiprintf_r+0x1080>
    80207a88:	91003ee1 	add	x1, x23, #0xf
    80207a8c:	aa1703e0 	mov	x0, x23
    80207a90:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207a94:	f9400000 	ldr	x0, [x0]
    80207a98:	b9806fe1 	ldrsw	x1, [sp, #108]
    80207a9c:	f9000001 	str	x1, [x0]
    80207aa0:	17fffcd1 	b	80206de4 <_vfiprintf_r+0xd4>
    80207aa4:	39400320 	ldrb	w0, [x25]
    80207aa8:	7101b01f 	cmp	w0, #0x6c
    80207aac:	540030e0 	b.eq	802080c8 <_vfiprintf_r+0x13b8>  // b.none
    80207ab0:	321c0318 	orr	w24, w24, #0x10
    80207ab4:	17fffd25 	b	80206f48 <_vfiprintf_r+0x238>
    80207ab8:	39400320 	ldrb	w0, [x25]
    80207abc:	7101a01f 	cmp	w0, #0x68
    80207ac0:	540030c0 	b.eq	802080d8 <_vfiprintf_r+0x13c8>  // b.none
    80207ac4:	321a0318 	orr	w24, w24, #0x40
    80207ac8:	17fffd20 	b	80206f48 <_vfiprintf_r+0x238>
    80207acc:	39400320 	ldrb	w0, [x25]
    80207ad0:	321b0318 	orr	w24, w24, #0x20
    80207ad4:	17fffd1d 	b	80206f48 <_vfiprintf_r+0x238>
    80207ad8:	b940c3e0 	ldr	w0, [sp, #192]
    80207adc:	2a1a03e8 	mov	w8, w26
    80207ae0:	2a1c03e3 	mov	w3, w28
    80207ae4:	37f812c0 	tbnz	w0, #31, 80207d3c <_vfiprintf_r+0x102c>
    80207ae8:	91003ee1 	add	x1, x23, #0xf
    80207aec:	aa1703e0 	mov	x0, x23
    80207af0:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207af4:	f9400001 	ldr	x1, [x0]
    80207af8:	528f0600 	mov	w0, #0x7830                	// #30768
    80207afc:	b0000042 	adrp	x2, 80210000 <__trunctfdf2+0xc0>
    80207b00:	321f0304 	orr	w4, w24, #0x2
    80207b04:	91140042 	add	x2, x2, #0x500
    80207b08:	f90053e2 	str	x2, [sp, #160]
    80207b0c:	790203e0 	strh	w0, [sp, #256]
    80207b10:	52800040 	mov	w0, #0x2                   	// #2
    80207b14:	17ffff93 	b	80207960 <_vfiprintf_r+0xc50>
    80207b18:	2a1803e4 	mov	w4, w24
    80207b1c:	7100041f 	cmp	w0, #0x1
    80207b20:	54000480 	b.eq	80207bb0 <_vfiprintf_r+0xea0>  // b.none
    80207b24:	910673fa 	add	x26, sp, #0x19c
    80207b28:	aa1a03fc 	mov	x28, x26
    80207b2c:	7100081f 	cmp	w0, #0x2
    80207b30:	54000141 	b.ne	80207b58 <_vfiprintf_r+0xe48>  // b.any
    80207b34:	f94053e2 	ldr	x2, [sp, #160]
    80207b38:	92400c20 	and	x0, x1, #0xf
    80207b3c:	d344fc21 	lsr	x1, x1, #4
    80207b40:	38606840 	ldrb	w0, [x2, x0]
    80207b44:	381fff80 	strb	w0, [x28, #-1]!
    80207b48:	b5ffff81 	cbnz	x1, 80207b38 <_vfiprintf_r+0xe28>
    80207b4c:	4b1c035a 	sub	w26, w26, w28
    80207b50:	2a0403f8 	mov	w24, w4
    80207b54:	17ffff91 	b	80207998 <_vfiprintf_r+0xc88>
    80207b58:	12000820 	and	w0, w1, #0x7
    80207b5c:	aa1c03e2 	mov	x2, x28
    80207b60:	1100c000 	add	w0, w0, #0x30
    80207b64:	381fff80 	strb	w0, [x28, #-1]!
    80207b68:	d343fc21 	lsr	x1, x1, #3
    80207b6c:	b5ffff61 	cbnz	x1, 80207b58 <_vfiprintf_r+0xe48>
    80207b70:	7100c01f 	cmp	w0, #0x30
    80207b74:	1a9f07e0 	cset	w0, ne	// ne = any
    80207b78:	6a00009f 	tst	w4, w0
    80207b7c:	54fffe80 	b.eq	80207b4c <_vfiprintf_r+0xe3c>  // b.none
    80207b80:	d1000842 	sub	x2, x2, #0x2
    80207b84:	52800600 	mov	w0, #0x30                  	// #48
    80207b88:	2a0403f8 	mov	w24, w4
    80207b8c:	4b02035a 	sub	w26, w26, w2
    80207b90:	381ff380 	sturb	w0, [x28, #-1]
    80207b94:	aa0203fc 	mov	x28, x2
    80207b98:	17ffff80 	b	80207998 <_vfiprintf_r+0xc88>
    80207b9c:	aa1603e3 	mov	x3, x22
    80207ba0:	5280002d 	mov	w13, #0x1                   	// #1
    80207ba4:	52800001 	mov	w1, #0x0                   	// #0
    80207ba8:	17fffd9f 	b	80207224 <_vfiprintf_r+0x514>
    80207bac:	2a1803e4 	mov	w4, w24
    80207bb0:	f100243f 	cmp	x1, #0x9
    80207bb4:	54002308 	b.hi	80208014 <_vfiprintf_r+0x1304>  // b.pmore
    80207bb8:	1100c021 	add	w1, w1, #0x30
    80207bbc:	2a0403f8 	mov	w24, w4
    80207bc0:	91066ffc 	add	x28, sp, #0x19b
    80207bc4:	5280003a 	mov	w26, #0x1                   	// #1
    80207bc8:	39066fe1 	strb	w1, [sp, #411]
    80207bcc:	17ffff73 	b	80207998 <_vfiprintf_r+0xc88>
    80207bd0:	aa1603fb 	mov	x27, x22
    80207bd4:	b9012bff 	str	wzr, [sp, #296]
    80207bd8:	17fffcd0 	b	80206f18 <_vfiprintf_r+0x208>
    80207bdc:	910673fc 	add	x28, sp, #0x19c
    80207be0:	52800003 	mov	w3, #0x0                   	// #0
    80207be4:	17ffff6d 	b	80207998 <_vfiprintf_r+0xc88>
    80207be8:	aa1603fb 	mov	x27, x22
    80207bec:	5280002b 	mov	w11, #0x1                   	// #1
    80207bf0:	52800001 	mov	w1, #0x0                   	// #0
    80207bf4:	17fffd33 	b	802070c0 <_vfiprintf_r+0x3b0>
    80207bf8:	cb0103e1 	neg	x1, x1
    80207bfc:	2a1803e4 	mov	w4, w24
    80207c00:	528005a2 	mov	w2, #0x2d                  	// #45
    80207c04:	52800020 	mov	w0, #0x1                   	// #1
    80207c08:	17ffff57 	b	80207964 <_vfiprintf_r+0xc54>
    80207c0c:	b4000d40 	cbz	x0, 80207db4 <_vfiprintf_r+0x10a4>
    80207c10:	910483e2 	add	x2, sp, #0x120
    80207c14:	aa1503e1 	mov	x1, x21
    80207c18:	aa1303e0 	mov	x0, x19
    80207c1c:	b9008bed 	str	w13, [sp, #136]
    80207c20:	b90093ec 	str	w12, [sp, #144]
    80207c24:	b9009be8 	str	w8, [sp, #152]
    80207c28:	291893e3 	stp	w3, w4, [sp, #196]
    80207c2c:	97fffbf9 	bl	80206c10 <__sprint_r.part.0>
    80207c30:	35ff9a80 	cbnz	w0, 80206f80 <_vfiprintf_r+0x270>
    80207c34:	b9412be1 	ldr	w1, [sp, #296]
    80207c38:	aa1603fb 	mov	x27, x22
    80207c3c:	f9409be0 	ldr	x0, [sp, #304]
    80207c40:	1100042b 	add	w11, w1, #0x1
    80207c44:	b9408bed 	ldr	w13, [sp, #136]
    80207c48:	b94093ec 	ldr	w12, [sp, #144]
    80207c4c:	b9409be8 	ldr	w8, [sp, #152]
    80207c50:	295893e3 	ldp	w3, w4, [sp, #196]
    80207c54:	17fffcf1 	b	80207018 <_vfiprintf_r+0x308>
    80207c58:	f94052a0 	ldr	x0, [x21, #160]
    80207c5c:	940005d9 	bl	802093c0 <__retarget_lock_acquire_recursive>
    80207c60:	79c022a0 	ldrsh	w0, [x21, #16]
    80207c64:	17fffc45 	b	80206d78 <_vfiprintf_r+0x68>
    80207c68:	9100437b 	add	x27, x27, #0x10
    80207c6c:	110005ab 	add	w11, w13, #0x1
    80207c70:	2a0d03e1 	mov	w1, w13
    80207c74:	17fffd15 	b	802070c8 <_vfiprintf_r+0x3b8>
    80207c78:	39400320 	ldrb	w0, [x25]
    80207c7c:	17fffcb3 	b	80206f48 <_vfiprintf_r+0x238>
    80207c80:	363024e4 	tbz	w4, #6, 8020811c <_vfiprintf_r+0x140c>
    80207c84:	37f83640 	tbnz	w0, #31, 8020834c <_vfiprintf_r+0x163c>
    80207c88:	91002ee1 	add	x1, x23, #0xb
    80207c8c:	aa1703e0 	mov	x0, x23
    80207c90:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207c94:	79400001 	ldrh	w1, [x0]
    80207c98:	52800020 	mov	w0, #0x1                   	// #1
    80207c9c:	17ffff31 	b	80207960 <_vfiprintf_r+0xc50>
    80207ca0:	363024f8 	tbz	w24, #6, 8020813c <_vfiprintf_r+0x142c>
    80207ca4:	37f83960 	tbnz	w0, #31, 802083d0 <_vfiprintf_r+0x16c0>
    80207ca8:	aa1703e0 	mov	x0, x23
    80207cac:	91002ee1 	add	x1, x23, #0xb
    80207cb0:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207cb4:	79400001 	ldrh	w1, [x0]
    80207cb8:	17ffff28 	b	80207958 <_vfiprintf_r+0xc48>
    80207cbc:	363027b8 	tbz	w24, #6, 802081b0 <_vfiprintf_r+0x14a0>
    80207cc0:	37f83760 	tbnz	w0, #31, 802083ac <_vfiprintf_r+0x169c>
    80207cc4:	91002ee1 	add	x1, x23, #0xb
    80207cc8:	aa1703e0 	mov	x0, x23
    80207ccc:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207cd0:	79800001 	ldrsh	x1, [x0]
    80207cd4:	aa0103e0 	mov	x0, x1
    80207cd8:	17ffff54 	b	80207a28 <_vfiprintf_r+0xd18>
    80207cdc:	aa1603fb 	mov	x27, x22
    80207ce0:	52800001 	mov	w1, #0x0                   	// #0
    80207ce4:	5280002b 	mov	w11, #0x1                   	// #1
    80207ce8:	17fffcf6 	b	802070c0 <_vfiprintf_r+0x3b0>
    80207cec:	2a1a03e8 	mov	w8, w26
    80207cf0:	2a1c03e3 	mov	w3, w28
    80207cf4:	17ffff44 	b	80207a04 <_vfiprintf_r+0xcf4>
    80207cf8:	b940c3e0 	ldr	w0, [sp, #192]
    80207cfc:	11002001 	add	w1, w0, #0x8
    80207d00:	7100003f 	cmp	w1, #0x0
    80207d04:	54002b6d 	b.le	80208270 <_vfiprintf_r+0x1560>
    80207d08:	91002ee0 	add	x0, x23, #0xb
    80207d0c:	b900c3e1 	str	w1, [sp, #192]
    80207d10:	927df000 	and	x0, x0, #0xfffffffffffffff8
    80207d14:	17fffee3 	b	802078a0 <_vfiprintf_r+0xb90>
    80207d18:	b940c3e1 	ldr	w1, [sp, #192]
    80207d1c:	11002021 	add	w1, w1, #0x8
    80207d20:	7100003f 	cmp	w1, #0x0
    80207d24:	54002b4d 	b.le	8020828c <_vfiprintf_r+0x157c>
    80207d28:	91003ee2 	add	x2, x23, #0xf
    80207d2c:	b900c3e1 	str	w1, [sp, #192]
    80207d30:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80207d34:	f90047e1 	str	x1, [sp, #136]
    80207d38:	17fffe81 	b	8020773c <_vfiprintf_r+0xa2c>
    80207d3c:	b940c3e0 	ldr	w0, [sp, #192]
    80207d40:	11002001 	add	w1, w0, #0x8
    80207d44:	7100003f 	cmp	w1, #0x0
    80207d48:	540028ad 	b.le	8020825c <_vfiprintf_r+0x154c>
    80207d4c:	91003ee2 	add	x2, x23, #0xf
    80207d50:	aa1703e0 	mov	x0, x23
    80207d54:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80207d58:	b900c3e1 	str	w1, [sp, #192]
    80207d5c:	17ffff66 	b	80207af4 <_vfiprintf_r+0xde4>
    80207d60:	b940c3e0 	ldr	w0, [sp, #192]
    80207d64:	37f836a0 	tbnz	w0, #31, 80208438 <_vfiprintf_r+0x1728>
    80207d68:	91002ee1 	add	x1, x23, #0xb
    80207d6c:	aa1703e0 	mov	x0, x23
    80207d70:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207d74:	b9400000 	ldr	w0, [x0]
    80207d78:	52800024 	mov	w4, #0x1                   	// #1
    80207d7c:	9104e3fc 	add	x28, sp, #0x138
    80207d80:	2a0403fa 	mov	w26, w4
    80207d84:	3903ffff 	strb	wzr, [sp, #255]
    80207d88:	3904e3e0 	strb	w0, [sp, #312]
    80207d8c:	17fffc96 	b	80206fe4 <_vfiprintf_r+0x2d4>
    80207d90:	b940c3e0 	ldr	w0, [sp, #192]
    80207d94:	11002001 	add	w1, w0, #0x8
    80207d98:	7100003f 	cmp	w1, #0x0
    80207d9c:	540038ed 	b.le	802084b8 <_vfiprintf_r+0x17a8>
    80207da0:	91003ee2 	add	x2, x23, #0xf
    80207da4:	aa1703e0 	mov	x0, x23
    80207da8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80207dac:	b900c3e1 	str	w1, [sp, #192]
    80207db0:	17ffff39 	b	80207a94 <_vfiprintf_r+0xd84>
    80207db4:	3943ffe1 	ldrb	w1, [sp, #255]
    80207db8:	340029e1 	cbz	w1, 802082f4 <_vfiprintf_r+0x15e4>
    80207dbc:	d2800020 	mov	x0, #0x1                   	// #1
    80207dc0:	9103ffe1 	add	x1, sp, #0xff
    80207dc4:	aa1603fb 	mov	x27, x22
    80207dc8:	2a0003eb 	mov	w11, w0
    80207dcc:	a91a03e1 	stp	x1, x0, [sp, #416]
    80207dd0:	17fffc9d 	b	80207044 <_vfiprintf_r+0x334>
    80207dd4:	2a1a03e8 	mov	w8, w26
    80207dd8:	2a1c03e3 	mov	w3, w28
    80207ddc:	b0000041 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80207de0:	91146021 	add	x1, x1, #0x518
    80207de4:	f90053e1 	str	x1, [sp, #160]
    80207de8:	b940c3e1 	ldr	w1, [sp, #192]
    80207dec:	372802d8 	tbnz	w24, #5, 80207e44 <_vfiprintf_r+0x1134>
    80207df0:	372002b8 	tbnz	w24, #4, 80207e44 <_vfiprintf_r+0x1134>
    80207df4:	36301bd8 	tbz	w24, #6, 8020816c <_vfiprintf_r+0x145c>
    80207df8:	37f82bc1 	tbnz	w1, #31, 80208370 <_vfiprintf_r+0x1660>
    80207dfc:	aa1703e1 	mov	x1, x23
    80207e00:	91002ee2 	add	x2, x23, #0xb
    80207e04:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80207e08:	79400021 	ldrh	w1, [x1]
    80207e0c:	14000013 	b	80207e58 <_vfiprintf_r+0x1148>
    80207e10:	2a1a03e8 	mov	w8, w26
    80207e14:	2a1c03e3 	mov	w3, w28
    80207e18:	2a1803e4 	mov	w4, w24
    80207e1c:	17fffeed 	b	802079d0 <_vfiprintf_r+0xcc0>
    80207e20:	b0000041 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80207e24:	2a1a03e8 	mov	w8, w26
    80207e28:	91140021 	add	x1, x1, #0x500
    80207e2c:	2a1c03e3 	mov	w3, w28
    80207e30:	f90053e1 	str	x1, [sp, #160]
    80207e34:	17ffffed 	b	80207de8 <_vfiprintf_r+0x10d8>
    80207e38:	2a1a03e8 	mov	w8, w26
    80207e3c:	2a1c03e3 	mov	w3, w28
    80207e40:	17fffebe 	b	80207938 <_vfiprintf_r+0xc28>
    80207e44:	37f80181 	tbnz	w1, #31, 80207e74 <_vfiprintf_r+0x1164>
    80207e48:	91003ee2 	add	x2, x23, #0xf
    80207e4c:	aa1703e1 	mov	x1, x23
    80207e50:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80207e54:	f9400021 	ldr	x1, [x1]
    80207e58:	f100003f 	cmp	x1, #0x0
    80207e5c:	1a9f07e2 	cset	w2, ne	// ne = any
    80207e60:	6a02031f 	tst	w24, w2
    80207e64:	54000501 	b.ne	80207f04 <_vfiprintf_r+0x11f4>  // b.any
    80207e68:	12157b04 	and	w4, w24, #0xfffffbff
    80207e6c:	52800040 	mov	w0, #0x2                   	// #2
    80207e70:	17fffebc 	b	80207960 <_vfiprintf_r+0xc50>
    80207e74:	b940c3e1 	ldr	w1, [sp, #192]
    80207e78:	11002022 	add	w2, w1, #0x8
    80207e7c:	7100005f 	cmp	w2, #0x0
    80207e80:	540016cd 	b.le	80208158 <_vfiprintf_r+0x1448>
    80207e84:	91003ee4 	add	x4, x23, #0xf
    80207e88:	aa1703e1 	mov	x1, x23
    80207e8c:	927df097 	and	x23, x4, #0xfffffffffffffff8
    80207e90:	b900c3e2 	str	w2, [sp, #192]
    80207e94:	17fffff0 	b	80207e54 <_vfiprintf_r+0x1144>
    80207e98:	b940c3e0 	ldr	w0, [sp, #192]
    80207e9c:	11002001 	add	w1, w0, #0x8
    80207ea0:	7100003f 	cmp	w1, #0x0
    80207ea4:	540017cd 	b.le	8020819c <_vfiprintf_r+0x148c>
    80207ea8:	91003ee2 	add	x2, x23, #0xf
    80207eac:	aa1703e0 	mov	x0, x23
    80207eb0:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80207eb4:	b900c3e1 	str	w1, [sp, #192]
    80207eb8:	17fffeda 	b	80207a20 <_vfiprintf_r+0xd10>
    80207ebc:	b940c3e0 	ldr	w0, [sp, #192]
    80207ec0:	11002001 	add	w1, w0, #0x8
    80207ec4:	7100003f 	cmp	w1, #0x0
    80207ec8:	5400184d 	b.le	802081d0 <_vfiprintf_r+0x14c0>
    80207ecc:	91003ee2 	add	x2, x23, #0xf
    80207ed0:	aa1703e0 	mov	x0, x23
    80207ed4:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80207ed8:	b900c3e1 	str	w1, [sp, #192]
    80207edc:	17fffec4 	b	802079ec <_vfiprintf_r+0xcdc>
    80207ee0:	b940c3e0 	ldr	w0, [sp, #192]
    80207ee4:	11002001 	add	w1, w0, #0x8
    80207ee8:	7100003f 	cmp	w1, #0x0
    80207eec:	540014ed 	b.le	80208188 <_vfiprintf_r+0x1478>
    80207ef0:	91003ee2 	add	x2, x23, #0xf
    80207ef4:	aa1703e0 	mov	x0, x23
    80207ef8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80207efc:	b900c3e1 	str	w1, [sp, #192]
    80207f00:	17fffe95 	b	80207954 <_vfiprintf_r+0xc44>
    80207f04:	321f0318 	orr	w24, w24, #0x2
    80207f08:	390407e0 	strb	w0, [sp, #257]
    80207f0c:	52800600 	mov	w0, #0x30                  	// #48
    80207f10:	390403e0 	strb	w0, [sp, #256]
    80207f14:	17ffffd5 	b	80207e68 <_vfiprintf_r+0x1158>
    80207f18:	910443e0 	add	x0, sp, #0x110
    80207f1c:	d2800102 	mov	x2, #0x8                   	// #8
    80207f20:	52800001 	mov	w1, #0x0                   	// #0
    80207f24:	b90073e8 	str	w8, [sp, #112]
    80207f28:	b90093e3 	str	w3, [sp, #144]
    80207f2c:	f9008ffc 	str	x28, [sp, #280]
    80207f30:	97ffebe4 	bl	80202ec0 <memset>
    80207f34:	b94093e3 	ldr	w3, [sp, #144]
    80207f38:	b94073e8 	ldr	w8, [sp, #112]
    80207f3c:	37f81663 	tbnz	w3, #31, 80208208 <_vfiprintf_r+0x14f8>
    80207f40:	5280001a 	mov	w26, #0x0                   	// #0
    80207f44:	d2800017 	mov	x23, #0x0                   	// #0
    80207f48:	b90073f8 	str	w24, [sp, #112]
    80207f4c:	2a1a03f8 	mov	w24, w26
    80207f50:	aa1903fa 	mov	x26, x25
    80207f54:	aa1503f9 	mov	x25, x21
    80207f58:	2a0303f5 	mov	w21, w3
    80207f5c:	b90093e8 	str	w8, [sp, #144]
    80207f60:	1400000d 	b	80207f94 <_vfiprintf_r+0x1284>
    80207f64:	910443e3 	add	x3, sp, #0x110
    80207f68:	9104e3e1 	add	x1, sp, #0x138
    80207f6c:	aa1303e0 	mov	x0, x19
    80207f70:	940004b4 	bl	80209240 <_wcrtomb_r>
    80207f74:	3100041f 	cmn	w0, #0x1
    80207f78:	54003560 	b.eq	80208624 <_vfiprintf_r+0x1914>  // b.none
    80207f7c:	0b000300 	add	w0, w24, w0
    80207f80:	6b15001f 	cmp	w0, w21
    80207f84:	540000ec 	b.gt	80207fa0 <_vfiprintf_r+0x1290>
    80207f88:	910012f7 	add	x23, x23, #0x4
    80207f8c:	540033e0 	b.eq	80208608 <_vfiprintf_r+0x18f8>  // b.none
    80207f90:	2a0003f8 	mov	w24, w0
    80207f94:	f9408fe0 	ldr	x0, [sp, #280]
    80207f98:	b8776802 	ldr	w2, [x0, x23]
    80207f9c:	35fffe42 	cbnz	w2, 80207f64 <_vfiprintf_r+0x1254>
    80207fa0:	aa1903f5 	mov	x21, x25
    80207fa4:	b94093e8 	ldr	w8, [sp, #144]
    80207fa8:	aa1a03f9 	mov	x25, x26
    80207fac:	2a1803fa 	mov	w26, w24
    80207fb0:	b94073f8 	ldr	w24, [sp, #112]
    80207fb4:	3400145a 	cbz	w26, 8020823c <_vfiprintf_r+0x152c>
    80207fb8:	71018f5f 	cmp	w26, #0x63
    80207fbc:	540021ec 	b.gt	802083f8 <_vfiprintf_r+0x16e8>
    80207fc0:	9104e3fc 	add	x28, sp, #0x138
    80207fc4:	f9003bff 	str	xzr, [sp, #112]
    80207fc8:	93407f57 	sxtw	x23, w26
    80207fcc:	d2800102 	mov	x2, #0x8                   	// #8
    80207fd0:	52800001 	mov	w1, #0x0                   	// #0
    80207fd4:	910443e0 	add	x0, sp, #0x110
    80207fd8:	b90093e8 	str	w8, [sp, #144]
    80207fdc:	97ffebb9 	bl	80202ec0 <memset>
    80207fe0:	910443e4 	add	x4, sp, #0x110
    80207fe4:	aa1703e3 	mov	x3, x23
    80207fe8:	910463e2 	add	x2, sp, #0x118
    80207fec:	aa1c03e1 	mov	x1, x28
    80207ff0:	aa1303e0 	mov	x0, x19
    80207ff4:	94000a37 	bl	8020a8d0 <_wcsrtombs_r>
    80207ff8:	b94093e8 	ldr	w8, [sp, #144]
    80207ffc:	eb0002ff 	cmp	x23, x0
    80208000:	54004821 	b.ne	80208904 <_vfiprintf_r+0x1bf4>  // b.any
    80208004:	7100035f 	cmp	w26, #0x0
    80208008:	383acb9f 	strb	wzr, [x28, w26, sxtw]
    8020800c:	1a9fa344 	csel	w4, w26, wzr, ge	// ge = tcont
    80208010:	1400008d 	b	80208244 <_vfiprintf_r+0x1534>
    80208014:	910673fa 	add	x26, sp, #0x19c
    80208018:	1216008a 	and	w10, w4, #0x400
    8020801c:	b202e7e6 	mov	x6, #0xcccccccccccccccc    	// #-3689348814741910324
    80208020:	aa1a03e2 	mov	x2, x26
    80208024:	aa1903e5 	mov	x5, x25
    80208028:	aa1a03e7 	mov	x7, x26
    8020802c:	aa1303f9 	mov	x25, x19
    80208030:	aa1503fa 	mov	x26, x21
    80208034:	f9405bf5 	ldr	x21, [sp, #176]
    80208038:	2a0a03f3 	mov	w19, w10
    8020803c:	5280000b 	mov	w11, #0x0                   	// #0
    80208040:	f29999a6 	movk	x6, #0xcccd
    80208044:	14000007 	b	80208060 <_vfiprintf_r+0x1350>
    80208048:	9bc67c38 	umulh	x24, x1, x6
    8020804c:	d343ff18 	lsr	x24, x24, #3
    80208050:	f100243f 	cmp	x1, #0x9
    80208054:	54000249 	b.ls	8020809c <_vfiprintf_r+0x138c>  // b.plast
    80208058:	aa1803e1 	mov	x1, x24
    8020805c:	aa1c03e2 	mov	x2, x28
    80208060:	9bc67c38 	umulh	x24, x1, x6
    80208064:	1100056b 	add	w11, w11, #0x1
    80208068:	d100045c 	sub	x28, x2, #0x1
    8020806c:	d343ff18 	lsr	x24, x24, #3
    80208070:	8b180b00 	add	x0, x24, x24, lsl #2
    80208074:	cb000420 	sub	x0, x1, x0, lsl #1
    80208078:	1100c000 	add	w0, w0, #0x30
    8020807c:	381ff040 	sturb	w0, [x2, #-1]
    80208080:	34fffe53 	cbz	w19, 80208048 <_vfiprintf_r+0x1338>
    80208084:	394002a0 	ldrb	w0, [x21]
    80208088:	7103fc1f 	cmp	w0, #0xff
    8020808c:	7a4b1000 	ccmp	w0, w11, #0x0, ne	// ne = any
    80208090:	54fffdc1 	b.ne	80208048 <_vfiprintf_r+0x1338>  // b.any
    80208094:	f100243f 	cmp	x1, #0x9
    80208098:	54001e28 	b.hi	8020845c <_vfiprintf_r+0x174c>  // b.pmore
    8020809c:	f9005bf5 	str	x21, [sp, #176]
    802080a0:	aa1a03f5 	mov	x21, x26
    802080a4:	aa0703fa 	mov	x26, x7
    802080a8:	aa1903f3 	mov	x19, x25
    802080ac:	4b1c035a 	sub	w26, w26, w28
    802080b0:	aa0503f9 	mov	x25, x5
    802080b4:	2a0403f8 	mov	w24, w4
    802080b8:	17fffe38 	b	80207998 <_vfiprintf_r+0xc88>
    802080bc:	aa1303e0 	mov	x0, x19
    802080c0:	97ffeb44 	bl	80202dd0 <__sinit>
    802080c4:	17fffb29 	b	80206d68 <_vfiprintf_r+0x58>
    802080c8:	39400720 	ldrb	w0, [x25, #1]
    802080cc:	321b0318 	orr	w24, w24, #0x20
    802080d0:	91000739 	add	x25, x25, #0x1
    802080d4:	17fffb9d 	b	80206f48 <_vfiprintf_r+0x238>
    802080d8:	39400720 	ldrb	w0, [x25, #1]
    802080dc:	32170318 	orr	w24, w24, #0x200
    802080e0:	91000739 	add	x25, x25, #0x1
    802080e4:	17fffb99 	b	80206f48 <_vfiprintf_r+0x238>
    802080e8:	7100187f 	cmp	w3, #0x6
    802080ec:	528000c9 	mov	w9, #0x6                   	// #6
    802080f0:	1a89907a 	csel	w26, w3, w9, ls	// ls = plast
    802080f4:	90000047 	adrp	x7, 80210000 <__trunctfdf2+0xc0>
    802080f8:	f94047f7 	ldr	x23, [sp, #136]
    802080fc:	2a1a03e4 	mov	w4, w26
    80208100:	9114c0fc 	add	x28, x7, #0x530
    80208104:	17fffbb8 	b	80206fe4 <_vfiprintf_r+0x2d4>
    80208108:	f9409be0 	ldr	x0, [sp, #304]
    8020810c:	b5002020 	cbnz	x0, 80208510 <_vfiprintf_r+0x1800>
    80208110:	79c022a0 	ldrsh	w0, [x21, #16]
    80208114:	b9012bff 	str	wzr, [sp, #296]
    80208118:	17fffba0 	b	80206f98 <_vfiprintf_r+0x288>
    8020811c:	364810a4 	tbz	w4, #9, 80208330 <_vfiprintf_r+0x1620>
    80208120:	37f824e0 	tbnz	w0, #31, 802085bc <_vfiprintf_r+0x18ac>
    80208124:	91002ee1 	add	x1, x23, #0xb
    80208128:	aa1703e0 	mov	x0, x23
    8020812c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208130:	39400001 	ldrb	w1, [x0]
    80208134:	52800020 	mov	w0, #0x1                   	// #1
    80208138:	17fffe0a 	b	80207960 <_vfiprintf_r+0xc50>
    8020813c:	36480e38 	tbz	w24, #9, 80208300 <_vfiprintf_r+0x15f0>
    80208140:	37f82500 	tbnz	w0, #31, 802085e0 <_vfiprintf_r+0x18d0>
    80208144:	aa1703e0 	mov	x0, x23
    80208148:	91002ee1 	add	x1, x23, #0xb
    8020814c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208150:	39400001 	ldrb	w1, [x0]
    80208154:	17fffe01 	b	80207958 <_vfiprintf_r+0xc48>
    80208158:	f94043e4 	ldr	x4, [sp, #128]
    8020815c:	b940c3e1 	ldr	w1, [sp, #192]
    80208160:	b900c3e2 	str	w2, [sp, #192]
    80208164:	8b21c081 	add	x1, x4, w1, sxtw
    80208168:	17ffff3b 	b	80207e54 <_vfiprintf_r+0x1144>
    8020816c:	36480d78 	tbz	w24, #9, 80208318 <_vfiprintf_r+0x1608>
    80208170:	37f82001 	tbnz	w1, #31, 80208570 <_vfiprintf_r+0x1860>
    80208174:	aa1703e1 	mov	x1, x23
    80208178:	91002ee2 	add	x2, x23, #0xb
    8020817c:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208180:	39400021 	ldrb	w1, [x1]
    80208184:	17ffff35 	b	80207e58 <_vfiprintf_r+0x1148>
    80208188:	f94043e2 	ldr	x2, [sp, #128]
    8020818c:	b940c3e0 	ldr	w0, [sp, #192]
    80208190:	b900c3e1 	str	w1, [sp, #192]
    80208194:	8b20c040 	add	x0, x2, w0, sxtw
    80208198:	17fffdef 	b	80207954 <_vfiprintf_r+0xc44>
    8020819c:	f94043e2 	ldr	x2, [sp, #128]
    802081a0:	b940c3e0 	ldr	w0, [sp, #192]
    802081a4:	b900c3e1 	str	w1, [sp, #192]
    802081a8:	8b20c040 	add	x0, x2, w0, sxtw
    802081ac:	17fffe1d 	b	80207a20 <_vfiprintf_r+0xd10>
    802081b0:	36480958 	tbz	w24, #9, 802082d8 <_vfiprintf_r+0x15c8>
    802081b4:	37f82780 	tbnz	w0, #31, 802086a4 <_vfiprintf_r+0x1994>
    802081b8:	91002ee1 	add	x1, x23, #0xb
    802081bc:	aa1703e0 	mov	x0, x23
    802081c0:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802081c4:	39800001 	ldrsb	x1, [x0]
    802081c8:	aa0103e0 	mov	x0, x1
    802081cc:	17fffe17 	b	80207a28 <_vfiprintf_r+0xd18>
    802081d0:	f94043e2 	ldr	x2, [sp, #128]
    802081d4:	b940c3e0 	ldr	w0, [sp, #192]
    802081d8:	b900c3e1 	str	w1, [sp, #192]
    802081dc:	8b20c040 	add	x0, x2, w0, sxtw
    802081e0:	17fffe03 	b	802079ec <_vfiprintf_r+0xcdc>
    802081e4:	b940c3e0 	ldr	w0, [sp, #192]
    802081e8:	11002001 	add	w1, w0, #0x8
    802081ec:	7100003f 	cmp	w1, #0x0
    802081f0:	54000d4d 	b.le	80208398 <_vfiprintf_r+0x1688>
    802081f4:	91002ee2 	add	x2, x23, #0xb
    802081f8:	aa1703e0 	mov	x0, x23
    802081fc:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208200:	b900c3e1 	str	w1, [sp, #192]
    80208204:	17fffd74 	b	802077d4 <_vfiprintf_r+0xac4>
    80208208:	910443e4 	add	x4, sp, #0x110
    8020820c:	910463e2 	add	x2, sp, #0x118
    80208210:	aa1303e0 	mov	x0, x19
    80208214:	d2800003 	mov	x3, #0x0                   	// #0
    80208218:	d2800001 	mov	x1, #0x0                   	// #0
    8020821c:	b90073e8 	str	w8, [sp, #112]
    80208220:	940009ac 	bl	8020a8d0 <_wcsrtombs_r>
    80208224:	2a0003fa 	mov	w26, w0
    80208228:	b94073e8 	ldr	w8, [sp, #112]
    8020822c:	3100041f 	cmn	w0, #0x1
    80208230:	54003180 	b.eq	80208860 <_vfiprintf_r+0x1b50>  // b.none
    80208234:	f9008ffc 	str	x28, [sp, #280]
    80208238:	17ffff5f 	b	80207fb4 <_vfiprintf_r+0x12a4>
    8020823c:	52800004 	mov	w4, #0x0                   	// #0
    80208240:	f9003bff 	str	xzr, [sp, #112]
    80208244:	3943ffe0 	ldrb	w0, [sp, #255]
    80208248:	52800003 	mov	w3, #0x0                   	// #0
    8020824c:	f94047f7 	ldr	x23, [sp, #136]
    80208250:	5280000d 	mov	w13, #0x0                   	// #0
    80208254:	35ffbac0 	cbnz	w0, 802079ac <_vfiprintf_r+0xc9c>
    80208258:	17fffb66 	b	80206ff0 <_vfiprintf_r+0x2e0>
    8020825c:	f94043e2 	ldr	x2, [sp, #128]
    80208260:	b940c3e0 	ldr	w0, [sp, #192]
    80208264:	b900c3e1 	str	w1, [sp, #192]
    80208268:	8b20c040 	add	x0, x2, w0, sxtw
    8020826c:	17fffe22 	b	80207af4 <_vfiprintf_r+0xde4>
    80208270:	f94043e2 	ldr	x2, [sp, #128]
    80208274:	b940c3e0 	ldr	w0, [sp, #192]
    80208278:	b900c3e1 	str	w1, [sp, #192]
    8020827c:	8b20c042 	add	x2, x2, w0, sxtw
    80208280:	aa1703e0 	mov	x0, x23
    80208284:	aa0203f7 	mov	x23, x2
    80208288:	17fffd86 	b	802078a0 <_vfiprintf_r+0xb90>
    8020828c:	f94043e4 	ldr	x4, [sp, #128]
    80208290:	f90047f7 	str	x23, [sp, #136]
    80208294:	b940c3e2 	ldr	w2, [sp, #192]
    80208298:	b900c3e1 	str	w1, [sp, #192]
    8020829c:	8b22c082 	add	x2, x4, w2, sxtw
    802082a0:	aa0203f7 	mov	x23, x2
    802082a4:	17fffd26 	b	8020773c <_vfiprintf_r+0xa2c>
    802082a8:	aa1603fb 	mov	x27, x22
    802082ac:	5280002b 	mov	w11, #0x1                   	// #1
    802082b0:	52800001 	mov	w1, #0x0                   	// #0
    802082b4:	17fffb85 	b	802070c8 <_vfiprintf_r+0x3b8>
    802082b8:	37f81700 	tbnz	w0, #31, 80208598 <_vfiprintf_r+0x1888>
    802082bc:	91003ee1 	add	x1, x23, #0xf
    802082c0:	aa1703e0 	mov	x0, x23
    802082c4:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802082c8:	f9400000 	ldr	x0, [x0]
    802082cc:	7940dbe1 	ldrh	w1, [sp, #108]
    802082d0:	79000001 	strh	w1, [x0]
    802082d4:	17fffac4 	b	80206de4 <_vfiprintf_r+0xd4>
    802082d8:	37f81f80 	tbnz	w0, #31, 802086c8 <_vfiprintf_r+0x19b8>
    802082dc:	91002ee1 	add	x1, x23, #0xb
    802082e0:	aa1703e0 	mov	x0, x23
    802082e4:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802082e8:	b9800001 	ldrsw	x1, [x0]
    802082ec:	aa0103e0 	mov	x0, x1
    802082f0:	17fffdce 	b	80207a28 <_vfiprintf_r+0xd18>
    802082f4:	aa1603fb 	mov	x27, x22
    802082f8:	5280002b 	mov	w11, #0x1                   	// #1
    802082fc:	17fffb55 	b	80207050 <_vfiprintf_r+0x340>
    80208300:	37f81ae0 	tbnz	w0, #31, 8020865c <_vfiprintf_r+0x194c>
    80208304:	aa1703e0 	mov	x0, x23
    80208308:	91002ee1 	add	x1, x23, #0xb
    8020830c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208310:	b9400001 	ldr	w1, [x0]
    80208314:	17fffd91 	b	80207958 <_vfiprintf_r+0xc48>
    80208318:	37f81ea1 	tbnz	w1, #31, 802086ec <_vfiprintf_r+0x19dc>
    8020831c:	aa1703e1 	mov	x1, x23
    80208320:	91002ee2 	add	x2, x23, #0xb
    80208324:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208328:	b9400021 	ldr	w1, [x1]
    8020832c:	17fffecb 	b	80207e58 <_vfiprintf_r+0x1148>
    80208330:	37f81840 	tbnz	w0, #31, 80208638 <_vfiprintf_r+0x1928>
    80208334:	91002ee1 	add	x1, x23, #0xb
    80208338:	aa1703e0 	mov	x0, x23
    8020833c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208340:	b9400001 	ldr	w1, [x0]
    80208344:	52800020 	mov	w0, #0x1                   	// #1
    80208348:	17fffd86 	b	80207960 <_vfiprintf_r+0xc50>
    8020834c:	b940c3e0 	ldr	w0, [sp, #192]
    80208350:	11002001 	add	w1, w0, #0x8
    80208354:	7100003f 	cmp	w1, #0x0
    80208358:	54001e8d 	b.le	80208728 <_vfiprintf_r+0x1a18>
    8020835c:	91002ee2 	add	x2, x23, #0xb
    80208360:	aa1703e0 	mov	x0, x23
    80208364:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208368:	b900c3e1 	str	w1, [sp, #192]
    8020836c:	17fffe4a 	b	80207c94 <_vfiprintf_r+0xf84>
    80208370:	b940c3e1 	ldr	w1, [sp, #192]
    80208374:	11002022 	add	w2, w1, #0x8
    80208378:	7100005f 	cmp	w2, #0x0
    8020837c:	54001ecd 	b.le	80208754 <_vfiprintf_r+0x1a44>
    80208380:	aa1703e1 	mov	x1, x23
    80208384:	91002ee4 	add	x4, x23, #0xb
    80208388:	927df097 	and	x23, x4, #0xfffffffffffffff8
    8020838c:	b900c3e2 	str	w2, [sp, #192]
    80208390:	79400021 	ldrh	w1, [x1]
    80208394:	17fffeb1 	b	80207e58 <_vfiprintf_r+0x1148>
    80208398:	f94043e2 	ldr	x2, [sp, #128]
    8020839c:	b940c3e0 	ldr	w0, [sp, #192]
    802083a0:	b900c3e1 	str	w1, [sp, #192]
    802083a4:	8b20c040 	add	x0, x2, w0, sxtw
    802083a8:	17fffd0b 	b	802077d4 <_vfiprintf_r+0xac4>
    802083ac:	b940c3e0 	ldr	w0, [sp, #192]
    802083b0:	11002001 	add	w1, w0, #0x8
    802083b4:	7100003f 	cmp	w1, #0x0
    802083b8:	54001aed 	b.le	80208714 <_vfiprintf_r+0x1a04>
    802083bc:	91002ee2 	add	x2, x23, #0xb
    802083c0:	aa1703e0 	mov	x0, x23
    802083c4:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802083c8:	b900c3e1 	str	w1, [sp, #192]
    802083cc:	17fffe41 	b	80207cd0 <_vfiprintf_r+0xfc0>
    802083d0:	b940c3e0 	ldr	w0, [sp, #192]
    802083d4:	11002001 	add	w1, w0, #0x8
    802083d8:	7100003f 	cmp	w1, #0x0
    802083dc:	54001b0d 	b.le	8020873c <_vfiprintf_r+0x1a2c>
    802083e0:	aa1703e0 	mov	x0, x23
    802083e4:	91002ee2 	add	x2, x23, #0xb
    802083e8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802083ec:	b900c3e1 	str	w1, [sp, #192]
    802083f0:	79400001 	ldrh	w1, [x0]
    802083f4:	17fffd59 	b	80207958 <_vfiprintf_r+0xc48>
    802083f8:	11000741 	add	w1, w26, #0x1
    802083fc:	aa1303e0 	mov	x0, x19
    80208400:	b90073e8 	str	w8, [sp, #112]
    80208404:	93407c21 	sxtw	x1, w1
    80208408:	9400018e 	bl	80208a40 <_malloc_r>
    8020840c:	b94073e8 	ldr	w8, [sp, #112]
    80208410:	aa0003fc 	mov	x28, x0
    80208414:	b4002260 	cbz	x0, 80208860 <_vfiprintf_r+0x1b50>
    80208418:	f9003be0 	str	x0, [sp, #112]
    8020841c:	17fffeeb 	b	80207fc8 <_vfiprintf_r+0x12b8>
    80208420:	f94052a0 	ldr	x0, [x21, #160]
    80208424:	940003f7 	bl	80209400 <__retarget_lock_release_recursive>
    80208428:	17fffa8f 	b	80206e64 <_vfiprintf_r+0x154>
    8020842c:	2a0303e4 	mov	w4, w3
    80208430:	2a0303fa 	mov	w26, w3
    80208434:	17ffff84 	b	80208244 <_vfiprintf_r+0x1534>
    80208438:	b940c3e0 	ldr	w0, [sp, #192]
    8020843c:	11002001 	add	w1, w0, #0x8
    80208440:	7100003f 	cmp	w1, #0x0
    80208444:	5400072d 	b.le	80208528 <_vfiprintf_r+0x1818>
    80208448:	91002ee2 	add	x2, x23, #0xb
    8020844c:	aa1703e0 	mov	x0, x23
    80208450:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208454:	b900c3e1 	str	w1, [sp, #192]
    80208458:	17fffe47 	b	80207d74 <_vfiprintf_r+0x1064>
    8020845c:	f94057e0 	ldr	x0, [sp, #168]
    80208460:	b90073e4 	str	w4, [sp, #112]
    80208464:	f9405fe1 	ldr	x1, [sp, #184]
    80208468:	cb00039c 	sub	x28, x28, x0
    8020846c:	aa0003e2 	mov	x2, x0
    80208470:	aa1c03e0 	mov	x0, x28
    80208474:	b9008be8 	str	w8, [sp, #136]
    80208478:	b90093e3 	str	w3, [sp, #144]
    8020847c:	f9004fe5 	str	x5, [sp, #152]
    80208480:	f9005be7 	str	x7, [sp, #176]
    80208484:	94001297 	bl	8020cee0 <strncpy>
    80208488:	394006a0 	ldrb	w0, [x21, #1]
    8020848c:	b202e7e6 	mov	x6, #0xcccccccccccccccc    	// #-3689348814741910324
    80208490:	f9404fe5 	ldr	x5, [sp, #152]
    80208494:	7100001f 	cmp	w0, #0x0
    80208498:	f9405be7 	ldr	x7, [sp, #176]
    8020849c:	9a9506b5 	cinc	x21, x21, ne	// ne = any
    802084a0:	b94073e4 	ldr	w4, [sp, #112]
    802084a4:	5280000b 	mov	w11, #0x0                   	// #0
    802084a8:	b9408be8 	ldr	w8, [sp, #136]
    802084ac:	f29999a6 	movk	x6, #0xcccd
    802084b0:	b94093e3 	ldr	w3, [sp, #144]
    802084b4:	17fffee9 	b	80208058 <_vfiprintf_r+0x1348>
    802084b8:	f94043e2 	ldr	x2, [sp, #128]
    802084bc:	b940c3e0 	ldr	w0, [sp, #192]
    802084c0:	b900c3e1 	str	w1, [sp, #192]
    802084c4:	8b20c040 	add	x0, x2, w0, sxtw
    802084c8:	17fffd73 	b	80207a94 <_vfiprintf_r+0xd84>
    802084cc:	aa1c03e0 	mov	x0, x28
    802084d0:	b90093e8 	str	w8, [sp, #144]
    802084d4:	97ffeb0b 	bl	80203100 <strlen>
    802084d8:	7100001f 	cmp	w0, #0x0
    802084dc:	b94093e8 	ldr	w8, [sp, #144]
    802084e0:	2a0003fa 	mov	w26, w0
    802084e4:	1a9fa004 	csel	w4, w0, wzr, ge	// ge = tcont
    802084e8:	f9003bff 	str	xzr, [sp, #112]
    802084ec:	17ffff56 	b	80208244 <_vfiprintf_r+0x1534>
    802084f0:	9000004b 	adrp	x11, 80210000 <__trunctfdf2+0xc0>
    802084f4:	2a0203ef 	mov	w15, w2
    802084f8:	9127016b 	add	x11, x11, #0x9c0
    802084fc:	17fffc24 	b	8020758c <_vfiprintf_r+0x87c>
    80208500:	9000004b 	adrp	x11, 80210000 <__trunctfdf2+0xc0>
    80208504:	11000446 	add	w6, w2, #0x1
    80208508:	9127016b 	add	x11, x11, #0x9c0
    8020850c:	17fffc60 	b	8020768c <_vfiprintf_r+0x97c>
    80208510:	aa1303e0 	mov	x0, x19
    80208514:	910483e2 	add	x2, sp, #0x120
    80208518:	aa1503e1 	mov	x1, x21
    8020851c:	97fff9bd 	bl	80206c10 <__sprint_r.part.0>
    80208520:	34ffdf80 	cbz	w0, 80208110 <_vfiprintf_r+0x1400>
    80208524:	17fffa9c 	b	80206f94 <_vfiprintf_r+0x284>
    80208528:	f94043e2 	ldr	x2, [sp, #128]
    8020852c:	b940c3e0 	ldr	w0, [sp, #192]
    80208530:	b900c3e1 	str	w1, [sp, #192]
    80208534:	8b20c040 	add	x0, x2, w0, sxtw
    80208538:	17fffe0f 	b	80207d74 <_vfiprintf_r+0x1064>
    8020853c:	9000004a 	adrp	x10, 80210000 <__trunctfdf2+0xc0>
    80208540:	2a0b03ed 	mov	w13, w11
    80208544:	9126c14a 	add	x10, x10, #0x9b0
    80208548:	17fffb58 	b	802072a8 <_vfiprintf_r+0x598>
    8020854c:	b940b2a0 	ldr	w0, [x21, #176]
    80208550:	370000a0 	tbnz	w0, #0, 80208564 <_vfiprintf_r+0x1854>
    80208554:	794022a0 	ldrh	w0, [x21, #16]
    80208558:	37480060 	tbnz	w0, #9, 80208564 <_vfiprintf_r+0x1854>
    8020855c:	f94052a0 	ldr	x0, [x21, #160]
    80208560:	940003a8 	bl	80209400 <__retarget_lock_release_recursive>
    80208564:	12800000 	mov	w0, #0xffffffff            	// #-1
    80208568:	b9006fe0 	str	w0, [sp, #108]
    8020856c:	17fffa8f 	b	80206fa8 <_vfiprintf_r+0x298>
    80208570:	b940c3e1 	ldr	w1, [sp, #192]
    80208574:	11002022 	add	w2, w1, #0x8
    80208578:	7100005f 	cmp	w2, #0x0
    8020857c:	5400150d 	b.le	8020881c <_vfiprintf_r+0x1b0c>
    80208580:	aa1703e1 	mov	x1, x23
    80208584:	91002ee4 	add	x4, x23, #0xb
    80208588:	927df097 	and	x23, x4, #0xfffffffffffffff8
    8020858c:	b900c3e2 	str	w2, [sp, #192]
    80208590:	39400021 	ldrb	w1, [x1]
    80208594:	17fffe31 	b	80207e58 <_vfiprintf_r+0x1148>
    80208598:	b940c3e0 	ldr	w0, [sp, #192]
    8020859c:	11002001 	add	w1, w0, #0x8
    802085a0:	7100003f 	cmp	w1, #0x0
    802085a4:	5400148d 	b.le	80208834 <_vfiprintf_r+0x1b24>
    802085a8:	91003ee2 	add	x2, x23, #0xf
    802085ac:	aa1703e0 	mov	x0, x23
    802085b0:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802085b4:	b900c3e1 	str	w1, [sp, #192]
    802085b8:	17ffff44 	b	802082c8 <_vfiprintf_r+0x15b8>
    802085bc:	b940c3e0 	ldr	w0, [sp, #192]
    802085c0:	11002001 	add	w1, w0, #0x8
    802085c4:	7100003f 	cmp	w1, #0x0
    802085c8:	5400154d 	b.le	80208870 <_vfiprintf_r+0x1b60>
    802085cc:	91002ee2 	add	x2, x23, #0xb
    802085d0:	aa1703e0 	mov	x0, x23
    802085d4:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802085d8:	b900c3e1 	str	w1, [sp, #192]
    802085dc:	17fffed5 	b	80208130 <_vfiprintf_r+0x1420>
    802085e0:	b940c3e0 	ldr	w0, [sp, #192]
    802085e4:	11002001 	add	w1, w0, #0x8
    802085e8:	7100003f 	cmp	w1, #0x0
    802085ec:	5400160d 	b.le	802088ac <_vfiprintf_r+0x1b9c>
    802085f0:	aa1703e0 	mov	x0, x23
    802085f4:	91002ee2 	add	x2, x23, #0xb
    802085f8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802085fc:	b900c3e1 	str	w1, [sp, #192]
    80208600:	39400001 	ldrb	w1, [x0]
    80208604:	17fffcd5 	b	80207958 <_vfiprintf_r+0xc48>
    80208608:	2a1503e3 	mov	w3, w21
    8020860c:	b94073f8 	ldr	w24, [sp, #112]
    80208610:	aa1903f5 	mov	x21, x25
    80208614:	b94093e8 	ldr	w8, [sp, #144]
    80208618:	aa1a03f9 	mov	x25, x26
    8020861c:	2a0303fa 	mov	w26, w3
    80208620:	17fffe65 	b	80207fb4 <_vfiprintf_r+0x12a4>
    80208624:	79c02320 	ldrsh	w0, [x25, #16]
    80208628:	aa1903f5 	mov	x21, x25
    8020862c:	321a0000 	orr	w0, w0, #0x40
    80208630:	79002320 	strh	w0, [x25, #16]
    80208634:	17fffa59 	b	80206f98 <_vfiprintf_r+0x288>
    80208638:	b940c3e0 	ldr	w0, [sp, #192]
    8020863c:	11002001 	add	w1, w0, #0x8
    80208640:	7100003f 	cmp	w1, #0x0
    80208644:	5400120d 	b.le	80208884 <_vfiprintf_r+0x1b74>
    80208648:	91002ee2 	add	x2, x23, #0xb
    8020864c:	aa1703e0 	mov	x0, x23
    80208650:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208654:	b900c3e1 	str	w1, [sp, #192]
    80208658:	17ffff3a 	b	80208340 <_vfiprintf_r+0x1630>
    8020865c:	b940c3e0 	ldr	w0, [sp, #192]
    80208660:	11002001 	add	w1, w0, #0x8
    80208664:	7100003f 	cmp	w1, #0x0
    80208668:	5400138d 	b.le	802088d8 <_vfiprintf_r+0x1bc8>
    8020866c:	aa1703e0 	mov	x0, x23
    80208670:	91002ee2 	add	x2, x23, #0xb
    80208674:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208678:	b900c3e1 	str	w1, [sp, #192]
    8020867c:	b9400001 	ldr	w1, [x0]
    80208680:	17fffcb6 	b	80207958 <_vfiprintf_r+0xc48>
    80208684:	37f80740 	tbnz	w0, #31, 8020876c <_vfiprintf_r+0x1a5c>
    80208688:	91003ee1 	add	x1, x23, #0xf
    8020868c:	aa1703e0 	mov	x0, x23
    80208690:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208694:	f9400000 	ldr	x0, [x0]
    80208698:	b9406fe1 	ldr	w1, [sp, #108]
    8020869c:	b9000001 	str	w1, [x0]
    802086a0:	17fff9d1 	b	80206de4 <_vfiprintf_r+0xd4>
    802086a4:	b940c3e0 	ldr	w0, [sp, #192]
    802086a8:	11002001 	add	w1, w0, #0x8
    802086ac:	7100003f 	cmp	w1, #0x0
    802086b0:	540010ad 	b.le	802088c4 <_vfiprintf_r+0x1bb4>
    802086b4:	91002ee2 	add	x2, x23, #0xb
    802086b8:	aa1703e0 	mov	x0, x23
    802086bc:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802086c0:	b900c3e1 	str	w1, [sp, #192]
    802086c4:	17fffec0 	b	802081c4 <_vfiprintf_r+0x14b4>
    802086c8:	b940c3e0 	ldr	w0, [sp, #192]
    802086cc:	11002001 	add	w1, w0, #0x8
    802086d0:	7100003f 	cmp	w1, #0x0
    802086d4:	54000e2d 	b.le	80208898 <_vfiprintf_r+0x1b88>
    802086d8:	91002ee2 	add	x2, x23, #0xb
    802086dc:	aa1703e0 	mov	x0, x23
    802086e0:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802086e4:	b900c3e1 	str	w1, [sp, #192]
    802086e8:	17ffff00 	b	802082e8 <_vfiprintf_r+0x15d8>
    802086ec:	b940c3e1 	ldr	w1, [sp, #192]
    802086f0:	11002022 	add	w2, w1, #0x8
    802086f4:	7100005f 	cmp	w2, #0x0
    802086f8:	54000a8d 	b.le	80208848 <_vfiprintf_r+0x1b38>
    802086fc:	aa1703e1 	mov	x1, x23
    80208700:	91002ee4 	add	x4, x23, #0xb
    80208704:	927df097 	and	x23, x4, #0xfffffffffffffff8
    80208708:	b900c3e2 	str	w2, [sp, #192]
    8020870c:	b9400021 	ldr	w1, [x1]
    80208710:	17fffdd2 	b	80207e58 <_vfiprintf_r+0x1148>
    80208714:	f94043e2 	ldr	x2, [sp, #128]
    80208718:	b940c3e0 	ldr	w0, [sp, #192]
    8020871c:	b900c3e1 	str	w1, [sp, #192]
    80208720:	8b20c040 	add	x0, x2, w0, sxtw
    80208724:	17fffd6b 	b	80207cd0 <_vfiprintf_r+0xfc0>
    80208728:	f94043e2 	ldr	x2, [sp, #128]
    8020872c:	b940c3e0 	ldr	w0, [sp, #192]
    80208730:	b900c3e1 	str	w1, [sp, #192]
    80208734:	8b20c040 	add	x0, x2, w0, sxtw
    80208738:	17fffd57 	b	80207c94 <_vfiprintf_r+0xf84>
    8020873c:	f94043e2 	ldr	x2, [sp, #128]
    80208740:	b940c3e0 	ldr	w0, [sp, #192]
    80208744:	b900c3e1 	str	w1, [sp, #192]
    80208748:	8b20c040 	add	x0, x2, w0, sxtw
    8020874c:	79400001 	ldrh	w1, [x0]
    80208750:	17fffc82 	b	80207958 <_vfiprintf_r+0xc48>
    80208754:	f94043e4 	ldr	x4, [sp, #128]
    80208758:	b940c3e1 	ldr	w1, [sp, #192]
    8020875c:	b900c3e2 	str	w2, [sp, #192]
    80208760:	8b21c081 	add	x1, x4, w1, sxtw
    80208764:	79400021 	ldrh	w1, [x1]
    80208768:	17fffdbc 	b	80207e58 <_vfiprintf_r+0x1148>
    8020876c:	b940c3e0 	ldr	w0, [sp, #192]
    80208770:	11002001 	add	w1, w0, #0x8
    80208774:	7100003f 	cmp	w1, #0x0
    80208778:	54000bcd 	b.le	802088f0 <_vfiprintf_r+0x1be0>
    8020877c:	91003ee2 	add	x2, x23, #0xf
    80208780:	aa1703e0 	mov	x0, x23
    80208784:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208788:	b900c3e1 	str	w1, [sp, #192]
    8020878c:	17ffffc2 	b	80208694 <_vfiprintf_r+0x1984>
    80208790:	b940c3e0 	ldr	w0, [sp, #192]
    80208794:	11002001 	add	w1, w0, #0x8
    80208798:	7100003f 	cmp	w1, #0x0
    8020879c:	5400024d 	b.le	802087e4 <_vfiprintf_r+0x1ad4>
    802087a0:	91003ee2 	add	x2, x23, #0xf
    802087a4:	aa1703e0 	mov	x0, x23
    802087a8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802087ac:	b900c3e1 	str	w1, [sp, #192]
    802087b0:	17fffcb1 	b	80207a74 <_vfiprintf_r+0xd64>
    802087b4:	b940c3e0 	ldr	w0, [sp, #192]
    802087b8:	37f80200 	tbnz	w0, #31, 802087f8 <_vfiprintf_r+0x1ae8>
    802087bc:	91002ee1 	add	x1, x23, #0xb
    802087c0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802087c4:	b94002e3 	ldr	w3, [x23]
    802087c8:	aa0103f7 	mov	x23, x1
    802087cc:	b900c3e0 	str	w0, [sp, #192]
    802087d0:	7100007f 	cmp	w3, #0x0
    802087d4:	39400720 	ldrb	w0, [x25, #1]
    802087d8:	5a9fa07c 	csinv	w28, w3, wzr, ge	// ge = tcont
    802087dc:	aa0203f9 	mov	x25, x2
    802087e0:	17fff9da 	b	80206f48 <_vfiprintf_r+0x238>
    802087e4:	f94043e2 	ldr	x2, [sp, #128]
    802087e8:	b940c3e0 	ldr	w0, [sp, #192]
    802087ec:	b900c3e1 	str	w1, [sp, #192]
    802087f0:	8b20c040 	add	x0, x2, w0, sxtw
    802087f4:	17fffca0 	b	80207a74 <_vfiprintf_r+0xd64>
    802087f8:	b940c3e0 	ldr	w0, [sp, #192]
    802087fc:	11002000 	add	w0, w0, #0x8
    80208800:	7100001f 	cmp	w0, #0x0
    80208804:	54fffdcc 	b.gt	802087bc <_vfiprintf_r+0x1aac>
    80208808:	f94043e4 	ldr	x4, [sp, #128]
    8020880c:	aa1703e1 	mov	x1, x23
    80208810:	b940c3e3 	ldr	w3, [sp, #192]
    80208814:	8b23c097 	add	x23, x4, w3, sxtw
    80208818:	17ffffeb 	b	802087c4 <_vfiprintf_r+0x1ab4>
    8020881c:	f94043e4 	ldr	x4, [sp, #128]
    80208820:	b940c3e1 	ldr	w1, [sp, #192]
    80208824:	b900c3e2 	str	w2, [sp, #192]
    80208828:	8b21c081 	add	x1, x4, w1, sxtw
    8020882c:	39400021 	ldrb	w1, [x1]
    80208830:	17fffd8a 	b	80207e58 <_vfiprintf_r+0x1148>
    80208834:	f94043e2 	ldr	x2, [sp, #128]
    80208838:	b940c3e0 	ldr	w0, [sp, #192]
    8020883c:	b900c3e1 	str	w1, [sp, #192]
    80208840:	8b20c040 	add	x0, x2, w0, sxtw
    80208844:	17fffea1 	b	802082c8 <_vfiprintf_r+0x15b8>
    80208848:	f94043e4 	ldr	x4, [sp, #128]
    8020884c:	b940c3e1 	ldr	w1, [sp, #192]
    80208850:	b900c3e2 	str	w2, [sp, #192]
    80208854:	8b21c081 	add	x1, x4, w1, sxtw
    80208858:	b9400021 	ldr	w1, [x1]
    8020885c:	17fffd7f 	b	80207e58 <_vfiprintf_r+0x1148>
    80208860:	79c022a0 	ldrsh	w0, [x21, #16]
    80208864:	321a0000 	orr	w0, w0, #0x40
    80208868:	790022a0 	strh	w0, [x21, #16]
    8020886c:	17fff9cb 	b	80206f98 <_vfiprintf_r+0x288>
    80208870:	f94043e2 	ldr	x2, [sp, #128]
    80208874:	b940c3e0 	ldr	w0, [sp, #192]
    80208878:	b900c3e1 	str	w1, [sp, #192]
    8020887c:	8b20c040 	add	x0, x2, w0, sxtw
    80208880:	17fffe2c 	b	80208130 <_vfiprintf_r+0x1420>
    80208884:	f94043e2 	ldr	x2, [sp, #128]
    80208888:	b940c3e0 	ldr	w0, [sp, #192]
    8020888c:	b900c3e1 	str	w1, [sp, #192]
    80208890:	8b20c040 	add	x0, x2, w0, sxtw
    80208894:	17fffeab 	b	80208340 <_vfiprintf_r+0x1630>
    80208898:	f94043e2 	ldr	x2, [sp, #128]
    8020889c:	b940c3e0 	ldr	w0, [sp, #192]
    802088a0:	b900c3e1 	str	w1, [sp, #192]
    802088a4:	8b20c040 	add	x0, x2, w0, sxtw
    802088a8:	17fffe90 	b	802082e8 <_vfiprintf_r+0x15d8>
    802088ac:	f94043e2 	ldr	x2, [sp, #128]
    802088b0:	b940c3e0 	ldr	w0, [sp, #192]
    802088b4:	b900c3e1 	str	w1, [sp, #192]
    802088b8:	8b20c040 	add	x0, x2, w0, sxtw
    802088bc:	39400001 	ldrb	w1, [x0]
    802088c0:	17fffc26 	b	80207958 <_vfiprintf_r+0xc48>
    802088c4:	f94043e2 	ldr	x2, [sp, #128]
    802088c8:	b940c3e0 	ldr	w0, [sp, #192]
    802088cc:	b900c3e1 	str	w1, [sp, #192]
    802088d0:	8b20c040 	add	x0, x2, w0, sxtw
    802088d4:	17fffe3c 	b	802081c4 <_vfiprintf_r+0x14b4>
    802088d8:	f94043e2 	ldr	x2, [sp, #128]
    802088dc:	b940c3e0 	ldr	w0, [sp, #192]
    802088e0:	b900c3e1 	str	w1, [sp, #192]
    802088e4:	8b20c040 	add	x0, x2, w0, sxtw
    802088e8:	b9400001 	ldr	w1, [x0]
    802088ec:	17fffc1b 	b	80207958 <_vfiprintf_r+0xc48>
    802088f0:	f94043e2 	ldr	x2, [sp, #128]
    802088f4:	b940c3e0 	ldr	w0, [sp, #192]
    802088f8:	b900c3e1 	str	w1, [sp, #192]
    802088fc:	8b20c040 	add	x0, x2, w0, sxtw
    80208900:	17ffff65 	b	80208694 <_vfiprintf_r+0x1984>
    80208904:	794022a0 	ldrh	w0, [x21, #16]
    80208908:	321a0000 	orr	w0, w0, #0x40
    8020890c:	790022a0 	strh	w0, [x21, #16]
    80208910:	17fff99c 	b	80206f80 <_vfiprintf_r+0x270>
	...

0000000080208920 <vfiprintf>:
    80208920:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80208924:	b0000044 	adrp	x4, 80211000 <__mprec_tens+0x180>
    80208928:	aa0003e3 	mov	x3, x0
    8020892c:	910003fd 	mov	x29, sp
    80208930:	ad400440 	ldp	q0, q1, [x2]
    80208934:	aa0103e2 	mov	x2, x1
    80208938:	f9402480 	ldr	x0, [x4, #72]
    8020893c:	aa0303e1 	mov	x1, x3
    80208940:	910043e3 	add	x3, sp, #0x10
    80208944:	ad0087e0 	stp	q0, q1, [sp, #16]
    80208948:	97fff8f2 	bl	80206d10 <_vfiprintf_r>
    8020894c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80208950:	d65f03c0 	ret
	...

0000000080208960 <__sbprintf>:
    80208960:	d11443ff 	sub	sp, sp, #0x510
    80208964:	a9007bfd 	stp	x29, x30, [sp]
    80208968:	910003fd 	mov	x29, sp
    8020896c:	a90153f3 	stp	x19, x20, [sp, #16]
    80208970:	aa0103f3 	mov	x19, x1
    80208974:	79402021 	ldrh	w1, [x1, #16]
    80208978:	aa0303f4 	mov	x20, x3
    8020897c:	910443e3 	add	x3, sp, #0x110
    80208980:	f9401a66 	ldr	x6, [x19, #48]
    80208984:	121e7821 	and	w1, w1, #0xfffffffd
    80208988:	f9402265 	ldr	x5, [x19, #64]
    8020898c:	a9025bf5 	stp	x21, x22, [sp, #32]
    80208990:	79402667 	ldrh	w7, [x19, #18]
    80208994:	b940b264 	ldr	w4, [x19, #176]
    80208998:	aa0203f6 	mov	x22, x2
    8020899c:	52808002 	mov	w2, #0x400                 	// #1024
    802089a0:	aa0003f5 	mov	x21, x0
    802089a4:	9103e3e0 	add	x0, sp, #0xf8
    802089a8:	f9002fe3 	str	x3, [sp, #88]
    802089ac:	b90067e2 	str	w2, [sp, #100]
    802089b0:	7900d3e1 	strh	w1, [sp, #104]
    802089b4:	7900d7e7 	strh	w7, [sp, #106]
    802089b8:	f9003be3 	str	x3, [sp, #112]
    802089bc:	b9007be2 	str	w2, [sp, #120]
    802089c0:	b90083ff 	str	wzr, [sp, #128]
    802089c4:	f90047e6 	str	x6, [sp, #136]
    802089c8:	f9004fe5 	str	x5, [sp, #152]
    802089cc:	b9010be4 	str	w4, [sp, #264]
    802089d0:	9400026c 	bl	80209380 <__retarget_lock_init_recursive>
    802089d4:	ad400680 	ldp	q0, q1, [x20]
    802089d8:	aa1603e2 	mov	x2, x22
    802089dc:	9100c3e3 	add	x3, sp, #0x30
    802089e0:	910163e1 	add	x1, sp, #0x58
    802089e4:	aa1503e0 	mov	x0, x21
    802089e8:	ad0187e0 	stp	q0, q1, [sp, #48]
    802089ec:	97fff8c9 	bl	80206d10 <_vfiprintf_r>
    802089f0:	2a0003f4 	mov	w20, w0
    802089f4:	37f800c0 	tbnz	w0, #31, 80208a0c <__sbprintf+0xac>
    802089f8:	910163e1 	add	x1, sp, #0x58
    802089fc:	aa1503e0 	mov	x0, x21
    80208a00:	94000d5c 	bl	8020bf70 <_fflush_r>
    80208a04:	7100001f 	cmp	w0, #0x0
    80208a08:	5a9f0294 	csinv	w20, w20, wzr, eq	// eq = none
    80208a0c:	7940d3e0 	ldrh	w0, [sp, #104]
    80208a10:	36300080 	tbz	w0, #6, 80208a20 <__sbprintf+0xc0>
    80208a14:	79402260 	ldrh	w0, [x19, #16]
    80208a18:	321a0000 	orr	w0, w0, #0x40
    80208a1c:	79002260 	strh	w0, [x19, #16]
    80208a20:	f9407fe0 	ldr	x0, [sp, #248]
    80208a24:	9400025f 	bl	802093a0 <__retarget_lock_close_recursive>
    80208a28:	a9407bfd 	ldp	x29, x30, [sp]
    80208a2c:	2a1403e0 	mov	w0, w20
    80208a30:	a94153f3 	ldp	x19, x20, [sp, #16]
    80208a34:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80208a38:	911443ff 	add	sp, sp, #0x510
    80208a3c:	d65f03c0 	ret

0000000080208a40 <_malloc_r>:
    80208a40:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    80208a44:	910003fd 	mov	x29, sp
    80208a48:	a90153f3 	stp	x19, x20, [sp, #16]
    80208a4c:	91005c34 	add	x20, x1, #0x17
    80208a50:	a9025bf5 	stp	x21, x22, [sp, #32]
    80208a54:	aa0003f5 	mov	x21, x0
    80208a58:	f100ba9f 	cmp	x20, #0x2e
    80208a5c:	54000ca8 	b.hi	80208bf0 <_malloc_r+0x1b0>  // b.pmore
    80208a60:	f100803f 	cmp	x1, #0x20
    80208a64:	54001988 	b.hi	80208d94 <_malloc_r+0x354>  // b.pmore
    80208a68:	94000792 	bl	8020a8b0 <__malloc_lock>
    80208a6c:	d2800414 	mov	x20, #0x20                  	// #32
    80208a70:	d2800a01 	mov	x1, #0x50                  	// #80
    80208a74:	52800080 	mov	w0, #0x4                   	// #4
    80208a78:	b0000056 	adrp	x22, 80211000 <__mprec_tens+0x180>
    80208a7c:	910742d6 	add	x22, x22, #0x1d0
    80208a80:	8b0102c1 	add	x1, x22, x1
    80208a84:	11000800 	add	w0, w0, #0x2
    80208a88:	d1004021 	sub	x1, x1, #0x10
    80208a8c:	f9400c33 	ldr	x19, [x1, #24]
    80208a90:	eb01027f 	cmp	x19, x1
    80208a94:	54001dc1 	b.ne	80208e4c <_malloc_r+0x40c>  // b.any
    80208a98:	f94012d3 	ldr	x19, [x22, #32]
    80208a9c:	b0000046 	adrp	x6, 80211000 <__mprec_tens+0x180>
    80208aa0:	910780c6 	add	x6, x6, #0x1e0
    80208aa4:	eb06027f 	cmp	x19, x6
    80208aa8:	54000f60 	b.eq	80208c94 <_malloc_r+0x254>  // b.none
    80208aac:	f9400661 	ldr	x1, [x19, #8]
    80208ab0:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    80208ab4:	cb140022 	sub	x2, x1, x20
    80208ab8:	f1007c5f 	cmp	x2, #0x1f
    80208abc:	540027ac 	b.gt	80208fb0 <_malloc_r+0x570>
    80208ac0:	a9021ac6 	stp	x6, x6, [x22, #32]
    80208ac4:	b6f81782 	tbz	x2, #63, 80208db4 <_malloc_r+0x374>
    80208ac8:	f94006c5 	ldr	x5, [x22, #8]
    80208acc:	f107fc3f 	cmp	x1, #0x1ff
    80208ad0:	54001ec8 	b.hi	80208ea8 <_malloc_r+0x468>  // b.pmore
    80208ad4:	d343fc22 	lsr	x2, x1, #3
    80208ad8:	d2800023 	mov	x3, #0x1                   	// #1
    80208adc:	11000441 	add	w1, w2, #0x1
    80208ae0:	13027c42 	asr	w2, w2, #2
    80208ae4:	531f7821 	lsl	w1, w1, #1
    80208ae8:	9ac22062 	lsl	x2, x3, x2
    80208aec:	aa0200a5 	orr	x5, x5, x2
    80208af0:	8b21cec1 	add	x1, x22, w1, sxtw #3
    80208af4:	f85f0422 	ldr	x2, [x1], #-16
    80208af8:	f90006c5 	str	x5, [x22, #8]
    80208afc:	a9010662 	stp	x2, x1, [x19, #16]
    80208b00:	f9000833 	str	x19, [x1, #16]
    80208b04:	f9000c53 	str	x19, [x2, #24]
    80208b08:	13027c01 	asr	w1, w0, #2
    80208b0c:	d2800024 	mov	x4, #0x1                   	// #1
    80208b10:	9ac12084 	lsl	x4, x4, x1
    80208b14:	eb05009f 	cmp	x4, x5
    80208b18:	54000ca8 	b.hi	80208cac <_malloc_r+0x26c>  // b.pmore
    80208b1c:	ea05009f 	tst	x4, x5
    80208b20:	540000c1 	b.ne	80208b38 <_malloc_r+0xf8>  // b.any
    80208b24:	121e7400 	and	w0, w0, #0xfffffffc
    80208b28:	d37ff884 	lsl	x4, x4, #1
    80208b2c:	11001000 	add	w0, w0, #0x4
    80208b30:	ea05009f 	tst	x4, x5
    80208b34:	54ffffa0 	b.eq	80208b28 <_malloc_r+0xe8>  // b.none
    80208b38:	928001e9 	mov	x9, #0xfffffffffffffff0    	// #-16
    80208b3c:	11000407 	add	w7, w0, #0x1
    80208b40:	2a0003e8 	mov	w8, w0
    80208b44:	531f78e7 	lsl	w7, w7, #1
    80208b48:	8b27cd27 	add	x7, x9, w7, sxtw #3
    80208b4c:	8b0702c7 	add	x7, x22, x7
    80208b50:	aa0703e5 	mov	x5, x7
    80208b54:	f9400ca1 	ldr	x1, [x5, #24]
    80208b58:	14000009 	b	80208b7c <_malloc_r+0x13c>
    80208b5c:	f9400422 	ldr	x2, [x1, #8]
    80208b60:	aa0103f3 	mov	x19, x1
    80208b64:	f9400c21 	ldr	x1, [x1, #24]
    80208b68:	927ef442 	and	x2, x2, #0xfffffffffffffffc
    80208b6c:	cb140043 	sub	x3, x2, x20
    80208b70:	f1007c7f 	cmp	x3, #0x1f
    80208b74:	54001e2c 	b.gt	80208f38 <_malloc_r+0x4f8>
    80208b78:	b6f81fe3 	tbz	x3, #63, 80208f74 <_malloc_r+0x534>
    80208b7c:	eb0100bf 	cmp	x5, x1
    80208b80:	54fffee1 	b.ne	80208b5c <_malloc_r+0x11c>  // b.any
    80208b84:	7100f91f 	cmp	w8, #0x3e
    80208b88:	5400242d 	b.le	8020900c <_malloc_r+0x5cc>
    80208b8c:	910040a5 	add	x5, x5, #0x10
    80208b90:	11000508 	add	w8, w8, #0x1
    80208b94:	f240051f 	tst	x8, #0x3
    80208b98:	54fffde1 	b.ne	80208b54 <_malloc_r+0x114>  // b.any
    80208b9c:	14000005 	b	80208bb0 <_malloc_r+0x170>
    80208ba0:	f85f04e1 	ldr	x1, [x7], #-16
    80208ba4:	51000400 	sub	w0, w0, #0x1
    80208ba8:	eb07003f 	cmp	x1, x7
    80208bac:	54003401 	b.ne	8020922c <_malloc_r+0x7ec>  // b.any
    80208bb0:	f240041f 	tst	x0, #0x3
    80208bb4:	54ffff61 	b.ne	80208ba0 <_malloc_r+0x160>  // b.any
    80208bb8:	f94006c0 	ldr	x0, [x22, #8]
    80208bbc:	8a240000 	bic	x0, x0, x4
    80208bc0:	f90006c0 	str	x0, [x22, #8]
    80208bc4:	d37ff884 	lsl	x4, x4, #1
    80208bc8:	d1000481 	sub	x1, x4, #0x1
    80208bcc:	eb00003f 	cmp	x1, x0
    80208bd0:	54000083 	b.cc	80208be0 <_malloc_r+0x1a0>  // b.lo, b.ul, b.last
    80208bd4:	14000036 	b	80208cac <_malloc_r+0x26c>
    80208bd8:	d37ff884 	lsl	x4, x4, #1
    80208bdc:	11001108 	add	w8, w8, #0x4
    80208be0:	ea00009f 	tst	x4, x0
    80208be4:	54ffffa0 	b.eq	80208bd8 <_malloc_r+0x198>  // b.none
    80208be8:	2a0803e0 	mov	w0, w8
    80208bec:	17ffffd4 	b	80208b3c <_malloc_r+0xfc>
    80208bf0:	927cee94 	and	x20, x20, #0xfffffffffffffff0
    80208bf4:	b2407be2 	mov	x2, #0x7fffffff            	// #2147483647
    80208bf8:	eb02029f 	cmp	x20, x2
    80208bfc:	fa549022 	ccmp	x1, x20, #0x2, ls	// ls = plast
    80208c00:	54000ca8 	b.hi	80208d94 <_malloc_r+0x354>  // b.pmore
    80208c04:	9400072b 	bl	8020a8b0 <__malloc_lock>
    80208c08:	f107de9f 	cmp	x20, #0x1f7
    80208c0c:	54001c89 	b.ls	80208f9c <_malloc_r+0x55c>  // b.plast
    80208c10:	d349fe81 	lsr	x1, x20, #9
    80208c14:	b4000c81 	cbz	x1, 80208da4 <_malloc_r+0x364>
    80208c18:	f100103f 	cmp	x1, #0x4
    80208c1c:	540017a8 	b.hi	80208f10 <_malloc_r+0x4d0>  // b.pmore
    80208c20:	d346fe81 	lsr	x1, x20, #6
    80208c24:	1100e420 	add	w0, w1, #0x39
    80208c28:	1100e025 	add	w5, w1, #0x38
    80208c2c:	531f7804 	lsl	w4, w0, #1
    80208c30:	937d7c84 	sbfiz	x4, x4, #3, #32
    80208c34:	b0000056 	adrp	x22, 80211000 <__mprec_tens+0x180>
    80208c38:	910742d6 	add	x22, x22, #0x1d0
    80208c3c:	8b0402c4 	add	x4, x22, x4
    80208c40:	d1004084 	sub	x4, x4, #0x10
    80208c44:	f9400c93 	ldr	x19, [x4, #24]
    80208c48:	eb13009f 	cmp	x4, x19
    80208c4c:	540000e1 	b.ne	80208c68 <_malloc_r+0x228>  // b.any
    80208c50:	17ffff92 	b	80208a98 <_malloc_r+0x58>
    80208c54:	f9400e63 	ldr	x3, [x19, #24]
    80208c58:	b6f811c2 	tbz	x2, #63, 80208e90 <_malloc_r+0x450>
    80208c5c:	aa0303f3 	mov	x19, x3
    80208c60:	eb03009f 	cmp	x4, x3
    80208c64:	54fff1a0 	b.eq	80208a98 <_malloc_r+0x58>  // b.none
    80208c68:	f9400661 	ldr	x1, [x19, #8]
    80208c6c:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    80208c70:	cb140022 	sub	x2, x1, x20
    80208c74:	f1007c5f 	cmp	x2, #0x1f
    80208c78:	54fffeed 	b.le	80208c54 <_malloc_r+0x214>
    80208c7c:	f94012d3 	ldr	x19, [x22, #32]
    80208c80:	b0000046 	adrp	x6, 80211000 <__mprec_tens+0x180>
    80208c84:	910780c6 	add	x6, x6, #0x1e0
    80208c88:	2a0503e0 	mov	w0, w5
    80208c8c:	eb06027f 	cmp	x19, x6
    80208c90:	54fff0e1 	b.ne	80208aac <_malloc_r+0x6c>  // b.any
    80208c94:	f94006c5 	ldr	x5, [x22, #8]
    80208c98:	13027c01 	asr	w1, w0, #2
    80208c9c:	d2800024 	mov	x4, #0x1                   	// #1
    80208ca0:	9ac12084 	lsl	x4, x4, x1
    80208ca4:	eb05009f 	cmp	x4, x5
    80208ca8:	54fff3a9 	b.ls	80208b1c <_malloc_r+0xdc>  // b.plast
    80208cac:	f9400ad3 	ldr	x19, [x22, #16]
    80208cb0:	a90363f7 	stp	x23, x24, [sp, #48]
    80208cb4:	f9400677 	ldr	x23, [x19, #8]
    80208cb8:	927ef6f7 	and	x23, x23, #0xfffffffffffffffc
    80208cbc:	cb1402e0 	sub	x0, x23, x20
    80208cc0:	f1007c1f 	cmp	x0, #0x1f
    80208cc4:	fa54c2e0 	ccmp	x23, x20, #0x0, gt
    80208cc8:	54000a42 	b.cs	80208e10 <_malloc_r+0x3d0>  // b.hs, b.nlast
    80208ccc:	900003c1 	adrp	x1, 80280000 <gits_lock>
    80208cd0:	a90573fb 	stp	x27, x28, [sp, #80]
    80208cd4:	b000005c 	adrp	x28, 80211000 <__mprec_tens+0x180>
    80208cd8:	f9413c21 	ldr	x1, [x1, #632]
    80208cdc:	d28203e3 	mov	x3, #0x101f                	// #4127
    80208ce0:	f940e382 	ldr	x2, [x28, #448]
    80208ce4:	8b010281 	add	x1, x20, x1
    80208ce8:	8b030038 	add	x24, x1, x3
    80208cec:	91008021 	add	x1, x1, #0x20
    80208cf0:	b100045f 	cmn	x2, #0x1
    80208cf4:	9274cf18 	and	x24, x24, #0xfffffffffffff000
    80208cf8:	9a811318 	csel	x24, x24, x1, ne	// ne = any
    80208cfc:	aa1503e0 	mov	x0, x21
    80208d00:	aa1803e1 	mov	x1, x24
    80208d04:	8b17027b 	add	x27, x19, x23
    80208d08:	a9046bf9 	stp	x25, x26, [sp, #64]
    80208d0c:	9400133d 	bl	8020da00 <_sbrk_r>
    80208d10:	aa0003f9 	mov	x25, x0
    80208d14:	b100041f 	cmn	x0, #0x1
    80208d18:	540006a0 	b.eq	80208dec <_malloc_r+0x3ac>  // b.none
    80208d1c:	eb00037f 	cmp	x27, x0
    80208d20:	54000628 	b.hi	80208de4 <_malloc_r+0x3a4>  // b.pmore
    80208d24:	900003da 	adrp	x26, 80280000 <gits_lock>
    80208d28:	b9424341 	ldr	w1, [x26, #576]
    80208d2c:	0b180021 	add	w1, w1, w24
    80208d30:	b9024341 	str	w1, [x26, #576]
    80208d34:	2a0103e0 	mov	w0, w1
    80208d38:	54001781 	b.ne	80209028 <_malloc_r+0x5e8>  // b.any
    80208d3c:	f2402f7f 	tst	x27, #0xfff
    80208d40:	54001741 	b.ne	80209028 <_malloc_r+0x5e8>  // b.any
    80208d44:	f9400ac2 	ldr	x2, [x22, #16]
    80208d48:	8b1802e0 	add	x0, x23, x24
    80208d4c:	b2400000 	orr	x0, x0, #0x1
    80208d50:	f9000440 	str	x0, [x2, #8]
    80208d54:	d503201f 	nop
    80208d58:	900003c0 	adrp	x0, 80280000 <gits_lock>
    80208d5c:	93407c21 	sxtw	x1, w1
    80208d60:	f9413802 	ldr	x2, [x0, #624]
    80208d64:	eb02003f 	cmp	x1, x2
    80208d68:	54000049 	b.ls	80208d70 <_malloc_r+0x330>  // b.plast
    80208d6c:	f9013801 	str	x1, [x0, #624]
    80208d70:	900003c0 	adrp	x0, 80280000 <gits_lock>
    80208d74:	f9400ad3 	ldr	x19, [x22, #16]
    80208d78:	f9413402 	ldr	x2, [x0, #616]
    80208d7c:	eb02003f 	cmp	x1, x2
    80208d80:	54000049 	b.ls	80208d88 <_malloc_r+0x348>  // b.plast
    80208d84:	f9013401 	str	x1, [x0, #616]
    80208d88:	f9400660 	ldr	x0, [x19, #8]
    80208d8c:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    80208d90:	1400001a 	b	80208df8 <_malloc_r+0x3b8>
    80208d94:	52800180 	mov	w0, #0xc                   	// #12
    80208d98:	d2800013 	mov	x19, #0x0                   	// #0
    80208d9c:	b90002a0 	str	w0, [x21]
    80208da0:	1400000c 	b	80208dd0 <_malloc_r+0x390>
    80208da4:	d2808004 	mov	x4, #0x400                 	// #1024
    80208da8:	52800800 	mov	w0, #0x40                  	// #64
    80208dac:	528007e5 	mov	w5, #0x3f                  	// #63
    80208db0:	17ffffa1 	b	80208c34 <_malloc_r+0x1f4>
    80208db4:	8b010261 	add	x1, x19, x1
    80208db8:	aa1503e0 	mov	x0, x21
    80208dbc:	91004273 	add	x19, x19, #0x10
    80208dc0:	f9400422 	ldr	x2, [x1, #8]
    80208dc4:	b2400042 	orr	x2, x2, #0x1
    80208dc8:	f9000422 	str	x2, [x1, #8]
    80208dcc:	940006bd 	bl	8020a8c0 <__malloc_unlock>
    80208dd0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80208dd4:	aa1303e0 	mov	x0, x19
    80208dd8:	a94153f3 	ldp	x19, x20, [sp, #16]
    80208ddc:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80208de0:	d65f03c0 	ret
    80208de4:	eb16027f 	cmp	x19, x22
    80208de8:	54001180 	b.eq	80209018 <_malloc_r+0x5d8>  // b.none
    80208dec:	f9400ad3 	ldr	x19, [x22, #16]
    80208df0:	f9400660 	ldr	x0, [x19, #8]
    80208df4:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    80208df8:	eb00029f 	cmp	x20, x0
    80208dfc:	cb140000 	sub	x0, x0, x20
    80208e00:	fa5f9804 	ccmp	x0, #0x1f, #0x4, ls	// ls = plast
    80208e04:	540019ad 	b.le	80209138 <_malloc_r+0x6f8>
    80208e08:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80208e0c:	a94573fb 	ldp	x27, x28, [sp, #80]
    80208e10:	8b140262 	add	x2, x19, x20
    80208e14:	b2400294 	orr	x20, x20, #0x1
    80208e18:	f9000674 	str	x20, [x19, #8]
    80208e1c:	b2400001 	orr	x1, x0, #0x1
    80208e20:	f9000ac2 	str	x2, [x22, #16]
    80208e24:	f9000441 	str	x1, [x2, #8]
    80208e28:	aa1503e0 	mov	x0, x21
    80208e2c:	91004273 	add	x19, x19, #0x10
    80208e30:	940006a4 	bl	8020a8c0 <__malloc_unlock>
    80208e34:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80208e38:	aa1303e0 	mov	x0, x19
    80208e3c:	a94153f3 	ldp	x19, x20, [sp, #16]
    80208e40:	a94363f7 	ldp	x23, x24, [sp, #48]
    80208e44:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80208e48:	d65f03c0 	ret
    80208e4c:	a9409261 	ldp	x1, x4, [x19, #8]
    80208e50:	aa1503e0 	mov	x0, x21
    80208e54:	f9400e63 	ldr	x3, [x19, #24]
    80208e58:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    80208e5c:	8b010261 	add	x1, x19, x1
    80208e60:	f9400422 	ldr	x2, [x1, #8]
    80208e64:	f9000c83 	str	x3, [x4, #24]
    80208e68:	b2400042 	orr	x2, x2, #0x1
    80208e6c:	f9000864 	str	x4, [x3, #16]
    80208e70:	f9000422 	str	x2, [x1, #8]
    80208e74:	91004273 	add	x19, x19, #0x10
    80208e78:	94000692 	bl	8020a8c0 <__malloc_unlock>
    80208e7c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80208e80:	aa1303e0 	mov	x0, x19
    80208e84:	a94153f3 	ldp	x19, x20, [sp, #16]
    80208e88:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80208e8c:	d65f03c0 	ret
    80208e90:	f9400a64 	ldr	x4, [x19, #16]
    80208e94:	8b010261 	add	x1, x19, x1
    80208e98:	aa1503e0 	mov	x0, x21
    80208e9c:	f9400422 	ldr	x2, [x1, #8]
    80208ea0:	f9000c83 	str	x3, [x4, #24]
    80208ea4:	17fffff1 	b	80208e68 <_malloc_r+0x428>
    80208ea8:	d349fc22 	lsr	x2, x1, #9
    80208eac:	f127fc3f 	cmp	x1, #0x9ff
    80208eb0:	54000989 	b.ls	80208fe0 <_malloc_r+0x5a0>  // b.plast
    80208eb4:	f100505f 	cmp	x2, #0x14
    80208eb8:	540014e8 	b.hi	80209154 <_malloc_r+0x714>  // b.pmore
    80208ebc:	11017044 	add	w4, w2, #0x5c
    80208ec0:	11016c43 	add	w3, w2, #0x5b
    80208ec4:	531f7884 	lsl	w4, w4, #1
    80208ec8:	937d7c84 	sbfiz	x4, x4, #3, #32
    80208ecc:	8b0402c4 	add	x4, x22, x4
    80208ed0:	f85f0482 	ldr	x2, [x4], #-16
    80208ed4:	eb02009f 	cmp	x4, x2
    80208ed8:	540000a1 	b.ne	80208eec <_malloc_r+0x4ac>  // b.any
    80208edc:	14000085 	b	802090f0 <_malloc_r+0x6b0>
    80208ee0:	f9400842 	ldr	x2, [x2, #16]
    80208ee4:	eb02009f 	cmp	x4, x2
    80208ee8:	540000a0 	b.eq	80208efc <_malloc_r+0x4bc>  // b.none
    80208eec:	f9400443 	ldr	x3, [x2, #8]
    80208ef0:	927ef463 	and	x3, x3, #0xfffffffffffffffc
    80208ef4:	eb01007f 	cmp	x3, x1
    80208ef8:	54ffff48 	b.hi	80208ee0 <_malloc_r+0x4a0>  // b.pmore
    80208efc:	f9400c44 	ldr	x4, [x2, #24]
    80208f00:	a9011262 	stp	x2, x4, [x19, #16]
    80208f04:	f9000893 	str	x19, [x4, #16]
    80208f08:	f9000c53 	str	x19, [x2, #24]
    80208f0c:	17fffeff 	b	80208b08 <_malloc_r+0xc8>
    80208f10:	f100503f 	cmp	x1, #0x14
    80208f14:	54000729 	b.ls	80208ff8 <_malloc_r+0x5b8>  // b.plast
    80208f18:	f101503f 	cmp	x1, #0x54
    80208f1c:	540012c8 	b.hi	80209174 <_malloc_r+0x734>  // b.pmore
    80208f20:	d34cfe81 	lsr	x1, x20, #12
    80208f24:	1101bc20 	add	w0, w1, #0x6f
    80208f28:	1101b825 	add	w5, w1, #0x6e
    80208f2c:	531f7804 	lsl	w4, w0, #1
    80208f30:	937d7c84 	sbfiz	x4, x4, #3, #32
    80208f34:	17ffff40 	b	80208c34 <_malloc_r+0x1f4>
    80208f38:	f9400a64 	ldr	x4, [x19, #16]
    80208f3c:	b2400280 	orr	x0, x20, #0x1
    80208f40:	f9000660 	str	x0, [x19, #8]
    80208f44:	8b140274 	add	x20, x19, x20
    80208f48:	b2400065 	orr	x5, x3, #0x1
    80208f4c:	aa1503e0 	mov	x0, x21
    80208f50:	f9000c81 	str	x1, [x4, #24]
    80208f54:	f9000824 	str	x4, [x1, #16]
    80208f58:	a90252d4 	stp	x20, x20, [x22, #32]
    80208f5c:	a9009a85 	stp	x5, x6, [x20, #8]
    80208f60:	f9000e86 	str	x6, [x20, #24]
    80208f64:	f8226a63 	str	x3, [x19, x2]
    80208f68:	91004273 	add	x19, x19, #0x10
    80208f6c:	94000655 	bl	8020a8c0 <__malloc_unlock>
    80208f70:	17ffff98 	b	80208dd0 <_malloc_r+0x390>
    80208f74:	8b020262 	add	x2, x19, x2
    80208f78:	aa1503e0 	mov	x0, x21
    80208f7c:	f8410e64 	ldr	x4, [x19, #16]!
    80208f80:	f9400443 	ldr	x3, [x2, #8]
    80208f84:	b2400063 	orr	x3, x3, #0x1
    80208f88:	f9000443 	str	x3, [x2, #8]
    80208f8c:	f9000c81 	str	x1, [x4, #24]
    80208f90:	f9000824 	str	x4, [x1, #16]
    80208f94:	9400064b 	bl	8020a8c0 <__malloc_unlock>
    80208f98:	17ffff8e 	b	80208dd0 <_malloc_r+0x390>
    80208f9c:	d343fe80 	lsr	x0, x20, #3
    80208fa0:	11000401 	add	w1, w0, #0x1
    80208fa4:	531f7821 	lsl	w1, w1, #1
    80208fa8:	937d7c21 	sbfiz	x1, x1, #3, #32
    80208fac:	17fffeb3 	b	80208a78 <_malloc_r+0x38>
    80208fb0:	8b140263 	add	x3, x19, x20
    80208fb4:	b2400294 	orr	x20, x20, #0x1
    80208fb8:	f9000674 	str	x20, [x19, #8]
    80208fbc:	b2400044 	orr	x4, x2, #0x1
    80208fc0:	a9020ec3 	stp	x3, x3, [x22, #32]
    80208fc4:	aa1503e0 	mov	x0, x21
    80208fc8:	a9009864 	stp	x4, x6, [x3, #8]
    80208fcc:	f9000c66 	str	x6, [x3, #24]
    80208fd0:	f8216a62 	str	x2, [x19, x1]
    80208fd4:	91004273 	add	x19, x19, #0x10
    80208fd8:	9400063a 	bl	8020a8c0 <__malloc_unlock>
    80208fdc:	17ffff7d 	b	80208dd0 <_malloc_r+0x390>
    80208fe0:	d346fc22 	lsr	x2, x1, #6
    80208fe4:	1100e444 	add	w4, w2, #0x39
    80208fe8:	1100e043 	add	w3, w2, #0x38
    80208fec:	531f7884 	lsl	w4, w4, #1
    80208ff0:	937d7c84 	sbfiz	x4, x4, #3, #32
    80208ff4:	17ffffb6 	b	80208ecc <_malloc_r+0x48c>
    80208ff8:	11017020 	add	w0, w1, #0x5c
    80208ffc:	11016c25 	add	w5, w1, #0x5b
    80209000:	531f7804 	lsl	w4, w0, #1
    80209004:	937d7c84 	sbfiz	x4, x4, #3, #32
    80209008:	17ffff0b 	b	80208c34 <_malloc_r+0x1f4>
    8020900c:	11000508 	add	w8, w8, #0x1
    80209010:	910080a5 	add	x5, x5, #0x20
    80209014:	17fffedf 	b	80208b90 <_malloc_r+0x150>
    80209018:	f00003ba 	adrp	x26, 80280000 <gits_lock>
    8020901c:	b9424340 	ldr	w0, [x26, #576]
    80209020:	0b180000 	add	w0, w0, w24
    80209024:	b9024340 	str	w0, [x26, #576]
    80209028:	f940e381 	ldr	x1, [x28, #448]
    8020902c:	b100043f 	cmn	x1, #0x1
    80209030:	54000b20 	b.eq	80209194 <_malloc_r+0x754>  // b.none
    80209034:	cb1b033b 	sub	x27, x25, x27
    80209038:	0b1b0000 	add	w0, w0, w27
    8020903c:	b9024340 	str	w0, [x26, #576]
    80209040:	f2400f3c 	ands	x28, x25, #0xf
    80209044:	54000620 	b.eq	80209108 <_malloc_r+0x6c8>  // b.none
    80209048:	cb1c0339 	sub	x25, x25, x28
    8020904c:	d282021b 	mov	x27, #0x1010                	// #4112
    80209050:	91004339 	add	x25, x25, #0x10
    80209054:	cb1c037b 	sub	x27, x27, x28
    80209058:	8b180338 	add	x24, x25, x24
    8020905c:	aa1503e0 	mov	x0, x21
    80209060:	cb18037b 	sub	x27, x27, x24
    80209064:	92402f7b 	and	x27, x27, #0xfff
    80209068:	aa1b03e1 	mov	x1, x27
    8020906c:	94001265 	bl	8020da00 <_sbrk_r>
    80209070:	b100041f 	cmn	x0, #0x1
    80209074:	54000b40 	b.eq	802091dc <_malloc_r+0x79c>  // b.none
    80209078:	cb190000 	sub	x0, x0, x25
    8020907c:	2a1b03e2 	mov	w2, w27
    80209080:	8b1b0018 	add	x24, x0, x27
    80209084:	b9424340 	ldr	w0, [x26, #576]
    80209088:	b2400318 	orr	x24, x24, #0x1
    8020908c:	f9000ad9 	str	x25, [x22, #16]
    80209090:	0b000041 	add	w1, w2, w0
    80209094:	b9024341 	str	w1, [x26, #576]
    80209098:	f9000738 	str	x24, [x25, #8]
    8020909c:	eb16027f 	cmp	x19, x22
    802090a0:	54ffe5c0 	b.eq	80208d58 <_malloc_r+0x318>  // b.none
    802090a4:	f1007eff 	cmp	x23, #0x1f
    802090a8:	54000449 	b.ls	80209130 <_malloc_r+0x6f0>  // b.plast
    802090ac:	f9400662 	ldr	x2, [x19, #8]
    802090b0:	f0000023 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    802090b4:	d10062e0 	sub	x0, x23, #0x18
    802090b8:	3dc27460 	ldr	q0, [x3, #2512]
    802090bc:	927cec00 	and	x0, x0, #0xfffffffffffffff0
    802090c0:	8b000263 	add	x3, x19, x0
    802090c4:	92400042 	and	x2, x2, #0x1
    802090c8:	aa000042 	orr	x2, x2, x0
    802090cc:	f9000662 	str	x2, [x19, #8]
    802090d0:	3c808060 	stur	q0, [x3, #8]
    802090d4:	f1007c1f 	cmp	x0, #0x1f
    802090d8:	54ffe409 	b.ls	80208d58 <_malloc_r+0x318>  // b.plast
    802090dc:	91004261 	add	x1, x19, #0x10
    802090e0:	aa1503e0 	mov	x0, x21
    802090e4:	94000dc7 	bl	8020c800 <_free_r>
    802090e8:	b9424341 	ldr	w1, [x26, #576]
    802090ec:	17ffff1b 	b	80208d58 <_malloc_r+0x318>
    802090f0:	13027c63 	asr	w3, w3, #2
    802090f4:	d2800021 	mov	x1, #0x1                   	// #1
    802090f8:	9ac32021 	lsl	x1, x1, x3
    802090fc:	aa0100a5 	orr	x5, x5, x1
    80209100:	f90006c5 	str	x5, [x22, #8]
    80209104:	17ffff7f 	b	80208f00 <_malloc_r+0x4c0>
    80209108:	8b18033b 	add	x27, x25, x24
    8020910c:	aa1503e0 	mov	x0, x21
    80209110:	cb1b03fb 	neg	x27, x27
    80209114:	92402f7b 	and	x27, x27, #0xfff
    80209118:	aa1b03e1 	mov	x1, x27
    8020911c:	94001239 	bl	8020da00 <_sbrk_r>
    80209120:	52800002 	mov	w2, #0x0                   	// #0
    80209124:	b100041f 	cmn	x0, #0x1
    80209128:	54fffa81 	b.ne	80209078 <_malloc_r+0x638>  // b.any
    8020912c:	17ffffd6 	b	80209084 <_malloc_r+0x644>
    80209130:	d2800020 	mov	x0, #0x1                   	// #1
    80209134:	f9000720 	str	x0, [x25, #8]
    80209138:	aa1503e0 	mov	x0, x21
    8020913c:	d2800013 	mov	x19, #0x0                   	// #0
    80209140:	940005e0 	bl	8020a8c0 <__malloc_unlock>
    80209144:	a94363f7 	ldp	x23, x24, [sp, #48]
    80209148:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020914c:	a94573fb 	ldp	x27, x28, [sp, #80]
    80209150:	17ffff20 	b	80208dd0 <_malloc_r+0x390>
    80209154:	f101505f 	cmp	x2, #0x54
    80209158:	54000228 	b.hi	8020919c <_malloc_r+0x75c>  // b.pmore
    8020915c:	d34cfc22 	lsr	x2, x1, #12
    80209160:	1101bc44 	add	w4, w2, #0x6f
    80209164:	1101b843 	add	w3, w2, #0x6e
    80209168:	531f7884 	lsl	w4, w4, #1
    8020916c:	937d7c84 	sbfiz	x4, x4, #3, #32
    80209170:	17ffff57 	b	80208ecc <_malloc_r+0x48c>
    80209174:	f105503f 	cmp	x1, #0x154
    80209178:	54000228 	b.hi	802091bc <_malloc_r+0x77c>  // b.pmore
    8020917c:	d34ffe81 	lsr	x1, x20, #15
    80209180:	1101e020 	add	w0, w1, #0x78
    80209184:	1101dc25 	add	w5, w1, #0x77
    80209188:	531f7804 	lsl	w4, w0, #1
    8020918c:	937d7c84 	sbfiz	x4, x4, #3, #32
    80209190:	17fffea9 	b	80208c34 <_malloc_r+0x1f4>
    80209194:	f900e399 	str	x25, [x28, #448]
    80209198:	17ffffaa 	b	80209040 <_malloc_r+0x600>
    8020919c:	f105505f 	cmp	x2, #0x154
    802091a0:	54000288 	b.hi	802091f0 <_malloc_r+0x7b0>  // b.pmore
    802091a4:	d34ffc22 	lsr	x2, x1, #15
    802091a8:	1101e044 	add	w4, w2, #0x78
    802091ac:	1101dc43 	add	w3, w2, #0x77
    802091b0:	531f7884 	lsl	w4, w4, #1
    802091b4:	937d7c84 	sbfiz	x4, x4, #3, #32
    802091b8:	17ffff45 	b	80208ecc <_malloc_r+0x48c>
    802091bc:	f115503f 	cmp	x1, #0x554
    802091c0:	54000288 	b.hi	80209210 <_malloc_r+0x7d0>  // b.pmore
    802091c4:	d352fe81 	lsr	x1, x20, #18
    802091c8:	1101f420 	add	w0, w1, #0x7d
    802091cc:	1101f025 	add	w5, w1, #0x7c
    802091d0:	531f7804 	lsl	w4, w0, #1
    802091d4:	937d7c84 	sbfiz	x4, x4, #3, #32
    802091d8:	17fffe97 	b	80208c34 <_malloc_r+0x1f4>
    802091dc:	d100439c 	sub	x28, x28, #0x10
    802091e0:	52800002 	mov	w2, #0x0                   	// #0
    802091e4:	8b1c0318 	add	x24, x24, x28
    802091e8:	cb190318 	sub	x24, x24, x25
    802091ec:	17ffffa6 	b	80209084 <_malloc_r+0x644>
    802091f0:	f115505f 	cmp	x2, #0x554
    802091f4:	54000168 	b.hi	80209220 <_malloc_r+0x7e0>  // b.pmore
    802091f8:	d352fc22 	lsr	x2, x1, #18
    802091fc:	1101f444 	add	w4, w2, #0x7d
    80209200:	1101f043 	add	w3, w2, #0x7c
    80209204:	531f7884 	lsl	w4, w4, #1
    80209208:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020920c:	17ffff30 	b	80208ecc <_malloc_r+0x48c>
    80209210:	d280fe04 	mov	x4, #0x7f0                 	// #2032
    80209214:	52800fe0 	mov	w0, #0x7f                  	// #127
    80209218:	52800fc5 	mov	w5, #0x7e                  	// #126
    8020921c:	17fffe86 	b	80208c34 <_malloc_r+0x1f4>
    80209220:	d280fe04 	mov	x4, #0x7f0                 	// #2032
    80209224:	52800fc3 	mov	w3, #0x7e                  	// #126
    80209228:	17ffff29 	b	80208ecc <_malloc_r+0x48c>
    8020922c:	f94006c0 	ldr	x0, [x22, #8]
    80209230:	17fffe65 	b	80208bc4 <_malloc_r+0x184>
	...

0000000080209240 <_wcrtomb_r>:
    80209240:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80209244:	9104f004 	add	x4, x0, #0x13c
    80209248:	910003fd 	mov	x29, sp
    8020924c:	a90153f3 	stp	x19, x20, [sp, #16]
    80209250:	aa0303f3 	mov	x19, x3
    80209254:	f100027f 	cmp	x19, #0x0
    80209258:	90000043 	adrp	x3, 80211000 <__mprec_tens+0x180>
    8020925c:	9a930093 	csel	x19, x4, x19, eq	// eq = none
    80209260:	aa0003f4 	mov	x20, x0
    80209264:	f945d864 	ldr	x4, [x3, #2992]
    80209268:	aa1303e3 	mov	x3, x19
    8020926c:	b4000121 	cbz	x1, 80209290 <_wcrtomb_r+0x50>
    80209270:	d63f0080 	blr	x4
    80209274:	2a0003e1 	mov	w1, w0
    80209278:	93407c20 	sxtw	x0, w1
    8020927c:	3100043f 	cmn	w1, #0x1
    80209280:	54000160 	b.eq	802092ac <_wcrtomb_r+0x6c>  // b.none
    80209284:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209288:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020928c:	d65f03c0 	ret
    80209290:	910083e1 	add	x1, sp, #0x20
    80209294:	52800002 	mov	w2, #0x0                   	// #0
    80209298:	d63f0080 	blr	x4
    8020929c:	2a0003e1 	mov	w1, w0
    802092a0:	93407c20 	sxtw	x0, w1
    802092a4:	3100043f 	cmn	w1, #0x1
    802092a8:	54fffee1 	b.ne	80209284 <_wcrtomb_r+0x44>  // b.any
    802092ac:	b900027f 	str	wzr, [x19]
    802092b0:	52801141 	mov	w1, #0x8a                  	// #138
    802092b4:	b9000281 	str	w1, [x20]
    802092b8:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    802092bc:	a94153f3 	ldp	x19, x20, [sp, #16]
    802092c0:	a8c37bfd 	ldp	x29, x30, [sp], #48
    802092c4:	d65f03c0 	ret
	...

00000000802092d0 <wcrtomb>:
    802092d0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    802092d4:	90000044 	adrp	x4, 80211000 <__mprec_tens+0x180>
    802092d8:	90000043 	adrp	x3, 80211000 <__mprec_tens+0x180>
    802092dc:	910003fd 	mov	x29, sp
    802092e0:	a90153f3 	stp	x19, x20, [sp, #16]
    802092e4:	f100005f 	cmp	x2, #0x0
    802092e8:	f9402494 	ldr	x20, [x4, #72]
    802092ec:	9104f284 	add	x4, x20, #0x13c
    802092f0:	9a820093 	csel	x19, x4, x2, eq	// eq = none
    802092f4:	f945d864 	ldr	x4, [x3, #2992]
    802092f8:	b40001a0 	cbz	x0, 8020932c <wcrtomb+0x5c>
    802092fc:	2a0103e2 	mov	w2, w1
    80209300:	aa0003e1 	mov	x1, x0
    80209304:	aa1303e3 	mov	x3, x19
    80209308:	aa1403e0 	mov	x0, x20
    8020930c:	d63f0080 	blr	x4
    80209310:	2a0003e1 	mov	w1, w0
    80209314:	93407c20 	sxtw	x0, w1
    80209318:	3100043f 	cmn	w1, #0x1
    8020931c:	540001a0 	b.eq	80209350 <wcrtomb+0x80>  // b.none
    80209320:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209324:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80209328:	d65f03c0 	ret
    8020932c:	910083e1 	add	x1, sp, #0x20
    80209330:	aa1303e3 	mov	x3, x19
    80209334:	aa1403e0 	mov	x0, x20
    80209338:	52800002 	mov	w2, #0x0                   	// #0
    8020933c:	d63f0080 	blr	x4
    80209340:	2a0003e1 	mov	w1, w0
    80209344:	93407c20 	sxtw	x0, w1
    80209348:	3100043f 	cmn	w1, #0x1
    8020934c:	54fffea1 	b.ne	80209320 <wcrtomb+0x50>  // b.any
    80209350:	b900027f 	str	wzr, [x19]
    80209354:	52801141 	mov	w1, #0x8a                  	// #138
    80209358:	b9000281 	str	w1, [x20]
    8020935c:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    80209360:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209364:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80209368:	d65f03c0 	ret
    8020936c:	00000000 	udf	#0

0000000080209370 <__retarget_lock_init>:
    80209370:	d65f03c0 	ret
	...

0000000080209380 <__retarget_lock_init_recursive>:
    80209380:	d65f03c0 	ret
	...

0000000080209390 <__retarget_lock_close>:
    80209390:	d65f03c0 	ret
	...

00000000802093a0 <__retarget_lock_close_recursive>:
    802093a0:	d65f03c0 	ret
	...

00000000802093b0 <__retarget_lock_acquire>:
    802093b0:	d65f03c0 	ret
	...

00000000802093c0 <__retarget_lock_acquire_recursive>:
    802093c0:	d65f03c0 	ret
	...

00000000802093d0 <__retarget_lock_try_acquire>:
    802093d0:	52800020 	mov	w0, #0x1                   	// #1
    802093d4:	d65f03c0 	ret
	...

00000000802093e0 <__retarget_lock_try_acquire_recursive>:
    802093e0:	52800020 	mov	w0, #0x1                   	// #1
    802093e4:	d65f03c0 	ret
	...

00000000802093f0 <__retarget_lock_release>:
    802093f0:	d65f03c0 	ret
	...

0000000080209400 <__retarget_lock_release_recursive>:
    80209400:	d65f03c0 	ret
	...

0000000080209410 <currentlocale>:
    80209410:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    80209414:	910003fd 	mov	x29, sp
    80209418:	a90153f3 	stp	x19, x20, [sp, #16]
    8020941c:	90000054 	adrp	x20, 80211000 <__mprec_tens+0x180>
    80209420:	912b4294 	add	x20, x20, #0xad0
    80209424:	a9025bf5 	stp	x21, x22, [sp, #32]
    80209428:	90000055 	adrp	x21, 80211000 <__mprec_tens+0x180>
    8020942c:	912c42b5 	add	x21, x21, #0xb10
    80209430:	f9001bf7 	str	x23, [sp, #48]
    80209434:	90000057 	adrp	x23, 80211000 <__mprec_tens+0x180>
    80209438:	912782f7 	add	x23, x23, #0x9e0
    8020943c:	90000056 	adrp	x22, 80211000 <__mprec_tens+0x180>
    80209440:	aa1503f3 	mov	x19, x21
    80209444:	912bc2c1 	add	x1, x22, #0xaf0
    80209448:	91038294 	add	x20, x20, #0xe0
    8020944c:	912bc2d6 	add	x22, x22, #0xaf0
    80209450:	aa1703e0 	mov	x0, x23
    80209454:	94000fbb 	bl	8020d340 <strcpy>
    80209458:	aa1303e1 	mov	x1, x19
    8020945c:	aa1603e0 	mov	x0, x22
    80209460:	91008273 	add	x19, x19, #0x20
    80209464:	94000f67 	bl	8020d200 <strcmp>
    80209468:	35000120 	cbnz	w0, 8020948c <currentlocale+0x7c>
    8020946c:	eb14027f 	cmp	x19, x20
    80209470:	54ffff41 	b.ne	80209458 <currentlocale+0x48>  // b.any
    80209474:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209478:	aa1703e0 	mov	x0, x23
    8020947c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209480:	f9401bf7 	ldr	x23, [sp, #48]
    80209484:	a8c47bfd 	ldp	x29, x30, [sp], #64
    80209488:	d65f03c0 	ret
    8020948c:	f0000033 	adrp	x19, 80210000 <__trunctfdf2+0xc0>
    80209490:	91150273 	add	x19, x19, #0x540
    80209494:	d503201f 	nop
    80209498:	aa1303e1 	mov	x1, x19
    8020949c:	aa1703e0 	mov	x0, x23
    802094a0:	94001434 	bl	8020e570 <strcat>
    802094a4:	aa1503e1 	mov	x1, x21
    802094a8:	aa1703e0 	mov	x0, x23
    802094ac:	910082b5 	add	x21, x21, #0x20
    802094b0:	94001430 	bl	8020e570 <strcat>
    802094b4:	eb1402bf 	cmp	x21, x20
    802094b8:	54ffff01 	b.ne	80209498 <currentlocale+0x88>  // b.any
    802094bc:	a94153f3 	ldp	x19, x20, [sp, #16]
    802094c0:	aa1703e0 	mov	x0, x23
    802094c4:	a9425bf5 	ldp	x21, x22, [sp, #32]
    802094c8:	f9401bf7 	ldr	x23, [sp, #48]
    802094cc:	a8c47bfd 	ldp	x29, x30, [sp], #64
    802094d0:	d65f03c0 	ret
	...

00000000802094e0 <__loadlocale>:
    802094e0:	a9b67bfd 	stp	x29, x30, [sp, #-160]!
    802094e4:	910003fd 	mov	x29, sp
    802094e8:	a90153f3 	stp	x19, x20, [sp, #16]
    802094ec:	937b7c34 	sbfiz	x20, x1, #5, #32
    802094f0:	8b140014 	add	x20, x0, x20
    802094f4:	aa0203f3 	mov	x19, x2
    802094f8:	a9025bf5 	stp	x21, x22, [sp, #32]
    802094fc:	aa0003f6 	mov	x22, x0
    80209500:	aa0203e0 	mov	x0, x2
    80209504:	a90363f7 	stp	x23, x24, [sp, #48]
    80209508:	2a0103f7 	mov	w23, w1
    8020950c:	aa1403e1 	mov	x1, x20
    80209510:	94000f3c 	bl	8020d200 <strcmp>
    80209514:	350000e0 	cbnz	w0, 80209530 <__loadlocale+0x50>
    80209518:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020951c:	aa1403e0 	mov	x0, x20
    80209520:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209524:	a94363f7 	ldp	x23, x24, [sp, #48]
    80209528:	a8ca7bfd 	ldp	x29, x30, [sp], #160
    8020952c:	d65f03c0 	ret
    80209530:	aa1303e0 	mov	x0, x19
    80209534:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209538:	f0000035 	adrp	x21, 80210000 <__trunctfdf2+0xc0>
    8020953c:	91152021 	add	x1, x1, #0x548
    80209540:	911542b5 	add	x21, x21, #0x550
    80209544:	94000f2f 	bl	8020d200 <strcmp>
    80209548:	340008e0 	cbz	w0, 80209664 <__loadlocale+0x184>
    8020954c:	aa1503e1 	mov	x1, x21
    80209550:	aa1303e0 	mov	x0, x19
    80209554:	94000f2b 	bl	8020d200 <strcmp>
    80209558:	34000780 	cbz	w0, 80209648 <__loadlocale+0x168>
    8020955c:	39400260 	ldrb	w0, [x19]
    80209560:	71010c1f 	cmp	w0, #0x43
    80209564:	540008e0 	b.eq	80209680 <__loadlocale+0x1a0>  // b.none
    80209568:	51018400 	sub	w0, w0, #0x61
    8020956c:	12001c00 	and	w0, w0, #0xff
    80209570:	7100641f 	cmp	w0, #0x19
    80209574:	54000668 	b.hi	80209640 <__loadlocale+0x160>  // b.pmore
    80209578:	39400660 	ldrb	w0, [x19, #1]
    8020957c:	51018400 	sub	w0, w0, #0x61
    80209580:	12001c00 	and	w0, w0, #0xff
    80209584:	7100641f 	cmp	w0, #0x19
    80209588:	540005c8 	b.hi	80209640 <__loadlocale+0x160>  // b.pmore
    8020958c:	39400a60 	ldrb	w0, [x19, #2]
    80209590:	91000a78 	add	x24, x19, #0x2
    80209594:	51018401 	sub	w1, w0, #0x61
    80209598:	12001c21 	and	w1, w1, #0xff
    8020959c:	7100643f 	cmp	w1, #0x19
    802095a0:	54000068 	b.hi	802095ac <__loadlocale+0xcc>  // b.pmore
    802095a4:	39400e60 	ldrb	w0, [x19, #3]
    802095a8:	91000e78 	add	x24, x19, #0x3
    802095ac:	71017c1f 	cmp	w0, #0x5f
    802095b0:	54000900 	b.eq	802096d0 <__loadlocale+0x1f0>  // b.none
    802095b4:	7100b81f 	cmp	w0, #0x2e
    802095b8:	54002f60 	b.eq	80209ba4 <__loadlocale+0x6c4>  // b.none
    802095bc:	528017e1 	mov	w1, #0xbf                  	// #191
    802095c0:	6a01001f 	tst	w0, w1
    802095c4:	540003e1 	b.ne	80209640 <__loadlocale+0x160>  // b.any
    802095c8:	910203f5 	add	x21, sp, #0x80
    802095cc:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    802095d0:	aa1503e0 	mov	x0, x21
    802095d4:	91158021 	add	x1, x1, #0x560
    802095d8:	a9046bf9 	stp	x25, x26, [sp, #64]
    802095dc:	94000f59 	bl	8020d340 <strcpy>
    802095e0:	39400300 	ldrb	w0, [x24]
    802095e4:	7101001f 	cmp	w0, #0x40
    802095e8:	54002e40 	b.eq	80209bb0 <__loadlocale+0x6d0>  // b.none
    802095ec:	52800018 	mov	w24, #0x0                   	// #0
    802095f0:	52800019 	mov	w25, #0x0                   	// #0
    802095f4:	5280001a 	mov	w26, #0x0                   	// #0
    802095f8:	394203e1 	ldrb	w1, [sp, #128]
    802095fc:	51010421 	sub	w1, w1, #0x41
    80209600:	7100d03f 	cmp	w1, #0x34
    80209604:	54000388 	b.hi	80209674 <__loadlocale+0x194>  // b.pmore
    80209608:	f0000020 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020960c:	91278000 	add	x0, x0, #0x9e0
    80209610:	a90573fb 	stp	x27, x28, [sp, #80]
    80209614:	78615800 	ldrh	w0, [x0, w1, uxtw #1]
    80209618:	10000061 	adr	x1, 80209624 <__loadlocale+0x144>
    8020961c:	8b20a820 	add	x0, x1, w0, sxth #2
    80209620:	d61f0000 	br	x0
    80209624:	d10d4800 	sub	x0, x0, #0x352
    80209628:	d28234a1 	mov	x1, #0x11a5                	// #4517
    8020962c:	f2a00021 	movk	x1, #0x1, lsl #16
    80209630:	9ac02420 	lsr	x0, x1, x0
    80209634:	37000c60 	tbnz	w0, #0, 802097c0 <__loadlocale+0x2e0>
    80209638:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020963c:	a94573fb 	ldp	x27, x28, [sp, #80]
    80209640:	d2800014 	mov	x20, #0x0                   	// #0
    80209644:	17ffffb5 	b	80209518 <__loadlocale+0x38>
    80209648:	910203f5 	add	x21, sp, #0x80
    8020964c:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209650:	aa1503e0 	mov	x0, x21
    80209654:	91156021 	add	x1, x1, #0x558
    80209658:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020965c:	94000f39 	bl	8020d340 <strcpy>
    80209660:	17ffffe3 	b	802095ec <__loadlocale+0x10c>
    80209664:	aa1503e1 	mov	x1, x21
    80209668:	aa1303e0 	mov	x0, x19
    8020966c:	94000f35 	bl	8020d340 <strcpy>
    80209670:	17ffffb7 	b	8020954c <__loadlocale+0x6c>
    80209674:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80209678:	d2800014 	mov	x20, #0x0                   	// #0
    8020967c:	17ffffa7 	b	80209518 <__loadlocale+0x38>
    80209680:	39400660 	ldrb	w0, [x19, #1]
    80209684:	5100b400 	sub	w0, w0, #0x2d
    80209688:	12001c00 	and	w0, w0, #0xff
    8020968c:	7100041f 	cmp	w0, #0x1
    80209690:	54fffd88 	b.hi	80209640 <__loadlocale+0x160>  // b.pmore
    80209694:	91000a78 	add	x24, x19, #0x2
    80209698:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020969c:	910203f5 	add	x21, sp, #0x80
    802096a0:	aa1803e1 	mov	x1, x24
    802096a4:	aa1503e0 	mov	x0, x21
    802096a8:	94000f26 	bl	8020d340 <strcpy>
    802096ac:	aa1503e0 	mov	x0, x21
    802096b0:	52800801 	mov	w1, #0x40                  	// #64
    802096b4:	94000e93 	bl	8020d100 <strchr>
    802096b8:	b4000040 	cbz	x0, 802096c0 <__loadlocale+0x1e0>
    802096bc:	3900001f 	strb	wzr, [x0]
    802096c0:	aa1503e0 	mov	x0, x21
    802096c4:	97ffe68f 	bl	80203100 <strlen>
    802096c8:	8b000318 	add	x24, x24, x0
    802096cc:	17ffffc5 	b	802095e0 <__loadlocale+0x100>
    802096d0:	39400700 	ldrb	w0, [x24, #1]
    802096d4:	51010400 	sub	w0, w0, #0x41
    802096d8:	12001c00 	and	w0, w0, #0xff
    802096dc:	7100641f 	cmp	w0, #0x19
    802096e0:	54fffb08 	b.hi	80209640 <__loadlocale+0x160>  // b.pmore
    802096e4:	39400b00 	ldrb	w0, [x24, #2]
    802096e8:	51010400 	sub	w0, w0, #0x41
    802096ec:	12001c00 	and	w0, w0, #0xff
    802096f0:	7100641f 	cmp	w0, #0x19
    802096f4:	54fffa68 	b.hi	80209640 <__loadlocale+0x160>  // b.pmore
    802096f8:	39400f00 	ldrb	w0, [x24, #3]
    802096fc:	91000f18 	add	x24, x24, #0x3
    80209700:	17ffffad 	b	802095b4 <__loadlocale+0xd4>
    80209704:	f000003b 	adrp	x27, 80210000 <__trunctfdf2+0xc0>
    80209708:	9116637b 	add	x27, x27, #0x598
    8020970c:	aa1b03e1 	mov	x1, x27
    80209710:	aa1503e0 	mov	x0, x21
    80209714:	9400137b 	bl	8020e500 <strcasecmp>
    80209718:	340000c0 	cbz	w0, 80209730 <__loadlocale+0x250>
    8020971c:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209720:	aa1503e0 	mov	x0, x21
    80209724:	91168021 	add	x1, x1, #0x5a0
    80209728:	94001376 	bl	8020e500 <strcasecmp>
    8020972c:	35fff860 	cbnz	w0, 80209638 <__loadlocale+0x158>
    80209730:	aa1b03e1 	mov	x1, x27
    80209734:	aa1503e0 	mov	x0, x21
    80209738:	94000f02 	bl	8020d340 <strcpy>
    8020973c:	9000003b 	adrp	x27, 8020d000 <_isatty_r+0x40>
    80209740:	90000022 	adrp	x2, 8020d000 <_isatty_r+0x40>
    80209744:	9138037b 	add	x27, x27, #0xe00
    80209748:	911c4042 	add	x2, x2, #0x710
    8020974c:	528000dc 	mov	w28, #0x6                   	// #6
    80209750:	71000aff 	cmp	w23, #0x2
    80209754:	54001fa0 	b.eq	80209b48 <__loadlocale+0x668>  // b.none
    80209758:	71001aff 	cmp	w23, #0x6
    8020975c:	54000081 	b.ne	8020976c <__loadlocale+0x28c>  // b.any
    80209760:	aa1503e1 	mov	x1, x21
    80209764:	91060ac0 	add	x0, x22, #0x182
    80209768:	94000ef6 	bl	8020d340 <strcpy>
    8020976c:	aa1303e1 	mov	x1, x19
    80209770:	aa1403e0 	mov	x0, x20
    80209774:	94000ef3 	bl	8020d340 <strcpy>
    80209778:	aa0003f4 	mov	x20, x0
    8020977c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209780:	aa1403e0 	mov	x0, x20
    80209784:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209788:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020978c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80209790:	a94573fb 	ldp	x27, x28, [sp, #80]
    80209794:	a8ca7bfd 	ldp	x29, x30, [sp], #160
    80209798:	d65f03c0 	ret
    8020979c:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    802097a0:	aa1503e0 	mov	x0, x21
    802097a4:	9118e021 	add	x1, x1, #0x638
    802097a8:	94001356 	bl	8020e500 <strcasecmp>
    802097ac:	35fff460 	cbnz	w0, 80209638 <__loadlocale+0x158>
    802097b0:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    802097b4:	aa1503e0 	mov	x0, x21
    802097b8:	91190021 	add	x1, x1, #0x640
    802097bc:	94000ee1 	bl	8020d340 <strcpy>
    802097c0:	9000003b 	adrp	x27, 8020d000 <_isatty_r+0x40>
    802097c4:	90000022 	adrp	x2, 8020d000 <_isatty_r+0x40>
    802097c8:	9136c37b 	add	x27, x27, #0xdb0
    802097cc:	911b4042 	add	x2, x2, #0x6d0
    802097d0:	5280003c 	mov	w28, #0x1                   	// #1
    802097d4:	17ffffdf 	b	80209750 <__loadlocale+0x270>
    802097d8:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    802097dc:	aa1503e0 	mov	x0, x21
    802097e0:	9117e021 	add	x1, x1, #0x5f8
    802097e4:	d2800082 	mov	x2, #0x4                   	// #4
    802097e8:	94000d56 	bl	8020cd40 <strncasecmp>
    802097ec:	35fff260 	cbnz	w0, 80209638 <__loadlocale+0x158>
    802097f0:	394213e0 	ldrb	w0, [sp, #132]
    802097f4:	394217e1 	ldrb	w1, [sp, #133]
    802097f8:	7100b41f 	cmp	w0, #0x2d
    802097fc:	1a800020 	csel	w0, w1, w0, eq	// eq = none
    80209800:	51014800 	sub	w0, w0, #0x52
    80209804:	12001c00 	and	w0, w0, #0xff
    80209808:	71008c1f 	cmp	w0, #0x23
    8020980c:	54fff168 	b.hi	80209638 <__loadlocale+0x158>  // b.pmore
    80209810:	d2800021 	mov	x1, #0x1                   	// #1
    80209814:	9ac02020 	lsl	x0, x1, x0
    80209818:	f21e001f 	tst	x0, #0x400000004
    8020981c:	540020e1 	b.ne	80209c38 <__loadlocale+0x758>  // b.any
    80209820:	f21d001f 	tst	x0, #0x800000008
    80209824:	54002001 	b.ne	80209c24 <__loadlocale+0x744>  // b.any
    80209828:	f200001f 	tst	x0, #0x100000001
    8020982c:	54fff060 	b.eq	80209638 <__loadlocale+0x158>  // b.none
    80209830:	aa1503e0 	mov	x0, x21
    80209834:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209838:	91180021 	add	x1, x1, #0x600
    8020983c:	94000ec1 	bl	8020d340 <strcpy>
    80209840:	17ffffe0 	b	802097c0 <__loadlocale+0x2e0>
    80209844:	f000003b 	adrp	x27, 80210000 <__trunctfdf2+0xc0>
    80209848:	9116a37b 	add	x27, x27, #0x5a8
    8020984c:	aa1b03e1 	mov	x1, x27
    80209850:	aa1503e0 	mov	x0, x21
    80209854:	9400132b 	bl	8020e500 <strcasecmp>
    80209858:	35ffef00 	cbnz	w0, 80209638 <__loadlocale+0x158>
    8020985c:	aa1b03e1 	mov	x1, x27
    80209860:	aa1503e0 	mov	x0, x21
    80209864:	94000eb7 	bl	8020d340 <strcpy>
    80209868:	b000003b 	adrp	x27, 8020e000 <__utf8_mbtowc+0x200>
    8020986c:	90000022 	adrp	x2, 8020d000 <_isatty_r+0x40>
    80209870:	910b037b 	add	x27, x27, #0x2c0
    80209874:	91250042 	add	x2, x2, #0x940
    80209878:	5280011c 	mov	w28, #0x8                   	// #8
    8020987c:	17ffffb5 	b	80209750 <__loadlocale+0x270>
    80209880:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209884:	aa1503e0 	mov	x0, x21
    80209888:	91174021 	add	x1, x1, #0x5d0
    8020988c:	d2800062 	mov	x2, #0x3                   	// #3
    80209890:	94000d2c 	bl	8020cd40 <strncasecmp>
    80209894:	35ffed20 	cbnz	w0, 80209638 <__loadlocale+0x158>
    80209898:	39420fe0 	ldrb	w0, [sp, #131]
    8020989c:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    802098a0:	d2800082 	mov	x2, #0x4                   	// #4
    802098a4:	91176021 	add	x1, x1, #0x5d8
    802098a8:	7100b41f 	cmp	w0, #0x2d
    802098ac:	910283e0 	add	x0, sp, #0xa0
    802098b0:	9a80141b 	cinc	x27, x0, eq	// eq = none
    802098b4:	d100777b 	sub	x27, x27, #0x1d
    802098b8:	aa1b03e0 	mov	x0, x27
    802098bc:	94000d21 	bl	8020cd40 <strncasecmp>
    802098c0:	35ffebc0 	cbnz	w0, 80209638 <__loadlocale+0x158>
    802098c4:	39401360 	ldrb	w0, [x27, #4]
    802098c8:	9101e3e1 	add	x1, sp, #0x78
    802098cc:	52800142 	mov	w2, #0xa                   	// #10
    802098d0:	7100b41f 	cmp	w0, #0x2d
    802098d4:	9a9b1760 	cinc	x0, x27, eq	// eq = none
    802098d8:	91001000 	add	x0, x0, #0x4
    802098dc:	94000d05 	bl	8020ccf0 <strtol>
    802098e0:	aa0003fb 	mov	x27, x0
    802098e4:	d1000400 	sub	x0, x0, #0x1
    802098e8:	f1003c1f 	cmp	x0, #0xf
    802098ec:	fa4c9b64 	ccmp	x27, #0xc, #0x4, ls	// ls = plast
    802098f0:	54ffea40 	b.eq	80209638 <__loadlocale+0x158>  // b.none
    802098f4:	f9403fe0 	ldr	x0, [sp, #120]
    802098f8:	39400000 	ldrb	w0, [x0]
    802098fc:	35ffe9e0 	cbnz	w0, 80209638 <__loadlocale+0x158>
    80209900:	aa1503e0 	mov	x0, x21
    80209904:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209908:	91178021 	add	x1, x1, #0x5e0
    8020990c:	94000e8d 	bl	8020d340 <strcpy>
    80209910:	910227e2 	add	x2, sp, #0x89
    80209914:	f1002b7f 	cmp	x27, #0xa
    80209918:	5400008d 	b.le	80209928 <__loadlocale+0x448>
    8020991c:	91022be2 	add	x2, sp, #0x8a
    80209920:	52800620 	mov	w0, #0x31                  	// #49
    80209924:	390227e0 	strb	w0, [sp, #137]
    80209928:	b203e7e1 	mov	x1, #0x6666666666666666    	// #7378697629483820646
    8020992c:	3900045f 	strb	wzr, [x2, #1]
    80209930:	f28ccce1 	movk	x1, #0x6667
    80209934:	9b417f61 	smulh	x1, x27, x1
    80209938:	9342fc21 	asr	x1, x1, #2
    8020993c:	cb9bfc21 	sub	x1, x1, x27, asr #63
    80209940:	8b010821 	add	x1, x1, x1, lsl #2
    80209944:	cb010760 	sub	x0, x27, x1, lsl #1
    80209948:	1100c000 	add	w0, w0, #0x30
    8020994c:	39000040 	strb	w0, [x2]
    80209950:	17ffff9c 	b	802097c0 <__loadlocale+0x2e0>
    80209954:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209958:	aa1503e0 	mov	x0, x21
    8020995c:	91192021 	add	x1, x1, #0x648
    80209960:	d2800062 	mov	x2, #0x3                   	// #3
    80209964:	94000cf7 	bl	8020cd40 <strncasecmp>
    80209968:	35ffe680 	cbnz	w0, 80209638 <__loadlocale+0x158>
    8020996c:	39420fe0 	ldrb	w0, [sp, #131]
    80209970:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209974:	91194021 	add	x1, x1, #0x650
    80209978:	7100b41f 	cmp	w0, #0x2d
    8020997c:	910283e0 	add	x0, sp, #0xa0
    80209980:	9a801400 	cinc	x0, x0, eq	// eq = none
    80209984:	d1007400 	sub	x0, x0, #0x1d
    80209988:	94000e1e 	bl	8020d200 <strcmp>
    8020998c:	35ffe560 	cbnz	w0, 80209638 <__loadlocale+0x158>
    80209990:	aa1503e0 	mov	x0, x21
    80209994:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209998:	91196021 	add	x1, x1, #0x658
    8020999c:	94000e69 	bl	8020d340 <strcpy>
    802099a0:	17ffff88 	b	802097c0 <__loadlocale+0x2e0>
    802099a4:	f000003b 	adrp	x27, 80210000 <__trunctfdf2+0xc0>
    802099a8:	9117237b 	add	x27, x27, #0x5c8
    802099ac:	aa1b03e1 	mov	x1, x27
    802099b0:	aa1503e0 	mov	x0, x21
    802099b4:	940012d3 	bl	8020e500 <strcasecmp>
    802099b8:	35ffe400 	cbnz	w0, 80209638 <__loadlocale+0x158>
    802099bc:	aa1b03e1 	mov	x1, x27
    802099c0:	aa1503e0 	mov	x0, x21
    802099c4:	94000e5f 	bl	8020d340 <strcpy>
    802099c8:	b000003b 	adrp	x27, 8020e000 <__utf8_mbtowc+0x200>
    802099cc:	90000022 	adrp	x2, 8020d000 <_isatty_r+0x40>
    802099d0:	9103037b 	add	x27, x27, #0xc0
    802099d4:	91200042 	add	x2, x2, #0x800
    802099d8:	5280005c 	mov	w28, #0x2                   	// #2
    802099dc:	17ffff5d 	b	80209750 <__loadlocale+0x270>
    802099e0:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    802099e4:	aa1503e0 	mov	x0, x21
    802099e8:	91186021 	add	x1, x1, #0x618
    802099ec:	d2800102 	mov	x2, #0x8                   	// #8
    802099f0:	94000cd4 	bl	8020cd40 <strncasecmp>
    802099f4:	35ffe220 	cbnz	w0, 80209638 <__loadlocale+0x158>
    802099f8:	394223e0 	ldrb	w0, [sp, #136]
    802099fc:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209a00:	9118a021 	add	x1, x1, #0x628
    80209a04:	7100b41f 	cmp	w0, #0x2d
    80209a08:	910283e0 	add	x0, sp, #0xa0
    80209a0c:	9a801400 	cinc	x0, x0, eq	// eq = none
    80209a10:	d1006000 	sub	x0, x0, #0x18
    80209a14:	940012bb 	bl	8020e500 <strcasecmp>
    80209a18:	35ffe100 	cbnz	w0, 80209638 <__loadlocale+0x158>
    80209a1c:	aa1503e0 	mov	x0, x21
    80209a20:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209a24:	9118c021 	add	x1, x1, #0x630
    80209a28:	94000e46 	bl	8020d340 <strcpy>
    80209a2c:	17ffff65 	b	802097c0 <__loadlocale+0x2e0>
    80209a30:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209a34:	aa1503e0 	mov	x0, x21
    80209a38:	9116c021 	add	x1, x1, #0x5b0
    80209a3c:	d2800062 	mov	x2, #0x3                   	// #3
    80209a40:	94000cc0 	bl	8020cd40 <strncasecmp>
    80209a44:	35ffdfa0 	cbnz	w0, 80209638 <__loadlocale+0x158>
    80209a48:	39420fe0 	ldrb	w0, [sp, #131]
    80209a4c:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209a50:	9116e021 	add	x1, x1, #0x5b8
    80209a54:	7100b41f 	cmp	w0, #0x2d
    80209a58:	910283e0 	add	x0, sp, #0xa0
    80209a5c:	9a801400 	cinc	x0, x0, eq	// eq = none
    80209a60:	d1007400 	sub	x0, x0, #0x1d
    80209a64:	940012a7 	bl	8020e500 <strcasecmp>
    80209a68:	35ffde80 	cbnz	w0, 80209638 <__loadlocale+0x158>
    80209a6c:	aa1503e0 	mov	x0, x21
    80209a70:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209a74:	91170021 	add	x1, x1, #0x5c0
    80209a78:	94000e32 	bl	8020d340 <strcpy>
    80209a7c:	b000003b 	adrp	x27, 8020e000 <__utf8_mbtowc+0x200>
    80209a80:	90000022 	adrp	x2, 8020d000 <_isatty_r+0x40>
    80209a84:	9106437b 	add	x27, x27, #0x190
    80209a88:	91224042 	add	x2, x2, #0x890
    80209a8c:	5280007c 	mov	w28, #0x3                   	// #3
    80209a90:	17ffff30 	b	80209750 <__loadlocale+0x270>
    80209a94:	394207e0 	ldrb	w0, [sp, #129]
    80209a98:	121a7800 	and	w0, w0, #0xffffffdf
    80209a9c:	12001c00 	and	w0, w0, #0xff
    80209aa0:	7101401f 	cmp	w0, #0x50
    80209aa4:	54ffdca1 	b.ne	80209638 <__loadlocale+0x158>  // b.any
    80209aa8:	d2800042 	mov	x2, #0x2                   	// #2
    80209aac:	aa1503e0 	mov	x0, x21
    80209ab0:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209ab4:	9117c021 	add	x1, x1, #0x5f0
    80209ab8:	94000d0a 	bl	8020cee0 <strncpy>
    80209abc:	9101e3e1 	add	x1, sp, #0x78
    80209ac0:	91020be0 	add	x0, sp, #0x82
    80209ac4:	52800142 	mov	w2, #0xa                   	// #10
    80209ac8:	94000c8a 	bl	8020ccf0 <strtol>
    80209acc:	f9403fe1 	ldr	x1, [sp, #120]
    80209ad0:	39400021 	ldrb	w1, [x1]
    80209ad4:	35ffdb21 	cbnz	w1, 80209638 <__loadlocale+0x158>
    80209ad8:	f10e901f 	cmp	x0, #0x3a4
    80209adc:	54fff760 	b.eq	802099c8 <__loadlocale+0x4e8>  // b.none
    80209ae0:	54000b6c 	b.gt	80209c4c <__loadlocale+0x76c>
    80209ae4:	f10d881f 	cmp	x0, #0x362
    80209ae8:	54000bec 	b.gt	80209c64 <__loadlocale+0x784>
    80209aec:	f10d441f 	cmp	x0, #0x351
    80209af0:	54ffd9ac 	b.gt	80209624 <__loadlocale+0x144>
    80209af4:	f106d41f 	cmp	x0, #0x1b5
    80209af8:	54ffe640 	b.eq	802097c0 <__loadlocale+0x2e0>  // b.none
    80209afc:	d10b4000 	sub	x0, x0, #0x2d0
    80209b00:	f100dc1f 	cmp	x0, #0x37
    80209b04:	54ffd9a8 	b.hi	80209638 <__loadlocale+0x158>  // b.pmore
    80209b08:	d2800021 	mov	x1, #0x1                   	// #1
    80209b0c:	f2a00041 	movk	x1, #0x2, lsl #16
    80209b10:	f2e01001 	movk	x1, #0x80, lsl #48
    80209b14:	9ac02420 	lsr	x0, x1, x0
    80209b18:	3707e540 	tbnz	w0, #0, 802097c0 <__loadlocale+0x2e0>
    80209b1c:	17fffec7 	b	80209638 <__loadlocale+0x158>
    80209b20:	f000003b 	adrp	x27, 80210000 <__trunctfdf2+0xc0>
    80209b24:	9115637b 	add	x27, x27, #0x558
    80209b28:	aa1b03e1 	mov	x1, x27
    80209b2c:	aa1503e0 	mov	x0, x21
    80209b30:	94001274 	bl	8020e500 <strcasecmp>
    80209b34:	35ffd820 	cbnz	w0, 80209638 <__loadlocale+0x158>
    80209b38:	aa1b03e1 	mov	x1, x27
    80209b3c:	aa1503e0 	mov	x0, x21
    80209b40:	94000e00 	bl	8020d340 <strcpy>
    80209b44:	17ffff1f 	b	802097c0 <__loadlocale+0x2e0>
    80209b48:	aa1503e1 	mov	x1, x21
    80209b4c:	91058ac0 	add	x0, x22, #0x162
    80209b50:	f90037e2 	str	x2, [sp, #104]
    80209b54:	94000dfb 	bl	8020d340 <strcpy>
    80209b58:	f94037e2 	ldr	x2, [sp, #104]
    80209b5c:	a90e6ec2 	stp	x2, x27, [x22, #224]
    80209b60:	aa1503e1 	mov	x1, x21
    80209b64:	390582dc 	strb	w28, [x22, #352]
    80209b68:	aa1603e0 	mov	x0, x22
    80209b6c:	9400083d 	bl	8020bc60 <__set_ctype>
    80209b70:	35000138 	cbnz	w24, 80209b94 <__loadlocale+0x6b4>
    80209b74:	7100079f 	cmp	w28, #0x1
    80209b78:	52000339 	eor	w25, w25, #0x1
    80209b7c:	1a9fd7e0 	cset	w0, gt
    80209b80:	6a00033f 	tst	w25, w0
    80209b84:	54000080 	b.eq	80209b94 <__loadlocale+0x6b4>  // b.none
    80209b88:	394203e0 	ldrb	w0, [sp, #128]
    80209b8c:	7101541f 	cmp	w0, #0x55
    80209b90:	1a9f07f8 	cset	w24, ne	// ne = any
    80209b94:	7100035f 	cmp	w26, #0x0
    80209b98:	5a9f0318 	csinv	w24, w24, wzr, eq	// eq = none
    80209b9c:	b900f2d8 	str	w24, [x22, #240]
    80209ba0:	17fffef3 	b	8020976c <__loadlocale+0x28c>
    80209ba4:	91000718 	add	x24, x24, #0x1
    80209ba8:	a9046bf9 	stp	x25, x26, [sp, #64]
    80209bac:	17fffebc 	b	8020969c <__loadlocale+0x1bc>
    80209bb0:	a90573fb 	stp	x27, x28, [sp, #80]
    80209bb4:	9100071b 	add	x27, x24, #0x1
    80209bb8:	aa1b03e0 	mov	x0, x27
    80209bbc:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209bc0:	52800018 	mov	w24, #0x0                   	// #0
    80209bc4:	9115c021 	add	x1, x1, #0x570
    80209bc8:	5280003a 	mov	w26, #0x1                   	// #1
    80209bcc:	94000d8d 	bl	8020d200 <strcmp>
    80209bd0:	2a0003f9 	mov	w25, w0
    80209bd4:	35000060 	cbnz	w0, 80209be0 <__loadlocale+0x700>
    80209bd8:	a94573fb 	ldp	x27, x28, [sp, #80]
    80209bdc:	17fffe87 	b	802095f8 <__loadlocale+0x118>
    80209be0:	aa1b03e0 	mov	x0, x27
    80209be4:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209be8:	5280001a 	mov	w26, #0x0                   	// #0
    80209bec:	91160021 	add	x1, x1, #0x580
    80209bf0:	52800039 	mov	w25, #0x1                   	// #1
    80209bf4:	94000d83 	bl	8020d200 <strcmp>
    80209bf8:	2a0003f8 	mov	w24, w0
    80209bfc:	34fffee0 	cbz	w0, 80209bd8 <__loadlocale+0x6f8>
    80209c00:	aa1b03e0 	mov	x0, x27
    80209c04:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209c08:	91164021 	add	x1, x1, #0x590
    80209c0c:	94000d7d 	bl	8020d200 <strcmp>
    80209c10:	7100001f 	cmp	w0, #0x0
    80209c14:	52800019 	mov	w25, #0x0                   	// #0
    80209c18:	a94573fb 	ldp	x27, x28, [sp, #80]
    80209c1c:	1a9f17f8 	cset	w24, eq	// eq = none
    80209c20:	17fffe76 	b	802095f8 <__loadlocale+0x118>
    80209c24:	aa1503e0 	mov	x0, x21
    80209c28:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209c2c:	91182021 	add	x1, x1, #0x608
    80209c30:	94000dc4 	bl	8020d340 <strcpy>
    80209c34:	17fffee3 	b	802097c0 <__loadlocale+0x2e0>
    80209c38:	aa1503e0 	mov	x0, x21
    80209c3c:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209c40:	91184021 	add	x1, x1, #0x610
    80209c44:	94000dbf 	bl	8020d340 <strcpy>
    80209c48:	17fffede 	b	802097c0 <__loadlocale+0x2e0>
    80209c4c:	f111941f 	cmp	x0, #0x465
    80209c50:	54ffdb80 	b.eq	802097c0 <__loadlocale+0x2e0>  // b.none
    80209c54:	d1138800 	sub	x0, x0, #0x4e2
    80209c58:	f100201f 	cmp	x0, #0x8
    80209c5c:	54ffdb29 	b.ls	802097c0 <__loadlocale+0x2e0>  // b.plast
    80209c60:	17fffe76 	b	80209638 <__loadlocale+0x158>
    80209c64:	f10da81f 	cmp	x0, #0x36a
    80209c68:	54ffce81 	b.ne	80209638 <__loadlocale+0x158>  // b.any
    80209c6c:	17fffed5 	b	802097c0 <__loadlocale+0x2e0>

0000000080209c70 <__get_locale_env>:
    80209c70:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80209c74:	910003fd 	mov	x29, sp
    80209c78:	a90153f3 	stp	x19, x20, [sp, #16]
    80209c7c:	2a0103f4 	mov	w20, w1
    80209c80:	aa0003f3 	mov	x19, x0
    80209c84:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209c88:	91198021 	add	x1, x1, #0x660
    80209c8c:	94000c8d 	bl	8020cec0 <_getenv_r>
    80209c90:	b4000060 	cbz	x0, 80209c9c <__get_locale_env+0x2c>
    80209c94:	39400001 	ldrb	w1, [x0]
    80209c98:	35000241 	cbnz	w1, 80209ce0 <__get_locale_env+0x70>
    80209c9c:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209ca0:	91300021 	add	x1, x1, #0xc00
    80209ca4:	aa1303e0 	mov	x0, x19
    80209ca8:	f874d821 	ldr	x1, [x1, w20, sxtw #3]
    80209cac:	94000c85 	bl	8020cec0 <_getenv_r>
    80209cb0:	b4000060 	cbz	x0, 80209cbc <__get_locale_env+0x4c>
    80209cb4:	39400001 	ldrb	w1, [x0]
    80209cb8:	35000141 	cbnz	w1, 80209ce0 <__get_locale_env+0x70>
    80209cbc:	f0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    80209cc0:	aa1303e0 	mov	x0, x19
    80209cc4:	9119a021 	add	x1, x1, #0x668
    80209cc8:	94000c7e 	bl	8020cec0 <_getenv_r>
    80209ccc:	b4000060 	cbz	x0, 80209cd8 <__get_locale_env+0x68>
    80209cd0:	39400001 	ldrb	w1, [x0]
    80209cd4:	35000061 	cbnz	w1, 80209ce0 <__get_locale_env+0x70>
    80209cd8:	90000040 	adrp	x0, 80211000 <__mprec_tens+0x180>
    80209cdc:	91320000 	add	x0, x0, #0xc80
    80209ce0:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209ce4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80209ce8:	d65f03c0 	ret
    80209cec:	00000000 	udf	#0

0000000080209cf0 <_setlocale_r>:
    80209cf0:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    80209cf4:	910003fd 	mov	x29, sp
    80209cf8:	a90153f3 	stp	x19, x20, [sp, #16]
    80209cfc:	a9025bf5 	stp	x21, x22, [sp, #32]
    80209d00:	a90363f7 	stp	x23, x24, [sp, #48]
    80209d04:	aa0003f7 	mov	x23, x0
    80209d08:	7100183f 	cmp	w1, #0x6
    80209d0c:	54000c28 	b.hi	80209e90 <_setlocale_r+0x1a0>  // b.pmore
    80209d10:	a9046bf9 	stp	x25, x26, [sp, #64]
    80209d14:	aa0203f9 	mov	x25, x2
    80209d18:	f9002bfb 	str	x27, [sp, #80]
    80209d1c:	2a0103fb 	mov	w27, w1
    80209d20:	b4001142 	cbz	x2, 80209f48 <_setlocale_r+0x258>
    80209d24:	f00003b6 	adrp	x22, 80280000 <gits_lock>
    80209d28:	90000055 	adrp	x21, 80211000 <__mprec_tens+0x180>
    80209d2c:	910f02d6 	add	x22, x22, #0x3c0
    80209d30:	912bc2b5 	add	x21, x21, #0xaf0
    80209d34:	f00003b8 	adrp	x24, 80280000 <gits_lock>
    80209d38:	910e8318 	add	x24, x24, #0x3a0
    80209d3c:	aa1603f3 	mov	x19, x22
    80209d40:	aa1503f4 	mov	x20, x21
    80209d44:	9103831a 	add	x26, x24, #0xe0
    80209d48:	aa1403e1 	mov	x1, x20
    80209d4c:	aa1303e0 	mov	x0, x19
    80209d50:	91008273 	add	x19, x19, #0x20
    80209d54:	94000d7b 	bl	8020d340 <strcpy>
    80209d58:	91008294 	add	x20, x20, #0x20
    80209d5c:	eb13035f 	cmp	x26, x19
    80209d60:	54ffff41 	b.ne	80209d48 <_setlocale_r+0x58>  // b.any
    80209d64:	39400320 	ldrb	w0, [x25]
    80209d68:	350005e0 	cbnz	w0, 80209e24 <_setlocale_r+0x134>
    80209d6c:	350010fb 	cbnz	w27, 80209f88 <_setlocale_r+0x298>
    80209d70:	aa1603f8 	mov	x24, x22
    80209d74:	52800033 	mov	w19, #0x1                   	// #1
    80209d78:	2a1303e1 	mov	w1, w19
    80209d7c:	aa1703e0 	mov	x0, x23
    80209d80:	97ffffbc 	bl	80209c70 <__get_locale_env>
    80209d84:	aa0003f4 	mov	x20, x0
    80209d88:	97ffe4de 	bl	80203100 <strlen>
    80209d8c:	aa0003e2 	mov	x2, x0
    80209d90:	aa1403e1 	mov	x1, x20
    80209d94:	aa1803e0 	mov	x0, x24
    80209d98:	f1007c5f 	cmp	x2, #0x1f
    80209d9c:	54000768 	b.hi	80209e88 <_setlocale_r+0x198>  // b.pmore
    80209da0:	11000673 	add	w19, w19, #0x1
    80209da4:	94000d67 	bl	8020d340 <strcpy>
    80209da8:	91008318 	add	x24, x24, #0x20
    80209dac:	71001e7f 	cmp	w19, #0x7
    80209db0:	54fffe41 	b.ne	80209d78 <_setlocale_r+0x88>  // b.any
    80209db4:	f00003ba 	adrp	x26, 80280000 <gits_lock>
    80209db8:	910b835a 	add	x26, x26, #0x2e0
    80209dbc:	90000059 	adrp	x25, 80211000 <__mprec_tens+0x180>
    80209dc0:	aa1a03f8 	mov	x24, x26
    80209dc4:	aa1603f4 	mov	x20, x22
    80209dc8:	912b4339 	add	x25, x25, #0xad0
    80209dcc:	52800033 	mov	w19, #0x1                   	// #1
    80209dd0:	aa1503e1 	mov	x1, x21
    80209dd4:	aa1803e0 	mov	x0, x24
    80209dd8:	94000d5a 	bl	8020d340 <strcpy>
    80209ddc:	aa1403e2 	mov	x2, x20
    80209de0:	2a1303e1 	mov	w1, w19
    80209de4:	aa1903e0 	mov	x0, x25
    80209de8:	97fffdbe 	bl	802094e0 <__loadlocale>
    80209dec:	b4000e80 	cbz	x0, 80209fbc <_setlocale_r+0x2cc>
    80209df0:	11000673 	add	w19, w19, #0x1
    80209df4:	91008318 	add	x24, x24, #0x20
    80209df8:	910082b5 	add	x21, x21, #0x20
    80209dfc:	91008294 	add	x20, x20, #0x20
    80209e00:	71001e7f 	cmp	w19, #0x7
    80209e04:	54fffe61 	b.ne	80209dd0 <_setlocale_r+0xe0>  // b.any
    80209e08:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209e0c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209e10:	a94363f7 	ldp	x23, x24, [sp, #48]
    80209e14:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80209e18:	f9402bfb 	ldr	x27, [sp, #80]
    80209e1c:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80209e20:	17fffd7c 	b	80209410 <currentlocale>
    80209e24:	340003fb 	cbz	w27, 80209ea0 <_setlocale_r+0x1b0>
    80209e28:	aa1903e0 	mov	x0, x25
    80209e2c:	97ffe4b5 	bl	80203100 <strlen>
    80209e30:	f1007c1f 	cmp	x0, #0x1f
    80209e34:	540002a8 	b.hi	80209e88 <_setlocale_r+0x198>  // b.pmore
    80209e38:	937b7f73 	sbfiz	x19, x27, #5, #32
    80209e3c:	aa1903e1 	mov	x1, x25
    80209e40:	8b130313 	add	x19, x24, x19
    80209e44:	aa1303e0 	mov	x0, x19
    80209e48:	94000d3e 	bl	8020d340 <strcpy>
    80209e4c:	aa1303e2 	mov	x2, x19
    80209e50:	2a1b03e1 	mov	w1, w27
    80209e54:	90000040 	adrp	x0, 80211000 <__mprec_tens+0x180>
    80209e58:	912b4000 	add	x0, x0, #0xad0
    80209e5c:	97fffda1 	bl	802094e0 <__loadlocale>
    80209e60:	aa0003f3 	mov	x19, x0
    80209e64:	97fffd6b 	bl	80209410 <currentlocale>
    80209e68:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80209e6c:	f9402bfb 	ldr	x27, [sp, #80]
    80209e70:	aa1303e0 	mov	x0, x19
    80209e74:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209e78:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209e7c:	a94363f7 	ldp	x23, x24, [sp, #48]
    80209e80:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80209e84:	d65f03c0 	ret
    80209e88:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80209e8c:	f9402bfb 	ldr	x27, [sp, #80]
    80209e90:	528002d5 	mov	w21, #0x16                  	// #22
    80209e94:	d2800013 	mov	x19, #0x0                   	// #0
    80209e98:	b90002f5 	str	w21, [x23]
    80209e9c:	17fffff5 	b	80209e70 <_setlocale_r+0x180>
    80209ea0:	aa1903e0 	mov	x0, x25
    80209ea4:	528005e1 	mov	w1, #0x2f                  	// #47
    80209ea8:	94000c96 	bl	8020d100 <strchr>
    80209eac:	aa0003f3 	mov	x19, x0
    80209eb0:	b5000060 	cbnz	x0, 80209ebc <_setlocale_r+0x1cc>
    80209eb4:	14000061 	b	8020a038 <_setlocale_r+0x348>
    80209eb8:	91000673 	add	x19, x19, #0x1
    80209ebc:	39400660 	ldrb	w0, [x19, #1]
    80209ec0:	7100bc1f 	cmp	w0, #0x2f
    80209ec4:	54ffffa0 	b.eq	80209eb8 <_setlocale_r+0x1c8>  // b.none
    80209ec8:	34fffe00 	cbz	w0, 80209e88 <_setlocale_r+0x198>
    80209ecc:	aa1603fa 	mov	x26, x22
    80209ed0:	52800034 	mov	w20, #0x1                   	// #1
    80209ed4:	cb190262 	sub	x2, x19, x25
    80209ed8:	71007c5f 	cmp	w2, #0x1f
    80209edc:	54fffd6c 	b.gt	80209e88 <_setlocale_r+0x198>
    80209ee0:	11000442 	add	w2, w2, #0x1
    80209ee4:	aa1903e1 	mov	x1, x25
    80209ee8:	aa1a03e0 	mov	x0, x26
    80209eec:	11000694 	add	w20, w20, #0x1
    80209ef0:	93407c42 	sxtw	x2, w2
    80209ef4:	940009eb 	bl	8020c6a0 <strlcpy>
    80209ef8:	39400261 	ldrb	w1, [x19]
    80209efc:	7100bc3f 	cmp	w1, #0x2f
    80209f00:	540000a1 	b.ne	80209f14 <_setlocale_r+0x224>  // b.any
    80209f04:	d503201f 	nop
    80209f08:	38401e61 	ldrb	w1, [x19, #1]!
    80209f0c:	7100bc3f 	cmp	w1, #0x2f
    80209f10:	54ffffc0 	b.eq	80209f08 <_setlocale_r+0x218>  // b.none
    80209f14:	34000ac1 	cbz	w1, 8020a06c <_setlocale_r+0x37c>
    80209f18:	aa1303e3 	mov	x3, x19
    80209f1c:	d503201f 	nop
    80209f20:	38401c61 	ldrb	w1, [x3, #1]!
    80209f24:	7100bc3f 	cmp	w1, #0x2f
    80209f28:	7a401824 	ccmp	w1, #0x0, #0x4, ne	// ne = any
    80209f2c:	54ffffa1 	b.ne	80209f20 <_setlocale_r+0x230>  // b.any
    80209f30:	9100835a 	add	x26, x26, #0x20
    80209f34:	71001e9f 	cmp	w20, #0x7
    80209f38:	54fff3e0 	b.eq	80209db4 <_setlocale_r+0xc4>  // b.none
    80209f3c:	aa1303f9 	mov	x25, x19
    80209f40:	aa0303f3 	mov	x19, x3
    80209f44:	17ffffe4 	b	80209ed4 <_setlocale_r+0x1e4>
    80209f48:	937b7c20 	sbfiz	x0, x1, #5, #32
    80209f4c:	90000041 	adrp	x1, 80211000 <__mprec_tens+0x180>
    80209f50:	912b4021 	add	x1, x1, #0xad0
    80209f54:	7100037f 	cmp	w27, #0x0
    80209f58:	8b010000 	add	x0, x0, x1
    80209f5c:	90000053 	adrp	x19, 80211000 <__mprec_tens+0x180>
    80209f60:	91278273 	add	x19, x19, #0x9e0
    80209f64:	9a800273 	csel	x19, x19, x0, eq	// eq = none
    80209f68:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209f6c:	aa1303e0 	mov	x0, x19
    80209f70:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209f74:	a94363f7 	ldp	x23, x24, [sp, #48]
    80209f78:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80209f7c:	f9402bfb 	ldr	x27, [sp, #80]
    80209f80:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80209f84:	d65f03c0 	ret
    80209f88:	2a1b03e1 	mov	w1, w27
    80209f8c:	aa1703e0 	mov	x0, x23
    80209f90:	97ffff38 	bl	80209c70 <__get_locale_env>
    80209f94:	aa0003f4 	mov	x20, x0
    80209f98:	97ffe45a 	bl	80203100 <strlen>
    80209f9c:	f1007c1f 	cmp	x0, #0x1f
    80209fa0:	54fff748 	b.hi	80209e88 <_setlocale_r+0x198>  // b.pmore
    80209fa4:	937b7f73 	sbfiz	x19, x27, #5, #32
    80209fa8:	aa1403e1 	mov	x1, x20
    80209fac:	8b130313 	add	x19, x24, x19
    80209fb0:	aa1303e0 	mov	x0, x19
    80209fb4:	94000ce3 	bl	8020d340 <strcpy>
    80209fb8:	17ffffa5 	b	80209e4c <_setlocale_r+0x15c>
    80209fbc:	f0000020 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    80209fc0:	b94002f5 	ldr	w21, [x23]
    80209fc4:	91154018 	add	x24, x0, #0x550
    80209fc8:	52800034 	mov	w20, #0x1                   	// #1
    80209fcc:	6b14027f 	cmp	w19, w20
    80209fd0:	540000e1 	b.ne	80209fec <_setlocale_r+0x2fc>  // b.any
    80209fd4:	14000016 	b	8020a02c <_setlocale_r+0x33c>
    80209fd8:	11000694 	add	w20, w20, #0x1
    80209fdc:	910082d6 	add	x22, x22, #0x20
    80209fe0:	9100835a 	add	x26, x26, #0x20
    80209fe4:	6b13029f 	cmp	w20, w19
    80209fe8:	54000220 	b.eq	8020a02c <_setlocale_r+0x33c>  // b.none
    80209fec:	aa1a03e1 	mov	x1, x26
    80209ff0:	aa1603e0 	mov	x0, x22
    80209ff4:	94000cd3 	bl	8020d340 <strcpy>
    80209ff8:	aa1603e2 	mov	x2, x22
    80209ffc:	2a1403e1 	mov	w1, w20
    8020a000:	aa1903e0 	mov	x0, x25
    8020a004:	97fffd37 	bl	802094e0 <__loadlocale>
    8020a008:	b5fffe80 	cbnz	x0, 80209fd8 <_setlocale_r+0x2e8>
    8020a00c:	aa1803e1 	mov	x1, x24
    8020a010:	aa1603e0 	mov	x0, x22
    8020a014:	94000ccb 	bl	8020d340 <strcpy>
    8020a018:	aa1603e2 	mov	x2, x22
    8020a01c:	2a1403e1 	mov	w1, w20
    8020a020:	aa1903e0 	mov	x0, x25
    8020a024:	97fffd2f 	bl	802094e0 <__loadlocale>
    8020a028:	17ffffec 	b	80209fd8 <_setlocale_r+0x2e8>
    8020a02c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020a030:	f9402bfb 	ldr	x27, [sp, #80]
    8020a034:	17ffff98 	b	80209e94 <_setlocale_r+0x1a4>
    8020a038:	aa1903e0 	mov	x0, x25
    8020a03c:	97ffe431 	bl	80203100 <strlen>
    8020a040:	f1007c1f 	cmp	x0, #0x1f
    8020a044:	54fff228 	b.hi	80209e88 <_setlocale_r+0x198>  // b.pmore
    8020a048:	aa1603f3 	mov	x19, x22
    8020a04c:	d503201f 	nop
    8020a050:	aa1303e0 	mov	x0, x19
    8020a054:	aa1903e1 	mov	x1, x25
    8020a058:	91008273 	add	x19, x19, #0x20
    8020a05c:	94000cb9 	bl	8020d340 <strcpy>
    8020a060:	eb13035f 	cmp	x26, x19
    8020a064:	54ffff61 	b.ne	8020a050 <_setlocale_r+0x360>  // b.any
    8020a068:	17ffff53 	b	80209db4 <_setlocale_r+0xc4>
    8020a06c:	71001e9f 	cmp	w20, #0x7
    8020a070:	54ffea20 	b.eq	80209db4 <_setlocale_r+0xc4>  // b.none
    8020a074:	937b7e93 	sbfiz	x19, x20, #5, #32
    8020a078:	8b130313 	add	x19, x24, x19
    8020a07c:	d503201f 	nop
    8020a080:	d1008261 	sub	x1, x19, #0x20
    8020a084:	aa1303e0 	mov	x0, x19
    8020a088:	11000694 	add	w20, w20, #0x1
    8020a08c:	94000cad 	bl	8020d340 <strcpy>
    8020a090:	91008273 	add	x19, x19, #0x20
    8020a094:	71001e9f 	cmp	w20, #0x7
    8020a098:	54ffff41 	b.ne	8020a080 <_setlocale_r+0x390>  // b.any
    8020a09c:	17ffff46 	b	80209db4 <_setlocale_r+0xc4>

000000008020a0a0 <__locale_mb_cur_max>:
    8020a0a0:	f0000020 	adrp	x0, 80211000 <__mprec_tens+0x180>
    8020a0a4:	3970c000 	ldrb	w0, [x0, #3120]
    8020a0a8:	d65f03c0 	ret
    8020a0ac:	00000000 	udf	#0

000000008020a0b0 <setlocale>:
    8020a0b0:	f0000023 	adrp	x3, 80211000 <__mprec_tens+0x180>
    8020a0b4:	aa0103e2 	mov	x2, x1
    8020a0b8:	2a0003e1 	mov	w1, w0
    8020a0bc:	f9402460 	ldr	x0, [x3, #72]
    8020a0c0:	17ffff0c 	b	80209cf0 <_setlocale_r>
	...

000000008020a0d0 <__localeconv_l>:
    8020a0d0:	91040000 	add	x0, x0, #0x100
    8020a0d4:	d65f03c0 	ret
	...

000000008020a0e0 <_localeconv_r>:
    8020a0e0:	f0000020 	adrp	x0, 80211000 <__mprec_tens+0x180>
    8020a0e4:	912f4000 	add	x0, x0, #0xbd0
    8020a0e8:	d65f03c0 	ret
    8020a0ec:	00000000 	udf	#0

000000008020a0f0 <localeconv>:
    8020a0f0:	f0000020 	adrp	x0, 80211000 <__mprec_tens+0x180>
    8020a0f4:	912f4000 	add	x0, x0, #0xbd0
    8020a0f8:	d65f03c0 	ret
    8020a0fc:	00000000 	udf	#0

000000008020a100 <_fclose_r>:
    8020a100:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020a104:	910003fd 	mov	x29, sp
    8020a108:	f90013f5 	str	x21, [sp, #32]
    8020a10c:	b4000661 	cbz	x1, 8020a1d8 <_fclose_r+0xd8>
    8020a110:	a90153f3 	stp	x19, x20, [sp, #16]
    8020a114:	aa0103f3 	mov	x19, x1
    8020a118:	aa0003f4 	mov	x20, x0
    8020a11c:	b4000060 	cbz	x0, 8020a128 <_fclose_r+0x28>
    8020a120:	f9402401 	ldr	x1, [x0, #72]
    8020a124:	b4000641 	cbz	x1, 8020a1ec <_fclose_r+0xec>
    8020a128:	b940b260 	ldr	w0, [x19, #176]
    8020a12c:	79c02261 	ldrsh	w1, [x19, #16]
    8020a130:	37000500 	tbnz	w0, #0, 8020a1d0 <_fclose_r+0xd0>
    8020a134:	36480601 	tbz	w1, #9, 8020a1f4 <_fclose_r+0xf4>
    8020a138:	aa1303e1 	mov	x1, x19
    8020a13c:	aa1403e0 	mov	x0, x20
    8020a140:	9400070c 	bl	8020bd70 <__sflush_r>
    8020a144:	2a0003f5 	mov	w21, w0
    8020a148:	f9402a62 	ldr	x2, [x19, #80]
    8020a14c:	b40000c2 	cbz	x2, 8020a164 <_fclose_r+0x64>
    8020a150:	f9401a61 	ldr	x1, [x19, #48]
    8020a154:	aa1403e0 	mov	x0, x20
    8020a158:	d63f0040 	blr	x2
    8020a15c:	7100001f 	cmp	w0, #0x0
    8020a160:	5a9fa2b5 	csinv	w21, w21, wzr, ge	// ge = tcont
    8020a164:	79402260 	ldrh	w0, [x19, #16]
    8020a168:	37380620 	tbnz	w0, #7, 8020a22c <_fclose_r+0x12c>
    8020a16c:	f9402e61 	ldr	x1, [x19, #88]
    8020a170:	b40000e1 	cbz	x1, 8020a18c <_fclose_r+0x8c>
    8020a174:	9101d260 	add	x0, x19, #0x74
    8020a178:	eb00003f 	cmp	x1, x0
    8020a17c:	54000060 	b.eq	8020a188 <_fclose_r+0x88>  // b.none
    8020a180:	aa1403e0 	mov	x0, x20
    8020a184:	9400099f 	bl	8020c800 <_free_r>
    8020a188:	f9002e7f 	str	xzr, [x19, #88]
    8020a18c:	f9403e61 	ldr	x1, [x19, #120]
    8020a190:	b4000081 	cbz	x1, 8020a1a0 <_fclose_r+0xa0>
    8020a194:	aa1403e0 	mov	x0, x20
    8020a198:	9400099a 	bl	8020c800 <_free_r>
    8020a19c:	f9003e7f 	str	xzr, [x19, #120]
    8020a1a0:	97ffe328 	bl	80202e40 <__sfp_lock_acquire>
    8020a1a4:	7900227f 	strh	wzr, [x19, #16]
    8020a1a8:	b940b260 	ldr	w0, [x19, #176]
    8020a1ac:	360003a0 	tbz	w0, #0, 8020a220 <_fclose_r+0x120>
    8020a1b0:	f9405260 	ldr	x0, [x19, #160]
    8020a1b4:	97fffc7b 	bl	802093a0 <__retarget_lock_close_recursive>
    8020a1b8:	97ffe326 	bl	80202e50 <__sfp_lock_release>
    8020a1bc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a1c0:	2a1503e0 	mov	w0, w21
    8020a1c4:	f94013f5 	ldr	x21, [sp, #32]
    8020a1c8:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020a1cc:	d65f03c0 	ret
    8020a1d0:	35fffb41 	cbnz	w1, 8020a138 <_fclose_r+0x38>
    8020a1d4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a1d8:	52800015 	mov	w21, #0x0                   	// #0
    8020a1dc:	2a1503e0 	mov	w0, w21
    8020a1e0:	f94013f5 	ldr	x21, [sp, #32]
    8020a1e4:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020a1e8:	d65f03c0 	ret
    8020a1ec:	97ffe2f9 	bl	80202dd0 <__sinit>
    8020a1f0:	17ffffce 	b	8020a128 <_fclose_r+0x28>
    8020a1f4:	f9405260 	ldr	x0, [x19, #160]
    8020a1f8:	97fffc72 	bl	802093c0 <__retarget_lock_acquire_recursive>
    8020a1fc:	79c02260 	ldrsh	w0, [x19, #16]
    8020a200:	35fff9c0 	cbnz	w0, 8020a138 <_fclose_r+0x38>
    8020a204:	b940b260 	ldr	w0, [x19, #176]
    8020a208:	3707fe60 	tbnz	w0, #0, 8020a1d4 <_fclose_r+0xd4>
    8020a20c:	f9405260 	ldr	x0, [x19, #160]
    8020a210:	52800015 	mov	w21, #0x0                   	// #0
    8020a214:	97fffc7b 	bl	80209400 <__retarget_lock_release_recursive>
    8020a218:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a21c:	17fffff0 	b	8020a1dc <_fclose_r+0xdc>
    8020a220:	f9405260 	ldr	x0, [x19, #160]
    8020a224:	97fffc77 	bl	80209400 <__retarget_lock_release_recursive>
    8020a228:	17ffffe2 	b	8020a1b0 <_fclose_r+0xb0>
    8020a22c:	f9400e61 	ldr	x1, [x19, #24]
    8020a230:	aa1403e0 	mov	x0, x20
    8020a234:	94000973 	bl	8020c800 <_free_r>
    8020a238:	17ffffcd 	b	8020a16c <_fclose_r+0x6c>
    8020a23c:	00000000 	udf	#0

000000008020a240 <fclose>:
    8020a240:	f0000022 	adrp	x2, 80211000 <__mprec_tens+0x180>
    8020a244:	aa0003e1 	mov	x1, x0
    8020a248:	f9402440 	ldr	x0, [x2, #72]
    8020a24c:	17ffffad 	b	8020a100 <_fclose_r>
	...

000000008020a280 <memchr>:
    8020a280:	d503245f 	bti	c
    8020a284:	b4000682 	cbz	x2, 8020a354 <memchr+0xd4>
    8020a288:	52808025 	mov	w5, #0x401                 	// #1025
    8020a28c:	72a80205 	movk	w5, #0x4010, lsl #16
    8020a290:	4e010c20 	dup	v0.16b, w1
    8020a294:	927be803 	and	x3, x0, #0xffffffffffffffe0
    8020a298:	4e040ca5 	dup	v5.4s, w5
    8020a29c:	f2401009 	ands	x9, x0, #0x1f
    8020a2a0:	9240104a 	and	x10, x2, #0x1f
    8020a2a4:	54000200 	b.eq	8020a2e4 <memchr+0x64>  // b.none
    8020a2a8:	4cdfa061 	ld1	{v1.16b-v2.16b}, [x3], #32
    8020a2ac:	d1008124 	sub	x4, x9, #0x20
    8020a2b0:	ab040042 	adds	x2, x2, x4
    8020a2b4:	6e208c23 	cmeq	v3.16b, v1.16b, v0.16b
    8020a2b8:	6e208c44 	cmeq	v4.16b, v2.16b, v0.16b
    8020a2bc:	4e251c63 	and	v3.16b, v3.16b, v5.16b
    8020a2c0:	4e251c84 	and	v4.16b, v4.16b, v5.16b
    8020a2c4:	4e24bc66 	addp	v6.16b, v3.16b, v4.16b
    8020a2c8:	4e26bcc6 	addp	v6.16b, v6.16b, v6.16b
    8020a2cc:	4e083cc6 	mov	x6, v6.d[0]
    8020a2d0:	d37ff924 	lsl	x4, x9, #1
    8020a2d4:	9ac424c6 	lsr	x6, x6, x4
    8020a2d8:	9ac420c6 	lsl	x6, x6, x4
    8020a2dc:	54000229 	b.ls	8020a320 <memchr+0xa0>  // b.plast
    8020a2e0:	b50002c6 	cbnz	x6, 8020a338 <memchr+0xb8>
    8020a2e4:	4cdfa061 	ld1	{v1.16b-v2.16b}, [x3], #32
    8020a2e8:	f1008042 	subs	x2, x2, #0x20
    8020a2ec:	6e208c23 	cmeq	v3.16b, v1.16b, v0.16b
    8020a2f0:	6e208c44 	cmeq	v4.16b, v2.16b, v0.16b
    8020a2f4:	540000a9 	b.ls	8020a308 <memchr+0x88>  // b.plast
    8020a2f8:	4ea41c66 	orr	v6.16b, v3.16b, v4.16b
    8020a2fc:	4ee6bcc6 	addp	v6.2d, v6.2d, v6.2d
    8020a300:	4e083cc6 	mov	x6, v6.d[0]
    8020a304:	b4ffff06 	cbz	x6, 8020a2e4 <memchr+0x64>
    8020a308:	4e251c63 	and	v3.16b, v3.16b, v5.16b
    8020a30c:	4e251c84 	and	v4.16b, v4.16b, v5.16b
    8020a310:	4e24bc66 	addp	v6.16b, v3.16b, v4.16b
    8020a314:	4e26bcc6 	addp	v6.16b, v6.16b, v6.16b
    8020a318:	4e083cc6 	mov	x6, v6.d[0]
    8020a31c:	540000e2 	b.cs	8020a338 <memchr+0xb8>  // b.hs, b.nlast
    8020a320:	8b090144 	add	x4, x10, x9
    8020a324:	92401084 	and	x4, x4, #0x1f
    8020a328:	d1008084 	sub	x4, x4, #0x20
    8020a32c:	cb0407e4 	neg	x4, x4, lsl #1
    8020a330:	9ac420c6 	lsl	x6, x6, x4
    8020a334:	9ac424c6 	lsr	x6, x6, x4
    8020a338:	dac000c6 	rbit	x6, x6
    8020a33c:	d1008063 	sub	x3, x3, #0x20
    8020a340:	f10000df 	cmp	x6, #0x0
    8020a344:	dac010c6 	clz	x6, x6
    8020a348:	8b460460 	add	x0, x3, x6, lsr #1
    8020a34c:	9a8003e0 	csel	x0, xzr, x0, eq	// eq = none
    8020a350:	d65f03c0 	ret
    8020a354:	d2800000 	mov	x0, #0x0                   	// #0
    8020a358:	d65f03c0 	ret
    8020a35c:	00000000 	udf	#0

000000008020a360 <__swsetup_r>:
    8020a360:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020a364:	f0000022 	adrp	x2, 80211000 <__mprec_tens+0x180>
    8020a368:	910003fd 	mov	x29, sp
    8020a36c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020a370:	aa0003f4 	mov	x20, x0
    8020a374:	aa0103f3 	mov	x19, x1
    8020a378:	f9402440 	ldr	x0, [x2, #72]
    8020a37c:	b4000060 	cbz	x0, 8020a388 <__swsetup_r+0x28>
    8020a380:	f9402401 	ldr	x1, [x0, #72]
    8020a384:	b4000761 	cbz	x1, 8020a470 <__swsetup_r+0x110>
    8020a388:	79c02262 	ldrsh	w2, [x19, #16]
    8020a38c:	36180462 	tbz	w2, #3, 8020a418 <__swsetup_r+0xb8>
    8020a390:	f9400e61 	ldr	x1, [x19, #24]
    8020a394:	b40002c1 	cbz	x1, 8020a3ec <__swsetup_r+0x8c>
    8020a398:	36000142 	tbz	w2, #0, 8020a3c0 <__swsetup_r+0x60>
    8020a39c:	b9402260 	ldr	w0, [x19, #32]
    8020a3a0:	b9000e7f 	str	wzr, [x19, #12]
    8020a3a4:	4b0003e0 	neg	w0, w0
    8020a3a8:	b9002a60 	str	w0, [x19, #40]
    8020a3ac:	52800000 	mov	w0, #0x0                   	// #0
    8020a3b0:	b4000141 	cbz	x1, 8020a3d8 <__swsetup_r+0x78>
    8020a3b4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a3b8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020a3bc:	d65f03c0 	ret
    8020a3c0:	52800000 	mov	w0, #0x0                   	// #0
    8020a3c4:	37080042 	tbnz	w2, #1, 8020a3cc <__swsetup_r+0x6c>
    8020a3c8:	b9402260 	ldr	w0, [x19, #32]
    8020a3cc:	b9000e60 	str	w0, [x19, #12]
    8020a3d0:	52800000 	mov	w0, #0x0                   	// #0
    8020a3d4:	b5ffff01 	cbnz	x1, 8020a3b4 <__swsetup_r+0x54>
    8020a3d8:	363ffee2 	tbz	w2, #7, 8020a3b4 <__swsetup_r+0x54>
    8020a3dc:	321a0042 	orr	w2, w2, #0x40
    8020a3e0:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020a3e4:	79002262 	strh	w2, [x19, #16]
    8020a3e8:	17fffff3 	b	8020a3b4 <__swsetup_r+0x54>
    8020a3ec:	52805000 	mov	w0, #0x280                 	// #640
    8020a3f0:	0a000040 	and	w0, w2, w0
    8020a3f4:	7108001f 	cmp	w0, #0x200
    8020a3f8:	54fffd00 	b.eq	8020a398 <__swsetup_r+0x38>  // b.none
    8020a3fc:	aa1303e1 	mov	x1, x19
    8020a400:	aa1403e0 	mov	x0, x20
    8020a404:	94000023 	bl	8020a490 <__smakebuf_r>
    8020a408:	79c02262 	ldrsh	w2, [x19, #16]
    8020a40c:	f9400e61 	ldr	x1, [x19, #24]
    8020a410:	3607fd82 	tbz	w2, #0, 8020a3c0 <__swsetup_r+0x60>
    8020a414:	17ffffe2 	b	8020a39c <__swsetup_r+0x3c>
    8020a418:	36200302 	tbz	w2, #4, 8020a478 <__swsetup_r+0x118>
    8020a41c:	371000c2 	tbnz	w2, #2, 8020a434 <__swsetup_r+0xd4>
    8020a420:	f9400e61 	ldr	x1, [x19, #24]
    8020a424:	321d0042 	orr	w2, w2, #0x8
    8020a428:	79002262 	strh	w2, [x19, #16]
    8020a42c:	b5fffb61 	cbnz	x1, 8020a398 <__swsetup_r+0x38>
    8020a430:	17ffffef 	b	8020a3ec <__swsetup_r+0x8c>
    8020a434:	f9402e61 	ldr	x1, [x19, #88]
    8020a438:	b4000101 	cbz	x1, 8020a458 <__swsetup_r+0xf8>
    8020a43c:	9101d260 	add	x0, x19, #0x74
    8020a440:	eb00003f 	cmp	x1, x0
    8020a444:	54000080 	b.eq	8020a454 <__swsetup_r+0xf4>  // b.none
    8020a448:	aa1403e0 	mov	x0, x20
    8020a44c:	940008ed 	bl	8020c800 <_free_r>
    8020a450:	79c02262 	ldrsh	w2, [x19, #16]
    8020a454:	f9002e7f 	str	xzr, [x19, #88]
    8020a458:	f9400e61 	ldr	x1, [x19, #24]
    8020a45c:	12800480 	mov	w0, #0xffffffdb            	// #-37
    8020a460:	0a000042 	and	w2, w2, w0
    8020a464:	f9000261 	str	x1, [x19]
    8020a468:	b9000a7f 	str	wzr, [x19, #8]
    8020a46c:	17ffffee 	b	8020a424 <__swsetup_r+0xc4>
    8020a470:	97ffe258 	bl	80202dd0 <__sinit>
    8020a474:	17ffffc5 	b	8020a388 <__swsetup_r+0x28>
    8020a478:	52800120 	mov	w0, #0x9                   	// #9
    8020a47c:	b9000280 	str	w0, [x20]
    8020a480:	321a0042 	orr	w2, w2, #0x40
    8020a484:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020a488:	79002262 	strh	w2, [x19, #16]
    8020a48c:	17ffffca 	b	8020a3b4 <__swsetup_r+0x54>

000000008020a490 <__smakebuf_r>:
    8020a490:	a9b57bfd 	stp	x29, x30, [sp, #-176]!
    8020a494:	910003fd 	mov	x29, sp
    8020a498:	79c02022 	ldrsh	w2, [x1, #16]
    8020a49c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020a4a0:	aa0103f3 	mov	x19, x1
    8020a4a4:	36080122 	tbz	w2, #1, 8020a4c8 <__smakebuf_r+0x38>
    8020a4a8:	9101dc20 	add	x0, x1, #0x77
    8020a4ac:	52800021 	mov	w1, #0x1                   	// #1
    8020a4b0:	f9000260 	str	x0, [x19]
    8020a4b4:	f9000e60 	str	x0, [x19, #24]
    8020a4b8:	b9002261 	str	w1, [x19, #32]
    8020a4bc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a4c0:	a8cb7bfd 	ldp	x29, x30, [sp], #176
    8020a4c4:	d65f03c0 	ret
    8020a4c8:	79c02421 	ldrsh	w1, [x1, #18]
    8020a4cc:	aa0003f4 	mov	x20, x0
    8020a4d0:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020a4d4:	f9001bf7 	str	x23, [sp, #48]
    8020a4d8:	37f80381 	tbnz	w1, #31, 8020a548 <__smakebuf_r+0xb8>
    8020a4dc:	910123e2 	add	x2, sp, #0x48
    8020a4e0:	94000aa4 	bl	8020cf70 <_fstat_r>
    8020a4e4:	37f80300 	tbnz	w0, #31, 8020a544 <__smakebuf_r+0xb4>
    8020a4e8:	b9404fe0 	ldr	w0, [sp, #76]
    8020a4ec:	d2808016 	mov	x22, #0x400                 	// #1024
    8020a4f0:	52810015 	mov	w21, #0x800                 	// #2048
    8020a4f4:	aa1603e1 	mov	x1, x22
    8020a4f8:	12140c00 	and	w0, w0, #0xf000
    8020a4fc:	7140081f 	cmp	w0, #0x2, lsl #12
    8020a500:	aa1403e0 	mov	x0, x20
    8020a504:	1a9f17f7 	cset	w23, eq	// eq = none
    8020a508:	97fff94e 	bl	80208a40 <_malloc_r>
    8020a50c:	b5000320 	cbnz	x0, 8020a570 <__smakebuf_r+0xe0>
    8020a510:	79c02260 	ldrsh	w0, [x19, #16]
    8020a514:	37480560 	tbnz	w0, #9, 8020a5c0 <__smakebuf_r+0x130>
    8020a518:	121e7400 	and	w0, w0, #0xfffffffc
    8020a51c:	9101de61 	add	x1, x19, #0x77
    8020a520:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020a524:	321f0000 	orr	w0, w0, #0x2
    8020a528:	f9401bf7 	ldr	x23, [sp, #48]
    8020a52c:	52800022 	mov	w2, #0x1                   	// #1
    8020a530:	f9000261 	str	x1, [x19]
    8020a534:	79002260 	strh	w0, [x19, #16]
    8020a538:	f9000e61 	str	x1, [x19, #24]
    8020a53c:	b9002262 	str	w2, [x19, #32]
    8020a540:	17ffffdf 	b	8020a4bc <__smakebuf_r+0x2c>
    8020a544:	79c02262 	ldrsh	w2, [x19, #16]
    8020a548:	f279005f 	tst	x2, #0x80
    8020a54c:	d2800800 	mov	x0, #0x40                  	// #64
    8020a550:	d2808016 	mov	x22, #0x400                 	// #1024
    8020a554:	9a8002d6 	csel	x22, x22, x0, eq	// eq = none
    8020a558:	aa1603e1 	mov	x1, x22
    8020a55c:	aa1403e0 	mov	x0, x20
    8020a560:	52800017 	mov	w23, #0x0                   	// #0
    8020a564:	52800015 	mov	w21, #0x0                   	// #0
    8020a568:	97fff936 	bl	80208a40 <_malloc_r>
    8020a56c:	b4fffd20 	cbz	x0, 8020a510 <__smakebuf_r+0x80>
    8020a570:	79c02262 	ldrsh	w2, [x19, #16]
    8020a574:	f9000260 	str	x0, [x19]
    8020a578:	32190042 	orr	w2, w2, #0x80
    8020a57c:	79002262 	strh	w2, [x19, #16]
    8020a580:	f9000e60 	str	x0, [x19, #24]
    8020a584:	b9002276 	str	w22, [x19, #32]
    8020a588:	35000117 	cbnz	w23, 8020a5a8 <__smakebuf_r+0x118>
    8020a58c:	2a150042 	orr	w2, w2, w21
    8020a590:	79002262 	strh	w2, [x19, #16]
    8020a594:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a598:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020a59c:	f9401bf7 	ldr	x23, [sp, #48]
    8020a5a0:	a8cb7bfd 	ldp	x29, x30, [sp], #176
    8020a5a4:	d65f03c0 	ret
    8020a5a8:	79c02661 	ldrsh	w1, [x19, #18]
    8020a5ac:	aa1403e0 	mov	x0, x20
    8020a5b0:	94000a84 	bl	8020cfc0 <_isatty_r>
    8020a5b4:	350000c0 	cbnz	w0, 8020a5cc <__smakebuf_r+0x13c>
    8020a5b8:	79c02262 	ldrsh	w2, [x19, #16]
    8020a5bc:	17fffff4 	b	8020a58c <__smakebuf_r+0xfc>
    8020a5c0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020a5c4:	f9401bf7 	ldr	x23, [sp, #48]
    8020a5c8:	17ffffbd 	b	8020a4bc <__smakebuf_r+0x2c>
    8020a5cc:	79402262 	ldrh	w2, [x19, #16]
    8020a5d0:	121e7442 	and	w2, w2, #0xfffffffc
    8020a5d4:	32000042 	orr	w2, w2, #0x1
    8020a5d8:	13003c42 	sxth	w2, w2
    8020a5dc:	17ffffec 	b	8020a58c <__smakebuf_r+0xfc>

000000008020a5e0 <__swhatbuf_r>:
    8020a5e0:	a9b67bfd 	stp	x29, x30, [sp, #-160]!
    8020a5e4:	910003fd 	mov	x29, sp
    8020a5e8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020a5ec:	aa0103f3 	mov	x19, x1
    8020a5f0:	79c02421 	ldrsh	w1, [x1, #18]
    8020a5f4:	f90013f5 	str	x21, [sp, #32]
    8020a5f8:	aa0203f4 	mov	x20, x2
    8020a5fc:	aa0303f5 	mov	x21, x3
    8020a600:	37f80201 	tbnz	w1, #31, 8020a640 <__swhatbuf_r+0x60>
    8020a604:	9100e3e2 	add	x2, sp, #0x38
    8020a608:	94000a5a 	bl	8020cf70 <_fstat_r>
    8020a60c:	37f801a0 	tbnz	w0, #31, 8020a640 <__swhatbuf_r+0x60>
    8020a610:	b9403fe2 	ldr	w2, [sp, #60]
    8020a614:	d2808001 	mov	x1, #0x400                 	// #1024
    8020a618:	52810000 	mov	w0, #0x800                 	// #2048
    8020a61c:	12140c42 	and	w2, w2, #0xf000
    8020a620:	7140085f 	cmp	w2, #0x2, lsl #12
    8020a624:	1a9f17e2 	cset	w2, eq	// eq = none
    8020a628:	b90002a2 	str	w2, [x21]
    8020a62c:	f94013f5 	ldr	x21, [sp, #32]
    8020a630:	f9000281 	str	x1, [x20]
    8020a634:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a638:	a8ca7bfd 	ldp	x29, x30, [sp], #160
    8020a63c:	d65f03c0 	ret
    8020a640:	79402264 	ldrh	w4, [x19, #16]
    8020a644:	52800002 	mov	w2, #0x0                   	// #0
    8020a648:	b90002a2 	str	w2, [x21]
    8020a64c:	d2808003 	mov	x3, #0x400                 	// #1024
    8020a650:	f94013f5 	ldr	x21, [sp, #32]
    8020a654:	f279009f 	tst	x4, #0x80
    8020a658:	d2800801 	mov	x1, #0x40                  	// #64
    8020a65c:	9a831021 	csel	x1, x1, x3, ne	// ne = any
    8020a660:	f9000281 	str	x1, [x20]
    8020a664:	52800000 	mov	w0, #0x0                   	// #0
    8020a668:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a66c:	a8ca7bfd 	ldp	x29, x30, [sp], #160
    8020a670:	d65f03c0 	ret
	...

000000008020a680 <memcpy>:
    8020a680:	d503245f 	bti	c
    8020a684:	8b020024 	add	x4, x1, x2
    8020a688:	8b020005 	add	x5, x0, x2
    8020a68c:	f102005f 	cmp	x2, #0x80
    8020a690:	54000788 	b.hi	8020a780 <memcpy+0x100>  // b.pmore
    8020a694:	f100805f 	cmp	x2, #0x20
    8020a698:	540003c8 	b.hi	8020a710 <memcpy+0x90>  // b.pmore
    8020a69c:	f100405f 	cmp	x2, #0x10
    8020a6a0:	540000c3 	b.cc	8020a6b8 <memcpy+0x38>  // b.lo, b.ul, b.last
    8020a6a4:	a9401c26 	ldp	x6, x7, [x1]
    8020a6a8:	a97f348c 	ldp	x12, x13, [x4, #-16]
    8020a6ac:	a9001c06 	stp	x6, x7, [x0]
    8020a6b0:	a93f34ac 	stp	x12, x13, [x5, #-16]
    8020a6b4:	d65f03c0 	ret
    8020a6b8:	361800c2 	tbz	w2, #3, 8020a6d0 <memcpy+0x50>
    8020a6bc:	f9400026 	ldr	x6, [x1]
    8020a6c0:	f85f8087 	ldur	x7, [x4, #-8]
    8020a6c4:	f9000006 	str	x6, [x0]
    8020a6c8:	f81f80a7 	stur	x7, [x5, #-8]
    8020a6cc:	d65f03c0 	ret
    8020a6d0:	361000c2 	tbz	w2, #2, 8020a6e8 <memcpy+0x68>
    8020a6d4:	b9400026 	ldr	w6, [x1]
    8020a6d8:	b85fc088 	ldur	w8, [x4, #-4]
    8020a6dc:	b9000006 	str	w6, [x0]
    8020a6e0:	b81fc0a8 	stur	w8, [x5, #-4]
    8020a6e4:	d65f03c0 	ret
    8020a6e8:	b4000102 	cbz	x2, 8020a708 <memcpy+0x88>
    8020a6ec:	d341fc4e 	lsr	x14, x2, #1
    8020a6f0:	39400026 	ldrb	w6, [x1]
    8020a6f4:	385ff08a 	ldurb	w10, [x4, #-1]
    8020a6f8:	386e6828 	ldrb	w8, [x1, x14]
    8020a6fc:	39000006 	strb	w6, [x0]
    8020a700:	382e6808 	strb	w8, [x0, x14]
    8020a704:	381ff0aa 	sturb	w10, [x5, #-1]
    8020a708:	d65f03c0 	ret
    8020a70c:	d503201f 	nop
    8020a710:	a9401c26 	ldp	x6, x7, [x1]
    8020a714:	a9412428 	ldp	x8, x9, [x1, #16]
    8020a718:	a97e2c8a 	ldp	x10, x11, [x4, #-32]
    8020a71c:	a97f348c 	ldp	x12, x13, [x4, #-16]
    8020a720:	f101005f 	cmp	x2, #0x40
    8020a724:	540000e8 	b.hi	8020a740 <memcpy+0xc0>  // b.pmore
    8020a728:	a9001c06 	stp	x6, x7, [x0]
    8020a72c:	a9012408 	stp	x8, x9, [x0, #16]
    8020a730:	a93e2caa 	stp	x10, x11, [x5, #-32]
    8020a734:	a93f34ac 	stp	x12, x13, [x5, #-16]
    8020a738:	d65f03c0 	ret
    8020a73c:	d503201f 	nop
    8020a740:	a9423c2e 	ldp	x14, x15, [x1, #32]
    8020a744:	a9434430 	ldp	x16, x17, [x1, #48]
    8020a748:	f101805f 	cmp	x2, #0x60
    8020a74c:	540000a9 	b.ls	8020a760 <memcpy+0xe0>  // b.plast
    8020a750:	a97c0c82 	ldp	x2, x3, [x4, #-64]
    8020a754:	a97d1081 	ldp	x1, x4, [x4, #-48]
    8020a758:	a93c0ca2 	stp	x2, x3, [x5, #-64]
    8020a75c:	a93d10a1 	stp	x1, x4, [x5, #-48]
    8020a760:	a9001c06 	stp	x6, x7, [x0]
    8020a764:	a9012408 	stp	x8, x9, [x0, #16]
    8020a768:	a9023c0e 	stp	x14, x15, [x0, #32]
    8020a76c:	a9034410 	stp	x16, x17, [x0, #48]
    8020a770:	a93e2caa 	stp	x10, x11, [x5, #-32]
    8020a774:	a93f34ac 	stp	x12, x13, [x5, #-16]
    8020a778:	d65f03c0 	ret
    8020a77c:	d503201f 	nop
    8020a780:	cb01000e 	sub	x14, x0, x1
    8020a784:	b4fffc2e 	cbz	x14, 8020a708 <memcpy+0x88>
    8020a788:	eb0201df 	cmp	x14, x2
    8020a78c:	540004a3 	b.cc	8020a820 <memcpy+0x1a0>  // b.lo, b.ul, b.last
    8020a790:	a940342c 	ldp	x12, x13, [x1]
    8020a794:	92400c0e 	and	x14, x0, #0xf
    8020a798:	927cec03 	and	x3, x0, #0xfffffffffffffff0
    8020a79c:	cb0e0021 	sub	x1, x1, x14
    8020a7a0:	8b0e0042 	add	x2, x2, x14
    8020a7a4:	a9411c26 	ldp	x6, x7, [x1, #16]
    8020a7a8:	a900340c 	stp	x12, x13, [x0]
    8020a7ac:	a9422428 	ldp	x8, x9, [x1, #32]
    8020a7b0:	a9432c2a 	ldp	x10, x11, [x1, #48]
    8020a7b4:	a9c4342c 	ldp	x12, x13, [x1, #64]!
    8020a7b8:	f1024042 	subs	x2, x2, #0x90
    8020a7bc:	54000169 	b.ls	8020a7e8 <memcpy+0x168>  // b.plast
    8020a7c0:	a9011c66 	stp	x6, x7, [x3, #16]
    8020a7c4:	a9411c26 	ldp	x6, x7, [x1, #16]
    8020a7c8:	a9022468 	stp	x8, x9, [x3, #32]
    8020a7cc:	a9422428 	ldp	x8, x9, [x1, #32]
    8020a7d0:	a9032c6a 	stp	x10, x11, [x3, #48]
    8020a7d4:	a9432c2a 	ldp	x10, x11, [x1, #48]
    8020a7d8:	a984346c 	stp	x12, x13, [x3, #64]!
    8020a7dc:	a9c4342c 	ldp	x12, x13, [x1, #64]!
    8020a7e0:	f1010042 	subs	x2, x2, #0x40
    8020a7e4:	54fffee8 	b.hi	8020a7c0 <memcpy+0x140>  // b.pmore
    8020a7e8:	a97c3c8e 	ldp	x14, x15, [x4, #-64]
    8020a7ec:	a9011c66 	stp	x6, x7, [x3, #16]
    8020a7f0:	a97d1c86 	ldp	x6, x7, [x4, #-48]
    8020a7f4:	a9022468 	stp	x8, x9, [x3, #32]
    8020a7f8:	a97e2488 	ldp	x8, x9, [x4, #-32]
    8020a7fc:	a9032c6a 	stp	x10, x11, [x3, #48]
    8020a800:	a97f2c8a 	ldp	x10, x11, [x4, #-16]
    8020a804:	a904346c 	stp	x12, x13, [x3, #64]
    8020a808:	a93c3cae 	stp	x14, x15, [x5, #-64]
    8020a80c:	a93d1ca6 	stp	x6, x7, [x5, #-48]
    8020a810:	a93e24a8 	stp	x8, x9, [x5, #-32]
    8020a814:	a93f2caa 	stp	x10, x11, [x5, #-16]
    8020a818:	d65f03c0 	ret
    8020a81c:	d503201f 	nop
    8020a820:	a97f348c 	ldp	x12, x13, [x4, #-16]
    8020a824:	92400cae 	and	x14, x5, #0xf
    8020a828:	cb0e0084 	sub	x4, x4, x14
    8020a82c:	cb0e0042 	sub	x2, x2, x14
    8020a830:	a97f1c86 	ldp	x6, x7, [x4, #-16]
    8020a834:	a93f34ac 	stp	x12, x13, [x5, #-16]
    8020a838:	a97e2488 	ldp	x8, x9, [x4, #-32]
    8020a83c:	a97d2c8a 	ldp	x10, x11, [x4, #-48]
    8020a840:	a9fc348c 	ldp	x12, x13, [x4, #-64]!
    8020a844:	cb0e00a5 	sub	x5, x5, x14
    8020a848:	f1020042 	subs	x2, x2, #0x80
    8020a84c:	54000169 	b.ls	8020a878 <memcpy+0x1f8>  // b.plast
    8020a850:	a93f1ca6 	stp	x6, x7, [x5, #-16]
    8020a854:	a97f1c86 	ldp	x6, x7, [x4, #-16]
    8020a858:	a93e24a8 	stp	x8, x9, [x5, #-32]
    8020a85c:	a97e2488 	ldp	x8, x9, [x4, #-32]
    8020a860:	a93d2caa 	stp	x10, x11, [x5, #-48]
    8020a864:	a97d2c8a 	ldp	x10, x11, [x4, #-48]
    8020a868:	a9bc34ac 	stp	x12, x13, [x5, #-64]!
    8020a86c:	a9fc348c 	ldp	x12, x13, [x4, #-64]!
    8020a870:	f1010042 	subs	x2, x2, #0x40
    8020a874:	54fffee8 	b.hi	8020a850 <memcpy+0x1d0>  // b.pmore
    8020a878:	a9430c22 	ldp	x2, x3, [x1, #48]
    8020a87c:	a93f1ca6 	stp	x6, x7, [x5, #-16]
    8020a880:	a9421c26 	ldp	x6, x7, [x1, #32]
    8020a884:	a93e24a8 	stp	x8, x9, [x5, #-32]
    8020a888:	a9412428 	ldp	x8, x9, [x1, #16]
    8020a88c:	a93d2caa 	stp	x10, x11, [x5, #-48]
    8020a890:	a9402c2a 	ldp	x10, x11, [x1]
    8020a894:	a93c34ac 	stp	x12, x13, [x5, #-64]
    8020a898:	a9030c02 	stp	x2, x3, [x0, #48]
    8020a89c:	a9021c06 	stp	x6, x7, [x0, #32]
    8020a8a0:	a9012408 	stp	x8, x9, [x0, #16]
    8020a8a4:	a9002c0a 	stp	x10, x11, [x0]
    8020a8a8:	d65f03c0 	ret
    8020a8ac:	00000000 	udf	#0

000000008020a8b0 <__malloc_lock>:
    8020a8b0:	d00003a0 	adrp	x0, 80280000 <gits_lock>
    8020a8b4:	910a8000 	add	x0, x0, #0x2a0
    8020a8b8:	17fffac2 	b	802093c0 <__retarget_lock_acquire_recursive>
    8020a8bc:	00000000 	udf	#0

000000008020a8c0 <__malloc_unlock>:
    8020a8c0:	d00003a0 	adrp	x0, 80280000 <gits_lock>
    8020a8c4:	910a8000 	add	x0, x0, #0x2a0
    8020a8c8:	17ffface 	b	80209400 <__retarget_lock_release_recursive>
    8020a8cc:	00000000 	udf	#0

000000008020a8d0 <_wcsrtombs_r>:
    8020a8d0:	aa0403e5 	mov	x5, x4
    8020a8d4:	aa0303e4 	mov	x4, x3
    8020a8d8:	92800003 	mov	x3, #0xffffffffffffffff    	// #-1
    8020a8dc:	140013f1 	b	8020f8a0 <_wcsnrtombs_r>

000000008020a8e0 <wcsrtombs>:
    8020a8e0:	f0000026 	adrp	x6, 80211000 <__mprec_tens+0x180>
    8020a8e4:	aa0003e4 	mov	x4, x0
    8020a8e8:	aa0103e5 	mov	x5, x1
    8020a8ec:	aa0403e1 	mov	x1, x4
    8020a8f0:	f94024c0 	ldr	x0, [x6, #72]
    8020a8f4:	aa0203e4 	mov	x4, x2
    8020a8f8:	aa0503e2 	mov	x2, x5
    8020a8fc:	aa0303e5 	mov	x5, x3
    8020a900:	92800003 	mov	x3, #0xffffffffffffffff    	// #-1
    8020a904:	140013e7 	b	8020f8a0 <_wcsnrtombs_r>
	...

000000008020a910 <quorem>:
    8020a910:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020a914:	910003fd 	mov	x29, sp
    8020a918:	a90153f3 	stp	x19, x20, [sp, #16]
    8020a91c:	b9401434 	ldr	w20, [x1, #20]
    8020a920:	a90363f7 	stp	x23, x24, [sp, #48]
    8020a924:	aa0003f8 	mov	x24, x0
    8020a928:	b9401400 	ldr	w0, [x0, #20]
    8020a92c:	6b14001f 	cmp	w0, w20
    8020a930:	54000b8b 	b.lt	8020aaa0 <quorem+0x190>  // b.tstop
    8020a934:	51000694 	sub	w20, w20, #0x1
    8020a938:	91006033 	add	x19, x1, #0x18
    8020a93c:	91006317 	add	x23, x24, #0x18
    8020a940:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020a944:	93407e8a 	sxtw	x10, w20
    8020a948:	937e7e80 	sbfiz	x0, x20, #2, #32
    8020a94c:	8b000276 	add	x22, x19, x0
    8020a950:	8b0002eb 	add	x11, x23, x0
    8020a954:	b86a7a62 	ldr	w2, [x19, x10, lsl #2]
    8020a958:	b86a7ae3 	ldr	w3, [x23, x10, lsl #2]
    8020a95c:	11000442 	add	w2, w2, #0x1
    8020a960:	1ac20875 	udiv	w21, w3, w2
    8020a964:	6b02007f 	cmp	w3, w2
    8020a968:	540004c3 	b.cc	8020aa00 <quorem+0xf0>  // b.lo, b.ul, b.last
    8020a96c:	aa1303e7 	mov	x7, x19
    8020a970:	aa1703e6 	mov	x6, x23
    8020a974:	52800009 	mov	w9, #0x0                   	// #0
    8020a978:	52800008 	mov	w8, #0x0                   	// #0
    8020a97c:	d503201f 	nop
    8020a980:	b84044e3 	ldr	w3, [x7], #4
    8020a984:	b94000c4 	ldr	w4, [x6]
    8020a988:	12003c65 	and	w5, w3, #0xffff
    8020a98c:	53107c63 	lsr	w3, w3, #16
    8020a990:	12003c82 	and	w2, w4, #0xffff
    8020a994:	1b1524a5 	madd	w5, w5, w21, w9
    8020a998:	53107ca9 	lsr	w9, w5, #16
    8020a99c:	4b252042 	sub	w2, w2, w5, uxth
    8020a9a0:	0b080042 	add	w2, w2, w8
    8020a9a4:	1b152463 	madd	w3, w3, w21, w9
    8020a9a8:	13107c40 	asr	w0, w2, #16
    8020a9ac:	4b232000 	sub	w0, w0, w3, uxth
    8020a9b0:	53107c69 	lsr	w9, w3, #16
    8020a9b4:	0b444003 	add	w3, w0, w4, lsr #16
    8020a9b8:	33103c62 	bfi	w2, w3, #16, #16
    8020a9bc:	b80044c2 	str	w2, [x6], #4
    8020a9c0:	13107c68 	asr	w8, w3, #16
    8020a9c4:	eb0702df 	cmp	x22, x7
    8020a9c8:	54fffdc2 	b.cs	8020a980 <quorem+0x70>  // b.hs, b.nlast
    8020a9cc:	b86a7ae0 	ldr	w0, [x23, x10, lsl #2]
    8020a9d0:	35000180 	cbnz	w0, 8020aa00 <quorem+0xf0>
    8020a9d4:	d1001160 	sub	x0, x11, #0x4
    8020a9d8:	eb0002ff 	cmp	x23, x0
    8020a9dc:	540000a3 	b.cc	8020a9f0 <quorem+0xe0>  // b.lo, b.ul, b.last
    8020a9e0:	14000007 	b	8020a9fc <quorem+0xec>
    8020a9e4:	51000694 	sub	w20, w20, #0x1
    8020a9e8:	eb0002ff 	cmp	x23, x0
    8020a9ec:	54000082 	b.cs	8020a9fc <quorem+0xec>  // b.hs, b.nlast
    8020a9f0:	b9400002 	ldr	w2, [x0]
    8020a9f4:	d1001000 	sub	x0, x0, #0x4
    8020a9f8:	34ffff62 	cbz	w2, 8020a9e4 <quorem+0xd4>
    8020a9fc:	b9001714 	str	w20, [x24, #20]
    8020aa00:	aa1803e0 	mov	x0, x24
    8020aa04:	9400114f 	bl	8020ef40 <__mcmp>
    8020aa08:	37f80400 	tbnz	w0, #31, 8020aa88 <quorem+0x178>
    8020aa0c:	aa1703e0 	mov	x0, x23
    8020aa10:	52800004 	mov	w4, #0x0                   	// #0
    8020aa14:	d503201f 	nop
    8020aa18:	b8404663 	ldr	w3, [x19], #4
    8020aa1c:	b9400002 	ldr	w2, [x0]
    8020aa20:	12003c41 	and	w1, w2, #0xffff
    8020aa24:	4b232021 	sub	w1, w1, w3, uxth
    8020aa28:	0b040021 	add	w1, w1, w4
    8020aa2c:	13107c24 	asr	w4, w1, #16
    8020aa30:	4b434083 	sub	w3, w4, w3, lsr #16
    8020aa34:	0b424062 	add	w2, w3, w2, lsr #16
    8020aa38:	33103c41 	bfi	w1, w2, #16, #16
    8020aa3c:	b8004401 	str	w1, [x0], #4
    8020aa40:	13107c44 	asr	w4, w2, #16
    8020aa44:	eb1302df 	cmp	x22, x19
    8020aa48:	54fffe82 	b.cs	8020aa18 <quorem+0x108>  // b.hs, b.nlast
    8020aa4c:	b874dae1 	ldr	w1, [x23, w20, sxtw #2]
    8020aa50:	8b34cae0 	add	x0, x23, w20, sxtw #2
    8020aa54:	35000181 	cbnz	w1, 8020aa84 <quorem+0x174>
    8020aa58:	d1001000 	sub	x0, x0, #0x4
    8020aa5c:	eb17001f 	cmp	x0, x23
    8020aa60:	540000a8 	b.hi	8020aa74 <quorem+0x164>  // b.pmore
    8020aa64:	14000007 	b	8020aa80 <quorem+0x170>
    8020aa68:	51000694 	sub	w20, w20, #0x1
    8020aa6c:	eb0002ff 	cmp	x23, x0
    8020aa70:	54000082 	b.cs	8020aa80 <quorem+0x170>  // b.hs, b.nlast
    8020aa74:	b9400001 	ldr	w1, [x0]
    8020aa78:	d1001000 	sub	x0, x0, #0x4
    8020aa7c:	34ffff61 	cbz	w1, 8020aa68 <quorem+0x158>
    8020aa80:	b9001714 	str	w20, [x24, #20]
    8020aa84:	110006b5 	add	w21, w21, #0x1
    8020aa88:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020aa8c:	2a1503e0 	mov	w0, w21
    8020aa90:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020aa94:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020aa98:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020aa9c:	d65f03c0 	ret
    8020aaa0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020aaa4:	52800000 	mov	w0, #0x0                   	// #0
    8020aaa8:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020aaac:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020aab0:	d65f03c0 	ret
	...

000000008020aac0 <_dtoa_r>:
    8020aac0:	a9b47bfd 	stp	x29, x30, [sp, #-192]!
    8020aac4:	910003fd 	mov	x29, sp
    8020aac8:	f9402806 	ldr	x6, [x0, #80]
    8020aacc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020aad0:	aa0003f3 	mov	x19, x0
    8020aad4:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020aad8:	aa0403f4 	mov	x20, x4
    8020aadc:	a90363f7 	stp	x23, x24, [sp, #48]
    8020aae0:	2a0103f7 	mov	w23, w1
    8020aae4:	aa0503f8 	mov	x24, x5
    8020aae8:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020aaec:	2a0203fa 	mov	w26, w2
    8020aaf0:	a90573fb 	stp	x27, x28, [sp, #80]
    8020aaf4:	9e66001c 	fmov	x28, d0
    8020aaf8:	f90043e3 	str	x3, [sp, #128]
    8020aafc:	6d0627e8 	stp	d8, d9, [sp, #96]
    8020ab00:	1e604008 	fmov	d8, d0
    8020ab04:	b4000106 	cbz	x6, 8020ab24 <_dtoa_r+0x64>
    8020ab08:	b9405803 	ldr	w3, [x0, #88]
    8020ab0c:	52800022 	mov	w2, #0x1                   	// #1
    8020ab10:	aa0603e1 	mov	x1, x6
    8020ab14:	1ac32042 	lsl	w2, w2, w3
    8020ab18:	290108c3 	stp	w3, w2, [x6, #8]
    8020ab1c:	94000ed9 	bl	8020e680 <_Bfree>
    8020ab20:	f9002a7f 	str	xzr, [x19, #80]
    8020ab24:	9e660100 	fmov	x0, d8
    8020ab28:	1e604109 	fmov	d9, d8
    8020ab2c:	52800001 	mov	w1, #0x0                   	// #0
    8020ab30:	d360fc00 	lsr	x0, x0, #32
    8020ab34:	2a0003f5 	mov	w21, w0
    8020ab38:	36f800a0 	tbz	w0, #31, 8020ab4c <_dtoa_r+0x8c>
    8020ab3c:	12007815 	and	w21, w0, #0x7fffffff
    8020ab40:	52800021 	mov	w1, #0x1                   	// #1
    8020ab44:	b3607ebc 	bfi	x28, x21, #32, #32
    8020ab48:	9e670389 	fmov	d9, x28
    8020ab4c:	120c2aa2 	and	w2, w21, #0x7ff00000
    8020ab50:	b9000281 	str	w1, [x20]
    8020ab54:	52affe00 	mov	w0, #0x7ff00000            	// #2146435072
    8020ab58:	6b00005f 	cmp	w2, w0
    8020ab5c:	54000e80 	b.eq	8020ad2c <_dtoa_r+0x26c>  // b.none
    8020ab60:	1e602128 	fcmp	d9, #0.0
    8020ab64:	54000261 	b.ne	8020abb0 <_dtoa_r+0xf0>  // b.any
    8020ab68:	f94043e1 	ldr	x1, [sp, #128]
    8020ab6c:	52800020 	mov	w0, #0x1                   	// #1
    8020ab70:	b9000020 	str	w0, [x1]
    8020ab74:	b4000098 	cbz	x24, 8020ab84 <_dtoa_r+0xc4>
    8020ab78:	d0000020 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020ab7c:	9114e400 	add	x0, x0, #0x539
    8020ab80:	f9000300 	str	x0, [x24]
    8020ab84:	d0000037 	adrp	x23, 80210000 <__trunctfdf2+0xc0>
    8020ab88:	9114e2f7 	add	x23, x23, #0x538
    8020ab8c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ab90:	aa1703e0 	mov	x0, x23
    8020ab94:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020ab98:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020ab9c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020aba0:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020aba4:	6d4627e8 	ldp	d8, d9, [sp, #96]
    8020aba8:	a8cc7bfd 	ldp	x29, x30, [sp], #192
    8020abac:	d65f03c0 	ret
    8020abb0:	1e604120 	fmov	d0, d9
    8020abb4:	9102e3e2 	add	x2, sp, #0xb8
    8020abb8:	9102f3e1 	add	x1, sp, #0xbc
    8020abbc:	aa1303e0 	mov	x0, x19
    8020abc0:	940011e4 	bl	8020f350 <__d2b>
    8020abc4:	aa0003f4 	mov	x20, x0
    8020abc8:	53147ea0 	lsr	w0, w21, #20
    8020abcc:	35000ca0 	cbnz	w0, 8020ad60 <_dtoa_r+0x2a0>
    8020abd0:	295707e3 	ldp	w3, w1, [sp, #184]
    8020abd4:	9e660100 	fmov	x0, d8
    8020abd8:	0b010061 	add	w1, w3, w1
    8020abdc:	1110c822 	add	w2, w1, #0x432
    8020abe0:	7100805f 	cmp	w2, #0x20
    8020abe4:	54002ead 	b.le	8020b1b8 <_dtoa_r+0x6f8>
    8020abe8:	11104825 	add	w5, w1, #0x412
    8020abec:	52800804 	mov	w4, #0x40                  	// #64
    8020abf0:	4b020082 	sub	w2, w4, w2
    8020abf4:	1ac52400 	lsr	w0, w0, w5
    8020abf8:	1ac222b5 	lsl	w21, w21, w2
    8020abfc:	2a0002a0 	orr	w0, w21, w0
    8020ac00:	1e630000 	ucvtf	d0, w0
    8020ac04:	51000420 	sub	w0, w1, #0x1
    8020ac08:	52800021 	mov	w1, #0x1                   	// #1
    8020ac0c:	b900a7e1 	str	w1, [sp, #164]
    8020ac10:	52bfc204 	mov	w4, #0xfe100000            	// #-32505856
    8020ac14:	9e660002 	fmov	x2, d0
    8020ac18:	d360fc41 	lsr	x1, x2, #32
    8020ac1c:	0b040021 	add	w1, w1, w4
    8020ac20:	b3607c22 	bfi	x2, x1, #32, #32
    8020ac24:	9e670042 	fmov	d2, x2
    8020ac28:	1e6f1001 	fmov	d1, #1.500000000000000000e+00
    8020ac2c:	d0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020ac30:	1e620003 	scvtf	d3, w0
    8020ac34:	1e613841 	fsub	d1, d2, d1
    8020ac38:	fd461c24 	ldr	d4, [x1, #3128]
    8020ac3c:	d0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020ac40:	fd462020 	ldr	d0, [x1, #3136]
    8020ac44:	d0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020ac48:	1f440020 	fmadd	d0, d1, d4, d0
    8020ac4c:	fd462422 	ldr	d2, [x1, #3144]
    8020ac50:	1f420060 	fmadd	d0, d3, d2, d0
    8020ac54:	1e602018 	fcmpe	d0, #0.0
    8020ac58:	1e780005 	fcvtzs	w5, d0
    8020ac5c:	54002a44 	b.mi	8020b1a4 <_dtoa_r+0x6e4>  // b.first
    8020ac60:	4b000060 	sub	w0, w3, w0
    8020ac64:	51000406 	sub	w6, w0, #0x1
    8020ac68:	710058bf 	cmp	w5, #0x16
    8020ac6c:	54002808 	b.hi	8020b16c <_dtoa_r+0x6ac>  // b.pmore
    8020ac70:	d0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020ac74:	913a0021 	add	x1, x1, #0xe80
    8020ac78:	fc65d820 	ldr	d0, [x1, w5, sxtw #3]
    8020ac7c:	1e692010 	fcmpe	d0, d9
    8020ac80:	54002d2c 	b.gt	8020b224 <_dtoa_r+0x764>
    8020ac84:	b900a3ff 	str	wzr, [sp, #160]
    8020ac88:	52800007 	mov	w7, #0x0                   	// #0
    8020ac8c:	7100001f 	cmp	w0, #0x0
    8020ac90:	5400008c 	b.gt	8020aca0 <_dtoa_r+0x1e0>
    8020ac94:	52800027 	mov	w7, #0x1                   	// #1
    8020ac98:	4b0000e7 	sub	w7, w7, w0
    8020ac9c:	52800006 	mov	w6, #0x0                   	// #0
    8020aca0:	0b0500c6 	add	w6, w6, w5
    8020aca4:	5280001b 	mov	w27, #0x0                   	// #0
    8020aca8:	b9008be5 	str	w5, [sp, #136]
    8020acac:	710026ff 	cmp	w23, #0x9
    8020acb0:	54000768 	b.hi	8020ad9c <_dtoa_r+0x2dc>  // b.pmore
    8020acb4:	710016ff 	cmp	w23, #0x5
    8020acb8:	5400286d 	b.le	8020b1c4 <_dtoa_r+0x704>
    8020acbc:	510012f7 	sub	w23, w23, #0x4
    8020acc0:	52800019 	mov	w25, #0x0                   	// #0
    8020acc4:	71000eff 	cmp	w23, #0x3
    8020acc8:	54005960 	b.eq	8020b7f4 <_dtoa_r+0xd34>  // b.none
    8020accc:	54002f2d 	b.le	8020b2b0 <_dtoa_r+0x7f0>
    8020acd0:	710012ff 	cmp	w23, #0x4
    8020acd4:	54002da1 	b.ne	8020b288 <_dtoa_r+0x7c8>  // b.any
    8020acd8:	52800020 	mov	w0, #0x1                   	// #1
    8020acdc:	b9007be0 	str	w0, [sp, #120]
    8020ace0:	7100035f 	cmp	w26, #0x0
    8020ace4:	5400536d 	b.le	8020b750 <_dtoa_r+0xc90>
    8020ace8:	2a1a03f5 	mov	w21, w26
    8020acec:	2a1a03e0 	mov	w0, w26
    8020acf0:	b900abfa 	str	w26, [sp, #168]
    8020acf4:	93407c04 	sxtw	x4, w0
    8020acf8:	71007c1f 	cmp	w0, #0x1f
    8020acfc:	540005cd 	b.le	8020adb4 <_dtoa_r+0x2f4>
    8020ad00:	52800023 	mov	w3, #0x1                   	// #1
    8020ad04:	52800082 	mov	w2, #0x4                   	// #4
    8020ad08:	531f7842 	lsl	w2, w2, #1
    8020ad0c:	2a0303e1 	mov	w1, w3
    8020ad10:	11000463 	add	w3, w3, #0x1
    8020ad14:	93407c40 	sxtw	x0, w2
    8020ad18:	91007000 	add	x0, x0, #0x1c
    8020ad1c:	eb04001f 	cmp	x0, x4
    8020ad20:	54ffff49 	b.ls	8020ad08 <_dtoa_r+0x248>  // b.plast
    8020ad24:	b9005a61 	str	w1, [x19, #88]
    8020ad28:	14000026 	b	8020adc0 <_dtoa_r+0x300>
    8020ad2c:	f94043e1 	ldr	x1, [sp, #128]
    8020ad30:	5284e1e0 	mov	w0, #0x270f                	// #9999
    8020ad34:	b9000020 	str	w0, [x1]
    8020ad38:	9e660120 	fmov	x0, d9
    8020ad3c:	f240cc1f 	tst	x0, #0xfffffffffffff
    8020ad40:	54000201 	b.ne	8020ad80 <_dtoa_r+0x2c0>  // b.any
    8020ad44:	d0000037 	adrp	x23, 80210000 <__trunctfdf2+0xc0>
    8020ad48:	b4006218 	cbz	x24, 8020b988 <_dtoa_r+0xec8>
    8020ad4c:	d0000020 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020ad50:	911b42f7 	add	x23, x23, #0x6d0
    8020ad54:	911b6000 	add	x0, x0, #0x6d8
    8020ad58:	f9000300 	str	x0, [x24]
    8020ad5c:	17ffff8c 	b	8020ab8c <_dtoa_r+0xcc>
    8020ad60:	9e660122 	fmov	x2, d9
    8020ad64:	b940bbe3 	ldr	w3, [sp, #184]
    8020ad68:	510ffc00 	sub	w0, w0, #0x3ff
    8020ad6c:	b900a7ff 	str	wzr, [sp, #164]
    8020ad70:	d360cc41 	ubfx	x1, x2, #32, #20
    8020ad74:	320c2421 	orr	w1, w1, #0x3ff00000
    8020ad78:	b3607c22 	bfi	x2, x1, #32, #32
    8020ad7c:	17ffffaa 	b	8020ac24 <_dtoa_r+0x164>
    8020ad80:	d0000037 	adrp	x23, 80210000 <__trunctfdf2+0xc0>
    8020ad84:	b4005ff8 	cbz	x24, 8020b980 <_dtoa_r+0xec0>
    8020ad88:	d0000020 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020ad8c:	911b82f7 	add	x23, x23, #0x6e0
    8020ad90:	911b8c00 	add	x0, x0, #0x6e3
    8020ad94:	f9000300 	str	x0, [x24]
    8020ad98:	17ffff7d 	b	8020ab8c <_dtoa_r+0xcc>
    8020ad9c:	52800039 	mov	w25, #0x1                   	// #1
    8020ada0:	52800017 	mov	w23, #0x0                   	// #0
    8020ada4:	12800015 	mov	w21, #0xffffffff            	// #-1
    8020ada8:	5280001a 	mov	w26, #0x0                   	// #0
    8020adac:	b9007bf9 	str	w25, [sp, #120]
    8020adb0:	b900abf5 	str	w21, [sp, #168]
    8020adb4:	52800001 	mov	w1, #0x0                   	// #0
    8020adb8:	b9005a7f 	str	wzr, [x19, #88]
    8020adbc:	d503201f 	nop
    8020adc0:	aa1303e0 	mov	x0, x19
    8020adc4:	29119be7 	stp	w7, w6, [sp, #140]
    8020adc8:	b9009be5 	str	w5, [sp, #152]
    8020adcc:	94000e09 	bl	8020e5f0 <_Balloc>
    8020add0:	29519be7 	ldp	w7, w6, [sp, #140]
    8020add4:	aa0003f6 	mov	x22, x0
    8020add8:	b9409be5 	ldr	w5, [sp, #152]
    8020addc:	b40072c0 	cbz	x0, 8020bc34 <_dtoa_r+0x1174>
    8020ade0:	71003abf 	cmp	w21, #0xe
    8020ade4:	f9002a76 	str	x22, [x19, #80]
    8020ade8:	1a9f87e0 	cset	w0, ls	// ls = plast
    8020adec:	2a1503e3 	mov	w3, w21
    8020adf0:	0a190004 	and	w4, w0, w25
    8020adf4:	6a19001f 	tst	w0, w25
    8020adf8:	54000ae0 	b.eq	8020af54 <_dtoa_r+0x494>  // b.none
    8020adfc:	b9408be0 	ldr	w0, [sp, #136]
    8020ae00:	7100001f 	cmp	w0, #0x0
    8020ae04:	5400446d 	b.le	8020b690 <_dtoa_r+0xbd0>
    8020ae08:	2a0003e4 	mov	w4, w0
    8020ae0c:	d0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020ae10:	aa0403e0 	mov	x0, x4
    8020ae14:	913a0021 	add	x1, x1, #0xe80
    8020ae18:	92400c02 	and	x2, x0, #0xf
    8020ae1c:	13047c80 	asr	w0, w4, #4
    8020ae20:	fc627820 	ldr	d0, [x1, x2, lsl #3]
    8020ae24:	aa0403e1 	mov	x1, x4
    8020ae28:	36404e01 	tbz	w1, #8, 8020b7e8 <_dtoa_r+0xd28>
    8020ae2c:	d0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020ae30:	12000c00 	and	w0, w0, #0xf
    8020ae34:	52800062 	mov	w2, #0x3                   	// #3
    8020ae38:	fd473821 	ldr	d1, [x1, #3696]
    8020ae3c:	1e611921 	fdiv	d1, d9, d1
    8020ae40:	34000160 	cbz	w0, 8020ae6c <_dtoa_r+0x3ac>
    8020ae44:	d0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020ae48:	91394021 	add	x1, x1, #0xe50
    8020ae4c:	d503201f 	nop
    8020ae50:	36000080 	tbz	w0, #0, 8020ae60 <_dtoa_r+0x3a0>
    8020ae54:	fd400022 	ldr	d2, [x1]
    8020ae58:	11000442 	add	w2, w2, #0x1
    8020ae5c:	1e620800 	fmul	d0, d0, d2
    8020ae60:	13017c00 	asr	w0, w0, #1
    8020ae64:	91002021 	add	x1, x1, #0x8
    8020ae68:	35ffff40 	cbnz	w0, 8020ae50 <_dtoa_r+0x390>
    8020ae6c:	1e601821 	fdiv	d1, d1, d0
    8020ae70:	b940a3e0 	ldr	w0, [sp, #160]
    8020ae74:	34000080 	cbz	w0, 8020ae84 <_dtoa_r+0x3c4>
    8020ae78:	1e6e1000 	fmov	d0, #1.000000000000000000e+00
    8020ae7c:	1e602030 	fcmpe	d1, d0
    8020ae80:	540054c4 	b.mi	8020b918 <_dtoa_r+0xe58>  // b.first
    8020ae84:	1e620042 	scvtf	d2, w2
    8020ae88:	1e639000 	fmov	d0, #7.000000000000000000e+00
    8020ae8c:	52bf9802 	mov	w2, #0xfcc00000            	// #-54525952
    8020ae90:	1f410040 	fmadd	d0, d2, d1, d0
    8020ae94:	9e660000 	fmov	x0, d0
    8020ae98:	d360fc01 	lsr	x1, x0, #32
    8020ae9c:	0b020021 	add	w1, w1, w2
    8020aea0:	b3607c20 	bfi	x0, x1, #32, #32
    8020aea4:	34003e15 	cbz	w21, 8020b664 <_dtoa_r+0xba4>
    8020aea8:	b9408bfc 	ldr	w28, [sp, #136]
    8020aeac:	2a1503e4 	mov	w4, w21
    8020aeb0:	1e780021 	fcvtzs	w1, d1
    8020aeb4:	9e670002 	fmov	d2, x0
    8020aeb8:	51000482 	sub	w2, w4, #0x1
    8020aebc:	d0000028 	adrp	x8, 80210000 <__trunctfdf2+0xc0>
    8020aec0:	913a0108 	add	x8, x8, #0xe80
    8020aec4:	910006c9 	add	x9, x22, #0x1
    8020aec8:	1e620020 	scvtf	d0, w1
    8020aecc:	1100c020 	add	w0, w1, #0x30
    8020aed0:	b9407be1 	ldr	w1, [sp, #120]
    8020aed4:	12001c00 	and	w0, w0, #0xff
    8020aed8:	fc62d903 	ldr	d3, [x8, w2, sxtw #3]
    8020aedc:	1e603821 	fsub	d1, d1, d0
    8020aee0:	340048e1 	cbz	w1, 8020b7fc <_dtoa_r+0xd3c>
    8020aee4:	1e6c1000 	fmov	d0, #5.000000000000000000e-01
    8020aee8:	390002c0 	strb	w0, [x22]
    8020aeec:	1e631800 	fdiv	d0, d0, d3
    8020aef0:	1e623800 	fsub	d0, d0, d2
    8020aef4:	1e612010 	fcmpe	d0, d1
    8020aef8:	5400684c 	b.gt	8020bc00 <_dtoa_r+0x1140>
    8020aefc:	52800022 	mov	w2, #0x1                   	// #1
    8020af00:	aa0903e0 	mov	x0, x9
    8020af04:	4b090042 	sub	w2, w2, w9
    8020af08:	1e6e1004 	fmov	d4, #1.000000000000000000e+00
    8020af0c:	1e649003 	fmov	d3, #1.000000000000000000e+01
    8020af10:	1400000a 	b	8020af38 <_dtoa_r+0x478>
    8020af14:	1e630821 	fmul	d1, d1, d3
    8020af18:	1e630800 	fmul	d0, d0, d3
    8020af1c:	1e780021 	fcvtzs	w1, d1
    8020af20:	1e620022 	scvtf	d2, w1
    8020af24:	1100c021 	add	w1, w1, #0x30
    8020af28:	38001401 	strb	w1, [x0], #1
    8020af2c:	1e623821 	fsub	d1, d1, d2
    8020af30:	1e602030 	fcmpe	d1, d0
    8020af34:	54005e24 	b.mi	8020baf8 <_dtoa_r+0x1038>  // b.first
    8020af38:	1e613882 	fsub	d2, d4, d1
    8020af3c:	1e602050 	fcmpe	d2, d0
    8020af40:	540017c4 	b.mi	8020b238 <_dtoa_r+0x778>  // b.first
    8020af44:	0b000041 	add	w1, w2, w0
    8020af48:	6b04003f 	cmp	w1, w4
    8020af4c:	54fffe4b 	b.lt	8020af14 <_dtoa_r+0x454>  // b.tstop
    8020af50:	9e66013c 	fmov	x28, d9
    8020af54:	b940bfe0 	ldr	w0, [sp, #188]
    8020af58:	b9408be1 	ldr	w1, [sp, #136]
    8020af5c:	7100001f 	cmp	w0, #0x0
    8020af60:	7a4ea820 	ccmp	w1, #0xe, #0x0, ge	// ge = tcont
    8020af64:	54003d6d 	b.le	8020b710 <_dtoa_r+0xc50>
    8020af68:	b9407be1 	ldr	w1, [sp, #120]
    8020af6c:	34003c81 	cbz	w1, 8020b6fc <_dtoa_r+0xc3c>
    8020af70:	710006ff 	cmp	w23, #0x1
    8020af74:	54004f6d 	b.le	8020b960 <_dtoa_r+0xea0>
    8020af78:	510006a3 	sub	w3, w21, #0x1
    8020af7c:	6b03037f 	cmp	w27, w3
    8020af80:	5400520b 	b.lt	8020b9c0 <_dtoa_r+0xf00>  // b.tstop
    8020af84:	4b1500e0 	sub	w0, w7, w21
    8020af88:	b9008fe0 	str	w0, [sp, #140]
    8020af8c:	4b030363 	sub	w3, w27, w3
    8020af90:	36f85e75 	tbz	w21, #31, 8020bb5c <_dtoa_r+0x109c>
    8020af94:	aa1303e0 	mov	x0, x19
    8020af98:	52800021 	mov	w1, #0x1                   	// #1
    8020af9c:	b90093e7 	str	w7, [sp, #144]
    8020afa0:	b9009be6 	str	w6, [sp, #152]
    8020afa4:	b900a7e5 	str	w5, [sp, #164]
    8020afa8:	b900afe3 	str	w3, [sp, #172]
    8020afac:	94000e95 	bl	8020ea00 <__i2b>
    8020afb0:	b94093e7 	ldr	w7, [sp, #144]
    8020afb4:	aa0003f9 	mov	x25, x0
    8020afb8:	b9409be6 	ldr	w6, [sp, #152]
    8020afbc:	b940a7e5 	ldr	w5, [sp, #164]
    8020afc0:	b940afe3 	ldr	w3, [sp, #172]
    8020afc4:	b9408fe1 	ldr	w1, [sp, #140]
    8020afc8:	7100003f 	cmp	w1, #0x0
    8020afcc:	7a40c8c4 	ccmp	w6, #0x0, #0x4, gt
    8020afd0:	540000ed 	b.le	8020afec <_dtoa_r+0x52c>
    8020afd4:	6b06003f 	cmp	w1, w6
    8020afd8:	1a86d020 	csel	w0, w1, w6, le
    8020afdc:	4b0000e7 	sub	w7, w7, w0
    8020afe0:	4b0000c6 	sub	w6, w6, w0
    8020afe4:	4b000021 	sub	w1, w1, w0
    8020afe8:	b9008fe1 	str	w1, [sp, #140]
    8020afec:	340001fb 	cbz	w27, 8020b028 <_dtoa_r+0x568>
    8020aff0:	b9407be0 	ldr	w0, [sp, #120]
    8020aff4:	34004ce0 	cbz	w0, 8020b990 <_dtoa_r+0xed0>
    8020aff8:	35005183 	cbnz	w3, 8020ba28 <_dtoa_r+0xf68>
    8020affc:	aa1403e1 	mov	x1, x20
    8020b000:	2a1b03e2 	mov	w2, w27
    8020b004:	aa1303e0 	mov	x0, x19
    8020b008:	b90093e7 	str	w7, [sp, #144]
    8020b00c:	b9009be6 	str	w6, [sp, #152]
    8020b010:	b900a7e5 	str	w5, [sp, #164]
    8020b014:	94000f27 	bl	8020ecb0 <__pow5mult>
    8020b018:	b94093e7 	ldr	w7, [sp, #144]
    8020b01c:	aa0003f4 	mov	x20, x0
    8020b020:	b9409be6 	ldr	w6, [sp, #152]
    8020b024:	b940a7e5 	ldr	w5, [sp, #164]
    8020b028:	aa1303e0 	mov	x0, x19
    8020b02c:	52800021 	mov	w1, #0x1                   	// #1
    8020b030:	b90093e7 	str	w7, [sp, #144]
    8020b034:	b9009be6 	str	w6, [sp, #152]
    8020b038:	b900a7e5 	str	w5, [sp, #164]
    8020b03c:	94000e71 	bl	8020ea00 <__i2b>
    8020b040:	b940a7e5 	ldr	w5, [sp, #164]
    8020b044:	aa0003fb 	mov	x27, x0
    8020b048:	b94093e7 	ldr	w7, [sp, #144]
    8020b04c:	b9409be6 	ldr	w6, [sp, #152]
    8020b050:	35003865 	cbnz	w5, 8020b75c <_dtoa_r+0xc9c>
    8020b054:	710006ff 	cmp	w23, #0x1
    8020b058:	54001c8d 	b.le	8020b3e8 <_dtoa_r+0x928>
    8020b05c:	52800020 	mov	w0, #0x1                   	// #1
    8020b060:	0b0000c0 	add	w0, w6, w0
    8020b064:	72001000 	ands	w0, w0, #0x1f
    8020b068:	54003100 	b.eq	8020b688 <_dtoa_r+0xbc8>  // b.none
    8020b06c:	52800401 	mov	w1, #0x20                  	// #32
    8020b070:	4b000021 	sub	w1, w1, w0
    8020b074:	7100103f 	cmp	w1, #0x4
    8020b078:	5400442d 	b.le	8020b8fc <_dtoa_r+0xe3c>
    8020b07c:	52800381 	mov	w1, #0x1c                  	// #28
    8020b080:	4b000020 	sub	w0, w1, w0
    8020b084:	b9408fe1 	ldr	w1, [sp, #140]
    8020b088:	0b0000e7 	add	w7, w7, w0
    8020b08c:	0b0000c6 	add	w6, w6, w0
    8020b090:	0b000021 	add	w1, w1, w0
    8020b094:	b9008fe1 	str	w1, [sp, #140]
    8020b098:	710000ff 	cmp	w7, #0x0
    8020b09c:	5400014d 	b.le	8020b0c4 <_dtoa_r+0x604>
    8020b0a0:	aa1403e1 	mov	x1, x20
    8020b0a4:	2a0703e2 	mov	w2, w7
    8020b0a8:	aa1303e0 	mov	x0, x19
    8020b0ac:	b90093e6 	str	w6, [sp, #144]
    8020b0b0:	b9009be5 	str	w5, [sp, #152]
    8020b0b4:	94000f47 	bl	8020edd0 <__lshift>
    8020b0b8:	b94093e6 	ldr	w6, [sp, #144]
    8020b0bc:	aa0003f4 	mov	x20, x0
    8020b0c0:	b9409be5 	ldr	w5, [sp, #152]
    8020b0c4:	710000df 	cmp	w6, #0x0
    8020b0c8:	5400010d 	b.le	8020b0e8 <_dtoa_r+0x628>
    8020b0cc:	aa1b03e1 	mov	x1, x27
    8020b0d0:	2a0603e2 	mov	w2, w6
    8020b0d4:	aa1303e0 	mov	x0, x19
    8020b0d8:	b90093e5 	str	w5, [sp, #144]
    8020b0dc:	94000f3d 	bl	8020edd0 <__lshift>
    8020b0e0:	aa0003fb 	mov	x27, x0
    8020b0e4:	b94093e5 	ldr	w5, [sp, #144]
    8020b0e8:	b940a3e0 	ldr	w0, [sp, #160]
    8020b0ec:	71000aff 	cmp	w23, #0x2
    8020b0f0:	1a9fd7e4 	cset	w4, gt
    8020b0f4:	350018e0 	cbnz	w0, 8020b410 <_dtoa_r+0x950>
    8020b0f8:	710002bf 	cmp	w21, #0x0
    8020b0fc:	7a40d884 	ccmp	w4, #0x0, #0x4, le
    8020b100:	54000de0 	b.eq	8020b2bc <_dtoa_r+0x7fc>  // b.none
    8020b104:	35002795 	cbnz	w21, 8020b5f4 <_dtoa_r+0xb34>
    8020b108:	52800003 	mov	w3, #0x0                   	// #0
    8020b10c:	528000a2 	mov	w2, #0x5                   	// #5
    8020b110:	aa1b03e1 	mov	x1, x27
    8020b114:	aa1303e0 	mov	x0, x19
    8020b118:	94000d62 	bl	8020e6a0 <__multadd>
    8020b11c:	aa0003fb 	mov	x27, x0
    8020b120:	aa1b03e1 	mov	x1, x27
    8020b124:	aa1403e0 	mov	x0, x20
    8020b128:	aa1603f7 	mov	x23, x22
    8020b12c:	94000f85 	bl	8020ef40 <__mcmp>
    8020b130:	7100001f 	cmp	w0, #0x0
    8020b134:	5400260d 	b.le	8020b5f4 <_dtoa_r+0xb34>
    8020b138:	b9408be0 	ldr	w0, [sp, #136]
    8020b13c:	910006d6 	add	x22, x22, #0x1
    8020b140:	1100041c 	add	w28, w0, #0x1
    8020b144:	52800620 	mov	w0, #0x31                  	// #49
    8020b148:	390002e0 	strb	w0, [x23]
    8020b14c:	aa1b03e1 	mov	x1, x27
    8020b150:	aa1303e0 	mov	x0, x19
    8020b154:	94000d4b 	bl	8020e680 <_Bfree>
    8020b158:	b4000859 	cbz	x25, 8020b260 <_dtoa_r+0x7a0>
    8020b15c:	aa1903e1 	mov	x1, x25
    8020b160:	aa1303e0 	mov	x0, x19
    8020b164:	94000d47 	bl	8020e680 <_Bfree>
    8020b168:	1400003e 	b	8020b260 <_dtoa_r+0x7a0>
    8020b16c:	52800021 	mov	w1, #0x1                   	// #1
    8020b170:	b900a3e1 	str	w1, [sp, #160]
    8020b174:	52800007 	mov	w7, #0x0                   	// #0
    8020b178:	37f800e6 	tbnz	w6, #31, 8020b194 <_dtoa_r+0x6d4>
    8020b17c:	36ffd925 	tbz	w5, #31, 8020aca0 <_dtoa_r+0x1e0>
    8020b180:	4b0500e7 	sub	w7, w7, w5
    8020b184:	4b0503fb 	neg	w27, w5
    8020b188:	b9008be5 	str	w5, [sp, #136]
    8020b18c:	52800005 	mov	w5, #0x0                   	// #0
    8020b190:	17fffec7 	b	8020acac <_dtoa_r+0x1ec>
    8020b194:	52800027 	mov	w7, #0x1                   	// #1
    8020b198:	52800006 	mov	w6, #0x0                   	// #0
    8020b19c:	4b0000e7 	sub	w7, w7, w0
    8020b1a0:	17fffff7 	b	8020b17c <_dtoa_r+0x6bc>
    8020b1a4:	1e6200a1 	scvtf	d1, w5
    8020b1a8:	1e602020 	fcmp	d1, d0
    8020b1ac:	1a9f07e1 	cset	w1, ne	// ne = any
    8020b1b0:	4b0100a5 	sub	w5, w5, w1
    8020b1b4:	17fffeab 	b	8020ac60 <_dtoa_r+0x1a0>
    8020b1b8:	4b0203e2 	neg	w2, w2
    8020b1bc:	1ac22000 	lsl	w0, w0, w2
    8020b1c0:	17fffe90 	b	8020ac00 <_dtoa_r+0x140>
    8020b1c4:	52800039 	mov	w25, #0x1                   	// #1
    8020b1c8:	71000eff 	cmp	w23, #0x3
    8020b1cc:	54003140 	b.eq	8020b7f4 <_dtoa_r+0xd34>  // b.none
    8020b1d0:	54ffd80c 	b.gt	8020acd0 <_dtoa_r+0x210>
    8020b1d4:	71000aff 	cmp	w23, #0x2
    8020b1d8:	540053c0 	b.eq	8020bc50 <_dtoa_r+0x1190>  // b.none
    8020b1dc:	b9005a7f 	str	wzr, [x19, #88]
    8020b1e0:	aa1303e0 	mov	x0, x19
    8020b1e4:	52800001 	mov	w1, #0x0                   	// #0
    8020b1e8:	b9007be7 	str	w7, [sp, #120]
    8020b1ec:	291197e6 	stp	w6, w5, [sp, #140]
    8020b1f0:	94000d00 	bl	8020e5f0 <_Balloc>
    8020b1f4:	b9407be7 	ldr	w7, [sp, #120]
    8020b1f8:	aa0003f6 	mov	x22, x0
    8020b1fc:	295197e6 	ldp	w6, w5, [sp, #140]
    8020b200:	b40051a0 	cbz	x0, 8020bc34 <_dtoa_r+0x1174>
    8020b204:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020b208:	5280001a 	mov	w26, #0x0                   	// #0
    8020b20c:	2a0003e3 	mov	w3, w0
    8020b210:	2a0003f5 	mov	w21, w0
    8020b214:	f9002a76 	str	x22, [x19, #80]
    8020b218:	b9007bf9 	str	w25, [sp, #120]
    8020b21c:	b900abe0 	str	w0, [sp, #168]
    8020b220:	17ffff4d 	b	8020af54 <_dtoa_r+0x494>
    8020b224:	510004a5 	sub	w5, w5, #0x1
    8020b228:	b900a3ff 	str	wzr, [sp, #160]
    8020b22c:	17ffffd2 	b	8020b174 <_dtoa_r+0x6b4>
    8020b230:	eb16001f 	cmp	x0, x22
    8020b234:	540042a0 	b.eq	8020ba88 <_dtoa_r+0xfc8>  // b.none
    8020b238:	aa0003e2 	mov	x2, x0
    8020b23c:	385ffc01 	ldrb	w1, [x0, #-1]!
    8020b240:	7100e43f 	cmp	w1, #0x39
    8020b244:	54ffff60 	b.eq	8020b230 <_dtoa_r+0x770>  // b.none
    8020b248:	11000421 	add	w1, w1, #0x1
    8020b24c:	12001c21 	and	w1, w1, #0xff
    8020b250:	aa1603f7 	mov	x23, x22
    8020b254:	aa0203f6 	mov	x22, x2
    8020b258:	39000001 	strb	w1, [x0]
    8020b25c:	d503201f 	nop
    8020b260:	aa1403e1 	mov	x1, x20
    8020b264:	aa1303e0 	mov	x0, x19
    8020b268:	94000d06 	bl	8020e680 <_Bfree>
    8020b26c:	390002df 	strb	wzr, [x22]
    8020b270:	f94043e1 	ldr	x1, [sp, #128]
    8020b274:	11000780 	add	w0, w28, #0x1
    8020b278:	b9000020 	str	w0, [x1]
    8020b27c:	b4ffc898 	cbz	x24, 8020ab8c <_dtoa_r+0xcc>
    8020b280:	f9000316 	str	x22, [x24]
    8020b284:	17fffe42 	b	8020ab8c <_dtoa_r+0xcc>
    8020b288:	52800020 	mov	w0, #0x1                   	// #1
    8020b28c:	528000b7 	mov	w23, #0x5                   	// #5
    8020b290:	b9007be0 	str	w0, [sp, #120]
    8020b294:	b9408be0 	ldr	w0, [sp, #136]
    8020b298:	0b000340 	add	w0, w26, w0
    8020b29c:	b900abe0 	str	w0, [sp, #168]
    8020b2a0:	11000415 	add	w21, w0, #0x1
    8020b2a4:	710002bf 	cmp	w21, #0x0
    8020b2a8:	1a9fc6a0 	csinc	w0, w21, wzr, gt
    8020b2ac:	17fffe92 	b	8020acf4 <_dtoa_r+0x234>
    8020b2b0:	52800057 	mov	w23, #0x2                   	// #2
    8020b2b4:	b9007bff 	str	wzr, [sp, #120]
    8020b2b8:	17fffe8a 	b	8020ace0 <_dtoa_r+0x220>
    8020b2bc:	b9407be0 	ldr	w0, [sp, #120]
    8020b2c0:	34000e00 	cbz	w0, 8020b480 <_dtoa_r+0x9c0>
    8020b2c4:	b9408fe2 	ldr	w2, [sp, #140]
    8020b2c8:	7100005f 	cmp	w2, #0x0
    8020b2cc:	540000ed 	b.le	8020b2e8 <_dtoa_r+0x828>
    8020b2d0:	aa1903e1 	mov	x1, x25
    8020b2d4:	aa1303e0 	mov	x0, x19
    8020b2d8:	b9007be5 	str	w5, [sp, #120]
    8020b2dc:	94000ebd 	bl	8020edd0 <__lshift>
    8020b2e0:	b9407be5 	ldr	w5, [sp, #120]
    8020b2e4:	aa0003f9 	mov	x25, x0
    8020b2e8:	f9003ff9 	str	x25, [sp, #120]
    8020b2ec:	35003e45 	cbnz	w5, 8020bab4 <_dtoa_r+0xff4>
    8020b2f0:	8b35c2d5 	add	x21, x22, w21, sxtw
    8020b2f4:	12000380 	and	w0, w28, #0x1
    8020b2f8:	f9004bf6 	str	x22, [sp, #144]
    8020b2fc:	b900a7e0 	str	w0, [sp, #164]
    8020b300:	aa1b03e1 	mov	x1, x27
    8020b304:	aa1403e0 	mov	x0, x20
    8020b308:	97fffd82 	bl	8020a910 <quorem>
    8020b30c:	1100c01a 	add	w26, w0, #0x30
    8020b310:	aa1903e1 	mov	x1, x25
    8020b314:	b900a3e0 	str	w0, [sp, #160]
    8020b318:	aa1403e0 	mov	x0, x20
    8020b31c:	94000f09 	bl	8020ef40 <__mcmp>
    8020b320:	f9403fe2 	ldr	x2, [sp, #120]
    8020b324:	aa1b03e1 	mov	x1, x27
    8020b328:	b9008fe0 	str	w0, [sp, #140]
    8020b32c:	aa1303e0 	mov	x0, x19
    8020b330:	94000f18 	bl	8020ef90 <__mdiff>
    8020b334:	aa0003e1 	mov	x1, x0
    8020b338:	b9401000 	ldr	w0, [x0, #16]
    8020b33c:	35001180 	cbnz	w0, 8020b56c <_dtoa_r+0xaac>
    8020b340:	aa1403e0 	mov	x0, x20
    8020b344:	f9004fe1 	str	x1, [sp, #152]
    8020b348:	94000efe 	bl	8020ef40 <__mcmp>
    8020b34c:	2a0003e2 	mov	w2, w0
    8020b350:	f9404fe1 	ldr	x1, [sp, #152]
    8020b354:	aa1303e0 	mov	x0, x19
    8020b358:	b9009be2 	str	w2, [sp, #152]
    8020b35c:	94000cc9 	bl	8020e680 <_Bfree>
    8020b360:	b9409be2 	ldr	w2, [sp, #152]
    8020b364:	2a0202e0 	orr	w0, w23, w2
    8020b368:	350014c0 	cbnz	w0, 8020b600 <_dtoa_r+0xb40>
    8020b36c:	b940a7e0 	ldr	w0, [sp, #164]
    8020b370:	34003fe0 	cbz	w0, 8020bb6c <_dtoa_r+0x10ac>
    8020b374:	b9408fe0 	ldr	w0, [sp, #140]
    8020b378:	37f81260 	tbnz	w0, #31, 8020b5c4 <_dtoa_r+0xb04>
    8020b37c:	f9404be0 	ldr	x0, [sp, #144]
    8020b380:	3800141a 	strb	w26, [x0], #1
    8020b384:	f9004be0 	str	x0, [sp, #144]
    8020b388:	eb0002bf 	cmp	x21, x0
    8020b38c:	54003d00 	b.eq	8020bb2c <_dtoa_r+0x106c>  // b.none
    8020b390:	aa1403e1 	mov	x1, x20
    8020b394:	52800003 	mov	w3, #0x0                   	// #0
    8020b398:	52800142 	mov	w2, #0xa                   	// #10
    8020b39c:	aa1303e0 	mov	x0, x19
    8020b3a0:	94000cc0 	bl	8020e6a0 <__multadd>
    8020b3a4:	aa0003f4 	mov	x20, x0
    8020b3a8:	f9403fe0 	ldr	x0, [sp, #120]
    8020b3ac:	aa1903e1 	mov	x1, x25
    8020b3b0:	52800003 	mov	w3, #0x0                   	// #0
    8020b3b4:	52800142 	mov	w2, #0xa                   	// #10
    8020b3b8:	eb00033f 	cmp	x25, x0
    8020b3bc:	aa1303e0 	mov	x0, x19
    8020b3c0:	540010e0 	b.eq	8020b5dc <_dtoa_r+0xb1c>  // b.none
    8020b3c4:	94000cb7 	bl	8020e6a0 <__multadd>
    8020b3c8:	aa0003f9 	mov	x25, x0
    8020b3cc:	f9403fe1 	ldr	x1, [sp, #120]
    8020b3d0:	aa1303e0 	mov	x0, x19
    8020b3d4:	52800003 	mov	w3, #0x0                   	// #0
    8020b3d8:	52800142 	mov	w2, #0xa                   	// #10
    8020b3dc:	94000cb1 	bl	8020e6a0 <__multadd>
    8020b3e0:	f9003fe0 	str	x0, [sp, #120]
    8020b3e4:	17ffffc7 	b	8020b300 <_dtoa_r+0x840>
    8020b3e8:	f240cf9f 	tst	x28, #0xfffffffffffff
    8020b3ec:	54ffe381 	b.ne	8020b05c <_dtoa_r+0x59c>  // b.any
    8020b3f0:	d360ff80 	lsr	x0, x28, #32
    8020b3f4:	f26c281f 	tst	x0, #0x7ff00000
    8020b3f8:	54ffe320 	b.eq	8020b05c <_dtoa_r+0x59c>  // b.none
    8020b3fc:	52800025 	mov	w5, #0x1                   	// #1
    8020b400:	110004e7 	add	w7, w7, #0x1
    8020b404:	110004c6 	add	w6, w6, #0x1
    8020b408:	2a0503e0 	mov	w0, w5
    8020b40c:	17ffff15 	b	8020b060 <_dtoa_r+0x5a0>
    8020b410:	aa1b03e1 	mov	x1, x27
    8020b414:	aa1403e0 	mov	x0, x20
    8020b418:	b90093e5 	str	w5, [sp, #144]
    8020b41c:	b9009be4 	str	w4, [sp, #152]
    8020b420:	94000ec8 	bl	8020ef40 <__mcmp>
    8020b424:	b94093e5 	ldr	w5, [sp, #144]
    8020b428:	b9409be4 	ldr	w4, [sp, #152]
    8020b42c:	36ffe660 	tbz	w0, #31, 8020b0f8 <_dtoa_r+0x638>
    8020b430:	b9408be0 	ldr	w0, [sp, #136]
    8020b434:	aa1403e1 	mov	x1, x20
    8020b438:	52800003 	mov	w3, #0x0                   	// #0
    8020b43c:	52800142 	mov	w2, #0xa                   	// #10
    8020b440:	51000400 	sub	w0, w0, #0x1
    8020b444:	b9008be0 	str	w0, [sp, #136]
    8020b448:	aa1303e0 	mov	x0, x19
    8020b44c:	b90093e5 	str	w5, [sp, #144]
    8020b450:	b9009be4 	str	w4, [sp, #152]
    8020b454:	94000c93 	bl	8020e6a0 <__multadd>
    8020b458:	aa0003f4 	mov	x20, x0
    8020b45c:	b9407be0 	ldr	w0, [sp, #120]
    8020b460:	b94093e5 	ldr	w5, [sp, #144]
    8020b464:	b9409be4 	ldr	w4, [sp, #152]
    8020b468:	350039e0 	cbnz	w0, 8020bba4 <_dtoa_r+0x10e4>
    8020b46c:	b940abe0 	ldr	w0, [sp, #168]
    8020b470:	7100001f 	cmp	w0, #0x0
    8020b474:	2a0003f5 	mov	w21, w0
    8020b478:	7a40d884 	ccmp	w4, #0x0, #0x4, le
    8020b47c:	54ffe441 	b.ne	8020b104 <_dtoa_r+0x644>  // b.any
    8020b480:	d2800017 	mov	x23, #0x0                   	// #0
    8020b484:	14000007 	b	8020b4a0 <_dtoa_r+0x9e0>
    8020b488:	aa1403e1 	mov	x1, x20
    8020b48c:	aa1303e0 	mov	x0, x19
    8020b490:	52800003 	mov	w3, #0x0                   	// #0
    8020b494:	52800142 	mov	w2, #0xa                   	// #10
    8020b498:	94000c82 	bl	8020e6a0 <__multadd>
    8020b49c:	aa0003f4 	mov	x20, x0
    8020b4a0:	aa1b03e1 	mov	x1, x27
    8020b4a4:	aa1403e0 	mov	x0, x20
    8020b4a8:	97fffd1a 	bl	8020a910 <quorem>
    8020b4ac:	1100c01a 	add	w26, w0, #0x30
    8020b4b0:	38376ada 	strb	w26, [x22, x23]
    8020b4b4:	910006f7 	add	x23, x23, #0x1
    8020b4b8:	6b1702bf 	cmp	w21, w23
    8020b4bc:	54fffe6c 	b.gt	8020b488 <_dtoa_r+0x9c8>
    8020b4c0:	710002bf 	cmp	w21, #0x0
    8020b4c4:	510006b5 	sub	w21, w21, #0x1
    8020b4c8:	d2800020 	mov	x0, #0x1                   	// #1
    8020b4cc:	9a95d415 	csinc	x21, x0, x21, le
    8020b4d0:	8b1502d5 	add	x21, x22, x21
    8020b4d4:	d2800017 	mov	x23, #0x0                   	// #0
    8020b4d8:	52800022 	mov	w2, #0x1                   	// #1
    8020b4dc:	aa1403e1 	mov	x1, x20
    8020b4e0:	aa1303e0 	mov	x0, x19
    8020b4e4:	94000e3b 	bl	8020edd0 <__lshift>
    8020b4e8:	aa1b03e1 	mov	x1, x27
    8020b4ec:	aa0003f4 	mov	x20, x0
    8020b4f0:	94000e94 	bl	8020ef40 <__mcmp>
    8020b4f4:	7100001f 	cmp	w0, #0x0
    8020b4f8:	5400008c 	b.gt	8020b508 <_dtoa_r+0xa48>
    8020b4fc:	1400013d 	b	8020b9f0 <_dtoa_r+0xf30>
    8020b500:	eb1602bf 	cmp	x21, x22
    8020b504:	54002880 	b.eq	8020ba14 <_dtoa_r+0xf54>  // b.none
    8020b508:	aa1503e2 	mov	x2, x21
    8020b50c:	d10006b5 	sub	x21, x21, #0x1
    8020b510:	385ff040 	ldurb	w0, [x2, #-1]
    8020b514:	7100e41f 	cmp	w0, #0x39
    8020b518:	54ffff40 	b.eq	8020b500 <_dtoa_r+0xa40>  // b.none
    8020b51c:	b9408bfc 	ldr	w28, [sp, #136]
    8020b520:	11000400 	add	w0, w0, #0x1
    8020b524:	390002a0 	strb	w0, [x21]
    8020b528:	aa1b03e1 	mov	x1, x27
    8020b52c:	aa1303e0 	mov	x0, x19
    8020b530:	f9003fe2 	str	x2, [sp, #120]
    8020b534:	94000c53 	bl	8020e680 <_Bfree>
    8020b538:	f9403fe2 	ldr	x2, [sp, #120]
    8020b53c:	b4001db9 	cbz	x25, 8020b8f0 <_dtoa_r+0xe30>
    8020b540:	f10002ff 	cmp	x23, #0x0
    8020b544:	fa5912e4 	ccmp	x23, x25, #0x4, ne	// ne = any
    8020b548:	540000c0 	b.eq	8020b560 <_dtoa_r+0xaa0>  // b.none
    8020b54c:	aa1703e1 	mov	x1, x23
    8020b550:	aa1303e0 	mov	x0, x19
    8020b554:	f9003fe2 	str	x2, [sp, #120]
    8020b558:	94000c4a 	bl	8020e680 <_Bfree>
    8020b55c:	f9403fe2 	ldr	x2, [sp, #120]
    8020b560:	aa1603f7 	mov	x23, x22
    8020b564:	aa0203f6 	mov	x22, x2
    8020b568:	17fffefd 	b	8020b15c <_dtoa_r+0x69c>
    8020b56c:	aa1303e0 	mov	x0, x19
    8020b570:	94000c44 	bl	8020e680 <_Bfree>
    8020b574:	b9408fe0 	ldr	w0, [sp, #140]
    8020b578:	37f800c0 	tbnz	w0, #31, 8020b590 <_dtoa_r+0xad0>
    8020b57c:	b9408fe0 	ldr	w0, [sp, #140]
    8020b580:	1200039c 	and	w28, w28, #0x1
    8020b584:	2a0002e0 	orr	w0, w23, w0
    8020b588:	2a00039c 	orr	w28, w28, w0
    8020b58c:	350004bc 	cbnz	w28, 8020b620 <_dtoa_r+0xb60>
    8020b590:	52800022 	mov	w2, #0x1                   	// #1
    8020b594:	aa1403e1 	mov	x1, x20
    8020b598:	aa1303e0 	mov	x0, x19
    8020b59c:	94000e0d 	bl	8020edd0 <__lshift>
    8020b5a0:	aa1b03e1 	mov	x1, x27
    8020b5a4:	aa0003f4 	mov	x20, x0
    8020b5a8:	94000e66 	bl	8020ef40 <__mcmp>
    8020b5ac:	7100001f 	cmp	w0, #0x0
    8020b5b0:	5400318d 	b.le	8020bbe0 <_dtoa_r+0x1120>
    8020b5b4:	7100e75f 	cmp	w26, #0x39
    8020b5b8:	54002c00 	b.eq	8020bb38 <_dtoa_r+0x1078>  // b.none
    8020b5bc:	b940a3e0 	ldr	w0, [sp, #160]
    8020b5c0:	1100c41a 	add	w26, w0, #0x31
    8020b5c4:	f9404be2 	ldr	x2, [sp, #144]
    8020b5c8:	aa1903f7 	mov	x23, x25
    8020b5cc:	f9403ff9 	ldr	x25, [sp, #120]
    8020b5d0:	b9408bfc 	ldr	w28, [sp, #136]
    8020b5d4:	3800145a 	strb	w26, [x2], #1
    8020b5d8:	17ffffd4 	b	8020b528 <_dtoa_r+0xa68>
    8020b5dc:	94000c31 	bl	8020e6a0 <__multadd>
    8020b5e0:	aa0003f9 	mov	x25, x0
    8020b5e4:	f9003fe0 	str	x0, [sp, #120]
    8020b5e8:	17ffff46 	b	8020b300 <_dtoa_r+0x840>
    8020b5ec:	d280001b 	mov	x27, #0x0                   	// #0
    8020b5f0:	d2800019 	mov	x25, #0x0                   	// #0
    8020b5f4:	2a3a03fc 	mvn	w28, w26
    8020b5f8:	aa1603f7 	mov	x23, x22
    8020b5fc:	17fffed4 	b	8020b14c <_dtoa_r+0x68c>
    8020b600:	b9408fe0 	ldr	w0, [sp, #140]
    8020b604:	37f83040 	tbnz	w0, #31, 8020bc0c <_dtoa_r+0x114c>
    8020b608:	b940a7e1 	ldr	w1, [sp, #164]
    8020b60c:	2a0002e0 	orr	w0, w23, w0
    8020b610:	2a000020 	orr	w0, w1, w0
    8020b614:	34002fc0 	cbz	w0, 8020bc0c <_dtoa_r+0x114c>
    8020b618:	7100005f 	cmp	w2, #0x0
    8020b61c:	54ffeb0d 	b.le	8020b37c <_dtoa_r+0x8bc>
    8020b620:	7100e75f 	cmp	w26, #0x39
    8020b624:	540028a0 	b.eq	8020bb38 <_dtoa_r+0x1078>  // b.none
    8020b628:	f9404be2 	ldr	x2, [sp, #144]
    8020b62c:	1100075a 	add	w26, w26, #0x1
    8020b630:	aa1903f7 	mov	x23, x25
    8020b634:	b9408bfc 	ldr	w28, [sp, #136]
    8020b638:	f9403ff9 	ldr	x25, [sp, #120]
    8020b63c:	3800145a 	strb	w26, [x2], #1
    8020b640:	17ffffba 	b	8020b528 <_dtoa_r+0xa68>
    8020b644:	1e620042 	scvtf	d2, w2
    8020b648:	1e639000 	fmov	d0, #7.000000000000000000e+00
    8020b64c:	52bf9802 	mov	w2, #0xfcc00000            	// #-54525952
    8020b650:	1f410040 	fmadd	d0, d2, d1, d0
    8020b654:	9e660000 	fmov	x0, d0
    8020b658:	d360fc01 	lsr	x1, x0, #32
    8020b65c:	0b020021 	add	w1, w1, w2
    8020b660:	b3607c20 	bfi	x0, x1, #32, #32
    8020b664:	1e629002 	fmov	d2, #5.000000000000000000e+00
    8020b668:	9e670000 	fmov	d0, x0
    8020b66c:	1e623821 	fsub	d1, d1, d2
    8020b670:	1e602030 	fcmpe	d1, d0
    8020b674:	5400066c 	b.gt	8020b740 <_dtoa_r+0xc80>
    8020b678:	1e614000 	fneg	d0, d0
    8020b67c:	1e602030 	fcmpe	d1, d0
    8020b680:	54fffb64 	b.mi	8020b5ec <_dtoa_r+0xb2c>  // b.first
    8020b684:	17fffe33 	b	8020af50 <_dtoa_r+0x490>
    8020b688:	52800380 	mov	w0, #0x1c                  	// #28
    8020b68c:	17fffe7e 	b	8020b084 <_dtoa_r+0x5c4>
    8020b690:	540013e0 	b.eq	8020b90c <_dtoa_r+0xe4c>  // b.none
    8020b694:	b9408be0 	ldr	w0, [sp, #136]
    8020b698:	b0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020b69c:	913a0021 	add	x1, x1, #0xe80
    8020b6a0:	4b0003e0 	neg	w0, w0
    8020b6a4:	92400c02 	and	x2, x0, #0xf
    8020b6a8:	13047c00 	asr	w0, w0, #4
    8020b6ac:	fc627822 	ldr	d2, [x1, x2, lsl #3]
    8020b6b0:	1e620922 	fmul	d2, d9, d2
    8020b6b4:	340029c0 	cbz	w0, 8020bbec <_dtoa_r+0x112c>
    8020b6b8:	1e604041 	fmov	d1, d2
    8020b6bc:	b0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020b6c0:	91394021 	add	x1, x1, #0xe50
    8020b6c4:	52800008 	mov	w8, #0x0                   	// #0
    8020b6c8:	52800042 	mov	w2, #0x2                   	// #2
    8020b6cc:	d503201f 	nop
    8020b6d0:	360000a0 	tbz	w0, #0, 8020b6e4 <_dtoa_r+0xc24>
    8020b6d4:	fd400020 	ldr	d0, [x1]
    8020b6d8:	11000442 	add	w2, w2, #0x1
    8020b6dc:	2a0403e8 	mov	w8, w4
    8020b6e0:	1e600821 	fmul	d1, d1, d0
    8020b6e4:	13017c00 	asr	w0, w0, #1
    8020b6e8:	91002021 	add	x1, x1, #0x8
    8020b6ec:	35ffff20 	cbnz	w0, 8020b6d0 <_dtoa_r+0xc10>
    8020b6f0:	7100011f 	cmp	w8, #0x0
    8020b6f4:	1e621c21 	fcsel	d1, d1, d2, ne	// ne = any
    8020b6f8:	17fffdde 	b	8020ae70 <_dtoa_r+0x3b0>
    8020b6fc:	2a1b03e3 	mov	w3, w27
    8020b700:	d2800019 	mov	x25, #0x0                   	// #0
    8020b704:	b9007bff 	str	wzr, [sp, #120]
    8020b708:	b9008fe7 	str	w7, [sp, #140]
    8020b70c:	17fffe2e 	b	8020afc4 <_dtoa_r+0x504>
    8020b710:	b0000020 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020b714:	913a0000 	add	x0, x0, #0xe80
    8020b718:	7100035f 	cmp	w26, #0x0
    8020b71c:	7a40baa0 	ccmp	w21, #0x0, #0x0, lt	// lt = tstop
    8020b720:	fc61d801 	ldr	d1, [x0, w1, sxtw #3]
    8020b724:	540015ec 	b.gt	8020b9e0 <_dtoa_r+0xf20>
    8020b728:	35fff635 	cbnz	w21, 8020b5ec <_dtoa_r+0xb2c>
    8020b72c:	1e629000 	fmov	d0, #5.000000000000000000e+00
    8020b730:	1e600821 	fmul	d1, d1, d0
    8020b734:	9e670380 	fmov	d0, x28
    8020b738:	1e602030 	fcmpe	d1, d0
    8020b73c:	54fff58a 	b.ge	8020b5ec <_dtoa_r+0xb2c>  // b.tcont
    8020b740:	aa1603f7 	mov	x23, x22
    8020b744:	d280001b 	mov	x27, #0x0                   	// #0
    8020b748:	d2800019 	mov	x25, #0x0                   	// #0
    8020b74c:	17fffe7b 	b	8020b138 <_dtoa_r+0x678>
    8020b750:	5280003a 	mov	w26, #0x1                   	// #1
    8020b754:	2a1a03f5 	mov	w21, w26
    8020b758:	17fffd96 	b	8020adb0 <_dtoa_r+0x2f0>
    8020b75c:	aa0003e1 	mov	x1, x0
    8020b760:	2a0503e2 	mov	w2, w5
    8020b764:	aa1303e0 	mov	x0, x19
    8020b768:	b90093e7 	str	w7, [sp, #144]
    8020b76c:	b9009be6 	str	w6, [sp, #152]
    8020b770:	94000d50 	bl	8020ecb0 <__pow5mult>
    8020b774:	b94093e7 	ldr	w7, [sp, #144]
    8020b778:	aa0003fb 	mov	x27, x0
    8020b77c:	b9409be6 	ldr	w6, [sp, #152]
    8020b780:	710006ff 	cmp	w23, #0x1
    8020b784:	5400020d 	b.le	8020b7c4 <_dtoa_r+0xd04>
    8020b788:	52800005 	mov	w5, #0x0                   	// #0
    8020b78c:	b9401760 	ldr	w0, [x27, #20]
    8020b790:	b90093e7 	str	w7, [sp, #144]
    8020b794:	51000400 	sub	w0, w0, #0x1
    8020b798:	b9009be6 	str	w6, [sp, #152]
    8020b79c:	b900a7e5 	str	w5, [sp, #164]
    8020b7a0:	8b20cb60 	add	x0, x27, w0, sxtw #2
    8020b7a4:	b9401800 	ldr	w0, [x0, #24]
    8020b7a8:	94000c4e 	bl	8020e8e0 <__hi0bits>
    8020b7ac:	52800401 	mov	w1, #0x20                  	// #32
    8020b7b0:	b94093e7 	ldr	w7, [sp, #144]
    8020b7b4:	b9409be6 	ldr	w6, [sp, #152]
    8020b7b8:	4b000020 	sub	w0, w1, w0
    8020b7bc:	b940a7e5 	ldr	w5, [sp, #164]
    8020b7c0:	17fffe28 	b	8020b060 <_dtoa_r+0x5a0>
    8020b7c4:	f240cf9f 	tst	x28, #0xfffffffffffff
    8020b7c8:	54fffe01 	b.ne	8020b788 <_dtoa_r+0xcc8>  // b.any
    8020b7cc:	d360ff80 	lsr	x0, x28, #32
    8020b7d0:	f26c281f 	tst	x0, #0x7ff00000
    8020b7d4:	54fffda0 	b.eq	8020b788 <_dtoa_r+0xcc8>  // b.none
    8020b7d8:	110004e7 	add	w7, w7, #0x1
    8020b7dc:	110004c6 	add	w6, w6, #0x1
    8020b7e0:	52800025 	mov	w5, #0x1                   	// #1
    8020b7e4:	17ffffea 	b	8020b78c <_dtoa_r+0xccc>
    8020b7e8:	1e604121 	fmov	d1, d9
    8020b7ec:	52800042 	mov	w2, #0x2                   	// #2
    8020b7f0:	17fffd94 	b	8020ae40 <_dtoa_r+0x380>
    8020b7f4:	b9007bff 	str	wzr, [sp, #120]
    8020b7f8:	17fffea7 	b	8020b294 <_dtoa_r+0x7d4>
    8020b7fc:	390002c0 	strb	w0, [x22]
    8020b800:	1e630842 	fmul	d2, d2, d3
    8020b804:	8b2442c0 	add	x0, x22, w4, uxtw
    8020b808:	aa0903e2 	mov	x2, x9
    8020b80c:	1e649003 	fmov	d3, #1.000000000000000000e+01
    8020b810:	7100049f 	cmp	w4, #0x1
    8020b814:	54001c40 	b.eq	8020bb9c <_dtoa_r+0x10dc>  // b.none
    8020b818:	1e630821 	fmul	d1, d1, d3
    8020b81c:	1e780021 	fcvtzs	w1, d1
    8020b820:	1e620020 	scvtf	d0, w1
    8020b824:	1100c021 	add	w1, w1, #0x30
    8020b828:	38001441 	strb	w1, [x2], #1
    8020b82c:	1e603821 	fsub	d1, d1, d0
    8020b830:	eb02001f 	cmp	x0, x2
    8020b834:	54ffff21 	b.ne	8020b818 <_dtoa_r+0xd58>  // b.any
    8020b838:	1e6c1000 	fmov	d0, #5.000000000000000000e-01
    8020b83c:	1e602843 	fadd	d3, d2, d0
    8020b840:	1e612070 	fcmpe	d3, d1
    8020b844:	54ffcfa4 	b.mi	8020b238 <_dtoa_r+0x778>  // b.first
    8020b848:	1e623800 	fsub	d0, d0, d2
    8020b84c:	1e612010 	fcmpe	d0, d1
    8020b850:	5400048c 	b.gt	8020b8e0 <_dtoa_r+0xe20>
    8020b854:	b940bfe0 	ldr	w0, [sp, #188]
    8020b858:	9e66013c 	fmov	x28, d9
    8020b85c:	7100001f 	cmp	w0, #0x0
    8020b860:	b9408be0 	ldr	w0, [sp, #136]
    8020b864:	7a4ea800 	ccmp	w0, #0xe, #0x0, ge	// ge = tcont
    8020b868:	54fff4ac 	b.gt	8020b6fc <_dtoa_r+0xc3c>
    8020b86c:	b9408be0 	ldr	w0, [sp, #136]
    8020b870:	aa1603f7 	mov	x23, x22
    8020b874:	aa0903f6 	mov	x22, x9
    8020b878:	fc60d901 	ldr	d1, [x8, w0, sxtw #3]
    8020b87c:	1e611920 	fdiv	d0, d9, d1
    8020b880:	51000460 	sub	w0, w3, #0x1
    8020b884:	8b0002c0 	add	x0, x22, x0
    8020b888:	1e649003 	fmov	d3, #1.000000000000000000e+01
    8020b88c:	1e780001 	fcvtzs	w1, d0
    8020b890:	1e620020 	scvtf	d0, w1
    8020b894:	1100c022 	add	w2, w1, #0x30
    8020b898:	390002e2 	strb	w2, [x23]
    8020b89c:	1f41a400 	fmsub	d0, d0, d1, d9
    8020b8a0:	710006bf 	cmp	w21, #0x1
    8020b8a4:	54000141 	b.ne	8020b8cc <_dtoa_r+0xe0c>  // b.any
    8020b8a8:	14000097 	b	8020bb04 <_dtoa_r+0x1044>
    8020b8ac:	1e611802 	fdiv	d2, d0, d1
    8020b8b0:	1e780041 	fcvtzs	w1, d2
    8020b8b4:	1e620022 	scvtf	d2, w1
    8020b8b8:	1100c022 	add	w2, w1, #0x30
    8020b8bc:	380016c2 	strb	w2, [x22], #1
    8020b8c0:	1f418040 	fmsub	d0, d2, d1, d0
    8020b8c4:	eb16001f 	cmp	x0, x22
    8020b8c8:	54001200 	b.eq	8020bb08 <_dtoa_r+0x1048>  // b.none
    8020b8cc:	1e630800 	fmul	d0, d0, d3
    8020b8d0:	1e602008 	fcmp	d0, #0.0
    8020b8d4:	54fffec1 	b.ne	8020b8ac <_dtoa_r+0xdec>  // b.any
    8020b8d8:	b9408bfc 	ldr	w28, [sp, #136]
    8020b8dc:	17fffe61 	b	8020b260 <_dtoa_r+0x7a0>
    8020b8e0:	aa0003e2 	mov	x2, x0
    8020b8e4:	385ffc01 	ldrb	w1, [x0, #-1]!
    8020b8e8:	7100c03f 	cmp	w1, #0x30
    8020b8ec:	54ffffa0 	b.eq	8020b8e0 <_dtoa_r+0xe20>  // b.none
    8020b8f0:	aa1603f7 	mov	x23, x22
    8020b8f4:	aa0203f6 	mov	x22, x2
    8020b8f8:	17fffe5a 	b	8020b260 <_dtoa_r+0x7a0>
    8020b8fc:	52800781 	mov	w1, #0x3c                  	// #60
    8020b900:	4b000020 	sub	w0, w1, w0
    8020b904:	54ffbca0 	b.eq	8020b098 <_dtoa_r+0x5d8>  // b.none
    8020b908:	17fffddf 	b	8020b084 <_dtoa_r+0x5c4>
    8020b90c:	1e604121 	fmov	d1, d9
    8020b910:	52800042 	mov	w2, #0x2                   	// #2
    8020b914:	17fffd57 	b	8020ae70 <_dtoa_r+0x3b0>
    8020b918:	34ffe975 	cbz	w21, 8020b644 <_dtoa_r+0xb84>
    8020b91c:	b940abe4 	ldr	w4, [sp, #168]
    8020b920:	7100009f 	cmp	w4, #0x0
    8020b924:	54ffb16d 	b.le	8020af50 <_dtoa_r+0x490>
    8020b928:	11000442 	add	w2, w2, #0x1
    8020b92c:	1e649003 	fmov	d3, #1.000000000000000000e+01
    8020b930:	1e639000 	fmov	d0, #7.000000000000000000e+00
    8020b934:	b9408be0 	ldr	w0, [sp, #136]
    8020b938:	1e620042 	scvtf	d2, w2
    8020b93c:	1e630821 	fmul	d1, d1, d3
    8020b940:	5100041c 	sub	w28, w0, #0x1
    8020b944:	52bf9808 	mov	w8, #0xfcc00000            	// #-54525952
    8020b948:	1f420020 	fmadd	d0, d1, d2, d0
    8020b94c:	9e660000 	fmov	x0, d0
    8020b950:	d360fc01 	lsr	x1, x0, #32
    8020b954:	0b080021 	add	w1, w1, w8
    8020b958:	b3607c20 	bfi	x0, x1, #32, #32
    8020b95c:	17fffd55 	b	8020aeb0 <_dtoa_r+0x3f0>
    8020b960:	b940a7e1 	ldr	w1, [sp, #164]
    8020b964:	34000981 	cbz	w1, 8020ba94 <_dtoa_r+0xfd4>
    8020b968:	1110cc00 	add	w0, w0, #0x433
    8020b96c:	2a1b03e3 	mov	w3, w27
    8020b970:	0b0000c6 	add	w6, w6, w0
    8020b974:	b9008fe7 	str	w7, [sp, #140]
    8020b978:	0b0000e7 	add	w7, w7, w0
    8020b97c:	17fffd86 	b	8020af94 <_dtoa_r+0x4d4>
    8020b980:	911b82f7 	add	x23, x23, #0x6e0
    8020b984:	17fffc82 	b	8020ab8c <_dtoa_r+0xcc>
    8020b988:	911b42f7 	add	x23, x23, #0x6d0
    8020b98c:	17fffc80 	b	8020ab8c <_dtoa_r+0xcc>
    8020b990:	aa1403e1 	mov	x1, x20
    8020b994:	2a1b03e2 	mov	w2, w27
    8020b998:	aa1303e0 	mov	x0, x19
    8020b99c:	b90093e7 	str	w7, [sp, #144]
    8020b9a0:	b9009be6 	str	w6, [sp, #152]
    8020b9a4:	b900a7e5 	str	w5, [sp, #164]
    8020b9a8:	94000cc2 	bl	8020ecb0 <__pow5mult>
    8020b9ac:	b94093e7 	ldr	w7, [sp, #144]
    8020b9b0:	aa0003f4 	mov	x20, x0
    8020b9b4:	b9409be6 	ldr	w6, [sp, #152]
    8020b9b8:	b940a7e5 	ldr	w5, [sp, #164]
    8020b9bc:	17fffd9b 	b	8020b028 <_dtoa_r+0x568>
    8020b9c0:	4b1b0060 	sub	w0, w3, w27
    8020b9c4:	0b1500c6 	add	w6, w6, w21
    8020b9c8:	2a0303fb 	mov	w27, w3
    8020b9cc:	0b0000a5 	add	w5, w5, w0
    8020b9d0:	52800003 	mov	w3, #0x0                   	// #0
    8020b9d4:	b9008fe7 	str	w7, [sp, #140]
    8020b9d8:	0b0702a7 	add	w7, w21, w7
    8020b9dc:	17fffd6e 	b	8020af94 <_dtoa_r+0x4d4>
    8020b9e0:	aa1603f7 	mov	x23, x22
    8020b9e4:	9e670389 	fmov	d9, x28
    8020b9e8:	910006d6 	add	x22, x22, #0x1
    8020b9ec:	17ffffa4 	b	8020b87c <_dtoa_r+0xdbc>
    8020b9f0:	54000041 	b.ne	8020b9f8 <_dtoa_r+0xf38>  // b.any
    8020b9f4:	3707d8ba 	tbnz	w26, #0, 8020b508 <_dtoa_r+0xa48>
    8020b9f8:	aa1503e2 	mov	x2, x21
    8020b9fc:	d10006b5 	sub	x21, x21, #0x1
    8020ba00:	385ff040 	ldurb	w0, [x2, #-1]
    8020ba04:	7100c01f 	cmp	w0, #0x30
    8020ba08:	54ffff80 	b.eq	8020b9f8 <_dtoa_r+0xf38>  // b.none
    8020ba0c:	b9408bfc 	ldr	w28, [sp, #136]
    8020ba10:	17fffec6 	b	8020b528 <_dtoa_r+0xa68>
    8020ba14:	b9408be0 	ldr	w0, [sp, #136]
    8020ba18:	1100041c 	add	w28, w0, #0x1
    8020ba1c:	52800620 	mov	w0, #0x31                  	// #49
    8020ba20:	390002c0 	strb	w0, [x22]
    8020ba24:	17fffec1 	b	8020b528 <_dtoa_r+0xa68>
    8020ba28:	2a0303e2 	mov	w2, w3
    8020ba2c:	aa1903e1 	mov	x1, x25
    8020ba30:	aa1303e0 	mov	x0, x19
    8020ba34:	b90093e3 	str	w3, [sp, #144]
    8020ba38:	b9009be7 	str	w7, [sp, #152]
    8020ba3c:	b900a7e6 	str	w6, [sp, #164]
    8020ba40:	b900afe5 	str	w5, [sp, #172]
    8020ba44:	94000c9b 	bl	8020ecb0 <__pow5mult>
    8020ba48:	aa1403e2 	mov	x2, x20
    8020ba4c:	aa0003f9 	mov	x25, x0
    8020ba50:	aa1903e1 	mov	x1, x25
    8020ba54:	aa1303e0 	mov	x0, x19
    8020ba58:	94000c1a 	bl	8020eac0 <__multiply>
    8020ba5c:	aa1403e1 	mov	x1, x20
    8020ba60:	aa0003f4 	mov	x20, x0
    8020ba64:	aa1303e0 	mov	x0, x19
    8020ba68:	94000b06 	bl	8020e680 <_Bfree>
    8020ba6c:	b94093e3 	ldr	w3, [sp, #144]
    8020ba70:	b9409be7 	ldr	w7, [sp, #152]
    8020ba74:	b940a7e6 	ldr	w6, [sp, #164]
    8020ba78:	6b03037b 	subs	w27, w27, w3
    8020ba7c:	b940afe5 	ldr	w5, [sp, #172]
    8020ba80:	54ffad40 	b.eq	8020b028 <_dtoa_r+0x568>  // b.none
    8020ba84:	17fffd5e 	b	8020affc <_dtoa_r+0x53c>
    8020ba88:	1100079c 	add	w28, w28, #0x1
    8020ba8c:	52800621 	mov	w1, #0x31                  	// #49
    8020ba90:	17fffdf0 	b	8020b250 <_dtoa_r+0x790>
    8020ba94:	b940bbe1 	ldr	w1, [sp, #184]
    8020ba98:	528006c0 	mov	w0, #0x36                  	// #54
    8020ba9c:	2a1b03e3 	mov	w3, w27
    8020baa0:	b9008fe7 	str	w7, [sp, #140]
    8020baa4:	4b010000 	sub	w0, w0, w1
    8020baa8:	0b0000c6 	add	w6, w6, w0
    8020baac:	0b0000e7 	add	w7, w7, w0
    8020bab0:	17fffd39 	b	8020af94 <_dtoa_r+0x4d4>
    8020bab4:	b9400b21 	ldr	w1, [x25, #8]
    8020bab8:	aa1303e0 	mov	x0, x19
    8020babc:	94000acd 	bl	8020e5f0 <_Balloc>
    8020bac0:	aa0003fa 	mov	x26, x0
    8020bac4:	b4000aa0 	cbz	x0, 8020bc18 <_dtoa_r+0x1158>
    8020bac8:	b9801722 	ldrsw	x2, [x25, #20]
    8020bacc:	91004321 	add	x1, x25, #0x10
    8020bad0:	91004000 	add	x0, x0, #0x10
    8020bad4:	91000842 	add	x2, x2, #0x2
    8020bad8:	d37ef442 	lsl	x2, x2, #2
    8020badc:	97fffae9 	bl	8020a680 <memcpy>
    8020bae0:	aa1a03e1 	mov	x1, x26
    8020bae4:	aa1303e0 	mov	x0, x19
    8020bae8:	52800022 	mov	w2, #0x1                   	// #1
    8020baec:	94000cb9 	bl	8020edd0 <__lshift>
    8020baf0:	f9003fe0 	str	x0, [sp, #120]
    8020baf4:	17fffdff 	b	8020b2f0 <_dtoa_r+0x830>
    8020baf8:	aa1603f7 	mov	x23, x22
    8020bafc:	aa0003f6 	mov	x22, x0
    8020bb00:	17fffdd8 	b	8020b260 <_dtoa_r+0x7a0>
    8020bb04:	aa1603e0 	mov	x0, x22
    8020bb08:	1e602800 	fadd	d0, d0, d0
    8020bb0c:	1e612010 	fcmpe	d0, d1
    8020bb10:	5400020c 	b.gt	8020bb50 <_dtoa_r+0x1090>
    8020bb14:	1e612000 	fcmp	d0, d1
    8020bb18:	54000041 	b.ne	8020bb20 <_dtoa_r+0x1060>  // b.any
    8020bb1c:	370001a1 	tbnz	w1, #0, 8020bb50 <_dtoa_r+0x1090>
    8020bb20:	b9408bfc 	ldr	w28, [sp, #136]
    8020bb24:	aa0003f6 	mov	x22, x0
    8020bb28:	17fffdce 	b	8020b260 <_dtoa_r+0x7a0>
    8020bb2c:	aa1903f7 	mov	x23, x25
    8020bb30:	f9403ff9 	ldr	x25, [sp, #120]
    8020bb34:	17fffe69 	b	8020b4d8 <_dtoa_r+0xa18>
    8020bb38:	f9404bf5 	ldr	x21, [sp, #144]
    8020bb3c:	aa1903f7 	mov	x23, x25
    8020bb40:	f9403ff9 	ldr	x25, [sp, #120]
    8020bb44:	52800720 	mov	w0, #0x39                  	// #57
    8020bb48:	380016a0 	strb	w0, [x21], #1
    8020bb4c:	17fffe6f 	b	8020b508 <_dtoa_r+0xa48>
    8020bb50:	b9408bfc 	ldr	w28, [sp, #136]
    8020bb54:	aa1703f6 	mov	x22, x23
    8020bb58:	17fffdb8 	b	8020b238 <_dtoa_r+0x778>
    8020bb5c:	0b1500c6 	add	w6, w6, w21
    8020bb60:	b9008fe7 	str	w7, [sp, #140]
    8020bb64:	0b0702a7 	add	w7, w21, w7
    8020bb68:	17fffd0b 	b	8020af94 <_dtoa_r+0x4d4>
    8020bb6c:	7100e75f 	cmp	w26, #0x39
    8020bb70:	54fffe40 	b.eq	8020bb38 <_dtoa_r+0x1078>  // b.none
    8020bb74:	f9404be2 	ldr	x2, [sp, #144]
    8020bb78:	aa1903f7 	mov	x23, x25
    8020bb7c:	295107fc 	ldp	w28, w1, [sp, #136]
    8020bb80:	b940a3e0 	ldr	w0, [sp, #160]
    8020bb84:	7100003f 	cmp	w1, #0x0
    8020bb88:	1100c400 	add	w0, w0, #0x31
    8020bb8c:	f9403ff9 	ldr	x25, [sp, #120]
    8020bb90:	1a9ac01a 	csel	w26, w0, w26, gt
    8020bb94:	3800145a 	strb	w26, [x2], #1
    8020bb98:	17fffe64 	b	8020b528 <_dtoa_r+0xa68>
    8020bb9c:	aa0903e0 	mov	x0, x9
    8020bba0:	17ffff26 	b	8020b838 <_dtoa_r+0xd78>
    8020bba4:	aa1903e1 	mov	x1, x25
    8020bba8:	aa1303e0 	mov	x0, x19
    8020bbac:	52800003 	mov	w3, #0x0                   	// #0
    8020bbb0:	52800142 	mov	w2, #0xa                   	// #10
    8020bbb4:	b9007be5 	str	w5, [sp, #120]
    8020bbb8:	b90093e4 	str	w4, [sp, #144]
    8020bbbc:	94000ab9 	bl	8020e6a0 <__multadd>
    8020bbc0:	b940abf5 	ldr	w21, [sp, #168]
    8020bbc4:	aa0003f9 	mov	x25, x0
    8020bbc8:	b94093e4 	ldr	w4, [sp, #144]
    8020bbcc:	710002bf 	cmp	w21, #0x0
    8020bbd0:	7a40d884 	ccmp	w4, #0x0, #0x4, le
    8020bbd4:	54000121 	b.ne	8020bbf8 <_dtoa_r+0x1138>  // b.any
    8020bbd8:	b9407be5 	ldr	w5, [sp, #120]
    8020bbdc:	17fffdba 	b	8020b2c4 <_dtoa_r+0x804>
    8020bbe0:	54ffcf21 	b.ne	8020b5c4 <_dtoa_r+0xb04>  // b.any
    8020bbe4:	3707ce9a 	tbnz	w26, #0, 8020b5b4 <_dtoa_r+0xaf4>
    8020bbe8:	17fffe77 	b	8020b5c4 <_dtoa_r+0xb04>
    8020bbec:	1e604041 	fmov	d1, d2
    8020bbf0:	52800042 	mov	w2, #0x2                   	// #2
    8020bbf4:	17fffc9f 	b	8020ae70 <_dtoa_r+0x3b0>
    8020bbf8:	b940abf5 	ldr	w21, [sp, #168]
    8020bbfc:	17fffd42 	b	8020b104 <_dtoa_r+0x644>
    8020bc00:	aa1603f7 	mov	x23, x22
    8020bc04:	aa0903f6 	mov	x22, x9
    8020bc08:	17fffd96 	b	8020b260 <_dtoa_r+0x7a0>
    8020bc0c:	7100005f 	cmp	w2, #0x0
    8020bc10:	54ffcc0c 	b.gt	8020b590 <_dtoa_r+0xad0>
    8020bc14:	17fffe6c 	b	8020b5c4 <_dtoa_r+0xb04>
    8020bc18:	b0000023 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020bc1c:	b0000020 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020bc20:	911ba063 	add	x3, x3, #0x6e8
    8020bc24:	911c0000 	add	x0, x0, #0x700
    8020bc28:	d2800002 	mov	x2, #0x0                   	// #0
    8020bc2c:	52805de1 	mov	w1, #0x2ef                 	// #751
    8020bc30:	94000a14 	bl	8020e480 <__assert_func>
    8020bc34:	b0000023 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020bc38:	b0000020 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020bc3c:	911ba063 	add	x3, x3, #0x6e8
    8020bc40:	911c0000 	add	x0, x0, #0x700
    8020bc44:	d2800002 	mov	x2, #0x0                   	// #0
    8020bc48:	528035e1 	mov	w1, #0x1af                 	// #431
    8020bc4c:	94000a0d 	bl	8020e480 <__assert_func>
    8020bc50:	b9007bff 	str	wzr, [sp, #120]
    8020bc54:	17fffc23 	b	8020ace0 <_dtoa_r+0x220>
	...

000000008020bc60 <__set_ctype>:
    8020bc60:	b0000021 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020bc64:	91318021 	add	x1, x1, #0xc60
    8020bc68:	f9007c01 	str	x1, [x0, #248]
    8020bc6c:	d65f03c0 	ret

000000008020bc70 <_close_r>:
    8020bc70:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020bc74:	910003fd 	mov	x29, sp
    8020bc78:	a90153f3 	stp	x19, x20, [sp, #16]
    8020bc7c:	b00003b4 	adrp	x20, 80280000 <gits_lock>
    8020bc80:	aa0003f3 	mov	x19, x0
    8020bc84:	b9048a9f 	str	wzr, [x20, #1160]
    8020bc88:	2a0103e0 	mov	w0, w1
    8020bc8c:	97ffd335 	bl	80200960 <_close>
    8020bc90:	3100041f 	cmn	w0, #0x1
    8020bc94:	54000080 	b.eq	8020bca4 <_close_r+0x34>  // b.none
    8020bc98:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020bc9c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020bca0:	d65f03c0 	ret
    8020bca4:	b9448a81 	ldr	w1, [x20, #1160]
    8020bca8:	34ffff81 	cbz	w1, 8020bc98 <_close_r+0x28>
    8020bcac:	b9000261 	str	w1, [x19]
    8020bcb0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020bcb4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020bcb8:	d65f03c0 	ret
    8020bcbc:	00000000 	udf	#0

000000008020bcc0 <_reclaim_reent>:
    8020bcc0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020bcc4:	d0000021 	adrp	x1, 80211000 <__mprec_tens+0x180>
    8020bcc8:	910003fd 	mov	x29, sp
    8020bccc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020bcd0:	aa0003f4 	mov	x20, x0
    8020bcd4:	f9402420 	ldr	x0, [x1, #72]
    8020bcd8:	eb14001f 	cmp	x0, x20
    8020bcdc:	54000440 	b.eq	8020bd64 <_reclaim_reent+0xa4>  // b.none
    8020bce0:	f9403681 	ldr	x1, [x20, #104]
    8020bce4:	b4000221 	cbz	x1, 8020bd28 <_reclaim_reent+0x68>
    8020bce8:	f90013f5 	str	x21, [sp, #32]
    8020bcec:	d2800015 	mov	x21, #0x0                   	// #0
    8020bcf0:	f8756833 	ldr	x19, [x1, x21]
    8020bcf4:	b40000f3 	cbz	x19, 8020bd10 <_reclaim_reent+0x50>
    8020bcf8:	aa1303e1 	mov	x1, x19
    8020bcfc:	aa1403e0 	mov	x0, x20
    8020bd00:	f9400273 	ldr	x19, [x19]
    8020bd04:	940002bf 	bl	8020c800 <_free_r>
    8020bd08:	b5ffff93 	cbnz	x19, 8020bcf8 <_reclaim_reent+0x38>
    8020bd0c:	f9403681 	ldr	x1, [x20, #104]
    8020bd10:	910022b5 	add	x21, x21, #0x8
    8020bd14:	f10802bf 	cmp	x21, #0x200
    8020bd18:	54fffec1 	b.ne	8020bcf0 <_reclaim_reent+0x30>  // b.any
    8020bd1c:	aa1403e0 	mov	x0, x20
    8020bd20:	940002b8 	bl	8020c800 <_free_r>
    8020bd24:	f94013f5 	ldr	x21, [sp, #32]
    8020bd28:	f9402a81 	ldr	x1, [x20, #80]
    8020bd2c:	b4000061 	cbz	x1, 8020bd38 <_reclaim_reent+0x78>
    8020bd30:	aa1403e0 	mov	x0, x20
    8020bd34:	940002b3 	bl	8020c800 <_free_r>
    8020bd38:	f9403e81 	ldr	x1, [x20, #120]
    8020bd3c:	b4000061 	cbz	x1, 8020bd48 <_reclaim_reent+0x88>
    8020bd40:	aa1403e0 	mov	x0, x20
    8020bd44:	940002af 	bl	8020c800 <_free_r>
    8020bd48:	f9402681 	ldr	x1, [x20, #72]
    8020bd4c:	b40000c1 	cbz	x1, 8020bd64 <_reclaim_reent+0xa4>
    8020bd50:	aa1403e0 	mov	x0, x20
    8020bd54:	aa0103f0 	mov	x16, x1
    8020bd58:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020bd5c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020bd60:	d61f0200 	br	x16
    8020bd64:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020bd68:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020bd6c:	d65f03c0 	ret

000000008020bd70 <__sflush_r>:
    8020bd70:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020bd74:	910003fd 	mov	x29, sp
    8020bd78:	79c02022 	ldrsh	w2, [x1, #16]
    8020bd7c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020bd80:	aa0103f3 	mov	x19, x1
    8020bd84:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020bd88:	aa0003f6 	mov	x22, x0
    8020bd8c:	371807e2 	tbnz	w2, #3, 8020be88 <__sflush_r+0x118>
    8020bd90:	32150040 	orr	w0, w2, #0x800
    8020bd94:	79002020 	strh	w0, [x1, #16]
    8020bd98:	b9400821 	ldr	w1, [x1, #8]
    8020bd9c:	7100003f 	cmp	w1, #0x0
    8020bda0:	54000b8d 	b.le	8020bf10 <__sflush_r+0x1a0>
    8020bda4:	f9402664 	ldr	x4, [x19, #72]
    8020bda8:	b4000664 	cbz	x4, 8020be74 <__sflush_r+0x104>
    8020bdac:	f9401a61 	ldr	x1, [x19, #48]
    8020bdb0:	b94002d4 	ldr	w20, [x22]
    8020bdb4:	b90002df 	str	wzr, [x22]
    8020bdb8:	37600b62 	tbnz	w2, #12, 8020bf24 <__sflush_r+0x1b4>
    8020bdbc:	d2800002 	mov	x2, #0x0                   	// #0
    8020bdc0:	aa1603e0 	mov	x0, x22
    8020bdc4:	52800023 	mov	w3, #0x1                   	// #1
    8020bdc8:	d63f0080 	blr	x4
    8020bdcc:	aa0003e2 	mov	x2, x0
    8020bdd0:	b100041f 	cmn	x0, #0x1
    8020bdd4:	54000be0 	b.eq	8020bf50 <__sflush_r+0x1e0>  // b.none
    8020bdd8:	f9401a61 	ldr	x1, [x19, #48]
    8020bddc:	f9402664 	ldr	x4, [x19, #72]
    8020bde0:	79c02260 	ldrsh	w0, [x19, #16]
    8020bde4:	361000e0 	tbz	w0, #2, 8020be00 <__sflush_r+0x90>
    8020bde8:	f9402e60 	ldr	x0, [x19, #88]
    8020bdec:	b9800a63 	ldrsw	x3, [x19, #8]
    8020bdf0:	cb030042 	sub	x2, x2, x3
    8020bdf4:	b4000060 	cbz	x0, 8020be00 <__sflush_r+0x90>
    8020bdf8:	b9807260 	ldrsw	x0, [x19, #112]
    8020bdfc:	cb000042 	sub	x2, x2, x0
    8020be00:	aa1603e0 	mov	x0, x22
    8020be04:	52800003 	mov	w3, #0x0                   	// #0
    8020be08:	d63f0080 	blr	x4
    8020be0c:	b100041f 	cmn	x0, #0x1
    8020be10:	540008e1 	b.ne	8020bf2c <__sflush_r+0x1bc>  // b.any
    8020be14:	b94002c3 	ldr	w3, [x22]
    8020be18:	79c02261 	ldrsh	w1, [x19, #16]
    8020be1c:	7100747f 	cmp	w3, #0x1d
    8020be20:	540006a8 	b.hi	8020bef4 <__sflush_r+0x184>  // b.pmore
    8020be24:	d2800022 	mov	x2, #0x1                   	// #1
    8020be28:	f2a40802 	movk	x2, #0x2040, lsl #16
    8020be2c:	9ac32442 	lsr	x2, x2, x3
    8020be30:	36000622 	tbz	w2, #0, 8020bef4 <__sflush_r+0x184>
    8020be34:	f9400e64 	ldr	x4, [x19, #24]
    8020be38:	12147822 	and	w2, w1, #0xfffff7ff
    8020be3c:	f9000264 	str	x4, [x19]
    8020be40:	b9000a7f 	str	wzr, [x19, #8]
    8020be44:	79002262 	strh	w2, [x19, #16]
    8020be48:	36600041 	tbz	w1, #12, 8020be50 <__sflush_r+0xe0>
    8020be4c:	340007e3 	cbz	w3, 8020bf48 <__sflush_r+0x1d8>
    8020be50:	f9402e61 	ldr	x1, [x19, #88]
    8020be54:	b90002d4 	str	w20, [x22]
    8020be58:	b40000e1 	cbz	x1, 8020be74 <__sflush_r+0x104>
    8020be5c:	9101d260 	add	x0, x19, #0x74
    8020be60:	eb00003f 	cmp	x1, x0
    8020be64:	54000060 	b.eq	8020be70 <__sflush_r+0x100>  // b.none
    8020be68:	aa1603e0 	mov	x0, x22
    8020be6c:	94000265 	bl	8020c800 <_free_r>
    8020be70:	f9002e7f 	str	xzr, [x19, #88]
    8020be74:	52800000 	mov	w0, #0x0                   	// #0
    8020be78:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020be7c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020be80:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020be84:	d65f03c0 	ret
    8020be88:	f9400c35 	ldr	x21, [x1, #24]
    8020be8c:	b4ffff55 	cbz	x21, 8020be74 <__sflush_r+0x104>
    8020be90:	f9400021 	ldr	x1, [x1]
    8020be94:	f9000275 	str	x21, [x19]
    8020be98:	52800000 	mov	w0, #0x0                   	// #0
    8020be9c:	cb150021 	sub	x1, x1, x21
    8020bea0:	2a0103f4 	mov	w20, w1
    8020bea4:	f240045f 	tst	x2, #0x3
    8020bea8:	54000041 	b.ne	8020beb0 <__sflush_r+0x140>  // b.any
    8020beac:	b9402260 	ldr	w0, [x19, #32]
    8020beb0:	b9000e60 	str	w0, [x19, #12]
    8020beb4:	7100003f 	cmp	w1, #0x0
    8020beb8:	540000ac 	b.gt	8020becc <__sflush_r+0x15c>
    8020bebc:	17ffffee 	b	8020be74 <__sflush_r+0x104>
    8020bec0:	8b20c2b5 	add	x21, x21, w0, sxtw
    8020bec4:	7100029f 	cmp	w20, #0x0
    8020bec8:	54fffd6d 	b.le	8020be74 <__sflush_r+0x104>
    8020becc:	f9401a61 	ldr	x1, [x19, #48]
    8020bed0:	2a1403e3 	mov	w3, w20
    8020bed4:	f9402264 	ldr	x4, [x19, #64]
    8020bed8:	aa1503e2 	mov	x2, x21
    8020bedc:	aa1603e0 	mov	x0, x22
    8020bee0:	d63f0080 	blr	x4
    8020bee4:	4b000294 	sub	w20, w20, w0
    8020bee8:	7100001f 	cmp	w0, #0x0
    8020beec:	54fffeac 	b.gt	8020bec0 <__sflush_r+0x150>
    8020bef0:	79c02261 	ldrsh	w1, [x19, #16]
    8020bef4:	321a0021 	orr	w1, w1, #0x40
    8020bef8:	79002261 	strh	w1, [x19, #16]
    8020befc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020bf00:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020bf04:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020bf08:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020bf0c:	d65f03c0 	ret
    8020bf10:	b9407261 	ldr	w1, [x19, #112]
    8020bf14:	7100003f 	cmp	w1, #0x0
    8020bf18:	54fff46c 	b.gt	8020bda4 <__sflush_r+0x34>
    8020bf1c:	52800000 	mov	w0, #0x0                   	// #0
    8020bf20:	17ffffd6 	b	8020be78 <__sflush_r+0x108>
    8020bf24:	f9404a62 	ldr	x2, [x19, #144]
    8020bf28:	17ffffaf 	b	8020bde4 <__sflush_r+0x74>
    8020bf2c:	79c02261 	ldrsh	w1, [x19, #16]
    8020bf30:	f9400e63 	ldr	x3, [x19, #24]
    8020bf34:	12147822 	and	w2, w1, #0xfffff7ff
    8020bf38:	f9000263 	str	x3, [x19]
    8020bf3c:	b9000a7f 	str	wzr, [x19, #8]
    8020bf40:	79002262 	strh	w2, [x19, #16]
    8020bf44:	3667f861 	tbz	w1, #12, 8020be50 <__sflush_r+0xe0>
    8020bf48:	f9004a60 	str	x0, [x19, #144]
    8020bf4c:	17ffffc1 	b	8020be50 <__sflush_r+0xe0>
    8020bf50:	b94002c0 	ldr	w0, [x22]
    8020bf54:	34fff420 	cbz	w0, 8020bdd8 <__sflush_r+0x68>
    8020bf58:	7100741f 	cmp	w0, #0x1d
    8020bf5c:	7a561804 	ccmp	w0, #0x16, #0x4, ne	// ne = any
    8020bf60:	54fffc81 	b.ne	8020bef0 <__sflush_r+0x180>  // b.any
    8020bf64:	52800000 	mov	w0, #0x0                   	// #0
    8020bf68:	b90002d4 	str	w20, [x22]
    8020bf6c:	17ffffc3 	b	8020be78 <__sflush_r+0x108>

000000008020bf70 <_fflush_r>:
    8020bf70:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020bf74:	910003fd 	mov	x29, sp
    8020bf78:	a90153f3 	stp	x19, x20, [sp, #16]
    8020bf7c:	aa0103f3 	mov	x19, x1
    8020bf80:	aa0003f4 	mov	x20, x0
    8020bf84:	f90013f5 	str	x21, [sp, #32]
    8020bf88:	b4000060 	cbz	x0, 8020bf94 <_fflush_r+0x24>
    8020bf8c:	f9402401 	ldr	x1, [x0, #72]
    8020bf90:	b4000481 	cbz	x1, 8020c020 <_fflush_r+0xb0>
    8020bf94:	79c02260 	ldrsh	w0, [x19, #16]
    8020bf98:	52800015 	mov	w21, #0x0                   	// #0
    8020bf9c:	34000180 	cbz	w0, 8020bfcc <_fflush_r+0x5c>
    8020bfa0:	b940b261 	ldr	w1, [x19, #176]
    8020bfa4:	37000041 	tbnz	w1, #0, 8020bfac <_fflush_r+0x3c>
    8020bfa8:	364801c0 	tbz	w0, #9, 8020bfe0 <_fflush_r+0x70>
    8020bfac:	aa1303e1 	mov	x1, x19
    8020bfb0:	aa1403e0 	mov	x0, x20
    8020bfb4:	97ffff6f 	bl	8020bd70 <__sflush_r>
    8020bfb8:	2a0003f5 	mov	w21, w0
    8020bfbc:	b940b261 	ldr	w1, [x19, #176]
    8020bfc0:	37000061 	tbnz	w1, #0, 8020bfcc <_fflush_r+0x5c>
    8020bfc4:	79402260 	ldrh	w0, [x19, #16]
    8020bfc8:	364801e0 	tbz	w0, #9, 8020c004 <_fflush_r+0x94>
    8020bfcc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020bfd0:	2a1503e0 	mov	w0, w21
    8020bfd4:	f94013f5 	ldr	x21, [sp, #32]
    8020bfd8:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020bfdc:	d65f03c0 	ret
    8020bfe0:	f9405260 	ldr	x0, [x19, #160]
    8020bfe4:	97fff4f7 	bl	802093c0 <__retarget_lock_acquire_recursive>
    8020bfe8:	aa1303e1 	mov	x1, x19
    8020bfec:	aa1403e0 	mov	x0, x20
    8020bff0:	97ffff60 	bl	8020bd70 <__sflush_r>
    8020bff4:	2a0003f5 	mov	w21, w0
    8020bff8:	b940b261 	ldr	w1, [x19, #176]
    8020bffc:	3707fe81 	tbnz	w1, #0, 8020bfcc <_fflush_r+0x5c>
    8020c000:	17fffff1 	b	8020bfc4 <_fflush_r+0x54>
    8020c004:	f9405260 	ldr	x0, [x19, #160]
    8020c008:	97fff4fe 	bl	80209400 <__retarget_lock_release_recursive>
    8020c00c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c010:	2a1503e0 	mov	w0, w21
    8020c014:	f94013f5 	ldr	x21, [sp, #32]
    8020c018:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020c01c:	d65f03c0 	ret
    8020c020:	97ffdb6c 	bl	80202dd0 <__sinit>
    8020c024:	17ffffdc 	b	8020bf94 <_fflush_r+0x24>
	...

000000008020c030 <fflush>:
    8020c030:	b40004e0 	cbz	x0, 8020c0cc <fflush+0x9c>
    8020c034:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020c038:	910003fd 	mov	x29, sp
    8020c03c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c040:	aa0003f3 	mov	x19, x0
    8020c044:	b0000020 	adrp	x0, 80211000 <__mprec_tens+0x180>
    8020c048:	f90013f5 	str	x21, [sp, #32]
    8020c04c:	f9402415 	ldr	x21, [x0, #72]
    8020c050:	b4000075 	cbz	x21, 8020c05c <fflush+0x2c>
    8020c054:	f94026a0 	ldr	x0, [x21, #72]
    8020c058:	b4000280 	cbz	x0, 8020c0a8 <fflush+0x78>
    8020c05c:	79c02260 	ldrsh	w0, [x19, #16]
    8020c060:	52800014 	mov	w20, #0x0                   	// #0
    8020c064:	34000180 	cbz	w0, 8020c094 <fflush+0x64>
    8020c068:	b940b261 	ldr	w1, [x19, #176]
    8020c06c:	37000041 	tbnz	w1, #0, 8020c074 <fflush+0x44>
    8020c070:	36480220 	tbz	w0, #9, 8020c0b4 <fflush+0x84>
    8020c074:	aa1303e1 	mov	x1, x19
    8020c078:	aa1503e0 	mov	x0, x21
    8020c07c:	97ffff3d 	bl	8020bd70 <__sflush_r>
    8020c080:	2a0003f4 	mov	w20, w0
    8020c084:	b940b261 	ldr	w1, [x19, #176]
    8020c088:	37000061 	tbnz	w1, #0, 8020c094 <fflush+0x64>
    8020c08c:	79402260 	ldrh	w0, [x19, #16]
    8020c090:	36480180 	tbz	w0, #9, 8020c0c0 <fflush+0x90>
    8020c094:	f94013f5 	ldr	x21, [sp, #32]
    8020c098:	2a1403e0 	mov	w0, w20
    8020c09c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c0a0:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020c0a4:	d65f03c0 	ret
    8020c0a8:	aa1503e0 	mov	x0, x21
    8020c0ac:	97ffdb49 	bl	80202dd0 <__sinit>
    8020c0b0:	17ffffeb 	b	8020c05c <fflush+0x2c>
    8020c0b4:	f9405260 	ldr	x0, [x19, #160]
    8020c0b8:	97fff4c2 	bl	802093c0 <__retarget_lock_acquire_recursive>
    8020c0bc:	17ffffee 	b	8020c074 <fflush+0x44>
    8020c0c0:	f9405260 	ldr	x0, [x19, #160]
    8020c0c4:	97fff4cf 	bl	80209400 <__retarget_lock_release_recursive>
    8020c0c8:	17fffff3 	b	8020c094 <fflush+0x64>
    8020c0cc:	b0000022 	adrp	x2, 80211000 <__mprec_tens+0x180>
    8020c0d0:	f0ffffe1 	adrp	x1, 8020b000 <_dtoa_r+0x540>
    8020c0d4:	b0000020 	adrp	x0, 80211000 <__mprec_tens+0x180>
    8020c0d8:	9106a042 	add	x2, x2, #0x1a8
    8020c0dc:	913dc021 	add	x1, x1, #0xf70
    8020c0e0:	91014000 	add	x0, x0, #0x50
    8020c0e4:	17ffdd87 	b	80203700 <_fwalk_sglue>
	...

000000008020c0f0 <frexp>:
    8020c0f0:	9e660002 	fmov	x2, d0
    8020c0f4:	b900001f 	str	wzr, [x0]
    8020c0f8:	12b00204 	mov	w4, #0x7fefffff            	// #2146435071
    8020c0fc:	d360f841 	ubfx	x1, x2, #32, #31
    8020c100:	d360fc43 	lsr	x3, x2, #32
    8020c104:	6b04003f 	cmp	w1, w4
    8020c108:	540002e8 	b.hi	8020c164 <frexp+0x74>  // b.pmore
    8020c10c:	2a020022 	orr	w2, w1, w2
    8020c110:	340002a2 	cbz	w2, 8020c164 <frexp+0x74>
    8020c114:	52800004 	mov	w4, #0x0                   	// #0
    8020c118:	f26c287f 	tst	x3, #0x7ff00000
    8020c11c:	54000121 	b.ne	8020c140 <frexp+0x50>  // b.any
    8020c120:	d2e86a01 	mov	x1, #0x4350000000000000    	// #4850376798678024192
    8020c124:	9e670021 	fmov	d1, x1
    8020c128:	128006a4 	mov	w4, #0xffffffca            	// #-54
    8020c12c:	1e610800 	fmul	d0, d0, d1
    8020c130:	9e660001 	fmov	x1, d0
    8020c134:	d360fc21 	lsr	x1, x1, #32
    8020c138:	2a0103e3 	mov	w3, w1
    8020c13c:	12007821 	and	w1, w1, #0x7fffffff
    8020c140:	9e660002 	fmov	x2, d0
    8020c144:	12015063 	and	w3, w3, #0x800fffff
    8020c148:	13147c21 	asr	w1, w1, #20
    8020c14c:	320b2063 	orr	w3, w3, #0x3fe00000
    8020c150:	510ff821 	sub	w1, w1, #0x3fe
    8020c154:	0b040021 	add	w1, w1, w4
    8020c158:	b9000001 	str	w1, [x0]
    8020c15c:	b3607c62 	bfi	x2, x3, #32, #32
    8020c160:	9e670040 	fmov	d0, x2
    8020c164:	d65f03c0 	ret
	...

000000008020c170 <_realloc_r>:
    8020c170:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    8020c174:	910003fd 	mov	x29, sp
    8020c178:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020c17c:	aa0203f5 	mov	x21, x2
    8020c180:	b4001021 	cbz	x1, 8020c384 <_realloc_r+0x214>
    8020c184:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c188:	aa0103f3 	mov	x19, x1
    8020c18c:	aa0003f6 	mov	x22, x0
    8020c190:	a90363f7 	stp	x23, x24, [sp, #48]
    8020c194:	d1004278 	sub	x24, x19, #0x10
    8020c198:	91005eb4 	add	x20, x21, #0x17
    8020c19c:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020c1a0:	97fff9c4 	bl	8020a8b0 <__malloc_lock>
    8020c1a4:	aa1803f9 	mov	x25, x24
    8020c1a8:	f9400700 	ldr	x0, [x24, #8]
    8020c1ac:	927ef417 	and	x23, x0, #0xfffffffffffffffc
    8020c1b0:	f100ba9f 	cmp	x20, #0x2e
    8020c1b4:	54000908 	b.hi	8020c2d4 <_realloc_r+0x164>  // b.pmore
    8020c1b8:	52800001 	mov	w1, #0x0                   	// #0
    8020c1bc:	7100003f 	cmp	w1, #0x0
    8020c1c0:	d2800414 	mov	x20, #0x20                  	// #32
    8020c1c4:	fa550280 	ccmp	x20, x21, #0x0, eq	// eq = none
    8020c1c8:	54000943 	b.cc	8020c2f0 <_realloc_r+0x180>  // b.lo, b.ul, b.last
    8020c1cc:	eb1402ff 	cmp	x23, x20
    8020c1d0:	54000a4a 	b.ge	8020c318 <_realloc_r+0x1a8>  // b.tcont
    8020c1d4:	b0000021 	adrp	x1, 80211000 <__mprec_tens+0x180>
    8020c1d8:	a90573fb 	stp	x27, x28, [sp, #80]
    8020c1dc:	9107403c 	add	x28, x1, #0x1d0
    8020c1e0:	8b170302 	add	x2, x24, x23
    8020c1e4:	f9400b83 	ldr	x3, [x28, #16]
    8020c1e8:	f9400441 	ldr	x1, [x2, #8]
    8020c1ec:	eb02007f 	cmp	x3, x2
    8020c1f0:	54000ea0 	b.eq	8020c3c4 <_realloc_r+0x254>  // b.none
    8020c1f4:	927ff823 	and	x3, x1, #0xfffffffffffffffe
    8020c1f8:	8b030043 	add	x3, x2, x3
    8020c1fc:	f9400463 	ldr	x3, [x3, #8]
    8020c200:	37000b63 	tbnz	w3, #0, 8020c36c <_realloc_r+0x1fc>
    8020c204:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    8020c208:	8b0102e3 	add	x3, x23, x1
    8020c20c:	eb03029f 	cmp	x20, x3
    8020c210:	5400078d 	b.le	8020c300 <_realloc_r+0x190>
    8020c214:	37000180 	tbnz	w0, #0, 8020c244 <_realloc_r+0xd4>
    8020c218:	f85f027b 	ldur	x27, [x19, #-16]
    8020c21c:	cb1b031b 	sub	x27, x24, x27
    8020c220:	f9400760 	ldr	x0, [x27, #8]
    8020c224:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020c228:	8b000021 	add	x1, x1, x0
    8020c22c:	8b17003a 	add	x26, x1, x23
    8020c230:	eb1a029f 	cmp	x20, x26
    8020c234:	540018ed 	b.le	8020c550 <_realloc_r+0x3e0>
    8020c238:	8b0002fa 	add	x26, x23, x0
    8020c23c:	eb1a029f 	cmp	x20, x26
    8020c240:	5400146d 	b.le	8020c4cc <_realloc_r+0x35c>
    8020c244:	aa1503e1 	mov	x1, x21
    8020c248:	aa1603e0 	mov	x0, x22
    8020c24c:	97fff1fd 	bl	80208a40 <_malloc_r>
    8020c250:	aa0003f5 	mov	x21, x0
    8020c254:	b4001d20 	cbz	x0, 8020c5f8 <_realloc_r+0x488>
    8020c258:	f9400701 	ldr	x1, [x24, #8]
    8020c25c:	d1004002 	sub	x2, x0, #0x10
    8020c260:	927ff821 	and	x1, x1, #0xfffffffffffffffe
    8020c264:	8b010301 	add	x1, x24, x1
    8020c268:	eb02003f 	cmp	x1, x2
    8020c26c:	54001140 	b.eq	8020c494 <_realloc_r+0x324>  // b.none
    8020c270:	d10022e2 	sub	x2, x23, #0x8
    8020c274:	f101205f 	cmp	x2, #0x48
    8020c278:	54001668 	b.hi	8020c544 <_realloc_r+0x3d4>  // b.pmore
    8020c27c:	f1009c5f 	cmp	x2, #0x27
    8020c280:	54001148 	b.hi	8020c4a8 <_realloc_r+0x338>  // b.pmore
    8020c284:	aa1303e1 	mov	x1, x19
    8020c288:	f9400022 	ldr	x2, [x1]
    8020c28c:	f9000002 	str	x2, [x0]
    8020c290:	f9400422 	ldr	x2, [x1, #8]
    8020c294:	f9000402 	str	x2, [x0, #8]
    8020c298:	f9400821 	ldr	x1, [x1, #16]
    8020c29c:	f9000801 	str	x1, [x0, #16]
    8020c2a0:	aa1303e1 	mov	x1, x19
    8020c2a4:	aa1603e0 	mov	x0, x22
    8020c2a8:	94000156 	bl	8020c800 <_free_r>
    8020c2ac:	aa1603e0 	mov	x0, x22
    8020c2b0:	97fff984 	bl	8020a8c0 <__malloc_unlock>
    8020c2b4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c2b8:	aa1503e0 	mov	x0, x21
    8020c2bc:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020c2c0:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020c2c4:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020c2c8:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020c2cc:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020c2d0:	d65f03c0 	ret
    8020c2d4:	927cee94 	and	x20, x20, #0xfffffffffffffff0
    8020c2d8:	b2407be1 	mov	x1, #0x7fffffff            	// #2147483647
    8020c2dc:	eb01029f 	cmp	x20, x1
    8020c2e0:	1a9f97e1 	cset	w1, hi	// hi = pmore
    8020c2e4:	7100003f 	cmp	w1, #0x0
    8020c2e8:	fa550280 	ccmp	x20, x21, #0x0, eq	// eq = none
    8020c2ec:	54fff702 	b.cs	8020c1cc <_realloc_r+0x5c>  // b.hs, b.nlast
    8020c2f0:	52800180 	mov	w0, #0xc                   	// #12
    8020c2f4:	d2800015 	mov	x21, #0x0                   	// #0
    8020c2f8:	b90002c0 	str	w0, [x22]
    8020c2fc:	14000015 	b	8020c350 <_realloc_r+0x1e0>
    8020c300:	a9410041 	ldp	x1, x0, [x2, #16]
    8020c304:	aa0303f7 	mov	x23, x3
    8020c308:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020c30c:	f9000c20 	str	x0, [x1, #24]
    8020c310:	f9000801 	str	x1, [x0, #16]
    8020c314:	d503201f 	nop
    8020c318:	f9400721 	ldr	x1, [x25, #8]
    8020c31c:	cb1402e0 	sub	x0, x23, x20
    8020c320:	8b170322 	add	x2, x25, x23
    8020c324:	92400021 	and	x1, x1, #0x1
    8020c328:	f1007c1f 	cmp	x0, #0x1f
    8020c32c:	54000348 	b.hi	8020c394 <_realloc_r+0x224>  // b.pmore
    8020c330:	aa0102e1 	orr	x1, x23, x1
    8020c334:	f9000721 	str	x1, [x25, #8]
    8020c338:	f9400440 	ldr	x0, [x2, #8]
    8020c33c:	b2400000 	orr	x0, x0, #0x1
    8020c340:	f9000440 	str	x0, [x2, #8]
    8020c344:	aa1303f5 	mov	x21, x19
    8020c348:	aa1603e0 	mov	x0, x22
    8020c34c:	97fff95d 	bl	8020a8c0 <__malloc_unlock>
    8020c350:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c354:	aa1503e0 	mov	x0, x21
    8020c358:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020c35c:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020c360:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020c364:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020c368:	d65f03c0 	ret
    8020c36c:	3707f6c0 	tbnz	w0, #0, 8020c244 <_realloc_r+0xd4>
    8020c370:	f85f027b 	ldur	x27, [x19, #-16]
    8020c374:	cb1b031b 	sub	x27, x24, x27
    8020c378:	f9400760 	ldr	x0, [x27, #8]
    8020c37c:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020c380:	17ffffae 	b	8020c238 <_realloc_r+0xc8>
    8020c384:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020c388:	aa0203e1 	mov	x1, x2
    8020c38c:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020c390:	17fff1ac 	b	80208a40 <_malloc_r>
    8020c394:	8b140324 	add	x4, x25, x20
    8020c398:	aa010281 	orr	x1, x20, x1
    8020c39c:	f9000721 	str	x1, [x25, #8]
    8020c3a0:	b2400003 	orr	x3, x0, #0x1
    8020c3a4:	91004081 	add	x1, x4, #0x10
    8020c3a8:	aa1603e0 	mov	x0, x22
    8020c3ac:	f9000483 	str	x3, [x4, #8]
    8020c3b0:	f9400443 	ldr	x3, [x2, #8]
    8020c3b4:	b2400063 	orr	x3, x3, #0x1
    8020c3b8:	f9000443 	str	x3, [x2, #8]
    8020c3bc:	94000111 	bl	8020c800 <_free_r>
    8020c3c0:	17ffffe1 	b	8020c344 <_realloc_r+0x1d4>
    8020c3c4:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    8020c3c8:	91008283 	add	x3, x20, #0x20
    8020c3cc:	8b170022 	add	x2, x1, x23
    8020c3d0:	eb03005f 	cmp	x2, x3
    8020c3d4:	54000e4a 	b.ge	8020c59c <_realloc_r+0x42c>  // b.tcont
    8020c3d8:	3707f360 	tbnz	w0, #0, 8020c244 <_realloc_r+0xd4>
    8020c3dc:	f85f027b 	ldur	x27, [x19, #-16]
    8020c3e0:	cb1b031b 	sub	x27, x24, x27
    8020c3e4:	f9400760 	ldr	x0, [x27, #8]
    8020c3e8:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020c3ec:	8b000021 	add	x1, x1, x0
    8020c3f0:	8b17003a 	add	x26, x1, x23
    8020c3f4:	eb1a007f 	cmp	x3, x26
    8020c3f8:	54fff20c 	b.gt	8020c238 <_realloc_r+0xc8>
    8020c3fc:	aa1b03f5 	mov	x21, x27
    8020c400:	d10022e2 	sub	x2, x23, #0x8
    8020c404:	f9400f60 	ldr	x0, [x27, #24]
    8020c408:	f8410ea1 	ldr	x1, [x21, #16]!
    8020c40c:	f9000c20 	str	x0, [x1, #24]
    8020c410:	f9000801 	str	x1, [x0, #16]
    8020c414:	f101205f 	cmp	x2, #0x48
    8020c418:	54001168 	b.hi	8020c644 <_realloc_r+0x4d4>  // b.pmore
    8020c41c:	aa1503e0 	mov	x0, x21
    8020c420:	f1009c5f 	cmp	x2, #0x27
    8020c424:	54000129 	b.ls	8020c448 <_realloc_r+0x2d8>  // b.plast
    8020c428:	f9400260 	ldr	x0, [x19]
    8020c42c:	f9000b60 	str	x0, [x27, #16]
    8020c430:	f9400660 	ldr	x0, [x19, #8]
    8020c434:	f9000f60 	str	x0, [x27, #24]
    8020c438:	f100dc5f 	cmp	x2, #0x37
    8020c43c:	540010c8 	b.hi	8020c654 <_realloc_r+0x4e4>  // b.pmore
    8020c440:	91004273 	add	x19, x19, #0x10
    8020c444:	91008360 	add	x0, x27, #0x20
    8020c448:	f9400261 	ldr	x1, [x19]
    8020c44c:	f9000001 	str	x1, [x0]
    8020c450:	f9400661 	ldr	x1, [x19, #8]
    8020c454:	f9000401 	str	x1, [x0, #8]
    8020c458:	f9400a61 	ldr	x1, [x19, #16]
    8020c45c:	f9000801 	str	x1, [x0, #16]
    8020c460:	8b140362 	add	x2, x27, x20
    8020c464:	cb140341 	sub	x1, x26, x20
    8020c468:	f9000b82 	str	x2, [x28, #16]
    8020c46c:	b2400021 	orr	x1, x1, #0x1
    8020c470:	aa1603e0 	mov	x0, x22
    8020c474:	f9000441 	str	x1, [x2, #8]
    8020c478:	f9400761 	ldr	x1, [x27, #8]
    8020c47c:	92400021 	and	x1, x1, #0x1
    8020c480:	aa140021 	orr	x1, x1, x20
    8020c484:	f9000761 	str	x1, [x27, #8]
    8020c488:	97fff90e 	bl	8020a8c0 <__malloc_unlock>
    8020c48c:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020c490:	17ffffb0 	b	8020c350 <_realloc_r+0x1e0>
    8020c494:	f9400420 	ldr	x0, [x1, #8]
    8020c498:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020c49c:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020c4a0:	8b0002f7 	add	x23, x23, x0
    8020c4a4:	17ffff9d 	b	8020c318 <_realloc_r+0x1a8>
    8020c4a8:	f9400260 	ldr	x0, [x19]
    8020c4ac:	f90002a0 	str	x0, [x21]
    8020c4b0:	f9400660 	ldr	x0, [x19, #8]
    8020c4b4:	f90006a0 	str	x0, [x21, #8]
    8020c4b8:	f100dc5f 	cmp	x2, #0x37
    8020c4bc:	540005e8 	b.hi	8020c578 <_realloc_r+0x408>  // b.pmore
    8020c4c0:	91004261 	add	x1, x19, #0x10
    8020c4c4:	910042a0 	add	x0, x21, #0x10
    8020c4c8:	17ffff70 	b	8020c288 <_realloc_r+0x118>
    8020c4cc:	aa1b03f5 	mov	x21, x27
    8020c4d0:	d10022e2 	sub	x2, x23, #0x8
    8020c4d4:	f8410ea1 	ldr	x1, [x21, #16]!
    8020c4d8:	f9400f60 	ldr	x0, [x27, #24]
    8020c4dc:	f9000c20 	str	x0, [x1, #24]
    8020c4e0:	f9000801 	str	x1, [x0, #16]
    8020c4e4:	f101205f 	cmp	x2, #0x48
    8020c4e8:	54000408 	b.hi	8020c568 <_realloc_r+0x3f8>  // b.pmore
    8020c4ec:	aa1503e0 	mov	x0, x21
    8020c4f0:	f1009c5f 	cmp	x2, #0x27
    8020c4f4:	54000129 	b.ls	8020c518 <_realloc_r+0x3a8>  // b.plast
    8020c4f8:	f9400260 	ldr	x0, [x19]
    8020c4fc:	f9000b60 	str	x0, [x27, #16]
    8020c500:	f9400660 	ldr	x0, [x19, #8]
    8020c504:	f9000f60 	str	x0, [x27, #24]
    8020c508:	f100dc5f 	cmp	x2, #0x37
    8020c50c:	54000648 	b.hi	8020c5d4 <_realloc_r+0x464>  // b.pmore
    8020c510:	91004273 	add	x19, x19, #0x10
    8020c514:	91008360 	add	x0, x27, #0x20
    8020c518:	f9400261 	ldr	x1, [x19]
    8020c51c:	f9000001 	str	x1, [x0]
    8020c520:	f9400661 	ldr	x1, [x19, #8]
    8020c524:	f9000401 	str	x1, [x0, #8]
    8020c528:	f9400a61 	ldr	x1, [x19, #16]
    8020c52c:	f9000801 	str	x1, [x0, #16]
    8020c530:	aa1b03f9 	mov	x25, x27
    8020c534:	aa1503f3 	mov	x19, x21
    8020c538:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020c53c:	aa1a03f7 	mov	x23, x26
    8020c540:	17ffff76 	b	8020c318 <_realloc_r+0x1a8>
    8020c544:	aa1303e1 	mov	x1, x19
    8020c548:	97fff84e 	bl	8020a680 <memcpy>
    8020c54c:	17ffff55 	b	8020c2a0 <_realloc_r+0x130>
    8020c550:	a9410041 	ldp	x1, x0, [x2, #16]
    8020c554:	f9000c20 	str	x0, [x1, #24]
    8020c558:	aa1b03f5 	mov	x21, x27
    8020c55c:	d10022e2 	sub	x2, x23, #0x8
    8020c560:	f9000801 	str	x1, [x0, #16]
    8020c564:	17ffffdc 	b	8020c4d4 <_realloc_r+0x364>
    8020c568:	aa1303e1 	mov	x1, x19
    8020c56c:	aa1503e0 	mov	x0, x21
    8020c570:	97fff844 	bl	8020a680 <memcpy>
    8020c574:	17ffffef 	b	8020c530 <_realloc_r+0x3c0>
    8020c578:	f9400a60 	ldr	x0, [x19, #16]
    8020c57c:	f9000aa0 	str	x0, [x21, #16]
    8020c580:	f9400e60 	ldr	x0, [x19, #24]
    8020c584:	f9000ea0 	str	x0, [x21, #24]
    8020c588:	f101205f 	cmp	x2, #0x48
    8020c58c:	54000400 	b.eq	8020c60c <_realloc_r+0x49c>  // b.none
    8020c590:	91008261 	add	x1, x19, #0x20
    8020c594:	910082a0 	add	x0, x21, #0x20
    8020c598:	17ffff3c 	b	8020c288 <_realloc_r+0x118>
    8020c59c:	8b140303 	add	x3, x24, x20
    8020c5a0:	cb140041 	sub	x1, x2, x20
    8020c5a4:	f9000b83 	str	x3, [x28, #16]
    8020c5a8:	b2400021 	orr	x1, x1, #0x1
    8020c5ac:	aa1603e0 	mov	x0, x22
    8020c5b0:	aa1303f5 	mov	x21, x19
    8020c5b4:	f9000461 	str	x1, [x3, #8]
    8020c5b8:	f9400701 	ldr	x1, [x24, #8]
    8020c5bc:	92400021 	and	x1, x1, #0x1
    8020c5c0:	aa140021 	orr	x1, x1, x20
    8020c5c4:	f9000701 	str	x1, [x24, #8]
    8020c5c8:	97fff8be 	bl	8020a8c0 <__malloc_unlock>
    8020c5cc:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020c5d0:	17ffff60 	b	8020c350 <_realloc_r+0x1e0>
    8020c5d4:	f9400a60 	ldr	x0, [x19, #16]
    8020c5d8:	f9001360 	str	x0, [x27, #32]
    8020c5dc:	f9400e60 	ldr	x0, [x19, #24]
    8020c5e0:	f9001760 	str	x0, [x27, #40]
    8020c5e4:	f101205f 	cmp	x2, #0x48
    8020c5e8:	54000200 	b.eq	8020c628 <_realloc_r+0x4b8>  // b.none
    8020c5ec:	91008273 	add	x19, x19, #0x20
    8020c5f0:	9100c360 	add	x0, x27, #0x30
    8020c5f4:	17ffffc9 	b	8020c518 <_realloc_r+0x3a8>
    8020c5f8:	aa1603e0 	mov	x0, x22
    8020c5fc:	d2800015 	mov	x21, #0x0                   	// #0
    8020c600:	97fff8b0 	bl	8020a8c0 <__malloc_unlock>
    8020c604:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020c608:	17ffff52 	b	8020c350 <_realloc_r+0x1e0>
    8020c60c:	f9401260 	ldr	x0, [x19, #32]
    8020c610:	f90012a0 	str	x0, [x21, #32]
    8020c614:	9100c261 	add	x1, x19, #0x30
    8020c618:	9100c2a0 	add	x0, x21, #0x30
    8020c61c:	f9401662 	ldr	x2, [x19, #40]
    8020c620:	f90016a2 	str	x2, [x21, #40]
    8020c624:	17ffff19 	b	8020c288 <_realloc_r+0x118>
    8020c628:	f9401260 	ldr	x0, [x19, #32]
    8020c62c:	f9001b60 	str	x0, [x27, #48]
    8020c630:	9100c273 	add	x19, x19, #0x30
    8020c634:	91010360 	add	x0, x27, #0x40
    8020c638:	f85f8261 	ldur	x1, [x19, #-8]
    8020c63c:	f9001f61 	str	x1, [x27, #56]
    8020c640:	17ffffb6 	b	8020c518 <_realloc_r+0x3a8>
    8020c644:	aa1303e1 	mov	x1, x19
    8020c648:	aa1503e0 	mov	x0, x21
    8020c64c:	97fff80d 	bl	8020a680 <memcpy>
    8020c650:	17ffff84 	b	8020c460 <_realloc_r+0x2f0>
    8020c654:	f9400a60 	ldr	x0, [x19, #16]
    8020c658:	f9001360 	str	x0, [x27, #32]
    8020c65c:	f9400e60 	ldr	x0, [x19, #24]
    8020c660:	f9001760 	str	x0, [x27, #40]
    8020c664:	f101205f 	cmp	x2, #0x48
    8020c668:	54000080 	b.eq	8020c678 <_realloc_r+0x508>  // b.none
    8020c66c:	91008273 	add	x19, x19, #0x20
    8020c670:	9100c360 	add	x0, x27, #0x30
    8020c674:	17ffff75 	b	8020c448 <_realloc_r+0x2d8>
    8020c678:	f9401260 	ldr	x0, [x19, #32]
    8020c67c:	f9001b60 	str	x0, [x27, #48]
    8020c680:	9100c273 	add	x19, x19, #0x30
    8020c684:	91010360 	add	x0, x27, #0x40
    8020c688:	f85f8261 	ldur	x1, [x19, #-8]
    8020c68c:	f9001f61 	str	x1, [x27, #56]
    8020c690:	17ffff6e 	b	8020c448 <_realloc_r+0x2d8>
	...

000000008020c6a0 <strlcpy>:
    8020c6a0:	aa0103e3 	mov	x3, x1
    8020c6a4:	b50000a2 	cbnz	x2, 8020c6b8 <strlcpy+0x18>
    8020c6a8:	14000008 	b	8020c6c8 <strlcpy+0x28>
    8020c6ac:	38401464 	ldrb	w4, [x3], #1
    8020c6b0:	38001404 	strb	w4, [x0], #1
    8020c6b4:	340000e4 	cbz	w4, 8020c6d0 <strlcpy+0x30>
    8020c6b8:	f1000442 	subs	x2, x2, #0x1
    8020c6bc:	54ffff81 	b.ne	8020c6ac <strlcpy+0xc>  // b.any
    8020c6c0:	3900001f 	strb	wzr, [x0]
    8020c6c4:	d503201f 	nop
    8020c6c8:	38401460 	ldrb	w0, [x3], #1
    8020c6cc:	35ffffe0 	cbnz	w0, 8020c6c8 <strlcpy+0x28>
    8020c6d0:	cb010060 	sub	x0, x3, x1
    8020c6d4:	d1000400 	sub	x0, x0, #0x1
    8020c6d8:	d65f03c0 	ret
    8020c6dc:	00000000 	udf	#0

000000008020c6e0 <_malloc_trim_r>:
    8020c6e0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020c6e4:	910003fd 	mov	x29, sp
    8020c6e8:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020c6ec:	b0000036 	adrp	x22, 80211000 <__mprec_tens+0x180>
    8020c6f0:	910742d6 	add	x22, x22, #0x1d0
    8020c6f4:	aa0003f5 	mov	x21, x0
    8020c6f8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c6fc:	f9001bf7 	str	x23, [sp, #48]
    8020c700:	aa0103f7 	mov	x23, x1
    8020c704:	97fff86b 	bl	8020a8b0 <__malloc_lock>
    8020c708:	f9400ac0 	ldr	x0, [x22, #16]
    8020c70c:	f9400414 	ldr	x20, [x0, #8]
    8020c710:	927ef694 	and	x20, x20, #0xfffffffffffffffc
    8020c714:	913f7e93 	add	x19, x20, #0xfdf
    8020c718:	cb170273 	sub	x19, x19, x23
    8020c71c:	9274ce73 	and	x19, x19, #0xfffffffffffff000
    8020c720:	d1400673 	sub	x19, x19, #0x1, lsl #12
    8020c724:	f13ffe7f 	cmp	x19, #0xfff
    8020c728:	5400010d 	b.le	8020c748 <_malloc_trim_r+0x68>
    8020c72c:	d2800001 	mov	x1, #0x0                   	// #0
    8020c730:	aa1503e0 	mov	x0, x21
    8020c734:	940004b3 	bl	8020da00 <_sbrk_r>
    8020c738:	f9400ac1 	ldr	x1, [x22, #16]
    8020c73c:	8b140021 	add	x1, x1, x20
    8020c740:	eb01001f 	cmp	x0, x1
    8020c744:	54000120 	b.eq	8020c768 <_malloc_trim_r+0x88>  // b.none
    8020c748:	aa1503e0 	mov	x0, x21
    8020c74c:	97fff85d 	bl	8020a8c0 <__malloc_unlock>
    8020c750:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c754:	52800000 	mov	w0, #0x0                   	// #0
    8020c758:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020c75c:	f9401bf7 	ldr	x23, [sp, #48]
    8020c760:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020c764:	d65f03c0 	ret
    8020c768:	cb1303e1 	neg	x1, x19
    8020c76c:	aa1503e0 	mov	x0, x21
    8020c770:	940004a4 	bl	8020da00 <_sbrk_r>
    8020c774:	b100041f 	cmn	x0, #0x1
    8020c778:	54000220 	b.eq	8020c7bc <_malloc_trim_r+0xdc>  // b.none
    8020c77c:	900003a2 	adrp	x2, 80280000 <gits_lock>
    8020c780:	cb130294 	sub	x20, x20, x19
    8020c784:	f9400ac3 	ldr	x3, [x22, #16]
    8020c788:	b2400294 	orr	x20, x20, #0x1
    8020c78c:	b9424041 	ldr	w1, [x2, #576]
    8020c790:	aa1503e0 	mov	x0, x21
    8020c794:	4b130021 	sub	w1, w1, w19
    8020c798:	f9000474 	str	x20, [x3, #8]
    8020c79c:	b9024041 	str	w1, [x2, #576]
    8020c7a0:	97fff848 	bl	8020a8c0 <__malloc_unlock>
    8020c7a4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c7a8:	52800020 	mov	w0, #0x1                   	// #1
    8020c7ac:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020c7b0:	f9401bf7 	ldr	x23, [sp, #48]
    8020c7b4:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020c7b8:	d65f03c0 	ret
    8020c7bc:	d2800001 	mov	x1, #0x0                   	// #0
    8020c7c0:	aa1503e0 	mov	x0, x21
    8020c7c4:	9400048f 	bl	8020da00 <_sbrk_r>
    8020c7c8:	f9400ac2 	ldr	x2, [x22, #16]
    8020c7cc:	cb020001 	sub	x1, x0, x2
    8020c7d0:	f1007c3f 	cmp	x1, #0x1f
    8020c7d4:	54fffbad 	b.le	8020c748 <_malloc_trim_r+0x68>
    8020c7d8:	b0000024 	adrp	x4, 80211000 <__mprec_tens+0x180>
    8020c7dc:	b2400021 	orr	x1, x1, #0x1
    8020c7e0:	f9000441 	str	x1, [x2, #8]
    8020c7e4:	900003a3 	adrp	x3, 80280000 <gits_lock>
    8020c7e8:	f940e081 	ldr	x1, [x4, #448]
    8020c7ec:	cb010000 	sub	x0, x0, x1
    8020c7f0:	b9024060 	str	w0, [x3, #576]
    8020c7f4:	17ffffd5 	b	8020c748 <_malloc_trim_r+0x68>
	...

000000008020c800 <_free_r>:
    8020c800:	b4000a21 	cbz	x1, 8020c944 <_free_r+0x144>
    8020c804:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020c808:	910003fd 	mov	x29, sp
    8020c80c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c810:	aa0103f3 	mov	x19, x1
    8020c814:	aa0003f4 	mov	x20, x0
    8020c818:	97fff826 	bl	8020a8b0 <__malloc_lock>
    8020c81c:	f85f8265 	ldur	x5, [x19, #-8]
    8020c820:	d1004263 	sub	x3, x19, #0x10
    8020c824:	b0000020 	adrp	x0, 80211000 <__mprec_tens+0x180>
    8020c828:	91074000 	add	x0, x0, #0x1d0
    8020c82c:	927ff8a2 	and	x2, x5, #0xfffffffffffffffe
    8020c830:	8b020064 	add	x4, x3, x2
    8020c834:	f9400806 	ldr	x6, [x0, #16]
    8020c838:	f9400481 	ldr	x1, [x4, #8]
    8020c83c:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    8020c840:	eb0400df 	cmp	x6, x4
    8020c844:	54000c00 	b.eq	8020c9c4 <_free_r+0x1c4>  // b.none
    8020c848:	f9000481 	str	x1, [x4, #8]
    8020c84c:	8b010086 	add	x6, x4, x1
    8020c850:	37000345 	tbnz	w5, #0, 8020c8b8 <_free_r+0xb8>
    8020c854:	f85f0267 	ldur	x7, [x19, #-16]
    8020c858:	b0000025 	adrp	x5, 80211000 <__mprec_tens+0x180>
    8020c85c:	f94004c6 	ldr	x6, [x6, #8]
    8020c860:	cb070063 	sub	x3, x3, x7
    8020c864:	8b070042 	add	x2, x2, x7
    8020c868:	910780a5 	add	x5, x5, #0x1e0
    8020c86c:	924000c6 	and	x6, x6, #0x1
    8020c870:	f9400867 	ldr	x7, [x3, #16]
    8020c874:	eb0500ff 	cmp	x7, x5
    8020c878:	54000940 	b.eq	8020c9a0 <_free_r+0x1a0>  // b.none
    8020c87c:	f9400c68 	ldr	x8, [x3, #24]
    8020c880:	f9000ce8 	str	x8, [x7, #24]
    8020c884:	f9000907 	str	x7, [x8, #16]
    8020c888:	b50001c6 	cbnz	x6, 8020c8c0 <_free_r+0xc0>
    8020c88c:	8b010042 	add	x2, x2, x1
    8020c890:	f9400881 	ldr	x1, [x4, #16]
    8020c894:	eb05003f 	cmp	x1, x5
    8020c898:	54000ea0 	b.eq	8020ca6c <_free_r+0x26c>  // b.none
    8020c89c:	f9400c85 	ldr	x5, [x4, #24]
    8020c8a0:	f9000c25 	str	x5, [x1, #24]
    8020c8a4:	b2400044 	orr	x4, x2, #0x1
    8020c8a8:	f90008a1 	str	x1, [x5, #16]
    8020c8ac:	f9000464 	str	x4, [x3, #8]
    8020c8b0:	f8226862 	str	x2, [x3, x2]
    8020c8b4:	14000006 	b	8020c8cc <_free_r+0xcc>
    8020c8b8:	f94004c5 	ldr	x5, [x6, #8]
    8020c8bc:	360006a5 	tbz	w5, #0, 8020c990 <_free_r+0x190>
    8020c8c0:	b2400041 	orr	x1, x2, #0x1
    8020c8c4:	f9000461 	str	x1, [x3, #8]
    8020c8c8:	f9000082 	str	x2, [x4]
    8020c8cc:	f107fc5f 	cmp	x2, #0x1ff
    8020c8d0:	540003c9 	b.ls	8020c948 <_free_r+0x148>  // b.plast
    8020c8d4:	d349fc41 	lsr	x1, x2, #9
    8020c8d8:	f127fc5f 	cmp	x2, #0x9ff
    8020c8dc:	540009c8 	b.hi	8020ca14 <_free_r+0x214>  // b.pmore
    8020c8e0:	d346fc41 	lsr	x1, x2, #6
    8020c8e4:	1100e424 	add	w4, w1, #0x39
    8020c8e8:	1100e025 	add	w5, w1, #0x38
    8020c8ec:	531f7884 	lsl	w4, w4, #1
    8020c8f0:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020c8f4:	8b040004 	add	x4, x0, x4
    8020c8f8:	f85f0481 	ldr	x1, [x4], #-16
    8020c8fc:	eb01009f 	cmp	x4, x1
    8020c900:	540000a1 	b.ne	8020c914 <_free_r+0x114>  // b.any
    8020c904:	14000053 	b	8020ca50 <_free_r+0x250>
    8020c908:	f9400821 	ldr	x1, [x1, #16]
    8020c90c:	eb01009f 	cmp	x4, x1
    8020c910:	540000a0 	b.eq	8020c924 <_free_r+0x124>  // b.none
    8020c914:	f9400420 	ldr	x0, [x1, #8]
    8020c918:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020c91c:	eb02001f 	cmp	x0, x2
    8020c920:	54ffff48 	b.hi	8020c908 <_free_r+0x108>  // b.pmore
    8020c924:	f9400c24 	ldr	x4, [x1, #24]
    8020c928:	a9011061 	stp	x1, x4, [x3, #16]
    8020c92c:	aa1403e0 	mov	x0, x20
    8020c930:	f9000883 	str	x3, [x4, #16]
    8020c934:	f9000c23 	str	x3, [x1, #24]
    8020c938:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c93c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020c940:	17fff7e0 	b	8020a8c0 <__malloc_unlock>
    8020c944:	d65f03c0 	ret
    8020c948:	d343fc44 	lsr	x4, x2, #3
    8020c94c:	d2800022 	mov	x2, #0x1                   	// #1
    8020c950:	11000481 	add	w1, w4, #0x1
    8020c954:	f9400405 	ldr	x5, [x0, #8]
    8020c958:	531f7821 	lsl	w1, w1, #1
    8020c95c:	13027c84 	asr	w4, w4, #2
    8020c960:	8b21cc01 	add	x1, x0, w1, sxtw #3
    8020c964:	9ac42042 	lsl	x2, x2, x4
    8020c968:	aa050042 	orr	x2, x2, x5
    8020c96c:	f9000402 	str	x2, [x0, #8]
    8020c970:	f85f0420 	ldr	x0, [x1], #-16
    8020c974:	a9010460 	stp	x0, x1, [x3, #16]
    8020c978:	f9000823 	str	x3, [x1, #16]
    8020c97c:	f9000c03 	str	x3, [x0, #24]
    8020c980:	aa1403e0 	mov	x0, x20
    8020c984:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c988:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020c98c:	17fff7cd 	b	8020a8c0 <__malloc_unlock>
    8020c990:	b0000025 	adrp	x5, 80211000 <__mprec_tens+0x180>
    8020c994:	8b010042 	add	x2, x2, x1
    8020c998:	910780a5 	add	x5, x5, #0x1e0
    8020c99c:	17ffffbd 	b	8020c890 <_free_r+0x90>
    8020c9a0:	b5000986 	cbnz	x6, 8020cad0 <_free_r+0x2d0>
    8020c9a4:	a9410085 	ldp	x5, x0, [x4, #16]
    8020c9a8:	8b020021 	add	x1, x1, x2
    8020c9ac:	f9000ca0 	str	x0, [x5, #24]
    8020c9b0:	b2400022 	orr	x2, x1, #0x1
    8020c9b4:	f9000805 	str	x5, [x0, #16]
    8020c9b8:	f9000462 	str	x2, [x3, #8]
    8020c9bc:	f8216861 	str	x1, [x3, x1]
    8020c9c0:	17fffff0 	b	8020c980 <_free_r+0x180>
    8020c9c4:	8b010041 	add	x1, x2, x1
    8020c9c8:	370000e5 	tbnz	w5, #0, 8020c9e4 <_free_r+0x1e4>
    8020c9cc:	f85f0262 	ldur	x2, [x19, #-16]
    8020c9d0:	cb020063 	sub	x3, x3, x2
    8020c9d4:	8b020021 	add	x1, x1, x2
    8020c9d8:	a9410864 	ldp	x4, x2, [x3, #16]
    8020c9dc:	f9000c82 	str	x2, [x4, #24]
    8020c9e0:	f9000844 	str	x4, [x2, #16]
    8020c9e4:	b0000022 	adrp	x2, 80211000 <__mprec_tens+0x180>
    8020c9e8:	b2400024 	orr	x4, x1, #0x1
    8020c9ec:	f9000464 	str	x4, [x3, #8]
    8020c9f0:	f940e442 	ldr	x2, [x2, #456]
    8020c9f4:	f9000803 	str	x3, [x0, #16]
    8020c9f8:	eb01005f 	cmp	x2, x1
    8020c9fc:	54fffc28 	b.hi	8020c980 <_free_r+0x180>  // b.pmore
    8020ca00:	900003a1 	adrp	x1, 80280000 <gits_lock>
    8020ca04:	aa1403e0 	mov	x0, x20
    8020ca08:	f9413c21 	ldr	x1, [x1, #632]
    8020ca0c:	97ffff35 	bl	8020c6e0 <_malloc_trim_r>
    8020ca10:	17ffffdc 	b	8020c980 <_free_r+0x180>
    8020ca14:	f100503f 	cmp	x1, #0x14
    8020ca18:	54000129 	b.ls	8020ca3c <_free_r+0x23c>  // b.plast
    8020ca1c:	f101503f 	cmp	x1, #0x54
    8020ca20:	54000328 	b.hi	8020ca84 <_free_r+0x284>  // b.pmore
    8020ca24:	d34cfc41 	lsr	x1, x2, #12
    8020ca28:	1101bc24 	add	w4, w1, #0x6f
    8020ca2c:	1101b825 	add	w5, w1, #0x6e
    8020ca30:	531f7884 	lsl	w4, w4, #1
    8020ca34:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020ca38:	17ffffaf 	b	8020c8f4 <_free_r+0xf4>
    8020ca3c:	11017024 	add	w4, w1, #0x5c
    8020ca40:	11016c25 	add	w5, w1, #0x5b
    8020ca44:	531f7884 	lsl	w4, w4, #1
    8020ca48:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020ca4c:	17ffffaa 	b	8020c8f4 <_free_r+0xf4>
    8020ca50:	f9400406 	ldr	x6, [x0, #8]
    8020ca54:	13027ca5 	asr	w5, w5, #2
    8020ca58:	d2800022 	mov	x2, #0x1                   	// #1
    8020ca5c:	9ac52042 	lsl	x2, x2, x5
    8020ca60:	aa060042 	orr	x2, x2, x6
    8020ca64:	f9000402 	str	x2, [x0, #8]
    8020ca68:	17ffffb0 	b	8020c928 <_free_r+0x128>
    8020ca6c:	a9020c03 	stp	x3, x3, [x0, #32]
    8020ca70:	b2400041 	orr	x1, x2, #0x1
    8020ca74:	a9009461 	stp	x1, x5, [x3, #8]
    8020ca78:	f9000c65 	str	x5, [x3, #24]
    8020ca7c:	f8226862 	str	x2, [x3, x2]
    8020ca80:	17ffffc0 	b	8020c980 <_free_r+0x180>
    8020ca84:	f105503f 	cmp	x1, #0x154
    8020ca88:	540000e8 	b.hi	8020caa4 <_free_r+0x2a4>  // b.pmore
    8020ca8c:	d34ffc41 	lsr	x1, x2, #15
    8020ca90:	1101e024 	add	w4, w1, #0x78
    8020ca94:	1101dc25 	add	w5, w1, #0x77
    8020ca98:	531f7884 	lsl	w4, w4, #1
    8020ca9c:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020caa0:	17ffff95 	b	8020c8f4 <_free_r+0xf4>
    8020caa4:	f115503f 	cmp	x1, #0x554
    8020caa8:	540000e8 	b.hi	8020cac4 <_free_r+0x2c4>  // b.pmore
    8020caac:	d352fc41 	lsr	x1, x2, #18
    8020cab0:	1101f424 	add	w4, w1, #0x7d
    8020cab4:	1101f025 	add	w5, w1, #0x7c
    8020cab8:	531f7884 	lsl	w4, w4, #1
    8020cabc:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020cac0:	17ffff8d 	b	8020c8f4 <_free_r+0xf4>
    8020cac4:	d280fe04 	mov	x4, #0x7f0                 	// #2032
    8020cac8:	52800fc5 	mov	w5, #0x7e                  	// #126
    8020cacc:	17ffff8a 	b	8020c8f4 <_free_r+0xf4>
    8020cad0:	b2400040 	orr	x0, x2, #0x1
    8020cad4:	f9000460 	str	x0, [x3, #8]
    8020cad8:	f9000082 	str	x2, [x4]
    8020cadc:	17ffffa9 	b	8020c980 <_free_r+0x180>

000000008020cae0 <_strtol_l.part.0>:
    8020cae0:	90000027 	adrp	x7, 80210000 <__trunctfdf2+0xc0>
    8020cae4:	aa0003ec 	mov	x12, x0
    8020cae8:	aa0103e6 	mov	x6, x1
    8020caec:	913184e7 	add	x7, x7, #0xc61
    8020caf0:	aa0603e8 	mov	x8, x6
    8020caf4:	384014c5 	ldrb	w5, [x6], #1
    8020caf8:	386548e4 	ldrb	w4, [x7, w5, uxtw]
    8020cafc:	371fffa4 	tbnz	w4, #3, 8020caf0 <_strtol_l.part.0+0x10>
    8020cb00:	7100b4bf 	cmp	w5, #0x2d
    8020cb04:	54000700 	b.eq	8020cbe4 <_strtol_l.part.0+0x104>  // b.none
    8020cb08:	92f0000b 	mov	x11, #0x7fffffffffffffff    	// #9223372036854775807
    8020cb0c:	5280000d 	mov	w13, #0x0                   	// #0
    8020cb10:	7100acbf 	cmp	w5, #0x2b
    8020cb14:	54000620 	b.eq	8020cbd8 <_strtol_l.part.0+0xf8>  // b.none
    8020cb18:	93407c6a 	sxtw	x10, w3
    8020cb1c:	721b787f 	tst	w3, #0xffffffef
    8020cb20:	540000c1 	b.ne	8020cb38 <_strtol_l.part.0+0x58>  // b.any
    8020cb24:	7100c0bf 	cmp	w5, #0x30
    8020cb28:	54000780 	b.eq	8020cc18 <_strtol_l.part.0+0x138>  // b.none
    8020cb2c:	35000963 	cbnz	w3, 8020cc58 <_strtol_l.part.0+0x178>
    8020cb30:	d280014a 	mov	x10, #0xa                   	// #10
    8020cb34:	2a0a03e3 	mov	w3, w10
    8020cb38:	9aca0968 	udiv	x8, x11, x10
    8020cb3c:	52800007 	mov	w7, #0x0                   	// #0
    8020cb40:	d2800000 	mov	x0, #0x0                   	// #0
    8020cb44:	1b0aad09 	msub	w9, w8, w10, w11
    8020cb48:	5100c0a4 	sub	w4, w5, #0x30
    8020cb4c:	7100249f 	cmp	w4, #0x9
    8020cb50:	540000a9 	b.ls	8020cb64 <_strtol_l.part.0+0x84>  // b.plast
    8020cb54:	510104a4 	sub	w4, w5, #0x41
    8020cb58:	7100649f 	cmp	w4, #0x19
    8020cb5c:	54000208 	b.hi	8020cb9c <_strtol_l.part.0+0xbc>  // b.pmore
    8020cb60:	5100dca4 	sub	w4, w5, #0x37
    8020cb64:	6b04007f 	cmp	w3, w4
    8020cb68:	5400028d 	b.le	8020cbb8 <_strtol_l.part.0+0xd8>
    8020cb6c:	710000ff 	cmp	w7, #0x0
    8020cb70:	12800007 	mov	w7, #0xffffffff            	// #-1
    8020cb74:	fa40a100 	ccmp	x8, x0, #0x0, ge	// ge = tcont
    8020cb78:	540000e3 	b.cc	8020cb94 <_strtol_l.part.0+0xb4>  // b.lo, b.ul, b.last
    8020cb7c:	eb00011f 	cmp	x8, x0
    8020cb80:	7a440120 	ccmp	w9, w4, #0x0, eq	// eq = none
    8020cb84:	5400008b 	b.lt	8020cb94 <_strtol_l.part.0+0xb4>  // b.tstop
    8020cb88:	93407c84 	sxtw	x4, w4
    8020cb8c:	52800027 	mov	w7, #0x1                   	// #1
    8020cb90:	9b0a1000 	madd	x0, x0, x10, x4
    8020cb94:	384014c5 	ldrb	w5, [x6], #1
    8020cb98:	17ffffec 	b	8020cb48 <_strtol_l.part.0+0x68>
    8020cb9c:	510184a4 	sub	w4, w5, #0x61
    8020cba0:	7100649f 	cmp	w4, #0x19
    8020cba4:	540000a8 	b.hi	8020cbb8 <_strtol_l.part.0+0xd8>  // b.pmore
    8020cba8:	51015ca4 	sub	w4, w5, #0x57
    8020cbac:	6b04007f 	cmp	w3, w4
    8020cbb0:	54fffdec 	b.gt	8020cb6c <_strtol_l.part.0+0x8c>
    8020cbb4:	d503201f 	nop
    8020cbb8:	310004ff 	cmn	w7, #0x1
    8020cbbc:	540001e0 	b.eq	8020cbf8 <_strtol_l.part.0+0x118>  // b.none
    8020cbc0:	710001bf 	cmp	w13, #0x0
    8020cbc4:	da800400 	cneg	x0, x0, ne	// ne = any
    8020cbc8:	b4000062 	cbz	x2, 8020cbd4 <_strtol_l.part.0+0xf4>
    8020cbcc:	35000387 	cbnz	w7, 8020cc3c <_strtol_l.part.0+0x15c>
    8020cbd0:	f9000041 	str	x1, [x2]
    8020cbd4:	d65f03c0 	ret
    8020cbd8:	394000c5 	ldrb	w5, [x6]
    8020cbdc:	91000906 	add	x6, x8, #0x2
    8020cbe0:	17ffffce 	b	8020cb18 <_strtol_l.part.0+0x38>
    8020cbe4:	394000c5 	ldrb	w5, [x6]
    8020cbe8:	d2f0000b 	mov	x11, #0x8000000000000000    	// #-9223372036854775808
    8020cbec:	91000906 	add	x6, x8, #0x2
    8020cbf0:	5280002d 	mov	w13, #0x1                   	// #1
    8020cbf4:	17ffffc9 	b	8020cb18 <_strtol_l.part.0+0x38>
    8020cbf8:	52800440 	mov	w0, #0x22                  	// #34
    8020cbfc:	b9000180 	str	w0, [x12]
    8020cc00:	aa0b03e0 	mov	x0, x11
    8020cc04:	b4fffe82 	cbz	x2, 8020cbd4 <_strtol_l.part.0+0xf4>
    8020cc08:	d10004c1 	sub	x1, x6, #0x1
    8020cc0c:	aa0b03e0 	mov	x0, x11
    8020cc10:	f9000041 	str	x1, [x2]
    8020cc14:	17fffff0 	b	8020cbd4 <_strtol_l.part.0+0xf4>
    8020cc18:	394000c0 	ldrb	w0, [x6]
    8020cc1c:	121a7800 	and	w0, w0, #0xffffffdf
    8020cc20:	12001c00 	and	w0, w0, #0xff
    8020cc24:	7101601f 	cmp	w0, #0x58
    8020cc28:	540000e0 	b.eq	8020cc44 <_strtol_l.part.0+0x164>  // b.none
    8020cc2c:	35000163 	cbnz	w3, 8020cc58 <_strtol_l.part.0+0x178>
    8020cc30:	d280010a 	mov	x10, #0x8                   	// #8
    8020cc34:	2a0a03e3 	mov	w3, w10
    8020cc38:	17ffffc0 	b	8020cb38 <_strtol_l.part.0+0x58>
    8020cc3c:	aa0003eb 	mov	x11, x0
    8020cc40:	17fffff2 	b	8020cc08 <_strtol_l.part.0+0x128>
    8020cc44:	394004c5 	ldrb	w5, [x6, #1]
    8020cc48:	d280020a 	mov	x10, #0x10                  	// #16
    8020cc4c:	910008c6 	add	x6, x6, #0x2
    8020cc50:	2a0a03e3 	mov	w3, w10
    8020cc54:	17ffffb9 	b	8020cb38 <_strtol_l.part.0+0x58>
    8020cc58:	d280020a 	mov	x10, #0x10                  	// #16
    8020cc5c:	2a0a03e3 	mov	w3, w10
    8020cc60:	17ffffb6 	b	8020cb38 <_strtol_l.part.0+0x58>
	...

000000008020cc70 <_strtol_r>:
    8020cc70:	7100907f 	cmp	w3, #0x24
    8020cc74:	7a419864 	ccmp	w3, #0x1, #0x4, ls	// ls = plast
    8020cc78:	54000040 	b.eq	8020cc80 <_strtol_r+0x10>  // b.none
    8020cc7c:	17ffff99 	b	8020cae0 <_strtol_l.part.0>
    8020cc80:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020cc84:	910003fd 	mov	x29, sp
    8020cc88:	97ffd6de 	bl	80202800 <__errno>
    8020cc8c:	528002c1 	mov	w1, #0x16                  	// #22
    8020cc90:	b9000001 	str	w1, [x0]
    8020cc94:	d2800000 	mov	x0, #0x0                   	// #0
    8020cc98:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020cc9c:	d65f03c0 	ret

000000008020cca0 <strtol_l>:
    8020cca0:	b0000024 	adrp	x4, 80211000 <__mprec_tens+0x180>
    8020cca4:	7100905f 	cmp	w2, #0x24
    8020cca8:	7a419844 	ccmp	w2, #0x1, #0x4, ls	// ls = plast
    8020ccac:	f9402484 	ldr	x4, [x4, #72]
    8020ccb0:	540000c0 	b.eq	8020ccc8 <strtol_l+0x28>  // b.none
    8020ccb4:	2a0203e3 	mov	w3, w2
    8020ccb8:	aa0103e2 	mov	x2, x1
    8020ccbc:	aa0003e1 	mov	x1, x0
    8020ccc0:	aa0403e0 	mov	x0, x4
    8020ccc4:	17ffff87 	b	8020cae0 <_strtol_l.part.0>
    8020ccc8:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020cccc:	910003fd 	mov	x29, sp
    8020ccd0:	97ffd6cc 	bl	80202800 <__errno>
    8020ccd4:	528002c1 	mov	w1, #0x16                  	// #22
    8020ccd8:	b9000001 	str	w1, [x0]
    8020ccdc:	d2800000 	mov	x0, #0x0                   	// #0
    8020cce0:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020cce4:	d65f03c0 	ret
	...

000000008020ccf0 <strtol>:
    8020ccf0:	b0000024 	adrp	x4, 80211000 <__mprec_tens+0x180>
    8020ccf4:	7100905f 	cmp	w2, #0x24
    8020ccf8:	7a419844 	ccmp	w2, #0x1, #0x4, ls	// ls = plast
    8020ccfc:	f9402484 	ldr	x4, [x4, #72]
    8020cd00:	540000c0 	b.eq	8020cd18 <strtol+0x28>  // b.none
    8020cd04:	2a0203e3 	mov	w3, w2
    8020cd08:	aa0103e2 	mov	x2, x1
    8020cd0c:	aa0003e1 	mov	x1, x0
    8020cd10:	aa0403e0 	mov	x0, x4
    8020cd14:	17ffff73 	b	8020cae0 <_strtol_l.part.0>
    8020cd18:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020cd1c:	910003fd 	mov	x29, sp
    8020cd20:	97ffd6b8 	bl	80202800 <__errno>
    8020cd24:	528002c1 	mov	w1, #0x16                  	// #22
    8020cd28:	b9000001 	str	w1, [x0]
    8020cd2c:	d2800000 	mov	x0, #0x0                   	// #0
    8020cd30:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020cd34:	d65f03c0 	ret
	...

000000008020cd40 <strncasecmp>:
    8020cd40:	aa0003e9 	mov	x9, x0
    8020cd44:	b4000342 	cbz	x2, 8020cdac <strncasecmp+0x6c>
    8020cd48:	90000027 	adrp	x7, 80210000 <__trunctfdf2+0xc0>
    8020cd4c:	d2800004 	mov	x4, #0x0                   	// #0
    8020cd50:	913184e7 	add	x7, x7, #0xc61
    8020cd54:	14000006 	b	8020cd6c <strncasecmp+0x2c>
    8020cd58:	6b000063 	subs	w3, w3, w0
    8020cd5c:	540002c1 	b.ne	8020cdb4 <strncasecmp+0x74>  // b.any
    8020cd60:	34000240 	cbz	w0, 8020cda8 <strncasecmp+0x68>
    8020cd64:	eb04005f 	cmp	x2, x4
    8020cd68:	54000220 	b.eq	8020cdac <strncasecmp+0x6c>  // b.none
    8020cd6c:	38646923 	ldrb	w3, [x9, x4]
    8020cd70:	38646820 	ldrb	w0, [x1, x4]
    8020cd74:	91000484 	add	x4, x4, #0x1
    8020cd78:	11008068 	add	w8, w3, #0x20
    8020cd7c:	386348e6 	ldrb	w6, [x7, w3, uxtw]
    8020cd80:	386048e5 	ldrb	w5, [x7, w0, uxtw]
    8020cd84:	120004c6 	and	w6, w6, #0x3
    8020cd88:	710004df 	cmp	w6, #0x1
    8020cd8c:	120004a5 	and	w5, w5, #0x3
    8020cd90:	1a830103 	csel	w3, w8, w3, eq	// eq = none
    8020cd94:	710004bf 	cmp	w5, #0x1
    8020cd98:	54fffe01 	b.ne	8020cd58 <strncasecmp+0x18>  // b.any
    8020cd9c:	11008000 	add	w0, w0, #0x20
    8020cda0:	6b000060 	subs	w0, w3, w0
    8020cda4:	54fffe00 	b.eq	8020cd64 <strncasecmp+0x24>  // b.none
    8020cda8:	d65f03c0 	ret
    8020cdac:	52800000 	mov	w0, #0x0                   	// #0
    8020cdb0:	d65f03c0 	ret
    8020cdb4:	2a0303e0 	mov	w0, w3
    8020cdb8:	d65f03c0 	ret
    8020cdbc:	00000000 	udf	#0

000000008020cdc0 <_findenv_r>:
    8020cdc0:	a9bb7bfd 	stp	x29, x30, [sp, #-80]!
    8020cdc4:	910003fd 	mov	x29, sp
    8020cdc8:	a90363f7 	stp	x23, x24, [sp, #48]
    8020cdcc:	b0000038 	adrp	x24, 80211000 <__mprec_tens+0x180>
    8020cdd0:	aa0003f7 	mov	x23, x0
    8020cdd4:	a90153f3 	stp	x19, x20, [sp, #16]
    8020cdd8:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020cddc:	aa0103f5 	mov	x21, x1
    8020cde0:	aa0203f6 	mov	x22, x2
    8020cde4:	94000ac7 	bl	8020f900 <__env_lock>
    8020cde8:	f9465314 	ldr	x20, [x24, #3232]
    8020cdec:	b40003f4 	cbz	x20, 8020ce68 <_findenv_r+0xa8>
    8020cdf0:	394002a3 	ldrb	w3, [x21]
    8020cdf4:	aa1503f3 	mov	x19, x21
    8020cdf8:	7100f47f 	cmp	w3, #0x3d
    8020cdfc:	7a401864 	ccmp	w3, #0x0, #0x4, ne	// ne = any
    8020ce00:	540000c0 	b.eq	8020ce18 <_findenv_r+0x58>  // b.none
    8020ce04:	d503201f 	nop
    8020ce08:	38401e63 	ldrb	w3, [x19, #1]!
    8020ce0c:	7100f47f 	cmp	w3, #0x3d
    8020ce10:	7a401864 	ccmp	w3, #0x0, #0x4, ne	// ne = any
    8020ce14:	54ffffa1 	b.ne	8020ce08 <_findenv_r+0x48>  // b.any
    8020ce18:	7100f47f 	cmp	w3, #0x3d
    8020ce1c:	54000260 	b.eq	8020ce68 <_findenv_r+0xa8>  // b.none
    8020ce20:	f9400280 	ldr	x0, [x20]
    8020ce24:	cb150273 	sub	x19, x19, x21
    8020ce28:	b4000200 	cbz	x0, 8020ce68 <_findenv_r+0xa8>
    8020ce2c:	93407e73 	sxtw	x19, w19
    8020ce30:	f90023f9 	str	x25, [sp, #64]
    8020ce34:	d503201f 	nop
    8020ce38:	aa1303e2 	mov	x2, x19
    8020ce3c:	aa1503e1 	mov	x1, x21
    8020ce40:	94000310 	bl	8020da80 <strncmp>
    8020ce44:	350000c0 	cbnz	w0, 8020ce5c <_findenv_r+0x9c>
    8020ce48:	f9400280 	ldr	x0, [x20]
    8020ce4c:	8b130019 	add	x25, x0, x19
    8020ce50:	38736800 	ldrb	w0, [x0, x19]
    8020ce54:	7100f41f 	cmp	w0, #0x3d
    8020ce58:	54000180 	b.eq	8020ce88 <_findenv_r+0xc8>  // b.none
    8020ce5c:	f8408e80 	ldr	x0, [x20, #8]!
    8020ce60:	b5fffec0 	cbnz	x0, 8020ce38 <_findenv_r+0x78>
    8020ce64:	f94023f9 	ldr	x25, [sp, #64]
    8020ce68:	aa1703e0 	mov	x0, x23
    8020ce6c:	94000aa9 	bl	8020f910 <__env_unlock>
    8020ce70:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ce74:	d2800000 	mov	x0, #0x0                   	// #0
    8020ce78:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020ce7c:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020ce80:	a8c57bfd 	ldp	x29, x30, [sp], #80
    8020ce84:	d65f03c0 	ret
    8020ce88:	f9465301 	ldr	x1, [x24, #3232]
    8020ce8c:	aa1703e0 	mov	x0, x23
    8020ce90:	cb010281 	sub	x1, x20, x1
    8020ce94:	9343fc21 	asr	x1, x1, #3
    8020ce98:	b90002c1 	str	w1, [x22]
    8020ce9c:	94000a9d 	bl	8020f910 <__env_unlock>
    8020cea0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020cea4:	91000720 	add	x0, x25, #0x1
    8020cea8:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020ceac:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020ceb0:	f94023f9 	ldr	x25, [sp, #64]
    8020ceb4:	a8c57bfd 	ldp	x29, x30, [sp], #80
    8020ceb8:	d65f03c0 	ret
    8020cebc:	00000000 	udf	#0

000000008020cec0 <_getenv_r>:
    8020cec0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020cec4:	910003fd 	mov	x29, sp
    8020cec8:	910073e2 	add	x2, sp, #0x1c
    8020cecc:	97ffffbd 	bl	8020cdc0 <_findenv_r>
    8020ced0:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020ced4:	d65f03c0 	ret
	...

000000008020cee0 <strncpy>:
    8020cee0:	aa000023 	orr	x3, x1, x0
    8020cee4:	aa0003e4 	mov	x4, x0
    8020cee8:	f240087f 	tst	x3, #0x7
    8020ceec:	fa470840 	ccmp	x2, #0x7, #0x0, eq	// eq = none
    8020cef0:	54000109 	b.ls	8020cf10 <strncpy+0x30>  // b.plast
    8020cef4:	14000011 	b	8020cf38 <strncpy+0x58>
    8020cef8:	38401425 	ldrb	w5, [x1], #1
    8020cefc:	d1000446 	sub	x6, x2, #0x1
    8020cf00:	38001465 	strb	w5, [x3], #1
    8020cf04:	340000c5 	cbz	w5, 8020cf1c <strncpy+0x3c>
    8020cf08:	aa0303e4 	mov	x4, x3
    8020cf0c:	aa0603e2 	mov	x2, x6
    8020cf10:	aa0403e3 	mov	x3, x4
    8020cf14:	b5ffff22 	cbnz	x2, 8020cef8 <strncpy+0x18>
    8020cf18:	d65f03c0 	ret
    8020cf1c:	8b020084 	add	x4, x4, x2
    8020cf20:	b4ffffc6 	cbz	x6, 8020cf18 <strncpy+0x38>
    8020cf24:	d503201f 	nop
    8020cf28:	3800147f 	strb	wzr, [x3], #1
    8020cf2c:	eb04007f 	cmp	x3, x4
    8020cf30:	54ffffc1 	b.ne	8020cf28 <strncpy+0x48>  // b.any
    8020cf34:	d65f03c0 	ret
    8020cf38:	b207dbe6 	mov	x6, #0xfefefefefefefefe    	// #-72340172838076674
    8020cf3c:	f29fdfe6 	movk	x6, #0xfeff
    8020cf40:	14000006 	b	8020cf58 <strncpy+0x78>
    8020cf44:	d1002042 	sub	x2, x2, #0x8
    8020cf48:	f8008485 	str	x5, [x4], #8
    8020cf4c:	91002021 	add	x1, x1, #0x8
    8020cf50:	f1001c5f 	cmp	x2, #0x7
    8020cf54:	54fffde9 	b.ls	8020cf10 <strncpy+0x30>  // b.plast
    8020cf58:	f9400025 	ldr	x5, [x1]
    8020cf5c:	8b0600a3 	add	x3, x5, x6
    8020cf60:	8a250063 	bic	x3, x3, x5
    8020cf64:	f201c07f 	tst	x3, #0x8080808080808080
    8020cf68:	54fffee0 	b.eq	8020cf44 <strncpy+0x64>  // b.none
    8020cf6c:	17ffffe9 	b	8020cf10 <strncpy+0x30>

000000008020cf70 <_fstat_r>:
    8020cf70:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020cf74:	910003fd 	mov	x29, sp
    8020cf78:	a90153f3 	stp	x19, x20, [sp, #16]
    8020cf7c:	900003b4 	adrp	x20, 80280000 <gits_lock>
    8020cf80:	aa0003f3 	mov	x19, x0
    8020cf84:	b9048a9f 	str	wzr, [x20, #1160]
    8020cf88:	2a0103e0 	mov	w0, w1
    8020cf8c:	aa0203e1 	mov	x1, x2
    8020cf90:	97ffce78 	bl	80200970 <_fstat>
    8020cf94:	3100041f 	cmn	w0, #0x1
    8020cf98:	54000080 	b.eq	8020cfa8 <_fstat_r+0x38>  // b.none
    8020cf9c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020cfa0:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020cfa4:	d65f03c0 	ret
    8020cfa8:	b9448a81 	ldr	w1, [x20, #1160]
    8020cfac:	34ffff81 	cbz	w1, 8020cf9c <_fstat_r+0x2c>
    8020cfb0:	b9000261 	str	w1, [x19]
    8020cfb4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020cfb8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020cfbc:	d65f03c0 	ret

000000008020cfc0 <_isatty_r>:
    8020cfc0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020cfc4:	910003fd 	mov	x29, sp
    8020cfc8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020cfcc:	900003b4 	adrp	x20, 80280000 <gits_lock>
    8020cfd0:	aa0003f3 	mov	x19, x0
    8020cfd4:	b9048a9f 	str	wzr, [x20, #1160]
    8020cfd8:	2a0103e0 	mov	w0, w1
    8020cfdc:	97ffce69 	bl	80200980 <_isatty>
    8020cfe0:	3100041f 	cmn	w0, #0x1
    8020cfe4:	54000080 	b.eq	8020cff4 <_isatty_r+0x34>  // b.none
    8020cfe8:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020cfec:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020cff0:	d65f03c0 	ret
    8020cff4:	b9448a81 	ldr	w1, [x20, #1160]
    8020cff8:	34ffff81 	cbz	w1, 8020cfe8 <_isatty_r+0x28>
    8020cffc:	b9000261 	str	w1, [x19]
    8020d000:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d004:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d008:	d65f03c0 	ret
    8020d00c:	00000000 	udf	#0

000000008020d010 <_lseek_r>:
    8020d010:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020d014:	910003fd 	mov	x29, sp
    8020d018:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d01c:	f0000394 	adrp	x20, 80280000 <gits_lock>
    8020d020:	aa0003f3 	mov	x19, x0
    8020d024:	b9048a9f 	str	wzr, [x20, #1160]
    8020d028:	2a0103e0 	mov	w0, w1
    8020d02c:	aa0203e1 	mov	x1, x2
    8020d030:	2a0303e2 	mov	w2, w3
    8020d034:	97ffce40 	bl	80200934 <_lseek>
    8020d038:	b100041f 	cmn	x0, #0x1
    8020d03c:	54000080 	b.eq	8020d04c <_lseek_r+0x3c>  // b.none
    8020d040:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d044:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d048:	d65f03c0 	ret
    8020d04c:	b9448a81 	ldr	w1, [x20, #1160]
    8020d050:	34ffff81 	cbz	w1, 8020d040 <_lseek_r+0x30>
    8020d054:	b9000261 	str	w1, [x19]
    8020d058:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d05c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d060:	d65f03c0 	ret
	...

000000008020d070 <_read_r>:
    8020d070:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020d074:	910003fd 	mov	x29, sp
    8020d078:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d07c:	f0000394 	adrp	x20, 80280000 <gits_lock>
    8020d080:	aa0003f3 	mov	x19, x0
    8020d084:	2a0103e0 	mov	w0, w1
    8020d088:	aa0203e1 	mov	x1, x2
    8020d08c:	b9048a9f 	str	wzr, [x20, #1160]
    8020d090:	aa0303e2 	mov	x2, x3
    8020d094:	97ffcdf7 	bl	80200870 <_read>
    8020d098:	93407c01 	sxtw	x1, w0
    8020d09c:	3100041f 	cmn	w0, #0x1
    8020d0a0:	540000a0 	b.eq	8020d0b4 <_read_r+0x44>  // b.none
    8020d0a4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d0a8:	aa0103e0 	mov	x0, x1
    8020d0ac:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d0b0:	d65f03c0 	ret
    8020d0b4:	b9448a80 	ldr	w0, [x20, #1160]
    8020d0b8:	34ffff60 	cbz	w0, 8020d0a4 <_read_r+0x34>
    8020d0bc:	b9000260 	str	w0, [x19]
    8020d0c0:	aa0103e0 	mov	x0, x1
    8020d0c4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d0c8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d0cc:	d65f03c0 	ret
	...

000000008020d100 <strchr>:
    8020d100:	d503245f 	bti	c
    8020d104:	52818064 	mov	w4, #0xc03                 	// #3075
    8020d108:	72b80604 	movk	w4, #0xc030, lsl #16
    8020d10c:	4e010c20 	dup	v0.16b, w1
    8020d110:	927be802 	and	x2, x0, #0xffffffffffffffe0
    8020d114:	4e040c90 	dup	v16.4s, w4
    8020d118:	f2401003 	ands	x3, x0, #0x1f
    8020d11c:	4eb08607 	add	v7.4s, v16.4s, v16.4s
    8020d120:	54000280 	b.eq	8020d170 <strchr+0x70>  // b.none
    8020d124:	4cdfa041 	ld1	{v1.16b-v2.16b}, [x2], #32
    8020d128:	cb0303e3 	neg	x3, x3
    8020d12c:	4e209823 	cmeq	v3.16b, v1.16b, #0
    8020d130:	6e208c25 	cmeq	v5.16b, v1.16b, v0.16b
    8020d134:	4e209844 	cmeq	v4.16b, v2.16b, #0
    8020d138:	6e208c46 	cmeq	v6.16b, v2.16b, v0.16b
    8020d13c:	6ee71ca3 	bif	v3.16b, v5.16b, v7.16b
    8020d140:	6ee71cc4 	bif	v4.16b, v6.16b, v7.16b
    8020d144:	4e301c71 	and	v17.16b, v3.16b, v16.16b
    8020d148:	4e301c92 	and	v18.16b, v4.16b, v16.16b
    8020d14c:	d37ff863 	lsl	x3, x3, #1
    8020d150:	4e32be31 	addp	v17.16b, v17.16b, v18.16b
    8020d154:	92800005 	mov	x5, #0xffffffffffffffff    	// #-1
    8020d158:	4e32be31 	addp	v17.16b, v17.16b, v18.16b
    8020d15c:	9ac324a3 	lsr	x3, x5, x3
    8020d160:	4e083e25 	mov	x5, v17.d[0]
    8020d164:	8a2300a3 	bic	x3, x5, x3
    8020d168:	b5000243 	cbnz	x3, 8020d1b0 <strchr+0xb0>
    8020d16c:	d503201f 	nop
    8020d170:	4cdfa041 	ld1	{v1.16b-v2.16b}, [x2], #32
    8020d174:	6e208c25 	cmeq	v5.16b, v1.16b, v0.16b
    8020d178:	6e208c46 	cmeq	v6.16b, v2.16b, v0.16b
    8020d17c:	6e213ca3 	cmhs	v3.16b, v5.16b, v1.16b
    8020d180:	6e223cc4 	cmhs	v4.16b, v6.16b, v2.16b
    8020d184:	4ea41c71 	orr	v17.16b, v3.16b, v4.16b
    8020d188:	6e31a631 	umaxp	v17.16b, v17.16b, v17.16b
    8020d18c:	4e083e23 	mov	x3, v17.d[0]
    8020d190:	b4ffff03 	cbz	x3, 8020d170 <strchr+0x70>
    8020d194:	6ee71ca3 	bif	v3.16b, v5.16b, v7.16b
    8020d198:	6ee71cc4 	bif	v4.16b, v6.16b, v7.16b
    8020d19c:	4e301c71 	and	v17.16b, v3.16b, v16.16b
    8020d1a0:	4e301c92 	and	v18.16b, v4.16b, v16.16b
    8020d1a4:	4e32be31 	addp	v17.16b, v17.16b, v18.16b
    8020d1a8:	4e32be31 	addp	v17.16b, v17.16b, v18.16b
    8020d1ac:	4e083e23 	mov	x3, v17.d[0]
    8020d1b0:	dac00063 	rbit	x3, x3
    8020d1b4:	d1008042 	sub	x2, x2, #0x20
    8020d1b8:	dac01063 	clz	x3, x3
    8020d1bc:	f240007f 	tst	x3, #0x1
    8020d1c0:	8b430440 	add	x0, x2, x3, lsr #1
    8020d1c4:	9a9f0000 	csel	x0, x0, xzr, eq	// eq = none
    8020d1c8:	d65f03c0 	ret
	...

000000008020d200 <strcmp>:
    8020d200:	d503245f 	bti	c
    8020d204:	cb00002a 	sub	x10, x1, x0
    8020d208:	b200c3e8 	mov	x8, #0x101010101010101     	// #72340172838076673
    8020d20c:	92400806 	and	x6, x0, #0x7
    8020d210:	f240095f 	tst	x10, #0x7
    8020d214:	54000401 	b.ne	8020d294 <strcmp+0x94>  // b.any
    8020d218:	b50002c6 	cbnz	x6, 8020d270 <strcmp+0x70>
    8020d21c:	d503201f 	nop
    8020d220:	f86a6803 	ldr	x3, [x0, x10]
    8020d224:	f8408402 	ldr	x2, [x0], #8
    8020d228:	cb080044 	sub	x4, x2, x8
    8020d22c:	b200d846 	orr	x6, x2, #0x7f7f7f7f7f7f7f7f
    8020d230:	ea260084 	bics	x4, x4, x6
    8020d234:	fa430040 	ccmp	x2, x3, #0x0, eq	// eq = none
    8020d238:	54ffff40 	b.eq	8020d220 <strcmp+0x20>  // b.none
    8020d23c:	ca030045 	eor	x5, x2, x3
    8020d240:	aa0400a6 	orr	x6, x5, x4
    8020d244:	dac00cc6 	rev	x6, x6
    8020d248:	dac00c42 	rev	x2, x2
    8020d24c:	dac00c63 	rev	x3, x3
    8020d250:	dac010c9 	clz	x9, x6
    8020d254:	9ac92042 	lsl	x2, x2, x9
    8020d258:	9ac92063 	lsl	x3, x3, x9
    8020d25c:	d378fc42 	lsr	x2, x2, #56
    8020d260:	cb43e040 	sub	x0, x2, x3, lsr #56
    8020d264:	d65f03c0 	ret
    8020d268:	d503201f 	nop
    8020d26c:	d503201f 	nop
    8020d270:	927df000 	and	x0, x0, #0xfffffffffffffff8
    8020d274:	f86a6803 	ldr	x3, [x0, x10]
    8020d278:	f8408402 	ldr	x2, [x0], #8
    8020d27c:	cb010fe9 	neg	x9, x1, lsl #3
    8020d280:	92800006 	mov	x6, #0xffffffffffffffff    	// #-1
    8020d284:	9ac924c6 	lsr	x6, x6, x9
    8020d288:	aa060042 	orr	x2, x2, x6
    8020d28c:	aa060063 	orr	x3, x3, x6
    8020d290:	17ffffe6 	b	8020d228 <strcmp+0x28>
    8020d294:	b4000106 	cbz	x6, 8020d2b4 <strcmp+0xb4>
    8020d298:	38401402 	ldrb	w2, [x0], #1
    8020d29c:	38401423 	ldrb	w3, [x1], #1
    8020d2a0:	7100005f 	cmp	w2, #0x0
    8020d2a4:	7a431040 	ccmp	w2, w3, #0x0, ne	// ne = any
    8020d2a8:	54000421 	b.ne	8020d32c <strcmp+0x12c>  // b.any
    8020d2ac:	f240081f 	tst	x0, #0x7
    8020d2b0:	54ffff41 	b.ne	8020d298 <strcmp+0x98>  // b.any
    8020d2b4:	cb010fe9 	neg	x9, x1, lsl #3
    8020d2b8:	927df021 	and	x1, x1, #0xfffffffffffffff8
    8020d2bc:	f8408427 	ldr	x7, [x1], #8
    8020d2c0:	9ac92506 	lsr	x6, x8, x9
    8020d2c4:	aa0600e7 	orr	x7, x7, x6
    8020d2c8:	cb0800e4 	sub	x4, x7, x8
    8020d2cc:	b200d8e6 	orr	x6, x7, #0x7f7f7f7f7f7f7f7f
    8020d2d0:	ea260084 	bics	x4, x4, x6
    8020d2d4:	540001e1 	b.ne	8020d310 <strcmp+0x110>  // b.any
    8020d2d8:	cb000025 	sub	x5, x1, x0
    8020d2dc:	d503201f 	nop
    8020d2e0:	f8656807 	ldr	x7, [x0, x5]
    8020d2e4:	f86a6803 	ldr	x3, [x0, x10]
    8020d2e8:	cb0800e4 	sub	x4, x7, x8
    8020d2ec:	b200d8e6 	orr	x6, x7, #0x7f7f7f7f7f7f7f7f
    8020d2f0:	f8408402 	ldr	x2, [x0], #8
    8020d2f4:	ea260084 	bics	x4, x4, x6
    8020d2f8:	fa430040 	ccmp	x2, x3, #0x0, eq	// eq = none
    8020d2fc:	54ffff20 	b.eq	8020d2e0 <strcmp+0xe0>  // b.none
    8020d300:	9ac92086 	lsl	x6, x4, x9
    8020d304:	ca030045 	eor	x5, x2, x3
    8020d308:	aa0600a6 	orr	x6, x5, x6
    8020d30c:	b5fff9c6 	cbnz	x6, 8020d244 <strcmp+0x44>
    8020d310:	f9400002 	ldr	x2, [x0]
    8020d314:	cb0903e9 	neg	x9, x9
    8020d318:	9ac924e3 	lsr	x3, x7, x9
    8020d31c:	9ac92484 	lsr	x4, x4, x9
    8020d320:	ca030045 	eor	x5, x2, x3
    8020d324:	aa0400a6 	orr	x6, x5, x4
    8020d328:	17ffffc7 	b	8020d244 <strcmp+0x44>
    8020d32c:	cb030040 	sub	x0, x2, x3
    8020d330:	d65f03c0 	ret
	...

000000008020d340 <strcpy>:
    8020d340:	d503245f 	bti	c
    8020d344:	927cec22 	and	x2, x1, #0xfffffffffffffff0
    8020d348:	4c407040 	ld1	{v0.16b}, [x2]
    8020d34c:	4e209801 	cmeq	v1.16b, v0.16b, #0
    8020d350:	d37ef425 	lsl	x5, x1, #2
    8020d354:	0f0c8422 	shrn	v2.8b, v1.8h, #4
    8020d358:	9e660044 	fmov	x4, d2
    8020d35c:	9ac52484 	lsr	x4, x4, x5
    8020d360:	b5000224 	cbnz	x4, 8020d3a4 <strcpy+0x64>
    8020d364:	3cc10c40 	ldr	q0, [x2, #16]!
    8020d368:	4e209801 	cmeq	v1.16b, v0.16b, #0
    8020d36c:	0f0c8422 	shrn	v2.8b, v1.8h, #4
    8020d370:	9e660044 	fmov	x4, d2
    8020d374:	b4000464 	cbz	x4, 8020d400 <strcpy+0xc0>
    8020d378:	dac00084 	rbit	x4, x4
    8020d37c:	cb010045 	sub	x5, x2, x1
    8020d380:	dac01084 	clz	x4, x4
    8020d384:	8b4408a4 	add	x4, x5, x4, lsr #2
    8020d388:	36200144 	tbz	w4, #4, 8020d3b0 <strcpy+0x70>
    8020d38c:	d1003c85 	sub	x5, x4, #0xf
    8020d390:	3dc00020 	ldr	q0, [x1]
    8020d394:	3ce56821 	ldr	q1, [x1, x5]
    8020d398:	3d800000 	str	q0, [x0]
    8020d39c:	3ca56801 	str	q1, [x0, x5]
    8020d3a0:	d65f03c0 	ret
    8020d3a4:	dac00084 	rbit	x4, x4
    8020d3a8:	dac01084 	clz	x4, x4
    8020d3ac:	d342fc84 	lsr	x4, x4, #2
    8020d3b0:	36180104 	tbz	w4, #3, 8020d3d0 <strcpy+0x90>
    8020d3b4:	d1001c85 	sub	x5, x4, #0x7
    8020d3b8:	f9400026 	ldr	x6, [x1]
    8020d3bc:	f8656827 	ldr	x7, [x1, x5]
    8020d3c0:	f9000006 	str	x6, [x0]
    8020d3c4:	f8256807 	str	x7, [x0, x5]
    8020d3c8:	d65f03c0 	ret
    8020d3cc:	d503201f 	nop
    8020d3d0:	f1000c85 	subs	x5, x4, #0x3
    8020d3d4:	540000c3 	b.cc	8020d3ec <strcpy+0xac>  // b.lo, b.ul, b.last
    8020d3d8:	b9400026 	ldr	w6, [x1]
    8020d3dc:	b8656827 	ldr	w7, [x1, x5]
    8020d3e0:	b9000006 	str	w6, [x0]
    8020d3e4:	b8256807 	str	w7, [x0, x5]
    8020d3e8:	d65f03c0 	ret
    8020d3ec:	b4000064 	cbz	x4, 8020d3f8 <strcpy+0xb8>
    8020d3f0:	79400026 	ldrh	w6, [x1]
    8020d3f4:	79000006 	strh	w6, [x0]
    8020d3f8:	3824681f 	strb	wzr, [x0, x4]
    8020d3fc:	d65f03c0 	ret
    8020d400:	cb000025 	sub	x5, x1, x0
    8020d404:	3dc00021 	ldr	q1, [x1]
    8020d408:	cb050043 	sub	x3, x2, x5
    8020d40c:	3d800001 	str	q1, [x0]
    8020d410:	3c820460 	str	q0, [x3], #32
    8020d414:	3dc00440 	ldr	q0, [x2, #16]
    8020d418:	4e209801 	cmeq	v1.16b, v0.16b, #0
    8020d41c:	6e21a422 	umaxp	v2.16b, v1.16b, v1.16b
    8020d420:	9e660044 	fmov	x4, d2
    8020d424:	b5000104 	cbnz	x4, 8020d444 <strcpy+0x104>
    8020d428:	3c9f0060 	stur	q0, [x3, #-16]
    8020d42c:	3cc20c40 	ldr	q0, [x2, #32]!
    8020d430:	4e209801 	cmeq	v1.16b, v0.16b, #0
    8020d434:	6e21a422 	umaxp	v2.16b, v1.16b, v1.16b
    8020d438:	9e660044 	fmov	x4, d2
    8020d43c:	b4fffea4 	cbz	x4, 8020d410 <strcpy+0xd0>
    8020d440:	91004063 	add	x3, x3, #0x10
    8020d444:	0f0c8422 	shrn	v2.8b, v1.8h, #4
    8020d448:	9e660044 	fmov	x4, d2
    8020d44c:	d1007c63 	sub	x3, x3, #0x1f
    8020d450:	dac00084 	rbit	x4, x4
    8020d454:	dac01084 	clz	x4, x4
    8020d458:	d342fc84 	lsr	x4, x4, #2
    8020d45c:	8b040063 	add	x3, x3, x4
    8020d460:	3ce56860 	ldr	q0, [x3, x5]
    8020d464:	3d800060 	str	q0, [x3]
    8020d468:	d65f03c0 	ret
    8020d46c:	00000000 	udf	#0

000000008020d470 <__fputwc>:
    8020d470:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020d474:	910003fd 	mov	x29, sp
    8020d478:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d47c:	2a0103f4 	mov	w20, w1
    8020d480:	aa0203f3 	mov	x19, x2
    8020d484:	f90013f5 	str	x21, [sp, #32]
    8020d488:	aa0003f5 	mov	x21, x0
    8020d48c:	97fff305 	bl	8020a0a0 <__locale_mb_cur_max>
    8020d490:	7100041f 	cmp	w0, #0x1
    8020d494:	54000081 	b.ne	8020d4a4 <__fputwc+0x34>  // b.any
    8020d498:	51000680 	sub	w0, w20, #0x1
    8020d49c:	7103f81f 	cmp	w0, #0xfe
    8020d4a0:	540004a9 	b.ls	8020d534 <__fputwc+0xc4>  // b.plast
    8020d4a4:	9102a263 	add	x3, x19, #0xa8
    8020d4a8:	2a1403e2 	mov	w2, w20
    8020d4ac:	9100e3e1 	add	x1, sp, #0x38
    8020d4b0:	aa1503e0 	mov	x0, x21
    8020d4b4:	97ffef63 	bl	80209240 <_wcrtomb_r>
    8020d4b8:	b100041f 	cmn	x0, #0x1
    8020d4bc:	54000400 	b.eq	8020d53c <__fputwc+0xcc>  // b.none
    8020d4c0:	b40001c0 	cbz	x0, 8020d4f8 <__fputwc+0x88>
    8020d4c4:	b9400e63 	ldr	w3, [x19, #12]
    8020d4c8:	3940e3e1 	ldrb	w1, [sp, #56]
    8020d4cc:	51000463 	sub	w3, w3, #0x1
    8020d4d0:	b9000e63 	str	w3, [x19, #12]
    8020d4d4:	36f800a3 	tbz	w3, #31, 8020d4e8 <__fputwc+0x78>
    8020d4d8:	b9402a64 	ldr	w4, [x19, #40]
    8020d4dc:	6b04007f 	cmp	w3, w4
    8020d4e0:	7a4aa824 	ccmp	w1, #0xa, #0x4, ge	// ge = tcont
    8020d4e4:	54000140 	b.eq	8020d50c <__fputwc+0x9c>  // b.none
    8020d4e8:	f9400263 	ldr	x3, [x19]
    8020d4ec:	91000464 	add	x4, x3, #0x1
    8020d4f0:	f9000264 	str	x4, [x19]
    8020d4f4:	39000061 	strb	w1, [x3]
    8020d4f8:	f94013f5 	ldr	x21, [sp, #32]
    8020d4fc:	2a1403e0 	mov	w0, w20
    8020d500:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d504:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020d508:	d65f03c0 	ret
    8020d50c:	aa1303e2 	mov	x2, x19
    8020d510:	aa1503e0 	mov	x0, x21
    8020d514:	940001cb 	bl	8020dc40 <__swbuf_r>
    8020d518:	3100041f 	cmn	w0, #0x1
    8020d51c:	54fffee1 	b.ne	8020d4f8 <__fputwc+0x88>  // b.any
    8020d520:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020d524:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d528:	f94013f5 	ldr	x21, [sp, #32]
    8020d52c:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020d530:	d65f03c0 	ret
    8020d534:	3900e3f4 	strb	w20, [sp, #56]
    8020d538:	17ffffe3 	b	8020d4c4 <__fputwc+0x54>
    8020d53c:	79402260 	ldrh	w0, [x19, #16]
    8020d540:	321a0000 	orr	w0, w0, #0x40
    8020d544:	79002260 	strh	w0, [x19, #16]
    8020d548:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020d54c:	17fffff6 	b	8020d524 <__fputwc+0xb4>

000000008020d550 <_fputwc_r>:
    8020d550:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020d554:	910003fd 	mov	x29, sp
    8020d558:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d55c:	aa0003f4 	mov	x20, x0
    8020d560:	b940b040 	ldr	w0, [x2, #176]
    8020d564:	aa0203f3 	mov	x19, x2
    8020d568:	79c02042 	ldrsh	w2, [x2, #16]
    8020d56c:	37000040 	tbnz	w0, #0, 8020d574 <_fputwc_r+0x24>
    8020d570:	36480322 	tbz	w2, #9, 8020d5d4 <_fputwc_r+0x84>
    8020d574:	376800c2 	tbnz	w2, #13, 8020d58c <_fputwc_r+0x3c>
    8020d578:	b940b260 	ldr	w0, [x19, #176]
    8020d57c:	32130042 	orr	w2, w2, #0x2000
    8020d580:	79002262 	strh	w2, [x19, #16]
    8020d584:	32130000 	orr	w0, w0, #0x2000
    8020d588:	b900b260 	str	w0, [x19, #176]
    8020d58c:	aa1403e0 	mov	x0, x20
    8020d590:	aa1303e2 	mov	x2, x19
    8020d594:	97ffffb7 	bl	8020d470 <__fputwc>
    8020d598:	2a0003f4 	mov	w20, w0
    8020d59c:	b940b261 	ldr	w1, [x19, #176]
    8020d5a0:	37000061 	tbnz	w1, #0, 8020d5ac <_fputwc_r+0x5c>
    8020d5a4:	79402260 	ldrh	w0, [x19, #16]
    8020d5a8:	364800a0 	tbz	w0, #9, 8020d5bc <_fputwc_r+0x6c>
    8020d5ac:	2a1403e0 	mov	w0, w20
    8020d5b0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d5b4:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020d5b8:	d65f03c0 	ret
    8020d5bc:	f9405260 	ldr	x0, [x19, #160]
    8020d5c0:	97ffef90 	bl	80209400 <__retarget_lock_release_recursive>
    8020d5c4:	2a1403e0 	mov	w0, w20
    8020d5c8:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d5cc:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020d5d0:	d65f03c0 	ret
    8020d5d4:	f9405260 	ldr	x0, [x19, #160]
    8020d5d8:	b9002fe1 	str	w1, [sp, #44]
    8020d5dc:	97ffef79 	bl	802093c0 <__retarget_lock_acquire_recursive>
    8020d5e0:	79c02262 	ldrsh	w2, [x19, #16]
    8020d5e4:	b9402fe1 	ldr	w1, [sp, #44]
    8020d5e8:	17ffffe3 	b	8020d574 <_fputwc_r+0x24>
    8020d5ec:	00000000 	udf	#0

000000008020d5f0 <fputwc>:
    8020d5f0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020d5f4:	90000022 	adrp	x2, 80211000 <__mprec_tens+0x180>
    8020d5f8:	910003fd 	mov	x29, sp
    8020d5fc:	f90013f5 	str	x21, [sp, #32]
    8020d600:	f9402455 	ldr	x21, [x2, #72]
    8020d604:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d608:	2a0003f4 	mov	w20, w0
    8020d60c:	aa0103f3 	mov	x19, x1
    8020d610:	b4000075 	cbz	x21, 8020d61c <fputwc+0x2c>
    8020d614:	f94026a0 	ldr	x0, [x21, #72]
    8020d618:	b4000480 	cbz	x0, 8020d6a8 <fputwc+0xb8>
    8020d61c:	b940b260 	ldr	w0, [x19, #176]
    8020d620:	79c02262 	ldrsh	w2, [x19, #16]
    8020d624:	37000040 	tbnz	w0, #0, 8020d62c <fputwc+0x3c>
    8020d628:	36480382 	tbz	w2, #9, 8020d698 <fputwc+0xa8>
    8020d62c:	376800c2 	tbnz	w2, #13, 8020d644 <fputwc+0x54>
    8020d630:	b940b260 	ldr	w0, [x19, #176]
    8020d634:	32130042 	orr	w2, w2, #0x2000
    8020d638:	79002262 	strh	w2, [x19, #16]
    8020d63c:	32130000 	orr	w0, w0, #0x2000
    8020d640:	b900b260 	str	w0, [x19, #176]
    8020d644:	2a1403e1 	mov	w1, w20
    8020d648:	aa1503e0 	mov	x0, x21
    8020d64c:	aa1303e2 	mov	x2, x19
    8020d650:	97ffff88 	bl	8020d470 <__fputwc>
    8020d654:	b940b261 	ldr	w1, [x19, #176]
    8020d658:	2a0003f4 	mov	w20, w0
    8020d65c:	37000061 	tbnz	w1, #0, 8020d668 <fputwc+0x78>
    8020d660:	79402260 	ldrh	w0, [x19, #16]
    8020d664:	364800c0 	tbz	w0, #9, 8020d67c <fputwc+0x8c>
    8020d668:	f94013f5 	ldr	x21, [sp, #32]
    8020d66c:	2a1403e0 	mov	w0, w20
    8020d670:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d674:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020d678:	d65f03c0 	ret
    8020d67c:	f9405260 	ldr	x0, [x19, #160]
    8020d680:	97ffef60 	bl	80209400 <__retarget_lock_release_recursive>
    8020d684:	f94013f5 	ldr	x21, [sp, #32]
    8020d688:	2a1403e0 	mov	w0, w20
    8020d68c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d690:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020d694:	d65f03c0 	ret
    8020d698:	f9405260 	ldr	x0, [x19, #160]
    8020d69c:	97ffef49 	bl	802093c0 <__retarget_lock_acquire_recursive>
    8020d6a0:	79c02262 	ldrsh	w2, [x19, #16]
    8020d6a4:	17ffffe2 	b	8020d62c <fputwc+0x3c>
    8020d6a8:	aa1503e0 	mov	x0, x21
    8020d6ac:	97ffd5c9 	bl	80202dd0 <__sinit>
    8020d6b0:	17ffffdb 	b	8020d61c <fputwc+0x2c>
	...

000000008020d6c0 <_wctomb_r>:
    8020d6c0:	90000024 	adrp	x4, 80211000 <__mprec_tens+0x180>
    8020d6c4:	f945d884 	ldr	x4, [x4, #2992]
    8020d6c8:	aa0403f0 	mov	x16, x4
    8020d6cc:	d61f0200 	br	x16

000000008020d6d0 <__ascii_wctomb>:
    8020d6d0:	aa0003e3 	mov	x3, x0
    8020d6d4:	b4000141 	cbz	x1, 8020d6fc <__ascii_wctomb+0x2c>
    8020d6d8:	7103fc5f 	cmp	w2, #0xff
    8020d6dc:	54000088 	b.hi	8020d6ec <__ascii_wctomb+0x1c>  // b.pmore
    8020d6e0:	52800020 	mov	w0, #0x1                   	// #1
    8020d6e4:	39000022 	strb	w2, [x1]
    8020d6e8:	d65f03c0 	ret
    8020d6ec:	52801141 	mov	w1, #0x8a                  	// #138
    8020d6f0:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020d6f4:	b9000061 	str	w1, [x3]
    8020d6f8:	d65f03c0 	ret
    8020d6fc:	52800000 	mov	w0, #0x0                   	// #0
    8020d700:	d65f03c0 	ret
	...

000000008020d710 <__utf8_wctomb>:
    8020d710:	aa0003e3 	mov	x3, x0
    8020d714:	b40004e1 	cbz	x1, 8020d7b0 <__utf8_wctomb+0xa0>
    8020d718:	7101fc5f 	cmp	w2, #0x7f
    8020d71c:	54000349 	b.ls	8020d784 <__utf8_wctomb+0x74>  // b.plast
    8020d720:	51020040 	sub	w0, w2, #0x80
    8020d724:	711dfc1f 	cmp	w0, #0x77f
    8020d728:	54000349 	b.ls	8020d790 <__utf8_wctomb+0x80>  // b.plast
    8020d72c:	51200044 	sub	w4, w2, #0x800
    8020d730:	529effe0 	mov	w0, #0xf7ff                	// #63487
    8020d734:	6b00009f 	cmp	w4, w0
    8020d738:	54000409 	b.ls	8020d7b8 <__utf8_wctomb+0xa8>  // b.plast
    8020d73c:	51404044 	sub	w4, w2, #0x10, lsl #12
    8020d740:	12bffe00 	mov	w0, #0xfffff               	// #1048575
    8020d744:	6b00009f 	cmp	w4, w0
    8020d748:	540004e8 	b.hi	8020d7e4 <__utf8_wctomb+0xd4>  // b.pmore
    8020d74c:	53127c45 	lsr	w5, w2, #18
    8020d750:	d34c4444 	ubfx	x4, x2, #12, #6
    8020d754:	d3462c43 	ubfx	x3, x2, #6, #6
    8020d758:	12001442 	and	w2, w2, #0x3f
    8020d75c:	321c6ca5 	orr	w5, w5, #0xfffffff0
    8020d760:	32196084 	orr	w4, w4, #0xffffff80
    8020d764:	32196063 	orr	w3, w3, #0xffffff80
    8020d768:	32196042 	orr	w2, w2, #0xffffff80
    8020d76c:	52800080 	mov	w0, #0x4                   	// #4
    8020d770:	39000025 	strb	w5, [x1]
    8020d774:	39000424 	strb	w4, [x1, #1]
    8020d778:	39000823 	strb	w3, [x1, #2]
    8020d77c:	39000c22 	strb	w2, [x1, #3]
    8020d780:	d65f03c0 	ret
    8020d784:	52800020 	mov	w0, #0x1                   	// #1
    8020d788:	39000022 	strb	w2, [x1]
    8020d78c:	d65f03c0 	ret
    8020d790:	53067c43 	lsr	w3, w2, #6
    8020d794:	12001442 	and	w2, w2, #0x3f
    8020d798:	321a6463 	orr	w3, w3, #0xffffffc0
    8020d79c:	32196042 	orr	w2, w2, #0xffffff80
    8020d7a0:	52800040 	mov	w0, #0x2                   	// #2
    8020d7a4:	39000023 	strb	w3, [x1]
    8020d7a8:	39000422 	strb	w2, [x1, #1]
    8020d7ac:	d65f03c0 	ret
    8020d7b0:	52800000 	mov	w0, #0x0                   	// #0
    8020d7b4:	d65f03c0 	ret
    8020d7b8:	530c7c44 	lsr	w4, w2, #12
    8020d7bc:	d3462c43 	ubfx	x3, x2, #6, #6
    8020d7c0:	12001442 	and	w2, w2, #0x3f
    8020d7c4:	321b6884 	orr	w4, w4, #0xffffffe0
    8020d7c8:	32196063 	orr	w3, w3, #0xffffff80
    8020d7cc:	32196042 	orr	w2, w2, #0xffffff80
    8020d7d0:	52800060 	mov	w0, #0x3                   	// #3
    8020d7d4:	39000024 	strb	w4, [x1]
    8020d7d8:	39000423 	strb	w3, [x1, #1]
    8020d7dc:	39000822 	strb	w2, [x1, #2]
    8020d7e0:	d65f03c0 	ret
    8020d7e4:	52801141 	mov	w1, #0x8a                  	// #138
    8020d7e8:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020d7ec:	b9000061 	str	w1, [x3]
    8020d7f0:	d65f03c0 	ret
	...

000000008020d800 <__sjis_wctomb>:
    8020d800:	aa0003e5 	mov	x5, x0
    8020d804:	12001c44 	and	w4, w2, #0xff
    8020d808:	d3483c43 	ubfx	x3, x2, #8, #8
    8020d80c:	b4000301 	cbz	x1, 8020d86c <__sjis_wctomb+0x6c>
    8020d810:	34000283 	cbz	w3, 8020d860 <__sjis_wctomb+0x60>
    8020d814:	1101fc60 	add	w0, w3, #0x7f
    8020d818:	11008063 	add	w3, w3, #0x20
    8020d81c:	12001c00 	and	w0, w0, #0xff
    8020d820:	12001c63 	and	w3, w3, #0xff
    8020d824:	7100781f 	cmp	w0, #0x1e
    8020d828:	7a4f8860 	ccmp	w3, #0xf, #0x0, hi	// hi = pmore
    8020d82c:	54000248 	b.hi	8020d874 <__sjis_wctomb+0x74>  // b.pmore
    8020d830:	51010080 	sub	w0, w4, #0x40
    8020d834:	51020084 	sub	w4, w4, #0x80
    8020d838:	12001c00 	and	w0, w0, #0xff
    8020d83c:	12001c84 	and	w4, w4, #0xff
    8020d840:	7100f81f 	cmp	w0, #0x3e
    8020d844:	52800f80 	mov	w0, #0x7c                  	// #124
    8020d848:	7a408080 	ccmp	w4, w0, #0x0, hi	// hi = pmore
    8020d84c:	54000148 	b.hi	8020d874 <__sjis_wctomb+0x74>  // b.pmore
    8020d850:	5ac00442 	rev16	w2, w2
    8020d854:	52800040 	mov	w0, #0x2                   	// #2
    8020d858:	79000022 	strh	w2, [x1]
    8020d85c:	d65f03c0 	ret
    8020d860:	52800020 	mov	w0, #0x1                   	// #1
    8020d864:	39000024 	strb	w4, [x1]
    8020d868:	d65f03c0 	ret
    8020d86c:	52800000 	mov	w0, #0x0                   	// #0
    8020d870:	d65f03c0 	ret
    8020d874:	52801141 	mov	w1, #0x8a                  	// #138
    8020d878:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020d87c:	b90000a1 	str	w1, [x5]
    8020d880:	d65f03c0 	ret
	...

000000008020d890 <__eucjp_wctomb>:
    8020d890:	aa0003e4 	mov	x4, x0
    8020d894:	12001c43 	and	w3, w2, #0xff
    8020d898:	d3483c45 	ubfx	x5, x2, #8, #8
    8020d89c:	b40003a1 	cbz	x1, 8020d910 <__eucjp_wctomb+0x80>
    8020d8a0:	34000325 	cbz	w5, 8020d904 <__eucjp_wctomb+0x74>
    8020d8a4:	11017ca0 	add	w0, w5, #0x5f
    8020d8a8:	1101c8a6 	add	w6, w5, #0x72
    8020d8ac:	12001c00 	and	w0, w0, #0xff
    8020d8b0:	12001cc6 	and	w6, w6, #0xff
    8020d8b4:	7101741f 	cmp	w0, #0x5d
    8020d8b8:	7a4188c0 	ccmp	w6, #0x1, #0x0, hi	// hi = pmore
    8020d8bc:	54000368 	b.hi	8020d928 <__eucjp_wctomb+0x98>  // b.pmore
    8020d8c0:	11017c66 	add	w6, w3, #0x5f
    8020d8c4:	12001cc6 	and	w6, w6, #0xff
    8020d8c8:	710174df 	cmp	w6, #0x5d
    8020d8cc:	54000269 	b.ls	8020d918 <__eucjp_wctomb+0x88>  // b.plast
    8020d8d0:	7101741f 	cmp	w0, #0x5d
    8020d8d4:	540002a8 	b.hi	8020d928 <__eucjp_wctomb+0x98>  // b.pmore
    8020d8d8:	32190063 	orr	w3, w3, #0x80
    8020d8dc:	11017c60 	add	w0, w3, #0x5f
    8020d8e0:	12001c00 	and	w0, w0, #0xff
    8020d8e4:	7101741f 	cmp	w0, #0x5d
    8020d8e8:	54000208 	b.hi	8020d928 <__eucjp_wctomb+0x98>  // b.pmore
    8020d8ec:	12800e02 	mov	w2, #0xffffff8f            	// #-113
    8020d8f0:	52800060 	mov	w0, #0x3                   	// #3
    8020d8f4:	39000022 	strb	w2, [x1]
    8020d8f8:	39000425 	strb	w5, [x1, #1]
    8020d8fc:	39000823 	strb	w3, [x1, #2]
    8020d900:	d65f03c0 	ret
    8020d904:	52800020 	mov	w0, #0x1                   	// #1
    8020d908:	39000023 	strb	w3, [x1]
    8020d90c:	d65f03c0 	ret
    8020d910:	52800000 	mov	w0, #0x0                   	// #0
    8020d914:	d65f03c0 	ret
    8020d918:	5ac00442 	rev16	w2, w2
    8020d91c:	52800040 	mov	w0, #0x2                   	// #2
    8020d920:	79000022 	strh	w2, [x1]
    8020d924:	d65f03c0 	ret
    8020d928:	52801141 	mov	w1, #0x8a                  	// #138
    8020d92c:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020d930:	b9000081 	str	w1, [x4]
    8020d934:	d65f03c0 	ret
	...

000000008020d940 <__jis_wctomb>:
    8020d940:	aa0003e6 	mov	x6, x0
    8020d944:	12001c45 	and	w5, w2, #0xff
    8020d948:	d3483c44 	ubfx	x4, x2, #8, #8
    8020d94c:	b40004c1 	cbz	x1, 8020d9e4 <__jis_wctomb+0xa4>
    8020d950:	34000304 	cbz	w4, 8020d9b0 <__jis_wctomb+0x70>
    8020d954:	51008484 	sub	w4, w4, #0x21
    8020d958:	12001c84 	and	w4, w4, #0xff
    8020d95c:	7101749f 	cmp	w4, #0x5d
    8020d960:	54000468 	b.hi	8020d9ec <__jis_wctomb+0xac>  // b.pmore
    8020d964:	510084a5 	sub	w5, w5, #0x21
    8020d968:	12001ca5 	and	w5, w5, #0xff
    8020d96c:	710174bf 	cmp	w5, #0x5d
    8020d970:	540003e8 	b.hi	8020d9ec <__jis_wctomb+0xac>  // b.pmore
    8020d974:	b9400064 	ldr	w4, [x3]
    8020d978:	52800040 	mov	w0, #0x2                   	// #2
    8020d97c:	35000144 	cbnz	w4, 8020d9a4 <__jis_wctomb+0x64>
    8020d980:	aa0103e4 	mov	x4, x1
    8020d984:	52800020 	mov	w0, #0x1                   	// #1
    8020d988:	b9000060 	str	w0, [x3]
    8020d98c:	52848365 	mov	w5, #0x241b                	// #9243
    8020d990:	52800843 	mov	w3, #0x42                  	// #66
    8020d994:	528000a0 	mov	w0, #0x5                   	// #5
    8020d998:	78003485 	strh	w5, [x4], #3
    8020d99c:	39000823 	strb	w3, [x1, #2]
    8020d9a0:	aa0403e1 	mov	x1, x4
    8020d9a4:	5ac00442 	rev16	w2, w2
    8020d9a8:	79000022 	strh	w2, [x1]
    8020d9ac:	d65f03c0 	ret
    8020d9b0:	b9400062 	ldr	w2, [x3]
    8020d9b4:	52800020 	mov	w0, #0x1                   	// #1
    8020d9b8:	34000122 	cbz	w2, 8020d9dc <__jis_wctomb+0x9c>
    8020d9bc:	aa0103e2 	mov	x2, x1
    8020d9c0:	b900007f 	str	wzr, [x3]
    8020d9c4:	52850364 	mov	w4, #0x281b                	// #10267
    8020d9c8:	52800843 	mov	w3, #0x42                  	// #66
    8020d9cc:	52800080 	mov	w0, #0x4                   	// #4
    8020d9d0:	78003444 	strh	w4, [x2], #3
    8020d9d4:	39000823 	strb	w3, [x1, #2]
    8020d9d8:	aa0203e1 	mov	x1, x2
    8020d9dc:	39000025 	strb	w5, [x1]
    8020d9e0:	d65f03c0 	ret
    8020d9e4:	52800020 	mov	w0, #0x1                   	// #1
    8020d9e8:	d65f03c0 	ret
    8020d9ec:	52801141 	mov	w1, #0x8a                  	// #138
    8020d9f0:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020d9f4:	b90000c1 	str	w1, [x6]
    8020d9f8:	d65f03c0 	ret
    8020d9fc:	00000000 	udf	#0

000000008020da00 <_sbrk_r>:
    8020da00:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020da04:	910003fd 	mov	x29, sp
    8020da08:	a90153f3 	stp	x19, x20, [sp, #16]
    8020da0c:	f0000394 	adrp	x20, 80280000 <gits_lock>
    8020da10:	aa0003f3 	mov	x19, x0
    8020da14:	b9048a9f 	str	wzr, [x20, #1160]
    8020da18:	aa0103e0 	mov	x0, x1
    8020da1c:	97ffcbe2 	bl	802009a4 <_sbrk>
    8020da20:	b100041f 	cmn	x0, #0x1
    8020da24:	54000080 	b.eq	8020da34 <_sbrk_r+0x34>  // b.none
    8020da28:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020da2c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020da30:	d65f03c0 	ret
    8020da34:	b9448a81 	ldr	w1, [x20, #1160]
    8020da38:	34ffff81 	cbz	w1, 8020da28 <_sbrk_r+0x28>
    8020da3c:	b9000261 	str	w1, [x19]
    8020da40:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020da44:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020da48:	d65f03c0 	ret
	...

000000008020da80 <strncmp>:
    8020da80:	d503245f 	bti	c
    8020da84:	b4000d42 	cbz	x2, 8020dc2c <strncmp+0x1ac>
    8020da88:	ca010008 	eor	x8, x0, x1
    8020da8c:	b200c3eb 	mov	x11, #0x101010101010101     	// #72340172838076673
    8020da90:	f240091f 	tst	x8, #0x7
    8020da94:	9240080d 	and	x13, x0, #0x7
    8020da98:	540004c1 	b.ne	8020db30 <strncmp+0xb0>  // b.any
    8020da9c:	b500030d 	cbnz	x13, 8020dafc <strncmp+0x7c>
    8020daa0:	f8408403 	ldr	x3, [x0], #8
    8020daa4:	f8408424 	ldr	x4, [x1], #8
    8020daa8:	f1002042 	subs	x2, x2, #0x8
    8020daac:	cb0b0068 	sub	x8, x3, x11
    8020dab0:	b200d869 	orr	x9, x3, #0x7f7f7f7f7f7f7f7f
    8020dab4:	ca040066 	eor	x6, x3, x4
    8020dab8:	da9f80ce 	csinv	x14, x6, xzr, hi	// hi = pmore
    8020dabc:	ea290105 	bics	x5, x8, x9
    8020dac0:	fa4009c0 	ccmp	x14, #0x0, #0x0, eq	// eq = none
    8020dac4:	54fffee0 	b.eq	8020daa0 <strncmp+0x20>  // b.none
    8020dac8:	aa0500c7 	orr	x7, x6, x5
    8020dacc:	91002042 	add	x2, x2, #0x8
    8020dad0:	dac00ce7 	rev	x7, x7
    8020dad4:	dac00c63 	rev	x3, x3
    8020dad8:	dac010ec 	clz	x12, x7
    8020dadc:	dac00c84 	rev	x4, x4
    8020dae0:	9acc2063 	lsl	x3, x3, x12
    8020dae4:	eb4c0c5f 	cmp	x2, x12, lsr #3
    8020dae8:	9acc2084 	lsl	x4, x4, x12
    8020daec:	d378fc63 	lsr	x3, x3, #56
    8020daf0:	cb44e060 	sub	x0, x3, x4, lsr #56
    8020daf4:	9a9f8000 	csel	x0, x0, xzr, hi	// hi = pmore
    8020daf8:	d65f03c0 	ret
    8020dafc:	927df000 	and	x0, x0, #0xfffffffffffffff8
    8020db00:	927df021 	and	x1, x1, #0xfffffffffffffff8
    8020db04:	f8408403 	ldr	x3, [x0], #8
    8020db08:	cb0d0fea 	neg	x10, x13, lsl #3
    8020db0c:	f8408424 	ldr	x4, [x1], #8
    8020db10:	92800009 	mov	x9, #0xffffffffffffffff    	// #-1
    8020db14:	9aca2529 	lsr	x9, x9, x10
    8020db18:	ab0d0042 	adds	x2, x2, x13
    8020db1c:	da9f3042 	csinv	x2, x2, xzr, cc	// cc = lo, ul, last
    8020db20:	aa090063 	orr	x3, x3, x9
    8020db24:	aa090084 	orr	x4, x4, x9
    8020db28:	17ffffe0 	b	8020daa8 <strncmp+0x28>
    8020db2c:	d503201f 	nop
    8020db30:	f100405f 	cmp	x2, #0x10
    8020db34:	54000122 	b.cs	8020db58 <strncmp+0xd8>  // b.hs, b.nlast
    8020db38:	38401403 	ldrb	w3, [x0], #1
    8020db3c:	38401424 	ldrb	w4, [x1], #1
    8020db40:	f1000442 	subs	x2, x2, #0x1
    8020db44:	7a418860 	ccmp	w3, #0x1, #0x0, hi	// hi = pmore
    8020db48:	7a442060 	ccmp	w3, w4, #0x0, cs	// cs = hs, nlast
    8020db4c:	54ffff60 	b.eq	8020db38 <strncmp+0xb8>  // b.none
    8020db50:	cb040060 	sub	x0, x3, x4
    8020db54:	d65f03c0 	ret
    8020db58:	b400016d 	cbz	x13, 8020db84 <strncmp+0x104>
    8020db5c:	cb0d03ed 	neg	x13, x13
    8020db60:	924009ad 	and	x13, x13, #0x7
    8020db64:	cb0d0042 	sub	x2, x2, x13
    8020db68:	38401403 	ldrb	w3, [x0], #1
    8020db6c:	38401424 	ldrb	w4, [x1], #1
    8020db70:	7100047f 	cmp	w3, #0x1
    8020db74:	7a442060 	ccmp	w3, w4, #0x0, cs	// cs = hs, nlast
    8020db78:	54fffec1 	b.ne	8020db50 <strncmp+0xd0>  // b.any
    8020db7c:	f10005ad 	subs	x13, x13, #0x1
    8020db80:	54ffff48 	b.hi	8020db68 <strncmp+0xe8>  // b.pmore
    8020db84:	d37df02c 	lsl	x12, x1, #3
    8020db88:	927cec21 	and	x1, x1, #0xfffffffffffffff0
    8020db8c:	9280000d 	mov	x13, #0xffffffffffffffff    	// #-1
    8020db90:	cb0c03ef 	neg	x15, x12
    8020db94:	f8408403 	ldr	x3, [x0], #8
    8020db98:	a8c12428 	ldp	x8, x9, [x1], #16
    8020db9c:	9acf21ad 	lsl	x13, x13, x15
    8020dba0:	924015ef 	and	x15, x15, #0x3f
    8020dba4:	373001ac 	tbnz	w12, #6, 8020dbd8 <strncmp+0x158>
    8020dba8:	9acc2504 	lsr	x4, x8, x12
    8020dbac:	9acf2128 	lsl	x8, x9, x15
    8020dbb0:	f1002042 	subs	x2, x2, #0x8
    8020dbb4:	aa080084 	orr	x4, x4, x8
    8020dbb8:	cb0b0065 	sub	x5, x3, x11
    8020dbbc:	ca040066 	eor	x6, x3, x4
    8020dbc0:	b200d86a 	orr	x10, x3, #0x7f7f7f7f7f7f7f7f
    8020dbc4:	da9f80ce 	csinv	x14, x6, xzr, hi	// hi = pmore
    8020dbc8:	8a2a00a5 	bic	x5, x5, x10
    8020dbcc:	aa0501ca 	orr	x10, x14, x5
    8020dbd0:	b5fff7ca 	cbnz	x10, 8020dac8 <strncmp+0x48>
    8020dbd4:	f8408403 	ldr	x3, [x0], #8
    8020dbd8:	9acc2524 	lsr	x4, x9, x12
    8020dbdc:	cb0b0065 	sub	x5, x3, x11
    8020dbe0:	b200d86a 	orr	x10, x3, #0x7f7f7f7f7f7f7f7f
    8020dbe4:	ca030086 	eor	x6, x4, x3
    8020dbe8:	8a2a00a5 	bic	x5, x5, x10
    8020dbec:	eb4f0c5f 	cmp	x2, x15, lsr #3
    8020dbf0:	aa0500c7 	orr	x7, x6, x5
    8020dbf4:	8a2d00e7 	bic	x7, x7, x13
    8020dbf8:	da9f80ea 	csinv	x10, x7, xzr, hi	// hi = pmore
    8020dbfc:	b5fff6aa 	cbnz	x10, 8020dad0 <strncmp+0x50>
    8020dc00:	a8c12428 	ldp	x8, x9, [x1], #16
    8020dc04:	f100205f 	cmp	x2, #0x8
    8020dc08:	9acf2104 	lsl	x4, x8, x15
    8020dc0c:	ca030086 	eor	x6, x4, x3
    8020dc10:	aa0500c7 	orr	x7, x6, x5
    8020dc14:	8a0d00e7 	and	x7, x7, x13
    8020dc18:	da9f80ea 	csinv	x10, x7, xzr, hi	// hi = pmore
    8020dc1c:	b5fff5aa 	cbnz	x10, 8020dad0 <strncmp+0x50>
    8020dc20:	f8408403 	ldr	x3, [x0], #8
    8020dc24:	d1002042 	sub	x2, x2, #0x8
    8020dc28:	17ffffe0 	b	8020dba8 <strncmp+0x128>
    8020dc2c:	d2800000 	mov	x0, #0x0                   	// #0
    8020dc30:	d65f03c0 	ret
	...

000000008020dc40 <__swbuf_r>:
    8020dc40:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020dc44:	910003fd 	mov	x29, sp
    8020dc48:	a90153f3 	stp	x19, x20, [sp, #16]
    8020dc4c:	2a0103f4 	mov	w20, w1
    8020dc50:	aa0203f3 	mov	x19, x2
    8020dc54:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020dc58:	aa0003f5 	mov	x21, x0
    8020dc5c:	b4000060 	cbz	x0, 8020dc68 <__swbuf_r+0x28>
    8020dc60:	f9402401 	ldr	x1, [x0, #72]
    8020dc64:	b4000861 	cbz	x1, 8020dd70 <__swbuf_r+0x130>
    8020dc68:	79c02260 	ldrsh	w0, [x19, #16]
    8020dc6c:	b9402a61 	ldr	w1, [x19, #40]
    8020dc70:	b9000e61 	str	w1, [x19, #12]
    8020dc74:	361803e0 	tbz	w0, #3, 8020dcf0 <__swbuf_r+0xb0>
    8020dc78:	f9400e61 	ldr	x1, [x19, #24]
    8020dc7c:	b40003a1 	cbz	x1, 8020dcf0 <__swbuf_r+0xb0>
    8020dc80:	12001e96 	and	w22, w20, #0xff
    8020dc84:	12001e94 	and	w20, w20, #0xff
    8020dc88:	36680460 	tbz	w0, #13, 8020dd14 <__swbuf_r+0xd4>
    8020dc8c:	f9400260 	ldr	x0, [x19]
    8020dc90:	b9402262 	ldr	w2, [x19, #32]
    8020dc94:	cb010001 	sub	x1, x0, x1
    8020dc98:	6b01005f 	cmp	w2, w1
    8020dc9c:	5400050d 	b.le	8020dd3c <__swbuf_r+0xfc>
    8020dca0:	11000421 	add	w1, w1, #0x1
    8020dca4:	b9400e62 	ldr	w2, [x19, #12]
    8020dca8:	91000403 	add	x3, x0, #0x1
    8020dcac:	f9000263 	str	x3, [x19]
    8020dcb0:	51000442 	sub	w2, w2, #0x1
    8020dcb4:	b9000e62 	str	w2, [x19, #12]
    8020dcb8:	39000016 	strb	w22, [x0]
    8020dcbc:	b9402260 	ldr	w0, [x19, #32]
    8020dcc0:	6b01001f 	cmp	w0, w1
    8020dcc4:	540004a0 	b.eq	8020dd58 <__swbuf_r+0x118>  // b.none
    8020dcc8:	71002a9f 	cmp	w20, #0xa
    8020dccc:	79402260 	ldrh	w0, [x19, #16]
    8020dcd0:	1a9f17e1 	cset	w1, eq	// eq = none
    8020dcd4:	6a00003f 	tst	w1, w0
    8020dcd8:	54000401 	b.ne	8020dd58 <__swbuf_r+0x118>  // b.any
    8020dcdc:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020dce0:	2a1403e0 	mov	w0, w20
    8020dce4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020dce8:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020dcec:	d65f03c0 	ret
    8020dcf0:	aa1303e1 	mov	x1, x19
    8020dcf4:	aa1503e0 	mov	x0, x21
    8020dcf8:	97fff19a 	bl	8020a360 <__swsetup_r>
    8020dcfc:	35000360 	cbnz	w0, 8020dd68 <__swbuf_r+0x128>
    8020dd00:	79c02260 	ldrsh	w0, [x19, #16]
    8020dd04:	12001e96 	and	w22, w20, #0xff
    8020dd08:	f9400e61 	ldr	x1, [x19, #24]
    8020dd0c:	12001e94 	and	w20, w20, #0xff
    8020dd10:	376ffbe0 	tbnz	w0, #13, 8020dc8c <__swbuf_r+0x4c>
    8020dd14:	b940b262 	ldr	w2, [x19, #176]
    8020dd18:	32130000 	orr	w0, w0, #0x2000
    8020dd1c:	79002260 	strh	w0, [x19, #16]
    8020dd20:	12127840 	and	w0, w2, #0xffffdfff
    8020dd24:	b900b260 	str	w0, [x19, #176]
    8020dd28:	f9400260 	ldr	x0, [x19]
    8020dd2c:	b9402262 	ldr	w2, [x19, #32]
    8020dd30:	cb010001 	sub	x1, x0, x1
    8020dd34:	6b01005f 	cmp	w2, w1
    8020dd38:	54fffb4c 	b.gt	8020dca0 <__swbuf_r+0x60>
    8020dd3c:	aa1303e1 	mov	x1, x19
    8020dd40:	aa1503e0 	mov	x0, x21
    8020dd44:	97fff88b 	bl	8020bf70 <_fflush_r>
    8020dd48:	35000100 	cbnz	w0, 8020dd68 <__swbuf_r+0x128>
    8020dd4c:	f9400260 	ldr	x0, [x19]
    8020dd50:	52800021 	mov	w1, #0x1                   	// #1
    8020dd54:	17ffffd4 	b	8020dca4 <__swbuf_r+0x64>
    8020dd58:	aa1303e1 	mov	x1, x19
    8020dd5c:	aa1503e0 	mov	x0, x21
    8020dd60:	97fff884 	bl	8020bf70 <_fflush_r>
    8020dd64:	34fffbc0 	cbz	w0, 8020dcdc <__swbuf_r+0x9c>
    8020dd68:	12800014 	mov	w20, #0xffffffff            	// #-1
    8020dd6c:	17ffffdc 	b	8020dcdc <__swbuf_r+0x9c>
    8020dd70:	97ffd418 	bl	80202dd0 <__sinit>
    8020dd74:	17ffffbd 	b	8020dc68 <__swbuf_r+0x28>
	...

000000008020dd80 <__swbuf>:
    8020dd80:	90000023 	adrp	x3, 80211000 <__mprec_tens+0x180>
    8020dd84:	aa0103e2 	mov	x2, x1
    8020dd88:	2a0003e1 	mov	w1, w0
    8020dd8c:	f9402460 	ldr	x0, [x3, #72]
    8020dd90:	17ffffac 	b	8020dc40 <__swbuf_r>
	...

000000008020dda0 <_mbtowc_r>:
    8020dda0:	90000025 	adrp	x5, 80211000 <__mprec_tens+0x180>
    8020dda4:	f945dca5 	ldr	x5, [x5, #3000]
    8020dda8:	aa0503f0 	mov	x16, x5
    8020ddac:	d61f0200 	br	x16

000000008020ddb0 <__ascii_mbtowc>:
    8020ddb0:	d10043ff 	sub	sp, sp, #0x10
    8020ddb4:	f100003f 	cmp	x1, #0x0
    8020ddb8:	910033e0 	add	x0, sp, #0xc
    8020ddbc:	9a810001 	csel	x1, x0, x1, eq	// eq = none
    8020ddc0:	b4000122 	cbz	x2, 8020dde4 <__ascii_mbtowc+0x34>
    8020ddc4:	b4000163 	cbz	x3, 8020ddf0 <__ascii_mbtowc+0x40>
    8020ddc8:	39400040 	ldrb	w0, [x2]
    8020ddcc:	b9000020 	str	w0, [x1]
    8020ddd0:	39400040 	ldrb	w0, [x2]
    8020ddd4:	7100001f 	cmp	w0, #0x0
    8020ddd8:	1a9f07e0 	cset	w0, ne	// ne = any
    8020dddc:	910043ff 	add	sp, sp, #0x10
    8020dde0:	d65f03c0 	ret
    8020dde4:	52800000 	mov	w0, #0x0                   	// #0
    8020dde8:	910043ff 	add	sp, sp, #0x10
    8020ddec:	d65f03c0 	ret
    8020ddf0:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020ddf4:	17fffffa 	b	8020dddc <__ascii_mbtowc+0x2c>
	...

000000008020de00 <__utf8_mbtowc>:
    8020de00:	d10043ff 	sub	sp, sp, #0x10
    8020de04:	f100003f 	cmp	x1, #0x0
    8020de08:	910033e5 	add	x5, sp, #0xc
    8020de0c:	9a8100a1 	csel	x1, x5, x1, eq	// eq = none
    8020de10:	b40004c2 	cbz	x2, 8020dea8 <__utf8_mbtowc+0xa8>
    8020de14:	b4001223 	cbz	x3, 8020e058 <__utf8_mbtowc+0x258>
    8020de18:	b9400087 	ldr	w7, [x4]
    8020de1c:	aa0003e9 	mov	x9, x0
    8020de20:	350003a7 	cbnz	w7, 8020de94 <__utf8_mbtowc+0x94>
    8020de24:	39400045 	ldrb	w5, [x2]
    8020de28:	52800026 	mov	w6, #0x1                   	// #1
    8020de2c:	340003a5 	cbz	w5, 8020dea0 <__utf8_mbtowc+0xa0>
    8020de30:	7101fcbf 	cmp	w5, #0x7f
    8020de34:	5400082d 	b.le	8020df38 <__utf8_mbtowc+0x138>
    8020de38:	510300a8 	sub	w8, w5, #0xc0
    8020de3c:	71007d1f 	cmp	w8, #0x1f
    8020de40:	540003a8 	b.hi	8020deb4 <__utf8_mbtowc+0xb4>  // b.pmore
    8020de44:	39001085 	strb	w5, [x4, #4]
    8020de48:	350000a7 	cbnz	w7, 8020de5c <__utf8_mbtowc+0x5c>
    8020de4c:	52800020 	mov	w0, #0x1                   	// #1
    8020de50:	b9000080 	str	w0, [x4]
    8020de54:	f100047f 	cmp	x3, #0x1
    8020de58:	54001000 	b.eq	8020e058 <__utf8_mbtowc+0x258>  // b.none
    8020de5c:	3866c842 	ldrb	w2, [x2, w6, sxtw]
    8020de60:	110004c0 	add	w0, w6, #0x1
    8020de64:	51020043 	sub	w3, w2, #0x80
    8020de68:	7100fc7f 	cmp	w3, #0x3f
    8020de6c:	54000fe8 	b.hi	8020e068 <__utf8_mbtowc+0x268>  // b.pmore
    8020de70:	710304bf 	cmp	w5, #0xc1
    8020de74:	54000fad 	b.le	8020e068 <__utf8_mbtowc+0x268>
    8020de78:	12001442 	and	w2, w2, #0x3f
    8020de7c:	531a10a5 	ubfiz	w5, w5, #6, #5
    8020de80:	b900009f 	str	wzr, [x4]
    8020de84:	2a0200a5 	orr	w5, w5, w2
    8020de88:	b9000025 	str	w5, [x1]
    8020de8c:	910043ff 	add	sp, sp, #0x10
    8020de90:	d65f03c0 	ret
    8020de94:	39401085 	ldrb	w5, [x4, #4]
    8020de98:	52800006 	mov	w6, #0x0                   	// #0
    8020de9c:	35fffca5 	cbnz	w5, 8020de30 <__utf8_mbtowc+0x30>
    8020dea0:	b900003f 	str	wzr, [x1]
    8020dea4:	b900009f 	str	wzr, [x4]
    8020dea8:	52800000 	mov	w0, #0x0                   	// #0
    8020deac:	910043ff 	add	sp, sp, #0x10
    8020deb0:	d65f03c0 	ret
    8020deb4:	510380a0 	sub	w0, w5, #0xe0
    8020deb8:	71003c1f 	cmp	w0, #0xf
    8020debc:	54000488 	b.hi	8020df4c <__utf8_mbtowc+0x14c>  // b.pmore
    8020dec0:	39001085 	strb	w5, [x4, #4]
    8020dec4:	34000a07 	cbz	w7, 8020e004 <__utf8_mbtowc+0x204>
    8020dec8:	b100047f 	cmn	x3, #0x1
    8020decc:	9a830463 	cinc	x3, x3, ne	// ne = any
    8020ded0:	710004ff 	cmp	w7, #0x1
    8020ded4:	54000a00 	b.eq	8020e014 <__utf8_mbtowc+0x214>  // b.none
    8020ded8:	39401488 	ldrb	w8, [x4, #5]
    8020dedc:	71027d1f 	cmp	w8, #0x9f
    8020dee0:	52801c00 	mov	w0, #0xe0                  	// #224
    8020dee4:	7a40d0a0 	ccmp	w5, w0, #0x0, le
    8020dee8:	54000c00 	b.eq	8020e068 <__utf8_mbtowc+0x268>  // b.none
    8020deec:	51020100 	sub	w0, w8, #0x80
    8020def0:	7100fc1f 	cmp	w0, #0x3f
    8020def4:	54000ba8 	b.hi	8020e068 <__utf8_mbtowc+0x268>  // b.pmore
    8020def8:	39001488 	strb	w8, [x4, #5]
    8020defc:	710004ff 	cmp	w7, #0x1
    8020df00:	54000a20 	b.eq	8020e044 <__utf8_mbtowc+0x244>  // b.none
    8020df04:	3866c843 	ldrb	w3, [x2, w6, sxtw]
    8020df08:	110004c0 	add	w0, w6, #0x1
    8020df0c:	51020062 	sub	w2, w3, #0x80
    8020df10:	7100fc5f 	cmp	w2, #0x3f
    8020df14:	54000aa8 	b.hi	8020e068 <__utf8_mbtowc+0x268>  // b.pmore
    8020df18:	53140ca2 	ubfiz	w2, w5, #12, #4
    8020df1c:	531a1508 	ubfiz	w8, w8, #6, #6
    8020df20:	2a080042 	orr	w2, w2, w8
    8020df24:	12001463 	and	w3, w3, #0x3f
    8020df28:	b900009f 	str	wzr, [x4]
    8020df2c:	2a030042 	orr	w2, w2, w3
    8020df30:	b9000022 	str	w2, [x1]
    8020df34:	17ffffde 	b	8020deac <__utf8_mbtowc+0xac>
    8020df38:	b900009f 	str	wzr, [x4]
    8020df3c:	52800020 	mov	w0, #0x1                   	// #1
    8020df40:	b9000025 	str	w5, [x1]
    8020df44:	910043ff 	add	sp, sp, #0x10
    8020df48:	d65f03c0 	ret
    8020df4c:	5103c0a0 	sub	w0, w5, #0xf0
    8020df50:	7100101f 	cmp	w0, #0x4
    8020df54:	540008a8 	b.hi	8020e068 <__utf8_mbtowc+0x268>  // b.pmore
    8020df58:	39001085 	strb	w5, [x4, #4]
    8020df5c:	34000647 	cbz	w7, 8020e024 <__utf8_mbtowc+0x224>
    8020df60:	b100047f 	cmn	x3, #0x1
    8020df64:	9a830463 	cinc	x3, x3, ne	// ne = any
    8020df68:	710004ff 	cmp	w7, #0x1
    8020df6c:	54000640 	b.eq	8020e034 <__utf8_mbtowc+0x234>  // b.none
    8020df70:	39401488 	ldrb	w8, [x4, #5]
    8020df74:	7103c0bf 	cmp	w5, #0xf0
    8020df78:	54000740 	b.eq	8020e060 <__utf8_mbtowc+0x260>  // b.none
    8020df7c:	71023d1f 	cmp	w8, #0x8f
    8020df80:	52801e80 	mov	w0, #0xf4                  	// #244
    8020df84:	7a40c0a0 	ccmp	w5, w0, #0x0, gt
    8020df88:	54000700 	b.eq	8020e068 <__utf8_mbtowc+0x268>  // b.none
    8020df8c:	51020100 	sub	w0, w8, #0x80
    8020df90:	7100fc1f 	cmp	w0, #0x3f
    8020df94:	540006a8 	b.hi	8020e068 <__utf8_mbtowc+0x268>  // b.pmore
    8020df98:	39001488 	strb	w8, [x4, #5]
    8020df9c:	710004ff 	cmp	w7, #0x1
    8020dfa0:	540006c0 	b.eq	8020e078 <__utf8_mbtowc+0x278>  // b.none
    8020dfa4:	b9400080 	ldr	w0, [x4]
    8020dfa8:	b100047f 	cmn	x3, #0x1
    8020dfac:	9a830463 	cinc	x3, x3, ne	// ne = any
    8020dfb0:	7100081f 	cmp	w0, #0x2
    8020dfb4:	540006a0 	b.eq	8020e088 <__utf8_mbtowc+0x288>  // b.none
    8020dfb8:	39401887 	ldrb	w7, [x4, #6]
    8020dfbc:	510200e0 	sub	w0, w7, #0x80
    8020dfc0:	7100fc1f 	cmp	w0, #0x3f
    8020dfc4:	54000528 	b.hi	8020e068 <__utf8_mbtowc+0x268>  // b.pmore
    8020dfc8:	3866c843 	ldrb	w3, [x2, w6, sxtw]
    8020dfcc:	110004c0 	add	w0, w6, #0x1
    8020dfd0:	51020062 	sub	w2, w3, #0x80
    8020dfd4:	7100fc5f 	cmp	w2, #0x3f
    8020dfd8:	54000488 	b.hi	8020e068 <__utf8_mbtowc+0x268>  // b.pmore
    8020dfdc:	530e08a2 	ubfiz	w2, w5, #18, #3
    8020dfe0:	53141508 	ubfiz	w8, w8, #12, #6
    8020dfe4:	531a14e7 	ubfiz	w7, w7, #6, #6
    8020dfe8:	12001463 	and	w3, w3, #0x3f
    8020dfec:	2a080042 	orr	w2, w2, w8
    8020dff0:	2a0300e7 	orr	w7, w7, w3
    8020dff4:	2a070042 	orr	w2, w2, w7
    8020dff8:	b9000022 	str	w2, [x1]
    8020dffc:	b900009f 	str	wzr, [x4]
    8020e000:	17ffffab 	b	8020deac <__utf8_mbtowc+0xac>
    8020e004:	52800020 	mov	w0, #0x1                   	// #1
    8020e008:	b9000080 	str	w0, [x4]
    8020e00c:	f100047f 	cmp	x3, #0x1
    8020e010:	54000240 	b.eq	8020e058 <__utf8_mbtowc+0x258>  // b.none
    8020e014:	3866c848 	ldrb	w8, [x2, w6, sxtw]
    8020e018:	52800027 	mov	w7, #0x1                   	// #1
    8020e01c:	0b0700c6 	add	w6, w6, w7
    8020e020:	17ffffaf 	b	8020dedc <__utf8_mbtowc+0xdc>
    8020e024:	52800020 	mov	w0, #0x1                   	// #1
    8020e028:	b9000080 	str	w0, [x4]
    8020e02c:	f100047f 	cmp	x3, #0x1
    8020e030:	54000140 	b.eq	8020e058 <__utf8_mbtowc+0x258>  // b.none
    8020e034:	3866c848 	ldrb	w8, [x2, w6, sxtw]
    8020e038:	52800027 	mov	w7, #0x1                   	// #1
    8020e03c:	0b0700c6 	add	w6, w6, w7
    8020e040:	17ffffcd 	b	8020df74 <__utf8_mbtowc+0x174>
    8020e044:	52800040 	mov	w0, #0x2                   	// #2
    8020e048:	b9000080 	str	w0, [x4]
    8020e04c:	f100087f 	cmp	x3, #0x2
    8020e050:	54fff5a1 	b.ne	8020df04 <__utf8_mbtowc+0x104>  // b.any
    8020e054:	d503201f 	nop
    8020e058:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020e05c:	17ffff94 	b	8020deac <__utf8_mbtowc+0xac>
    8020e060:	71023d1f 	cmp	w8, #0x8f
    8020e064:	54fff94c 	b.gt	8020df8c <__utf8_mbtowc+0x18c>
    8020e068:	52801141 	mov	w1, #0x8a                  	// #138
    8020e06c:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020e070:	b9000121 	str	w1, [x9]
    8020e074:	17ffff8e 	b	8020deac <__utf8_mbtowc+0xac>
    8020e078:	52800040 	mov	w0, #0x2                   	// #2
    8020e07c:	b9000080 	str	w0, [x4]
    8020e080:	f100087f 	cmp	x3, #0x2
    8020e084:	54fffea0 	b.eq	8020e058 <__utf8_mbtowc+0x258>  // b.none
    8020e088:	3866c847 	ldrb	w7, [x2, w6, sxtw]
    8020e08c:	110004c6 	add	w6, w6, #0x1
    8020e090:	510200e0 	sub	w0, w7, #0x80
    8020e094:	7100fc1f 	cmp	w0, #0x3f
    8020e098:	54fffe88 	b.hi	8020e068 <__utf8_mbtowc+0x268>  // b.pmore
    8020e09c:	52800060 	mov	w0, #0x3                   	// #3
    8020e0a0:	b9000080 	str	w0, [x4]
    8020e0a4:	39001887 	strb	w7, [x4, #6]
    8020e0a8:	f1000c7f 	cmp	x3, #0x3
    8020e0ac:	54fff8e1 	b.ne	8020dfc8 <__utf8_mbtowc+0x1c8>  // b.any
    8020e0b0:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020e0b4:	17ffff7e 	b	8020deac <__utf8_mbtowc+0xac>
	...

000000008020e0c0 <__sjis_mbtowc>:
    8020e0c0:	d10043ff 	sub	sp, sp, #0x10
    8020e0c4:	f100003f 	cmp	x1, #0x0
    8020e0c8:	910033e5 	add	x5, sp, #0xc
    8020e0cc:	9a8100a1 	csel	x1, x5, x1, eq	// eq = none
    8020e0d0:	b40004c2 	cbz	x2, 8020e168 <__sjis_mbtowc+0xa8>
    8020e0d4:	b4000503 	cbz	x3, 8020e174 <__sjis_mbtowc+0xb4>
    8020e0d8:	aa0003e6 	mov	x6, x0
    8020e0dc:	b9400080 	ldr	w0, [x4]
    8020e0e0:	39400045 	ldrb	w5, [x2]
    8020e0e4:	35000320 	cbnz	w0, 8020e148 <__sjis_mbtowc+0x88>
    8020e0e8:	510204a7 	sub	w7, w5, #0x81
    8020e0ec:	510380a0 	sub	w0, w5, #0xe0
    8020e0f0:	710078ff 	cmp	w7, #0x1e
    8020e0f4:	7a4f8800 	ccmp	w0, #0xf, #0x0, hi	// hi = pmore
    8020e0f8:	540002c8 	b.hi	8020e150 <__sjis_mbtowc+0x90>  // b.pmore
    8020e0fc:	52800020 	mov	w0, #0x1                   	// #1
    8020e100:	b9000080 	str	w0, [x4]
    8020e104:	39001085 	strb	w5, [x4, #4]
    8020e108:	f100047f 	cmp	x3, #0x1
    8020e10c:	54000340 	b.eq	8020e174 <__sjis_mbtowc+0xb4>  // b.none
    8020e110:	39400445 	ldrb	w5, [x2, #1]
    8020e114:	52800040 	mov	w0, #0x2                   	// #2
    8020e118:	510100a3 	sub	w3, w5, #0x40
    8020e11c:	510200a2 	sub	w2, w5, #0x80
    8020e120:	7100f87f 	cmp	w3, #0x3e
    8020e124:	52800f83 	mov	w3, #0x7c                  	// #124
    8020e128:	7a438040 	ccmp	w2, w3, #0x0, hi	// hi = pmore
    8020e12c:	54000288 	b.hi	8020e17c <__sjis_mbtowc+0xbc>  // b.pmore
    8020e130:	39401082 	ldrb	w2, [x4, #4]
    8020e134:	0b0220a2 	add	w2, w5, w2, lsl #8
    8020e138:	b9000022 	str	w2, [x1]
    8020e13c:	b900009f 	str	wzr, [x4]
    8020e140:	910043ff 	add	sp, sp, #0x10
    8020e144:	d65f03c0 	ret
    8020e148:	7100041f 	cmp	w0, #0x1
    8020e14c:	54fffe60 	b.eq	8020e118 <__sjis_mbtowc+0x58>  // b.none
    8020e150:	b9000025 	str	w5, [x1]
    8020e154:	39400040 	ldrb	w0, [x2]
    8020e158:	7100001f 	cmp	w0, #0x0
    8020e15c:	1a9f07e0 	cset	w0, ne	// ne = any
    8020e160:	910043ff 	add	sp, sp, #0x10
    8020e164:	d65f03c0 	ret
    8020e168:	52800000 	mov	w0, #0x0                   	// #0
    8020e16c:	910043ff 	add	sp, sp, #0x10
    8020e170:	d65f03c0 	ret
    8020e174:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020e178:	17fffffa 	b	8020e160 <__sjis_mbtowc+0xa0>
    8020e17c:	52801141 	mov	w1, #0x8a                  	// #138
    8020e180:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020e184:	b90000c1 	str	w1, [x6]
    8020e188:	17fffff6 	b	8020e160 <__sjis_mbtowc+0xa0>
    8020e18c:	00000000 	udf	#0

000000008020e190 <__eucjp_mbtowc>:
    8020e190:	d10043ff 	sub	sp, sp, #0x10
    8020e194:	f100003f 	cmp	x1, #0x0
    8020e198:	910033e6 	add	x6, sp, #0xc
    8020e19c:	9a8100c1 	csel	x1, x6, x1, eq	// eq = none
    8020e1a0:	b4000782 	cbz	x2, 8020e290 <__eucjp_mbtowc+0x100>
    8020e1a4:	b40007c3 	cbz	x3, 8020e29c <__eucjp_mbtowc+0x10c>
    8020e1a8:	aa0003e5 	mov	x5, x0
    8020e1ac:	b9400080 	ldr	w0, [x4]
    8020e1b0:	39400046 	ldrb	w6, [x2]
    8020e1b4:	35000380 	cbnz	w0, 8020e224 <__eucjp_mbtowc+0x94>
    8020e1b8:	510284c7 	sub	w7, w6, #0xa1
    8020e1bc:	510238c0 	sub	w0, w6, #0x8e
    8020e1c0:	710174ff 	cmp	w7, #0x5d
    8020e1c4:	7a418800 	ccmp	w0, #0x1, #0x0, hi	// hi = pmore
    8020e1c8:	54000388 	b.hi	8020e238 <__eucjp_mbtowc+0xa8>  // b.pmore
    8020e1cc:	52800020 	mov	w0, #0x1                   	// #1
    8020e1d0:	b9000080 	str	w0, [x4]
    8020e1d4:	39001086 	strb	w6, [x4, #4]
    8020e1d8:	f100047f 	cmp	x3, #0x1
    8020e1dc:	54000600 	b.eq	8020e29c <__eucjp_mbtowc+0x10c>  // b.none
    8020e1e0:	39400447 	ldrb	w7, [x2, #1]
    8020e1e4:	52800040 	mov	w0, #0x2                   	// #2
    8020e1e8:	510284e6 	sub	w6, w7, #0xa1
    8020e1ec:	710174df 	cmp	w6, #0x5d
    8020e1f0:	540005a8 	b.hi	8020e2a4 <__eucjp_mbtowc+0x114>  // b.pmore
    8020e1f4:	39401086 	ldrb	w6, [x4, #4]
    8020e1f8:	71023cdf 	cmp	w6, #0x8f
    8020e1fc:	54000401 	b.ne	8020e27c <__eucjp_mbtowc+0xec>  // b.any
    8020e200:	52800048 	mov	w8, #0x2                   	// #2
    8020e204:	93407c06 	sxtw	x6, w0
    8020e208:	b9000088 	str	w8, [x4]
    8020e20c:	39001487 	strb	w7, [x4, #5]
    8020e210:	eb0300df 	cmp	x6, x3
    8020e214:	54000442 	b.cs	8020e29c <__eucjp_mbtowc+0x10c>  // b.hs, b.nlast
    8020e218:	38666847 	ldrb	w7, [x2, x6]
    8020e21c:	11000400 	add	w0, w0, #0x1
    8020e220:	1400000d 	b	8020e254 <__eucjp_mbtowc+0xc4>
    8020e224:	2a0603e7 	mov	w7, w6
    8020e228:	7100041f 	cmp	w0, #0x1
    8020e22c:	54fffde0 	b.eq	8020e1e8 <__eucjp_mbtowc+0x58>  // b.none
    8020e230:	7100081f 	cmp	w0, #0x2
    8020e234:	540000e0 	b.eq	8020e250 <__eucjp_mbtowc+0xc0>  // b.none
    8020e238:	b9000026 	str	w6, [x1]
    8020e23c:	39400040 	ldrb	w0, [x2]
    8020e240:	7100001f 	cmp	w0, #0x0
    8020e244:	1a9f07e0 	cset	w0, ne	// ne = any
    8020e248:	910043ff 	add	sp, sp, #0x10
    8020e24c:	d65f03c0 	ret
    8020e250:	52800020 	mov	w0, #0x1                   	// #1
    8020e254:	510284e2 	sub	w2, w7, #0xa1
    8020e258:	7101745f 	cmp	w2, #0x5d
    8020e25c:	54000248 	b.hi	8020e2a4 <__eucjp_mbtowc+0x114>  // b.pmore
    8020e260:	39401482 	ldrb	w2, [x4, #5]
    8020e264:	120018e7 	and	w7, w7, #0x7f
    8020e268:	0b0220e2 	add	w2, w7, w2, lsl #8
    8020e26c:	b9000022 	str	w2, [x1]
    8020e270:	b900009f 	str	wzr, [x4]
    8020e274:	910043ff 	add	sp, sp, #0x10
    8020e278:	d65f03c0 	ret
    8020e27c:	0b0620e6 	add	w6, w7, w6, lsl #8
    8020e280:	b9000026 	str	w6, [x1]
    8020e284:	b900009f 	str	wzr, [x4]
    8020e288:	910043ff 	add	sp, sp, #0x10
    8020e28c:	d65f03c0 	ret
    8020e290:	52800000 	mov	w0, #0x0                   	// #0
    8020e294:	910043ff 	add	sp, sp, #0x10
    8020e298:	d65f03c0 	ret
    8020e29c:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020e2a0:	17ffffea 	b	8020e248 <__eucjp_mbtowc+0xb8>
    8020e2a4:	52801141 	mov	w1, #0x8a                  	// #138
    8020e2a8:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020e2ac:	b90000a1 	str	w1, [x5]
    8020e2b0:	17ffffe6 	b	8020e248 <__eucjp_mbtowc+0xb8>
	...

000000008020e2c0 <__jis_mbtowc>:
    8020e2c0:	d10043ff 	sub	sp, sp, #0x10
    8020e2c4:	f100003f 	cmp	x1, #0x0
    8020e2c8:	910033e5 	add	x5, sp, #0xc
    8020e2cc:	9a8100a1 	csel	x1, x5, x1, eq	// eq = none
    8020e2d0:	b4000cc2 	cbz	x2, 8020e468 <__jis_mbtowc+0x1a8>
    8020e2d4:	b40008c3 	cbz	x3, 8020e3ec <__jis_mbtowc+0x12c>
    8020e2d8:	39400085 	ldrb	w5, [x4]
    8020e2dc:	d000000c 	adrp	x12, 80210000 <__trunctfdf2+0xc0>
    8020e2e0:	d000000b 	adrp	x11, 80210000 <__trunctfdf2+0xc0>
    8020e2e4:	aa0003ed 	mov	x13, x0
    8020e2e8:	9135c18c 	add	x12, x12, #0xd70
    8020e2ec:	9137016b 	add	x11, x11, #0xdc0
    8020e2f0:	aa0203ef 	mov	x15, x2
    8020e2f4:	52800009 	mov	w9, #0x0                   	// #0
    8020e2f8:	d2800008 	mov	x8, #0x0                   	// #0
    8020e2fc:	38686847 	ldrb	w7, [x2, x8]
    8020e300:	8b08004e 	add	x14, x2, x8
    8020e304:	7100a0ff 	cmp	w7, #0x28
    8020e308:	54000b80 	b.eq	8020e478 <__jis_mbtowc+0x1b8>  // b.none
    8020e30c:	54000388 	b.hi	8020e37c <__jis_mbtowc+0xbc>  // b.pmore
    8020e310:	52800006 	mov	w6, #0x0                   	// #0
    8020e314:	71006cff 	cmp	w7, #0x1b
    8020e318:	540000c0 	b.eq	8020e330 <__jis_mbtowc+0x70>  // b.none
    8020e31c:	52800026 	mov	w6, #0x1                   	// #1
    8020e320:	710090ff 	cmp	w7, #0x24
    8020e324:	54000060 	b.eq	8020e330 <__jis_mbtowc+0x70>  // b.none
    8020e328:	528000c6 	mov	w6, #0x6                   	// #6
    8020e32c:	350003a7 	cbnz	w7, 8020e3a0 <__jis_mbtowc+0xe0>
    8020e330:	d37d1ca0 	ubfiz	x0, x5, #3, #8
    8020e334:	8b250005 	add	x5, x0, w5, uxtb
    8020e338:	8b050180 	add	x0, x12, x5
    8020e33c:	8b050165 	add	x5, x11, x5
    8020e340:	3866c80a 	ldrb	w10, [x0, w6, sxtw]
    8020e344:	3866c8a5 	ldrb	w5, [x5, w6, sxtw]
    8020e348:	71000d5f 	cmp	w10, #0x3
    8020e34c:	54000420 	b.eq	8020e3d0 <__jis_mbtowc+0x110>  // b.none
    8020e350:	54000528 	b.hi	8020e3f4 <__jis_mbtowc+0x134>  // b.pmore
    8020e354:	7100055f 	cmp	w10, #0x1
    8020e358:	54000600 	b.eq	8020e418 <__jis_mbtowc+0x158>  // b.none
    8020e35c:	7100095f 	cmp	w10, #0x2
    8020e360:	54000720 	b.eq	8020e444 <__jis_mbtowc+0x184>  // b.none
    8020e364:	b900009f 	str	wzr, [x4]
    8020e368:	11000520 	add	w0, w9, #0x1
    8020e36c:	394001e2 	ldrb	w2, [x15]
    8020e370:	b9000022 	str	w2, [x1]
    8020e374:	910043ff 	add	sp, sp, #0x10
    8020e378:	d65f03c0 	ret
    8020e37c:	52800086 	mov	w6, #0x4                   	// #4
    8020e380:	710108ff 	cmp	w7, #0x42
    8020e384:	54fffd60 	b.eq	8020e330 <__jis_mbtowc+0x70>  // b.none
    8020e388:	528000a6 	mov	w6, #0x5                   	// #5
    8020e38c:	710128ff 	cmp	w7, #0x4a
    8020e390:	54fffd00 	b.eq	8020e330 <__jis_mbtowc+0x70>  // b.none
    8020e394:	52800066 	mov	w6, #0x3                   	// #3
    8020e398:	710100ff 	cmp	w7, #0x40
    8020e39c:	54fffca0 	b.eq	8020e330 <__jis_mbtowc+0x70>  // b.none
    8020e3a0:	510084e0 	sub	w0, w7, #0x21
    8020e3a4:	7101741f 	cmp	w0, #0x5d
    8020e3a8:	d37d1ca0 	ubfiz	x0, x5, #3, #8
    8020e3ac:	8b250005 	add	x5, x0, w5, uxtb
    8020e3b0:	1a9f97e6 	cset	w6, hi	// hi = pmore
    8020e3b4:	11001cc6 	add	w6, w6, #0x7
    8020e3b8:	8b050180 	add	x0, x12, x5
    8020e3bc:	8b050165 	add	x5, x11, x5
    8020e3c0:	3866c80a 	ldrb	w10, [x0, w6, sxtw]
    8020e3c4:	3866c8a5 	ldrb	w5, [x5, w6, sxtw]
    8020e3c8:	71000d5f 	cmp	w10, #0x3
    8020e3cc:	54fffc21 	b.ne	8020e350 <__jis_mbtowc+0x90>  // b.any
    8020e3d0:	91000508 	add	x8, x8, #0x1
    8020e3d4:	8b08004f 	add	x15, x2, x8
    8020e3d8:	11000528 	add	w8, w9, #0x1
    8020e3dc:	aa0803e9 	mov	x9, x8
    8020e3e0:	eb03011f 	cmp	x8, x3
    8020e3e4:	54fff8c3 	b.cc	8020e2fc <__jis_mbtowc+0x3c>  // b.lo, b.ul, b.last
    8020e3e8:	b9000085 	str	w5, [x4]
    8020e3ec:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020e3f0:	17ffffe1 	b	8020e374 <__jis_mbtowc+0xb4>
    8020e3f4:	7100115f 	cmp	w10, #0x4
    8020e3f8:	54ffff00 	b.eq	8020e3d8 <__jis_mbtowc+0x118>  // b.none
    8020e3fc:	7100155f 	cmp	w10, #0x5
    8020e400:	54000181 	b.ne	8020e430 <__jis_mbtowc+0x170>  // b.any
    8020e404:	b900009f 	str	wzr, [x4]
    8020e408:	52800000 	mov	w0, #0x0                   	// #0
    8020e40c:	b900003f 	str	wzr, [x1]
    8020e410:	910043ff 	add	sp, sp, #0x10
    8020e414:	d65f03c0 	ret
    8020e418:	11000528 	add	w8, w9, #0x1
    8020e41c:	39001087 	strb	w7, [x4, #4]
    8020e420:	aa0803e9 	mov	x9, x8
    8020e424:	eb03011f 	cmp	x8, x3
    8020e428:	54fff6a3 	b.cc	8020e2fc <__jis_mbtowc+0x3c>  // b.lo, b.ul, b.last
    8020e42c:	17ffffef 	b	8020e3e8 <__jis_mbtowc+0x128>
    8020e430:	52801141 	mov	w1, #0x8a                  	// #138
    8020e434:	b90001a1 	str	w1, [x13]
    8020e438:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020e43c:	910043ff 	add	sp, sp, #0x10
    8020e440:	d65f03c0 	ret
    8020e444:	52800020 	mov	w0, #0x1                   	// #1
    8020e448:	b9000080 	str	w0, [x4]
    8020e44c:	39401082 	ldrb	w2, [x4, #4]
    8020e450:	0b000120 	add	w0, w9, w0
    8020e454:	394001c3 	ldrb	w3, [x14]
    8020e458:	0b022062 	add	w2, w3, w2, lsl #8
    8020e45c:	b9000022 	str	w2, [x1]
    8020e460:	910043ff 	add	sp, sp, #0x10
    8020e464:	d65f03c0 	ret
    8020e468:	b900009f 	str	wzr, [x4]
    8020e46c:	52800020 	mov	w0, #0x1                   	// #1
    8020e470:	910043ff 	add	sp, sp, #0x10
    8020e474:	d65f03c0 	ret
    8020e478:	52800046 	mov	w6, #0x2                   	// #2
    8020e47c:	17ffffad 	b	8020e330 <__jis_mbtowc+0x70>

000000008020e480 <__assert_func>:
    8020e480:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020e484:	f0000004 	adrp	x4, 80211000 <__mprec_tens+0x180>
    8020e488:	aa0303e5 	mov	x5, x3
    8020e48c:	910003fd 	mov	x29, sp
    8020e490:	f9402487 	ldr	x7, [x4, #72]
    8020e494:	aa0003e3 	mov	x3, x0
    8020e498:	aa0203e6 	mov	x6, x2
    8020e49c:	2a0103e4 	mov	w4, w1
    8020e4a0:	aa0503e2 	mov	x2, x5
    8020e4a4:	f9400ce0 	ldr	x0, [x7, #24]
    8020e4a8:	b40000e6 	cbz	x6, 8020e4c4 <__assert_func+0x44>
    8020e4ac:	d0000005 	adrp	x5, 80210000 <__trunctfdf2+0xc0>
    8020e4b0:	911d80a5 	add	x5, x5, #0x760
    8020e4b4:	d0000001 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020e4b8:	911dc021 	add	x1, x1, #0x770
    8020e4bc:	94000535 	bl	8020f990 <fiprintf>
    8020e4c0:	94000554 	bl	8020fa10 <abort>
    8020e4c4:	d0000005 	adrp	x5, 80210000 <__trunctfdf2+0xc0>
    8020e4c8:	910ee0a5 	add	x5, x5, #0x3b8
    8020e4cc:	aa0503e6 	mov	x6, x5
    8020e4d0:	17fffff9 	b	8020e4b4 <__assert_func+0x34>
	...

000000008020e4e0 <__assert>:
    8020e4e0:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020e4e4:	aa0203e3 	mov	x3, x2
    8020e4e8:	d2800002 	mov	x2, #0x0                   	// #0
    8020e4ec:	910003fd 	mov	x29, sp
    8020e4f0:	97ffffe4 	bl	8020e480 <__assert_func>
	...

000000008020e500 <strcasecmp>:
    8020e500:	d0000006 	adrp	x6, 80210000 <__trunctfdf2+0xc0>
    8020e504:	aa0003e8 	mov	x8, x0
    8020e508:	913184c6 	add	x6, x6, #0xc61
    8020e50c:	d2800003 	mov	x3, #0x0                   	// #0
    8020e510:	38636902 	ldrb	w2, [x8, x3]
    8020e514:	38636820 	ldrb	w0, [x1, x3]
    8020e518:	11008047 	add	w7, w2, #0x20
    8020e51c:	386248c5 	ldrb	w5, [x6, w2, uxtw]
    8020e520:	386048c4 	ldrb	w4, [x6, w0, uxtw]
    8020e524:	120004a5 	and	w5, w5, #0x3
    8020e528:	710004bf 	cmp	w5, #0x1
    8020e52c:	12000484 	and	w4, w4, #0x3
    8020e530:	1a8200e2 	csel	w2, w7, w2, eq	// eq = none
    8020e534:	7100049f 	cmp	w4, #0x1
    8020e538:	540000c0 	b.eq	8020e550 <strcasecmp+0x50>  // b.none
    8020e53c:	6b000042 	subs	w2, w2, w0
    8020e540:	54000121 	b.ne	8020e564 <strcasecmp+0x64>  // b.any
    8020e544:	91000463 	add	x3, x3, #0x1
    8020e548:	35fffe40 	cbnz	w0, 8020e510 <strcasecmp+0x10>
    8020e54c:	d65f03c0 	ret
    8020e550:	11008000 	add	w0, w0, #0x20
    8020e554:	91000463 	add	x3, x3, #0x1
    8020e558:	6b000040 	subs	w0, w2, w0
    8020e55c:	54fffda0 	b.eq	8020e510 <strcasecmp+0x10>  // b.none
    8020e560:	d65f03c0 	ret
    8020e564:	2a0203e0 	mov	w0, w2
    8020e568:	d65f03c0 	ret
    8020e56c:	00000000 	udf	#0

000000008020e570 <strcat>:
    8020e570:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020e574:	910003fd 	mov	x29, sp
    8020e578:	f9000bf3 	str	x19, [sp, #16]
    8020e57c:	aa0003f3 	mov	x19, x0
    8020e580:	f240081f 	tst	x0, #0x7
    8020e584:	540001c1 	b.ne	8020e5bc <strcat+0x4c>  // b.any
    8020e588:	f9400002 	ldr	x2, [x0]
    8020e58c:	b207dbe4 	mov	x4, #0xfefefefefefefefe    	// #-72340172838076674
    8020e590:	f29fdfe4 	movk	x4, #0xfeff
    8020e594:	8b040043 	add	x3, x2, x4
    8020e598:	8a220062 	bic	x2, x3, x2
    8020e59c:	f201c05f 	tst	x2, #0x8080808080808080
    8020e5a0:	540000e1 	b.ne	8020e5bc <strcat+0x4c>  // b.any
    8020e5a4:	d503201f 	nop
    8020e5a8:	f8408c02 	ldr	x2, [x0, #8]!
    8020e5ac:	8b040043 	add	x3, x2, x4
    8020e5b0:	8a220062 	bic	x2, x3, x2
    8020e5b4:	f201c05f 	tst	x2, #0x8080808080808080
    8020e5b8:	54ffff80 	b.eq	8020e5a8 <strcat+0x38>  // b.none
    8020e5bc:	39400002 	ldrb	w2, [x0]
    8020e5c0:	34000082 	cbz	w2, 8020e5d0 <strcat+0x60>
    8020e5c4:	d503201f 	nop
    8020e5c8:	38401c02 	ldrb	w2, [x0, #1]!
    8020e5cc:	35ffffe2 	cbnz	w2, 8020e5c8 <strcat+0x58>
    8020e5d0:	97fffb5c 	bl	8020d340 <strcpy>
    8020e5d4:	aa1303e0 	mov	x0, x19
    8020e5d8:	f9400bf3 	ldr	x19, [sp, #16]
    8020e5dc:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020e5e0:	d65f03c0 	ret
	...

000000008020e5f0 <_Balloc>:
    8020e5f0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020e5f4:	910003fd 	mov	x29, sp
    8020e5f8:	f9403402 	ldr	x2, [x0, #104]
    8020e5fc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020e600:	aa0003f3 	mov	x19, x0
    8020e604:	2a0103f4 	mov	w20, w1
    8020e608:	b4000142 	cbz	x2, 8020e630 <_Balloc+0x40>
    8020e60c:	93407e81 	sxtw	x1, w20
    8020e610:	f8617840 	ldr	x0, [x2, x1, lsl #3]
    8020e614:	b40001e0 	cbz	x0, 8020e650 <_Balloc+0x60>
    8020e618:	f9400003 	ldr	x3, [x0]
    8020e61c:	f8217843 	str	x3, [x2, x1, lsl #3]
    8020e620:	f900081f 	str	xzr, [x0, #16]
    8020e624:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020e628:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020e62c:	d65f03c0 	ret
    8020e630:	d2800822 	mov	x2, #0x41                  	// #65
    8020e634:	d2800101 	mov	x1, #0x8                   	// #8
    8020e638:	940003fe 	bl	8020f630 <_calloc_r>
    8020e63c:	f9003660 	str	x0, [x19, #104]
    8020e640:	aa0003e2 	mov	x2, x0
    8020e644:	b5fffe40 	cbnz	x0, 8020e60c <_Balloc+0x1c>
    8020e648:	d2800000 	mov	x0, #0x0                   	// #0
    8020e64c:	17fffff6 	b	8020e624 <_Balloc+0x34>
    8020e650:	52800021 	mov	w1, #0x1                   	// #1
    8020e654:	aa1303e0 	mov	x0, x19
    8020e658:	1ad42033 	lsl	w19, w1, w20
    8020e65c:	d2800021 	mov	x1, #0x1                   	// #1
    8020e660:	93407e62 	sxtw	x2, w19
    8020e664:	91001c42 	add	x2, x2, #0x7
    8020e668:	d37ef442 	lsl	x2, x2, #2
    8020e66c:	940003f1 	bl	8020f630 <_calloc_r>
    8020e670:	b4fffec0 	cbz	x0, 8020e648 <_Balloc+0x58>
    8020e674:	29014c14 	stp	w20, w19, [x0, #8]
    8020e678:	17ffffea 	b	8020e620 <_Balloc+0x30>
    8020e67c:	00000000 	udf	#0

000000008020e680 <_Bfree>:
    8020e680:	b40000c1 	cbz	x1, 8020e698 <_Bfree+0x18>
    8020e684:	f9403400 	ldr	x0, [x0, #104]
    8020e688:	b9800822 	ldrsw	x2, [x1, #8]
    8020e68c:	f8627803 	ldr	x3, [x0, x2, lsl #3]
    8020e690:	f9000023 	str	x3, [x1]
    8020e694:	f8227801 	str	x1, [x0, x2, lsl #3]
    8020e698:	d65f03c0 	ret
    8020e69c:	00000000 	udf	#0

000000008020e6a0 <__multadd>:
    8020e6a0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020e6a4:	91006027 	add	x7, x1, #0x18
    8020e6a8:	d2800005 	mov	x5, #0x0                   	// #0
    8020e6ac:	910003fd 	mov	x29, sp
    8020e6b0:	a90153f3 	stp	x19, x20, [sp, #16]
    8020e6b4:	2a0303f3 	mov	w19, w3
    8020e6b8:	b9401434 	ldr	w20, [x1, #20]
    8020e6bc:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020e6c0:	aa0103f5 	mov	x21, x1
    8020e6c4:	aa0003f6 	mov	x22, x0
    8020e6c8:	b86578e4 	ldr	w4, [x7, x5, lsl #2]
    8020e6cc:	12003c83 	and	w3, w4, #0xffff
    8020e6d0:	53107c84 	lsr	w4, w4, #16
    8020e6d4:	1b024c63 	madd	w3, w3, w2, w19
    8020e6d8:	12003c66 	and	w6, w3, #0xffff
    8020e6dc:	53107c63 	lsr	w3, w3, #16
    8020e6e0:	1b020c83 	madd	w3, w4, w2, w3
    8020e6e4:	0b0340c4 	add	w4, w6, w3, lsl #16
    8020e6e8:	b82578e4 	str	w4, [x7, x5, lsl #2]
    8020e6ec:	910004a5 	add	x5, x5, #0x1
    8020e6f0:	53107c73 	lsr	w19, w3, #16
    8020e6f4:	6b05029f 	cmp	w20, w5
    8020e6f8:	54fffe8c 	b.gt	8020e6c8 <__multadd+0x28>
    8020e6fc:	34000113 	cbz	w19, 8020e71c <__multadd+0x7c>
    8020e700:	b9400ea0 	ldr	w0, [x21, #12]
    8020e704:	6b14001f 	cmp	w0, w20
    8020e708:	5400014d 	b.le	8020e730 <__multadd+0x90>
    8020e70c:	8b34caa0 	add	x0, x21, w20, sxtw #2
    8020e710:	11000694 	add	w20, w20, #0x1
    8020e714:	b9001813 	str	w19, [x0, #24]
    8020e718:	b90016b4 	str	w20, [x21, #20]
    8020e71c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020e720:	aa1503e0 	mov	x0, x21
    8020e724:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020e728:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020e72c:	d65f03c0 	ret
    8020e730:	b9400aa1 	ldr	w1, [x21, #8]
    8020e734:	aa1603e0 	mov	x0, x22
    8020e738:	f9001bf7 	str	x23, [sp, #48]
    8020e73c:	11000421 	add	w1, w1, #0x1
    8020e740:	97ffffac 	bl	8020e5f0 <_Balloc>
    8020e744:	aa0003f7 	mov	x23, x0
    8020e748:	b4000260 	cbz	x0, 8020e794 <__multadd+0xf4>
    8020e74c:	b98016a2 	ldrsw	x2, [x21, #20]
    8020e750:	910042a1 	add	x1, x21, #0x10
    8020e754:	91004000 	add	x0, x0, #0x10
    8020e758:	91000842 	add	x2, x2, #0x2
    8020e75c:	d37ef442 	lsl	x2, x2, #2
    8020e760:	97ffefc8 	bl	8020a680 <memcpy>
    8020e764:	f94036c0 	ldr	x0, [x22, #104]
    8020e768:	b9800aa1 	ldrsw	x1, [x21, #8]
    8020e76c:	f8617802 	ldr	x2, [x0, x1, lsl #3]
    8020e770:	f90002a2 	str	x2, [x21]
    8020e774:	f8217815 	str	x21, [x0, x1, lsl #3]
    8020e778:	aa1703f5 	mov	x21, x23
    8020e77c:	8b34caa0 	add	x0, x21, w20, sxtw #2
    8020e780:	11000694 	add	w20, w20, #0x1
    8020e784:	f9401bf7 	ldr	x23, [sp, #48]
    8020e788:	b9001813 	str	w19, [x0, #24]
    8020e78c:	b90016b4 	str	w20, [x21, #20]
    8020e790:	17ffffe3 	b	8020e71c <__multadd+0x7c>
    8020e794:	d0000003 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020e798:	d0000000 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020e79c:	911ba063 	add	x3, x3, #0x6e8
    8020e7a0:	911e8000 	add	x0, x0, #0x7a0
    8020e7a4:	d2800002 	mov	x2, #0x0                   	// #0
    8020e7a8:	52801741 	mov	w1, #0xba                  	// #186
    8020e7ac:	97ffff35 	bl	8020e480 <__assert_func>

000000008020e7b0 <__s2b>:
    8020e7b0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020e7b4:	5291c725 	mov	w5, #0x8e39                	// #36409
    8020e7b8:	72a71c65 	movk	w5, #0x38e3, lsl #16
    8020e7bc:	910003fd 	mov	x29, sp
    8020e7c0:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020e7c4:	2a0303f5 	mov	w21, w3
    8020e7c8:	11002063 	add	w3, w3, #0x8
    8020e7cc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020e7d0:	2a0203f6 	mov	w22, w2
    8020e7d4:	aa0003f4 	mov	x20, x0
    8020e7d8:	9b257c65 	smull	x5, w3, w5
    8020e7dc:	a90363f7 	stp	x23, x24, [sp, #48]
    8020e7e0:	aa0103f3 	mov	x19, x1
    8020e7e4:	2a0403f7 	mov	w23, w4
    8020e7e8:	9361fca5 	asr	x5, x5, #33
    8020e7ec:	4b837ca2 	sub	w2, w5, w3, asr #31
    8020e7f0:	710026bf 	cmp	w21, #0x9
    8020e7f4:	5400064d 	b.le	8020e8bc <__s2b+0x10c>
    8020e7f8:	52800020 	mov	w0, #0x1                   	// #1
    8020e7fc:	52800001 	mov	w1, #0x0                   	// #0
    8020e800:	531f7800 	lsl	w0, w0, #1
    8020e804:	11000421 	add	w1, w1, #0x1
    8020e808:	6b00005f 	cmp	w2, w0
    8020e80c:	54ffffac 	b.gt	8020e800 <__s2b+0x50>
    8020e810:	aa1403e0 	mov	x0, x20
    8020e814:	97ffff77 	bl	8020e5f0 <_Balloc>
    8020e818:	aa0003e1 	mov	x1, x0
    8020e81c:	b4000540 	cbz	x0, 8020e8c4 <__s2b+0x114>
    8020e820:	52800020 	mov	w0, #0x1                   	// #1
    8020e824:	2902dc20 	stp	w0, w23, [x1, #20]
    8020e828:	710026df 	cmp	w22, #0x9
    8020e82c:	540002ac 	b.gt	8020e880 <__s2b+0xd0>
    8020e830:	91002a73 	add	x19, x19, #0xa
    8020e834:	52800136 	mov	w22, #0x9                   	// #9
    8020e838:	6b1602bf 	cmp	w21, w22
    8020e83c:	5400016d 	b.le	8020e868 <__s2b+0xb8>
    8020e840:	4b1602b5 	sub	w21, w21, w22
    8020e844:	8b150275 	add	x21, x19, x21
    8020e848:	38401663 	ldrb	w3, [x19], #1
    8020e84c:	aa1403e0 	mov	x0, x20
    8020e850:	52800142 	mov	w2, #0xa                   	// #10
    8020e854:	5100c063 	sub	w3, w3, #0x30
    8020e858:	97ffff92 	bl	8020e6a0 <__multadd>
    8020e85c:	aa0003e1 	mov	x1, x0
    8020e860:	eb15027f 	cmp	x19, x21
    8020e864:	54ffff21 	b.ne	8020e848 <__s2b+0x98>  // b.any
    8020e868:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020e86c:	aa0103e0 	mov	x0, x1
    8020e870:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020e874:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020e878:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020e87c:	d65f03c0 	ret
    8020e880:	91002678 	add	x24, x19, #0x9
    8020e884:	8b364273 	add	x19, x19, w22, uxtw
    8020e888:	aa1803f7 	mov	x23, x24
    8020e88c:	d503201f 	nop
    8020e890:	384016e3 	ldrb	w3, [x23], #1
    8020e894:	aa1403e0 	mov	x0, x20
    8020e898:	52800142 	mov	w2, #0xa                   	// #10
    8020e89c:	5100c063 	sub	w3, w3, #0x30
    8020e8a0:	97ffff80 	bl	8020e6a0 <__multadd>
    8020e8a4:	aa0003e1 	mov	x1, x0
    8020e8a8:	eb1302ff 	cmp	x23, x19
    8020e8ac:	54ffff21 	b.ne	8020e890 <__s2b+0xe0>  // b.any
    8020e8b0:	510022d3 	sub	w19, w22, #0x8
    8020e8b4:	8b130313 	add	x19, x24, x19
    8020e8b8:	17ffffe0 	b	8020e838 <__s2b+0x88>
    8020e8bc:	52800001 	mov	w1, #0x0                   	// #0
    8020e8c0:	17ffffd4 	b	8020e810 <__s2b+0x60>
    8020e8c4:	d0000003 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020e8c8:	d0000000 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020e8cc:	911ba063 	add	x3, x3, #0x6e8
    8020e8d0:	911e8000 	add	x0, x0, #0x7a0
    8020e8d4:	d2800002 	mov	x2, #0x0                   	// #0
    8020e8d8:	52801a61 	mov	w1, #0xd3                  	// #211
    8020e8dc:	97fffee9 	bl	8020e480 <__assert_func>

000000008020e8e0 <__hi0bits>:
    8020e8e0:	2a0003e1 	mov	w1, w0
    8020e8e4:	529fffe2 	mov	w2, #0xffff                	// #65535
    8020e8e8:	52800000 	mov	w0, #0x0                   	// #0
    8020e8ec:	6b02003f 	cmp	w1, w2
    8020e8f0:	54000068 	b.hi	8020e8fc <__hi0bits+0x1c>  // b.pmore
    8020e8f4:	53103c21 	lsl	w1, w1, #16
    8020e8f8:	52800200 	mov	w0, #0x10                  	// #16
    8020e8fc:	12bfe002 	mov	w2, #0xffffff              	// #16777215
    8020e900:	6b02003f 	cmp	w1, w2
    8020e904:	54000068 	b.hi	8020e910 <__hi0bits+0x30>  // b.pmore
    8020e908:	11002000 	add	w0, w0, #0x8
    8020e90c:	53185c21 	lsl	w1, w1, #8
    8020e910:	12be0002 	mov	w2, #0xfffffff             	// #268435455
    8020e914:	6b02003f 	cmp	w1, w2
    8020e918:	54000068 	b.hi	8020e924 <__hi0bits+0x44>  // b.pmore
    8020e91c:	11001000 	add	w0, w0, #0x4
    8020e920:	531c6c21 	lsl	w1, w1, #4
    8020e924:	12b80002 	mov	w2, #0x3fffffff            	// #1073741823
    8020e928:	6b02003f 	cmp	w1, w2
    8020e92c:	54000089 	b.ls	8020e93c <__hi0bits+0x5c>  // b.plast
    8020e930:	2a2103e1 	mvn	w1, w1
    8020e934:	0b417c00 	add	w0, w0, w1, lsr #31
    8020e938:	d65f03c0 	ret
    8020e93c:	531e7422 	lsl	w2, w1, #2
    8020e940:	37e800c1 	tbnz	w1, #29, 8020e958 <__hi0bits+0x78>
    8020e944:	f262005f 	tst	x2, #0x40000000
    8020e948:	11000c00 	add	w0, w0, #0x3
    8020e94c:	52800401 	mov	w1, #0x20                  	// #32
    8020e950:	1a811000 	csel	w0, w0, w1, ne	// ne = any
    8020e954:	d65f03c0 	ret
    8020e958:	11000800 	add	w0, w0, #0x2
    8020e95c:	d65f03c0 	ret

000000008020e960 <__lo0bits>:
    8020e960:	aa0003e2 	mov	x2, x0
    8020e964:	52800000 	mov	w0, #0x0                   	// #0
    8020e968:	b9400041 	ldr	w1, [x2]
    8020e96c:	f240083f 	tst	x1, #0x7
    8020e970:	540000e0 	b.eq	8020e98c <__lo0bits+0x2c>  // b.none
    8020e974:	370000a1 	tbnz	w1, #0, 8020e988 <__lo0bits+0x28>
    8020e978:	360803a1 	tbz	w1, #1, 8020e9ec <__lo0bits+0x8c>
    8020e97c:	53017c21 	lsr	w1, w1, #1
    8020e980:	52800020 	mov	w0, #0x1                   	// #1
    8020e984:	b9000041 	str	w1, [x2]
    8020e988:	d65f03c0 	ret
    8020e98c:	72003c3f 	tst	w1, #0xffff
    8020e990:	54000061 	b.ne	8020e99c <__lo0bits+0x3c>  // b.any
    8020e994:	53107c21 	lsr	w1, w1, #16
    8020e998:	52800200 	mov	w0, #0x10                  	// #16
    8020e99c:	72001c3f 	tst	w1, #0xff
    8020e9a0:	54000061 	b.ne	8020e9ac <__lo0bits+0x4c>  // b.any
    8020e9a4:	11002000 	add	w0, w0, #0x8
    8020e9a8:	53087c21 	lsr	w1, w1, #8
    8020e9ac:	f2400c3f 	tst	x1, #0xf
    8020e9b0:	54000061 	b.ne	8020e9bc <__lo0bits+0x5c>  // b.any
    8020e9b4:	11001000 	add	w0, w0, #0x4
    8020e9b8:	53047c21 	lsr	w1, w1, #4
    8020e9bc:	f240043f 	tst	x1, #0x3
    8020e9c0:	54000061 	b.ne	8020e9cc <__lo0bits+0x6c>  // b.any
    8020e9c4:	11000800 	add	w0, w0, #0x2
    8020e9c8:	53027c21 	lsr	w1, w1, #2
    8020e9cc:	37000081 	tbnz	w1, #0, 8020e9dc <__lo0bits+0x7c>
    8020e9d0:	11000400 	add	w0, w0, #0x1
    8020e9d4:	53017c21 	lsr	w1, w1, #1
    8020e9d8:	34000061 	cbz	w1, 8020e9e4 <__lo0bits+0x84>
    8020e9dc:	b9000041 	str	w1, [x2]
    8020e9e0:	d65f03c0 	ret
    8020e9e4:	52800400 	mov	w0, #0x20                  	// #32
    8020e9e8:	d65f03c0 	ret
    8020e9ec:	53027c21 	lsr	w1, w1, #2
    8020e9f0:	52800040 	mov	w0, #0x2                   	// #2
    8020e9f4:	b9000041 	str	w1, [x2]
    8020e9f8:	d65f03c0 	ret
    8020e9fc:	00000000 	udf	#0

000000008020ea00 <__i2b>:
    8020ea00:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020ea04:	910003fd 	mov	x29, sp
    8020ea08:	f9403402 	ldr	x2, [x0, #104]
    8020ea0c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020ea10:	aa0003f3 	mov	x19, x0
    8020ea14:	2a0103f4 	mov	w20, w1
    8020ea18:	b4000182 	cbz	x2, 8020ea48 <__i2b+0x48>
    8020ea1c:	f9400440 	ldr	x0, [x2, #8]
    8020ea20:	b40002e0 	cbz	x0, 8020ea7c <__i2b+0x7c>
    8020ea24:	f9400001 	ldr	x1, [x0]
    8020ea28:	f9000441 	str	x1, [x2, #8]
    8020ea2c:	d0000001 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020ea30:	b9001814 	str	w20, [x0, #24]
    8020ea34:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ea38:	fd462c20 	ldr	d0, [x1, #3160]
    8020ea3c:	fd000800 	str	d0, [x0, #16]
    8020ea40:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020ea44:	d65f03c0 	ret
    8020ea48:	d2800822 	mov	x2, #0x41                  	// #65
    8020ea4c:	d2800101 	mov	x1, #0x8                   	// #8
    8020ea50:	940002f8 	bl	8020f630 <_calloc_r>
    8020ea54:	f9003660 	str	x0, [x19, #104]
    8020ea58:	aa0003e2 	mov	x2, x0
    8020ea5c:	b5fffe00 	cbnz	x0, 8020ea1c <__i2b+0x1c>
    8020ea60:	d0000003 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020ea64:	d0000000 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020ea68:	911ba063 	add	x3, x3, #0x6e8
    8020ea6c:	911e8000 	add	x0, x0, #0x7a0
    8020ea70:	d2800002 	mov	x2, #0x0                   	// #0
    8020ea74:	528028a1 	mov	w1, #0x145                 	// #325
    8020ea78:	97fffe82 	bl	8020e480 <__assert_func>
    8020ea7c:	aa1303e0 	mov	x0, x19
    8020ea80:	d2800482 	mov	x2, #0x24                  	// #36
    8020ea84:	d2800021 	mov	x1, #0x1                   	// #1
    8020ea88:	940002ea 	bl	8020f630 <_calloc_r>
    8020ea8c:	b4fffea0 	cbz	x0, 8020ea60 <__i2b+0x60>
    8020ea90:	d0000001 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020ea94:	b9001814 	str	w20, [x0, #24]
    8020ea98:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ea9c:	fd462820 	ldr	d0, [x1, #3152]
    8020eaa0:	d0000001 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020eaa4:	fd000400 	str	d0, [x0, #8]
    8020eaa8:	fd462c20 	ldr	d0, [x1, #3160]
    8020eaac:	fd000800 	str	d0, [x0, #16]
    8020eab0:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020eab4:	d65f03c0 	ret
	...

000000008020eac0 <__multiply>:
    8020eac0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020eac4:	910003fd 	mov	x29, sp
    8020eac8:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020eacc:	aa0103f5 	mov	x21, x1
    8020ead0:	b9401436 	ldr	w22, [x1, #20]
    8020ead4:	f9001bf7 	str	x23, [sp, #48]
    8020ead8:	b9401457 	ldr	w23, [x2, #20]
    8020eadc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020eae0:	aa0203f4 	mov	x20, x2
    8020eae4:	6b1702df 	cmp	w22, w23
    8020eae8:	540000eb 	b.lt	8020eb04 <__multiply+0x44>  // b.tstop
    8020eaec:	2a1703e2 	mov	w2, w23
    8020eaf0:	aa1403e1 	mov	x1, x20
    8020eaf4:	2a1603f7 	mov	w23, w22
    8020eaf8:	aa1503f4 	mov	x20, x21
    8020eafc:	2a0203f6 	mov	w22, w2
    8020eb00:	aa0103f5 	mov	x21, x1
    8020eb04:	29410a81 	ldp	w1, w2, [x20, #8]
    8020eb08:	0b1602f3 	add	w19, w23, w22
    8020eb0c:	6b13005f 	cmp	w2, w19
    8020eb10:	1a81a421 	cinc	w1, w1, lt	// lt = tstop
    8020eb14:	97fffeb7 	bl	8020e5f0 <_Balloc>
    8020eb18:	b4000b80 	cbz	x0, 8020ec88 <__multiply+0x1c8>
    8020eb1c:	91006007 	add	x7, x0, #0x18
    8020eb20:	8b33c8e8 	add	x8, x7, w19, sxtw #2
    8020eb24:	aa0703e3 	mov	x3, x7
    8020eb28:	eb0800ff 	cmp	x7, x8
    8020eb2c:	54000082 	b.cs	8020eb3c <__multiply+0x7c>  // b.hs, b.nlast
    8020eb30:	b800447f 	str	wzr, [x3], #4
    8020eb34:	eb03011f 	cmp	x8, x3
    8020eb38:	54ffffc8 	b.hi	8020eb30 <__multiply+0x70>  // b.pmore
    8020eb3c:	910062a6 	add	x6, x21, #0x18
    8020eb40:	9100628b 	add	x11, x20, #0x18
    8020eb44:	8b36c8c9 	add	x9, x6, w22, sxtw #2
    8020eb48:	8b37c965 	add	x5, x11, w23, sxtw #2
    8020eb4c:	eb0900df 	cmp	x6, x9
    8020eb50:	54000822 	b.cs	8020ec54 <__multiply+0x194>  // b.hs, b.nlast
    8020eb54:	cb1400aa 	sub	x10, x5, x20
    8020eb58:	91006694 	add	x20, x20, #0x19
    8020eb5c:	d100654a 	sub	x10, x10, #0x19
    8020eb60:	d2800081 	mov	x1, #0x4                   	// #4
    8020eb64:	927ef54a 	and	x10, x10, #0xfffffffffffffffc
    8020eb68:	eb1400bf 	cmp	x5, x20
    8020eb6c:	8b01014a 	add	x10, x10, x1
    8020eb70:	9a81214a 	csel	x10, x10, x1, cs	// cs = hs, nlast
    8020eb74:	14000007 	b	8020eb90 <__multiply+0xd0>
    8020eb78:	53107c63 	lsr	w3, w3, #16
    8020eb7c:	350003c3 	cbnz	w3, 8020ebf4 <__multiply+0x134>
    8020eb80:	910010c6 	add	x6, x6, #0x4
    8020eb84:	910010e7 	add	x7, x7, #0x4
    8020eb88:	eb06013f 	cmp	x9, x6
    8020eb8c:	54000649 	b.ls	8020ec54 <__multiply+0x194>  // b.plast
    8020eb90:	b94000c3 	ldr	w3, [x6]
    8020eb94:	72003c6d 	ands	w13, w3, #0xffff
    8020eb98:	54ffff00 	b.eq	8020eb78 <__multiply+0xb8>  // b.none
    8020eb9c:	aa0703ec 	mov	x12, x7
    8020eba0:	aa0b03e4 	mov	x4, x11
    8020eba4:	5280000e 	mov	w14, #0x0                   	// #0
    8020eba8:	b8404481 	ldr	w1, [x4], #4
    8020ebac:	b9400183 	ldr	w3, [x12]
    8020ebb0:	12003c22 	and	w2, w1, #0xffff
    8020ebb4:	12003c6f 	and	w15, w3, #0xffff
    8020ebb8:	53107c21 	lsr	w1, w1, #16
    8020ebbc:	53107c63 	lsr	w3, w3, #16
    8020ebc0:	1b0d3c42 	madd	w2, w2, w13, w15
    8020ebc4:	1b0d0c21 	madd	w1, w1, w13, w3
    8020ebc8:	0b0e0042 	add	w2, w2, w14
    8020ebcc:	0b424021 	add	w1, w1, w2, lsr #16
    8020ebd0:	33103c22 	bfi	w2, w1, #16, #16
    8020ebd4:	b8004582 	str	w2, [x12], #4
    8020ebd8:	53107c2e 	lsr	w14, w1, #16
    8020ebdc:	eb0400bf 	cmp	x5, x4
    8020ebe0:	54fffe48 	b.hi	8020eba8 <__multiply+0xe8>  // b.pmore
    8020ebe4:	b82a68ee 	str	w14, [x7, x10]
    8020ebe8:	b94000c3 	ldr	w3, [x6]
    8020ebec:	53107c63 	lsr	w3, w3, #16
    8020ebf0:	34fffc83 	cbz	w3, 8020eb80 <__multiply+0xc0>
    8020ebf4:	b94000e1 	ldr	w1, [x7]
    8020ebf8:	aa0703ed 	mov	x13, x7
    8020ebfc:	aa0b03e4 	mov	x4, x11
    8020ec00:	5280000e 	mov	w14, #0x0                   	// #0
    8020ec04:	2a0103ec 	mov	w12, w1
    8020ec08:	79400082 	ldrh	w2, [x4]
    8020ec0c:	1b033842 	madd	w2, w2, w3, w14
    8020ec10:	0b4c4042 	add	w2, w2, w12, lsr #16
    8020ec14:	33103c41 	bfi	w1, w2, #16, #16
    8020ec18:	b80045a1 	str	w1, [x13], #4
    8020ec1c:	b8404481 	ldr	w1, [x4], #4
    8020ec20:	b94001ac 	ldr	w12, [x13]
    8020ec24:	53107c21 	lsr	w1, w1, #16
    8020ec28:	12003d8e 	and	w14, w12, #0xffff
    8020ec2c:	1b033821 	madd	w1, w1, w3, w14
    8020ec30:	0b424021 	add	w1, w1, w2, lsr #16
    8020ec34:	53107c2e 	lsr	w14, w1, #16
    8020ec38:	eb0400bf 	cmp	x5, x4
    8020ec3c:	54fffe68 	b.hi	8020ec08 <__multiply+0x148>  // b.pmore
    8020ec40:	910010c6 	add	x6, x6, #0x4
    8020ec44:	b82a68e1 	str	w1, [x7, x10]
    8020ec48:	910010e7 	add	x7, x7, #0x4
    8020ec4c:	eb06013f 	cmp	x9, x6
    8020ec50:	54fffa08 	b.hi	8020eb90 <__multiply+0xd0>  // b.pmore
    8020ec54:	7100027f 	cmp	w19, #0x0
    8020ec58:	5400008c 	b.gt	8020ec68 <__multiply+0x1a8>
    8020ec5c:	14000005 	b	8020ec70 <__multiply+0x1b0>
    8020ec60:	71000673 	subs	w19, w19, #0x1
    8020ec64:	54000060 	b.eq	8020ec70 <__multiply+0x1b0>  // b.none
    8020ec68:	b85fcd01 	ldr	w1, [x8, #-4]!
    8020ec6c:	34ffffa1 	cbz	w1, 8020ec60 <__multiply+0x1a0>
    8020ec70:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020ec74:	f9401bf7 	ldr	x23, [sp, #48]
    8020ec78:	b9001413 	str	w19, [x0, #20]
    8020ec7c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ec80:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020ec84:	d65f03c0 	ret
    8020ec88:	d0000003 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020ec8c:	d0000000 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020ec90:	911ba063 	add	x3, x3, #0x6e8
    8020ec94:	911e8000 	add	x0, x0, #0x7a0
    8020ec98:	d2800002 	mov	x2, #0x0                   	// #0
    8020ec9c:	52802c41 	mov	w1, #0x162                 	// #354
    8020eca0:	97fffdf8 	bl	8020e480 <__assert_func>
	...

000000008020ecb0 <__pow5mult>:
    8020ecb0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020ecb4:	910003fd 	mov	x29, sp
    8020ecb8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020ecbc:	2a0203f3 	mov	w19, w2
    8020ecc0:	72000442 	ands	w2, w2, #0x3
    8020ecc4:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020ecc8:	aa0003f6 	mov	x22, x0
    8020eccc:	aa0103f5 	mov	x21, x1
    8020ecd0:	540004c1 	b.ne	8020ed68 <__pow5mult+0xb8>  // b.any
    8020ecd4:	13027e73 	asr	w19, w19, #2
    8020ecd8:	340002f3 	cbz	w19, 8020ed34 <__pow5mult+0x84>
    8020ecdc:	f94032d4 	ldr	x20, [x22, #96]
    8020ece0:	b4000554 	cbz	x20, 8020ed88 <__pow5mult+0xd8>
    8020ece4:	370000f3 	tbnz	w19, #0, 8020ed00 <__pow5mult+0x50>
    8020ece8:	13017e73 	asr	w19, w19, #1
    8020ecec:	34000253 	cbz	w19, 8020ed34 <__pow5mult+0x84>
    8020ecf0:	f9400280 	ldr	x0, [x20]
    8020ecf4:	b40002a0 	cbz	x0, 8020ed48 <__pow5mult+0x98>
    8020ecf8:	aa0003f4 	mov	x20, x0
    8020ecfc:	3607ff73 	tbz	w19, #0, 8020ece8 <__pow5mult+0x38>
    8020ed00:	aa1403e2 	mov	x2, x20
    8020ed04:	aa1503e1 	mov	x1, x21
    8020ed08:	aa1603e0 	mov	x0, x22
    8020ed0c:	97ffff6d 	bl	8020eac0 <__multiply>
    8020ed10:	b40000d5 	cbz	x21, 8020ed28 <__pow5mult+0x78>
    8020ed14:	f94036c1 	ldr	x1, [x22, #104]
    8020ed18:	b9800aa2 	ldrsw	x2, [x21, #8]
    8020ed1c:	f8627823 	ldr	x3, [x1, x2, lsl #3]
    8020ed20:	f90002a3 	str	x3, [x21]
    8020ed24:	f8227835 	str	x21, [x1, x2, lsl #3]
    8020ed28:	aa0003f5 	mov	x21, x0
    8020ed2c:	13017e73 	asr	w19, w19, #1
    8020ed30:	35fffe13 	cbnz	w19, 8020ecf0 <__pow5mult+0x40>
    8020ed34:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ed38:	aa1503e0 	mov	x0, x21
    8020ed3c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020ed40:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020ed44:	d65f03c0 	ret
    8020ed48:	aa1403e2 	mov	x2, x20
    8020ed4c:	aa1403e1 	mov	x1, x20
    8020ed50:	aa1603e0 	mov	x0, x22
    8020ed54:	97ffff5b 	bl	8020eac0 <__multiply>
    8020ed58:	f9000280 	str	x0, [x20]
    8020ed5c:	aa0003f4 	mov	x20, x0
    8020ed60:	f900001f 	str	xzr, [x0]
    8020ed64:	17ffffe6 	b	8020ecfc <__pow5mult+0x4c>
    8020ed68:	51000442 	sub	w2, w2, #0x1
    8020ed6c:	d0000004 	adrp	x4, 80210000 <__trunctfdf2+0xc0>
    8020ed70:	91382084 	add	x4, x4, #0xe08
    8020ed74:	52800003 	mov	w3, #0x0                   	// #0
    8020ed78:	b862d882 	ldr	w2, [x4, w2, sxtw #2]
    8020ed7c:	97fffe49 	bl	8020e6a0 <__multadd>
    8020ed80:	aa0003f5 	mov	x21, x0
    8020ed84:	17ffffd4 	b	8020ecd4 <__pow5mult+0x24>
    8020ed88:	aa1603e0 	mov	x0, x22
    8020ed8c:	52800021 	mov	w1, #0x1                   	// #1
    8020ed90:	97fffe18 	bl	8020e5f0 <_Balloc>
    8020ed94:	aa0003f4 	mov	x20, x0
    8020ed98:	b40000e0 	cbz	x0, 8020edb4 <__pow5mult+0x104>
    8020ed9c:	d2800020 	mov	x0, #0x1                   	// #1
    8020eda0:	f2c04e20 	movk	x0, #0x271, lsl #32
    8020eda4:	f8014280 	stur	x0, [x20, #20]
    8020eda8:	f90032d4 	str	x20, [x22, #96]
    8020edac:	f900029f 	str	xzr, [x20]
    8020edb0:	17ffffcd 	b	8020ece4 <__pow5mult+0x34>
    8020edb4:	d0000003 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020edb8:	d0000000 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020edbc:	911ba063 	add	x3, x3, #0x6e8
    8020edc0:	911e8000 	add	x0, x0, #0x7a0
    8020edc4:	d2800002 	mov	x2, #0x0                   	// #0
    8020edc8:	528028a1 	mov	w1, #0x145                 	// #325
    8020edcc:	97fffdad 	bl	8020e480 <__assert_func>

000000008020edd0 <__lshift>:
    8020edd0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020edd4:	910003fd 	mov	x29, sp
    8020edd8:	a90363f7 	stp	x23, x24, [sp, #48]
    8020eddc:	13057c58 	asr	w24, w2, #5
    8020ede0:	b9401437 	ldr	w23, [x1, #20]
    8020ede4:	b9400c23 	ldr	w3, [x1, #12]
    8020ede8:	0b170317 	add	w23, w24, w23
    8020edec:	a90153f3 	stp	x19, x20, [sp, #16]
    8020edf0:	aa0103f4 	mov	x20, x1
    8020edf4:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020edf8:	110006f5 	add	w21, w23, #0x1
    8020edfc:	b9400821 	ldr	w1, [x1, #8]
    8020ee00:	2a0203f3 	mov	w19, w2
    8020ee04:	aa0003f6 	mov	x22, x0
    8020ee08:	6b0302bf 	cmp	w21, w3
    8020ee0c:	540000ad 	b.le	8020ee20 <__lshift+0x50>
    8020ee10:	531f7863 	lsl	w3, w3, #1
    8020ee14:	11000421 	add	w1, w1, #0x1
    8020ee18:	6b0302bf 	cmp	w21, w3
    8020ee1c:	54ffffac 	b.gt	8020ee10 <__lshift+0x40>
    8020ee20:	aa1603e0 	mov	x0, x22
    8020ee24:	97fffdf3 	bl	8020e5f0 <_Balloc>
    8020ee28:	b40007a0 	cbz	x0, 8020ef1c <__lshift+0x14c>
    8020ee2c:	91006005 	add	x5, x0, #0x18
    8020ee30:	7100031f 	cmp	w24, #0x0
    8020ee34:	5400012d 	b.le	8020ee58 <__lshift+0x88>
    8020ee38:	11001b04 	add	w4, w24, #0x6
    8020ee3c:	aa0503e3 	mov	x3, x5
    8020ee40:	8b24c804 	add	x4, x0, w4, sxtw #2
    8020ee44:	d503201f 	nop
    8020ee48:	b800447f 	str	wzr, [x3], #4
    8020ee4c:	eb04007f 	cmp	x3, x4
    8020ee50:	54ffffc1 	b.ne	8020ee48 <__lshift+0x78>  // b.any
    8020ee54:	8b3848a5 	add	x5, x5, w24, uxtw #2
    8020ee58:	b9801686 	ldrsw	x6, [x20, #20]
    8020ee5c:	91006283 	add	x3, x20, #0x18
    8020ee60:	72001267 	ands	w7, w19, #0x1f
    8020ee64:	8b060866 	add	x6, x3, x6, lsl #2
    8020ee68:	54000480 	b.eq	8020eef8 <__lshift+0x128>  // b.none
    8020ee6c:	52800408 	mov	w8, #0x20                  	// #32
    8020ee70:	aa0503e1 	mov	x1, x5
    8020ee74:	4b070108 	sub	w8, w8, w7
    8020ee78:	52800004 	mov	w4, #0x0                   	// #0
    8020ee7c:	d503201f 	nop
    8020ee80:	b9400062 	ldr	w2, [x3]
    8020ee84:	1ac72042 	lsl	w2, w2, w7
    8020ee88:	2a040042 	orr	w2, w2, w4
    8020ee8c:	b8004422 	str	w2, [x1], #4
    8020ee90:	b8404464 	ldr	w4, [x3], #4
    8020ee94:	1ac82484 	lsr	w4, w4, w8
    8020ee98:	eb0300df 	cmp	x6, x3
    8020ee9c:	54ffff28 	b.hi	8020ee80 <__lshift+0xb0>  // b.pmore
    8020eea0:	cb1400c1 	sub	x1, x6, x20
    8020eea4:	91006682 	add	x2, x20, #0x19
    8020eea8:	d1006421 	sub	x1, x1, #0x19
    8020eeac:	eb0200df 	cmp	x6, x2
    8020eeb0:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    8020eeb4:	d2800082 	mov	x2, #0x4                   	// #4
    8020eeb8:	8b020021 	add	x1, x1, x2
    8020eebc:	9a822021 	csel	x1, x1, x2, cs	// cs = hs, nlast
    8020eec0:	b82168a4 	str	w4, [x5, x1]
    8020eec4:	35000044 	cbnz	w4, 8020eecc <__lshift+0xfc>
    8020eec8:	2a1703f5 	mov	w21, w23
    8020eecc:	f94036c1 	ldr	x1, [x22, #104]
    8020eed0:	b9800a82 	ldrsw	x2, [x20, #8]
    8020eed4:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020eed8:	f8627823 	ldr	x3, [x1, x2, lsl #3]
    8020eedc:	b9001415 	str	w21, [x0, #20]
    8020eee0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020eee4:	f9000283 	str	x3, [x20]
    8020eee8:	f8227834 	str	x20, [x1, x2, lsl #3]
    8020eeec:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020eef0:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020eef4:	d65f03c0 	ret
    8020eef8:	b8404461 	ldr	w1, [x3], #4
    8020eefc:	b80044a1 	str	w1, [x5], #4
    8020ef00:	eb0300df 	cmp	x6, x3
    8020ef04:	54fffe29 	b.ls	8020eec8 <__lshift+0xf8>  // b.plast
    8020ef08:	b8404461 	ldr	w1, [x3], #4
    8020ef0c:	b80044a1 	str	w1, [x5], #4
    8020ef10:	eb0300df 	cmp	x6, x3
    8020ef14:	54ffff28 	b.hi	8020eef8 <__lshift+0x128>  // b.pmore
    8020ef18:	17ffffec 	b	8020eec8 <__lshift+0xf8>
    8020ef1c:	d0000003 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020ef20:	d0000000 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020ef24:	911ba063 	add	x3, x3, #0x6e8
    8020ef28:	911e8000 	add	x0, x0, #0x7a0
    8020ef2c:	d2800002 	mov	x2, #0x0                   	// #0
    8020ef30:	52803bc1 	mov	w1, #0x1de                 	// #478
    8020ef34:	97fffd53 	bl	8020e480 <__assert_func>
	...

000000008020ef40 <__mcmp>:
    8020ef40:	b9401422 	ldr	w2, [x1, #20]
    8020ef44:	aa0003e5 	mov	x5, x0
    8020ef48:	b9401400 	ldr	w0, [x0, #20]
    8020ef4c:	6b020000 	subs	w0, w0, w2
    8020ef50:	540001e1 	b.ne	8020ef8c <__mcmp+0x4c>  // b.any
    8020ef54:	937e7c43 	sbfiz	x3, x2, #2, #32
    8020ef58:	910060a5 	add	x5, x5, #0x18
    8020ef5c:	91006021 	add	x1, x1, #0x18
    8020ef60:	8b0300a2 	add	x2, x5, x3
    8020ef64:	8b030021 	add	x1, x1, x3
    8020ef68:	14000003 	b	8020ef74 <__mcmp+0x34>
    8020ef6c:	eb0200bf 	cmp	x5, x2
    8020ef70:	540000e2 	b.cs	8020ef8c <__mcmp+0x4c>  // b.hs, b.nlast
    8020ef74:	b85fcc44 	ldr	w4, [x2, #-4]!
    8020ef78:	b85fcc23 	ldr	w3, [x1, #-4]!
    8020ef7c:	6b03009f 	cmp	w4, w3
    8020ef80:	54ffff60 	b.eq	8020ef6c <__mcmp+0x2c>  // b.none
    8020ef84:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020ef88:	1a9f3400 	csinc	w0, w0, wzr, cc	// cc = lo, ul, last
    8020ef8c:	d65f03c0 	ret

000000008020ef90 <__mdiff>:
    8020ef90:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020ef94:	910003fd 	mov	x29, sp
    8020ef98:	a90153f3 	stp	x19, x20, [sp, #16]
    8020ef9c:	aa0103f3 	mov	x19, x1
    8020efa0:	aa0203f4 	mov	x20, x2
    8020efa4:	b9401421 	ldr	w1, [x1, #20]
    8020efa8:	b9401442 	ldr	w2, [x2, #20]
    8020efac:	f90013f5 	str	x21, [sp, #32]
    8020efb0:	6b020021 	subs	w1, w1, w2
    8020efb4:	35000241 	cbnz	w1, 8020effc <__mdiff+0x6c>
    8020efb8:	937e7c42 	sbfiz	x2, x2, #2, #32
    8020efbc:	91006261 	add	x1, x19, #0x18
    8020efc0:	91006284 	add	x4, x20, #0x18
    8020efc4:	8b020023 	add	x3, x1, x2
    8020efc8:	8b020084 	add	x4, x4, x2
    8020efcc:	14000003 	b	8020efd8 <__mdiff+0x48>
    8020efd0:	eb03003f 	cmp	x1, x3
    8020efd4:	54000a62 	b.cs	8020f120 <__mdiff+0x190>  // b.hs, b.nlast
    8020efd8:	b85fcc66 	ldr	w6, [x3, #-4]!
    8020efdc:	b85fcc85 	ldr	w5, [x4, #-4]!
    8020efe0:	6b0500df 	cmp	w6, w5
    8020efe4:	54ffff60 	b.eq	8020efd0 <__mdiff+0x40>  // b.none
    8020efe8:	aa1403e1 	mov	x1, x20
    8020efec:	1a9f27f5 	cset	w21, cc	// cc = lo, ul, last
    8020eff0:	9a933294 	csel	x20, x20, x19, cc	// cc = lo, ul, last
    8020eff4:	9a813273 	csel	x19, x19, x1, cc	// cc = lo, ul, last
    8020eff8:	14000005 	b	8020f00c <__mdiff+0x7c>
    8020effc:	aa1403e1 	mov	x1, x20
    8020f000:	1a9f57f5 	cset	w21, mi	// mi = first
    8020f004:	9a934294 	csel	x20, x20, x19, mi	// mi = first
    8020f008:	9a814273 	csel	x19, x19, x1, mi	// mi = first
    8020f00c:	b9400a81 	ldr	w1, [x20, #8]
    8020f010:	97fffd78 	bl	8020e5f0 <_Balloc>
    8020f014:	b4000b00 	cbz	x0, 8020f174 <__mdiff+0x1e4>
    8020f018:	b9801668 	ldrsw	x8, [x19, #20]
    8020f01c:	91006289 	add	x9, x20, #0x18
    8020f020:	b9401687 	ldr	w7, [x20, #20]
    8020f024:	91006262 	add	x2, x19, #0x18
    8020f028:	9100600b 	add	x11, x0, #0x18
    8020f02c:	d2800305 	mov	x5, #0x18                  	// #24
    8020f030:	8b080848 	add	x8, x2, x8, lsl #2
    8020f034:	52800001 	mov	w1, #0x0                   	// #0
    8020f038:	8b27c92a 	add	x10, x9, w7, sxtw #2
    8020f03c:	b9001015 	str	w21, [x0, #16]
    8020f040:	b8656a86 	ldr	w6, [x20, x5]
    8020f044:	b8656a64 	ldr	w4, [x19, x5]
    8020f048:	12003cc3 	and	w3, w6, #0xffff
    8020f04c:	53107cc6 	lsr	w6, w6, #16
    8020f050:	4b242063 	sub	w3, w3, w4, uxth
    8020f054:	4b4440c4 	sub	w4, w6, w4, lsr #16
    8020f058:	0b010063 	add	w3, w3, w1
    8020f05c:	0b834084 	add	w4, w4, w3, asr #16
    8020f060:	33103c83 	bfi	w3, w4, #16, #16
    8020f064:	b8256803 	str	w3, [x0, x5]
    8020f068:	910010a5 	add	x5, x5, #0x4
    8020f06c:	13107c81 	asr	w1, w4, #16
    8020f070:	8b050264 	add	x4, x19, x5
    8020f074:	eb04011f 	cmp	x8, x4
    8020f078:	54fffe48 	b.hi	8020f040 <__mdiff+0xb0>  // b.pmore
    8020f07c:	cb130104 	sub	x4, x8, x19
    8020f080:	91006662 	add	x2, x19, #0x19
    8020f084:	d1006484 	sub	x4, x4, #0x19
    8020f088:	eb02011f 	cmp	x8, x2
    8020f08c:	1a9f37e6 	cset	w6, cs	// cs = hs, nlast
    8020f090:	d2800088 	mov	x8, #0x4                   	// #4
    8020f094:	d342fc82 	lsr	x2, x4, #2
    8020f098:	710000df 	cmp	w6, #0x0
    8020f09c:	91000445 	add	x5, x2, #0x1
    8020f0a0:	d37ef4a5 	lsl	x5, x5, #2
    8020f0a4:	9a8810a5 	csel	x5, x5, x8, ne	// ne = any
    8020f0a8:	8b050128 	add	x8, x9, x5
    8020f0ac:	8b050165 	add	x5, x11, x5
    8020f0b0:	eb08015f 	cmp	x10, x8
    8020f0b4:	54000489 	b.ls	8020f144 <__mdiff+0x1b4>  // b.plast
    8020f0b8:	d100054a 	sub	x10, x10, #0x1
    8020f0bc:	d2800004 	mov	x4, #0x0                   	// #0
    8020f0c0:	cb08014a 	sub	x10, x10, x8
    8020f0c4:	d342fd49 	lsr	x9, x10, #2
    8020f0c8:	b8647902 	ldr	w2, [x8, x4, lsl #2]
    8020f0cc:	eb04013f 	cmp	x9, x4
    8020f0d0:	0b010043 	add	w3, w2, w1
    8020f0d4:	0b222021 	add	w1, w1, w2, uxth
    8020f0d8:	53107c42 	lsr	w2, w2, #16
    8020f0dc:	0b814041 	add	w1, w2, w1, asr #16
    8020f0e0:	33103c23 	bfi	w3, w1, #16, #16
    8020f0e4:	b82478a3 	str	w3, [x5, x4, lsl #2]
    8020f0e8:	13107c21 	asr	w1, w1, #16
    8020f0ec:	91000484 	add	x4, x4, #0x1
    8020f0f0:	54fffec1 	b.ne	8020f0c8 <__mdiff+0x138>  // b.any
    8020f0f4:	927ef54a 	and	x10, x10, #0xfffffffffffffffc
    8020f0f8:	8b0a00a1 	add	x1, x5, x10
    8020f0fc:	35000083 	cbnz	w3, 8020f10c <__mdiff+0x17c>
    8020f100:	b85fcc22 	ldr	w2, [x1, #-4]!
    8020f104:	510004e7 	sub	w7, w7, #0x1
    8020f108:	34ffffc2 	cbz	w2, 8020f100 <__mdiff+0x170>
    8020f10c:	b9001407 	str	w7, [x0, #20]
    8020f110:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f114:	f94013f5 	ldr	x21, [sp, #32]
    8020f118:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020f11c:	d65f03c0 	ret
    8020f120:	52800001 	mov	w1, #0x0                   	// #0
    8020f124:	97fffd33 	bl	8020e5f0 <_Balloc>
    8020f128:	b4000180 	cbz	x0, 8020f158 <__mdiff+0x1c8>
    8020f12c:	d2800021 	mov	x1, #0x1                   	// #1
    8020f130:	f8014001 	stur	x1, [x0, #20]
    8020f134:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f138:	f94013f5 	ldr	x21, [sp, #32]
    8020f13c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020f140:	d65f03c0 	ret
    8020f144:	d37ef442 	lsl	x2, x2, #2
    8020f148:	710000df 	cmp	w6, #0x0
    8020f14c:	9a9f1042 	csel	x2, x2, xzr, ne	// ne = any
    8020f150:	8b020161 	add	x1, x11, x2
    8020f154:	17ffffea 	b	8020f0fc <__mdiff+0x16c>
    8020f158:	b0000003 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020f15c:	b0000000 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020f160:	911ba063 	add	x3, x3, #0x6e8
    8020f164:	911e8000 	add	x0, x0, #0x7a0
    8020f168:	d2800002 	mov	x2, #0x0                   	// #0
    8020f16c:	528046e1 	mov	w1, #0x237                 	// #567
    8020f170:	97fffcc4 	bl	8020e480 <__assert_func>
    8020f174:	b0000003 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020f178:	b0000000 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020f17c:	911ba063 	add	x3, x3, #0x6e8
    8020f180:	911e8000 	add	x0, x0, #0x7a0
    8020f184:	d2800002 	mov	x2, #0x0                   	// #0
    8020f188:	528048a1 	mov	w1, #0x245                 	// #581
    8020f18c:	97fffcbd 	bl	8020e480 <__assert_func>

000000008020f190 <__ulp>:
    8020f190:	9e660000 	fmov	x0, d0
    8020f194:	52bf9801 	mov	w1, #0xfcc00000            	// #-54525952
    8020f198:	d360fc00 	lsr	x0, x0, #32
    8020f19c:	120c2800 	and	w0, w0, #0x7ff00000
    8020f1a0:	0b010000 	add	w0, w0, w1
    8020f1a4:	52800001 	mov	w1, #0x0                   	// #0
    8020f1a8:	7100001f 	cmp	w0, #0x0
    8020f1ac:	540000ad 	b.le	8020f1c0 <__ulp+0x30>
    8020f1b0:	2a0103e1 	mov	w1, w1
    8020f1b4:	aa008020 	orr	x0, x1, x0, lsl #32
    8020f1b8:	9e670000 	fmov	d0, x0
    8020f1bc:	d65f03c0 	ret
    8020f1c0:	4b0003e0 	neg	w0, w0
    8020f1c4:	13147c00 	asr	w0, w0, #20
    8020f1c8:	71004c1f 	cmp	w0, #0x13
    8020f1cc:	5400010c 	b.gt	8020f1ec <__ulp+0x5c>
    8020f1d0:	52a00102 	mov	w2, #0x80000               	// #524288
    8020f1d4:	52800001 	mov	w1, #0x0                   	// #0
    8020f1d8:	1ac02840 	asr	w0, w2, w0
    8020f1dc:	2a0103e1 	mov	w1, w1
    8020f1e0:	aa008020 	orr	x0, x1, x0, lsl #32
    8020f1e4:	9e670000 	fmov	d0, x0
    8020f1e8:	d65f03c0 	ret
    8020f1ec:	51005002 	sub	w2, w0, #0x14
    8020f1f0:	52b00001 	mov	w1, #0x80000000            	// #-2147483648
    8020f1f4:	71007c5f 	cmp	w2, #0x1f
    8020f1f8:	52800000 	mov	w0, #0x0                   	// #0
    8020f1fc:	1ac22421 	lsr	w1, w1, w2
    8020f200:	1a9fb421 	csinc	w1, w1, wzr, lt	// lt = tstop
    8020f204:	2a0103e1 	mov	w1, w1
    8020f208:	aa008020 	orr	x0, x1, x0, lsl #32
    8020f20c:	9e670000 	fmov	d0, x0
    8020f210:	d65f03c0 	ret
	...

000000008020f220 <__b2d>:
    8020f220:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020f224:	91006006 	add	x6, x0, #0x18
    8020f228:	aa0103e5 	mov	x5, x1
    8020f22c:	910003fd 	mov	x29, sp
    8020f230:	b9801404 	ldrsw	x4, [x0, #20]
    8020f234:	8b0408c4 	add	x4, x6, x4, lsl #2
    8020f238:	d1001087 	sub	x7, x4, #0x4
    8020f23c:	b85fc083 	ldur	w3, [x4, #-4]
    8020f240:	2a0303e0 	mov	w0, w3
    8020f244:	97fffda7 	bl	8020e8e0 <__hi0bits>
    8020f248:	52800401 	mov	w1, #0x20                  	// #32
    8020f24c:	4b000022 	sub	w2, w1, w0
    8020f250:	b90000a2 	str	w2, [x5]
    8020f254:	7100281f 	cmp	w0, #0xa
    8020f258:	5400056d 	b.le	8020f304 <__b2d+0xe4>
    8020f25c:	51002c05 	sub	w5, w0, #0xb
    8020f260:	eb0700df 	cmp	x6, x7
    8020f264:	540002a2 	b.cs	8020f2b8 <__b2d+0x98>  // b.hs, b.nlast
    8020f268:	b85f8080 	ldur	w0, [x4, #-8]
    8020f26c:	340003e5 	cbz	w5, 8020f2e8 <__b2d+0xc8>
    8020f270:	4b050022 	sub	w2, w1, w5
    8020f274:	1ac52063 	lsl	w3, w3, w5
    8020f278:	d2800001 	mov	x1, #0x0                   	// #0
    8020f27c:	d1002087 	sub	x7, x4, #0x8
    8020f280:	1ac22408 	lsr	w8, w0, w2
    8020f284:	2a080063 	orr	w3, w3, w8
    8020f288:	320c2463 	orr	w3, w3, #0x3ff00000
    8020f28c:	1ac52000 	lsl	w0, w0, w5
    8020f290:	b3607c61 	bfi	x1, x3, #32, #32
    8020f294:	eb0700df 	cmp	x6, x7
    8020f298:	540002e2 	b.cs	8020f2f4 <__b2d+0xd4>  // b.hs, b.nlast
    8020f29c:	b85f4083 	ldur	w3, [x4, #-12]
    8020f2a0:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020f2a4:	1ac22462 	lsr	w2, w3, w2
    8020f2a8:	2a020000 	orr	w0, w0, w2
    8020f2ac:	b3407c01 	bfxil	x1, x0, #0, #32
    8020f2b0:	9e670020 	fmov	d0, x1
    8020f2b4:	d65f03c0 	ret
    8020f2b8:	71002c1f 	cmp	w0, #0xb
    8020f2bc:	54000140 	b.eq	8020f2e4 <__b2d+0xc4>  // b.none
    8020f2c0:	1ac52063 	lsl	w3, w3, w5
    8020f2c4:	320c2463 	orr	w3, w3, #0x3ff00000
    8020f2c8:	d2800001 	mov	x1, #0x0                   	// #0
    8020f2cc:	52800000 	mov	w0, #0x0                   	// #0
    8020f2d0:	b3607c61 	bfi	x1, x3, #32, #32
    8020f2d4:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020f2d8:	b3407c01 	bfxil	x1, x0, #0, #32
    8020f2dc:	9e670020 	fmov	d0, x1
    8020f2e0:	d65f03c0 	ret
    8020f2e4:	52800000 	mov	w0, #0x0                   	// #0
    8020f2e8:	320c2463 	orr	w3, w3, #0x3ff00000
    8020f2ec:	d2800001 	mov	x1, #0x0                   	// #0
    8020f2f0:	b3607c61 	bfi	x1, x3, #32, #32
    8020f2f4:	b3407c01 	bfxil	x1, x0, #0, #32
    8020f2f8:	9e670020 	fmov	d0, x1
    8020f2fc:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020f300:	d65f03c0 	ret
    8020f304:	52800165 	mov	w5, #0xb                   	// #11
    8020f308:	4b0000a5 	sub	w5, w5, w0
    8020f30c:	d2800001 	mov	x1, #0x0                   	// #0
    8020f310:	52800002 	mov	w2, #0x0                   	// #0
    8020f314:	1ac52468 	lsr	w8, w3, w5
    8020f318:	320c2508 	orr	w8, w8, #0x3ff00000
    8020f31c:	b3607d01 	bfi	x1, x8, #32, #32
    8020f320:	eb0700df 	cmp	x6, x7
    8020f324:	54000062 	b.cs	8020f330 <__b2d+0x110>  // b.hs, b.nlast
    8020f328:	b85f8082 	ldur	w2, [x4, #-8]
    8020f32c:	1ac52442 	lsr	w2, w2, w5
    8020f330:	11005400 	add	w0, w0, #0x15
    8020f334:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020f338:	1ac02063 	lsl	w3, w3, w0
    8020f33c:	2a020060 	orr	w0, w3, w2
    8020f340:	b3407c01 	bfxil	x1, x0, #0, #32
    8020f344:	9e670020 	fmov	d0, x1
    8020f348:	d65f03c0 	ret
    8020f34c:	00000000 	udf	#0

000000008020f350 <__d2b>:
    8020f350:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020f354:	910003fd 	mov	x29, sp
    8020f358:	fd0013e8 	str	d8, [sp, #32]
    8020f35c:	1e604008 	fmov	d8, d0
    8020f360:	a90153f3 	stp	x19, x20, [sp, #16]
    8020f364:	aa0103f4 	mov	x20, x1
    8020f368:	aa0203f3 	mov	x19, x2
    8020f36c:	52800021 	mov	w1, #0x1                   	// #1
    8020f370:	97fffca0 	bl	8020e5f0 <_Balloc>
    8020f374:	b40007e0 	cbz	x0, 8020f470 <__d2b+0x120>
    8020f378:	9e660103 	fmov	x3, d8
    8020f37c:	aa0003e4 	mov	x4, x0
    8020f380:	d374f865 	ubfx	x5, x3, #52, #11
    8020f384:	d360cc60 	ubfx	x0, x3, #32, #20
    8020f388:	320c0001 	orr	w1, w0, #0x100000
    8020f38c:	710000bf 	cmp	w5, #0x0
    8020f390:	1a801020 	csel	w0, w1, w0, ne	// ne = any
    8020f394:	b9003fe0 	str	w0, [sp, #60]
    8020f398:	35000283 	cbnz	w3, 8020f3e8 <__d2b+0x98>
    8020f39c:	9100f3e0 	add	x0, sp, #0x3c
    8020f3a0:	97fffd70 	bl	8020e960 <__lo0bits>
    8020f3a4:	b9403fe1 	ldr	w1, [sp, #60]
    8020f3a8:	52800023 	mov	w3, #0x1                   	// #1
    8020f3ac:	b9001483 	str	w3, [x4, #20]
    8020f3b0:	11008000 	add	w0, w0, #0x20
    8020f3b4:	b9001881 	str	w1, [x4, #24]
    8020f3b8:	340003a5 	cbz	w5, 8020f42c <__d2b+0xdc>
    8020f3bc:	5110cca5 	sub	w5, w5, #0x433
    8020f3c0:	fd4013e8 	ldr	d8, [sp, #32]
    8020f3c4:	0b0000a5 	add	w5, w5, w0
    8020f3c8:	b9000285 	str	w5, [x20]
    8020f3cc:	528006a3 	mov	w3, #0x35                  	// #53
    8020f3d0:	4b000063 	sub	w3, w3, w0
    8020f3d4:	b9000263 	str	w3, [x19]
    8020f3d8:	aa0403e0 	mov	x0, x4
    8020f3dc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f3e0:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020f3e4:	d65f03c0 	ret
    8020f3e8:	9100e3e0 	add	x0, sp, #0x38
    8020f3ec:	bd003be8 	str	s8, [sp, #56]
    8020f3f0:	97fffd5c 	bl	8020e960 <__lo0bits>
    8020f3f4:	b9403fe1 	ldr	w1, [sp, #60]
    8020f3f8:	34000380 	cbz	w0, 8020f468 <__d2b+0x118>
    8020f3fc:	b9403be3 	ldr	w3, [sp, #56]
    8020f400:	4b0003e2 	neg	w2, w0
    8020f404:	1ac22022 	lsl	w2, w1, w2
    8020f408:	2a030042 	orr	w2, w2, w3
    8020f40c:	1ac02421 	lsr	w1, w1, w0
    8020f410:	b9003fe1 	str	w1, [sp, #60]
    8020f414:	7100003f 	cmp	w1, #0x0
    8020f418:	29030482 	stp	w2, w1, [x4, #24]
    8020f41c:	1a9f07e3 	cset	w3, ne	// ne = any
    8020f420:	11000463 	add	w3, w3, #0x1
    8020f424:	b9001483 	str	w3, [x4, #20]
    8020f428:	35fffca5 	cbnz	w5, 8020f3bc <__d2b+0x6c>
    8020f42c:	92800061 	mov	x1, #0xfffffffffffffffc    	// #-4
    8020f430:	5110c800 	sub	w0, w0, #0x432
    8020f434:	8b23c821 	add	x1, x1, w3, sxtw #2
    8020f438:	b9000280 	str	w0, [x20]
    8020f43c:	8b010080 	add	x0, x4, x1
    8020f440:	531b6863 	lsl	w3, w3, #5
    8020f444:	b9401800 	ldr	w0, [x0, #24]
    8020f448:	97fffd26 	bl	8020e8e0 <__hi0bits>
    8020f44c:	fd4013e8 	ldr	d8, [sp, #32]
    8020f450:	4b000063 	sub	w3, w3, w0
    8020f454:	b9000263 	str	w3, [x19]
    8020f458:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f45c:	aa0403e0 	mov	x0, x4
    8020f460:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020f464:	d65f03c0 	ret
    8020f468:	b9403be2 	ldr	w2, [sp, #56]
    8020f46c:	17ffffea 	b	8020f414 <__d2b+0xc4>
    8020f470:	b0000003 	adrp	x3, 80210000 <__trunctfdf2+0xc0>
    8020f474:	b0000000 	adrp	x0, 80210000 <__trunctfdf2+0xc0>
    8020f478:	911ba063 	add	x3, x3, #0x6e8
    8020f47c:	911e8000 	add	x0, x0, #0x7a0
    8020f480:	d2800002 	mov	x2, #0x0                   	// #0
    8020f484:	528061e1 	mov	w1, #0x30f                 	// #783
    8020f488:	97fffbfe 	bl	8020e480 <__assert_func>
    8020f48c:	00000000 	udf	#0

000000008020f490 <__ratio>:
    8020f490:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020f494:	aa0103e9 	mov	x9, x1
    8020f498:	aa0003ea 	mov	x10, x0
    8020f49c:	910003fd 	mov	x29, sp
    8020f4a0:	910063e1 	add	x1, sp, #0x18
    8020f4a4:	97ffff5f 	bl	8020f220 <__b2d>
    8020f4a8:	910073e1 	add	x1, sp, #0x1c
    8020f4ac:	aa0903e0 	mov	x0, x9
    8020f4b0:	1e604001 	fmov	d1, d0
    8020f4b4:	9e66000b 	fmov	x11, d0
    8020f4b8:	97ffff5a 	bl	8020f220 <__b2d>
    8020f4bc:	b9401523 	ldr	w3, [x9, #20]
    8020f4c0:	b9401540 	ldr	w0, [x10, #20]
    8020f4c4:	29430be1 	ldp	w1, w2, [sp, #24]
    8020f4c8:	4b030000 	sub	w0, w0, w3
    8020f4cc:	4b020021 	sub	w1, w1, w2
    8020f4d0:	0b001420 	add	w0, w1, w0, lsl #5
    8020f4d4:	7100001f 	cmp	w0, #0x0
    8020f4d8:	5400010d 	b.le	8020f4f8 <__ratio+0x68>
    8020f4dc:	d360fd61 	lsr	x1, x11, #32
    8020f4e0:	0b005020 	add	w0, w1, w0, lsl #20
    8020f4e4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020f4e8:	b3607c0b 	bfi	x11, x0, #32, #32
    8020f4ec:	9e670161 	fmov	d1, x11
    8020f4f0:	1e601820 	fdiv	d0, d1, d0
    8020f4f4:	d65f03c0 	ret
    8020f4f8:	9e660001 	fmov	x1, d0
    8020f4fc:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020f500:	d360fc22 	lsr	x2, x1, #32
    8020f504:	4b005040 	sub	w0, w2, w0, lsl #20
    8020f508:	b3607c01 	bfi	x1, x0, #32, #32
    8020f50c:	9e670020 	fmov	d0, x1
    8020f510:	1e601820 	fdiv	d0, d1, d0
    8020f514:	d65f03c0 	ret
	...

000000008020f520 <_mprec_log10>:
    8020f520:	1e6e1000 	fmov	d0, #1.000000000000000000e+00
    8020f524:	1e649001 	fmov	d1, #1.000000000000000000e+01
    8020f528:	71005c1f 	cmp	w0, #0x17
    8020f52c:	540000ad 	b.le	8020f540 <_mprec_log10+0x20>
    8020f530:	1e610800 	fmul	d0, d0, d1
    8020f534:	71000400 	subs	w0, w0, #0x1
    8020f538:	54ffffc1 	b.ne	8020f530 <_mprec_log10+0x10>  // b.any
    8020f53c:	d65f03c0 	ret
    8020f540:	b0000001 	adrp	x1, 80210000 <__trunctfdf2+0xc0>
    8020f544:	913a0021 	add	x1, x1, #0xe80
    8020f548:	fc60d820 	ldr	d0, [x1, w0, sxtw #3]
    8020f54c:	d65f03c0 	ret

000000008020f550 <__copybits>:
    8020f550:	51000421 	sub	w1, w1, #0x1
    8020f554:	91006046 	add	x6, x2, #0x18
    8020f558:	13057c24 	asr	w4, w1, #5
    8020f55c:	b9801441 	ldrsw	x1, [x2, #20]
    8020f560:	11000484 	add	w4, w4, #0x1
    8020f564:	8b0108c1 	add	x1, x6, x1, lsl #2
    8020f568:	8b24c804 	add	x4, x0, w4, sxtw #2
    8020f56c:	eb0100df 	cmp	x6, x1
    8020f570:	540001e2 	b.cs	8020f5ac <__copybits+0x5c>  // b.hs, b.nlast
    8020f574:	cb020023 	sub	x3, x1, x2
    8020f578:	d2800001 	mov	x1, #0x0                   	// #0
    8020f57c:	d1006463 	sub	x3, x3, #0x19
    8020f580:	d342fc63 	lsr	x3, x3, #2
    8020f584:	91000467 	add	x7, x3, #0x1
    8020f588:	b86178c5 	ldr	w5, [x6, x1, lsl #2]
    8020f58c:	eb03003f 	cmp	x1, x3
    8020f590:	b8217805 	str	w5, [x0, x1, lsl #2]
    8020f594:	91000421 	add	x1, x1, #0x1
    8020f598:	54ffff81 	b.ne	8020f588 <__copybits+0x38>  // b.any
    8020f59c:	8b070800 	add	x0, x0, x7, lsl #2
    8020f5a0:	eb00009f 	cmp	x4, x0
    8020f5a4:	54000089 	b.ls	8020f5b4 <__copybits+0x64>  // b.plast
    8020f5a8:	b800441f 	str	wzr, [x0], #4
    8020f5ac:	eb00009f 	cmp	x4, x0
    8020f5b0:	54ffffc8 	b.hi	8020f5a8 <__copybits+0x58>  // b.pmore
    8020f5b4:	d65f03c0 	ret
	...

000000008020f5c0 <__any_on>:
    8020f5c0:	91006003 	add	x3, x0, #0x18
    8020f5c4:	b9401400 	ldr	w0, [x0, #20]
    8020f5c8:	13057c22 	asr	w2, w1, #5
    8020f5cc:	6b02001f 	cmp	w0, w2
    8020f5d0:	5400012a 	b.ge	8020f5f4 <__any_on+0x34>  // b.tcont
    8020f5d4:	8b20c862 	add	x2, x3, w0, sxtw #2
    8020f5d8:	14000003 	b	8020f5e4 <__any_on+0x24>
    8020f5dc:	b85fcc40 	ldr	w0, [x2, #-4]!
    8020f5e0:	35000220 	cbnz	w0, 8020f624 <__any_on+0x64>
    8020f5e4:	eb03005f 	cmp	x2, x3
    8020f5e8:	54ffffa8 	b.hi	8020f5dc <__any_on+0x1c>  // b.pmore
    8020f5ec:	52800000 	mov	w0, #0x0                   	// #0
    8020f5f0:	d65f03c0 	ret
    8020f5f4:	93407c40 	sxtw	x0, w2
    8020f5f8:	8b22c862 	add	x2, x3, w2, sxtw #2
    8020f5fc:	54ffff4d 	b.le	8020f5e4 <__any_on+0x24>
    8020f600:	72001021 	ands	w1, w1, #0x1f
    8020f604:	54ffff00 	b.eq	8020f5e4 <__any_on+0x24>  // b.none
    8020f608:	b8607865 	ldr	w5, [x3, x0, lsl #2]
    8020f60c:	52800020 	mov	w0, #0x1                   	// #1
    8020f610:	1ac124a4 	lsr	w4, w5, w1
    8020f614:	1ac12081 	lsl	w1, w4, w1
    8020f618:	6b0100bf 	cmp	w5, w1
    8020f61c:	54fffe40 	b.eq	8020f5e4 <__any_on+0x24>  // b.none
    8020f620:	d65f03c0 	ret
    8020f624:	52800020 	mov	w0, #0x1                   	// #1
    8020f628:	d65f03c0 	ret
    8020f62c:	00000000 	udf	#0

000000008020f630 <_calloc_r>:
    8020f630:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020f634:	9bc27c23 	umulh	x3, x1, x2
    8020f638:	9b027c21 	mul	x1, x1, x2
    8020f63c:	910003fd 	mov	x29, sp
    8020f640:	f9000bf3 	str	x19, [sp, #16]
    8020f644:	b5000463 	cbnz	x3, 8020f6d0 <_calloc_r+0xa0>
    8020f648:	97ffe4fe 	bl	80208a40 <_malloc_r>
    8020f64c:	aa0003f3 	mov	x19, x0
    8020f650:	b4000460 	cbz	x0, 8020f6dc <_calloc_r+0xac>
    8020f654:	f85f8002 	ldur	x2, [x0, #-8]
    8020f658:	927ef442 	and	x2, x2, #0xfffffffffffffffc
    8020f65c:	d1002042 	sub	x2, x2, #0x8
    8020f660:	f101205f 	cmp	x2, #0x48
    8020f664:	540001c8 	b.hi	8020f69c <_calloc_r+0x6c>  // b.pmore
    8020f668:	f1009c5f 	cmp	x2, #0x27
    8020f66c:	540000c9 	b.ls	8020f684 <_calloc_r+0x54>  // b.plast
    8020f670:	4f000400 	movi	v0.4s, #0x0
    8020f674:	91004000 	add	x0, x0, #0x10
    8020f678:	3c9f0000 	stur	q0, [x0, #-16]
    8020f67c:	f100dc5f 	cmp	x2, #0x37
    8020f680:	540001a8 	b.hi	8020f6b4 <_calloc_r+0x84>  // b.pmore
    8020f684:	a9007c1f 	stp	xzr, xzr, [x0]
    8020f688:	f900081f 	str	xzr, [x0, #16]
    8020f68c:	aa1303e0 	mov	x0, x19
    8020f690:	f9400bf3 	ldr	x19, [sp, #16]
    8020f694:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020f698:	d65f03c0 	ret
    8020f69c:	52800001 	mov	w1, #0x0                   	// #0
    8020f6a0:	97ffce08 	bl	80202ec0 <memset>
    8020f6a4:	aa1303e0 	mov	x0, x19
    8020f6a8:	f9400bf3 	ldr	x19, [sp, #16]
    8020f6ac:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020f6b0:	d65f03c0 	ret
    8020f6b4:	3d800660 	str	q0, [x19, #16]
    8020f6b8:	91008260 	add	x0, x19, #0x20
    8020f6bc:	f101205f 	cmp	x2, #0x48
    8020f6c0:	54fffe21 	b.ne	8020f684 <_calloc_r+0x54>  // b.any
    8020f6c4:	9100c260 	add	x0, x19, #0x30
    8020f6c8:	3d800a60 	str	q0, [x19, #32]
    8020f6cc:	17ffffee 	b	8020f684 <_calloc_r+0x54>
    8020f6d0:	97ffcc4c 	bl	80202800 <__errno>
    8020f6d4:	52800181 	mov	w1, #0xc                   	// #12
    8020f6d8:	b9000001 	str	w1, [x0]
    8020f6dc:	d2800013 	mov	x19, #0x0                   	// #0
    8020f6e0:	aa1303e0 	mov	x0, x19
    8020f6e4:	f9400bf3 	ldr	x19, [sp, #16]
    8020f6e8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020f6ec:	d65f03c0 	ret

000000008020f6f0 <_wcsnrtombs_l>:
    8020f6f0:	a9b87bfd 	stp	x29, x30, [sp, #-128]!
    8020f6f4:	f10000bf 	cmp	x5, #0x0
    8020f6f8:	910003fd 	mov	x29, sp
    8020f6fc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020f700:	aa0003f4 	mov	x20, x0
    8020f704:	91051000 	add	x0, x0, #0x144
    8020f708:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020f70c:	aa0203f6 	mov	x22, x2
    8020f710:	aa0103f5 	mov	x21, x1
    8020f714:	a90363f7 	stp	x23, x24, [sp, #48]
    8020f718:	aa0603f7 	mov	x23, x6
    8020f71c:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020f720:	9a850019 	csel	x25, x0, x5, eq	// eq = none
    8020f724:	a90573fb 	stp	x27, x28, [sp, #80]
    8020f728:	f940005c 	ldr	x28, [x2]
    8020f72c:	b4000901 	cbz	x1, 8020f84c <_wcsnrtombs_l+0x15c>
    8020f730:	aa0403f3 	mov	x19, x4
    8020f734:	b4000a84 	cbz	x4, 8020f884 <_wcsnrtombs_l+0x194>
    8020f738:	d100047a 	sub	x26, x3, #0x1
    8020f73c:	b4000a43 	cbz	x3, 8020f884 <_wcsnrtombs_l+0x194>
    8020f740:	d280001b 	mov	x27, #0x0                   	// #0
    8020f744:	f90037f5 	str	x21, [sp, #104]
    8020f748:	1400000a 	b	8020f770 <_wcsnrtombs_l+0x80>
    8020f74c:	b50003f5 	cbnz	x21, 8020f7c8 <_wcsnrtombs_l+0xd8>
    8020f750:	b8404780 	ldr	w0, [x28], #4
    8020f754:	34000640 	cbz	w0, 8020f81c <_wcsnrtombs_l+0x12c>
    8020f758:	eb13009f 	cmp	x4, x19
    8020f75c:	54000982 	b.cs	8020f88c <_wcsnrtombs_l+0x19c>  // b.hs, b.nlast
    8020f760:	d100075a 	sub	x26, x26, #0x1
    8020f764:	aa0403fb 	mov	x27, x4
    8020f768:	b100075f 	cmn	x26, #0x1
    8020f76c:	540001e0 	b.eq	8020f7a8 <_wcsnrtombs_l+0xb8>  // b.none
    8020f770:	f94072e4 	ldr	x4, [x23, #224]
    8020f774:	aa1903e3 	mov	x3, x25
    8020f778:	b9400382 	ldr	w2, [x28]
    8020f77c:	9101c3e1 	add	x1, sp, #0x70
    8020f780:	f9400338 	ldr	x24, [x25]
    8020f784:	aa1403e0 	mov	x0, x20
    8020f788:	d63f0080 	blr	x4
    8020f78c:	3100041f 	cmn	w0, #0x1
    8020f790:	54000620 	b.eq	8020f854 <_wcsnrtombs_l+0x164>  // b.none
    8020f794:	93407c01 	sxtw	x1, w0
    8020f798:	8b1b0024 	add	x4, x1, x27
    8020f79c:	eb13009f 	cmp	x4, x19
    8020f7a0:	54fffd69 	b.ls	8020f74c <_wcsnrtombs_l+0x5c>  // b.plast
    8020f7a4:	f9000338 	str	x24, [x25]
    8020f7a8:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f7ac:	aa1b03e0 	mov	x0, x27
    8020f7b0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020f7b4:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020f7b8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020f7bc:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020f7c0:	a8c87bfd 	ldp	x29, x30, [sp], #128
    8020f7c4:	d65f03c0 	ret
    8020f7c8:	7100001f 	cmp	w0, #0x0
    8020f7cc:	540001ed 	b.le	8020f808 <_wcsnrtombs_l+0x118>
    8020f7d0:	f94037e2 	ldr	x2, [sp, #104]
    8020f7d4:	d2800027 	mov	x7, #0x1                   	// #1
    8020f7d8:	d1000443 	sub	x3, x2, #0x1
    8020f7dc:	d503201f 	nop
    8020f7e0:	9101c3e2 	add	x2, sp, #0x70
    8020f7e4:	eb07003f 	cmp	x1, x7
    8020f7e8:	8b070042 	add	x2, x2, x7
    8020f7ec:	385ff042 	ldurb	w2, [x2, #-1]
    8020f7f0:	38276862 	strb	w2, [x3, x7]
    8020f7f4:	910004e7 	add	x7, x7, #0x1
    8020f7f8:	54ffff41 	b.ne	8020f7e0 <_wcsnrtombs_l+0xf0>  // b.any
    8020f7fc:	f94037e1 	ldr	x1, [sp, #104]
    8020f800:	8b204020 	add	x0, x1, w0, uxtw
    8020f804:	f90037e0 	str	x0, [sp, #104]
    8020f808:	f94002c0 	ldr	x0, [x22]
    8020f80c:	91001000 	add	x0, x0, #0x4
    8020f810:	f90002c0 	str	x0, [x22]
    8020f814:	b8404780 	ldr	w0, [x28], #4
    8020f818:	35fffa00 	cbnz	w0, 8020f758 <_wcsnrtombs_l+0x68>
    8020f81c:	b4000055 	cbz	x21, 8020f824 <_wcsnrtombs_l+0x134>
    8020f820:	f90002df 	str	xzr, [x22]
    8020f824:	b900033f 	str	wzr, [x25]
    8020f828:	d100049b 	sub	x27, x4, #0x1
    8020f82c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f830:	aa1b03e0 	mov	x0, x27
    8020f834:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020f838:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020f83c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020f840:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020f844:	a8c87bfd 	ldp	x29, x30, [sp], #128
    8020f848:	d65f03c0 	ret
    8020f84c:	92800013 	mov	x19, #0xffffffffffffffff    	// #-1
    8020f850:	17ffffba 	b	8020f738 <_wcsnrtombs_l+0x48>
    8020f854:	52801140 	mov	w0, #0x8a                  	// #138
    8020f858:	b9000280 	str	w0, [x20]
    8020f85c:	b900033f 	str	wzr, [x25]
    8020f860:	9280001b 	mov	x27, #0xffffffffffffffff    	// #-1
    8020f864:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f868:	aa1b03e0 	mov	x0, x27
    8020f86c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020f870:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020f874:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020f878:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020f87c:	a8c87bfd 	ldp	x29, x30, [sp], #128
    8020f880:	d65f03c0 	ret
    8020f884:	d280001b 	mov	x27, #0x0                   	// #0
    8020f888:	17ffffc8 	b	8020f7a8 <_wcsnrtombs_l+0xb8>
    8020f88c:	aa0403fb 	mov	x27, x4
    8020f890:	17ffffc6 	b	8020f7a8 <_wcsnrtombs_l+0xb8>
	...

000000008020f8a0 <_wcsnrtombs_r>:
    8020f8a0:	d0000000 	adrp	x0, 80211000 <__mprec_tens+0x180>
    8020f8a4:	d0000006 	adrp	x6, 80211000 <__mprec_tens+0x180>
    8020f8a8:	912b40c6 	add	x6, x6, #0xad0
    8020f8ac:	f9402400 	ldr	x0, [x0, #72]
    8020f8b0:	17ffff90 	b	8020f6f0 <_wcsnrtombs_l>
	...

000000008020f8c0 <wcsnrtombs>:
    8020f8c0:	d0000006 	adrp	x6, 80211000 <__mprec_tens+0x180>
    8020f8c4:	aa0003e8 	mov	x8, x0
    8020f8c8:	aa0103e7 	mov	x7, x1
    8020f8cc:	aa0203e5 	mov	x5, x2
    8020f8d0:	f94024c0 	ldr	x0, [x6, #72]
    8020f8d4:	aa0303e6 	mov	x6, x3
    8020f8d8:	aa0803e1 	mov	x1, x8
    8020f8dc:	aa0503e3 	mov	x3, x5
    8020f8e0:	aa0703e2 	mov	x2, x7
    8020f8e4:	aa0403e5 	mov	x5, x4
    8020f8e8:	aa0603e4 	mov	x4, x6
    8020f8ec:	d0000006 	adrp	x6, 80211000 <__mprec_tens+0x180>
    8020f8f0:	912b40c6 	add	x6, x6, #0xad0
    8020f8f4:	17ffff7f 	b	8020f6f0 <_wcsnrtombs_l>
	...

000000008020f900 <__env_lock>:
    8020f900:	b0000380 	adrp	x0, 80280000 <gits_lock>
    8020f904:	910a6000 	add	x0, x0, #0x298
    8020f908:	17ffe6ae 	b	802093c0 <__retarget_lock_acquire_recursive>
    8020f90c:	00000000 	udf	#0

000000008020f910 <__env_unlock>:
    8020f910:	b0000380 	adrp	x0, 80280000 <gits_lock>
    8020f914:	910a6000 	add	x0, x0, #0x298
    8020f918:	17ffe6ba 	b	80209400 <__retarget_lock_release_recursive>
    8020f91c:	00000000 	udf	#0

000000008020f920 <_fiprintf_r>:
    8020f920:	a9b07bfd 	stp	x29, x30, [sp, #-256]!
    8020f924:	128004e9 	mov	w9, #0xffffffd8            	// #-40
    8020f928:	12800fe8 	mov	w8, #0xffffff80            	// #-128
    8020f92c:	910003fd 	mov	x29, sp
    8020f930:	910343ea 	add	x10, sp, #0xd0
    8020f934:	910403eb 	add	x11, sp, #0x100
    8020f938:	a9032feb 	stp	x11, x11, [sp, #48]
    8020f93c:	f90023ea 	str	x10, [sp, #64]
    8020f940:	290923e9 	stp	w9, w8, [sp, #72]
    8020f944:	3d8017e0 	str	q0, [sp, #80]
    8020f948:	ad41c3e0 	ldp	q0, q16, [sp, #48]
    8020f94c:	3d801be1 	str	q1, [sp, #96]
    8020f950:	3d801fe2 	str	q2, [sp, #112]
    8020f954:	ad00c3e0 	stp	q0, q16, [sp, #16]
    8020f958:	3d8023e3 	str	q3, [sp, #128]
    8020f95c:	3d8027e4 	str	q4, [sp, #144]
    8020f960:	3d802be5 	str	q5, [sp, #160]
    8020f964:	3d802fe6 	str	q6, [sp, #176]
    8020f968:	3d8033e7 	str	q7, [sp, #192]
    8020f96c:	a90d93e3 	stp	x3, x4, [sp, #216]
    8020f970:	910043e3 	add	x3, sp, #0x10
    8020f974:	a90e9be5 	stp	x5, x6, [sp, #232]
    8020f978:	f9007fe7 	str	x7, [sp, #248]
    8020f97c:	97ffdce5 	bl	80206d10 <_vfiprintf_r>
    8020f980:	a8d07bfd 	ldp	x29, x30, [sp], #256
    8020f984:	d65f03c0 	ret
	...

000000008020f990 <fiprintf>:
    8020f990:	a9b07bfd 	stp	x29, x30, [sp, #-256]!
    8020f994:	128005eb 	mov	w11, #0xffffffd0            	// #-48
    8020f998:	12800fea 	mov	w10, #0xffffff80            	// #-128
    8020f99c:	910003fd 	mov	x29, sp
    8020f9a0:	910403ec 	add	x12, sp, #0x100
    8020f9a4:	910343e8 	add	x8, sp, #0xd0
    8020f9a8:	d0000009 	adrp	x9, 80211000 <__mprec_tens+0x180>
    8020f9ac:	a90333ec 	stp	x12, x12, [sp, #48]
    8020f9b0:	f90023e8 	str	x8, [sp, #64]
    8020f9b4:	aa0103e8 	mov	x8, x1
    8020f9b8:	29092beb 	stp	w11, w10, [sp, #72]
    8020f9bc:	aa0003e1 	mov	x1, x0
    8020f9c0:	f9402520 	ldr	x0, [x9, #72]
    8020f9c4:	3d8017e0 	str	q0, [sp, #80]
    8020f9c8:	ad41c3e0 	ldp	q0, q16, [sp, #48]
    8020f9cc:	3d801be1 	str	q1, [sp, #96]
    8020f9d0:	3d801fe2 	str	q2, [sp, #112]
    8020f9d4:	ad00c3e0 	stp	q0, q16, [sp, #16]
    8020f9d8:	3d8023e3 	str	q3, [sp, #128]
    8020f9dc:	3d8027e4 	str	q4, [sp, #144]
    8020f9e0:	3d802be5 	str	q5, [sp, #160]
    8020f9e4:	3d802fe6 	str	q6, [sp, #176]
    8020f9e8:	3d8033e7 	str	q7, [sp, #192]
    8020f9ec:	a90d0fe2 	stp	x2, x3, [sp, #208]
    8020f9f0:	910043e3 	add	x3, sp, #0x10
    8020f9f4:	aa0803e2 	mov	x2, x8
    8020f9f8:	a90e17e4 	stp	x4, x5, [sp, #224]
    8020f9fc:	a90f1fe6 	stp	x6, x7, [sp, #240]
    8020fa00:	97ffdcc4 	bl	80206d10 <_vfiprintf_r>
    8020fa04:	a8d07bfd 	ldp	x29, x30, [sp], #256
    8020fa08:	d65f03c0 	ret
    8020fa0c:	00000000 	udf	#0

000000008020fa10 <abort>:
    8020fa10:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020fa14:	528000c0 	mov	w0, #0x6                   	// #6
    8020fa18:	910003fd 	mov	x29, sp
    8020fa1c:	94000099 	bl	8020fc80 <raise>
    8020fa20:	52800020 	mov	w0, #0x1                   	// #1
    8020fa24:	97ffc3e7 	bl	802009c0 <_exit>
	...

000000008020fa30 <_init_signal_r>:
    8020fa30:	f940a801 	ldr	x1, [x0, #336]
    8020fa34:	b4000061 	cbz	x1, 8020fa40 <_init_signal_r+0x10>
    8020fa38:	52800000 	mov	w0, #0x0                   	// #0
    8020fa3c:	d65f03c0 	ret
    8020fa40:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020fa44:	d2802001 	mov	x1, #0x100                 	// #256
    8020fa48:	910003fd 	mov	x29, sp
    8020fa4c:	f9000bf3 	str	x19, [sp, #16]
    8020fa50:	aa0003f3 	mov	x19, x0
    8020fa54:	97ffe3fb 	bl	80208a40 <_malloc_r>
    8020fa58:	f900aa60 	str	x0, [x19, #336]
    8020fa5c:	b4000140 	cbz	x0, 8020fa84 <_init_signal_r+0x54>
    8020fa60:	91040001 	add	x1, x0, #0x100
    8020fa64:	d503201f 	nop
    8020fa68:	f800841f 	str	xzr, [x0], #8
    8020fa6c:	eb01001f 	cmp	x0, x1
    8020fa70:	54ffffc1 	b.ne	8020fa68 <_init_signal_r+0x38>  // b.any
    8020fa74:	52800000 	mov	w0, #0x0                   	// #0
    8020fa78:	f9400bf3 	ldr	x19, [sp, #16]
    8020fa7c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fa80:	d65f03c0 	ret
    8020fa84:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020fa88:	17fffffc 	b	8020fa78 <_init_signal_r+0x48>
    8020fa8c:	00000000 	udf	#0

000000008020fa90 <_signal_r>:
    8020fa90:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020fa94:	910003fd 	mov	x29, sp
    8020fa98:	a90153f3 	stp	x19, x20, [sp, #16]
    8020fa9c:	93407c33 	sxtw	x19, w1
    8020faa0:	aa0003f4 	mov	x20, x0
    8020faa4:	71007e7f 	cmp	w19, #0x1f
    8020faa8:	54000108 	b.hi	8020fac8 <_signal_r+0x38>  // b.pmore
    8020faac:	f940a801 	ldr	x1, [x0, #336]
    8020fab0:	b4000141 	cbz	x1, 8020fad8 <_signal_r+0x48>
    8020fab4:	f8737820 	ldr	x0, [x1, x19, lsl #3]
    8020fab8:	f8337822 	str	x2, [x1, x19, lsl #3]
    8020fabc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fac0:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020fac4:	d65f03c0 	ret
    8020fac8:	528002c0 	mov	w0, #0x16                  	// #22
    8020facc:	b9000280 	str	w0, [x20]
    8020fad0:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    8020fad4:	17fffffa 	b	8020fabc <_signal_r+0x2c>
    8020fad8:	d2802001 	mov	x1, #0x100                 	// #256
    8020fadc:	f90017e2 	str	x2, [sp, #40]
    8020fae0:	97ffe3d8 	bl	80208a40 <_malloc_r>
    8020fae4:	f900aa80 	str	x0, [x20, #336]
    8020fae8:	f94017e2 	ldr	x2, [sp, #40]
    8020faec:	aa0003e1 	mov	x1, x0
    8020faf0:	b4ffff00 	cbz	x0, 8020fad0 <_signal_r+0x40>
    8020faf4:	91040003 	add	x3, x0, #0x100
    8020faf8:	f800841f 	str	xzr, [x0], #8
    8020fafc:	eb03001f 	cmp	x0, x3
    8020fb00:	54ffffc1 	b.ne	8020faf8 <_signal_r+0x68>  // b.any
    8020fb04:	17ffffec 	b	8020fab4 <_signal_r+0x24>
	...

000000008020fb10 <_raise_r>:
    8020fb10:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020fb14:	910003fd 	mov	x29, sp
    8020fb18:	a90153f3 	stp	x19, x20, [sp, #16]
    8020fb1c:	aa0003f4 	mov	x20, x0
    8020fb20:	71007c3f 	cmp	w1, #0x1f
    8020fb24:	54000408 	b.hi	8020fba4 <_raise_r+0x94>  // b.pmore
    8020fb28:	f940a800 	ldr	x0, [x0, #336]
    8020fb2c:	2a0103f3 	mov	w19, w1
    8020fb30:	b40001e0 	cbz	x0, 8020fb6c <_raise_r+0x5c>
    8020fb34:	93407c22 	sxtw	x2, w1
    8020fb38:	f8627801 	ldr	x1, [x0, x2, lsl #3]
    8020fb3c:	b4000181 	cbz	x1, 8020fb6c <_raise_r+0x5c>
    8020fb40:	f100043f 	cmp	x1, #0x1
    8020fb44:	540000c0 	b.eq	8020fb5c <_raise_r+0x4c>  // b.none
    8020fb48:	b100043f 	cmn	x1, #0x1
    8020fb4c:	54000200 	b.eq	8020fb8c <_raise_r+0x7c>  // b.none
    8020fb50:	f822781f 	str	xzr, [x0, x2, lsl #3]
    8020fb54:	2a1303e0 	mov	w0, w19
    8020fb58:	d63f0020 	blr	x1
    8020fb5c:	52800000 	mov	w0, #0x0                   	// #0
    8020fb60:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fb64:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fb68:	d65f03c0 	ret
    8020fb6c:	aa1403e0 	mov	x0, x20
    8020fb70:	940000f0 	bl	8020ff30 <_getpid_r>
    8020fb74:	2a1303e2 	mov	w2, w19
    8020fb78:	2a0003e1 	mov	w1, w0
    8020fb7c:	aa1403e0 	mov	x0, x20
    8020fb80:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fb84:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fb88:	140000d6 	b	8020fee0 <_kill_r>
    8020fb8c:	528002c1 	mov	w1, #0x16                  	// #22
    8020fb90:	b9000281 	str	w1, [x20]
    8020fb94:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fb98:	52800020 	mov	w0, #0x1                   	// #1
    8020fb9c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fba0:	d65f03c0 	ret
    8020fba4:	528002c1 	mov	w1, #0x16                  	// #22
    8020fba8:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020fbac:	b9000281 	str	w1, [x20]
    8020fbb0:	17ffffec 	b	8020fb60 <_raise_r+0x50>
	...

000000008020fbc0 <__sigtramp_r>:
    8020fbc0:	71007c3f 	cmp	w1, #0x1f
    8020fbc4:	540005a8 	b.hi	8020fc78 <__sigtramp_r+0xb8>  // b.pmore
    8020fbc8:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020fbcc:	910003fd 	mov	x29, sp
    8020fbd0:	a90153f3 	stp	x19, x20, [sp, #16]
    8020fbd4:	2a0103f3 	mov	w19, w1
    8020fbd8:	aa0003f4 	mov	x20, x0
    8020fbdc:	f940a801 	ldr	x1, [x0, #336]
    8020fbe0:	b4000321 	cbz	x1, 8020fc44 <__sigtramp_r+0x84>
    8020fbe4:	f873d822 	ldr	x2, [x1, w19, sxtw #3]
    8020fbe8:	8b33cc21 	add	x1, x1, w19, sxtw #3
    8020fbec:	b4000182 	cbz	x2, 8020fc1c <__sigtramp_r+0x5c>
    8020fbf0:	b100045f 	cmn	x2, #0x1
    8020fbf4:	54000240 	b.eq	8020fc3c <__sigtramp_r+0x7c>  // b.none
    8020fbf8:	f100045f 	cmp	x2, #0x1
    8020fbfc:	54000180 	b.eq	8020fc2c <__sigtramp_r+0x6c>  // b.none
    8020fc00:	f900003f 	str	xzr, [x1]
    8020fc04:	2a1303e0 	mov	w0, w19
    8020fc08:	d63f0040 	blr	x2
    8020fc0c:	52800000 	mov	w0, #0x0                   	// #0
    8020fc10:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fc14:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fc18:	d65f03c0 	ret
    8020fc1c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fc20:	52800020 	mov	w0, #0x1                   	// #1
    8020fc24:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fc28:	d65f03c0 	ret
    8020fc2c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fc30:	52800060 	mov	w0, #0x3                   	// #3
    8020fc34:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fc38:	d65f03c0 	ret
    8020fc3c:	52800040 	mov	w0, #0x2                   	// #2
    8020fc40:	17fffff4 	b	8020fc10 <__sigtramp_r+0x50>
    8020fc44:	d2802001 	mov	x1, #0x100                 	// #256
    8020fc48:	97ffe37e 	bl	80208a40 <_malloc_r>
    8020fc4c:	f900aa80 	str	x0, [x20, #336]
    8020fc50:	aa0003e1 	mov	x1, x0
    8020fc54:	b40000e0 	cbz	x0, 8020fc70 <__sigtramp_r+0xb0>
    8020fc58:	91040002 	add	x2, x0, #0x100
    8020fc5c:	d503201f 	nop
    8020fc60:	f800841f 	str	xzr, [x0], #8
    8020fc64:	eb02001f 	cmp	x0, x2
    8020fc68:	54ffffc1 	b.ne	8020fc60 <__sigtramp_r+0xa0>  // b.any
    8020fc6c:	17ffffde 	b	8020fbe4 <__sigtramp_r+0x24>
    8020fc70:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020fc74:	17ffffe7 	b	8020fc10 <__sigtramp_r+0x50>
    8020fc78:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020fc7c:	d65f03c0 	ret

000000008020fc80 <raise>:
    8020fc80:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020fc84:	d0000001 	adrp	x1, 80211000 <__mprec_tens+0x180>
    8020fc88:	910003fd 	mov	x29, sp
    8020fc8c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020fc90:	f9402434 	ldr	x20, [x1, #72]
    8020fc94:	71007c1f 	cmp	w0, #0x1f
    8020fc98:	540003e8 	b.hi	8020fd14 <raise+0x94>  // b.pmore
    8020fc9c:	f940aa82 	ldr	x2, [x20, #336]
    8020fca0:	2a0003f3 	mov	w19, w0
    8020fca4:	b40001c2 	cbz	x2, 8020fcdc <raise+0x5c>
    8020fca8:	93407c03 	sxtw	x3, w0
    8020fcac:	f8637841 	ldr	x1, [x2, x3, lsl #3]
    8020fcb0:	b4000161 	cbz	x1, 8020fcdc <raise+0x5c>
    8020fcb4:	f100043f 	cmp	x1, #0x1
    8020fcb8:	540000a0 	b.eq	8020fccc <raise+0x4c>  // b.none
    8020fcbc:	b100043f 	cmn	x1, #0x1
    8020fcc0:	540001e0 	b.eq	8020fcfc <raise+0x7c>  // b.none
    8020fcc4:	f823785f 	str	xzr, [x2, x3, lsl #3]
    8020fcc8:	d63f0020 	blr	x1
    8020fccc:	52800000 	mov	w0, #0x0                   	// #0
    8020fcd0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fcd4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fcd8:	d65f03c0 	ret
    8020fcdc:	aa1403e0 	mov	x0, x20
    8020fce0:	94000094 	bl	8020ff30 <_getpid_r>
    8020fce4:	2a1303e2 	mov	w2, w19
    8020fce8:	2a0003e1 	mov	w1, w0
    8020fcec:	aa1403e0 	mov	x0, x20
    8020fcf0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fcf4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fcf8:	1400007a 	b	8020fee0 <_kill_r>
    8020fcfc:	528002c1 	mov	w1, #0x16                  	// #22
    8020fd00:	b9000281 	str	w1, [x20]
    8020fd04:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fd08:	52800020 	mov	w0, #0x1                   	// #1
    8020fd0c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fd10:	d65f03c0 	ret
    8020fd14:	528002c1 	mov	w1, #0x16                  	// #22
    8020fd18:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020fd1c:	b9000281 	str	w1, [x20]
    8020fd20:	17ffffec 	b	8020fcd0 <raise+0x50>
	...

000000008020fd30 <signal>:
    8020fd30:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020fd34:	d0000002 	adrp	x2, 80211000 <__mprec_tens+0x180>
    8020fd38:	910003fd 	mov	x29, sp
    8020fd3c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020fd40:	93407c13 	sxtw	x19, w0
    8020fd44:	f90013f5 	str	x21, [sp, #32]
    8020fd48:	f9402455 	ldr	x21, [x2, #72]
    8020fd4c:	71007e7f 	cmp	w19, #0x1f
    8020fd50:	54000148 	b.hi	8020fd78 <signal+0x48>  // b.pmore
    8020fd54:	aa0103f4 	mov	x20, x1
    8020fd58:	f940aaa1 	ldr	x1, [x21, #336]
    8020fd5c:	b4000161 	cbz	x1, 8020fd88 <signal+0x58>
    8020fd60:	f8737820 	ldr	x0, [x1, x19, lsl #3]
    8020fd64:	f8337834 	str	x20, [x1, x19, lsl #3]
    8020fd68:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fd6c:	f94013f5 	ldr	x21, [sp, #32]
    8020fd70:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020fd74:	d65f03c0 	ret
    8020fd78:	528002c0 	mov	w0, #0x16                  	// #22
    8020fd7c:	b90002a0 	str	w0, [x21]
    8020fd80:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    8020fd84:	17fffff9 	b	8020fd68 <signal+0x38>
    8020fd88:	d2802001 	mov	x1, #0x100                 	// #256
    8020fd8c:	aa1503e0 	mov	x0, x21
    8020fd90:	97ffe32c 	bl	80208a40 <_malloc_r>
    8020fd94:	f900aaa0 	str	x0, [x21, #336]
    8020fd98:	aa0003e1 	mov	x1, x0
    8020fd9c:	b4ffff20 	cbz	x0, 8020fd80 <signal+0x50>
    8020fda0:	91040002 	add	x2, x0, #0x100
    8020fda4:	d503201f 	nop
    8020fda8:	f800841f 	str	xzr, [x0], #8
    8020fdac:	eb00005f 	cmp	x2, x0
    8020fdb0:	54ffffc1 	b.ne	8020fda8 <signal+0x78>  // b.any
    8020fdb4:	17ffffeb 	b	8020fd60 <signal+0x30>
	...

000000008020fdc0 <_init_signal>:
    8020fdc0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020fdc4:	d0000000 	adrp	x0, 80211000 <__mprec_tens+0x180>
    8020fdc8:	910003fd 	mov	x29, sp
    8020fdcc:	f9000bf3 	str	x19, [sp, #16]
    8020fdd0:	f9402413 	ldr	x19, [x0, #72]
    8020fdd4:	f940aa60 	ldr	x0, [x19, #336]
    8020fdd8:	b40000a0 	cbz	x0, 8020fdec <_init_signal+0x2c>
    8020fddc:	52800000 	mov	w0, #0x0                   	// #0
    8020fde0:	f9400bf3 	ldr	x19, [sp, #16]
    8020fde4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fde8:	d65f03c0 	ret
    8020fdec:	aa1303e0 	mov	x0, x19
    8020fdf0:	d2802001 	mov	x1, #0x100                 	// #256
    8020fdf4:	97ffe313 	bl	80208a40 <_malloc_r>
    8020fdf8:	f900aa60 	str	x0, [x19, #336]
    8020fdfc:	b40000e0 	cbz	x0, 8020fe18 <_init_signal+0x58>
    8020fe00:	91040001 	add	x1, x0, #0x100
    8020fe04:	d503201f 	nop
    8020fe08:	f800841f 	str	xzr, [x0], #8
    8020fe0c:	eb01001f 	cmp	x0, x1
    8020fe10:	54ffffc1 	b.ne	8020fe08 <_init_signal+0x48>  // b.any
    8020fe14:	17fffff2 	b	8020fddc <_init_signal+0x1c>
    8020fe18:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020fe1c:	17fffff1 	b	8020fde0 <_init_signal+0x20>

000000008020fe20 <__sigtramp>:
    8020fe20:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020fe24:	d0000001 	adrp	x1, 80211000 <__mprec_tens+0x180>
    8020fe28:	910003fd 	mov	x29, sp
    8020fe2c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020fe30:	f9402434 	ldr	x20, [x1, #72]
    8020fe34:	71007c1f 	cmp	w0, #0x1f
    8020fe38:	54000508 	b.hi	8020fed8 <__sigtramp+0xb8>  // b.pmore
    8020fe3c:	2a0003f3 	mov	w19, w0
    8020fe40:	f940aa80 	ldr	x0, [x20, #336]
    8020fe44:	b4000320 	cbz	x0, 8020fea8 <__sigtramp+0x88>
    8020fe48:	f873d801 	ldr	x1, [x0, w19, sxtw #3]
    8020fe4c:	8b33cc00 	add	x0, x0, w19, sxtw #3
    8020fe50:	b4000181 	cbz	x1, 8020fe80 <__sigtramp+0x60>
    8020fe54:	b100043f 	cmn	x1, #0x1
    8020fe58:	54000240 	b.eq	8020fea0 <__sigtramp+0x80>  // b.none
    8020fe5c:	f100043f 	cmp	x1, #0x1
    8020fe60:	54000180 	b.eq	8020fe90 <__sigtramp+0x70>  // b.none
    8020fe64:	f900001f 	str	xzr, [x0]
    8020fe68:	2a1303e0 	mov	w0, w19
    8020fe6c:	d63f0020 	blr	x1
    8020fe70:	52800000 	mov	w0, #0x0                   	// #0
    8020fe74:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fe78:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fe7c:	d65f03c0 	ret
    8020fe80:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fe84:	52800020 	mov	w0, #0x1                   	// #1
    8020fe88:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fe8c:	d65f03c0 	ret
    8020fe90:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fe94:	52800060 	mov	w0, #0x3                   	// #3
    8020fe98:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fe9c:	d65f03c0 	ret
    8020fea0:	52800040 	mov	w0, #0x2                   	// #2
    8020fea4:	17fffff4 	b	8020fe74 <__sigtramp+0x54>
    8020fea8:	aa1403e0 	mov	x0, x20
    8020feac:	d2802001 	mov	x1, #0x100                 	// #256
    8020feb0:	97ffe2e4 	bl	80208a40 <_malloc_r>
    8020feb4:	f900aa80 	str	x0, [x20, #336]
    8020feb8:	b4000100 	cbz	x0, 8020fed8 <__sigtramp+0xb8>
    8020febc:	aa0003e1 	mov	x1, x0
    8020fec0:	91040002 	add	x2, x0, #0x100
    8020fec4:	d503201f 	nop
    8020fec8:	f800843f 	str	xzr, [x1], #8
    8020fecc:	eb01005f 	cmp	x2, x1
    8020fed0:	54ffffc1 	b.ne	8020fec8 <__sigtramp+0xa8>  // b.any
    8020fed4:	17ffffdd 	b	8020fe48 <__sigtramp+0x28>
    8020fed8:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020fedc:	17ffffe6 	b	8020fe74 <__sigtramp+0x54>

000000008020fee0 <_kill_r>:
    8020fee0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020fee4:	910003fd 	mov	x29, sp
    8020fee8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020feec:	b0000394 	adrp	x20, 80280000 <gits_lock>
    8020fef0:	aa0003f3 	mov	x19, x0
    8020fef4:	b9048a9f 	str	wzr, [x20, #1160]
    8020fef8:	2a0103e0 	mov	w0, w1
    8020fefc:	2a0203e1 	mov	w1, w2
    8020ff00:	97ffc2b8 	bl	802009e0 <_kill>
    8020ff04:	3100041f 	cmn	w0, #0x1
    8020ff08:	54000080 	b.eq	8020ff18 <_kill_r+0x38>  // b.none
    8020ff0c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ff10:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020ff14:	d65f03c0 	ret
    8020ff18:	b9448a81 	ldr	w1, [x20, #1160]
    8020ff1c:	34ffff81 	cbz	w1, 8020ff0c <_kill_r+0x2c>
    8020ff20:	b9000261 	str	w1, [x19]
    8020ff24:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ff28:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020ff2c:	d65f03c0 	ret

000000008020ff30 <_getpid_r>:
    8020ff30:	17ffc2a8 	b	802009d0 <_getpid>
	...

000000008020ff40 <__trunctfdf2>:
    8020ff40:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020ff44:	9e660002 	fmov	x2, d0
    8020ff48:	9eae0003 	fmov	x3, v0.d[1]
    8020ff4c:	910003fd 	mov	x29, sp
    8020ff50:	f9000bf3 	str	x19, [sp, #16]
    8020ff54:	d53b4404 	mrs	x4, fpcr
    8020ff58:	aa0303e0 	mov	x0, x3
    8020ff5c:	d37ffc61 	lsr	x1, x3, #63
    8020ff60:	d370f863 	ubfx	x3, x3, #48, #15
    8020ff64:	aa0103e5 	mov	x5, x1
    8020ff68:	d37dbc00 	ubfiz	x0, x0, #3, #48
    8020ff6c:	91000467 	add	x7, x3, #0x1
    8020ff70:	12001c26 	and	w6, w1, #0xff
    8020ff74:	aa0103e8 	mov	x8, x1
    8020ff78:	aa42f400 	orr	x0, x0, x2, lsr #61
    8020ff7c:	d37df041 	lsl	x1, x2, #3
    8020ff80:	f27f34ff 	tst	x7, #0x7ffe
    8020ff84:	54000920 	b.eq	802100a8 <__trunctfdf2+0x168>  // b.none
    8020ff88:	92877fe7 	mov	x7, #0xffffffffffffc400    	// #-15360
    8020ff8c:	8b070063 	add	x3, x3, x7
    8020ff90:	f11ff87f 	cmp	x3, #0x7fe
    8020ff94:	540002ed 	b.le	8020fff0 <__trunctfdf2+0xb0>
    8020ff98:	f26a0484 	ands	x4, x4, #0xc00000
    8020ff9c:	540007c0 	b.eq	80210094 <__trunctfdf2+0x154>  // b.none
    8020ffa0:	f150009f 	cmp	x4, #0x400, lsl #12
    8020ffa4:	54001520 	b.eq	80210248 <__trunctfdf2+0x308>  // b.none
    8020ffa8:	f160009f 	cmp	x4, #0x800, lsl #12
    8020ffac:	1a9f17e0 	cset	w0, eq	// eq = none
    8020ffb0:	6a0000df 	tst	w6, w0
    8020ffb4:	54000701 	b.ne	80210094 <__trunctfdf2+0x154>  // b.any
    8020ffb8:	f150009f 	cmp	x4, #0x400, lsl #12
    8020ffbc:	540015c0 	b.eq	80210274 <__trunctfdf2+0x334>  // b.none
    8020ffc0:	f160009f 	cmp	x4, #0x800, lsl #12
    8020ffc4:	1a9f17e0 	cset	w0, eq	// eq = none
    8020ffc8:	6a0000df 	tst	w6, w0
    8020ffcc:	54000641 	b.ne	80210094 <__trunctfdf2+0x154>  // b.any
    8020ffd0:	92f00213 	mov	x19, #0x7fefffffffffffff    	// #9218868437227405311
    8020ffd4:	52800280 	mov	w0, #0x14                  	// #20
    8020ffd8:	aa05fe73 	orr	x19, x19, x5, lsl #63
    8020ffdc:	940000cd 	bl	80210310 <__sfp_handle_exceptions>
    8020ffe0:	9e670260 	fmov	d0, x19
    8020ffe4:	f9400bf3 	ldr	x19, [sp, #16]
    8020ffe8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020ffec:	d65f03c0 	ret
    8020fff0:	f100007f 	cmp	x3, #0x0
    8020fff4:	54000aad 	b.le	80210148 <__trunctfdf2+0x208>
    8020fff8:	eb021fff 	cmp	xzr, x2, lsl #7
    8020fffc:	52800002 	mov	w2, #0x0                   	// #0
    80210000:	9a9f07e7 	cset	x7, ne	// ne = any
    80210004:	aa41f0e1 	orr	x1, x7, x1, lsr #60
    80210008:	aa001021 	orr	x1, x1, x0, lsl #4
    8021000c:	f100003f 	cmp	x1, #0x0
    80210010:	1a9f07e0 	cset	w0, ne	// ne = any
    80210014:	0a000040 	and	w0, w2, w0
    80210018:	f240083f 	tst	x1, #0x7
    8021001c:	540015c0 	b.eq	802102d4 <__trunctfdf2+0x394>  // b.none
    80210020:	926a0484 	and	x4, x4, #0xc00000
    80210024:	f150009f 	cmp	x4, #0x400, lsl #12
    80210028:	54000240 	b.eq	80210070 <__trunctfdf2+0x130>  // b.none
    8021002c:	f160009f 	cmp	x4, #0x800, lsl #12
    80210030:	54000d00 	b.eq	802101d0 <__trunctfdf2+0x290>  // b.none
    80210034:	b5000c84 	cbnz	x4, 802101c4 <__trunctfdf2+0x284>
    80210038:	92400c22 	and	x2, x1, #0xf
    8021003c:	f100105f 	cmp	x2, #0x4
    80210040:	54000aa1 	b.ne	80210194 <__trunctfdf2+0x254>  // b.any
    80210044:	d343d821 	ubfx	x1, x1, #3, #52
    80210048:	12002863 	and	w3, w3, #0x7ff
    8021004c:	d2800002 	mov	x2, #0x0                   	// #0
    80210050:	34001260 	cbz	w0, 8021029c <__trunctfdf2+0x35c>
    80210054:	b340cc22 	bfxil	x2, x1, #0, #52
    80210058:	52800300 	mov	w0, #0x18                  	// #24
    8021005c:	b34c2862 	bfi	x2, x3, #52, #11
    80210060:	b34100c2 	bfi	x2, x6, #63, #1
    80210064:	aa0203f3 	mov	x19, x2
    80210068:	940000aa 	bl	80210310 <__sfp_handle_exceptions>
    8021006c:	17ffffdd 	b	8020ffe0 <__trunctfdf2+0xa0>
    80210070:	b5000bc5 	cbnz	x5, 802101e8 <__trunctfdf2+0x2a8>
    80210074:	91002021 	add	x1, x1, #0x8
    80210078:	92490022 	and	x2, x1, #0x80000000000000
    8021007c:	35000920 	cbnz	w0, 802101a0 <__trunctfdf2+0x260>
    80210080:	b4000b62 	cbz	x2, 802101ec <__trunctfdf2+0x2ac>
    80210084:	91000462 	add	x2, x3, #0x1
    80210088:	f11ff87f 	cmp	x3, #0x7fe
    8021008c:	54001161 	b.ne	802102b8 <__trunctfdf2+0x378>  // b.any
    80210090:	b5fff944 	cbnz	x4, 8020ffb8 <__trunctfdf2+0x78>
    80210094:	d34100b3 	lsl	x19, x5, #63
    80210098:	52800280 	mov	w0, #0x14                  	// #20
    8021009c:	b24c2a73 	orr	x19, x19, #0x7ff0000000000000
    802100a0:	9400009c 	bl	80210310 <__sfp_handle_exceptions>
    802100a4:	17ffffcf 	b	8020ffe0 <__trunctfdf2+0xa0>
    802100a8:	aa010002 	orr	x2, x0, x1
    802100ac:	b5000203 	cbnz	x3, 802100ec <__trunctfdf2+0x1ac>
    802100b0:	d34100b3 	lsl	x19, x5, #63
    802100b4:	b4fff962 	cbz	x2, 8020ffe0 <__trunctfdf2+0xa0>
    802100b8:	926a0484 	and	x4, x4, #0xc00000
    802100bc:	f150009f 	cmp	x4, #0x400, lsl #12
    802100c0:	54000ce0 	b.eq	8021025c <__trunctfdf2+0x31c>  // b.none
    802100c4:	f160009f 	cmp	x4, #0x800, lsl #12
    802100c8:	54000b60 	b.eq	80210234 <__trunctfdf2+0x2f4>  // b.none
    802100cc:	f100009f 	cmp	x4, #0x0
    802100d0:	d28000a0 	mov	x0, #0x5                   	// #5
    802100d4:	9a9f0401 	csinc	x1, x0, xzr, eq	// eq = none
    802100d8:	d2800008 	mov	x8, #0x0                   	// #0
    802100dc:	d343d821 	ubfx	x1, x1, #3, #52
    802100e0:	12002908 	and	w8, w8, #0x7ff
    802100e4:	52800300 	mov	w0, #0x18                  	// #24
    802100e8:	14000033 	b	802101b4 <__trunctfdf2+0x274>
    802100ec:	b4000222 	cbz	x2, 80210130 <__trunctfdf2+0x1f0>
    802100f0:	d28fffe2 	mov	x2, #0x7fff                	// #32767
    802100f4:	93c1f001 	extr	x1, x0, x1, #60
    802100f8:	d372fc00 	lsr	x0, x0, #50
    802100fc:	eb02007f 	cmp	x3, x2
    80210100:	d343fc21 	lsr	x1, x1, #3
    80210104:	52000000 	eor	w0, w0, #0x1
    80210108:	b24d0021 	orr	x1, x1, #0x8000000000000
    8021010c:	1a9f0000 	csel	w0, w0, wzr, eq	// eq = none
    80210110:	5280fff3 	mov	w19, #0x7ff                 	// #2047
    80210114:	aa13d033 	orr	x19, x1, x19, lsl #52
    80210118:	aa05fe73 	orr	x19, x19, x5, lsl #63
    8021011c:	35fff600 	cbnz	w0, 8020ffdc <__trunctfdf2+0x9c>
    80210120:	9e670260 	fmov	d0, x19
    80210124:	f9400bf3 	ldr	x19, [sp, #16]
    80210128:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8021012c:	d65f03c0 	ret
    80210130:	d34100b3 	lsl	x19, x5, #63
    80210134:	b24c2a73 	orr	x19, x19, #0x7ff0000000000000
    80210138:	9e670260 	fmov	d0, x19
    8021013c:	f9400bf3 	ldr	x19, [sp, #16]
    80210140:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210144:	d65f03c0 	ret
    80210148:	b100d07f 	cmn	x3, #0x34
    8021014c:	54fffb6b 	b.lt	802100b8 <__trunctfdf2+0x178>  // b.tstop
    80210150:	d28007a7 	mov	x7, #0x3d                  	// #61
    80210154:	cb0300e8 	sub	x8, x7, x3
    80210158:	b24d0000 	orr	x0, x0, #0x8000000000000
    8021015c:	f100fd1f 	cmp	x8, #0x3f
    80210160:	540004ec 	b.gt	802101fc <__trunctfdf2+0x2bc>
    80210164:	11000c68 	add	w8, w3, #0x3
    80210168:	4b0300e7 	sub	w7, w7, w3
    8021016c:	52800022 	mov	w2, #0x1                   	// #1
    80210170:	d2800003 	mov	x3, #0x0                   	// #0
    80210174:	9ac82029 	lsl	x9, x1, x8
    80210178:	f100013f 	cmp	x9, #0x0
    8021017c:	9a9f07e9 	cset	x9, ne	// ne = any
    80210180:	9ac72421 	lsr	x1, x1, x7
    80210184:	aa090021 	orr	x1, x1, x9
    80210188:	9ac82000 	lsl	x0, x0, x8
    8021018c:	aa010001 	orr	x1, x0, x1
    80210190:	17ffff9f 	b	8021000c <__trunctfdf2+0xcc>
    80210194:	91001021 	add	x1, x1, #0x4
    80210198:	92490022 	and	x2, x1, #0x80000000000000
    8021019c:	34fff720 	cbz	w0, 80210080 <__trunctfdf2+0x140>
    802101a0:	b4000142 	cbz	x2, 802101c8 <__trunctfdf2+0x288>
    802101a4:	91000468 	add	x8, x3, #0x1
    802101a8:	d2800001 	mov	x1, #0x0                   	// #0
    802101ac:	12002908 	and	w8, w8, #0x7ff
    802101b0:	52800300 	mov	w0, #0x18                  	// #24
    802101b4:	aa08d028 	orr	x8, x1, x8, lsl #52
    802101b8:	aa05fd13 	orr	x19, x8, x5, lsl #63
    802101bc:	94000055 	bl	80210310 <__sfp_handle_exceptions>
    802101c0:	17ffff88 	b	8020ffe0 <__trunctfdf2+0xa0>
    802101c4:	34000140 	cbz	w0, 802101ec <__trunctfdf2+0x2ac>
    802101c8:	aa0303e8 	mov	x8, x3
    802101cc:	17ffffc4 	b	802100dc <__trunctfdf2+0x19c>
    802101d0:	b5fff525 	cbnz	x5, 80210074 <__trunctfdf2+0x134>
    802101d4:	340000c0 	cbz	w0, 802101ec <__trunctfdf2+0x2ac>
    802101d8:	aa0303e8 	mov	x8, x3
    802101dc:	aa0803e3 	mov	x3, x8
    802101e0:	aa0303e8 	mov	x8, x3
    802101e4:	17ffffbe 	b	802100dc <__trunctfdf2+0x19c>
    802101e8:	35ffff00 	cbnz	w0, 802101c8 <__trunctfdf2+0x288>
    802101ec:	d343d821 	ubfx	x1, x1, #3, #52
    802101f0:	12002868 	and	w8, w3, #0x7ff
    802101f4:	52800200 	mov	w0, #0x10                  	// #16
    802101f8:	17ffffef 	b	802101b4 <__trunctfdf2+0x274>
    802101fc:	11010c62 	add	w2, w3, #0x43
    80210200:	f101011f 	cmp	x8, #0x40
    80210204:	12800047 	mov	w7, #0xfffffffd            	// #-3
    80210208:	4b0300e3 	sub	w3, w7, w3
    8021020c:	9ac22002 	lsl	x2, x0, x2
    80210210:	aa020022 	orr	x2, x1, x2
    80210214:	9a811041 	csel	x1, x2, x1, ne	// ne = any
    80210218:	9ac32400 	lsr	x0, x0, x3
    8021021c:	f100003f 	cmp	x1, #0x0
    80210220:	52800022 	mov	w2, #0x1                   	// #1
    80210224:	9a9f07e1 	cset	x1, ne	// ne = any
    80210228:	d2800003 	mov	x3, #0x0                   	// #0
    8021022c:	aa000021 	orr	x1, x1, x0
    80210230:	17ffff77 	b	8021000c <__trunctfdf2+0xcc>
    80210234:	d2800021 	mov	x1, #0x1                   	// #1
    80210238:	b4fffd25 	cbz	x5, 802101dc <__trunctfdf2+0x29c>
    8021023c:	d2800008 	mov	x8, #0x0                   	// #0
    80210240:	d2800121 	mov	x1, #0x9                   	// #9
    80210244:	17ffffa6 	b	802100dc <__trunctfdf2+0x19c>
    80210248:	b5000165 	cbnz	x5, 80210274 <__trunctfdf2+0x334>
    8021024c:	d2effe13 	mov	x19, #0x7ff0000000000000    	// #9218868437227405312
    80210250:	52800280 	mov	w0, #0x14                  	// #20
    80210254:	9400002f 	bl	80210310 <__sfp_handle_exceptions>
    80210258:	17ffff62 	b	8020ffe0 <__trunctfdf2+0xa0>
    8021025c:	d2800121 	mov	x1, #0x9                   	// #9
    80210260:	b4fff3e5 	cbz	x5, 802100dc <__trunctfdf2+0x19c>
    80210264:	d2800003 	mov	x3, #0x0                   	// #0
    80210268:	d2800021 	mov	x1, #0x1                   	// #1
    8021026c:	aa0303e8 	mov	x8, x3
    80210270:	17ffff9b 	b	802100dc <__trunctfdf2+0x19c>
    80210274:	f10000bf 	cmp	x5, #0x0
    80210278:	92e00200 	mov	x0, #0xffefffffffffffff    	// #-4503599627370497
    8021027c:	d2effe01 	mov	x1, #0x7ff0000000000000    	// #9218868437227405312
    80210280:	9e670000 	fmov	d0, x0
    80210284:	9e670021 	fmov	d1, x1
    80210288:	52800280 	mov	w0, #0x14                  	// #20
    8021028c:	1e611c00 	fcsel	d0, d0, d1, ne	// ne = any
    80210290:	9e660013 	fmov	x19, d0
    80210294:	9400001f 	bl	80210310 <__sfp_handle_exceptions>
    80210298:	17ffff52 	b	8020ffe0 <__trunctfdf2+0xa0>
    8021029c:	b340cc22 	bfxil	x2, x1, #0, #52
    802102a0:	52800200 	mov	w0, #0x10                  	// #16
    802102a4:	b34c2862 	bfi	x2, x3, #52, #11
    802102a8:	b34100c2 	bfi	x2, x6, #63, #1
    802102ac:	aa0203f3 	mov	x19, x2
    802102b0:	94000018 	bl	80210310 <__sfp_handle_exceptions>
    802102b4:	17ffff4b 	b	8020ffe0 <__trunctfdf2+0xa0>
    802102b8:	92fc0203 	mov	x3, #0x1fefffffffffffff    	// #2301339409586323455
    802102bc:	52800200 	mov	w0, #0x10                  	// #16
    802102c0:	8a410c61 	and	x1, x3, x1, lsr #3
    802102c4:	aa02d022 	orr	x2, x1, x2, lsl #52
    802102c8:	aa05fc53 	orr	x19, x2, x5, lsl #63
    802102cc:	94000011 	bl	80210310 <__sfp_handle_exceptions>
    802102d0:	17ffff44 	b	8020ffe0 <__trunctfdf2+0xa0>
    802102d4:	d343d821 	ubfx	x1, x1, #3, #52
    802102d8:	12002873 	and	w19, w3, #0x7ff
    802102dc:	350000e0 	cbnz	w0, 802102f8 <__trunctfdf2+0x3b8>
    802102e0:	d2800002 	mov	x2, #0x0                   	// #0
    802102e4:	b340cc22 	bfxil	x2, x1, #0, #52
    802102e8:	b34c2a62 	bfi	x2, x19, #52, #11
    802102ec:	b34100c2 	bfi	x2, x6, #63, #1
    802102f0:	aa0203f3 	mov	x19, x2
    802102f4:	17ffff3b 	b	8020ffe0 <__trunctfdf2+0xa0>
    802102f8:	530b2c80 	ubfx	w0, w4, #11, #1
    802102fc:	531d7000 	lsl	w0, w0, #3
    80210300:	17ffff85 	b	80210114 <__trunctfdf2+0x1d4>
	...

0000000080210310 <__sfp_handle_exceptions>:
    80210310:	36000080 	tbz	w0, #0, 80210320 <__sfp_handle_exceptions+0x10>
    80210314:	0f000401 	movi	v1.2s, #0x0
    80210318:	1e211820 	fdiv	s0, s1, s1
    8021031c:	d53b4421 	mrs	x1, fpsr
    80210320:	360800a0 	tbz	w0, #1, 80210334 <__sfp_handle_exceptions+0x24>
    80210324:	1e2e1001 	fmov	s1, #1.000000000000000000e+00
    80210328:	0f000402 	movi	v2.2s, #0x0
    8021032c:	1e221820 	fdiv	s0, s1, s2
    80210330:	d53b4421 	mrs	x1, fpsr
    80210334:	36100100 	tbz	w0, #2, 80210354 <__sfp_handle_exceptions+0x44>
    80210338:	5298b5c2 	mov	w2, #0xc5ae                	// #50606
    8021033c:	12b01001 	mov	w1, #0x7f7fffff            	// #2139095039
    80210340:	72ae93a2 	movk	w2, #0x749d, lsl #16
    80210344:	1e270021 	fmov	s1, w1
    80210348:	1e270042 	fmov	s2, w2
    8021034c:	1e222820 	fadd	s0, s1, s2
    80210350:	d53b4421 	mrs	x1, fpsr
    80210354:	36180080 	tbz	w0, #3, 80210364 <__sfp_handle_exceptions+0x54>
    80210358:	0f044401 	movi	v1.2s, #0x80, lsl #16
    8021035c:	1e210820 	fmul	s0, s1, s1
    80210360:	d53b4421 	mrs	x1, fpsr
    80210364:	362000c0 	tbz	w0, #4, 8021037c <__sfp_handle_exceptions+0x6c>
    80210368:	12b01000 	mov	w0, #0x7f7fffff            	// #2139095039
    8021036c:	1e2e1002 	fmov	s2, #1.000000000000000000e+00
    80210370:	1e270001 	fmov	s1, w0
    80210374:	1e223820 	fsub	s0, s1, s2
    80210378:	d53b4420 	mrs	x0, fpsr
    8021037c:	d65f03c0 	ret
