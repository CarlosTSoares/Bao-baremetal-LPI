
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
    80200044:	10013de1 	adr	x1, 80202800 <_exception_vector>
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
    80200068:	10013cc1 	adr	x1, 80202800 <_exception_vector>
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
    80200088:	100bfbc1 	adr	x1, 80218000 <root_page_table>
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
    802000c0:	1008b241 	adr	x1, 80211708 <wait_flag>
    mov x2, #1
    802000c4:	d2800022 	mov	x2, #0x1                   	// #1
    str x2, [x1]
    802000c8:	f9000022 	str	x2, [x1]

1:
    adr x1, wait_flag
    802000cc:	1008b1e1 	adr	x1, 80211708 <wait_flag>
    ldr x2, [x1]
    802000d0:	f9400022 	ldr	x2, [x1]
    cbz x2, 1b
    802000d4:	b4ffffc2 	cbz	x2, 802000cc <_enter_el1+0x64>

    mov x3, #SPSel_SP							
    802000d8:	d2800023 	mov	x3, #0x1                   	// #1
	msr SPSEL, x3	
    802000dc:	d5184203 	msr	spsel, x3

    adr x1, _stack_base
    802000e0:	10409c01 	adr	x1, 80281460 <_stack_base>
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
    80200138:	80281458 	.word	0x80281458
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
    8020093c:	940009b1 	bl	80203000 <__errno>
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
    80200988:	9400099e 	bl	80203000 <__errno>
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
    802009a4:	b0000082 	adrp	x2, 80211000 <blanks.1+0x60>
{
    802009a8:	2a0003e1 	mov	w1, w0
    char* current_heap_end = heap_end;
    802009ac:	f9437040 	ldr	x0, [x2, #1760]
    heap_end += increment;
    802009b0:	8b21c001 	add	x1, x0, w1, sxtw
    802009b4:	f9037041 	str	x1, [x2, #1760]
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
    802009e8:	94000986 	bl	80203000 <__errno>
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
    80200a40:	94000634 	bl	80202310 <main>
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
    80200b40:	940000e0 	bl	80200ec0 <gic_init>
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
    80200c58:	94000322 	bl	802018e0 <gic_set_enable>
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
    80200c70:	14000310 	b	802018b0 <gic_set_route>

0000000080200c74 <irq_disable>:

void irq_disable(unsigned id) {
    gic_set_enable(id, false); 
    80200c74:	2a0003e0 	mov	w0, w0
    80200c78:	52800001 	mov	w1, #0x0                   	// #0
    80200c7c:	14000319 	b	802018e0 <gic_set_enable>

0000000080200c80 <irq_set_prio>:
}

void irq_set_prio(unsigned id, unsigned prio){
    gic_set_prio(id, (uint8_t) prio);
    80200c80:	2a0003e0 	mov	w0, w0
    80200c84:	140002c7 	b	802017a0 <gic_set_prio>
    80200c88:	d503201f 	nop
    80200c8c:	d503201f 	nop

0000000080200c90 <irq_send_ipi>:
}

void irq_send_ipi(unsigned long target_cpu_mask) {
    80200c90:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80200c94:	910003fd 	mov	x29, sp
    80200c98:	a90153f3 	stp	x19, x20, [sp, #16]
    80200c9c:	aa0003f4 	mov	x20, x0
    80200ca0:	d2800013 	mov	x19, #0x0                   	// #0
    80200ca4:	14000004 	b	80200cb4 <irq_send_ipi+0x24>
    for(int i = 0; i < sizeof(target_cpu_mask)*8; i++) {
    80200ca8:	91000673 	add	x19, x19, #0x1
    80200cac:	f101027f 	cmp	x19, #0x40
    80200cb0:	54000120 	b.eq	80200cd4 <irq_send_ipi+0x44>  // b.none
        if(target_cpu_mask & (1ull << i)) {
    80200cb4:	9ad32681 	lsr	x1, x20, x19
    80200cb8:	3607ff81 	tbz	w1, #0, 80200ca8 <irq_send_ipi+0x18>
            gic_send_sgi(i, IPI_IRQ_ID);
    80200cbc:	aa1303e0 	mov	x0, x19
    80200cc0:	d2800001 	mov	x1, #0x0                   	// #0
    for(int i = 0; i < sizeof(target_cpu_mask)*8; i++) {
    80200cc4:	91000673 	add	x19, x19, #0x1
            gic_send_sgi(i, IPI_IRQ_ID);
    80200cc8:	940002af 	bl	80201784 <gic_send_sgi>
    for(int i = 0; i < sizeof(target_cpu_mask)*8; i++) {
    80200ccc:	f101027f 	cmp	x19, #0x40
    80200cd0:	54ffff21 	b.ne	80200cb4 <irq_send_ipi+0x24>  // b.any
        }
    }
}
    80200cd4:	a94153f3 	ldp	x19, x20, [sp, #16]
    80200cd8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80200cdc:	d65f03c0 	ret

0000000080200ce0 <timer_set>:
SYSREG_GEN_ACCESSORS(cntvct_el0);
    80200ce0:	d53be041 	mrs	x1, cntvct_el0
unsigned long TIMER_FREQ;

void timer_set(uint64_t n)
{
    uint64_t current = sysreg_cntvct_el0_read();
    sysreg_cntv_cval_el0_write(current + n);
    80200ce4:	8b010000 	add	x0, x0, x1
SYSREG_GEN_ACCESSORS(cntv_cval_el0);
    80200ce8:	d51be340 	msr	cntv_cval_el0, x0
}
    80200cec:	d65f03c0 	ret

0000000080200cf0 <timer_get>:
SYSREG_GEN_ACCESSORS(cntvct_el0);
    80200cf0:	d53be040 	mrs	x0, cntvct_el0

uint64_t timer_get()
{
    uint64_t time = sysreg_cntvct_el0_read();
    return time; // assumes plat_freq = 100MHz
}
    80200cf4:	d65f03c0 	ret
	...

0000000080200d00 <gic_num_irqs>:


inline unsigned long gic_num_irqs()
{
    uint32_t itlinenumber =
        bit_extract(gicd->TYPER, GICD_TYPER_ITLN_OFF, GICD_TYPER_ITLN_LEN);
    80200d00:	b0000080 	adrp	x0, 80211000 <blanks.1+0x60>
    80200d04:	f9437400 	ldr	x0, [x0, #1768]
    80200d08:	b9400400 	ldr	w0, [x0, #4]
    return 32 * itlinenumber + 1;
    80200d0c:	d37b1000 	ubfiz	x0, x0, #5, #5
}
    80200d10:	91000400 	add	x0, x0, #0x1
    80200d14:	d65f03c0 	ret
    80200d18:	d503201f 	nop
    80200d1c:	d503201f 	nop

0000000080200d20 <gic_cpu_init>:
SYSREG_GEN_ACCESSORS(icc_sre_el1);
    80200d20:	d538cca0 	mrs	x0, icc_sre_el1
//    }
//}

void gic_cpu_init()
{
    sysreg_icc_sre_el1_write(sysreg_icc_sre_el1_read() | ICC_SRE_SRE_BIT);
    80200d24:	b2400000 	orr	x0, x0, #0x1
    80200d28:	d518cca0 	msr	icc_sre_el1, x0
    ISB();
    80200d2c:	d5033fdf 	isb
    gicd->CTLR |= (1ull << 6);
    80200d30:	b0000080 	adrp	x0, 80211000 <blanks.1+0x60>
    80200d34:	911ba002 	add	x2, x0, #0x6e8
    80200d38:	f9437401 	ldr	x1, [x0, #1768]
    gicr[get_cpuid()].WAKER &= ~GICR_ProcessorSleep_BIT;
    80200d3c:	f9400442 	ldr	x2, [x2, #8]
    gicd->CTLR |= (1ull << 6);
    80200d40:	b9400020 	ldr	w0, [x1]
    80200d44:	321a0000 	orr	w0, w0, #0x40
    80200d48:	b9000020 	str	w0, [x1]
SYSREG_GEN_ACCESSORS(mpidr_el1);
    80200d4c:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].WAKER &= ~GICR_ProcessorSleep_BIT;
    80200d50:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200d54:	8b000040 	add	x0, x2, x0
    80200d58:	b9401401 	ldr	w1, [x0, #20]
    80200d5c:	121e7821 	and	w1, w1, #0xfffffffd
    80200d60:	b9001401 	str	w1, [x0, #20]
    while(gicr[get_cpuid()].WAKER & GICR_ChildrenASleep_BIT) { }
    80200d64:	d503201f 	nop
    80200d68:	d53800a0 	mrs	x0, mpidr_el1
    80200d6c:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200d70:	8b000040 	add	x0, x2, x0
    80200d74:	b9401400 	ldr	w0, [x0, #20]
    80200d78:	3717ff80 	tbnz	w0, #2, 80200d68 <gic_cpu_init+0x48>
    80200d7c:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].IGROUPR0 = -1;
    80200d80:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200d84:	12800003 	mov	w3, #0xffffffff            	// #-1
    80200d88:	8b000040 	add	x0, x2, x0
    80200d8c:	91404000 	add	x0, x0, #0x10, lsl #12
    80200d90:	b9008003 	str	w3, [x0, #128]
    80200d94:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].ICENABLER0 = -1;
    80200d98:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200d9c:	8b000040 	add	x0, x2, x0
    80200da0:	91404000 	add	x0, x0, #0x10, lsl #12
    80200da4:	b9018003 	str	w3, [x0, #384]
    80200da8:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].ICPENDR0 = -1;
    80200dac:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200db0:	8b000040 	add	x0, x2, x0
    80200db4:	91404000 	add	x0, x0, #0x10, lsl #12
    80200db8:	b9028003 	str	w3, [x0, #640]
    80200dbc:	d53800a0 	mrs	x0, mpidr_el1
    gicr[get_cpuid()].ICACTIVER0 = -1;
    80200dc0:	d36f1c00 	ubfiz	x0, x0, #17, #8
    for (int i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
    80200dc4:	52800001 	mov	w1, #0x0                   	// #0
    gicr[get_cpuid()].ICACTIVER0 = -1;
    80200dc8:	8b000040 	add	x0, x2, x0
    80200dcc:	91404000 	add	x0, x0, #0x10, lsl #12
    80200dd0:	b9038003 	str	w3, [x0, #896]
    for (int i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
    80200dd4:	d503201f 	nop
    80200dd8:	d53800a0 	mrs	x0, mpidr_el1
        gicr[get_cpuid()].IPRIORITYR[i] = -1;
    80200ddc:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80200de0:	8b000040 	add	x0, x2, x0
    80200de4:	8b21c800 	add	x0, x0, w1, sxtw #2
    for (int i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
    80200de8:	11000421 	add	w1, w1, #0x1
        gicr[get_cpuid()].IPRIORITYR[i] = -1;
    80200dec:	91404000 	add	x0, x0, #0x10, lsl #12
    80200df0:	b9040003 	str	w3, [x0, #1024]
    for (int i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
    80200df4:	7100203f 	cmp	w1, #0x8
    80200df8:	54ffff01 	b.ne	80200dd8 <gic_cpu_init+0xb8>  // b.any
SYSREG_GEN_ACCESSORS(icc_pmr_el1);
    80200dfc:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    80200e00:	d5184600 	msr	icc_pmr_el1, x0
SYSREG_GEN_ACCESSORS(icc_ctlr_el1);
    80200e04:	d2800020 	mov	x0, #0x1                   	// #1
    80200e08:	d518cc80 	msr	icc_ctlr_el1, x0
SYSREG_GEN_ACCESSORS(icc_igrpen1_el1);
    80200e0c:	d518cce0 	msr	icc_igrpen1_el1, x0
    gicr_init();
    gicc_init();
}
    80200e10:	d65f03c0 	ret

0000000080200e14 <gicd_init>:
        bit_extract(gicd->TYPER, GICD_TYPER_ITLN_OFF, GICD_TYPER_ITLN_LEN);
    80200e14:	b0000080 	adrp	x0, 80211000 <blanks.1+0x60>
void gicd_init()
{
    size_t int_num = gic_num_irqs();

    /* Bring distributor to known state */
    for (int i = GIC_NUM_PRIVINT_REGS; i < GIC_NUM_INT_REGS(int_num); i++) {
    80200e18:	52800022 	mov	w2, #0x1                   	// #1
        gicd->IGROUPR[i] = -1;
    80200e1c:	12800001 	mov	w1, #0xffffffff            	// #-1
        bit_extract(gicd->TYPER, GICD_TYPER_ITLN_OFF, GICD_TYPER_ITLN_LEN);
    80200e20:	f9437403 	ldr	x3, [x0, #1768]
    80200e24:	b9400460 	ldr	w0, [x3, #4]
    return 32 * itlinenumber + 1;
    80200e28:	d37b1000 	ubfiz	x0, x0, #5, #5
    80200e2c:	91000405 	add	x5, x0, #0x1
    for (int i = GIC_NUM_PRIVINT_REGS; i < GIC_NUM_INT_REGS(int_num); i++) {
    80200e30:	d345fc00 	lsr	x0, x0, #5
    80200e34:	2a0003e4 	mov	w4, w0
    80200e38:	f100041f 	cmp	x0, #0x1
    80200e3c:	54000389 	b.ls	80200eac <gicd_init+0x98>  // b.plast
        gicd->IGROUPR[i] = -1;
    80200e40:	8b22c860 	add	x0, x3, w2, sxtw #2
    for (int i = GIC_NUM_PRIVINT_REGS; i < GIC_NUM_INT_REGS(int_num); i++) {
    80200e44:	11000442 	add	w2, w2, #0x1
        gicd->IGROUPR[i] = -1;
    80200e48:	b9008001 	str	w1, [x0, #128]
        /**
         * Make sure all interrupts are not enabled, non pending,
         * non active.
         */
        gicd->ICENABLER[i] = -1;
    80200e4c:	b9018001 	str	w1, [x0, #384]
        gicd->ICPENDR[i] = -1;
    80200e50:	b9028001 	str	w1, [x0, #640]
        gicd->ICACTIVER[i] = -1;
    80200e54:	b9038001 	str	w1, [x0, #896]
    for (int i = GIC_NUM_PRIVINT_REGS; i < GIC_NUM_INT_REGS(int_num); i++) {
    80200e58:	6b02009f 	cmp	w4, w2
    80200e5c:	54ffff21 	b.ne	80200e40 <gicd_init+0x2c>  // b.any
    }

    /* All interrupts have lowest priority possible by default */
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_PRIO_REGS(int_num); i++)
    80200e60:	d342fca4 	lsr	x4, x5, #2
    80200e64:	f1020cbf 	cmp	x5, #0x83
    80200e68:	54000229 	b.ls	80200eac <gicd_init+0x98>  // b.plast
    80200e6c:	52800400 	mov	w0, #0x20                  	// #32
        gicd->IPRIORITYR[i] = -1;
    80200e70:	12800005 	mov	w5, #0xffffffff            	// #-1
    80200e74:	d503201f 	nop
    80200e78:	8b20c861 	add	x1, x3, w0, sxtw #2
    80200e7c:	2a0003e2 	mov	w2, w0
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_PRIO_REGS(int_num); i++)
    80200e80:	11000400 	add	w0, w0, #0x1
        gicd->IPRIORITYR[i] = -1;
    80200e84:	b9040025 	str	w5, [x1, #1024]
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_PRIO_REGS(int_num); i++)
    80200e88:	6b00009f 	cmp	w4, w0
    80200e8c:	54ffff61 	b.ne	80200e78 <gicd_init+0x64>  // b.any

    /* No CPU targets for any interrupt by default */
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_TARGET_REGS(int_num); i++)
    80200e90:	52800400 	mov	w0, #0x20                  	// #32
    80200e94:	d503201f 	nop
        gicd->ITARGETSR[i] = 0;
    80200e98:	8b20c864 	add	x4, x3, w0, sxtw #2
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_TARGET_REGS(int_num); i++)
    80200e9c:	6b00005f 	cmp	w2, w0
    80200ea0:	11000400 	add	w0, w0, #0x1
        gicd->ITARGETSR[i] = 0;
    80200ea4:	b908009f 	str	wzr, [x4, #2048]
    for (int i = GIC_CPU_PRIV; i < GIC_NUM_TARGET_REGS(int_num); i++)
    80200ea8:	54ffff81 	b.ne	80200e98 <gicd_init+0x84>  // b.any
    /* ICFGR are platform dependent, lets leave them as is */

    /* No need to setup gicd->NSACR as all interrupts are  setup to group 1 */

    /* Enable distributor and affinity routing */
    gicd->CTLR |= GICD_CTLR_ARE_NS_BIT | GICD_CTLR_ENA_BIT;
    80200eac:	b9400060 	ldr	w0, [x3]
    80200eb0:	52800241 	mov	w1, #0x12                  	// #18
    80200eb4:	2a010000 	orr	w0, w0, w1
    80200eb8:	b9000060 	str	w0, [x3]
}
    80200ebc:	d65f03c0 	ret

0000000080200ec0 <gic_init>:

void gic_init()
{
    80200ec0:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80200ec4:	910003fd 	mov	x29, sp
    gic_cpu_init();
    80200ec8:	97ffff96 	bl	80200d20 <gic_cpu_init>
SYSREG_GEN_ACCESSORS(mpidr_el1);
    80200ecc:	d53800a0 	mrs	x0, mpidr_el1

    if (get_cpuid() == 0) {
    80200ed0:	72001c1f 	tst	w0, #0xff
    80200ed4:	54000060 	b.eq	80200ee0 <gic_init+0x20>  // b.none
        gicd_init();
        its_init(); /*Alloc tables and map lpis*/
        //printf("Gic initializated\n");
    }

}
    80200ed8:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80200edc:	d65f03c0 	ret
        gicd_init();
    80200ee0:	97ffffcd 	bl	80200e14 <gicd_init>
}
    80200ee4:	a8c17bfd 	ldp	x29, x30, [sp], #16
        its_init(); /*Alloc tables and map lpis*/
    80200ee8:	1400045a 	b	80202050 <its_init>
    80200eec:	d503201f 	nop

0000000080200ef0 <gic_handle>:

void gic_handle()
{
    80200ef0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80200ef4:	910003fd 	mov	x29, sp
    80200ef8:	f9000bf3 	str	x19, [sp, #16]
SYSREG_GEN_ACCESSORS(icc_iar1_el1);
    80200efc:	d538cc13 	mrs	x19, icc_iar1_el1
    unsigned long ack = sysreg_icc_iar1_el1_read();
    unsigned long id = ack & ((1UL << 24) -1);
    80200f00:	92405e60 	and	x0, x19, #0xffffff

    if (id >= 1022 && id != 8192) return;
    80200f04:	d2840001 	mov	x1, #0x2000                	// #8192
    80200f08:	f10ff41f 	cmp	x0, #0x3fd
    80200f0c:	fa418004 	ccmp	x0, x1, #0x4, hi	// hi = pmore
    80200f10:	54000061 	b.ne	80200f1c <gic_handle+0x2c>  // b.any

    irq_handle(id);
    80200f14:	97fffe47 	bl	80200830 <irq_handle>
SYSREG_GEN_ACCESSORS(icc_eoir1_el1);
    80200f18:	d518cc33 	msr	icc_eoir1_el1, x19

    sysreg_icc_eoir1_el1_write(ack);
    //sysreg_icc_dir_el1_write(ack);
}
    80200f1c:	f9400bf3 	ldr	x19, [sp, #16]
    80200f20:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80200f24:	d65f03c0 	ret
    80200f28:	d503201f 	nop
    80200f2c:	d503201f 	nop

0000000080200f30 <gicd_get_prio>:

unsigned long gicd_get_prio(unsigned long int_id)
{
    80200f30:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    80200f34:	d37df002 	lsl	x2, x0, #3
    asm volatile (
    80200f38:	d0000101 	adrp	x1, 80222000 <init_lock>
    80200f3c:	52800023 	mov	w3, #0x1                   	// #1
    80200f40:	91004024 	add	x4, x1, #0x10
    80200f44:	d342f000 	ubfx	x0, x0, #2, #59
    80200f48:	885ffc85 	ldaxr	w5, [x4]
    80200f4c:	35ffffe5 	cbnz	w5, 80200f48 <gicd_get_prio+0x18>
    80200f50:	88057c83 	stxr	w5, w3, [x4]
    80200f54:	35ffffa5 	cbnz	w5, 80200f48 <gicd_get_prio+0x18>
    unsigned long off = GIC_PRIO_OFF(int_id);

    spin_lock(&gicd_lock);

    unsigned long prio =
        gicd->IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    80200f58:	b0000081 	adrp	x1, 80211000 <blanks.1+0x60>
    80200f5c:	b9000fe5 	str	w5, [sp, #12]
    unsigned long off = GIC_PRIO_OFF(int_id);
    80200f60:	927d0442 	and	x2, x2, #0x18
        gicd->IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    80200f64:	f9437421 	ldr	x1, [x1, #1768]
    80200f68:	8b000820 	add	x0, x1, x0, lsl #2
    80200f6c:	b9440003 	ldr	w3, [x0, #1024]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80200f70:	889ffc9f 	stlr	wzr, [x4]
    80200f74:	92800001 	mov	x1, #0xffffffffffffffff    	// #-1
    80200f78:	11002044 	add	w4, w2, #0x8
    80200f7c:	aa0103e0 	mov	x0, x1
    80200f80:	1ac22463 	lsr	w3, w3, w2
    80200f84:	9ac22021 	lsl	x1, x1, x2
    unsigned long prio =
    80200f88:	8a030021 	and	x1, x1, x3
        gicd->IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    80200f8c:	9ac42000 	lsl	x0, x0, x4

    spin_unlock(&gicd_lock);

    return prio;
}
    80200f90:	8a200020 	bic	x0, x1, x0
    80200f94:	910043ff 	add	sp, sp, #0x10
    80200f98:	d65f03c0 	ret
    80200f9c:	d503201f 	nop

0000000080200fa0 <gicd_set_icfgr>:

void gicd_set_icfgr(unsigned long int_id, uint8_t cfg)
{
    80200fa0:	d10043ff 	sub	sp, sp, #0x10
    asm volatile (
    80200fa4:	d0000102 	adrp	x2, 80222000 <init_lock>
    80200fa8:	12001c21 	and	w1, w1, #0xff
    80200fac:	52800023 	mov	w3, #0x1                   	// #1
    80200fb0:	91004044 	add	x4, x2, #0x10
    80200fb4:	885ffc85 	ldaxr	w5, [x4]
    80200fb8:	35ffffe5 	cbnz	w5, 80200fb4 <gicd_set_icfgr+0x14>
    80200fbc:	88057c83 	stxr	w5, w3, [x4]
    80200fc0:	35ffffa5 	cbnz	w5, 80200fb4 <gicd_set_icfgr+0x14>

    unsigned long reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    unsigned long off = (int_id * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8);
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;

    gicd->ICFGR[reg_ind] = (gicd->ICFGR[reg_ind] & ~mask) | ((cfg << off) & mask);
    80200fc4:	b0000083 	adrp	x3, 80211000 <blanks.1+0x60>
    80200fc8:	b9000fe5 	str	w5, [sp, #12]
    unsigned long reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    80200fcc:	d344f802 	ubfx	x2, x0, #4, #59
    unsigned long off = (int_id * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8);
    80200fd0:	d37f0c00 	ubfiz	x0, x0, #1, #4
    gicd->ICFGR[reg_ind] = (gicd->ICFGR[reg_ind] & ~mask) | ((cfg << off) & mask);
    80200fd4:	f9437465 	ldr	x5, [x3, #1768]
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;
    80200fd8:	52800063 	mov	w3, #0x3                   	// #3
    80200fdc:	1ac02063 	lsl	w3, w3, w0
    gicd->ICFGR[reg_ind] = (gicd->ICFGR[reg_ind] & ~mask) | ((cfg << off) & mask);
    80200fe0:	1ac02021 	lsl	w1, w1, w0
    80200fe4:	8b0208a0 	add	x0, x5, x2, lsl #2
    80200fe8:	b94c0002 	ldr	w2, [x0, #3072]
    80200fec:	4a020021 	eor	w1, w1, w2
    80200ff0:	0a030021 	and	w1, w1, w3
    80200ff4:	4a020021 	eor	w1, w1, w2
    80200ff8:	b90c0001 	str	w1, [x0, #3072]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80200ffc:	889ffc9f 	stlr	wzr, [x4]

    spin_unlock(&gicd_lock);
}
    80201000:	910043ff 	add	sp, sp, #0x10
    80201004:	d65f03c0 	ret
    80201008:	d503201f 	nop
    8020100c:	d503201f 	nop

0000000080201010 <gicd_set_prio>:

void gicd_set_prio(unsigned long int_id, uint8_t prio)
{
    80201010:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    80201014:	d37df002 	lsl	x2, x0, #3
    asm volatile (
    80201018:	b0000103 	adrp	x3, 80222000 <init_lock>
{
    8020101c:	12001c21 	and	w1, w1, #0xff
    80201020:	52800024 	mov	w4, #0x1                   	// #1
    unsigned long off = GIC_PRIO_OFF(int_id);
    80201024:	d37d0400 	ubfiz	x0, x0, #3, #2
    80201028:	91004065 	add	x5, x3, #0x10
    8020102c:	885ffca6 	ldaxr	w6, [x5]
    80201030:	35ffffe6 	cbnz	w6, 8020102c <gicd_set_prio+0x1c>
    80201034:	88067ca4 	stxr	w6, w4, [x5]
    80201038:	35ffffa6 	cbnz	w6, 8020102c <gicd_set_prio+0x1c>
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);

    spin_lock(&gicd_lock);

    gicd->IPRIORITYR[reg_ind] =
        (gicd->IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    8020103c:	90000083 	adrp	x3, 80211000 <blanks.1+0x60>
    80201040:	b9000fe6 	str	w6, [sp, #12]
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    80201044:	d345fc42 	lsr	x2, x2, #5
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    80201048:	11002007 	add	w7, w0, #0x8
    8020104c:	f9437466 	ldr	x6, [x3, #1768]
    80201050:	92800003 	mov	x3, #0xffffffffffffffff    	// #-1
    80201054:	aa0303e4 	mov	x4, x3
        (gicd->IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    80201058:	1ac02021 	lsl	w1, w1, w0
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    8020105c:	9ac72063 	lsl	x3, x3, x7
    80201060:	8b0208c2 	add	x2, x6, x2, lsl #2
    80201064:	9ac02084 	lsl	x4, x4, x0
    80201068:	8a230083 	bic	x3, x4, x3
        (gicd->IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    8020106c:	b9440040 	ldr	w0, [x2, #1024]
    80201070:	4a000021 	eor	w1, w1, w0
    80201074:	0a030021 	and	w1, w1, w3
    80201078:	4a000021 	eor	w1, w1, w0
    gicd->IPRIORITYR[reg_ind] =
    8020107c:	b9040041 	str	w1, [x2, #1024]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201080:	889ffcbf 	stlr	wzr, [x5]

    spin_unlock(&gicd_lock);
}
    80201084:	910043ff 	add	sp, sp, #0x10
    80201088:	d65f03c0 	ret
    8020108c:	d503201f 	nop

0000000080201090 <gicd_get_state>:

enum int_state gicd_get_state(unsigned long int_id)
{
    unsigned long reg_ind = GIC_INT_REG(int_id);
    unsigned long mask = GIC_INT_MASK(int_id);
    80201090:	52800022 	mov	w2, #0x1                   	// #1
{
    80201094:	d10043ff 	sub	sp, sp, #0x10
    asm volatile (
    80201098:	b0000101 	adrp	x1, 80222000 <init_lock>
    unsigned long mask = GIC_INT_MASK(int_id);
    8020109c:	1ac02043 	lsl	w3, w2, w0
    802010a0:	91004024 	add	x4, x1, #0x10
    802010a4:	885ffc85 	ldaxr	w5, [x4]
    802010a8:	35ffffe5 	cbnz	w5, 802010a4 <gicd_get_state+0x14>
    802010ac:	88057c82 	stxr	w5, w2, [x4]
    802010b0:	35ffffa5 	cbnz	w5, 802010a4 <gicd_get_state+0x14>

    spin_lock(&gicd_lock);

    enum int_state pend = (gicd->ISPENDR[reg_ind] & mask) ? PEND : 0;
    802010b4:	90000081 	adrp	x1, 80211000 <blanks.1+0x60>
    unsigned long reg_ind = GIC_INT_REG(int_id);
    802010b8:	d345fc00 	lsr	x0, x0, #5
    802010bc:	b9000fe5 	str	w5, [sp, #12]
    enum int_state pend = (gicd->ISPENDR[reg_ind] & mask) ? PEND : 0;
    802010c0:	f9437421 	ldr	x1, [x1, #1768]
    802010c4:	8b000820 	add	x0, x1, x0, lsl #2
    802010c8:	b9420002 	ldr	w2, [x0, #512]
    enum int_state act = (gicd->ISACTIVER[reg_ind] & mask) ? ACT : 0;
    802010cc:	b9430000 	ldr	w0, [x0, #768]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802010d0:	889ffc9f 	stlr	wzr, [x4]
    802010d4:	6a00007f 	tst	w3, w0
    802010d8:	1a9f07e1 	cset	w1, ne	// ne = any
    enum int_state pend = (gicd->ISPENDR[reg_ind] & mask) ? PEND : 0;
    802010dc:	6a02007f 	tst	w3, w2
    802010e0:	1a9f07e0 	cset	w0, ne	// ne = any

    spin_unlock(&gicd_lock);

    return pend | act;
}
    802010e4:	910043ff 	add	sp, sp, #0x10
    802010e8:	2a010400 	orr	w0, w0, w1, lsl #1
    802010ec:	d65f03c0 	ret

00000000802010f0 <gicd_set_act>:
    asm volatile (
    802010f0:	b0000102 	adrp	x2, 80222000 <init_lock>

    spin_unlock(&gicd_lock);
}

void gicd_set_act(unsigned long int_id, bool act)
{
    802010f4:	d10043ff 	sub	sp, sp, #0x10
    802010f8:	12001c21 	and	w1, w1, #0xff
    unsigned long reg_ind = GIC_INT_REG(int_id);
    802010fc:	d345fc04 	lsr	x4, x0, #5
    80201100:	91004046 	add	x6, x2, #0x10
    80201104:	52800023 	mov	w3, #0x1                   	// #1
    80201108:	885ffcc5 	ldaxr	w5, [x6]
    8020110c:	35ffffe5 	cbnz	w5, 80201108 <gicd_set_act+0x18>
    80201110:	88057cc3 	stxr	w5, w3, [x6]
    80201114:	35ffffa5 	cbnz	w5, 80201108 <gicd_set_act+0x18>

    spin_lock(&gicd_lock);

    if (act) {
        gicd->ISACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    80201118:	1ac02063 	lsl	w3, w3, w0
    8020111c:	90000080 	adrp	x0, 80211000 <blanks.1+0x60>
    80201120:	b9000fe5 	str	w5, [sp, #12]
    80201124:	f9437400 	ldr	x0, [x0, #1768]
    80201128:	8b040804 	add	x4, x0, x4, lsl #2
    if (act) {
    8020112c:	360000c1 	tbz	w1, #0, 80201144 <gicd_set_act+0x54>
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201130:	91004042 	add	x2, x2, #0x10
        gicd->ISACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    80201134:	b9030083 	str	w3, [x4, #768]
    80201138:	889ffc5f 	stlr	wzr, [x2]
    } else {
        gicd->ICACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    }

    spin_unlock(&gicd_lock);
}
    8020113c:	910043ff 	add	sp, sp, #0x10
    80201140:	d65f03c0 	ret
    80201144:	91004042 	add	x2, x2, #0x10
        gicd->ICACTIVER[reg_ind] = GIC_INT_MASK(int_id);
    80201148:	b9038083 	str	w3, [x4, #896]
    8020114c:	889ffc5f 	stlr	wzr, [x2]
}
    80201150:	910043ff 	add	sp, sp, #0x10
    80201154:	d65f03c0 	ret
    80201158:	d503201f 	nop
    8020115c:	d503201f 	nop

0000000080201160 <gicd_set_state>:

void gicd_set_state(unsigned long int_id, enum int_state state)
{
    80201160:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80201164:	2a0103e8 	mov	w8, w1
    80201168:	aa0003e7 	mov	x7, x0
    8020116c:	910003fd 	mov	x29, sp
    gicd_set_act(int_id, state & ACT);
    80201170:	d3410501 	ubfx	x1, x8, #1, #1
    80201174:	97ffffdf 	bl	802010f0 <gicd_set_act>
    asm volatile (
    80201178:	b0000100 	adrp	x0, 80222000 <init_lock>
    gicd_set_pend(int_id, state & PEND);
    8020117c:	12000108 	and	w8, w8, #0x1
    80201180:	91004003 	add	x3, x0, #0x10
    80201184:	52800021 	mov	w1, #0x1                   	// #1
    80201188:	885ffc62 	ldaxr	w2, [x3]
    8020118c:	35ffffe2 	cbnz	w2, 80201188 <gicd_set_state+0x28>
    80201190:	88027c61 	stxr	w2, w1, [x3]
    80201194:	35ffffa2 	cbnz	w2, 80201188 <gicd_set_state+0x28>
    80201198:	b9001fe2 	str	w2, [sp, #28]
    if (gic_is_sgi(int_id)) {
    8020119c:	f1003cff 	cmp	x7, #0xf
    802011a0:	540001e8 	b.hi	802011dc <gicd_set_state+0x7c>  // b.pmore
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011a4:	90000083 	adrp	x3, 80211000 <blanks.1+0x60>
        unsigned long reg_ind = GICD_SGI_REG(int_id);
    802011a8:	d342fce2 	lsr	x2, x7, #2
        unsigned long off = GICD_SGI_OFF(int_id);
    802011ac:	d37d04e7 	ubfiz	x7, x7, #3, #2
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011b0:	f9437463 	ldr	x3, [x3, #1768]
        if (pend) {
    802011b4:	34000348 	cbz	w8, 8020121c <gicd_set_state+0xbc>
SYSREG_GEN_ACCESSORS(mpidr_el1);
    802011b8:	d53800a4 	mrs	x4, mpidr_el1
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011bc:	8b020862 	add	x2, x3, x2, lsl #2
    802011c0:	0b2400e3 	add	w3, w7, w4, uxtb
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802011c4:	91004000 	add	x0, x0, #0x10
    802011c8:	1ac32021 	lsl	w1, w1, w3
    802011cc:	b90f2041 	str	w1, [x2, #3872]
    802011d0:	889ffc1f 	stlr	wzr, [x0]
}
    802011d4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802011d8:	d65f03c0 	ret
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011dc:	90000082 	adrp	x2, 80211000 <blanks.1+0x60>
            gicd->ISPENDR[reg_ind] = GIC_INT_MASK(int_id);
    802011e0:	1ac72021 	lsl	w1, w1, w7
        unsigned long reg_ind = GIC_INT_REG(int_id);
    802011e4:	d345fce7 	lsr	x7, x7, #5
            gicd->SPENDSGIR[reg_ind] = (1U) << (off + get_cpuid());
    802011e8:	f9437442 	ldr	x2, [x2, #1768]
            gicd->ISPENDR[reg_ind] = GIC_INT_MASK(int_id);
    802011ec:	8b070847 	add	x7, x2, x7, lsl #2
        if (pend) {
    802011f0:	350000c8 	cbnz	w8, 80201208 <gicd_set_state+0xa8>
    802011f4:	91004000 	add	x0, x0, #0x10
            gicd->ICPENDR[reg_ind] = GIC_INT_MASK(int_id);
    802011f8:	b90280e1 	str	w1, [x7, #640]
    802011fc:	889ffc1f 	stlr	wzr, [x0]
}
    80201200:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80201204:	d65f03c0 	ret
    80201208:	91004000 	add	x0, x0, #0x10
            gicd->ISPENDR[reg_ind] = GIC_INT_MASK(int_id);
    8020120c:	b90200e1 	str	w1, [x7, #512]
    80201210:	889ffc1f 	stlr	wzr, [x0]
}
    80201214:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80201218:	d65f03c0 	ret
            gicd->CPENDSGIR[reg_ind] = BIT_MASK(off, 8);
    8020121c:	8b020862 	add	x2, x3, x2, lsl #2
    80201220:	110020e4 	add	w4, w7, #0x8
    80201224:	d2800023 	mov	x3, #0x1                   	// #1
    80201228:	92800001 	mov	x1, #0xffffffffffffffff    	// #-1
    8020122c:	9ac72063 	lsl	x3, x3, x7
    80201230:	4b0303e3 	neg	w3, w3
    80201234:	9ac42021 	lsl	x1, x1, x4
    80201238:	91004000 	add	x0, x0, #0x10
    8020123c:	0a210061 	bic	w1, w3, w1
    80201240:	b90f1041 	str	w1, [x2, #3856]
    80201244:	889ffc1f 	stlr	wzr, [x0]
}
    80201248:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020124c:	d65f03c0 	ret

0000000080201250 <gicd_set_trgt>:

void gicd_set_trgt(unsigned long int_id, uint8_t trgt)
{
    80201250:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_TARGET_REG(int_id);
    80201254:	d37df004 	lsl	x4, x0, #3
    asm volatile (
    80201258:	b0000102 	adrp	x2, 80222000 <init_lock>
{
    8020125c:	12001c21 	and	w1, w1, #0xff
    80201260:	52800023 	mov	w3, #0x1                   	// #1
    unsigned long off = GIC_TARGET_OFF(int_id);
    80201264:	d37d0400 	ubfiz	x0, x0, #3, #2
    80201268:	91004046 	add	x6, x2, #0x10
    8020126c:	885ffcc5 	ldaxr	w5, [x6]
    80201270:	35ffffe5 	cbnz	w5, 8020126c <gicd_set_trgt+0x1c>
    80201274:	88057cc3 	stxr	w5, w3, [x6]
    80201278:	35ffffa5 	cbnz	w5, 8020126c <gicd_set_trgt+0x1c>
    uint32_t mask = BIT_MASK(off, GIC_TARGET_BITS);

    spin_lock(&gicd_lock);

    gicd->ITARGETSR[reg_ind] =
        (gicd->ITARGETSR[reg_ind] & ~mask) | ((trgt << off) & mask);
    8020127c:	90000083 	adrp	x3, 80211000 <blanks.1+0x60>
    80201280:	b9000fe5 	str	w5, [sp, #12]
    unsigned long reg_ind = GIC_TARGET_REG(int_id);
    80201284:	d345fc84 	lsr	x4, x4, #5
    uint32_t mask = BIT_MASK(off, GIC_TARGET_BITS);
    80201288:	d2800022 	mov	x2, #0x1                   	// #1
    8020128c:	f9437465 	ldr	x5, [x3, #1768]
    80201290:	9ac02042 	lsl	x2, x2, x0
        (gicd->ITARGETSR[reg_ind] & ~mask) | ((trgt << off) & mask);
    80201294:	1ac02021 	lsl	w1, w1, w0
    uint32_t mask = BIT_MASK(off, GIC_TARGET_BITS);
    80201298:	11002000 	add	w0, w0, #0x8
    8020129c:	4b0203e3 	neg	w3, w2
    802012a0:	92800002 	mov	x2, #0xffffffffffffffff    	// #-1
    802012a4:	8b0408a4 	add	x4, x5, x4, lsl #2
    802012a8:	9ac02040 	lsl	x0, x2, x0
        (gicd->ITARGETSR[reg_ind] & ~mask) | ((trgt << off) & mask);
    802012ac:	b9480085 	ldr	w5, [x4, #2048]
    802012b0:	4a050021 	eor	w1, w1, w5
    802012b4:	0a010062 	and	w2, w3, w1
    802012b8:	0a200040 	bic	w0, w2, w0
    802012bc:	4a050000 	eor	w0, w0, w5
    gicd->ITARGETSR[reg_ind] =
    802012c0:	b9080080 	str	w0, [x4, #2048]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802012c4:	889ffcdf 	stlr	wzr, [x6]

    spin_unlock(&gicd_lock);
}
    802012c8:	910043ff 	add	sp, sp, #0x10
    802012cc:	d65f03c0 	ret

00000000802012d0 <gicd_set_route>:

void gicd_set_route(unsigned long int_id, unsigned long trgt)
{
    if (gic_is_priv(int_id)) return;
    802012d0:	f1007c1f 	cmp	x0, #0x1f
    802012d4:	54000129 	b.ls	802012f8 <gicd_set_route+0x28>  // b.plast
     * syndrome register. Bao has no support for its emulation. Therefore 
     * we perform the 64-bit access explicitly as two 32-bit stores.
     */

    uint64_t _trgt = trgt;
    volatile uint32_t *irouter = (uint32_t*) &gicd->IROUTER[int_id];
    802012d8:	90000082 	adrp	x2, 80211000 <blanks.1+0x60>
    802012dc:	91300000 	add	x0, x0, #0xc00
    irouter[0] = _trgt;
    irouter[1] = (_trgt >> 32);
    802012e0:	d360fc24 	lsr	x4, x1, #32
    volatile uint32_t *irouter = (uint32_t*) &gicd->IROUTER[int_id];
    802012e4:	f9437442 	ldr	x2, [x2, #1768]
    802012e8:	d37df000 	lsl	x0, x0, #3
    802012ec:	8b000043 	add	x3, x2, x0
    irouter[0] = _trgt;
    802012f0:	b8206841 	str	w1, [x2, x0]
    irouter[1] = (_trgt >> 32);
    802012f4:	b9000464 	str	w4, [x3, #4]
}
    802012f8:	d65f03c0 	ret
    802012fc:	d503201f 	nop

0000000080201300 <gicd_set_enable>:

void gicd_set_enable(unsigned long int_id, bool en)
{
    unsigned long bit = GIC_INT_MASK(int_id);
    80201300:	52800023 	mov	w3, #0x1                   	// #1
    asm volatile (
    80201304:	b0000102 	adrp	x2, 80222000 <init_lock>
    80201308:	1ac02064 	lsl	w4, w3, w0
{
    8020130c:	d10043ff 	sub	sp, sp, #0x10
    80201310:	12001c21 	and	w1, w1, #0xff

    unsigned long reg_ind = GIC_INT_REG(int_id);
    80201314:	d345fc00 	lsr	x0, x0, #5
    80201318:	91004046 	add	x6, x2, #0x10
    8020131c:	885ffcc5 	ldaxr	w5, [x6]
    80201320:	35ffffe5 	cbnz	w5, 8020131c <gicd_set_enable+0x1c>
    80201324:	88057cc3 	stxr	w5, w3, [x6]
    80201328:	35ffffa5 	cbnz	w5, 8020131c <gicd_set_enable+0x1c>
    8020132c:	b9000fe5 	str	w5, [sp, #12]
    spin_lock(&gicd_lock);
    if (en)
    80201330:	36000121 	tbz	w1, #0, 80201354 <gicd_set_enable+0x54>
        gicd->ISENABLER[reg_ind] = bit;
    80201334:	90000081 	adrp	x1, 80211000 <blanks.1+0x60>
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201338:	91004042 	add	x2, x2, #0x10
    8020133c:	f9437421 	ldr	x1, [x1, #1768]
    80201340:	8b000820 	add	x0, x1, x0, lsl #2
    80201344:	b9010004 	str	w4, [x0, #256]
    80201348:	889ffc5f 	stlr	wzr, [x2]
    else
        gicd->ICENABLER[reg_ind] = bit;
    spin_unlock(&gicd_lock);
}
    8020134c:	910043ff 	add	sp, sp, #0x10
    80201350:	d65f03c0 	ret
        gicd->ICENABLER[reg_ind] = bit;
    80201354:	90000081 	adrp	x1, 80211000 <blanks.1+0x60>
    80201358:	91004042 	add	x2, x2, #0x10
    8020135c:	f9437421 	ldr	x1, [x1, #1768]
    80201360:	8b000820 	add	x0, x1, x0, lsl #2
    80201364:	b9018004 	str	w4, [x0, #384]
    80201368:	889ffc5f 	stlr	wzr, [x2]
}
    8020136c:	910043ff 	add	sp, sp, #0x10
    80201370:	d65f03c0 	ret

0000000080201374 <gicr_set_prio>:
    asm volatile (
    80201374:	b0000103 	adrp	x3, 80222000 <init_lock>
    80201378:	91004063 	add	x3, x3, #0x10

void gicr_set_prio(unsigned long int_id, uint8_t prio, uint32_t gicr_id)
{
    8020137c:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    80201380:	d37df004 	lsl	x4, x0, #3
{
    80201384:	12001c21 	and	w1, w1, #0xff
    unsigned long off = GIC_PRIO_OFF(int_id);
    80201388:	d37d0400 	ubfiz	x0, x0, #3, #2
    8020138c:	52800025 	mov	w5, #0x1                   	// #1
    80201390:	91001067 	add	x7, x3, #0x4
    80201394:	885ffce6 	ldaxr	w6, [x7]
    80201398:	35ffffe6 	cbnz	w6, 80201394 <gicr_set_prio+0x20>
    8020139c:	88067ce5 	stxr	w6, w5, [x7]
    802013a0:	35ffffa6 	cbnz	w6, 80201394 <gicr_set_prio+0x20>
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    802013a4:	d345fc84 	lsr	x4, x4, #5
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);

    spin_lock(&gicr_lock);

    gicr[gicr_id].IPRIORITYR[reg_ind] =
        (gicr[gicr_id].IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    802013a8:	90000085 	adrp	x5, 80211000 <blanks.1+0x60>
    802013ac:	b9000fe6 	str	w6, [sp, #12]
    gicr[gicr_id].IPRIORITYR[reg_ind] =
    802013b0:	52a00048 	mov	w8, #0x20000               	// #131072
    802013b4:	d37ef486 	lsl	x6, x4, #2
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    802013b8:	11002007 	add	w7, w0, #0x8
    802013bc:	f94378a4 	ldr	x4, [x5, #1776]
    802013c0:	92800005 	mov	x5, #0xffffffffffffffff    	// #-1
    802013c4:	9ba81842 	umaddl	x2, w2, w8, x6
    802013c8:	aa0503e6 	mov	x6, x5
        (gicr[gicr_id].IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    802013cc:	1ac02021 	lsl	w1, w1, w0
    802013d0:	8b020082 	add	x2, x4, x2
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    802013d4:	9ac020c6 	lsl	x6, x6, x0
        (gicr[gicr_id].IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    802013d8:	91404042 	add	x2, x2, #0x10, lsl #12
    unsigned long mask = BIT_MASK(off, GIC_PRIO_BITS);
    802013dc:	9ac720a5 	lsl	x5, x5, x7
    802013e0:	8a2500c5 	bic	x5, x6, x5
        (gicr[gicr_id].IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);
    802013e4:	b9440040 	ldr	w0, [x2, #1024]
    802013e8:	4a000021 	eor	w1, w1, w0
    802013ec:	0a050021 	and	w1, w1, w5
    802013f0:	4a000021 	eor	w1, w1, w0
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802013f4:	91001060 	add	x0, x3, #0x4
    gicr[gicr_id].IPRIORITYR[reg_ind] =
    802013f8:	b9040041 	str	w1, [x2, #1024]
    802013fc:	889ffc1f 	stlr	wzr, [x0]

    spin_unlock(&gicr_lock);
}
    80201400:	910043ff 	add	sp, sp, #0x10
    80201404:	d65f03c0 	ret
    80201408:	d503201f 	nop
    8020140c:	d503201f 	nop

0000000080201410 <gicr_get_prio>:
    asm volatile (
    80201410:	b0000102 	adrp	x2, 80222000 <init_lock>
    80201414:	91004042 	add	x2, x2, #0x10

unsigned long gicr_get_prio(unsigned long int_id, uint32_t gicr_id)
{
    80201418:	d10043ff 	sub	sp, sp, #0x10
    unsigned long reg_ind = GIC_PRIO_REG(int_id);
    8020141c:	d37df003 	lsl	x3, x0, #3
    80201420:	52800024 	mov	w4, #0x1                   	// #1
    80201424:	d342f000 	ubfx	x0, x0, #2, #59
    80201428:	91001046 	add	x6, x2, #0x4
    8020142c:	885ffcc5 	ldaxr	w5, [x6]
    80201430:	35ffffe5 	cbnz	w5, 8020142c <gicr_get_prio+0x1c>
    80201434:	88057cc4 	stxr	w5, w4, [x6]
    80201438:	35ffffa5 	cbnz	w5, 8020142c <gicr_get_prio+0x1c>
    unsigned long off = GIC_PRIO_OFF(int_id);

    spin_lock(&gicr_lock);

    unsigned long prio =
        gicr[gicr_id].IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    8020143c:	90000084 	adrp	x4, 80211000 <blanks.1+0x60>
    80201440:	d36f7c21 	ubfiz	x1, x1, #17, #32
    80201444:	91401000 	add	x0, x0, #0x4, lsl #12
    80201448:	b9000fe5 	str	w5, [sp, #12]
    8020144c:	f9437884 	ldr	x4, [x4, #1776]
    unsigned long off = GIC_PRIO_OFF(int_id);
    80201450:	927d0463 	and	x3, x3, #0x18
        gicr[gicr_id].IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    80201454:	8b010081 	add	x1, x4, x1
    80201458:	8b000820 	add	x0, x1, x0, lsl #2
    8020145c:	b9440000 	ldr	w0, [x0, #1024]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201460:	889ffcdf 	stlr	wzr, [x6]
    80201464:	92800001 	mov	x1, #0xffffffffffffffff    	// #-1
    80201468:	1ac32402 	lsr	w2, w0, w3
    8020146c:	11002064 	add	w4, w3, #0x8
    80201470:	aa0103e0 	mov	x0, x1
    80201474:	9ac32021 	lsl	x1, x1, x3
    unsigned long prio =
    80201478:	8a020021 	and	x1, x1, x2
        gicr[gicr_id].IPRIORITYR[reg_ind] >> off & BIT_MASK(off, GIC_PRIO_BITS);
    8020147c:	9ac42000 	lsl	x0, x0, x4

    spin_unlock(&gicr_lock);

    return prio;
}
    80201480:	8a200020 	bic	x0, x1, x0
    80201484:	910043ff 	add	sp, sp, #0x10
    80201488:	d65f03c0 	ret
    8020148c:	d503201f 	nop

0000000080201490 <gicr_set_icfgr>:
    asm volatile (
    80201490:	b0000103 	adrp	x3, 80222000 <init_lock>
    80201494:	91004063 	add	x3, x3, #0x10

void gicr_set_icfgr(unsigned long int_id, uint8_t cfg, uint32_t gicr_id)
{
    80201498:	d10043ff 	sub	sp, sp, #0x10
    8020149c:	12001c21 	and	w1, w1, #0xff
    802014a0:	91001065 	add	x5, x3, #0x4
    802014a4:	52800024 	mov	w4, #0x1                   	// #1
    802014a8:	885ffca6 	ldaxr	w6, [x5]
    802014ac:	35ffffe6 	cbnz	w6, 802014a8 <gicr_set_icfgr+0x18>
    802014b0:	88067ca4 	stxr	w6, w4, [x5]
    802014b4:	35ffffa6 	cbnz	w6, 802014a8 <gicr_set_icfgr+0x18>
    spin_lock(&gicr_lock);

    unsigned long reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    unsigned long off = (int_id * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8);
    802014b8:	d37f0c05 	ubfiz	x5, x0, #1, #4
    unsigned long reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    802014bc:	d37ff800 	lsl	x0, x0, #1
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;

    if (reg_ind == 0) {
    802014c0:	f1007c1f 	cmp	x0, #0x1f
        gicr[gicr_id].ICFGR0 =
            (gicr[gicr_id].ICFGR0 & ~mask) | ((cfg << off) & mask);
    802014c4:	90000080 	adrp	x0, 80211000 <blanks.1+0x60>
    802014c8:	d36f7c42 	ubfiz	x2, x2, #17, #32
    802014cc:	b9000fe6 	str	w6, [sp, #12]
    802014d0:	f9437800 	ldr	x0, [x0, #1776]
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;
    802014d4:	52800064 	mov	w4, #0x3                   	// #3
            (gicr[gicr_id].ICFGR0 & ~mask) | ((cfg << off) & mask);
    802014d8:	1ac52021 	lsl	w1, w1, w5
    802014dc:	8b020000 	add	x0, x0, x2
    unsigned long mask = ((1U << GIC_CONFIG_BITS) - 1) << off;
    802014e0:	1ac52084 	lsl	w4, w4, w5
            (gicr[gicr_id].ICFGR0 & ~mask) | ((cfg << off) & mask);
    802014e4:	91404000 	add	x0, x0, #0x10, lsl #12
    if (reg_ind == 0) {
    802014e8:	54000148 	b.hi	80201510 <gicr_set_icfgr+0x80>  // b.pmore
            (gicr[gicr_id].ICFGR0 & ~mask) | ((cfg << off) & mask);
    802014ec:	b94c0002 	ldr	w2, [x0, #3072]
    802014f0:	4a010041 	eor	w1, w2, w1
    802014f4:	0a040021 	and	w1, w1, w4
    802014f8:	4a020021 	eor	w1, w1, w2
        gicr[gicr_id].ICFGR0 =
    802014fc:	b90c0001 	str	w1, [x0, #3072]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201500:	91001060 	add	x0, x3, #0x4
    80201504:	889ffc1f 	stlr	wzr, [x0]
        gicr[gicr_id].ICFGR1 =
            (gicr[gicr_id].ICFGR1 & ~mask) | ((cfg << off) & mask);
    }

    spin_unlock(&gicr_lock);
}
    80201508:	910043ff 	add	sp, sp, #0x10
    8020150c:	d65f03c0 	ret
            (gicr[gicr_id].ICFGR1 & ~mask) | ((cfg << off) & mask);
    80201510:	b94c0402 	ldr	w2, [x0, #3076]
    80201514:	4a010041 	eor	w1, w2, w1
    80201518:	0a040021 	and	w1, w1, w4
    8020151c:	4a020021 	eor	w1, w1, w2
        gicr[gicr_id].ICFGR1 =
    80201520:	b90c0401 	str	w1, [x0, #3076]
    80201524:	91001060 	add	x0, x3, #0x4
    80201528:	889ffc1f 	stlr	wzr, [x0]
}
    8020152c:	910043ff 	add	sp, sp, #0x10
    80201530:	d65f03c0 	ret

0000000080201534 <gicr_get_state>:

enum int_state gicr_get_state(unsigned long int_id, uint32_t gicr_id)
{
    unsigned long mask = GIC_INT_MASK(int_id);
    80201534:	52800023 	mov	w3, #0x1                   	// #1
    asm volatile (
    80201538:	b0000102 	adrp	x2, 80222000 <init_lock>
    8020153c:	91004042 	add	x2, x2, #0x10
{
    80201540:	d10043ff 	sub	sp, sp, #0x10
    unsigned long mask = GIC_INT_MASK(int_id);
    80201544:	1ac02064 	lsl	w4, w3, w0
    80201548:	91001040 	add	x0, x2, #0x4
    8020154c:	885ffc05 	ldaxr	w5, [x0]
    80201550:	35ffffe5 	cbnz	w5, 8020154c <gicr_get_state+0x18>
    80201554:	88057c03 	stxr	w5, w3, [x0]
    80201558:	35ffffa5 	cbnz	w5, 8020154c <gicr_get_state+0x18>

    spin_lock(&gicr_lock);

    enum int_state pend = (gicr[gicr_id].ISPENDR0 & mask) ? PEND : 0;
    8020155c:	90000080 	adrp	x0, 80211000 <blanks.1+0x60>
    80201560:	d36f7c23 	ubfiz	x3, x1, #17, #32
    80201564:	b9000fe5 	str	w5, [sp, #12]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201568:	91001042 	add	x2, x2, #0x4
    8020156c:	f9437801 	ldr	x1, [x0, #1776]
    80201570:	8b030021 	add	x1, x1, x3
    80201574:	91404021 	add	x1, x1, #0x10, lsl #12
    80201578:	b9420020 	ldr	w0, [x1, #512]
    enum int_state act = (gicr[gicr_id].ISACTIVER0 & mask) ? ACT : 0;
    8020157c:	b9430021 	ldr	w1, [x1, #768]
    80201580:	889ffc5f 	stlr	wzr, [x2]
    80201584:	6a01009f 	tst	w4, w1
    80201588:	1a9f07e1 	cset	w1, ne	// ne = any
    enum int_state pend = (gicr[gicr_id].ISPENDR0 & mask) ? PEND : 0;
    8020158c:	6a00009f 	tst	w4, w0
    80201590:	1a9f07e0 	cset	w0, ne	// ne = any

    spin_unlock(&gicr_lock);

    return pend | act;
}
    80201594:	910043ff 	add	sp, sp, #0x10
    80201598:	2a010400 	orr	w0, w0, w1, lsl #1
    8020159c:	d65f03c0 	ret

00000000802015a0 <gicr_set_act>:
    asm volatile (
    802015a0:	b0000103 	adrp	x3, 80222000 <init_lock>
    802015a4:	91004063 	add	x3, x3, #0x10
    }
    spin_unlock(&gicr_lock);
}

void gicr_set_act(unsigned long int_id, bool act, uint32_t gicr_id)
{
    802015a8:	d10043ff 	sub	sp, sp, #0x10
    802015ac:	12001c21 	and	w1, w1, #0xff
    802015b0:	91001066 	add	x6, x3, #0x4
    802015b4:	52800024 	mov	w4, #0x1                   	// #1
    802015b8:	885ffcc5 	ldaxr	w5, [x6]
    802015bc:	35ffffe5 	cbnz	w5, 802015b8 <gicr_set_act+0x18>
    802015c0:	88057cc4 	stxr	w5, w4, [x6]
    802015c4:	35ffffa5 	cbnz	w5, 802015b8 <gicr_set_act+0x18>
    spin_lock(&gicr_lock);

    if (act) {
        gicr[gicr_id].ISACTIVER0 = GIC_INT_MASK(int_id);
    802015c8:	1ac02084 	lsl	w4, w4, w0
    802015cc:	90000080 	adrp	x0, 80211000 <blanks.1+0x60>
    802015d0:	d36f7c42 	ubfiz	x2, x2, #17, #32
    802015d4:	b9000fe5 	str	w5, [sp, #12]
    802015d8:	f9437800 	ldr	x0, [x0, #1776]
    802015dc:	8b020000 	add	x0, x0, x2
    802015e0:	91404000 	add	x0, x0, #0x10, lsl #12
    if (act) {
    802015e4:	360000c1 	tbz	w1, #0, 802015fc <gicr_set_act+0x5c>
        gicr[gicr_id].ISACTIVER0 = GIC_INT_MASK(int_id);
    802015e8:	b9030004 	str	w4, [x0, #768]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802015ec:	91001060 	add	x0, x3, #0x4
    802015f0:	889ffc1f 	stlr	wzr, [x0]
    } else {
        gicr[gicr_id].ICACTIVER0 = GIC_INT_MASK(int_id);
    }

    spin_unlock(&gicr_lock);
}
    802015f4:	910043ff 	add	sp, sp, #0x10
    802015f8:	d65f03c0 	ret
        gicr[gicr_id].ICACTIVER0 = GIC_INT_MASK(int_id);
    802015fc:	b9038004 	str	w4, [x0, #896]
    80201600:	91001060 	add	x0, x3, #0x4
    80201604:	889ffc1f 	stlr	wzr, [x0]
}
    80201608:	910043ff 	add	sp, sp, #0x10
    8020160c:	d65f03c0 	ret

0000000080201610 <gicr_set_state>:

void gicr_set_state(unsigned long int_id, enum int_state state, uint32_t gicr_id)
{
    80201610:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80201614:	2a0103e8 	mov	w8, w1
    80201618:	aa0003e9 	mov	x9, x0
    8020161c:	910003fd 	mov	x29, sp
    gicr_set_act(int_id, state & ACT, gicr_id);
    80201620:	d3410501 	ubfx	x1, x8, #1, #1
{
    80201624:	2a0203e7 	mov	w7, w2
    gicr_set_act(int_id, state & ACT, gicr_id);
    80201628:	97ffffde 	bl	802015a0 <gicr_set_act>
    asm volatile (
    8020162c:	b0000103 	adrp	x3, 80222000 <init_lock>
    80201630:	91004063 	add	x3, x3, #0x10
    80201634:	91001061 	add	x1, x3, #0x4
    80201638:	52800024 	mov	w4, #0x1                   	// #1
    8020163c:	885ffc20 	ldaxr	w0, [x1]
    80201640:	35ffffe0 	cbnz	w0, 8020163c <gicr_set_state+0x2c>
    80201644:	88007c24 	stxr	w0, w4, [x1]
    80201648:	35ffffa0 	cbnz	w0, 8020163c <gicr_set_state+0x2c>
    8020164c:	b9001fe0 	str	w0, [sp, #28]
        gicr[gicr_id].ISPENDR0 = (1U) << (int_id);
    80201650:	90000080 	adrp	x0, 80211000 <blanks.1+0x60>
    80201654:	d36f7ce7 	ubfiz	x7, x7, #17, #32
    80201658:	1ac92084 	lsl	w4, w4, w9
    8020165c:	f9437800 	ldr	x0, [x0, #1776]
    80201660:	8b070000 	add	x0, x0, x7
    80201664:	91404000 	add	x0, x0, #0x10, lsl #12
    if (pend) {
    80201668:	360000c8 	tbz	w8, #0, 80201680 <gicr_set_state+0x70>
        gicr[gicr_id].ISPENDR0 = (1U) << (int_id);
    8020166c:	b9020004 	str	w4, [x0, #512]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201670:	91001060 	add	x0, x3, #0x4
    80201674:	889ffc1f 	stlr	wzr, [x0]
    gicr_set_pend(int_id, state & PEND, gicr_id);
}
    80201678:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020167c:	d65f03c0 	ret
        gicr[gicr_id].ICPENDR0 = (1U) << (int_id);
    80201680:	b9028004 	str	w4, [x0, #640]
    80201684:	91001060 	add	x0, x3, #0x4
    80201688:	889ffc1f 	stlr	wzr, [x0]
}
    8020168c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80201690:	d65f03c0 	ret

0000000080201694 <gicr_set_trgt>:
    asm volatile (
    80201694:	b0000100 	adrp	x0, 80222000 <init_lock>
    80201698:	91004000 	add	x0, x0, #0x10

void gicr_set_trgt(unsigned long int_id, uint8_t trgt, uint32_t gicr_id)
{
    8020169c:	d10043ff 	sub	sp, sp, #0x10
    802016a0:	52800021 	mov	w1, #0x1                   	// #1
    802016a4:	91001003 	add	x3, x0, #0x4
    802016a8:	885ffc62 	ldaxr	w2, [x3]
    802016ac:	35ffffe2 	cbnz	w2, 802016a8 <gicr_set_trgt+0x14>
    802016b0:	88027c61 	stxr	w2, w1, [x3]
    802016b4:	35ffffa2 	cbnz	w2, 802016a8 <gicr_set_trgt+0x14>
    802016b8:	b9000fe2 	str	w2, [sp, #12]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802016bc:	889ffc7f 	stlr	wzr, [x3]
    spin_lock(&gicr_lock);

    spin_unlock(&gicr_lock);
}
    802016c0:	910043ff 	add	sp, sp, #0x10
    802016c4:	d65f03c0 	ret
    802016c8:	d503201f 	nop
    802016cc:	d503201f 	nop

00000000802016d0 <gicr_set_route>:

void gicr_set_route(unsigned long int_id, uint8_t trgt, uint32_t gicr_id)
    802016d0:	b0000100 	adrp	x0, 80222000 <init_lock>
    802016d4:	91004000 	add	x0, x0, #0x10
    802016d8:	d10043ff 	sub	sp, sp, #0x10
    802016dc:	52800021 	mov	w1, #0x1                   	// #1
    802016e0:	91001003 	add	x3, x0, #0x4
    802016e4:	885ffc62 	ldaxr	w2, [x3]
    802016e8:	35ffffe2 	cbnz	w2, 802016e4 <gicr_set_route+0x14>
    802016ec:	88027c61 	stxr	w2, w1, [x3]
    802016f0:	35ffffa2 	cbnz	w2, 802016e4 <gicr_set_route+0x14>
    802016f4:	b9000fe2 	str	w2, [sp, #12]
    802016f8:	889ffc7f 	stlr	wzr, [x3]
    802016fc:	910043ff 	add	sp, sp, #0x10
    80201700:	d65f03c0 	ret

0000000080201704 <gicr_set_enable>:
    gicr_set_trgt(int_id, trgt, gicr_id);
}

void gicr_set_enable(unsigned long int_id, bool en, uint32_t gicr_id)
{
    unsigned long bit = GIC_INT_MASK(int_id);
    80201704:	52800024 	mov	w4, #0x1                   	// #1
    asm volatile (
    80201708:	b0000103 	adrp	x3, 80222000 <init_lock>
    8020170c:	91004063 	add	x3, x3, #0x10
{
    80201710:	d10043ff 	sub	sp, sp, #0x10
    80201714:	12001c21 	and	w1, w1, #0xff
    80201718:	91001066 	add	x6, x3, #0x4
    unsigned long bit = GIC_INT_MASK(int_id);
    8020171c:	1ac02080 	lsl	w0, w4, w0
    80201720:	885ffcc5 	ldaxr	w5, [x6]
    80201724:	35ffffe5 	cbnz	w5, 80201720 <gicr_set_enable+0x1c>
    80201728:	88057cc4 	stxr	w5, w4, [x6]
    8020172c:	35ffffa5 	cbnz	w5, 80201720 <gicr_set_enable+0x1c>
    80201730:	b9000fe5 	str	w5, [sp, #12]

    spin_lock(&gicr_lock);
    if (en)
        gicr[gicr_id].ISENABLER0 = bit;
    80201734:	d36f7c42 	ubfiz	x2, x2, #17, #32
    if (en)
    80201738:	36000141 	tbz	w1, #0, 80201760 <gicr_set_enable+0x5c>
        gicr[gicr_id].ISENABLER0 = bit;
    8020173c:	90000081 	adrp	x1, 80211000 <blanks.1+0x60>
    80201740:	f9437821 	ldr	x1, [x1, #1776]
    80201744:	8b020021 	add	x1, x1, x2
    80201748:	91404021 	add	x1, x1, #0x10, lsl #12
    8020174c:	b9010020 	str	w0, [x1, #256]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80201750:	91001060 	add	x0, x3, #0x4
    80201754:	889ffc1f 	stlr	wzr, [x0]
    else
        gicr[gicr_id].ICENABLER0 = bit;
    spin_unlock(&gicr_lock);
}
    80201758:	910043ff 	add	sp, sp, #0x10
    8020175c:	d65f03c0 	ret
        gicr[gicr_id].ICENABLER0 = bit;
    80201760:	90000081 	adrp	x1, 80211000 <blanks.1+0x60>
    80201764:	f9437821 	ldr	x1, [x1, #1776]
    80201768:	8b020021 	add	x1, x1, x2
    8020176c:	91404021 	add	x1, x1, #0x10, lsl #12
    80201770:	b9018020 	str	w0, [x1, #384]
    80201774:	91001060 	add	x0, x3, #0x4
    80201778:	889ffc1f 	stlr	wzr, [x0]
}
    8020177c:	910043ff 	add	sp, sp, #0x10
    80201780:	d65f03c0 	ret

0000000080201784 <gic_send_sgi>:
    else return false;
}

void gic_send_sgi(unsigned long cpu_target, unsigned long sgi_num)
{
    if (sgi_num >= GIC_MAX_SGIS) return;
    80201784:	f1003c3f 	cmp	x1, #0xf
    80201788:	540000a8 	b.hi	8020179c <gic_send_sgi+0x18>  // b.pmore
    
    unsigned long sgi = (1UL << (cpu_target & 0xffull)) | (sgi_num << 24);
    8020178c:	d2800022 	mov	x2, #0x1                   	// #1
    80201790:	9ac02040 	lsl	x0, x2, x0
    80201794:	aa016001 	orr	x1, x0, x1, lsl #24
SYSREG_GEN_ACCESSORS(icc_sgi1r_el1);
    80201798:	d518cba1 	msr	icc_sgi1r_el1, x1
    sysreg_icc_sgi1r_el1_write(sgi); 
}
    8020179c:	d65f03c0 	ret

00000000802017a0 <gic_set_prio>:
    if (int_id > 32 && int_id < 1025) return true;
    802017a0:	d1008402 	sub	x2, x0, #0x21

void gic_set_prio(unsigned long int_id, uint8_t prio)
{
    802017a4:	12001c21 	and	w1, w1, #0xff
    if (int_id > 32 && int_id < 1025) return true;
    802017a8:	f10f7c5f 	cmp	x2, #0x3df
    802017ac:	54000048 	b.hi	802017b4 <gic_set_prio+0x14>  // b.pmore
    if (irq_in_gicd(int_id)) {
        return gicd_set_prio(int_id, prio);
    802017b0:	17fffe18 	b	80201010 <gicd_set_prio>
SYSREG_GEN_ACCESSORS(mpidr_el1);
    802017b4:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_prio(int_id, prio, get_cpuid());
    802017b8:	12001c42 	and	w2, w2, #0xff
    802017bc:	17fffeee 	b	80201374 <gicr_set_prio>

00000000802017c0 <gic_get_prio>:
    if (int_id > 32 && int_id < 1025) return true;
    802017c0:	d1008401 	sub	x1, x0, #0x21
    802017c4:	f10f7c3f 	cmp	x1, #0x3df
    802017c8:	54000048 	b.hi	802017d0 <gic_get_prio+0x10>  // b.pmore
}

unsigned long gic_get_prio(unsigned long int_id)
{
    if (irq_in_gicd(int_id)) {
        return gicd_get_prio(int_id);
    802017cc:	17fffdd9 	b	80200f30 <gicd_get_prio>
    802017d0:	d53800a1 	mrs	x1, mpidr_el1
    } else {
        return gicr_get_prio(int_id, get_cpuid());
    802017d4:	12001c21 	and	w1, w1, #0xff
    802017d8:	17ffff0e 	b	80201410 <gicr_get_prio>
    802017dc:	d503201f 	nop

00000000802017e0 <gic_set_icfgr>:
    if (int_id > 32 && int_id < 1025) return true;
    802017e0:	d1008402 	sub	x2, x0, #0x21
    }
}

void gic_set_icfgr(unsigned long int_id, uint8_t cfg)
{
    802017e4:	12001c21 	and	w1, w1, #0xff
    if (int_id > 32 && int_id < 1025) return true;
    802017e8:	f10f7c5f 	cmp	x2, #0x3df
    802017ec:	54000048 	b.hi	802017f4 <gic_set_icfgr+0x14>  // b.pmore
    if (irq_in_gicd(int_id)) {
        return gicd_set_icfgr(int_id, cfg);
    802017f0:	17fffdec 	b	80200fa0 <gicd_set_icfgr>
    802017f4:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_icfgr(int_id, cfg, get_cpuid());
    802017f8:	12001c42 	and	w2, w2, #0xff
    802017fc:	17ffff25 	b	80201490 <gicr_set_icfgr>

0000000080201800 <gic_get_state>:
    if (int_id > 32 && int_id < 1025) return true;
    80201800:	d1008401 	sub	x1, x0, #0x21
    80201804:	f10f7c3f 	cmp	x1, #0x3df
    80201808:	54000048 	b.hi	80201810 <gic_get_state+0x10>  // b.pmore
}

enum int_state gic_get_state(unsigned long int_id)
{
    if (irq_in_gicd(int_id)) {
        return gicd_get_state(int_id);
    8020180c:	17fffe21 	b	80201090 <gicd_get_state>
    80201810:	d53800a1 	mrs	x1, mpidr_el1
    } else {
        return gicr_get_state(int_id, get_cpuid());
    80201814:	12001c21 	and	w1, w1, #0xff
    80201818:	17ffff47 	b	80201534 <gicr_get_state>
    8020181c:	d503201f 	nop

0000000080201820 <gic_set_act>:
    if (int_id > 32 && int_id < 1025) return true;
    80201820:	d1008402 	sub	x2, x0, #0x21
        return gicr_set_pend(int_id, pend, get_cpuid());
    }
}

void gic_set_act(unsigned long int_id, bool act)
{
    80201824:	12001c21 	and	w1, w1, #0xff
    if (int_id > 32 && int_id < 1025) return true;
    80201828:	f10f7c5f 	cmp	x2, #0x3df
    8020182c:	54000048 	b.hi	80201834 <gic_set_act+0x14>  // b.pmore
    if (irq_in_gicd(int_id)) {
        return gicd_set_act(int_id, act);
    80201830:	17fffe30 	b	802010f0 <gicd_set_act>
    80201834:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_act(int_id, act, get_cpuid());
    80201838:	12001c42 	and	w2, w2, #0xff
    8020183c:	17ffff59 	b	802015a0 <gicr_set_act>

0000000080201840 <gic_set_state>:
    if (int_id > 32 && int_id < 1025) return true;
    80201840:	d1008402 	sub	x2, x0, #0x21
    80201844:	f10f7c5f 	cmp	x2, #0x3df
    80201848:	54000048 	b.hi	80201850 <gic_set_state+0x10>  // b.pmore
}

void gic_set_state(unsigned long int_id, enum int_state state)
{
    if (irq_in_gicd(int_id)) {
        return gicd_set_state(int_id, state);
    8020184c:	17fffe45 	b	80201160 <gicd_set_state>
    80201850:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_state(int_id, state, get_cpuid());
    80201854:	12001c42 	and	w2, w2, #0xff
    80201858:	17ffff6e 	b	80201610 <gicr_set_state>
    8020185c:	d503201f 	nop

0000000080201860 <gic_set_trgt>:
    if (int_id > 32 && int_id < 1025) return true;
    80201860:	d1008402 	sub	x2, x0, #0x21
    80201864:	f10f7c5f 	cmp	x2, #0x3df
    80201868:	54000068 	b.hi	80201874 <gic_set_trgt+0x14>  // b.pmore
    8020186c:	12001c21 	and	w1, w1, #0xff
}

void gic_set_trgt(unsigned long int_id, uint8_t trgt)
{
    if (irq_in_gicd(int_id)) {
        return gicd_set_trgt(int_id, trgt);
    80201870:	17fffe78 	b	80201250 <gicd_set_trgt>
{
    80201874:	d10043ff 	sub	sp, sp, #0x10
    80201878:	d53800a0 	mrs	x0, mpidr_el1
    asm volatile (
    8020187c:	b0000100 	adrp	x0, 80222000 <init_lock>
    80201880:	91004000 	add	x0, x0, #0x10
    80201884:	52800021 	mov	w1, #0x1                   	// #1
    80201888:	91001003 	add	x3, x0, #0x4
    8020188c:	885ffc62 	ldaxr	w2, [x3]
    80201890:	35ffffe2 	cbnz	w2, 8020188c <gic_set_trgt+0x2c>
    80201894:	88027c61 	stxr	w2, w1, [x3]
    80201898:	35ffffa2 	cbnz	w2, 8020188c <gic_set_trgt+0x2c>
    8020189c:	b9000fe2 	str	w2, [sp, #12]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    802018a0:	889ffc7f 	stlr	wzr, [x3]
    } else {
        return gicr_set_trgt(int_id, trgt, get_cpuid());
    }
}
    802018a4:	910043ff 	add	sp, sp, #0x10
    802018a8:	d65f03c0 	ret
    802018ac:	d503201f 	nop

00000000802018b0 <gic_set_route>:
    if (gic_is_priv(int_id)) return;
    802018b0:	f1007c1f 	cmp	x0, #0x1f
    802018b4:	54000129 	b.ls	802018d8 <gic_set_route+0x28>  // b.plast
    volatile uint32_t *irouter = (uint32_t*) &gicd->IROUTER[int_id];
    802018b8:	90000082 	adrp	x2, 80211000 <blanks.1+0x60>
    802018bc:	91300000 	add	x0, x0, #0xc00
    irouter[1] = (_trgt >> 32);
    802018c0:	d360fc24 	lsr	x4, x1, #32
    volatile uint32_t *irouter = (uint32_t*) &gicd->IROUTER[int_id];
    802018c4:	f9437442 	ldr	x2, [x2, #1768]
    802018c8:	d37df000 	lsl	x0, x0, #3
    802018cc:	8b000043 	add	x3, x2, x0
    irouter[0] = _trgt;
    802018d0:	b8206841 	str	w1, [x2, x0]
    irouter[1] = (_trgt >> 32);
    802018d4:	b9000464 	str	w4, [x3, #4]

void gic_set_route(unsigned long int_id, unsigned long trgt)
{
    return gicd_set_route(int_id, trgt);
}
    802018d8:	d65f03c0 	ret
    802018dc:	d503201f 	nop

00000000802018e0 <gic_set_enable>:
    if (int_id > 32 && int_id < 1025) return true;
    802018e0:	d1008402 	sub	x2, x0, #0x21

void gic_set_enable(unsigned long int_id, bool en)
{
    802018e4:	12001c21 	and	w1, w1, #0xff
    if (int_id > 32 && int_id < 1025) return true;
    802018e8:	f10f7c5f 	cmp	x2, #0x3df
    802018ec:	54000048 	b.hi	802018f4 <gic_set_enable+0x14>  // b.pmore
    if (irq_in_gicd(int_id)) {
        return gicd_set_enable(int_id, en);
    802018f0:	17fffe84 	b	80201300 <gicd_set_enable>
    802018f4:	d53800a2 	mrs	x2, mpidr_el1
    } else {
        return gicr_set_enable(int_id, en, get_cpuid());
    802018f8:	12001c42 	and	w2, w2, #0xff
    802018fc:	17ffff82 	b	80201704 <gicr_set_enable>

0000000080201900 <gicr_set_propbaser>:
}

/*LPI support*/
void gicr_set_propbaser(uint64_t propbaser,uint8_t rdist_id)
{
    gicr[rdist_id].PROPBASER = propbaser;
    80201900:	90000082 	adrp	x2, 80211000 <blanks.1+0x60>
    80201904:	d36f1c21 	ubfiz	x1, x1, #17, #8
    80201908:	f9437842 	ldr	x2, [x2, #1776]
    8020190c:	8b010042 	add	x2, x2, x1
    80201910:	f9003840 	str	x0, [x2, #112]
}
    80201914:	d65f03c0 	ret
    80201918:	d503201f 	nop
    8020191c:	d503201f 	nop

0000000080201920 <gicr_set_pendbaser>:

void gicr_set_pendbaser(uint64_t pendbaser,uint8_t rdist_id)
{
    gicr[rdist_id].PENDBASER = pendbaser;
    80201920:	90000082 	adrp	x2, 80211000 <blanks.1+0x60>
    80201924:	d36f1c21 	ubfiz	x1, x1, #17, #8
    80201928:	f9437842 	ldr	x2, [x2, #1776]
    8020192c:	8b010042 	add	x2, x2, x1
    80201930:	f9003c40 	str	x0, [x2, #120]
}
    80201934:	d65f03c0 	ret
    80201938:	d503201f 	nop
    8020193c:	d503201f 	nop

0000000080201940 <gicr_disable_lpi>:

void gicr_disable_lpi(uint8_t rdist_id)
{
    gicr[rdist_id].CTLR &= ~0x1; 
    80201940:	90000081 	adrp	x1, 80211000 <blanks.1+0x60>
    80201944:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80201948:	f9437822 	ldr	x2, [x1, #1776]
    8020194c:	b8606841 	ldr	w1, [x2, x0]
    80201950:	121f7821 	and	w1, w1, #0xfffffffe
    80201954:	b8206841 	str	w1, [x2, x0]
}
    80201958:	d65f03c0 	ret
    8020195c:	d503201f 	nop

0000000080201960 <gicr_enable_lpi>:

void gicr_enable_lpi(uint8_t rdist_id)
{
    gicr[rdist_id].CTLR |= 0x1;
    80201960:	90000081 	adrp	x1, 80211000 <blanks.1+0x60>
    80201964:	d36f1c00 	ubfiz	x0, x0, #17, #8
    80201968:	f9437822 	ldr	x2, [x1, #1776]
    8020196c:	b8606841 	ldr	w1, [x2, x0]
    80201970:	32000021 	orr	w1, w1, #0x1
    80201974:	b8206841 	str	w1, [x2, x0]
}
    80201978:	d65f03c0 	ret
    8020197c:	00000000 	udf	#0

0000000080201980 <pmu_start_cycle_count>:
/*PMU operation*/
volatile uint64_t prev_timer_val = 0;

// Enable the PMU cycle counter and reset it to zero
void pmu_start_cycle_count() {
    asm volatile(
    80201980:	52800020 	mov	w0, #0x1                   	// #1
    80201984:	52b00001 	mov	w1, #0x80000000            	// #-2147483648
    80201988:	52800002 	mov	w2, #0x0                   	// #0
    8020198c:	d51b9c00 	msr	pmcr_el0, x0
    80201990:	d51b9c21 	msr	pmcntenset_el0, x1
    80201994:	d51b9d02 	msr	pmccntr_el0, x2
        "msr PMCR_EL0, %0\n"  // Enable PMU and reset all counters
        "msr PMCNTENSET_EL0, %1\n"  // Enable the cycle counter
        "msr PMCCNTR_EL0, %2\n"  // Reset cycle counter to 0
        :: "r"(1), "r"(1 << 31), "r"(0)
    );
}
    80201998:	d65f03c0 	ret
    8020199c:	d503201f 	nop

00000000802019a0 <pmu_get_cycle_count>:
// }

// Read the PMU cycle counter
uint64_t pmu_get_cycle_count() {
    uint64_t cycle_count;
    asm volatile("mrs %0, PMCCNTR_EL0" : "=r"(cycle_count));
    802019a0:	d53b9d00 	mrs	x0, pmccntr_el0
    return cycle_count;
}
    802019a4:	d65f03c0 	ret
    802019a8:	d503201f 	nop
    802019ac:	d503201f 	nop

00000000802019b0 <flush_dcache_range>:



void flush_dcache_range(uintptr_t start, size_t length) {
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    uintptr_t end = start + length;
    802019b0:	8b010001 	add	x1, x0, x1
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    802019b4:	927ae400 	and	x0, x0, #0xffffffffffffffc0

    while (addr < end) {
    802019b8:	eb01001f 	cmp	x0, x1
    802019bc:	540000a2 	b.cs	802019d0 <flush_dcache_range+0x20>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    802019c0:	d50b7e20 	dc	civac, x0
        addr += 64;
    802019c4:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    802019c8:	eb00003f 	cmp	x1, x0
    802019cc:	54ffffa8 	b.hi	802019c0 <flush_dcache_range+0x10>  // b.pmore
    }
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    802019d0:	d5033f9f 	dsb	sy
}
    802019d4:	d65f03c0 	ret
    802019d8:	d503201f 	nop
    802019dc:	d503201f 	nop

00000000802019e0 <its_send_mapc>:
/* Command Generation*/

void its_send_mapc(){

    /*Point to the next cmd in the cmd queue*/
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    802019e0:	f0000160 	adrp	x0, 80230000 <its>
    802019e4:	91000001 	add	x1, x0, #0x0

    /*MAP Coll ID 0 to redistributor 0*/

    its_cmd->cmd[0] = 0x09;
    802019e8:	d2800126 	mov	x6, #0x9                   	// #9
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x8000000000000000;
    802019ec:	d2f00005 	mov	x5, #0x8000000000000000    	// #-9223372036854775808
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    802019f0:	f9400002 	ldr	x2, [x0]
    802019f4:	b9402824 	ldr	w4, [x1, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    802019f8:	927ae440 	and	x0, x2, #0xffffffffffffffc0
    uintptr_t end = start + length;
    802019fc:	91404041 	add	x1, x2, #0x10, lsl #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a00:	8b020083 	add	x3, x4, x2
    its_cmd->cmd[0] = 0x09;
    80201a04:	f8226886 	str	x6, [x4, x2]
    its_cmd->cmd[2] = 0x8000000000000000;
    80201a08:	a900947f 	stp	xzr, x5, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201a0c:	f9000c7f 	str	xzr, [x3, #24]
    while (addr < end) {
    80201a10:	eb01001f 	cmp	x0, x1
    80201a14:	540000a2 	b.cs	80201a28 <its_send_mapc+0x48>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201a18:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201a1c:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201a20:	eb00003f 	cmp	x1, x0
    80201a24:	54ffffa8 	b.hi	80201a18 <its_send_mapc+0x38>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201a28:	d5033f9f 	dsb	sy

    flush_dcache_range(its.cmd_queue,0x10000);


}
    80201a2c:	d65f03c0 	ret

0000000080201a30 <its_send_invall>:

void its_send_invall(){

    /*Point to the next cmd in the cmd qeueu*/
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a30:	f0000160 	adrp	x0, 80230000 <its>
    80201a34:	91000001 	add	x1, x0, #0x0

    its_cmd->cmd[0] = 0x0d;
    80201a38:	d28001a5 	mov	x5, #0xd                   	// #13
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a3c:	f9400002 	ldr	x2, [x0]
    80201a40:	b9402824 	ldr	w4, [x1, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201a44:	927ae440 	and	x0, x2, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201a48:	91404041 	add	x1, x2, #0x10, lsl #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a4c:	8b020083 	add	x3, x4, x2
    its_cmd->cmd[0] = 0x0d;
    80201a50:	f8226885 	str	x5, [x4, x2]
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    80201a54:	a900fc7f 	stp	xzr, xzr, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201a58:	f9000c7f 	str	xzr, [x3, #24]
    while (addr < end) {
    80201a5c:	eb01001f 	cmp	x0, x1
    80201a60:	540000c2 	b.cs	80201a78 <its_send_invall+0x48>  // b.hs, b.nlast
    80201a64:	d503201f 	nop
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201a68:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201a6c:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201a70:	eb00003f 	cmp	x1, x0
    80201a74:	54ffffa8 	b.hi	80201a68 <its_send_invall+0x38>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201a78:	d5033f9f 	dsb	sy

    flush_dcache_range(its.cmd_queue,0x10000);

}
    80201a7c:	d65f03c0 	ret

0000000080201a80 <its_send_int>:

void its_send_int(){
    /*Point to the next cmd in the cmd qeueu*/
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a80:	f0000160 	adrp	x0, 80230000 <its>
    80201a84:	91000001 	add	x1, x0, #0x0

    /*Generate lpi associated to the eventID 0 and device ID 0*/

    its_cmd->cmd[0] = 0x03;
    80201a88:	d2800065 	mov	x5, #0x3                   	// #3
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a8c:	f9400002 	ldr	x2, [x0]
    80201a90:	b9402824 	ldr	w4, [x1, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201a94:	927ae440 	and	x0, x2, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201a98:	91404041 	add	x1, x2, #0x10, lsl #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201a9c:	8b020083 	add	x3, x4, x2
    its_cmd->cmd[0] = 0x03;
    80201aa0:	f8226885 	str	x5, [x4, x2]
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    80201aa4:	a900fc7f 	stp	xzr, xzr, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201aa8:	f9000c7f 	str	xzr, [x3, #24]
    while (addr < end) {
    80201aac:	eb01001f 	cmp	x0, x1
    80201ab0:	540000c2 	b.cs	80201ac8 <its_send_int+0x48>  // b.hs, b.nlast
    80201ab4:	d503201f 	nop
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201ab8:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201abc:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201ac0:	eb00003f 	cmp	x1, x0
    80201ac4:	54ffffa8 	b.hi	80201ab8 <its_send_int+0x38>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201ac8:	d5033f9f 	dsb	sy

    flush_dcache_range(its.cmd_queue,0x10000);

}
    80201acc:	d65f03c0 	ret

0000000080201ad0 <its_send_sync>:

void its_send_sync(){

    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201ad0:	f0000160 	adrp	x0, 80230000 <its>
    80201ad4:	91000001 	add	x1, x0, #0x0

    /*Sync redistributor 0*/

    its_cmd->cmd[0] = 0x05;
    80201ad8:	d28000a5 	mov	x5, #0x5                   	// #5
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201adc:	f9400002 	ldr	x2, [x0]
    80201ae0:	b9402824 	ldr	w4, [x1, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201ae4:	927ae440 	and	x0, x2, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201ae8:	91404041 	add	x1, x2, #0x10, lsl #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201aec:	8b020083 	add	x3, x4, x2
    its_cmd->cmd[0] = 0x05;
    80201af0:	f8226885 	str	x5, [x4, x2]
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    80201af4:	a900fc7f 	stp	xzr, xzr, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201af8:	f9000c7f 	str	xzr, [x3, #24]
    while (addr < end) {
    80201afc:	eb01001f 	cmp	x0, x1
    80201b00:	540000c2 	b.cs	80201b18 <its_send_sync+0x48>  // b.hs, b.nlast
    80201b04:	d503201f 	nop
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201b08:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201b0c:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201b10:	eb00003f 	cmp	x1, x0
    80201b14:	54ffffa8 	b.hi	80201b08 <its_send_sync+0x38>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201b18:	d5033f9f 	dsb	sy

    flush_dcache_range(its.cmd_queue,0x10000);

}
    80201b1c:	d65f03c0 	ret

0000000080201b20 <its_send_mapd>:

void its_send_mapd(){

    uint64_t itt_addr = (uint64_t)its.itt_table;
    80201b20:	f0000161 	adrp	x1, 80230000 <its>
    80201b24:	91000020 	add	x0, x1, #0x0
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);

    /*Map device id 0 to ITT address*/

    its_cmd->cmd[0] = 0x08;
    80201b28:	d2800107 	mov	x7, #0x8                   	// #8
    its_cmd->cmd[1] = 0x01;       /*1 bit size*/
    80201b2c:	d2800026 	mov	x6, #0x1                   	// #1
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b30:	f9400022 	ldr	x2, [x1]
    80201b34:	b9402805 	ldr	w5, [x0, #40]
    uint64_t itt_addr = (uint64_t)its.itt_table;
    80201b38:	f9400804 	ldr	x4, [x0, #16]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b3c:	8b0200a3 	add	x3, x5, x2
    uintptr_t end = start + length;
    80201b40:	91404041 	add	x1, x2, #0x10, lsl #12
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201b44:	927ae440 	and	x0, x2, #0xffffffffffffffc0
    its_cmd->cmd[0] = 0x08;
    80201b48:	f82268a7 	str	x7, [x5, x2]
    its_cmd->cmd[2] = (1ULL << 63) | itt_addr;        /*Verify alignment*/
    80201b4c:	b2410082 	orr	x2, x4, #0x8000000000000000
    80201b50:	a9008866 	stp	x6, x2, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201b54:	f9000c7f 	str	xzr, [x3, #24]
    while (addr < end) {
    80201b58:	eb01001f 	cmp	x0, x1
    80201b5c:	540000a2 	b.cs	80201b70 <its_send_mapd+0x50>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201b60:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201b64:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201b68:	eb00003f 	cmp	x1, x0
    80201b6c:	54ffffa8 	b.hi	80201b60 <its_send_mapd+0x40>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201b70:	d5033f9f 	dsb	sy

    flush_dcache_range(its.cmd_queue,0x10000);

}
    80201b74:	d65f03c0 	ret
    80201b78:	d503201f 	nop
    80201b7c:	d503201f 	nop

0000000080201b80 <its_send_mapti>:

void its_send_mapti(){

    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b80:	f0000160 	adrp	x0, 80230000 <its>
    80201b84:	91000001 	add	x1, x0, #0x0

    its_cmd->cmd[0] = 0x0a;
    80201b88:	d2800146 	mov	x6, #0xa                   	// #10
    its_cmd->cmd[1] = 0x200000000000;       /*8192 pINTID*/
    80201b8c:	d2c40005 	mov	x5, #0x200000000000        	// #35184372088832
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201b90:	f9400002 	ldr	x2, [x0]
    80201b94:	b9402824 	ldr	w4, [x1, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201b98:	927ae440 	and	x0, x2, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201b9c:	91404041 	add	x1, x2, #0x10, lsl #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201ba0:	8b020083 	add	x3, x4, x2
    its_cmd->cmd[0] = 0x0a;
    80201ba4:	f8226886 	str	x6, [x4, x2]
    its_cmd->cmd[2] = 0x00;                 /*Coll ID 0*/
    80201ba8:	a900fc65 	stp	x5, xzr, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201bac:	f9000c7f 	str	xzr, [x3, #24]
    while (addr < end) {
    80201bb0:	eb01001f 	cmp	x0, x1
    80201bb4:	540000a2 	b.cs	80201bc8 <its_send_mapti+0x48>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201bb8:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201bbc:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201bc0:	eb00003f 	cmp	x1, x0
    80201bc4:	54ffffa8 	b.hi	80201bb8 <its_send_mapti+0x38>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201bc8:	d5033f9f 	dsb	sy

    flush_dcache_range(its.cmd_queue,0x10000);
}
    80201bcc:	d65f03c0 	ret

0000000080201bd0 <its_send_inv>:

void its_send_inv(){
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201bd0:	f0000160 	adrp	x0, 80230000 <its>
    80201bd4:	91000001 	add	x1, x0, #0x0

    /*Cache consistent with LPI tables held in memory*/

    its_cmd->cmd[0] = 0x0c;
    80201bd8:	d2800185 	mov	x5, #0xc                   	// #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201bdc:	f9400002 	ldr	x2, [x0]
    80201be0:	b9402824 	ldr	w4, [x1, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201be4:	927ae440 	and	x0, x2, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201be8:	91404041 	add	x1, x2, #0x10, lsl #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201bec:	8b020083 	add	x3, x4, x2
    its_cmd->cmd[0] = 0x0c;
    80201bf0:	f8226885 	str	x5, [x4, x2]
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    80201bf4:	a900fc7f 	stp	xzr, xzr, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201bf8:	f9000c7f 	str	xzr, [x3, #24]
    while (addr < end) {
    80201bfc:	eb01001f 	cmp	x0, x1
    80201c00:	540000c2 	b.cs	80201c18 <its_send_inv+0x48>  // b.hs, b.nlast
    80201c04:	d503201f 	nop
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201c08:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201c0c:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201c10:	eb00003f 	cmp	x1, x0
    80201c14:	54ffffa8 	b.hi	80201c08 <its_send_inv+0x38>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201c18:	d5033f9f 	dsb	sy

    flush_dcache_range(its.cmd_queue,0x10000);
}
    80201c1c:	d65f03c0 	ret

0000000080201c20 <its_cpu_init_collections>:
void its_cpu_init_collections(){

    /*Bind the Collection ID with the target redistributor*/
    /*For this configuration, collection ID 0 is hardwired to redistributor 0*/

    cmd_off = gits->CWRITER;
    80201c20:	90000086 	adrp	x6, 80211000 <blanks.1+0x60>
    80201c24:	f0000164 	adrp	x4, 80230000 <its>
    80201c28:	91000082 	add	x2, x4, #0x0
    its_cmd->cmd[0] = 0x09;
    80201c2c:	d2800129 	mov	x9, #0x9                   	// #9
    cmd_off = gits->CWRITER;
    80201c30:	f9437cc0 	ldr	x0, [x6, #1784]
    its_cmd->cmd[2] = 0x8000000000000000;
    80201c34:	d2f00008 	mov	x8, #0x8000000000000000    	// #-9223372036854775808
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201c38:	f9400083 	ldr	x3, [x4]
    cmd_off = gits->CWRITER;
    80201c3c:	f9404407 	ldr	x7, [x0, #136]
    uintptr_t end = start + length;
    80201c40:	91404061 	add	x1, x3, #0x10, lsl #12
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201c44:	927ae460 	and	x0, x3, #0xffffffffffffffc0
    cmd_off = gits->CWRITER;
    80201c48:	b9002847 	str	w7, [x2, #40]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201c4c:	8b274065 	add	x5, x3, w7, uxtw
    its_cmd->cmd[0] = 0x09;
    80201c50:	f8274869 	str	x9, [x3, w7, uxtw]
    its_cmd->cmd[2] = 0x8000000000000000;
    80201c54:	a900a0bf 	stp	xzr, x8, [x5, #8]
    its_cmd->cmd[3] = 0x00;
    80201c58:	f9000cbf 	str	xzr, [x5, #24]
    while (addr < end) {
    80201c5c:	eb01001f 	cmp	x0, x1
    80201c60:	540000c2 	b.cs	80201c78 <its_cpu_init_collections+0x58>  // b.hs, b.nlast
    80201c64:	d503201f 	nop
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201c68:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201c6c:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201c70:	eb00003f 	cmp	x1, x0
    80201c74:	54ffffa8 	b.hi	80201c68 <its_cpu_init_collections+0x48>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201c78:	d5033f9f 	dsb	sy
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201c7c:	f9400085 	ldr	x5, [x4]
    its_cmd->cmd[0] = 0x05;
    80201c80:	d28000a8 	mov	x8, #0x5                   	// #5
    its_send_mapc();
    cmd_off += 0x20;
    80201c84:	b9402843 	ldr	w3, [x2, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201c88:	927ae4a0 	and	x0, x5, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201c8c:	914040a1 	add	x1, x5, #0x10, lsl #12
    cmd_off += 0x20;
    80201c90:	11008063 	add	w3, w3, #0x20
    80201c94:	b9002843 	str	w3, [x2, #40]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201c98:	8b2340a7 	add	x7, x5, w3, uxtw
    its_cmd->cmd[0] = 0x05;
    80201c9c:	f82348a8 	str	x8, [x5, w3, uxtw]
    its_cmd->cmd[2] = 0x00;
    80201ca0:	a900fcff 	stp	xzr, xzr, [x7, #8]
    its_cmd->cmd[3] = 0x00;
    80201ca4:	f9000cff 	str	xzr, [x7, #24]
    while (addr < end) {
    80201ca8:	eb01001f 	cmp	x0, x1
    80201cac:	540000a2 	b.cs	80201cc0 <its_cpu_init_collections+0xa0>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201cb0:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201cb4:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201cb8:	eb00003f 	cmp	x1, x0
    80201cbc:	54ffffa8 	b.hi	80201cb0 <its_cpu_init_collections+0x90>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201cc0:	d5033f9f 	dsb	sy

    //flush


    /*Increment CWRITTER*/
    gits->CWRITER = cmd_off;
    80201cc4:	f9437cc0 	ldr	x0, [x6, #1784]
    its_cmd->cmd[0] = 0x0d;
    80201cc8:	d28001a7 	mov	x7, #0xd                   	// #13
    cmd_off += 0x20;
    80201ccc:	b9402845 	ldr	w5, [x2, #40]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201cd0:	f9400081 	ldr	x1, [x4]
    cmd_off += 0x20;
    80201cd4:	110080a3 	add	w3, w5, #0x20
    80201cd8:	aa0303e5 	mov	x5, x3
    gits->CWRITER = cmd_off;
    80201cdc:	f9004403 	str	x3, [x0, #136]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201ce0:	8b010063 	add	x3, x3, x1
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201ce4:	927ae420 	and	x0, x1, #0xffffffffffffffc0
    cmd_off += 0x20;
    80201ce8:	b9002845 	str	w5, [x2, #40]
    its_cmd->cmd[0] = 0x0d;
    80201cec:	f8254827 	str	x7, [x1, w5, uxtw]
    uintptr_t end = start + length;
    80201cf0:	91404021 	add	x1, x1, #0x10, lsl #12
    its_cmd->cmd[2] = 0x00;
    80201cf4:	a900fc7f 	stp	xzr, xzr, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201cf8:	f9000c7f 	str	xzr, [x3, #24]
    while (addr < end) {
    80201cfc:	eb01001f 	cmp	x0, x1
    80201d00:	540000c2 	b.cs	80201d18 <its_cpu_init_collections+0xf8>  // b.hs, b.nlast
    80201d04:	d503201f 	nop
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201d08:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201d0c:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201d10:	eb00003f 	cmp	x1, x0
    80201d14:	54ffffa8 	b.hi	80201d08 <its_cpu_init_collections+0xe8>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201d18:	d5033f9f 	dsb	sy
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201d1c:	f9400084 	ldr	x4, [x4]
    its_cmd->cmd[0] = 0x05;
    80201d20:	d28000a7 	mov	x7, #0x5                   	// #5

    its_send_invall();
    cmd_off += 0x20;
    80201d24:	b9402843 	ldr	w3, [x2, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201d28:	927ae480 	and	x0, x4, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201d2c:	91404081 	add	x1, x4, #0x10, lsl #12
    cmd_off += 0x20;
    80201d30:	11008063 	add	w3, w3, #0x20
    80201d34:	b9002843 	str	w3, [x2, #40]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201d38:	8b234085 	add	x5, x4, w3, uxtw
    its_cmd->cmd[0] = 0x05;
    80201d3c:	f8234887 	str	x7, [x4, w3, uxtw]
    its_cmd->cmd[2] = 0x00;
    80201d40:	a900fcbf 	stp	xzr, xzr, [x5, #8]
    its_cmd->cmd[3] = 0x00;
    80201d44:	f9000cbf 	str	xzr, [x5, #24]
    while (addr < end) {
    80201d48:	eb01001f 	cmp	x0, x1
    80201d4c:	540000a2 	b.cs	80201d60 <its_cpu_init_collections+0x140>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201d50:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201d54:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201d58:	eb00003f 	cmp	x1, x0
    80201d5c:	54ffffa8 	b.hi	80201d50 <its_cpu_init_collections+0x130>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201d60:	d5033f9f 	dsb	sy
    its_send_sync();
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;
    80201d64:	f9437cc1 	ldr	x1, [x6, #1784]
    cmd_off += 0x20;
    80201d68:	b9402840 	ldr	w0, [x2, #40]
    80201d6c:	11008000 	add	w0, w0, #0x20
    80201d70:	b9002840 	str	w0, [x2, #40]
    gits->CWRITER = cmd_off;
    80201d74:	f9004420 	str	x0, [x1, #136]

}
    80201d78:	d65f03c0 	ret
    80201d7c:	d503201f 	nop

0000000080201d80 <its_cpu_init>:


int its_cpu_init(void)
{
    80201d80:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80201d84:	910003fd 	mov	x29, sp
    int ret;

    /*UPDATE Collection table*/
	its_cpu_init_collections();
    80201d88:	97ffffa6 	bl	80201c20 <its_cpu_init_collections>

	return 0;
}
    80201d8c:	52800000 	mov	w0, #0x0                   	// #0
    80201d90:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80201d94:	d65f03c0 	ret
    80201d98:	d503201f 	nop
    80201d9c:	d503201f 	nop

0000000080201da0 <its_device_init>:

/*
    Device specific initialization
*/

int its_device_init(){
    80201da0:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!

    /*Map the itt_addr to the device_ID in device table*/
    cmd_off = gits->CWRITER;
    80201da4:	9000008a 	adrp	x10, 80211000 <blanks.1+0x60>
    80201da8:	f0000169 	adrp	x9, 80230000 <its>
int its_device_init(){
    80201dac:	910003fd 	mov	x29, sp
    cmd_off = gits->CWRITER;
    80201db0:	f9437d40 	ldr	x0, [x10, #1784]
    80201db4:	91000128 	add	x8, x9, #0x0
    80201db8:	f9404400 	ldr	x0, [x0, #136]
    80201dbc:	b9002900 	str	w0, [x8, #40]
    its_send_mapd();
    80201dc0:	97ffff58 	bl	80201b20 <its_send_mapd>
    //its_send_sync(); // ???
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;
    80201dc4:	f9437d40 	ldr	x0, [x10, #1784]
    its_cmd->cmd[1] = 0x200000000000;       /*8192 pINTID*/
    80201dc8:	d2c40004 	mov	x4, #0x200000000000        	// #35184372088832
    cmd_off += 0x20;
    80201dcc:	b9402903 	ldr	w3, [x8, #40]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201dd0:	f9400121 	ldr	x1, [x9]
    cmd_off += 0x20;
    80201dd4:	11008062 	add	w2, w3, #0x20
    80201dd8:	aa0203e3 	mov	x3, x2
    gits->CWRITER = cmd_off;
    80201ddc:	f9004402 	str	x2, [x0, #136]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201de0:	8b010042 	add	x2, x2, x1
    its_cmd->cmd[0] = 0x0a;
    80201de4:	d2800140 	mov	x0, #0xa                   	// #10
    cmd_off += 0x20;
    80201de8:	b9002903 	str	w3, [x8, #40]
    its_cmd->cmd[0] = 0x0a;
    80201dec:	f8234820 	str	x0, [x1, w3, uxtw]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201df0:	927ae420 	and	x0, x1, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201df4:	91404021 	add	x1, x1, #0x10, lsl #12
    its_cmd->cmd[2] = 0x00;                 /*Coll ID 0*/
    80201df8:	a900fc44 	stp	x4, xzr, [x2, #8]
    its_cmd->cmd[3] = 0x00;
    80201dfc:	f9000c5f 	str	xzr, [x2, #24]
    while (addr < end) {
    80201e00:	eb01001f 	cmp	x0, x1
    80201e04:	540000a2 	b.cs	80201e18 <its_device_init+0x78>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201e08:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201e0c:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201e10:	eb00003f 	cmp	x1, x0
    80201e14:	54ffffa8 	b.hi	80201e08 <its_device_init+0x68>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201e18:	d5033f9f 	dsb	sy
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201e1c:	f9400123 	ldr	x3, [x9]
    its_cmd->cmd[0] = 0x05;
    80201e20:	d28000a5 	mov	x5, #0x5                   	// #5

    /*Map the eventID and deviceID to collection ID int the itt table*/
    its_send_mapti();
    cmd_off += 0x20;
    80201e24:	b9402902 	ldr	w2, [x8, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201e28:	927ae460 	and	x0, x3, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201e2c:	91404061 	add	x1, x3, #0x10, lsl #12
    cmd_off += 0x20;
    80201e30:	11008042 	add	w2, w2, #0x20
    80201e34:	b9002902 	str	w2, [x8, #40]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201e38:	8b224064 	add	x4, x3, w2, uxtw
    its_cmd->cmd[0] = 0x05;
    80201e3c:	f8224865 	str	x5, [x3, w2, uxtw]
    its_cmd->cmd[2] = 0x00;
    80201e40:	a900fc9f 	stp	xzr, xzr, [x4, #8]
    its_cmd->cmd[3] = 0x00;
    80201e44:	f9000c9f 	str	xzr, [x4, #24]
    while (addr < end) {
    80201e48:	eb01001f 	cmp	x0, x1
    80201e4c:	540000a2 	b.cs	80201e60 <its_device_init+0xc0>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201e50:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201e54:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201e58:	eb00003f 	cmp	x1, x0
    80201e5c:	54ffffa8 	b.hi	80201e50 <its_device_init+0xb0>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201e60:	d5033f9f 	dsb	sy
    its_send_sync();
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;
    80201e64:	f9437d43 	ldr	x3, [x10, #1784]
    its.prop_table[pINTID - 8192] = val;
    80201e68:	12800bc2 	mov	w2, #0xffffffa1            	// #-95
    80201e6c:	f9400d01 	ldr	x1, [x8, #24]
    cmd_off += 0x20;
    80201e70:	b9402900 	ldr	w0, [x8, #40]
    80201e74:	11008000 	add	w0, w0, #0x20
    80201e78:	b9002900 	str	w0, [x8, #40]
    gits->CWRITER = cmd_off;
    80201e7c:	f9004460 	str	x0, [x3, #136]
    its.prop_table[pINTID - 8192] = val;
    80201e80:	39000022 	strb	w2, [x1]


    /*Sync LPI config tables in the redistributor*/
    its_enable_lpi(8192);

    flush_dcache_range((uint64_t)its.prop_table,0x10000);
    80201e84:	f9400d01 	ldr	x1, [x8, #24]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201e88:	927ae420 	and	x0, x1, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201e8c:	91404021 	add	x1, x1, #0x10, lsl #12
    while (addr < end) {
    80201e90:	eb01001f 	cmp	x0, x1
    80201e94:	540000a2 	b.cs	80201ea8 <its_device_init+0x108>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201e98:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201e9c:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201ea0:	eb00003f 	cmp	x1, x0
    80201ea4:	54ffffa8 	b.hi	80201e98 <its_device_init+0xf8>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201ea8:	d5033f9f 	dsb	sy
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201eac:	f9400122 	ldr	x2, [x9]
    its_cmd->cmd[0] = 0x0c;
    80201eb0:	d2800185 	mov	x5, #0xc                   	// #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201eb4:	b9402904 	ldr	w4, [x8, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201eb8:	927ae440 	and	x0, x2, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201ebc:	91404041 	add	x1, x2, #0x10, lsl #12
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201ec0:	8b020083 	add	x3, x4, x2
    its_cmd->cmd[0] = 0x0c;
    80201ec4:	f8226885 	str	x5, [x4, x2]
    its_cmd->cmd[2] = 0x00;
    80201ec8:	a900fc7f 	stp	xzr, xzr, [x3, #8]
    its_cmd->cmd[3] = 0x00;
    80201ecc:	f9000c7f 	str	xzr, [x3, #24]
    while (addr < end) {
    80201ed0:	eb01001f 	cmp	x0, x1
    80201ed4:	540000a2 	b.cs	80201ee8 <its_device_init+0x148>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201ed8:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201edc:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201ee0:	eb00003f 	cmp	x1, x0
    80201ee4:	54ffffa8 	b.hi	80201ed8 <its_device_init+0x138>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201ee8:	d5033f9f 	dsb	sy
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201eec:	f9400123 	ldr	x3, [x9]
    its_cmd->cmd[0] = 0x05;
    80201ef0:	d28000a5 	mov	x5, #0x5                   	// #5

    its_send_inv();
    cmd_off += 0x20;
    80201ef4:	b9402902 	ldr	w2, [x8, #40]
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201ef8:	927ae460 	and	x0, x3, #0xffffffffffffffc0
    uintptr_t end = start + length;
    80201efc:	91404061 	add	x1, x3, #0x10, lsl #12
    cmd_off += 0x20;
    80201f00:	11008042 	add	w2, w2, #0x20
    80201f04:	b9002902 	str	w2, [x8, #40]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201f08:	8b224064 	add	x4, x3, w2, uxtw
    its_cmd->cmd[0] = 0x05;
    80201f0c:	f8224865 	str	x5, [x3, w2, uxtw]
    its_cmd->cmd[2] = 0x00;
    80201f10:	a900fc9f 	stp	xzr, xzr, [x4, #8]
    its_cmd->cmd[3] = 0x00;
    80201f14:	f9000c9f 	str	xzr, [x4, #24]
    while (addr < end) {
    80201f18:	eb01001f 	cmp	x0, x1
    80201f1c:	540000a2 	b.cs	80201f30 <its_device_init+0x190>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201f20:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201f24:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201f28:	eb00003f 	cmp	x1, x0
    80201f2c:	54ffffa8 	b.hi	80201f20 <its_device_init+0x180>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201f30:	d5033f9f 	dsb	sy
    its_send_sync();    //all the ITS operations globally observed
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;
    80201f34:	f9437d42 	ldr	x2, [x10, #1784]

    return 0;
}
    80201f38:	52800000 	mov	w0, #0x0                   	// #0
    cmd_off += 0x20;
    80201f3c:	b9402901 	ldr	w1, [x8, #40]
    80201f40:	11008021 	add	w1, w1, #0x20
    gits->CWRITER = cmd_off;
    80201f44:	f9004441 	str	x1, [x2, #136]
    cmd_off += 0x20;
    80201f48:	b9002901 	str	w1, [x8, #40]
}
    80201f4c:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80201f50:	d65f03c0 	ret

0000000080201f54 <its_trigger_lpi>:

void its_trigger_lpi(){

    cmd_off = gits->CWRITER;
    80201f54:	90000086 	adrp	x6, 80211000 <blanks.1+0x60>
    80201f58:	f0000167 	adrp	x7, 80230000 <its>
    80201f5c:	910000e3 	add	x3, x7, #0x0
    its_cmd->cmd[0] = 0x03;
    80201f60:	d2800068 	mov	x8, #0x3                   	// #3
    cmd_off = gits->CWRITER;
    80201f64:	f9437cc0 	ldr	x0, [x6, #1784]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201f68:	f94000e2 	ldr	x2, [x7]
    cmd_off = gits->CWRITER;
    80201f6c:	f9404405 	ldr	x5, [x0, #136]
    uintptr_t end = start + length;
    80201f70:	91404041 	add	x1, x2, #0x10, lsl #12
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201f74:	927ae440 	and	x0, x2, #0xffffffffffffffc0
    cmd_off = gits->CWRITER;
    80201f78:	b9002865 	str	w5, [x3, #40]
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201f7c:	8b254044 	add	x4, x2, w5, uxtw
    its_cmd->cmd[0] = 0x03;
    80201f80:	f8254848 	str	x8, [x2, w5, uxtw]
    its_cmd->cmd[2] = 0x00;
    80201f84:	a900fc9f 	stp	xzr, xzr, [x4, #8]
    its_cmd->cmd[3] = 0x00;
    80201f88:	f9000c9f 	str	xzr, [x4, #24]
    while (addr < end) {
    80201f8c:	eb01001f 	cmp	x0, x1
    80201f90:	540000c2 	b.cs	80201fa8 <its_trigger_lpi+0x54>  // b.hs, b.nlast
    80201f94:	d503201f 	nop
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80201f98:	d50b7e20 	dc	civac, x0
        addr += 64;
    80201f9c:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80201fa0:	eb00003f 	cmp	x1, x0
    80201fa4:	54ffffa8 	b.hi	80201f98 <its_trigger_lpi+0x44>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80201fa8:	d5033f9f 	dsb	sy
    its_send_int();
    cmd_off += 0x20;
    80201fac:	b9402865 	ldr	w5, [x3, #40]
    gits->CWRITER = cmd_off;
    80201fb0:	f9437cc0 	ldr	x0, [x6, #1784]
    cmd_off += 0x20;
    80201fb4:	110080a4 	add	w4, w5, #0x20
    80201fb8:	aa0403e5 	mov	x5, x4
    80201fbc:	b9002864 	str	w4, [x3, #40]
    gits->CWRITER = cmd_off;
    80201fc0:	f9004404 	str	x4, [x0, #136]
    80201fc4:	d503201f 	nop
    // struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off - 0x20);

    // its_test = *its_cmd;


    while(gits->CREADR != gits->CWRITER);
    80201fc8:	f9404802 	ldr	x2, [x0, #144]
    80201fcc:	f9404401 	ldr	x1, [x0, #136]
    80201fd0:	eb01005f 	cmp	x2, x1
    80201fd4:	54ffffa1 	b.ne	80201fc8 <its_trigger_lpi+0x74>  // b.any
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201fd8:	f94000e1 	ldr	x1, [x7]
    its_cmd->cmd[0] = 0x05;
    80201fdc:	d28000a7 	mov	x7, #0x5                   	// #5
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);
    80201fe0:	8b010082 	add	x2, x4, x1
    uintptr_t addr = start & ~(64 - 1);  // Align start to cache line boundary
    80201fe4:	927ae420 	and	x0, x1, #0xffffffffffffffc0
    its_cmd->cmd[0] = 0x05;
    80201fe8:	f8254827 	str	x7, [x1, w5, uxtw]
    uintptr_t end = start + length;
    80201fec:	91404021 	add	x1, x1, #0x10, lsl #12
    its_cmd->cmd[2] = 0x00;
    80201ff0:	a900fc5f 	stp	xzr, xzr, [x2, #8]
    its_cmd->cmd[3] = 0x00;
    80201ff4:	f9000c5f 	str	xzr, [x2, #24]
    while (addr < end) {
    80201ff8:	eb01001f 	cmp	x0, x1
    80201ffc:	540000a2 	b.cs	80202010 <its_trigger_lpi+0xbc>  // b.hs, b.nlast
        __asm__ volatile ("dc civac, %0" : : "r" (addr) : "memory");  // Clean and invalidate
    80202000:	d50b7e20 	dc	civac, x0
        addr += 64;
    80202004:	91010000 	add	x0, x0, #0x40
    while (addr < end) {
    80202008:	eb00003f 	cmp	x1, x0
    8020200c:	54ffffa8 	b.hi	80202000 <its_trigger_lpi+0xac>  // b.pmore
    __asm__ volatile ("dsb sy");  // Ensure completion of the cache flush
    80202010:	d5033f9f 	dsb	sy

    its_send_sync();
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;
    80202014:	f9437cc5 	ldr	x5, [x6, #1784]
    asm volatile(
    80202018:	52800021 	mov	w1, #0x1                   	// #1
    cmd_off += 0x20;
    8020201c:	b9402860 	ldr	w0, [x3, #40]
    asm volatile(
    80202020:	52b00002 	mov	w2, #0x80000000            	// #-2147483648
    80202024:	52800004 	mov	w4, #0x0                   	// #0
    cmd_off += 0x20;
    80202028:	11008000 	add	w0, w0, #0x20
    8020202c:	b9002860 	str	w0, [x3, #40]
    gits->CWRITER = cmd_off;
    80202030:	f90044a0 	str	x0, [x5, #136]
    asm volatile(
    80202034:	d51b9c01 	msr	pmcr_el0, x1
    80202038:	d51b9c22 	msr	pmcntenset_el0, x2
    8020203c:	d51b9d04 	msr	pmccntr_el0, x4
    asm volatile("mrs %0, PMCCNTR_EL0" : "=r"(cycle_count));
    80202040:	d53b9d00 	mrs	x0, pmccntr_el0

    /*Previous start point of PMU*/

    /*Get the initial value of the PMU*/
    pmu_start_cycle_count();
    prev_timer_val = pmu_get_cycle_count(); //Used to calculate the number of cycles registered after the interrupt being triggered
    80202044:	f9001860 	str	x0, [x3, #48]

}
    80202048:	d65f03c0 	ret
    8020204c:	d503201f 	nop

0000000080202050 <its_init>:

int its_init(void){
    80202050:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!

    int err;

    /*store table addrs in its data structure*/
    its.cmd_queue = (uint64_t)cmd_queue;
    80202054:	d0000360 	adrp	x0, 80270000 <cmd_queue>
    80202058:	91000000 	add	x0, x0, #0x0
int its_init(void){
    8020205c:	910003fd 	mov	x29, sp
    80202060:	a90153f3 	stp	x19, x20, [sp, #16]
    gits->CTLR &= 0xfffe;
    80202064:	f0000074 	adrp	x20, 80211000 <blanks.1+0x60>
    its.device_table = device_table;
    80202068:	d00002e4 	adrp	x4, 80260000 <device_table>
    gits->CTLR &= 0xfffe;
    8020206c:	f9437e85 	ldr	x5, [x20, #1784]
    its.device_table = device_table;
    80202070:	91000084 	add	x4, x4, #0x0
    its.itt_table = itt_table;
    its.prop_table = prop_table;
    80202074:	d0000203 	adrp	x3, 80244000 <prop_table>
    its.pend_table = pend_table;
    80202078:	d00001e2 	adrp	x2, 80240000 <pend_table>
    its.prop_table = prop_table;
    8020207c:	91000063 	add	x3, x3, #0x0
    its.pend_table = pend_table;
    80202080:	91000042 	add	x2, x2, #0x0
    gits->CTLR &= 0xfffe;
    80202084:	b94000a1 	ldr	w1, [x5]
int its_init(void){
    80202088:	f90013f5 	str	x21, [sp, #32]
    its.cmd_queue = (uint64_t)cmd_queue;
    8020208c:	d0000175 	adrp	x21, 80230000 <its>
    80202090:	910002b3 	add	x19, x21, #0x0
    gits->CTLR &= 0xfffe;
    80202094:	121f3821 	and	w1, w1, #0xfffe
    its.cmd_queue = (uint64_t)cmd_queue;
    80202098:	f90002a0 	str	x0, [x21]
    its.itt_table = itt_table;
    8020209c:	d0000260 	adrp	x0, 80250000 <itt_table>
    802020a0:	91000000 	add	x0, x0, #0x0
    802020a4:	a9008264 	stp	x4, x0, [x19, #8]
    gicr_disable_lpi(0);
    802020a8:	52800000 	mov	w0, #0x0                   	// #0
    its.pend_table = pend_table;
    802020ac:	a9018a63 	stp	x3, x2, [x19, #24]
    gits->CTLR &= 0xfffe;
    802020b0:	b90000a1 	str	w1, [x5]
    gicr_disable_lpi(0);
    802020b4:	97fffe23 	bl	80201940 <gicr_disable_lpi>
    gits->CBASER = (uint64_t)its.cmd_queue | GITS_BASER_InnerShareable | GITS_BASER_NonCache | 0xf;
    802020b8:	f9437e83 	ldr	x3, [x20, #1784]
    802020bc:	d28081e1 	mov	x1, #0x40f                 	// #1039
    802020c0:	f94002a0 	ldr	x0, [x21]
    802020c4:	f2e10001 	movk	x1, #0x800, lsl #48
            gits->BASER[index] = (uint64_t)its.itt_table | GITS_BASER_InnerShareable | GITS_BASER_NonCache | 0xe;
    802020c8:	f9400a65 	ldr	x5, [x19, #16]
    gits->CBASER = (uint64_t)its.cmd_queue | GITS_BASER_InnerShareable | GITS_BASER_NonCache | 0xf;
    802020cc:	aa010000 	orr	x0, x0, x1
    802020d0:	f9004060 	str	x0, [x3, #128]
            gits->BASER[index] = (uint64_t)its.itt_table | GITS_BASER_InnerShareable | GITS_BASER_NonCache | 0xe;
    802020d4:	d1000422 	sub	x2, x1, #0x1
    802020d8:	aa0200a5 	orr	x5, x5, x2
        if(bit_extract(gits->BASER[index], GITS_BASER_TYPE_OFF, GITS_BASER_TYPE_LEN) == 0x1) //Equal device table type
    802020dc:	d2e02004 	mov	x4, #0x100000000000000     	// #72057594037927936
    gits->CBASER |= 1ULL << 63; //add valid
    802020e0:	f9404061 	ldr	x1, [x3, #128]
    for (size_t index = 0; index < 8; index++) {
    802020e4:	d2800000 	mov	x0, #0x0                   	// #0
    gits->CBASER |= 1ULL << 63; //add valid
    802020e8:	b2410021 	orr	x1, x1, #0x8000000000000000
    802020ec:	f9004061 	str	x1, [x3, #128]
    for (size_t index = 0; index < 8; index++) {
    802020f0:	8b000c62 	add	x2, x3, x0, lsl #3
    802020f4:	91000400 	add	x0, x0, #0x1
        if(bit_extract(gits->BASER[index], GITS_BASER_TYPE_OFF, GITS_BASER_TYPE_LEN) == 0x1) //Equal device table type
    802020f8:	f9408041 	ldr	x1, [x2, #256]
    802020fc:	92480821 	and	x1, x1, #0x700000000000000
    80202100:	eb04003f 	cmp	x1, x4
    80202104:	540000a1 	b.ne	80202118 <its_init+0xc8>  // b.any
            gits->BASER[index] = (uint64_t)its.itt_table | GITS_BASER_InnerShareable | GITS_BASER_NonCache | 0xe;
    80202108:	f9008045 	str	x5, [x2, #256]
            gits->BASER[index] |= (1ULL << 63);  //set valid bit
    8020210c:	f9408041 	ldr	x1, [x2, #256]
    80202110:	b2410021 	orr	x1, x1, #0x8000000000000000
    80202114:	f9008041 	str	x1, [x2, #256]
    for (size_t index = 0; index < 8; index++) {
    80202118:	f100201f 	cmp	x0, #0x8
    8020211c:	54fffea1 	b.ne	802020f0 <its_init+0xa0>  // b.any
    propbaser = (uint64_t)its.prop_table | GICR_PROPBASER_InnerShareable | GICR_PROPBASER_NonCache | lpi_id_bits;
    80202120:	f9400e62 	ldr	x2, [x19, #24]
    gicr_set_propbaser(propbaser,0);
    80202124:	52800001 	mov	w1, #0x0                   	// #0
    propbaser = (uint64_t)its.prop_table | GICR_PROPBASER_InnerShareable | GICR_PROPBASER_NonCache | lpi_id_bits;
    80202128:	d28091e0 	mov	x0, #0x48f                 	// #1167
    gicr_set_propbaser(propbaser,0);
    8020212c:	aa000040 	orr	x0, x2, x0
    80202130:	97fffdf4 	bl	80201900 <gicr_set_propbaser>
    uint64_t pendbaser = (uint64_t)its.pend_table | GICR_PROPBASER_InnerShareable | GICR_PROPBASER_NonCache;
    80202134:	f9401262 	ldr	x2, [x19, #32]
    gicr_set_pendbaser(pendbaser,0);
    80202138:	52800001 	mov	w1, #0x0                   	// #0
    uint64_t pendbaser = (uint64_t)its.pend_table | GICR_PROPBASER_InnerShareable | GICR_PROPBASER_NonCache;
    8020213c:	d2809000 	mov	x0, #0x480                 	// #1152
    gicr_set_pendbaser(pendbaser,0);
    80202140:	aa000040 	orr	x0, x2, x0
    80202144:	97fffdf7 	bl	80201920 <gicr_set_pendbaser>
    gicr_enable_lpi(0);
    80202148:	52800000 	mov	w0, #0x0                   	// #0
    8020214c:	97fffe05 	bl	80201960 <gicr_enable_lpi>
    gits->CTLR |= 0x1;
    80202150:	f9437e82 	ldr	x2, [x20, #1784]
    *ptr |= 0x2;
    80202154:	d2980001 	mov	x1, #0xc000                	// #49152
    80202158:	f2aa3441 	movk	x1, #0x51a2, lsl #16
    gits->CTLR |= 0x1;
    8020215c:	b9400040 	ldr	w0, [x2]
    80202160:	32000000 	orr	w0, w0, #0x1
    80202164:	b9000040 	str	w0, [x2]
    *ptr |= 0x2;
    80202168:	b9400020 	ldr	w0, [x1]
    8020216c:	321f0000 	orr	w0, w0, #0x2
    80202170:	b9000020 	str	w0, [x1]
	its_cpu_init_collections();
    80202174:	97fffeab 	bl	80201c20 <its_cpu_init_collections>
    err = its_cpu_init();
    if(err)
        return err;


    err = its_device_init();
    80202178:	97ffff0a 	bl	80201da0 <its_device_init>
    // printf("Value of trkvidr is 0x%x",*ptr);

    // printf("ITS initialization finished\n");
    // printf("ITS initialization finished\n");
    // printf("ITS initialization finished\n");
}
    8020217c:	a94153f3 	ldp	x19, x20, [sp, #16]
    80202180:	f94013f5 	ldr	x21, [sp, #32]
    80202184:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80202188:	d65f03c0 	ret
    8020218c:	d503201f 	nop

0000000080202190 <get_creadr>:

uint64_t get_creadr(){
    return gits->CREADR;
    80202190:	f0000060 	adrp	x0, 80211000 <blanks.1+0x60>
    80202194:	f9437c00 	ldr	x0, [x0, #1784]
    80202198:	f9404800 	ldr	x0, [x0, #144]
}
    8020219c:	d65f03c0 	ret

00000000802021a0 <get_cqueue>:

uint64_t get_cqueue(){
    //return ((its_test.cmd[3] << 24) | (its_test.cmd[2] << 16) | (its_test.cmd[1] << 8) | its_test.cmd[0]);
    return 0;
    802021a0:	d2800000 	mov	x0, #0x0                   	// #0
    802021a4:	d65f03c0 	ret
	...

00000000802021b0 <lpi_handler>:
    // }
}



void lpi_handler(unsigned id){
    802021b0:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    802021b4:	910003fd 	mov	x29, sp
    uint64_t curr_timer_val = pmu_get_cycle_count();
    802021b8:	97fffdfa 	bl	802019a0 <pmu_get_cycle_count>
    //printf("LPI %d received: timer val %d\n",id,curr_timer_val-prev_timer_val);
    test[index_test++] = curr_timer_val-prev_timer_val;
    timer_set(TIMER_INTERVAL);
    802021bc:	90000101 	adrp	x1, 80222000 <init_lock>
    802021c0:	d281a802 	mov	x2, #0xd40                 	// #3392
    802021c4:	f2a00062 	movk	x2, #0x3, lsl #16
    802021c8:	d2869b66 	mov	x6, #0x34db                	// #13531
    802021cc:	f9400421 	ldr	x1, [x1, #8]
    test[index_test++] = curr_timer_val-prev_timer_val;
    802021d0:	d0000163 	adrp	x3, 80230000 <its>
    timer_set(TIMER_INTERVAL);
    802021d4:	f2baf6c6 	movk	x6, #0xd7b6, lsl #16
    test[index_test++] = curr_timer_val-prev_timer_val;
    802021d8:	d00003e4 	adrp	x4, 80280000 <gits_lock>
    timer_set(TIMER_INTERVAL);
    802021dc:	f2dbd046 	movk	x6, #0xde82, lsl #32
    802021e0:	9b027c21 	mul	x1, x1, x2
    802021e4:	f2e86366 	movk	x6, #0x431b, lsl #48
    test[index_test++] = curr_timer_val-prev_timer_val;
    802021e8:	f9401865 	ldr	x5, [x3, #48]
    802021ec:	91002083 	add	x3, x4, #0x8
    802021f0:	b9400882 	ldr	w2, [x4, #8]
    802021f4:	91002063 	add	x3, x3, #0x8
    timer_set(TIMER_INTERVAL);
    802021f8:	9bc67c21 	umulh	x1, x1, x6
    test[index_test++] = curr_timer_val-prev_timer_val;
    802021fc:	cb050000 	sub	x0, x0, x5
    80202200:	2a0203e5 	mov	w5, w2
    80202204:	11000442 	add	w2, w2, #0x1
    80202208:	b9000882 	str	w2, [x4, #8]
    8020220c:	f8257860 	str	x0, [x3, x5, lsl #3]
    timer_set(TIMER_INTERVAL);
    80202210:	d352fc20 	lsr	x0, x1, #18
    80202214:	97fffab3 	bl	80200ce0 <timer_set>
    lpi_handled = 1;
    80202218:	f0000060 	adrp	x0, 80211000 <blanks.1+0x60>
    8020221c:	52800021 	mov	w1, #0x1                   	// #1
    // irq_enable(TIMER_IRQ_ID);
}
    80202220:	a8c17bfd 	ldp	x29, x30, [sp], #16
    lpi_handled = 1;
    80202224:	391c0001 	strb	w1, [x0, #1792]
}
    80202228:	d65f03c0 	ret
    8020222c:	d503201f 	nop

0000000080202230 <timer_handler>:
void timer_handler(){
    80202230:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80202234:	910003fd 	mov	x29, sp
    80202238:	a90153f3 	stp	x19, x20, [sp, #16]
    if(lpi_handled)
    8020223c:	f0000074 	adrp	x20, 80211000 <blanks.1+0x60>
    80202240:	395c0280 	ldrb	w0, [x20, #1792]
    80202244:	72001c1f 	tst	w0, #0xff
    80202248:	54000180 	b.eq	80202278 <timer_handler+0x48>  // b.none
        if(index_test < 502){
    8020224c:	d00003f3 	adrp	x19, 80280000 <gits_lock>
    80202250:	91002262 	add	x2, x19, #0x8
    80202254:	b9400a60 	ldr	w0, [x19, #8]
    80202258:	7107d41f 	cmp	w0, #0x1f5
    8020225c:	54000148 	b.hi	80202284 <timer_handler+0x54>  // b.pmore
        if(index_test)
    80202260:	b9400a60 	ldr	w0, [x19, #8]
    80202264:	35000380 	cbnz	w0, 802022d4 <timer_handler+0xa4>
        lpi_handled = 0;
    80202268:	391c029f 	strb	wzr, [x20, #1792]
        if(index_test < 501)
    8020226c:	b9400a60 	ldr	w0, [x19, #8]
    80202270:	7107d01f 	cmp	w0, #0x1f4
    80202274:	540002a9 	b.ls	802022c8 <timer_handler+0x98>  // b.plast
}
    80202278:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020227c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80202280:	d65f03c0 	ret
        printf("Done\n");
    80202284:	d0000060 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    80202288:	912ea000 	add	x0, x0, #0xba8
    8020228c:	940003d9 	bl	802031f0 <puts>
        timer_set(TIME_S(60));
    80202290:	90000100 	adrp	x0, 80222000 <init_lock>
    80202294:	d290e002 	mov	x2, #0x8700                	// #34560
    80202298:	f2a07262 	movk	x2, #0x393, lsl #16
    8020229c:	d2869b61 	mov	x1, #0x34db                	// #13531
    802022a0:	f9400400 	ldr	x0, [x0, #8]
    802022a4:	f2baf6c1 	movk	x1, #0xd7b6, lsl #16
}
    802022a8:	a94153f3 	ldp	x19, x20, [sp, #16]
        timer_set(TIME_S(60));
    802022ac:	f2dbd041 	movk	x1, #0xde82, lsl #32
    802022b0:	9b027c00 	mul	x0, x0, x2
    802022b4:	f2e86361 	movk	x1, #0x431b, lsl #48
}
    802022b8:	a8c27bfd 	ldp	x29, x30, [sp], #32
        timer_set(TIME_S(60));
    802022bc:	9bc17c00 	umulh	x0, x0, x1
    802022c0:	d352fc00 	lsr	x0, x0, #18
    802022c4:	17fffa87 	b	80200ce0 <timer_set>
}
    802022c8:	a94153f3 	ldp	x19, x20, [sp, #16]
    802022cc:	a8c27bfd 	ldp	x29, x30, [sp], #32
            its_trigger_lpi();
    802022d0:	17ffff21 	b	80201f54 <its_trigger_lpi>
            printf("Value of sample %d is %d\n",index_test -1,test[index_test -1]);
    802022d4:	b9400a61 	ldr	w1, [x19, #8]
    802022d8:	91002042 	add	x2, x2, #0x8
    802022dc:	b9400a63 	ldr	w3, [x19, #8]
    802022e0:	d0000060 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    802022e4:	51000421 	sub	w1, w1, #0x1
    802022e8:	912e2000 	add	x0, x0, #0xb88
    802022ec:	51000463 	sub	w3, w3, #0x1
    802022f0:	f8637842 	ldr	x2, [x2, x3, lsl #3]
    802022f4:	94000363 	bl	80203080 <printf>
    802022f8:	17ffffdc 	b	80202268 <timer_handler+0x38>
    802022fc:	d503201f 	nop

0000000080202300 <get_counter_frequency>:
    asm volatile("mrs %0, CNTFRQ_EL0" : "=r"(frequency));
    80202300:	d53be000 	mrs	x0, cntfrq_el0
}
    80202304:	d65f03c0 	ret
	...

0000000080202310 <main>:

void main(void){
    80202310:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80202314:	910003fd 	mov	x29, sp
    80202318:	f9000bf3 	str	x19, [sp, #16]
    8020231c:	d53800a0 	mrs	x0, mpidr_el1
    80202320:	d00003f3 	adrp	x19, 80280000 <gits_lock>
    80202324:	91002273 	add	x19, x19, #0x8

    static volatile bool master_done = false;

    if(cpu_is_master()){
    80202328:	72001c1f 	tst	w0, #0xff
    8020232c:	540001a0 	b.eq	80202360 <main+0x50>  // b.none
        master_done = true;
    }
    // spin_lock(&print_lock);
    // printf("Here\n");
    // spin_unlock(&print_lock);
    while(!master_done);
    80202330:	397ec260 	ldrb	w0, [x19, #4016]
    80202334:	3607ffe0 	tbz	w0, #0, 80202330 <main+0x20>
    asm volatile (
    80202338:	52800020 	mov	w0, #0x1                   	// #1
    8020233c:	913ed262 	add	x2, x19, #0xfb4
    80202340:	885ffc41 	ldaxr	w1, [x2]
    80202344:	35ffffe1 	cbnz	w1, 80202340 <main+0x30>
    80202348:	88017c40 	stxr	w1, w0, [x2]
    8020234c:	35ffffa1 	cbnz	w1, 80202340 <main+0x30>
    80202350:	b9002fe1 	str	w1, [sp, #44]
    asm volatile ("stlr wzr, %0\n\t" :: "Q"(*lock));
    80202354:	889ffc5f 	stlr	wzr, [x2]
    80202358:	d503207f 	wfi
        //printf("cpu %d up\n", get_cpuid());
        //printf("Here\n");
        spin_unlock(&print_lock);
    //}

    while(1) wfi();
    8020235c:	17ffffff 	b	80202358 <main+0x48>
        irq_set_handler(TIMER_IRQ_ID, timer_handler);
    80202360:	52800360 	mov	w0, #0x1b                  	// #27
    80202364:	90000001 	adrp	x1, 80202000 <its_trigger_lpi+0xac>
    80202368:	9108c021 	add	x1, x1, #0x230
    8020236c:	97fff925 	bl	80200800 <irq_set_handler>
        timer_set(TIMER_INTERVAL);
    80202370:	90000100 	adrp	x0, 80222000 <init_lock>
    80202374:	d281a802 	mov	x2, #0xd40                 	// #3392
    80202378:	f2a00062 	movk	x2, #0x3, lsl #16
    8020237c:	d2884801 	mov	x1, #0x4240                	// #16960
    80202380:	f9400400 	ldr	x0, [x0, #8]
    80202384:	f2a001e1 	movk	x1, #0xf, lsl #16
    80202388:	9b027c00 	mul	x0, x0, x2
    8020238c:	9ac10800 	udiv	x0, x0, x1
    80202390:	97fffa54 	bl	80200ce0 <timer_set>
        irq_enable(TIMER_IRQ_ID);
    80202394:	52800360 	mov	w0, #0x1b                  	// #27
    80202398:	97fffa2a 	bl	80200c40 <irq_enable>
        irq_set_prio(TIMER_IRQ_ID, IRQ_MAX_PRIO);
    8020239c:	52800001 	mov	w1, #0x0                   	// #0
    802023a0:	52800360 	mov	w0, #0x1b                  	// #27
    802023a4:	97fffa37 	bl	80200c80 <irq_set_prio>
        irq_set_handler(8192, lpi_handler);
    802023a8:	52840000 	mov	w0, #0x2000                	// #8192
    802023ac:	90000001 	adrp	x1, 80202000 <its_trigger_lpi+0xac>
    802023b0:	9106c021 	add	x1, x1, #0x1b0
    802023b4:	97fff913 	bl	80200800 <irq_set_handler>
        master_done = true;
    802023b8:	52800020 	mov	w0, #0x1                   	// #1
    802023bc:	393ec260 	strb	w0, [x19, #4016]
    802023c0:	17ffffdc 	b	80202330 <main+0x20>
	...

0000000080202800 <_exception_vector>:
/* 
 * EL1 with SP0
 */  
.balign ENTRY_SIZE
curr_el_sp0_sync:        
    b	.
    80202800:	14000000 	b	80202800 <_exception_vector>
    80202804:	d503201f 	nop
    80202808:	d503201f 	nop
    8020280c:	d503201f 	nop
    80202810:	d503201f 	nop
    80202814:	d503201f 	nop
    80202818:	d503201f 	nop
    8020281c:	d503201f 	nop
    80202820:	d503201f 	nop
    80202824:	d503201f 	nop
    80202828:	d503201f 	nop
    8020282c:	d503201f 	nop
    80202830:	d503201f 	nop
    80202834:	d503201f 	nop
    80202838:	d503201f 	nop
    8020283c:	d503201f 	nop
    80202840:	d503201f 	nop
    80202844:	d503201f 	nop
    80202848:	d503201f 	nop
    8020284c:	d503201f 	nop
    80202850:	d503201f 	nop
    80202854:	d503201f 	nop
    80202858:	d503201f 	nop
    8020285c:	d503201f 	nop
    80202860:	d503201f 	nop
    80202864:	d503201f 	nop
    80202868:	d503201f 	nop
    8020286c:	d503201f 	nop
    80202870:	d503201f 	nop
    80202874:	d503201f 	nop
    80202878:	d503201f 	nop
    8020287c:	d503201f 	nop

0000000080202880 <curr_el_sp0_irq>:
.balign ENTRY_SIZE
curr_el_sp0_irq:  
    b   .
    80202880:	14000000 	b	80202880 <curr_el_sp0_irq>
    80202884:	d503201f 	nop
    80202888:	d503201f 	nop
    8020288c:	d503201f 	nop
    80202890:	d503201f 	nop
    80202894:	d503201f 	nop
    80202898:	d503201f 	nop
    8020289c:	d503201f 	nop
    802028a0:	d503201f 	nop
    802028a4:	d503201f 	nop
    802028a8:	d503201f 	nop
    802028ac:	d503201f 	nop
    802028b0:	d503201f 	nop
    802028b4:	d503201f 	nop
    802028b8:	d503201f 	nop
    802028bc:	d503201f 	nop
    802028c0:	d503201f 	nop
    802028c4:	d503201f 	nop
    802028c8:	d503201f 	nop
    802028cc:	d503201f 	nop
    802028d0:	d503201f 	nop
    802028d4:	d503201f 	nop
    802028d8:	d503201f 	nop
    802028dc:	d503201f 	nop
    802028e0:	d503201f 	nop
    802028e4:	d503201f 	nop
    802028e8:	d503201f 	nop
    802028ec:	d503201f 	nop
    802028f0:	d503201f 	nop
    802028f4:	d503201f 	nop
    802028f8:	d503201f 	nop
    802028fc:	d503201f 	nop

0000000080202900 <curr_el_sp0_fiq>:
.balign ENTRY_SIZE
curr_el_sp0_fiq:         
    b	.
    80202900:	14000000 	b	80202900 <curr_el_sp0_fiq>
    80202904:	d503201f 	nop
    80202908:	d503201f 	nop
    8020290c:	d503201f 	nop
    80202910:	d503201f 	nop
    80202914:	d503201f 	nop
    80202918:	d503201f 	nop
    8020291c:	d503201f 	nop
    80202920:	d503201f 	nop
    80202924:	d503201f 	nop
    80202928:	d503201f 	nop
    8020292c:	d503201f 	nop
    80202930:	d503201f 	nop
    80202934:	d503201f 	nop
    80202938:	d503201f 	nop
    8020293c:	d503201f 	nop
    80202940:	d503201f 	nop
    80202944:	d503201f 	nop
    80202948:	d503201f 	nop
    8020294c:	d503201f 	nop
    80202950:	d503201f 	nop
    80202954:	d503201f 	nop
    80202958:	d503201f 	nop
    8020295c:	d503201f 	nop
    80202960:	d503201f 	nop
    80202964:	d503201f 	nop
    80202968:	d503201f 	nop
    8020296c:	d503201f 	nop
    80202970:	d503201f 	nop
    80202974:	d503201f 	nop
    80202978:	d503201f 	nop
    8020297c:	d503201f 	nop

0000000080202980 <curr_el_sp0_serror>:
.balign ENTRY_SIZE
curr_el_sp0_serror:      
    b	.
    80202980:	14000000 	b	80202980 <curr_el_sp0_serror>
    80202984:	d503201f 	nop
    80202988:	d503201f 	nop
    8020298c:	d503201f 	nop
    80202990:	d503201f 	nop
    80202994:	d503201f 	nop
    80202998:	d503201f 	nop
    8020299c:	d503201f 	nop
    802029a0:	d503201f 	nop
    802029a4:	d503201f 	nop
    802029a8:	d503201f 	nop
    802029ac:	d503201f 	nop
    802029b0:	d503201f 	nop
    802029b4:	d503201f 	nop
    802029b8:	d503201f 	nop
    802029bc:	d503201f 	nop
    802029c0:	d503201f 	nop
    802029c4:	d503201f 	nop
    802029c8:	d503201f 	nop
    802029cc:	d503201f 	nop
    802029d0:	d503201f 	nop
    802029d4:	d503201f 	nop
    802029d8:	d503201f 	nop
    802029dc:	d503201f 	nop
    802029e0:	d503201f 	nop
    802029e4:	d503201f 	nop
    802029e8:	d503201f 	nop
    802029ec:	d503201f 	nop
    802029f0:	d503201f 	nop
    802029f4:	d503201f 	nop
    802029f8:	d503201f 	nop
    802029fc:	d503201f 	nop

0000000080202a00 <curr_el_spx_sync>:
/* 
 * EL1 with SPx
 */  
.balign ENTRY_SIZE  
curr_el_spx_sync:        
    b	.
    80202a00:	14000000 	b	80202a00 <curr_el_spx_sync>
    80202a04:	d503201f 	nop
    80202a08:	d503201f 	nop
    80202a0c:	d503201f 	nop
    80202a10:	d503201f 	nop
    80202a14:	d503201f 	nop
    80202a18:	d503201f 	nop
    80202a1c:	d503201f 	nop
    80202a20:	d503201f 	nop
    80202a24:	d503201f 	nop
    80202a28:	d503201f 	nop
    80202a2c:	d503201f 	nop
    80202a30:	d503201f 	nop
    80202a34:	d503201f 	nop
    80202a38:	d503201f 	nop
    80202a3c:	d503201f 	nop
    80202a40:	d503201f 	nop
    80202a44:	d503201f 	nop
    80202a48:	d503201f 	nop
    80202a4c:	d503201f 	nop
    80202a50:	d503201f 	nop
    80202a54:	d503201f 	nop
    80202a58:	d503201f 	nop
    80202a5c:	d503201f 	nop
    80202a60:	d503201f 	nop
    80202a64:	d503201f 	nop
    80202a68:	d503201f 	nop
    80202a6c:	d503201f 	nop
    80202a70:	d503201f 	nop
    80202a74:	d503201f 	nop
    80202a78:	d503201f 	nop
    80202a7c:	d503201f 	nop

0000000080202a80 <curr_el_spx_irq>:
.balign ENTRY_SIZE
curr_el_spx_irq:       
    SAVE_REGS
    80202a80:	d102c3ff 	sub	sp, sp, #0xb0
    80202a84:	a90007e0 	stp	x0, x1, [sp]
    80202a88:	a9010fe2 	stp	x2, x3, [sp, #16]
    80202a8c:	a90217e4 	stp	x4, x5, [sp, #32]
    80202a90:	a9031fe6 	stp	x6, x7, [sp, #48]
    80202a94:	a90427e8 	stp	x8, x9, [sp, #64]
    80202a98:	a9052fea 	stp	x10, x11, [sp, #80]
    80202a9c:	a90637ec 	stp	x12, x13, [sp, #96]
    80202aa0:	a9073fee 	stp	x14, x15, [sp, #112]
    80202aa4:	a90847f0 	stp	x16, x17, [sp, #128]
    80202aa8:	a9094ff2 	stp	x18, x19, [sp, #144]
    80202aac:	a90a7bfd 	stp	x29, x30, [sp, #160]
    bl	gic_handle
    80202ab0:	97fff910 	bl	80200ef0 <gic_handle>
    RESTORE_REGS
    80202ab4:	a94007e0 	ldp	x0, x1, [sp]
    80202ab8:	a9410fe2 	ldp	x2, x3, [sp, #16]
    80202abc:	a94217e4 	ldp	x4, x5, [sp, #32]
    80202ac0:	a9431fe6 	ldp	x6, x7, [sp, #48]
    80202ac4:	a94427e8 	ldp	x8, x9, [sp, #64]
    80202ac8:	a9452fea 	ldp	x10, x11, [sp, #80]
    80202acc:	a94637ec 	ldp	x12, x13, [sp, #96]
    80202ad0:	a9473fee 	ldp	x14, x15, [sp, #112]
    80202ad4:	a94847f0 	ldp	x16, x17, [sp, #128]
    80202ad8:	a9494ff2 	ldp	x18, x19, [sp, #144]
    80202adc:	a94a7bfd 	ldp	x29, x30, [sp, #160]
    80202ae0:	9102c3ff 	add	sp, sp, #0xb0
    eret
    80202ae4:	d69f03e0 	eret
    80202ae8:	d503201f 	nop
    80202aec:	d503201f 	nop
    80202af0:	d503201f 	nop
    80202af4:	d503201f 	nop
    80202af8:	d503201f 	nop
    80202afc:	d503201f 	nop

0000000080202b00 <curr_el_spx_fiq>:
.balign ENTRY_SIZE
curr_el_spx_fiq:         
    SAVE_REGS
    80202b00:	d102c3ff 	sub	sp, sp, #0xb0
    80202b04:	a90007e0 	stp	x0, x1, [sp]
    80202b08:	a9010fe2 	stp	x2, x3, [sp, #16]
    80202b0c:	a90217e4 	stp	x4, x5, [sp, #32]
    80202b10:	a9031fe6 	stp	x6, x7, [sp, #48]
    80202b14:	a90427e8 	stp	x8, x9, [sp, #64]
    80202b18:	a9052fea 	stp	x10, x11, [sp, #80]
    80202b1c:	a90637ec 	stp	x12, x13, [sp, #96]
    80202b20:	a9073fee 	stp	x14, x15, [sp, #112]
    80202b24:	a90847f0 	stp	x16, x17, [sp, #128]
    80202b28:	a9094ff2 	stp	x18, x19, [sp, #144]
    80202b2c:	a90a7bfd 	stp	x29, x30, [sp, #160]
    bl	gic_handle
    80202b30:	97fff8f0 	bl	80200ef0 <gic_handle>
    RESTORE_REGS
    80202b34:	a94007e0 	ldp	x0, x1, [sp]
    80202b38:	a9410fe2 	ldp	x2, x3, [sp, #16]
    80202b3c:	a94217e4 	ldp	x4, x5, [sp, #32]
    80202b40:	a9431fe6 	ldp	x6, x7, [sp, #48]
    80202b44:	a94427e8 	ldp	x8, x9, [sp, #64]
    80202b48:	a9452fea 	ldp	x10, x11, [sp, #80]
    80202b4c:	a94637ec 	ldp	x12, x13, [sp, #96]
    80202b50:	a9473fee 	ldp	x14, x15, [sp, #112]
    80202b54:	a94847f0 	ldp	x16, x17, [sp, #128]
    80202b58:	a9494ff2 	ldp	x18, x19, [sp, #144]
    80202b5c:	a94a7bfd 	ldp	x29, x30, [sp, #160]
    80202b60:	9102c3ff 	add	sp, sp, #0xb0
    eret
    80202b64:	d69f03e0 	eret
    80202b68:	d503201f 	nop
    80202b6c:	d503201f 	nop
    80202b70:	d503201f 	nop
    80202b74:	d503201f 	nop
    80202b78:	d503201f 	nop
    80202b7c:	d503201f 	nop

0000000080202b80 <curr_el_spx_serror>:
.balign ENTRY_SIZE
curr_el_spx_serror:      
    b	.         
    80202b80:	14000000 	b	80202b80 <curr_el_spx_serror>
    80202b84:	d503201f 	nop
    80202b88:	d503201f 	nop
    80202b8c:	d503201f 	nop
    80202b90:	d503201f 	nop
    80202b94:	d503201f 	nop
    80202b98:	d503201f 	nop
    80202b9c:	d503201f 	nop
    80202ba0:	d503201f 	nop
    80202ba4:	d503201f 	nop
    80202ba8:	d503201f 	nop
    80202bac:	d503201f 	nop
    80202bb0:	d503201f 	nop
    80202bb4:	d503201f 	nop
    80202bb8:	d503201f 	nop
    80202bbc:	d503201f 	nop
    80202bc0:	d503201f 	nop
    80202bc4:	d503201f 	nop
    80202bc8:	d503201f 	nop
    80202bcc:	d503201f 	nop
    80202bd0:	d503201f 	nop
    80202bd4:	d503201f 	nop
    80202bd8:	d503201f 	nop
    80202bdc:	d503201f 	nop
    80202be0:	d503201f 	nop
    80202be4:	d503201f 	nop
    80202be8:	d503201f 	nop
    80202bec:	d503201f 	nop
    80202bf0:	d503201f 	nop
    80202bf4:	d503201f 	nop
    80202bf8:	d503201f 	nop
    80202bfc:	d503201f 	nop

0000000080202c00 <lower_el_aarch64_sync>:
 * Lower EL using AArch64
 */  

.balign ENTRY_SIZE
lower_el_aarch64_sync:
    b .
    80202c00:	14000000 	b	80202c00 <lower_el_aarch64_sync>
    80202c04:	d503201f 	nop
    80202c08:	d503201f 	nop
    80202c0c:	d503201f 	nop
    80202c10:	d503201f 	nop
    80202c14:	d503201f 	nop
    80202c18:	d503201f 	nop
    80202c1c:	d503201f 	nop
    80202c20:	d503201f 	nop
    80202c24:	d503201f 	nop
    80202c28:	d503201f 	nop
    80202c2c:	d503201f 	nop
    80202c30:	d503201f 	nop
    80202c34:	d503201f 	nop
    80202c38:	d503201f 	nop
    80202c3c:	d503201f 	nop
    80202c40:	d503201f 	nop
    80202c44:	d503201f 	nop
    80202c48:	d503201f 	nop
    80202c4c:	d503201f 	nop
    80202c50:	d503201f 	nop
    80202c54:	d503201f 	nop
    80202c58:	d503201f 	nop
    80202c5c:	d503201f 	nop
    80202c60:	d503201f 	nop
    80202c64:	d503201f 	nop
    80202c68:	d503201f 	nop
    80202c6c:	d503201f 	nop
    80202c70:	d503201f 	nop
    80202c74:	d503201f 	nop
    80202c78:	d503201f 	nop
    80202c7c:	d503201f 	nop

0000000080202c80 <lower_el_aarch64_irq>:
.balign ENTRY_SIZE
lower_el_aarch64_irq:    
    b .
    80202c80:	14000000 	b	80202c80 <lower_el_aarch64_irq>
    80202c84:	d503201f 	nop
    80202c88:	d503201f 	nop
    80202c8c:	d503201f 	nop
    80202c90:	d503201f 	nop
    80202c94:	d503201f 	nop
    80202c98:	d503201f 	nop
    80202c9c:	d503201f 	nop
    80202ca0:	d503201f 	nop
    80202ca4:	d503201f 	nop
    80202ca8:	d503201f 	nop
    80202cac:	d503201f 	nop
    80202cb0:	d503201f 	nop
    80202cb4:	d503201f 	nop
    80202cb8:	d503201f 	nop
    80202cbc:	d503201f 	nop
    80202cc0:	d503201f 	nop
    80202cc4:	d503201f 	nop
    80202cc8:	d503201f 	nop
    80202ccc:	d503201f 	nop
    80202cd0:	d503201f 	nop
    80202cd4:	d503201f 	nop
    80202cd8:	d503201f 	nop
    80202cdc:	d503201f 	nop
    80202ce0:	d503201f 	nop
    80202ce4:	d503201f 	nop
    80202ce8:	d503201f 	nop
    80202cec:	d503201f 	nop
    80202cf0:	d503201f 	nop
    80202cf4:	d503201f 	nop
    80202cf8:	d503201f 	nop
    80202cfc:	d503201f 	nop

0000000080202d00 <lower_el_aarch64_fiq>:
.balign ENTRY_SIZE
lower_el_aarch64_fiq:    
    b	.
    80202d00:	14000000 	b	80202d00 <lower_el_aarch64_fiq>
    80202d04:	d503201f 	nop
    80202d08:	d503201f 	nop
    80202d0c:	d503201f 	nop
    80202d10:	d503201f 	nop
    80202d14:	d503201f 	nop
    80202d18:	d503201f 	nop
    80202d1c:	d503201f 	nop
    80202d20:	d503201f 	nop
    80202d24:	d503201f 	nop
    80202d28:	d503201f 	nop
    80202d2c:	d503201f 	nop
    80202d30:	d503201f 	nop
    80202d34:	d503201f 	nop
    80202d38:	d503201f 	nop
    80202d3c:	d503201f 	nop
    80202d40:	d503201f 	nop
    80202d44:	d503201f 	nop
    80202d48:	d503201f 	nop
    80202d4c:	d503201f 	nop
    80202d50:	d503201f 	nop
    80202d54:	d503201f 	nop
    80202d58:	d503201f 	nop
    80202d5c:	d503201f 	nop
    80202d60:	d503201f 	nop
    80202d64:	d503201f 	nop
    80202d68:	d503201f 	nop
    80202d6c:	d503201f 	nop
    80202d70:	d503201f 	nop
    80202d74:	d503201f 	nop
    80202d78:	d503201f 	nop
    80202d7c:	d503201f 	nop

0000000080202d80 <lower_el_aarch64_serror>:
.balign ENTRY_SIZE
lower_el_aarch64_serror: 
    b	.          
    80202d80:	14000000 	b	80202d80 <lower_el_aarch64_serror>
    80202d84:	d503201f 	nop
    80202d88:	d503201f 	nop
    80202d8c:	d503201f 	nop
    80202d90:	d503201f 	nop
    80202d94:	d503201f 	nop
    80202d98:	d503201f 	nop
    80202d9c:	d503201f 	nop
    80202da0:	d503201f 	nop
    80202da4:	d503201f 	nop
    80202da8:	d503201f 	nop
    80202dac:	d503201f 	nop
    80202db0:	d503201f 	nop
    80202db4:	d503201f 	nop
    80202db8:	d503201f 	nop
    80202dbc:	d503201f 	nop
    80202dc0:	d503201f 	nop
    80202dc4:	d503201f 	nop
    80202dc8:	d503201f 	nop
    80202dcc:	d503201f 	nop
    80202dd0:	d503201f 	nop
    80202dd4:	d503201f 	nop
    80202dd8:	d503201f 	nop
    80202ddc:	d503201f 	nop
    80202de0:	d503201f 	nop
    80202de4:	d503201f 	nop
    80202de8:	d503201f 	nop
    80202dec:	d503201f 	nop
    80202df0:	d503201f 	nop
    80202df4:	d503201f 	nop
    80202df8:	d503201f 	nop
    80202dfc:	d503201f 	nop

0000000080202e00 <lower_el_aarch32_sync>:
/* 
 * Lower EL using AArch32
 */  
.balign ENTRY_SIZE   
lower_el_aarch32_sync:   
    b	.
    80202e00:	14000000 	b	80202e00 <lower_el_aarch32_sync>
    80202e04:	d503201f 	nop
    80202e08:	d503201f 	nop
    80202e0c:	d503201f 	nop
    80202e10:	d503201f 	nop
    80202e14:	d503201f 	nop
    80202e18:	d503201f 	nop
    80202e1c:	d503201f 	nop
    80202e20:	d503201f 	nop
    80202e24:	d503201f 	nop
    80202e28:	d503201f 	nop
    80202e2c:	d503201f 	nop
    80202e30:	d503201f 	nop
    80202e34:	d503201f 	nop
    80202e38:	d503201f 	nop
    80202e3c:	d503201f 	nop
    80202e40:	d503201f 	nop
    80202e44:	d503201f 	nop
    80202e48:	d503201f 	nop
    80202e4c:	d503201f 	nop
    80202e50:	d503201f 	nop
    80202e54:	d503201f 	nop
    80202e58:	d503201f 	nop
    80202e5c:	d503201f 	nop
    80202e60:	d503201f 	nop
    80202e64:	d503201f 	nop
    80202e68:	d503201f 	nop
    80202e6c:	d503201f 	nop
    80202e70:	d503201f 	nop
    80202e74:	d503201f 	nop
    80202e78:	d503201f 	nop
    80202e7c:	d503201f 	nop

0000000080202e80 <lower_el_aarch32_irq>:
.balign ENTRY_SIZE
lower_el_aarch32_irq:    
    b	.
    80202e80:	14000000 	b	80202e80 <lower_el_aarch32_irq>
    80202e84:	d503201f 	nop
    80202e88:	d503201f 	nop
    80202e8c:	d503201f 	nop
    80202e90:	d503201f 	nop
    80202e94:	d503201f 	nop
    80202e98:	d503201f 	nop
    80202e9c:	d503201f 	nop
    80202ea0:	d503201f 	nop
    80202ea4:	d503201f 	nop
    80202ea8:	d503201f 	nop
    80202eac:	d503201f 	nop
    80202eb0:	d503201f 	nop
    80202eb4:	d503201f 	nop
    80202eb8:	d503201f 	nop
    80202ebc:	d503201f 	nop
    80202ec0:	d503201f 	nop
    80202ec4:	d503201f 	nop
    80202ec8:	d503201f 	nop
    80202ecc:	d503201f 	nop
    80202ed0:	d503201f 	nop
    80202ed4:	d503201f 	nop
    80202ed8:	d503201f 	nop
    80202edc:	d503201f 	nop
    80202ee0:	d503201f 	nop
    80202ee4:	d503201f 	nop
    80202ee8:	d503201f 	nop
    80202eec:	d503201f 	nop
    80202ef0:	d503201f 	nop
    80202ef4:	d503201f 	nop
    80202ef8:	d503201f 	nop
    80202efc:	d503201f 	nop

0000000080202f00 <lower_el_aarch32_fiq>:
.balign ENTRY_SIZE
lower_el_aarch32_fiq:    
    b	.
    80202f00:	14000000 	b	80202f00 <lower_el_aarch32_fiq>
    80202f04:	d503201f 	nop
    80202f08:	d503201f 	nop
    80202f0c:	d503201f 	nop
    80202f10:	d503201f 	nop
    80202f14:	d503201f 	nop
    80202f18:	d503201f 	nop
    80202f1c:	d503201f 	nop
    80202f20:	d503201f 	nop
    80202f24:	d503201f 	nop
    80202f28:	d503201f 	nop
    80202f2c:	d503201f 	nop
    80202f30:	d503201f 	nop
    80202f34:	d503201f 	nop
    80202f38:	d503201f 	nop
    80202f3c:	d503201f 	nop
    80202f40:	d503201f 	nop
    80202f44:	d503201f 	nop
    80202f48:	d503201f 	nop
    80202f4c:	d503201f 	nop
    80202f50:	d503201f 	nop
    80202f54:	d503201f 	nop
    80202f58:	d503201f 	nop
    80202f5c:	d503201f 	nop
    80202f60:	d503201f 	nop
    80202f64:	d503201f 	nop
    80202f68:	d503201f 	nop
    80202f6c:	d503201f 	nop
    80202f70:	d503201f 	nop
    80202f74:	d503201f 	nop
    80202f78:	d503201f 	nop
    80202f7c:	d503201f 	nop

0000000080202f80 <lower_el_aarch32_serror>:
.balign ENTRY_SIZE
lower_el_aarch32_serror: 
    b	.
    80202f80:	14000000 	b	80202f80 <lower_el_aarch32_serror>
    80202f84:	d503201f 	nop
    80202f88:	d503201f 	nop
    80202f8c:	d503201f 	nop
    80202f90:	d503201f 	nop
    80202f94:	d503201f 	nop
    80202f98:	d503201f 	nop
    80202f9c:	d503201f 	nop
    80202fa0:	d503201f 	nop
    80202fa4:	d503201f 	nop
    80202fa8:	d503201f 	nop
    80202fac:	d503201f 	nop
    80202fb0:	d503201f 	nop
    80202fb4:	d503201f 	nop
    80202fb8:	d503201f 	nop
    80202fbc:	d503201f 	nop
    80202fc0:	d503201f 	nop
    80202fc4:	d503201f 	nop
    80202fc8:	d503201f 	nop
    80202fcc:	d503201f 	nop
    80202fd0:	d503201f 	nop
    80202fd4:	d503201f 	nop
    80202fd8:	d503201f 	nop
    80202fdc:	d503201f 	nop
    80202fe0:	d503201f 	nop
    80202fe4:	d503201f 	nop
    80202fe8:	d503201f 	nop
    80202fec:	d503201f 	nop
    80202ff0:	d503201f 	nop
    80202ff4:	d503201f 	nop
    80202ff8:	d503201f 	nop
    80202ffc:	d503201f 	nop

0000000080203000 <__errno>:
    80203000:	d0000060 	adrp	x0, 80211000 <blanks.1+0x60>
    80203004:	f9438800 	ldr	x0, [x0, #1808]
    80203008:	d65f03c0 	ret
    8020300c:	00000000 	udf	#0

0000000080203010 <_printf_r>:
    80203010:	a9b07bfd 	stp	x29, x30, [sp, #-256]!
    80203014:	128005e9 	mov	w9, #0xffffffd0            	// #-48
    80203018:	12800fe8 	mov	w8, #0xffffff80            	// #-128
    8020301c:	910003fd 	mov	x29, sp
    80203020:	910343ea 	add	x10, sp, #0xd0
    80203024:	910403eb 	add	x11, sp, #0x100
    80203028:	a9032feb 	stp	x11, x11, [sp, #48]
    8020302c:	f90023ea 	str	x10, [sp, #64]
    80203030:	290923e9 	stp	w9, w8, [sp, #72]
    80203034:	3d8017e0 	str	q0, [sp, #80]
    80203038:	ad41c3e0 	ldp	q0, q16, [sp, #48]
    8020303c:	3d801be1 	str	q1, [sp, #96]
    80203040:	3d801fe2 	str	q2, [sp, #112]
    80203044:	3d8023e3 	str	q3, [sp, #128]
    80203048:	3d8027e4 	str	q4, [sp, #144]
    8020304c:	3d802be5 	str	q5, [sp, #160]
    80203050:	3d802fe6 	str	q6, [sp, #176]
    80203054:	3d8033e7 	str	q7, [sp, #192]
    80203058:	a90d0fe2 	stp	x2, x3, [sp, #208]
    8020305c:	aa0103e2 	mov	x2, x1
    80203060:	910043e3 	add	x3, sp, #0x10
    80203064:	a90e17e4 	stp	x4, x5, [sp, #224]
    80203068:	a90f1fe6 	stp	x6, x7, [sp, #240]
    8020306c:	ad00c3e0 	stp	q0, q16, [sp, #16]
    80203070:	f9400801 	ldr	x1, [x0, #16]
    80203074:	940003e3 	bl	80204000 <_vfprintf_r>
    80203078:	a8d07bfd 	ldp	x29, x30, [sp], #256
    8020307c:	d65f03c0 	ret

0000000080203080 <printf>:
    80203080:	a9af7bfd 	stp	x29, x30, [sp, #-272]!
    80203084:	128006eb 	mov	w11, #0xffffffc8            	// #-56
    80203088:	12800fea 	mov	w10, #0xffffff80            	// #-128
    8020308c:	910003fd 	mov	x29, sp
    80203090:	910343ec 	add	x12, sp, #0xd0
    80203094:	910443e8 	add	x8, sp, #0x110
    80203098:	d0000069 	adrp	x9, 80211000 <blanks.1+0x60>
    8020309c:	a90323e8 	stp	x8, x8, [sp, #48]
    802030a0:	aa0003e8 	mov	x8, x0
    802030a4:	f90023ec 	str	x12, [sp, #64]
    802030a8:	29092beb 	stp	w11, w10, [sp, #72]
    802030ac:	f9438920 	ldr	x0, [x9, #1808]
    802030b0:	3d8017e0 	str	q0, [sp, #80]
    802030b4:	ad41c3e0 	ldp	q0, q16, [sp, #48]
    802030b8:	3d801be1 	str	q1, [sp, #96]
    802030bc:	3d801fe2 	str	q2, [sp, #112]
    802030c0:	3d8023e3 	str	q3, [sp, #128]
    802030c4:	3d8027e4 	str	q4, [sp, #144]
    802030c8:	3d802be5 	str	q5, [sp, #160]
    802030cc:	3d802fe6 	str	q6, [sp, #176]
    802030d0:	3d8033e7 	str	q7, [sp, #192]
    802030d4:	a90d8be1 	stp	x1, x2, [sp, #216]
    802030d8:	aa0803e2 	mov	x2, x8
    802030dc:	a90e93e3 	stp	x3, x4, [sp, #232]
    802030e0:	910043e3 	add	x3, sp, #0x10
    802030e4:	a90f9be5 	stp	x5, x6, [sp, #248]
    802030e8:	f90087e7 	str	x7, [sp, #264]
    802030ec:	ad00c3e0 	stp	q0, q16, [sp, #16]
    802030f0:	f9400801 	ldr	x1, [x0, #16]
    802030f4:	940003c3 	bl	80204000 <_vfprintf_r>
    802030f8:	a8d17bfd 	ldp	x29, x30, [sp], #272
    802030fc:	d65f03c0 	ret

0000000080203100 <_puts_r>:
    80203100:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    80203104:	910003fd 	mov	x29, sp
    80203108:	a90153f3 	stp	x19, x20, [sp, #16]
    8020310c:	aa0003f4 	mov	x20, x0
    80203110:	aa0103f3 	mov	x19, x1
    80203114:	aa0103e0 	mov	x0, x1
    80203118:	940001fa 	bl	80203900 <strlen>
    8020311c:	f9402682 	ldr	x2, [x20, #72]
    80203120:	91000404 	add	x4, x0, #0x1
    80203124:	910103e6 	add	x6, sp, #0x40
    80203128:	b0000061 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020312c:	d2800023 	mov	x3, #0x1                   	// #1
    80203130:	912e8021 	add	x1, x1, #0xba0
    80203134:	52800045 	mov	w5, #0x2                   	// #2
    80203138:	f90017e6 	str	x6, [sp, #40]
    8020313c:	b90033e5 	str	w5, [sp, #48]
    80203140:	a903cfe4 	stp	x4, x19, [sp, #56]
    80203144:	a90487e0 	stp	x0, x1, [sp, #72]
    80203148:	f9002fe3 	str	x3, [sp, #88]
    8020314c:	f9400a93 	ldr	x19, [x20, #16]
    80203150:	b4000482 	cbz	x2, 802031e0 <_puts_r+0xe0>
    80203154:	b940b261 	ldr	w1, [x19, #176]
    80203158:	79c02260 	ldrsh	w0, [x19, #16]
    8020315c:	37000041 	tbnz	w1, #0, 80203164 <_puts_r+0x64>
    80203160:	36480380 	tbz	w0, #9, 802031d0 <_puts_r+0xd0>
    80203164:	376800c0 	tbnz	w0, #13, 8020317c <_puts_r+0x7c>
    80203168:	b940b261 	ldr	w1, [x19, #176]
    8020316c:	32130000 	orr	w0, w0, #0x2000
    80203170:	79002260 	strh	w0, [x19, #16]
    80203174:	12127820 	and	w0, w1, #0xffffdfff
    80203178:	b900b260 	str	w0, [x19, #176]
    8020317c:	aa1403e0 	mov	x0, x20
    80203180:	aa1303e1 	mov	x1, x19
    80203184:	9100a3e2 	add	x2, sp, #0x28
    80203188:	9400022a 	bl	80203a30 <__sfvwrite_r>
    8020318c:	b940b261 	ldr	w1, [x19, #176]
    80203190:	7100001f 	cmp	w0, #0x0
    80203194:	52800154 	mov	w20, #0xa                   	// #10
    80203198:	5a9f0294 	csinv	w20, w20, wzr, eq	// eq = none
    8020319c:	37000061 	tbnz	w1, #0, 802031a8 <_puts_r+0xa8>
    802031a0:	79402260 	ldrh	w0, [x19, #16]
    802031a4:	364800a0 	tbz	w0, #9, 802031b8 <_puts_r+0xb8>
    802031a8:	2a1403e0 	mov	w0, w20
    802031ac:	a94153f3 	ldp	x19, x20, [sp, #16]
    802031b0:	a8c67bfd 	ldp	x29, x30, [sp], #96
    802031b4:	d65f03c0 	ret
    802031b8:	f9405260 	ldr	x0, [x19, #160]
    802031bc:	94001a91 	bl	80209c00 <__retarget_lock_release_recursive>
    802031c0:	2a1403e0 	mov	w0, w20
    802031c4:	a94153f3 	ldp	x19, x20, [sp, #16]
    802031c8:	a8c67bfd 	ldp	x29, x30, [sp], #96
    802031cc:	d65f03c0 	ret
    802031d0:	f9405260 	ldr	x0, [x19, #160]
    802031d4:	94001a7b 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    802031d8:	79c02260 	ldrsh	w0, [x19, #16]
    802031dc:	17ffffe2 	b	80203164 <_puts_r+0x64>
    802031e0:	aa1403e0 	mov	x0, x20
    802031e4:	940000fb 	bl	802035d0 <__sinit>
    802031e8:	17ffffdb 	b	80203154 <_puts_r+0x54>
    802031ec:	00000000 	udf	#0

00000000802031f0 <puts>:
    802031f0:	d0000062 	adrp	x2, 80211000 <blanks.1+0x60>
    802031f4:	aa0003e1 	mov	x1, x0
    802031f8:	f9438840 	ldr	x0, [x2, #1808]
    802031fc:	17ffffc1 	b	80203100 <_puts_r>

0000000080203200 <stdio_exit_handler>:
    80203200:	d0000062 	adrp	x2, 80211000 <blanks.1+0x60>
    80203204:	f0000021 	adrp	x1, 8020a000 <__loadlocale+0x320>
    80203208:	9121c042 	add	x2, x2, #0x870
    8020320c:	91240021 	add	x1, x1, #0x900
    80203210:	d0000060 	adrp	x0, 80211000 <blanks.1+0x60>
    80203214:	911c6000 	add	x0, x0, #0x718
    80203218:	1400033a 	b	80203f00 <_fwalk_sglue>
    8020321c:	00000000 	udf	#0

0000000080203220 <cleanup_stdio>:
    80203220:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80203224:	b00003e2 	adrp	x2, 80280000 <gits_lock>
    80203228:	913f2042 	add	x2, x2, #0xfc8
    8020322c:	910003fd 	mov	x29, sp
    80203230:	f9400401 	ldr	x1, [x0, #8]
    80203234:	f9000bf3 	str	x19, [sp, #16]
    80203238:	aa0003f3 	mov	x19, x0
    8020323c:	eb02003f 	cmp	x1, x2
    80203240:	54000040 	b.eq	80203248 <cleanup_stdio+0x28>  // b.none
    80203244:	94001daf 	bl	8020a900 <_fclose_r>
    80203248:	f9400a61 	ldr	x1, [x19, #16]
    8020324c:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    80203250:	91020000 	add	x0, x0, #0x80
    80203254:	eb00003f 	cmp	x1, x0
    80203258:	54000060 	b.eq	80203264 <cleanup_stdio+0x44>  // b.none
    8020325c:	aa1303e0 	mov	x0, x19
    80203260:	94001da8 	bl	8020a900 <_fclose_r>
    80203264:	f9400e61 	ldr	x1, [x19, #24]
    80203268:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    8020326c:	9104e000 	add	x0, x0, #0x138
    80203270:	eb00003f 	cmp	x1, x0
    80203274:	540000a0 	b.eq	80203288 <cleanup_stdio+0x68>  // b.none
    80203278:	aa1303e0 	mov	x0, x19
    8020327c:	f9400bf3 	ldr	x19, [sp, #16]
    80203280:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80203284:	14001d9f 	b	8020a900 <_fclose_r>
    80203288:	f9400bf3 	ldr	x19, [sp, #16]
    8020328c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80203290:	d65f03c0 	ret
	...

00000000802032a0 <__fp_lock>:
    802032a0:	b940b020 	ldr	w0, [x1, #176]
    802032a4:	37000060 	tbnz	w0, #0, 802032b0 <__fp_lock+0x10>
    802032a8:	79402020 	ldrh	w0, [x1, #16]
    802032ac:	36480060 	tbz	w0, #9, 802032b8 <__fp_lock+0x18>
    802032b0:	52800000 	mov	w0, #0x0                   	// #0
    802032b4:	d65f03c0 	ret
    802032b8:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    802032bc:	910003fd 	mov	x29, sp
    802032c0:	f9405020 	ldr	x0, [x1, #160]
    802032c4:	94001a3f 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    802032c8:	52800000 	mov	w0, #0x0                   	// #0
    802032cc:	a8c17bfd 	ldp	x29, x30, [sp], #16
    802032d0:	d65f03c0 	ret
	...

00000000802032e0 <__fp_unlock>:
    802032e0:	b940b020 	ldr	w0, [x1, #176]
    802032e4:	37000060 	tbnz	w0, #0, 802032f0 <__fp_unlock+0x10>
    802032e8:	79402020 	ldrh	w0, [x1, #16]
    802032ec:	36480060 	tbz	w0, #9, 802032f8 <__fp_unlock+0x18>
    802032f0:	52800000 	mov	w0, #0x0                   	// #0
    802032f4:	d65f03c0 	ret
    802032f8:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    802032fc:	910003fd 	mov	x29, sp
    80203300:	f9405020 	ldr	x0, [x1, #160]
    80203304:	94001a3f 	bl	80209c00 <__retarget_lock_release_recursive>
    80203308:	52800000 	mov	w0, #0x0                   	// #0
    8020330c:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80203310:	d65f03c0 	ret
	...

0000000080203320 <global_stdio_init.part.0>:
    80203320:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    80203324:	b00003e0 	adrp	x0, 80280000 <gits_lock>
    80203328:	d00003e2 	adrp	x2, 80281000 <__sf+0x38>
    8020332c:	910003fd 	mov	x29, sp
    80203330:	a90153f3 	stp	x19, x20, [sp, #16]
    80203334:	913f2013 	add	x19, x0, #0xfc8
    80203338:	52800083 	mov	w3, #0x4                   	// #4
    8020333c:	90000001 	adrp	x1, 80203000 <__errno>
    80203340:	91080021 	add	x1, x1, #0x200
    80203344:	f900f841 	str	x1, [x2, #496]
    80203348:	d2800102 	mov	x2, #0x8                   	// #8
    8020334c:	52800001 	mov	w1, #0x0                   	// #0
    80203350:	a9025bf5 	stp	x21, x22, [sp, #32]
    80203354:	90000014 	adrp	x20, 80203000 <__errno>
    80203358:	f9001bf7 	str	x23, [sp, #48]
    8020335c:	9123c294 	add	x20, x20, #0x8f0
    80203360:	f907e41f 	str	xzr, [x0, #4040]
    80203364:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    80203368:	9101c000 	add	x0, x0, #0x70
    8020336c:	f900067f 	str	xzr, [x19, #8]
    80203370:	b9001263 	str	w3, [x19, #16]
    80203374:	90000016 	adrp	x22, 80203000 <__errno>
    80203378:	f9000e7f 	str	xzr, [x19, #24]
    8020337c:	9120c2d6 	add	x22, x22, #0x830
    80203380:	b900227f 	str	wzr, [x19, #32]
    80203384:	90000015 	adrp	x21, 80203000 <__errno>
    80203388:	b9002a7f 	str	wzr, [x19, #40]
    8020338c:	912282b5 	add	x21, x21, #0x8a0
    80203390:	b900b27f 	str	wzr, [x19, #176]
    80203394:	940000cb 	bl	802036c0 <memset>
    80203398:	90000017 	adrp	x23, 80203000 <__errno>
    8020339c:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    802033a0:	911f42f7 	add	x23, x23, #0x7d0
    802033a4:	9101a000 	add	x0, x0, #0x68
    802033a8:	a9035e73 	stp	x19, x23, [x19, #48]
    802033ac:	a9045676 	stp	x22, x21, [x19, #64]
    802033b0:	f9002a74 	str	x20, [x19, #80]
    802033b4:	940019f3 	bl	80209b80 <__retarget_lock_init_recursive>
    802033b8:	52800123 	mov	w3, #0x9                   	// #9
    802033bc:	d2800102 	mov	x2, #0x8                   	// #8
    802033c0:	72a00023 	movk	w3, #0x1, lsl #16
    802033c4:	52800001 	mov	w1, #0x0                   	// #0
    802033c8:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    802033cc:	9104a000 	add	x0, x0, #0x128
    802033d0:	f9005e7f 	str	xzr, [x19, #184]
    802033d4:	f900627f 	str	xzr, [x19, #192]
    802033d8:	b900ca63 	str	w3, [x19, #200]
    802033dc:	f9006a7f 	str	xzr, [x19, #208]
    802033e0:	b900da7f 	str	wzr, [x19, #216]
    802033e4:	b900e27f 	str	wzr, [x19, #224]
    802033e8:	b9016a7f 	str	wzr, [x19, #360]
    802033ec:	940000b5 	bl	802036c0 <memset>
    802033f0:	d00003e1 	adrp	x1, 80281000 <__sf+0x38>
    802033f4:	91020021 	add	x1, x1, #0x80
    802033f8:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    802033fc:	91048000 	add	x0, x0, #0x120
    80203400:	a90ede61 	stp	x1, x23, [x19, #232]
    80203404:	a90fd676 	stp	x22, x21, [x19, #248]
    80203408:	f9008674 	str	x20, [x19, #264]
    8020340c:	940019dd 	bl	80209b80 <__retarget_lock_init_recursive>
    80203410:	52800243 	mov	w3, #0x12                  	// #18
    80203414:	d2800102 	mov	x2, #0x8                   	// #8
    80203418:	72a00043 	movk	w3, #0x2, lsl #16
    8020341c:	52800001 	mov	w1, #0x0                   	// #0
    80203420:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    80203424:	91078000 	add	x0, x0, #0x1e0
    80203428:	f900ba7f 	str	xzr, [x19, #368]
    8020342c:	f900be7f 	str	xzr, [x19, #376]
    80203430:	b9018263 	str	w3, [x19, #384]
    80203434:	f900c67f 	str	xzr, [x19, #392]
    80203438:	b901927f 	str	wzr, [x19, #400]
    8020343c:	b9019a7f 	str	wzr, [x19, #408]
    80203440:	b902227f 	str	wzr, [x19, #544]
    80203444:	9400009f 	bl	802036c0 <memset>
    80203448:	d00003e1 	adrp	x1, 80281000 <__sf+0x38>
    8020344c:	9104e021 	add	x1, x1, #0x138
    80203450:	a91a5e61 	stp	x1, x23, [x19, #416]
    80203454:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    80203458:	91076000 	add	x0, x0, #0x1d8
    8020345c:	a91b5676 	stp	x22, x21, [x19, #432]
    80203460:	f900e274 	str	x20, [x19, #448]
    80203464:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203468:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020346c:	f9401bf7 	ldr	x23, [sp, #48]
    80203470:	a8c47bfd 	ldp	x29, x30, [sp], #64
    80203474:	140019c3 	b	80209b80 <__retarget_lock_init_recursive>
	...

0000000080203480 <__sfp>:
    80203480:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    80203484:	910003fd 	mov	x29, sp
    80203488:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020348c:	d00003f5 	adrp	x21, 80281000 <__sf+0x38>
    80203490:	9109c2b5 	add	x21, x21, #0x270
    80203494:	aa0003f6 	mov	x22, x0
    80203498:	aa1503e0 	mov	x0, x21
    8020349c:	a90153f3 	stp	x19, x20, [sp, #16]
    802034a0:	f9001bf7 	str	x23, [sp, #48]
    802034a4:	940019c7 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    802034a8:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    802034ac:	f940f800 	ldr	x0, [x0, #496]
    802034b0:	b40007a0 	cbz	x0, 802035a4 <__sfp+0x124>
    802034b4:	d0000074 	adrp	x20, 80211000 <blanks.1+0x60>
    802034b8:	9121c294 	add	x20, x20, #0x870
    802034bc:	52801717 	mov	w23, #0xb8                  	// #184
    802034c0:	b9400a82 	ldr	w2, [x20, #8]
    802034c4:	f9400a93 	ldr	x19, [x20, #16]
    802034c8:	7100005f 	cmp	w2, #0x0
    802034cc:	5400044d 	b.le	80203554 <__sfp+0xd4>
    802034d0:	9bb74c42 	umaddl	x2, w2, w23, x19
    802034d4:	14000004 	b	802034e4 <__sfp+0x64>
    802034d8:	9102e273 	add	x19, x19, #0xb8
    802034dc:	eb13005f 	cmp	x2, x19
    802034e0:	540003a0 	b.eq	80203554 <__sfp+0xd4>  // b.none
    802034e4:	79c02261 	ldrsh	w1, [x19, #16]
    802034e8:	35ffff81 	cbnz	w1, 802034d8 <__sfp+0x58>
    802034ec:	129fffc0 	mov	w0, #0xffff0001            	// #-65535
    802034f0:	b9001260 	str	w0, [x19, #16]
    802034f4:	b900b27f 	str	wzr, [x19, #176]
    802034f8:	91028260 	add	x0, x19, #0xa0
    802034fc:	940019a1 	bl	80209b80 <__retarget_lock_init_recursive>
    80203500:	aa1503e0 	mov	x0, x21
    80203504:	940019bf 	bl	80209c00 <__retarget_lock_release_recursive>
    80203508:	f900027f 	str	xzr, [x19]
    8020350c:	9102a260 	add	x0, x19, #0xa8
    80203510:	f900067f 	str	xzr, [x19, #8]
    80203514:	d2800102 	mov	x2, #0x8                   	// #8
    80203518:	f9000e7f 	str	xzr, [x19, #24]
    8020351c:	52800001 	mov	w1, #0x0                   	// #0
    80203520:	b900227f 	str	wzr, [x19, #32]
    80203524:	b9002a7f 	str	wzr, [x19, #40]
    80203528:	94000066 	bl	802036c0 <memset>
    8020352c:	f9002e7f 	str	xzr, [x19, #88]
    80203530:	b900627f 	str	wzr, [x19, #96]
    80203534:	f9003e7f 	str	xzr, [x19, #120]
    80203538:	b900827f 	str	wzr, [x19, #128]
    8020353c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80203540:	aa1303e0 	mov	x0, x19
    80203544:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203548:	f9401bf7 	ldr	x23, [sp, #48]
    8020354c:	a8c47bfd 	ldp	x29, x30, [sp], #64
    80203550:	d65f03c0 	ret
    80203554:	f9400293 	ldr	x19, [x20]
    80203558:	b4000073 	cbz	x19, 80203564 <__sfp+0xe4>
    8020355c:	aa1303f4 	mov	x20, x19
    80203560:	17ffffd8 	b	802034c0 <__sfp+0x40>
    80203564:	aa1603e0 	mov	x0, x22
    80203568:	d2805f01 	mov	x1, #0x2f8                 	// #760
    8020356c:	94001735 	bl	80209240 <_malloc_r>
    80203570:	aa0003f3 	mov	x19, x0
    80203574:	b40001c0 	cbz	x0, 802035ac <__sfp+0x12c>
    80203578:	91006000 	add	x0, x0, #0x18
    8020357c:	52800081 	mov	w1, #0x4                   	// #4
    80203580:	f900027f 	str	xzr, [x19]
    80203584:	d2805c02 	mov	x2, #0x2e0                 	// #736
    80203588:	b9000a61 	str	w1, [x19, #8]
    8020358c:	52800001 	mov	w1, #0x0                   	// #0
    80203590:	f9000a60 	str	x0, [x19, #16]
    80203594:	9400004b 	bl	802036c0 <memset>
    80203598:	f9000293 	str	x19, [x20]
    8020359c:	aa1303f4 	mov	x20, x19
    802035a0:	17ffffc8 	b	802034c0 <__sfp+0x40>
    802035a4:	97ffff5f 	bl	80203320 <global_stdio_init.part.0>
    802035a8:	17ffffc3 	b	802034b4 <__sfp+0x34>
    802035ac:	f900029f 	str	xzr, [x20]
    802035b0:	aa1503e0 	mov	x0, x21
    802035b4:	94001993 	bl	80209c00 <__retarget_lock_release_recursive>
    802035b8:	52800180 	mov	w0, #0xc                   	// #12
    802035bc:	b90002c0 	str	w0, [x22]
    802035c0:	17ffffdf 	b	8020353c <__sfp+0xbc>
	...

00000000802035d0 <__sinit>:
    802035d0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    802035d4:	910003fd 	mov	x29, sp
    802035d8:	a90153f3 	stp	x19, x20, [sp, #16]
    802035dc:	aa0003f4 	mov	x20, x0
    802035e0:	d00003f3 	adrp	x19, 80281000 <__sf+0x38>
    802035e4:	9109c273 	add	x19, x19, #0x270
    802035e8:	aa1303e0 	mov	x0, x19
    802035ec:	94001975 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    802035f0:	f9402680 	ldr	x0, [x20, #72]
    802035f4:	b50000e0 	cbnz	x0, 80203610 <__sinit+0x40>
    802035f8:	d00003e1 	adrp	x1, 80281000 <__sf+0x38>
    802035fc:	90000000 	adrp	x0, 80203000 <__errno>
    80203600:	91088000 	add	x0, x0, #0x220
    80203604:	f9002680 	str	x0, [x20, #72]
    80203608:	f940f820 	ldr	x0, [x1, #496]
    8020360c:	b40000a0 	cbz	x0, 80203620 <__sinit+0x50>
    80203610:	aa1303e0 	mov	x0, x19
    80203614:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203618:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020361c:	14001979 	b	80209c00 <__retarget_lock_release_recursive>
    80203620:	97ffff40 	bl	80203320 <global_stdio_init.part.0>
    80203624:	aa1303e0 	mov	x0, x19
    80203628:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020362c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80203630:	14001974 	b	80209c00 <__retarget_lock_release_recursive>
	...

0000000080203640 <__sfp_lock_acquire>:
    80203640:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    80203644:	9109c000 	add	x0, x0, #0x270
    80203648:	1400195e 	b	80209bc0 <__retarget_lock_acquire_recursive>
    8020364c:	00000000 	udf	#0

0000000080203650 <__sfp_lock_release>:
    80203650:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    80203654:	9109c000 	add	x0, x0, #0x270
    80203658:	1400196a 	b	80209c00 <__retarget_lock_release_recursive>
    8020365c:	00000000 	udf	#0

0000000080203660 <__fp_lock_all>:
    80203660:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80203664:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    80203668:	9109c000 	add	x0, x0, #0x270
    8020366c:	910003fd 	mov	x29, sp
    80203670:	94001954 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    80203674:	a8c17bfd 	ldp	x29, x30, [sp], #16
    80203678:	d0000062 	adrp	x2, 80211000 <blanks.1+0x60>
    8020367c:	90000001 	adrp	x1, 80203000 <__errno>
    80203680:	9121c042 	add	x2, x2, #0x870
    80203684:	910a8021 	add	x1, x1, #0x2a0
    80203688:	d2800000 	mov	x0, #0x0                   	// #0
    8020368c:	1400021d 	b	80203f00 <_fwalk_sglue>

0000000080203690 <__fp_unlock_all>:
    80203690:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80203694:	d0000062 	adrp	x2, 80211000 <blanks.1+0x60>
    80203698:	90000001 	adrp	x1, 80203000 <__errno>
    8020369c:	910003fd 	mov	x29, sp
    802036a0:	9121c042 	add	x2, x2, #0x870
    802036a4:	910b8021 	add	x1, x1, #0x2e0
    802036a8:	d2800000 	mov	x0, #0x0                   	// #0
    802036ac:	94000215 	bl	80203f00 <_fwalk_sglue>
    802036b0:	a8c17bfd 	ldp	x29, x30, [sp], #16
    802036b4:	d00003e0 	adrp	x0, 80281000 <__sf+0x38>
    802036b8:	9109c000 	add	x0, x0, #0x270
    802036bc:	14001951 	b	80209c00 <__retarget_lock_release_recursive>

00000000802036c0 <memset>:
    802036c0:	d503245f 	bti	c
    802036c4:	4e010c20 	dup	v0.16b, w1
    802036c8:	8b020004 	add	x4, x0, x2
    802036cc:	f101805f 	cmp	x2, #0x60
    802036d0:	54000388 	b.hi	80203740 <memset+0x80>  // b.pmore
    802036d4:	f100405f 	cmp	x2, #0x10
    802036d8:	540001e2 	b.cs	80203714 <memset+0x54>  // b.hs, b.nlast
    802036dc:	4e083c01 	mov	x1, v0.d[0]
    802036e0:	36180082 	tbz	w2, #3, 802036f0 <memset+0x30>
    802036e4:	f9000001 	str	x1, [x0]
    802036e8:	f81f8081 	stur	x1, [x4, #-8]
    802036ec:	d65f03c0 	ret
    802036f0:	36100082 	tbz	w2, #2, 80203700 <memset+0x40>
    802036f4:	b9000001 	str	w1, [x0]
    802036f8:	b81fc081 	stur	w1, [x4, #-4]
    802036fc:	d65f03c0 	ret
    80203700:	b4000082 	cbz	x2, 80203710 <memset+0x50>
    80203704:	39000001 	strb	w1, [x0]
    80203708:	36080042 	tbz	w2, #1, 80203710 <memset+0x50>
    8020370c:	781fe081 	sturh	w1, [x4, #-2]
    80203710:	d65f03c0 	ret
    80203714:	3d800000 	str	q0, [x0]
    80203718:	373000c2 	tbnz	w2, #6, 80203730 <memset+0x70>
    8020371c:	3c9f0080 	stur	q0, [x4, #-16]
    80203720:	36280062 	tbz	w2, #5, 8020372c <memset+0x6c>
    80203724:	3d800400 	str	q0, [x0, #16]
    80203728:	3c9e0080 	stur	q0, [x4, #-32]
    8020372c:	d65f03c0 	ret
    80203730:	3d800400 	str	q0, [x0, #16]
    80203734:	ad010000 	stp	q0, q0, [x0, #32]
    80203738:	ad3f0080 	stp	q0, q0, [x4, #-32]
    8020373c:	d65f03c0 	ret
    80203740:	12001c21 	and	w1, w1, #0xff
    80203744:	927cec03 	and	x3, x0, #0xfffffffffffffff0
    80203748:	3d800000 	str	q0, [x0]
    8020374c:	f102805f 	cmp	x2, #0xa0
    80203750:	7a402820 	ccmp	w1, #0x0, #0x0, cs	// cs = hs, nlast
    80203754:	54000241 	b.ne	8020379c <memset+0xdc>  // b.any
    80203758:	d53b00e5 	mrs	x5, dczid_el0
    8020375c:	924010a5 	and	x5, x5, #0x1f
    80203760:	f10010bf 	cmp	x5, #0x4
    80203764:	540001c1 	b.ne	8020379c <memset+0xdc>  // b.any
    80203768:	3d800460 	str	q0, [x3, #16]
    8020376c:	ad010060 	stp	q0, q0, [x3, #32]
    80203770:	927ae463 	and	x3, x3, #0xffffffffffffffc0
    80203774:	cb030082 	sub	x2, x4, x3
    80203778:	d1020042 	sub	x2, x2, #0x80
    8020377c:	d503201f 	nop
    80203780:	91010063 	add	x3, x3, #0x40
    80203784:	d50b7423 	dc	zva, x3
    80203788:	f1010042 	subs	x2, x2, #0x40
    8020378c:	54ffffa8 	b.hi	80203780 <memset+0xc0>  // b.pmore
    80203790:	ad3e0080 	stp	q0, q0, [x4, #-64]
    80203794:	ad3f0080 	stp	q0, q0, [x4, #-32]
    80203798:	d65f03c0 	ret
    8020379c:	cb030082 	sub	x2, x4, x3
    802037a0:	d1004063 	sub	x3, x3, #0x10
    802037a4:	d1014042 	sub	x2, x2, #0x50
    802037a8:	ad010060 	stp	q0, q0, [x3, #32]
    802037ac:	ad820060 	stp	q0, q0, [x3, #64]!
    802037b0:	f1010042 	subs	x2, x2, #0x40
    802037b4:	54ffffa8 	b.hi	802037a8 <memset+0xe8>  // b.pmore
    802037b8:	ad3e0080 	stp	q0, q0, [x4, #-64]
    802037bc:	ad3f0080 	stp	q0, q0, [x4, #-32]
    802037c0:	d65f03c0 	ret
	...

00000000802037d0 <__sread>:
    802037d0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    802037d4:	93407c63 	sxtw	x3, w3
    802037d8:	910003fd 	mov	x29, sp
    802037dc:	f9000bf3 	str	x19, [sp, #16]
    802037e0:	aa0103f3 	mov	x19, x1
    802037e4:	79c02421 	ldrsh	w1, [x1, #18]
    802037e8:	94002822 	bl	8020d870 <_read_r>
    802037ec:	b7f800e0 	tbnz	x0, #63, 80203808 <__sread+0x38>
    802037f0:	f9404a61 	ldr	x1, [x19, #144]
    802037f4:	8b000021 	add	x1, x1, x0
    802037f8:	f9004a61 	str	x1, [x19, #144]
    802037fc:	f9400bf3 	ldr	x19, [sp, #16]
    80203800:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80203804:	d65f03c0 	ret
    80203808:	79402261 	ldrh	w1, [x19, #16]
    8020380c:	12137821 	and	w1, w1, #0xffffefff
    80203810:	79002261 	strh	w1, [x19, #16]
    80203814:	f9400bf3 	ldr	x19, [sp, #16]
    80203818:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020381c:	d65f03c0 	ret

0000000080203820 <__seofread>:
    80203820:	52800000 	mov	w0, #0x0                   	// #0
    80203824:	d65f03c0 	ret
	...

0000000080203830 <__swrite>:
    80203830:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80203834:	910003fd 	mov	x29, sp
    80203838:	79c02024 	ldrsh	w4, [x1, #16]
    8020383c:	a90153f3 	stp	x19, x20, [sp, #16]
    80203840:	aa0103f3 	mov	x19, x1
    80203844:	aa0003f4 	mov	x20, x0
    80203848:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020384c:	aa0203f5 	mov	x21, x2
    80203850:	2a0303f6 	mov	w22, w3
    80203854:	37400184 	tbnz	w4, #8, 80203884 <__swrite+0x54>
    80203858:	79c02661 	ldrsh	w1, [x19, #18]
    8020385c:	12137884 	and	w4, w4, #0xffffefff
    80203860:	79002264 	strh	w4, [x19, #16]
    80203864:	93407ec3 	sxtw	x3, w22
    80203868:	aa1503e2 	mov	x2, x21
    8020386c:	aa1403e0 	mov	x0, x20
    80203870:	940001cc 	bl	80203fa0 <_write_r>
    80203874:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203878:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020387c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80203880:	d65f03c0 	ret
    80203884:	79c02421 	ldrsh	w1, [x1, #18]
    80203888:	52800043 	mov	w3, #0x2                   	// #2
    8020388c:	d2800002 	mov	x2, #0x0                   	// #0
    80203890:	940027e0 	bl	8020d810 <_lseek_r>
    80203894:	79c02264 	ldrsh	w4, [x19, #16]
    80203898:	17fffff0 	b	80203858 <__swrite+0x28>
    8020389c:	00000000 	udf	#0

00000000802038a0 <__sseek>:
    802038a0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    802038a4:	910003fd 	mov	x29, sp
    802038a8:	f9000bf3 	str	x19, [sp, #16]
    802038ac:	aa0103f3 	mov	x19, x1
    802038b0:	79c02421 	ldrsh	w1, [x1, #18]
    802038b4:	940027d7 	bl	8020d810 <_lseek_r>
    802038b8:	79c02261 	ldrsh	w1, [x19, #16]
    802038bc:	b100041f 	cmn	x0, #0x1
    802038c0:	540000e0 	b.eq	802038dc <__sseek+0x3c>  // b.none
    802038c4:	32140021 	orr	w1, w1, #0x1000
    802038c8:	79002261 	strh	w1, [x19, #16]
    802038cc:	f9004a60 	str	x0, [x19, #144]
    802038d0:	f9400bf3 	ldr	x19, [sp, #16]
    802038d4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802038d8:	d65f03c0 	ret
    802038dc:	12137821 	and	w1, w1, #0xffffefff
    802038e0:	79002261 	strh	w1, [x19, #16]
    802038e4:	f9400bf3 	ldr	x19, [sp, #16]
    802038e8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802038ec:	d65f03c0 	ret

00000000802038f0 <__sclose>:
    802038f0:	79c02421 	ldrsh	w1, [x1, #18]
    802038f4:	140022df 	b	8020c470 <_close_r>
	...

0000000080203900 <strlen>:
    80203900:	d503245f 	bti	c
    80203904:	92402c04 	and	x4, x0, #0xfff
    80203908:	f13f809f 	cmp	x4, #0xfe0
    8020390c:	540006c8 	b.hi	802039e4 <strlen+0xe4>  // b.pmore
    80203910:	a9400c02 	ldp	x2, x3, [x0]
    80203914:	b200c3e8 	mov	x8, #0x101010101010101     	// #72340172838076673
    80203918:	cb080044 	sub	x4, x2, x8
    8020391c:	b200d845 	orr	x5, x2, #0x7f7f7f7f7f7f7f7f
    80203920:	cb080066 	sub	x6, x3, x8
    80203924:	b200d867 	orr	x7, x3, #0x7f7f7f7f7f7f7f7f
    80203928:	ea250084 	bics	x4, x4, x5
    8020392c:	8a2700c5 	bic	x5, x6, x7
    80203930:	fa4008a0 	ccmp	x5, #0x0, #0x0, eq	// eq = none
    80203934:	54000100 	b.eq	80203954 <strlen+0x54>  // b.none
    80203938:	9a853084 	csel	x4, x4, x5, cc	// cc = lo, ul, last
    8020393c:	d2800100 	mov	x0, #0x8                   	// #8
    80203940:	dac00c84 	rev	x4, x4
    80203944:	9a8033e0 	csel	x0, xzr, x0, cc	// cc = lo, ul, last
    80203948:	dac01084 	clz	x4, x4
    8020394c:	8b440c00 	add	x0, x0, x4, lsr #3
    80203950:	d65f03c0 	ret
    80203954:	a9410c02 	ldp	x2, x3, [x0, #16]
    80203958:	cb080044 	sub	x4, x2, x8
    8020395c:	b200d845 	orr	x5, x2, #0x7f7f7f7f7f7f7f7f
    80203960:	cb080066 	sub	x6, x3, x8
    80203964:	b200d867 	orr	x7, x3, #0x7f7f7f7f7f7f7f7f
    80203968:	ea250084 	bics	x4, x4, x5
    8020396c:	8a2700c5 	bic	x5, x6, x7
    80203970:	fa4008a0 	ccmp	x5, #0x0, #0x0, eq	// eq = none
    80203974:	54000140 	b.eq	8020399c <strlen+0x9c>  // b.none
    80203978:	9a853084 	csel	x4, x4, x5, cc	// cc = lo, ul, last
    8020397c:	d2800300 	mov	x0, #0x18                  	// #24
    80203980:	dac00c84 	rev	x4, x4
    80203984:	d2800206 	mov	x6, #0x10                  	// #16
    80203988:	dac01084 	clz	x4, x4
    8020398c:	9a8030c0 	csel	x0, x6, x0, cc	// cc = lo, ul, last
    80203990:	8b440c00 	add	x0, x0, x4, lsr #3
    80203994:	d65f03c0 	ret
    80203998:	d503201f 	nop
    8020399c:	927be801 	and	x1, x0, #0xffffffffffffffe0
    802039a0:	adc10821 	ldp	q1, q2, [x1, #32]!
    802039a4:	6e22ac20 	uminp	v0.16b, v1.16b, v2.16b
    802039a8:	6e20ac00 	uminp	v0.16b, v0.16b, v0.16b
    802039ac:	0e209800 	cmeq	v0.8b, v0.8b, #0
    802039b0:	9e660003 	fmov	x3, d0
    802039b4:	b4ffff63 	cbz	x3, 802039a0 <strlen+0xa0>
    802039b8:	4e209820 	cmeq	v0.16b, v1.16b, #0
    802039bc:	cb000020 	sub	x0, x1, x0
    802039c0:	35000063 	cbnz	w3, 802039cc <strlen+0xcc>
    802039c4:	4e209840 	cmeq	v0.16b, v2.16b, #0
    802039c8:	91004000 	add	x0, x0, #0x10
    802039cc:	0f0c8400 	shrn	v0.8b, v0.8h, #4
    802039d0:	9e660003 	fmov	x3, d0
    802039d4:	dac00063 	rbit	x3, x3
    802039d8:	dac01062 	clz	x2, x3
    802039dc:	8b420800 	add	x0, x0, x2, lsr #2
    802039e0:	d65f03c0 	ret
    802039e4:	927be801 	and	x1, x0, #0xffffffffffffffe0
    802039e8:	52818062 	mov	w2, #0xc03                 	// #3075
    802039ec:	72b80602 	movk	w2, #0xc030, lsl #16
    802039f0:	4c40a021 	ld1	{v1.16b-v2.16b}, [x1]
    802039f4:	4e040c40 	dup	v0.4s, w2
    802039f8:	4e209821 	cmeq	v1.16b, v1.16b, #0
    802039fc:	4e209842 	cmeq	v2.16b, v2.16b, #0
    80203a00:	4e201c21 	and	v1.16b, v1.16b, v0.16b
    80203a04:	4e201c42 	and	v2.16b, v2.16b, v0.16b
    80203a08:	4e22bc20 	addp	v0.16b, v1.16b, v2.16b
    80203a0c:	4e20bc00 	addp	v0.16b, v0.16b, v0.16b
    80203a10:	9e660003 	fmov	x3, d0
    80203a14:	d37ff804 	lsl	x4, x0, #1
    80203a18:	9ac42463 	lsr	x3, x3, x4
    80203a1c:	b4fffc23 	cbz	x3, 802039a0 <strlen+0xa0>
    80203a20:	dac00063 	rbit	x3, x3
    80203a24:	dac01060 	clz	x0, x3
    80203a28:	d341fc00 	lsr	x0, x0, #1
    80203a2c:	d65f03c0 	ret

0000000080203a30 <__sfvwrite_r>:
    80203a30:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    80203a34:	910003fd 	mov	x29, sp
    80203a38:	a9025bf5 	stp	x21, x22, [sp, #32]
    80203a3c:	aa0003f5 	mov	x21, x0
    80203a40:	f9400840 	ldr	x0, [x2, #16]
    80203a44:	b4000ac0 	cbz	x0, 80203b9c <__sfvwrite_r+0x16c>
    80203a48:	79c02025 	ldrsh	w5, [x1, #16]
    80203a4c:	a90153f3 	stp	x19, x20, [sp, #16]
    80203a50:	aa0103f3 	mov	x19, x1
    80203a54:	a90573fb 	stp	x27, x28, [sp, #80]
    80203a58:	aa0203fb 	mov	x27, x2
    80203a5c:	36180a85 	tbz	w5, #3, 80203bac <__sfvwrite_r+0x17c>
    80203a60:	f9400c20 	ldr	x0, [x1, #24]
    80203a64:	b4000a40 	cbz	x0, 80203bac <__sfvwrite_r+0x17c>
    80203a68:	a90363f7 	stp	x23, x24, [sp, #48]
    80203a6c:	f9400374 	ldr	x20, [x27]
    80203a70:	360803e5 	tbz	w5, #1, 80203aec <__sfvwrite_r+0xbc>
    80203a74:	f9401a61 	ldr	x1, [x19, #48]
    80203a78:	d2800017 	mov	x23, #0x0                   	// #0
    80203a7c:	f9402264 	ldr	x4, [x19, #64]
    80203a80:	d2800016 	mov	x22, #0x0                   	// #0
    80203a84:	b27653f8 	mov	x24, #0x7ffffc00            	// #2147482624
    80203a88:	eb1802df 	cmp	x22, x24
    80203a8c:	aa1703e2 	mov	x2, x23
    80203a90:	9a9892c3 	csel	x3, x22, x24, ls	// ls = plast
    80203a94:	aa1503e0 	mov	x0, x21
    80203a98:	b4000256 	cbz	x22, 80203ae0 <__sfvwrite_r+0xb0>
    80203a9c:	d63f0080 	blr	x4
    80203aa0:	7100001f 	cmp	w0, #0x0
    80203aa4:	5400216d 	b.le	80203ed0 <__sfvwrite_r+0x4a0>
    80203aa8:	f9400b61 	ldr	x1, [x27, #16]
    80203aac:	93407c00 	sxtw	x0, w0
    80203ab0:	8b0002f7 	add	x23, x23, x0
    80203ab4:	cb0002d6 	sub	x22, x22, x0
    80203ab8:	cb000020 	sub	x0, x1, x0
    80203abc:	f9000b60 	str	x0, [x27, #16]
    80203ac0:	b40020c0 	cbz	x0, 80203ed8 <__sfvwrite_r+0x4a8>
    80203ac4:	eb1802df 	cmp	x22, x24
    80203ac8:	aa1703e2 	mov	x2, x23
    80203acc:	f9401a61 	ldr	x1, [x19, #48]
    80203ad0:	9a9892c3 	csel	x3, x22, x24, ls	// ls = plast
    80203ad4:	f9402264 	ldr	x4, [x19, #64]
    80203ad8:	aa1503e0 	mov	x0, x21
    80203adc:	b5fffe16 	cbnz	x22, 80203a9c <__sfvwrite_r+0x6c>
    80203ae0:	a9405a97 	ldp	x23, x22, [x20]
    80203ae4:	91004294 	add	x20, x20, #0x10
    80203ae8:	17ffffe8 	b	80203a88 <__sfvwrite_r+0x58>
    80203aec:	a9046bf9 	stp	x25, x26, [sp, #64]
    80203af0:	36000a65 	tbz	w5, #0, 80203c3c <__sfvwrite_r+0x20c>
    80203af4:	52800018 	mov	w24, #0x0                   	// #0
    80203af8:	52800000 	mov	w0, #0x0                   	// #0
    80203afc:	d280001a 	mov	x26, #0x0                   	// #0
    80203b00:	d2800019 	mov	x25, #0x0                   	// #0
    80203b04:	d503201f 	nop
    80203b08:	b40007f9 	cbz	x25, 80203c04 <__sfvwrite_r+0x1d4>
    80203b0c:	34000860 	cbz	w0, 80203c18 <__sfvwrite_r+0x1e8>
    80203b10:	f9400260 	ldr	x0, [x19]
    80203b14:	93407f17 	sxtw	x23, w24
    80203b18:	f9400e61 	ldr	x1, [x19, #24]
    80203b1c:	eb1902ff 	cmp	x23, x25
    80203b20:	b9400e76 	ldr	w22, [x19, #12]
    80203b24:	9a9992f7 	csel	x23, x23, x25, ls	// ls = plast
    80203b28:	b9402263 	ldr	w3, [x19, #32]
    80203b2c:	eb01001f 	cmp	x0, x1
    80203b30:	0b160076 	add	w22, w3, w22
    80203b34:	7a5682e4 	ccmp	w23, w22, #0x4, hi	// hi = pmore
    80203b38:	540019ac 	b.gt	80203e6c <__sfvwrite_r+0x43c>
    80203b3c:	6b17007f 	cmp	w3, w23
    80203b40:	540017ec 	b.gt	80203e3c <__sfvwrite_r+0x40c>
    80203b44:	f9401a61 	ldr	x1, [x19, #48]
    80203b48:	aa1a03e2 	mov	x2, x26
    80203b4c:	f9402264 	ldr	x4, [x19, #64]
    80203b50:	aa1503e0 	mov	x0, x21
    80203b54:	d63f0080 	blr	x4
    80203b58:	2a0003f6 	mov	w22, w0
    80203b5c:	7100001f 	cmp	w0, #0x0
    80203b60:	540003cd 	b.le	80203bd8 <__sfvwrite_r+0x1a8>
    80203b64:	6b160318 	subs	w24, w24, w22
    80203b68:	52800020 	mov	w0, #0x1                   	// #1
    80203b6c:	540002e0 	b.eq	80203bc8 <__sfvwrite_r+0x198>  // b.none
    80203b70:	f9400b61 	ldr	x1, [x27, #16]
    80203b74:	93407ed6 	sxtw	x22, w22
    80203b78:	8b16035a 	add	x26, x26, x22
    80203b7c:	cb160339 	sub	x25, x25, x22
    80203b80:	cb160021 	sub	x1, x1, x22
    80203b84:	f9000b61 	str	x1, [x27, #16]
    80203b88:	b5fffc01 	cbnz	x1, 80203b08 <__sfvwrite_r+0xd8>
    80203b8c:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203b90:	a94363f7 	ldp	x23, x24, [sp, #48]
    80203b94:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80203b98:	a94573fb 	ldp	x27, x28, [sp, #80]
    80203b9c:	52800000 	mov	w0, #0x0                   	// #0
    80203ba0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80203ba4:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80203ba8:	d65f03c0 	ret
    80203bac:	aa1303e1 	mov	x1, x19
    80203bb0:	aa1503e0 	mov	x0, x21
    80203bb4:	94001beb 	bl	8020ab60 <__swsetup_r>
    80203bb8:	350001a0 	cbnz	w0, 80203bec <__sfvwrite_r+0x1bc>
    80203bbc:	79c02265 	ldrsh	w5, [x19, #16]
    80203bc0:	a90363f7 	stp	x23, x24, [sp, #48]
    80203bc4:	17ffffaa 	b	80203a6c <__sfvwrite_r+0x3c>
    80203bc8:	aa1303e1 	mov	x1, x19
    80203bcc:	aa1503e0 	mov	x0, x21
    80203bd0:	940022e8 	bl	8020c770 <_fflush_r>
    80203bd4:	34fffce0 	cbz	w0, 80203b70 <__sfvwrite_r+0x140>
    80203bd8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80203bdc:	79c02260 	ldrsh	w0, [x19, #16]
    80203be0:	a94363f7 	ldp	x23, x24, [sp, #48]
    80203be4:	321a0000 	orr	w0, w0, #0x40
    80203be8:	79002260 	strh	w0, [x19, #16]
    80203bec:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203bf0:	12800000 	mov	w0, #0xffffffff            	// #-1
    80203bf4:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80203bf8:	a94573fb 	ldp	x27, x28, [sp, #80]
    80203bfc:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80203c00:	d65f03c0 	ret
    80203c04:	f9400699 	ldr	x25, [x20, #8]
    80203c08:	aa1403e0 	mov	x0, x20
    80203c0c:	91004294 	add	x20, x20, #0x10
    80203c10:	b4ffffb9 	cbz	x25, 80203c04 <__sfvwrite_r+0x1d4>
    80203c14:	f940001a 	ldr	x26, [x0]
    80203c18:	aa1903e2 	mov	x2, x25
    80203c1c:	aa1a03e0 	mov	x0, x26
    80203c20:	52800141 	mov	w1, #0xa                   	// #10
    80203c24:	94001b97 	bl	8020aa80 <memchr>
    80203c28:	91000418 	add	x24, x0, #0x1
    80203c2c:	f100001f 	cmp	x0, #0x0
    80203c30:	cb1a0318 	sub	x24, x24, x26
    80203c34:	1a991718 	csinc	w24, w24, w25, ne	// ne = any
    80203c38:	17ffffb6 	b	80203b10 <__sfvwrite_r+0xe0>
    80203c3c:	f9400264 	ldr	x4, [x19]
    80203c40:	d280001c 	mov	x28, #0x0                   	// #0
    80203c44:	b9400e61 	ldr	w1, [x19, #12]
    80203c48:	d280001a 	mov	x26, #0x0                   	// #0
    80203c4c:	d503201f 	nop
    80203c50:	aa0403e0 	mov	x0, x4
    80203c54:	2a0103f8 	mov	w24, w1
    80203c58:	b40003fa 	cbz	x26, 80203cd4 <__sfvwrite_r+0x2a4>
    80203c5c:	36480425 	tbz	w5, #9, 80203ce0 <__sfvwrite_r+0x2b0>
    80203c60:	93407c37 	sxtw	x23, w1
    80203c64:	eb1a02ff 	cmp	x23, x26
    80203c68:	540008c9 	b.ls	80203d80 <__sfvwrite_r+0x350>  // b.plast
    80203c6c:	93407f41 	sxtw	x1, w26
    80203c70:	aa0103f9 	mov	x25, x1
    80203c74:	aa0403e0 	mov	x0, x4
    80203c78:	aa0103f7 	mov	x23, x1
    80203c7c:	2a1a03f8 	mov	w24, w26
    80203c80:	aa1c03e1 	mov	x1, x28
    80203c84:	aa1703e2 	mov	x2, x23
    80203c88:	94001c7e 	bl	8020ae80 <memcpy>
    80203c8c:	f9400264 	ldr	x4, [x19]
    80203c90:	b9400e61 	ldr	w1, [x19, #12]
    80203c94:	8b170084 	add	x4, x4, x23
    80203c98:	f9000264 	str	x4, [x19]
    80203c9c:	4b180021 	sub	w1, w1, w24
    80203ca0:	b9000e61 	str	w1, [x19, #12]
    80203ca4:	f9400b60 	ldr	x0, [x27, #16]
    80203ca8:	8b19039c 	add	x28, x28, x25
    80203cac:	cb19035a 	sub	x26, x26, x25
    80203cb0:	cb190000 	sub	x0, x0, x25
    80203cb4:	f9000b60 	str	x0, [x27, #16]
    80203cb8:	b4fff6a0 	cbz	x0, 80203b8c <__sfvwrite_r+0x15c>
    80203cbc:	f9400264 	ldr	x4, [x19]
    80203cc0:	b9400e61 	ldr	w1, [x19, #12]
    80203cc4:	79c02265 	ldrsh	w5, [x19, #16]
    80203cc8:	aa0403e0 	mov	x0, x4
    80203ccc:	2a0103f8 	mov	w24, w1
    80203cd0:	b5fffc7a 	cbnz	x26, 80203c5c <__sfvwrite_r+0x22c>
    80203cd4:	a9406a9c 	ldp	x28, x26, [x20]
    80203cd8:	91004294 	add	x20, x20, #0x10
    80203cdc:	17ffffdd 	b	80203c50 <__sfvwrite_r+0x220>
    80203ce0:	f9400e60 	ldr	x0, [x19, #24]
    80203ce4:	eb04001f 	cmp	x0, x4
    80203ce8:	54000243 	b.cc	80203d30 <__sfvwrite_r+0x300>  // b.lo, b.ul, b.last
    80203cec:	b9402265 	ldr	w5, [x19, #32]
    80203cf0:	eb25c35f 	cmp	x26, w5, sxtw
    80203cf4:	540001e3 	b.cc	80203d30 <__sfvwrite_r+0x300>  // b.lo, b.ul, b.last
    80203cf8:	b2407be0 	mov	x0, #0x7fffffff            	// #2147483647
    80203cfc:	eb00035f 	cmp	x26, x0
    80203d00:	9a809343 	csel	x3, x26, x0, ls	// ls = plast
    80203d04:	aa1c03e2 	mov	x2, x28
    80203d08:	f9401a61 	ldr	x1, [x19, #48]
    80203d0c:	aa1503e0 	mov	x0, x21
    80203d10:	1ac50c63 	sdiv	w3, w3, w5
    80203d14:	f9402264 	ldr	x4, [x19, #64]
    80203d18:	1b057c63 	mul	w3, w3, w5
    80203d1c:	d63f0080 	blr	x4
    80203d20:	7100001f 	cmp	w0, #0x0
    80203d24:	54fff5ad 	b.le	80203bd8 <__sfvwrite_r+0x1a8>
    80203d28:	93407c19 	sxtw	x25, w0
    80203d2c:	17ffffde 	b	80203ca4 <__sfvwrite_r+0x274>
    80203d30:	93407c23 	sxtw	x3, w1
    80203d34:	aa0403e0 	mov	x0, x4
    80203d38:	eb1a007f 	cmp	x3, x26
    80203d3c:	aa1c03e1 	mov	x1, x28
    80203d40:	9a9a9078 	csel	x24, x3, x26, ls	// ls = plast
    80203d44:	93407f19 	sxtw	x25, w24
    80203d48:	aa1903e2 	mov	x2, x25
    80203d4c:	94001c4d 	bl	8020ae80 <memcpy>
    80203d50:	f9400264 	ldr	x4, [x19]
    80203d54:	b9400e61 	ldr	w1, [x19, #12]
    80203d58:	8b190084 	add	x4, x4, x25
    80203d5c:	f9000264 	str	x4, [x19]
    80203d60:	4b180021 	sub	w1, w1, w24
    80203d64:	b9000e61 	str	w1, [x19, #12]
    80203d68:	35fff9e1 	cbnz	w1, 80203ca4 <__sfvwrite_r+0x274>
    80203d6c:	aa1303e1 	mov	x1, x19
    80203d70:	aa1503e0 	mov	x0, x21
    80203d74:	9400227f 	bl	8020c770 <_fflush_r>
    80203d78:	34fff960 	cbz	w0, 80203ca4 <__sfvwrite_r+0x274>
    80203d7c:	17ffff97 	b	80203bd8 <__sfvwrite_r+0x1a8>
    80203d80:	93407f59 	sxtw	x25, w26
    80203d84:	52809001 	mov	w1, #0x480                 	// #1152
    80203d88:	6a0100bf 	tst	w5, w1
    80203d8c:	54fff7a0 	b.eq	80203c80 <__sfvwrite_r+0x250>  // b.none
    80203d90:	b9402266 	ldr	w6, [x19, #32]
    80203d94:	f9400e61 	ldr	x1, [x19, #24]
    80203d98:	0b0604c6 	add	w6, w6, w6, lsl #1
    80203d9c:	cb010099 	sub	x25, x4, x1
    80203da0:	0b467cc6 	add	w6, w6, w6, lsr #31
    80203da4:	93407f36 	sxtw	x22, w25
    80203da8:	13017cd7 	asr	w23, w6, #1
    80203dac:	910006c0 	add	x0, x22, #0x1
    80203db0:	8b1a0000 	add	x0, x0, x26
    80203db4:	93407ee2 	sxtw	x2, w23
    80203db8:	eb00005f 	cmp	x2, x0
    80203dbc:	54000082 	b.cs	80203dcc <__sfvwrite_r+0x39c>  // b.hs, b.nlast
    80203dc0:	11000726 	add	w6, w25, #0x1
    80203dc4:	0b1a00d7 	add	w23, w6, w26
    80203dc8:	93407ee2 	sxtw	x2, w23
    80203dcc:	36500685 	tbz	w5, #10, 80203e9c <__sfvwrite_r+0x46c>
    80203dd0:	aa0203e1 	mov	x1, x2
    80203dd4:	aa1503e0 	mov	x0, x21
    80203dd8:	9400151a 	bl	80209240 <_malloc_r>
    80203ddc:	aa0003f8 	mov	x24, x0
    80203de0:	b4000840 	cbz	x0, 80203ee8 <__sfvwrite_r+0x4b8>
    80203de4:	f9400e61 	ldr	x1, [x19, #24]
    80203de8:	aa1603e2 	mov	x2, x22
    80203dec:	94001c25 	bl	8020ae80 <memcpy>
    80203df0:	79402260 	ldrh	w0, [x19, #16]
    80203df4:	12809001 	mov	w1, #0xfffffb7f            	// #-1153
    80203df8:	0a010000 	and	w0, w0, w1
    80203dfc:	32190000 	orr	w0, w0, #0x80
    80203e00:	79002260 	strh	w0, [x19, #16]
    80203e04:	8b160300 	add	x0, x24, x22
    80203e08:	4b1902e4 	sub	w4, w23, w25
    80203e0c:	93407f59 	sxtw	x25, w26
    80203e10:	f9000260 	str	x0, [x19]
    80203e14:	b9000e64 	str	w4, [x19, #12]
    80203e18:	aa1903e1 	mov	x1, x25
    80203e1c:	f9000e78 	str	x24, [x19, #24]
    80203e20:	aa0003e4 	mov	x4, x0
    80203e24:	b9002277 	str	w23, [x19, #32]
    80203e28:	2a1a03f8 	mov	w24, w26
    80203e2c:	eb1a033f 	cmp	x25, x26
    80203e30:	54fff208 	b.hi	80203c70 <__sfvwrite_r+0x240>  // b.pmore
    80203e34:	aa1903f7 	mov	x23, x25
    80203e38:	17ffff92 	b	80203c80 <__sfvwrite_r+0x250>
    80203e3c:	93407efc 	sxtw	x28, w23
    80203e40:	aa1a03e1 	mov	x1, x26
    80203e44:	aa1c03e2 	mov	x2, x28
    80203e48:	94001c0e 	bl	8020ae80 <memcpy>
    80203e4c:	f9400260 	ldr	x0, [x19]
    80203e50:	2a1703f6 	mov	w22, w23
    80203e54:	b9400e61 	ldr	w1, [x19, #12]
    80203e58:	8b1c0000 	add	x0, x0, x28
    80203e5c:	f9000260 	str	x0, [x19]
    80203e60:	4b170021 	sub	w1, w1, w23
    80203e64:	b9000e61 	str	w1, [x19, #12]
    80203e68:	17ffff3f 	b	80203b64 <__sfvwrite_r+0x134>
    80203e6c:	93407ed7 	sxtw	x23, w22
    80203e70:	aa1a03e1 	mov	x1, x26
    80203e74:	aa1703e2 	mov	x2, x23
    80203e78:	94001c02 	bl	8020ae80 <memcpy>
    80203e7c:	f9400262 	ldr	x2, [x19]
    80203e80:	aa1303e1 	mov	x1, x19
    80203e84:	aa1503e0 	mov	x0, x21
    80203e88:	8b170042 	add	x2, x2, x23
    80203e8c:	f9000262 	str	x2, [x19]
    80203e90:	94002238 	bl	8020c770 <_fflush_r>
    80203e94:	34ffe680 	cbz	w0, 80203b64 <__sfvwrite_r+0x134>
    80203e98:	17ffff50 	b	80203bd8 <__sfvwrite_r+0x1a8>
    80203e9c:	aa1503e0 	mov	x0, x21
    80203ea0:	940022b4 	bl	8020c970 <_realloc_r>
    80203ea4:	aa0003f8 	mov	x24, x0
    80203ea8:	b5fffae0 	cbnz	x0, 80203e04 <__sfvwrite_r+0x3d4>
    80203eac:	f9400e61 	ldr	x1, [x19, #24]
    80203eb0:	aa1503e0 	mov	x0, x21
    80203eb4:	94002453 	bl	8020d000 <_free_r>
    80203eb8:	79c02260 	ldrsh	w0, [x19, #16]
    80203ebc:	52800181 	mov	w1, #0xc                   	// #12
    80203ec0:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80203ec4:	12187800 	and	w0, w0, #0xffffff7f
    80203ec8:	b90002a1 	str	w1, [x21]
    80203ecc:	17ffff45 	b	80203be0 <__sfvwrite_r+0x1b0>
    80203ed0:	79c02260 	ldrsh	w0, [x19, #16]
    80203ed4:	17ffff43 	b	80203be0 <__sfvwrite_r+0x1b0>
    80203ed8:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203edc:	a94363f7 	ldp	x23, x24, [sp, #48]
    80203ee0:	a94573fb 	ldp	x27, x28, [sp, #80]
    80203ee4:	17ffff2e 	b	80203b9c <__sfvwrite_r+0x16c>
    80203ee8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80203eec:	52800181 	mov	w1, #0xc                   	// #12
    80203ef0:	79c02260 	ldrsh	w0, [x19, #16]
    80203ef4:	b90002a1 	str	w1, [x21]
    80203ef8:	17ffff3a 	b	80203be0 <__sfvwrite_r+0x1b0>
    80203efc:	00000000 	udf	#0

0000000080203f00 <_fwalk_sglue>:
    80203f00:	a9bb7bfd 	stp	x29, x30, [sp, #-80]!
    80203f04:	910003fd 	mov	x29, sp
    80203f08:	a9025bf5 	stp	x21, x22, [sp, #32]
    80203f0c:	aa0203f6 	mov	x22, x2
    80203f10:	52800015 	mov	w21, #0x0                   	// #0
    80203f14:	a90363f7 	stp	x23, x24, [sp, #48]
    80203f18:	aa0003f7 	mov	x23, x0
    80203f1c:	aa0103f8 	mov	x24, x1
    80203f20:	a90153f3 	stp	x19, x20, [sp, #16]
    80203f24:	f90023f9 	str	x25, [sp, #64]
    80203f28:	52801719 	mov	w25, #0xb8                  	// #184
    80203f2c:	d503201f 	nop
    80203f30:	b9400ad4 	ldr	w20, [x22, #8]
    80203f34:	f9400ad3 	ldr	x19, [x22, #16]
    80203f38:	7100029f 	cmp	w20, #0x0
    80203f3c:	5400020d 	b.le	80203f7c <_fwalk_sglue+0x7c>
    80203f40:	9bb94e94 	umaddl	x20, w20, w25, x19
    80203f44:	d503201f 	nop
    80203f48:	79402263 	ldrh	w3, [x19, #16]
    80203f4c:	7100047f 	cmp	w3, #0x1
    80203f50:	54000109 	b.ls	80203f70 <_fwalk_sglue+0x70>  // b.plast
    80203f54:	79c02663 	ldrsh	w3, [x19, #18]
    80203f58:	aa1303e1 	mov	x1, x19
    80203f5c:	aa1703e0 	mov	x0, x23
    80203f60:	3100047f 	cmn	w3, #0x1
    80203f64:	54000060 	b.eq	80203f70 <_fwalk_sglue+0x70>  // b.none
    80203f68:	d63f0300 	blr	x24
    80203f6c:	2a0002b5 	orr	w21, w21, w0
    80203f70:	9102e273 	add	x19, x19, #0xb8
    80203f74:	eb14027f 	cmp	x19, x20
    80203f78:	54fffe81 	b.ne	80203f48 <_fwalk_sglue+0x48>  // b.any
    80203f7c:	f94002d6 	ldr	x22, [x22]
    80203f80:	b5fffd96 	cbnz	x22, 80203f30 <_fwalk_sglue+0x30>
    80203f84:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203f88:	2a1503e0 	mov	w0, w21
    80203f8c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80203f90:	a94363f7 	ldp	x23, x24, [sp, #48]
    80203f94:	f94023f9 	ldr	x25, [sp, #64]
    80203f98:	a8c57bfd 	ldp	x29, x30, [sp], #80
    80203f9c:	d65f03c0 	ret

0000000080203fa0 <_write_r>:
    80203fa0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80203fa4:	910003fd 	mov	x29, sp
    80203fa8:	a90153f3 	stp	x19, x20, [sp, #16]
    80203fac:	d00003f4 	adrp	x20, 80281000 <__sf+0x38>
    80203fb0:	aa0003f3 	mov	x19, x0
    80203fb4:	2a0103e0 	mov	w0, w1
    80203fb8:	aa0203e1 	mov	x1, x2
    80203fbc:	b9044a9f 	str	wzr, [x20, #1096]
    80203fc0:	aa0303e2 	mov	x2, x3
    80203fc4:	97fff23f 	bl	802008c0 <_write>
    80203fc8:	93407c01 	sxtw	x1, w0
    80203fcc:	3100041f 	cmn	w0, #0x1
    80203fd0:	540000a0 	b.eq	80203fe4 <_write_r+0x44>  // b.none
    80203fd4:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203fd8:	aa0103e0 	mov	x0, x1
    80203fdc:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80203fe0:	d65f03c0 	ret
    80203fe4:	b9444a80 	ldr	w0, [x20, #1096]
    80203fe8:	34ffff60 	cbz	w0, 80203fd4 <_write_r+0x34>
    80203fec:	b9000260 	str	w0, [x19]
    80203ff0:	aa0103e0 	mov	x0, x1
    80203ff4:	a94153f3 	ldp	x19, x20, [sp, #16]
    80203ff8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80203ffc:	d65f03c0 	ret

0000000080204000 <_vfprintf_r>:
    80204000:	d10a43ff 	sub	sp, sp, #0x290
    80204004:	a9007bfd 	stp	x29, x30, [sp]
    80204008:	910003fd 	mov	x29, sp
    8020400c:	a9025bf5 	stp	x21, x22, [sp, #32]
    80204010:	aa0103f5 	mov	x21, x1
    80204014:	f9400061 	ldr	x1, [x3]
    80204018:	f9003fe1 	str	x1, [sp, #120]
    8020401c:	f9400461 	ldr	x1, [x3, #8]
    80204020:	f90053e1 	str	x1, [sp, #160]
    80204024:	f9400861 	ldr	x1, [x3, #16]
    80204028:	f90087e1 	str	x1, [sp, #264]
    8020402c:	b9401861 	ldr	w1, [x3, #24]
    80204030:	b90093e1 	str	w1, [sp, #144]
    80204034:	b9401c61 	ldr	w1, [x3, #28]
    80204038:	a90153f3 	stp	x19, x20, [sp, #16]
    8020403c:	aa0303f4 	mov	x20, x3
    80204040:	aa0003f3 	mov	x19, x0
    80204044:	a90363f7 	stp	x23, x24, [sp, #48]
    80204048:	aa0203f7 	mov	x23, x2
    8020404c:	b900f7e1 	str	w1, [sp, #244]
    80204050:	94001a24 	bl	8020a8e0 <_localeconv_r>
    80204054:	f9400000 	ldr	x0, [x0]
    80204058:	f9005be0 	str	x0, [sp, #176]
    8020405c:	97fffe29 	bl	80203900 <strlen>
    80204060:	f90057e0 	str	x0, [sp, #168]
    80204064:	d2800102 	mov	x2, #0x8                   	// #8
    80204068:	9105e3e0 	add	x0, sp, #0x178
    8020406c:	52800001 	mov	w1, #0x0                   	// #0
    80204070:	97fffd94 	bl	802036c0 <memset>
    80204074:	b4000073 	cbz	x19, 80204080 <_vfprintf_r+0x80>
    80204078:	f9402660 	ldr	x0, [x19, #72]
    8020407c:	b400cb40 	cbz	x0, 802059e4 <_vfprintf_r+0x19e4>
    80204080:	b940b2a1 	ldr	w1, [x21, #176]
    80204084:	79c022a0 	ldrsh	w0, [x21, #16]
    80204088:	37000041 	tbnz	w1, #0, 80204090 <_vfprintf_r+0x90>
    8020408c:	3648a2e0 	tbz	w0, #9, 802054e8 <_vfprintf_r+0x14e8>
    80204090:	376800c0 	tbnz	w0, #13, 802040a8 <_vfprintf_r+0xa8>
    80204094:	b940b2a1 	ldr	w1, [x21, #176]
    80204098:	32130000 	orr	w0, w0, #0x2000
    8020409c:	790022a0 	strh	w0, [x21, #16]
    802040a0:	12127821 	and	w1, w1, #0xffffdfff
    802040a4:	b900b2a1 	str	w1, [x21, #176]
    802040a8:	361805e0 	tbz	w0, #3, 80204164 <_vfprintf_r+0x164>
    802040ac:	f9400ea1 	ldr	x1, [x21, #24]
    802040b0:	b40005a1 	cbz	x1, 80204164 <_vfprintf_r+0x164>
    802040b4:	52800341 	mov	w1, #0x1a                  	// #26
    802040b8:	0a010001 	and	w1, w0, w1
    802040bc:	7100283f 	cmp	w1, #0xa
    802040c0:	54000640 	b.eq	80204188 <_vfprintf_r+0x188>  // b.none
    802040c4:	910843f6 	add	x22, sp, #0x210
    802040c8:	6d0627e8 	stp	d8, d9, [sp, #96]
    802040cc:	2f00e408 	movi	d8, #0x0
    802040d0:	d0000074 	adrp	x20, 80212000 <__malloc_av_+0x760>
    802040d4:	aa1703ea 	mov	x10, x23
    802040d8:	91068294 	add	x20, x20, #0x1a0
    802040dc:	a90573fb 	stp	x27, x28, [sp, #80]
    802040e0:	aa1603fc 	mov	x28, x22
    802040e4:	90000060 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    802040e8:	913b3000 	add	x0, x0, #0xecc
    802040ec:	a9046bf9 	stp	x25, x26, [sp, #64]
    802040f0:	b90077ff 	str	wzr, [sp, #116]
    802040f4:	f90043e0 	str	x0, [sp, #128]
    802040f8:	b90097ff 	str	wzr, [sp, #148]
    802040fc:	a90e7fff 	stp	xzr, xzr, [sp, #224]
    80204100:	b900f3ff 	str	wzr, [sp, #240]
    80204104:	a90fffff 	stp	xzr, xzr, [sp, #248]
    80204108:	f900cbf6 	str	x22, [sp, #400]
    8020410c:	b9019bff 	str	wzr, [sp, #408]
    80204110:	f900d3ff 	str	xzr, [sp, #416]
    80204114:	aa0a03f7 	mov	x23, x10
    80204118:	aa0a03f8 	mov	x24, x10
    8020411c:	d503201f 	nop
    80204120:	f9407699 	ldr	x25, [x20, #232]
    80204124:	940019df 	bl	8020a8a0 <__locale_mb_cur_max>
    80204128:	9105e3e4 	add	x4, sp, #0x178
    8020412c:	93407c03 	sxtw	x3, w0
    80204130:	aa1703e2 	mov	x2, x23
    80204134:	9105b3e1 	add	x1, sp, #0x16c
    80204138:	aa1303e0 	mov	x0, x19
    8020413c:	d63f0320 	blr	x25
    80204140:	7100001f 	cmp	w0, #0x0
    80204144:	34000580 	cbz	w0, 802041f4 <_vfprintf_r+0x1f4>
    80204148:	5400048b 	b.lt	802041d8 <_vfprintf_r+0x1d8>  // b.tstop
    8020414c:	b9416fe1 	ldr	w1, [sp, #364]
    80204150:	7100943f 	cmp	w1, #0x25
    80204154:	540039a0 	b.eq	80204888 <_vfprintf_r+0x888>  // b.none
    80204158:	93407c00 	sxtw	x0, w0
    8020415c:	8b0002f7 	add	x23, x23, x0
    80204160:	17fffff0 	b	80204120 <_vfprintf_r+0x120>
    80204164:	aa1503e1 	mov	x1, x21
    80204168:	aa1303e0 	mov	x0, x19
    8020416c:	94001a7d 	bl	8020ab60 <__swsetup_r>
    80204170:	35014ee0 	cbnz	w0, 80206b4c <_vfprintf_r+0x2b4c>
    80204174:	79c022a0 	ldrsh	w0, [x21, #16]
    80204178:	52800341 	mov	w1, #0x1a                  	// #26
    8020417c:	0a010001 	and	w1, w0, w1
    80204180:	7100283f 	cmp	w1, #0xa
    80204184:	54fffa01 	b.ne	802040c4 <_vfprintf_r+0xc4>  // b.any
    80204188:	79c026a1 	ldrsh	w1, [x21, #18]
    8020418c:	37fff9c1 	tbnz	w1, #31, 802040c4 <_vfprintf_r+0xc4>
    80204190:	b940b2a1 	ldr	w1, [x21, #176]
    80204194:	37000041 	tbnz	w1, #0, 8020419c <_vfprintf_r+0x19c>
    80204198:	364918c0 	tbz	w0, #9, 802064b0 <_vfprintf_r+0x24b0>
    8020419c:	ad400680 	ldp	q0, q1, [x20]
    802041a0:	aa1703e2 	mov	x2, x23
    802041a4:	aa1503e1 	mov	x1, x21
    802041a8:	9104c3e3 	add	x3, sp, #0x130
    802041ac:	aa1303e0 	mov	x0, x19
    802041b0:	ad0987e0 	stp	q0, q1, [sp, #304]
    802041b4:	94000c5f 	bl	80207330 <__sbprintf>
    802041b8:	b90077e0 	str	w0, [sp, #116]
    802041bc:	a9407bfd 	ldp	x29, x30, [sp]
    802041c0:	a94153f3 	ldp	x19, x20, [sp, #16]
    802041c4:	a9425bf5 	ldp	x21, x22, [sp, #32]
    802041c8:	a94363f7 	ldp	x23, x24, [sp, #48]
    802041cc:	b94077e0 	ldr	w0, [sp, #116]
    802041d0:	910a43ff 	add	sp, sp, #0x290
    802041d4:	d65f03c0 	ret
    802041d8:	9105e3e0 	add	x0, sp, #0x178
    802041dc:	d2800102 	mov	x2, #0x8                   	// #8
    802041e0:	52800001 	mov	w1, #0x0                   	// #0
    802041e4:	97fffd37 	bl	802036c0 <memset>
    802041e8:	d2800020 	mov	x0, #0x1                   	// #1
    802041ec:	8b0002f7 	add	x23, x23, x0
    802041f0:	17ffffcc 	b	80204120 <_vfprintf_r+0x120>
    802041f4:	2a0003fa 	mov	w26, w0
    802041f8:	cb1802e0 	sub	x0, x23, x24
    802041fc:	aa1803ea 	mov	x10, x24
    80204200:	2a0003fb 	mov	w27, w0
    80204204:	3400e3a0 	cbz	w0, 80205e78 <_vfprintf_r+0x1e78>
    80204208:	f940d3e2 	ldr	x2, [sp, #416]
    8020420c:	93407f61 	sxtw	x1, w27
    80204210:	b9419be0 	ldr	w0, [sp, #408]
    80204214:	8b010042 	add	x2, x2, x1
    80204218:	a900078a 	stp	x10, x1, [x28]
    8020421c:	11000400 	add	w0, w0, #0x1
    80204220:	b9019be0 	str	w0, [sp, #408]
    80204224:	9100439c 	add	x28, x28, #0x10
    80204228:	f900d3e2 	str	x2, [sp, #416]
    8020422c:	71001c1f 	cmp	w0, #0x7
    80204230:	5400452c 	b.gt	80204ad4 <_vfprintf_r+0xad4>
    80204234:	b94077e0 	ldr	w0, [sp, #116]
    80204238:	0b1b0000 	add	w0, w0, w27
    8020423c:	b90077e0 	str	w0, [sp, #116]
    80204240:	3400e1da 	cbz	w26, 80205e78 <_vfprintf_r+0x1e78>
    80204244:	910006ea 	add	x10, x23, #0x1
    80204248:	394006e8 	ldrb	w8, [x23, #1]
    8020424c:	12800007 	mov	w7, #0xffffffff            	// #-1
    80204250:	5280000b 	mov	w11, #0x0                   	// #0
    80204254:	52800009 	mov	w9, #0x0                   	// #0
    80204258:	2a0b03f8 	mov	w24, w11
    8020425c:	2a0903f7 	mov	w23, w9
    80204260:	2a0703f9 	mov	w25, w7
    80204264:	aa0a03fa 	mov	x26, x10
    80204268:	39057fff 	strb	wzr, [sp, #351]
    8020426c:	9100075a 	add	x26, x26, #0x1
    80204270:	51008100 	sub	w0, w8, #0x20
    80204274:	7101681f 	cmp	w0, #0x5a
    80204278:	540000c8 	b.hi	80204290 <_vfprintf_r+0x290>  // b.pmore
    8020427c:	f94043e1 	ldr	x1, [sp, #128]
    80204280:	78605820 	ldrh	w0, [x1, w0, uxtw #1]
    80204284:	10000061 	adr	x1, 80204290 <_vfprintf_r+0x290>
    80204288:	8b20a820 	add	x0, x1, w0, sxth #2
    8020428c:	d61f0000 	br	x0
    80204290:	2a1703e9 	mov	w9, w23
    80204294:	2a1803eb 	mov	w11, w24
    80204298:	aa1a03ea 	mov	x10, x26
    8020429c:	3400dee8 	cbz	w8, 80205e78 <_vfprintf_r+0x1e78>
    802042a0:	5280003a 	mov	w26, #0x1                   	// #1
    802042a4:	9106a3fb 	add	x27, sp, #0x1a8
    802042a8:	2a1a03f7 	mov	w23, w26
    802042ac:	52800001 	mov	w1, #0x0                   	// #0
    802042b0:	d2800019 	mov	x25, #0x0                   	// #0
    802042b4:	52800007 	mov	w7, #0x0                   	// #0
    802042b8:	52800018 	mov	w24, #0x0                   	// #0
    802042bc:	b9008bff 	str	wzr, [sp, #136]
    802042c0:	b9009bff 	str	wzr, [sp, #152]
    802042c4:	39057fff 	strb	wzr, [sp, #351]
    802042c8:	3906a3e8 	strb	w8, [sp, #424]
    802042cc:	d503201f 	nop
    802042d0:	721f0132 	ands	w18, w9, #0x2
    802042d4:	11000b42 	add	w2, w26, #0x2
    802042d8:	f940d3e0 	ldr	x0, [sp, #416]
    802042dc:	1a9a105a 	csel	w26, w2, w26, ne	// ne = any
    802042e0:	5280108e 	mov	w14, #0x84                  	// #132
    802042e4:	6a0e012e 	ands	w14, w9, w14
    802042e8:	54000081 	b.ne	802042f8 <_vfprintf_r+0x2f8>  // b.any
    802042ec:	4b1a0164 	sub	w4, w11, w26
    802042f0:	7100009f 	cmp	w4, #0x0
    802042f4:	54001a6c 	b.gt	80204640 <_vfprintf_r+0x640>
    802042f8:	340001a1 	cbz	w1, 8020432c <_vfprintf_r+0x32c>
    802042fc:	b9419be1 	ldr	w1, [sp, #408]
    80204300:	91057fe2 	add	x2, sp, #0x15f
    80204304:	91000400 	add	x0, x0, #0x1
    80204308:	f9000382 	str	x2, [x28]
    8020430c:	11000421 	add	w1, w1, #0x1
    80204310:	d2800022 	mov	x2, #0x1                   	// #1
    80204314:	f9000782 	str	x2, [x28, #8]
    80204318:	9100439c 	add	x28, x28, #0x10
    8020431c:	b9019be1 	str	w1, [sp, #408]
    80204320:	f900d3e0 	str	x0, [sp, #416]
    80204324:	71001c3f 	cmp	w1, #0x7
    80204328:	54003e4c 	b.gt	80204af0 <_vfprintf_r+0xaf0>
    8020432c:	340001b2 	cbz	w18, 80204360 <_vfprintf_r+0x360>
    80204330:	b9419be1 	ldr	w1, [sp, #408]
    80204334:	910583e2 	add	x2, sp, #0x160
    80204338:	91000800 	add	x0, x0, #0x2
    8020433c:	f9000382 	str	x2, [x28]
    80204340:	11000421 	add	w1, w1, #0x1
    80204344:	d2800042 	mov	x2, #0x2                   	// #2
    80204348:	f9000782 	str	x2, [x28, #8]
    8020434c:	9100439c 	add	x28, x28, #0x10
    80204350:	b9019be1 	str	w1, [sp, #408]
    80204354:	f900d3e0 	str	x0, [sp, #416]
    80204358:	71001c3f 	cmp	w1, #0x7
    8020435c:	5400730c 	b.gt	802051bc <_vfprintf_r+0x11bc>
    80204360:	710201df 	cmp	w14, #0x80
    80204364:	540029e0 	b.eq	802048a0 <_vfprintf_r+0x8a0>  // b.none
    80204368:	4b1700e7 	sub	w7, w7, w23
    8020436c:	710000ff 	cmp	w7, #0x0
    80204370:	5400050c 	b.gt	80204410 <_vfprintf_r+0x410>
    80204374:	37400e29 	tbnz	w9, #8, 80204538 <_vfprintf_r+0x538>
    80204378:	b9419be1 	ldr	w1, [sp, #408]
    8020437c:	93407eec 	sxtw	x12, w23
    80204380:	8b0c0000 	add	x0, x0, x12
    80204384:	a900339b 	stp	x27, x12, [x28]
    80204388:	11000421 	add	w1, w1, #0x1
    8020438c:	b9019be1 	str	w1, [sp, #408]
    80204390:	f900d3e0 	str	x0, [sp, #416]
    80204394:	71001c3f 	cmp	w1, #0x7
    80204398:	5400224c 	b.gt	802047e0 <_vfprintf_r+0x7e0>
    8020439c:	9100439c 	add	x28, x28, #0x10
    802043a0:	36100089 	tbz	w9, #2, 802043b0 <_vfprintf_r+0x3b0>
    802043a4:	4b1a0177 	sub	w23, w11, w26
    802043a8:	710002ff 	cmp	w23, #0x0
    802043ac:	5400730c 	b.gt	8020520c <_vfprintf_r+0x120c>
    802043b0:	b94077e1 	ldr	w1, [sp, #116]
    802043b4:	6b1a017f 	cmp	w11, w26
    802043b8:	1a9aa163 	csel	w3, w11, w26, ge	// ge = tcont
    802043bc:	0b030021 	add	w1, w1, w3
    802043c0:	b90077e1 	str	w1, [sp, #116]
    802043c4:	b5002300 	cbnz	x0, 80204824 <_vfprintf_r+0x824>
    802043c8:	b9019bff 	str	wzr, [sp, #408]
    802043cc:	b40000d9 	cbz	x25, 802043e4 <_vfprintf_r+0x3e4>
    802043d0:	aa1903e1 	mov	x1, x25
    802043d4:	aa1303e0 	mov	x0, x19
    802043d8:	f90047ea 	str	x10, [sp, #136]
    802043dc:	94002309 	bl	8020d000 <_free_r>
    802043e0:	f94047ea 	ldr	x10, [sp, #136]
    802043e4:	aa1603fc 	mov	x28, x22
    802043e8:	17ffff4b 	b	80204114 <_vfprintf_r+0x114>
    802043ec:	5100c100 	sub	w0, w8, #0x30
    802043f0:	52800018 	mov	w24, #0x0                   	// #0
    802043f4:	38401748 	ldrb	w8, [x26], #1
    802043f8:	0b180b0b 	add	w11, w24, w24, lsl #2
    802043fc:	0b0b0418 	add	w24, w0, w11, lsl #1
    80204400:	5100c100 	sub	w0, w8, #0x30
    80204404:	7100241f 	cmp	w0, #0x9
    80204408:	54ffff69 	b.ls	802043f4 <_vfprintf_r+0x3f4>  // b.plast
    8020440c:	17ffff99 	b	80204270 <_vfprintf_r+0x270>
    80204410:	90000064 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    80204414:	b9419be1 	ldr	w1, [sp, #408]
    80204418:	913e4084 	add	x4, x4, #0xf90
    8020441c:	710040ff 	cmp	w7, #0x10
    80204420:	5400058d 	b.le	802044d0 <_vfprintf_r+0x4d0>
    80204424:	aa1c03e2 	mov	x2, x28
    80204428:	d280020d 	mov	x13, #0x10                  	// #16
    8020442c:	aa0a03fc 	mov	x28, x10
    80204430:	b900bbe9 	str	w9, [sp, #184]
    80204434:	b900c3e8 	str	w8, [sp, #192]
    80204438:	b900cbeb 	str	w11, [sp, #200]
    8020443c:	b900d3f7 	str	w23, [sp, #208]
    80204440:	2a0703f7 	mov	w23, w7
    80204444:	b900dbf8 	str	w24, [sp, #216]
    80204448:	aa0403f8 	mov	x24, x4
    8020444c:	14000004 	b	8020445c <_vfprintf_r+0x45c>
    80204450:	510042f7 	sub	w23, w23, #0x10
    80204454:	710042ff 	cmp	w23, #0x10
    80204458:	540002ad 	b.le	802044ac <_vfprintf_r+0x4ac>
    8020445c:	91004000 	add	x0, x0, #0x10
    80204460:	11000421 	add	w1, w1, #0x1
    80204464:	a9003458 	stp	x24, x13, [x2]
    80204468:	91004042 	add	x2, x2, #0x10
    8020446c:	b9019be1 	str	w1, [sp, #408]
    80204470:	f900d3e0 	str	x0, [sp, #416]
    80204474:	71001c3f 	cmp	w1, #0x7
    80204478:	54fffecd 	b.le	80204450 <_vfprintf_r+0x450>
    8020447c:	910643e2 	add	x2, sp, #0x190
    80204480:	aa1503e1 	mov	x1, x21
    80204484:	aa1303e0 	mov	x0, x19
    80204488:	94000c1a 	bl	802074f0 <__sprint_r>
    8020448c:	35001da0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80204490:	510042f7 	sub	w23, w23, #0x10
    80204494:	b9419be1 	ldr	w1, [sp, #408]
    80204498:	f940d3e0 	ldr	x0, [sp, #416]
    8020449c:	aa1603e2 	mov	x2, x22
    802044a0:	d280020d 	mov	x13, #0x10                  	// #16
    802044a4:	710042ff 	cmp	w23, #0x10
    802044a8:	54fffdac 	b.gt	8020445c <_vfprintf_r+0x45c>
    802044ac:	2a1703e7 	mov	w7, w23
    802044b0:	aa1803e4 	mov	x4, x24
    802044b4:	b940bbe9 	ldr	w9, [sp, #184]
    802044b8:	aa1c03ea 	mov	x10, x28
    802044bc:	b940c3e8 	ldr	w8, [sp, #192]
    802044c0:	aa0203fc 	mov	x28, x2
    802044c4:	b940cbeb 	ldr	w11, [sp, #200]
    802044c8:	b940d3f7 	ldr	w23, [sp, #208]
    802044cc:	b940dbf8 	ldr	w24, [sp, #216]
    802044d0:	93407ce7 	sxtw	x7, w7
    802044d4:	11000421 	add	w1, w1, #0x1
    802044d8:	8b070000 	add	x0, x0, x7
    802044dc:	a9001f84 	stp	x4, x7, [x28]
    802044e0:	9100439c 	add	x28, x28, #0x10
    802044e4:	b9019be1 	str	w1, [sp, #408]
    802044e8:	f900d3e0 	str	x0, [sp, #416]
    802044ec:	71001c3f 	cmp	w1, #0x7
    802044f0:	54fff42d 	b.le	80204374 <_vfprintf_r+0x374>
    802044f4:	910643e2 	add	x2, sp, #0x190
    802044f8:	aa1503e1 	mov	x1, x21
    802044fc:	aa1303e0 	mov	x0, x19
    80204500:	b900bbe9 	str	w9, [sp, #184]
    80204504:	b900c3e8 	str	w8, [sp, #192]
    80204508:	b900cbeb 	str	w11, [sp, #200]
    8020450c:	f9006bea 	str	x10, [sp, #208]
    80204510:	94000bf8 	bl	802074f0 <__sprint_r>
    80204514:	35001960 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80204518:	b940bbe9 	ldr	w9, [sp, #184]
    8020451c:	aa1603fc 	mov	x28, x22
    80204520:	f9406bea 	ldr	x10, [sp, #208]
    80204524:	f940d3e0 	ldr	x0, [sp, #416]
    80204528:	b940c3e8 	ldr	w8, [sp, #192]
    8020452c:	b940cbeb 	ldr	w11, [sp, #200]
    80204530:	3647f249 	tbz	w9, #8, 80204378 <_vfprintf_r+0x378>
    80204534:	d503201f 	nop
    80204538:	7101951f 	cmp	w8, #0x65
    8020453c:	5400252d 	b.le	802049e0 <_vfprintf_r+0x9e0>
    80204540:	1e602108 	fcmp	d8, #0.0
    80204544:	54001001 	b.ne	80204744 <_vfprintf_r+0x744>  // b.any
    80204548:	b9419be1 	ldr	w1, [sp, #408]
    8020454c:	91000400 	add	x0, x0, #0x1
    80204550:	90000062 	adrp	x2, 80210000 <_wcsnrtombs_l+0x110>
    80204554:	d2800024 	mov	x4, #0x1                   	// #1
    80204558:	91302042 	add	x2, x2, #0xc08
    8020455c:	11000421 	add	w1, w1, #0x1
    80204560:	a9001382 	stp	x2, x4, [x28]
    80204564:	9100439c 	add	x28, x28, #0x10
    80204568:	b9019be1 	str	w1, [sp, #408]
    8020456c:	f900d3e0 	str	x0, [sp, #416]
    80204570:	71001c3f 	cmp	w1, #0x7
    80204574:	5400b08c 	b.gt	80205b84 <_vfprintf_r+0x1b84>
    80204578:	b94097e2 	ldr	w2, [sp, #148]
    8020457c:	b9416be1 	ldr	w1, [sp, #360]
    80204580:	6b02003f 	cmp	w1, w2
    80204584:	54007baa 	b.ge	802054f8 <_vfprintf_r+0x14f8>  // b.tcont
    80204588:	a94a8fe2 	ldp	x2, x3, [sp, #168]
    8020458c:	a9000b83 	stp	x3, x2, [x28]
    80204590:	b9419be1 	ldr	w1, [sp, #408]
    80204594:	9100439c 	add	x28, x28, #0x10
    80204598:	11000421 	add	w1, w1, #0x1
    8020459c:	b9019be1 	str	w1, [sp, #408]
    802045a0:	8b020000 	add	x0, x0, x2
    802045a4:	f900d3e0 	str	x0, [sp, #416]
    802045a8:	71001c3f 	cmp	w1, #0x7
    802045ac:	540088ec 	b.gt	802056c8 <_vfprintf_r+0x16c8>
    802045b0:	b94097e1 	ldr	w1, [sp, #148]
    802045b4:	51000437 	sub	w23, w1, #0x1
    802045b8:	710002ff 	cmp	w23, #0x0
    802045bc:	54ffef2d 	b.le	802043a0 <_vfprintf_r+0x3a0>
    802045c0:	90000064 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    802045c4:	b9419be1 	ldr	w1, [sp, #408]
    802045c8:	913e4084 	add	x4, x4, #0xf90
    802045cc:	710042ff 	cmp	w23, #0x10
    802045d0:	5400bc4d 	b.le	80205d58 <_vfprintf_r+0x1d58>
    802045d4:	aa1c03e2 	mov	x2, x28
    802045d8:	aa0403f8 	mov	x24, x4
    802045dc:	aa0a03fc 	mov	x28, x10
    802045e0:	d280021b 	mov	x27, #0x10                  	// #16
    802045e4:	b9008be9 	str	w9, [sp, #136]
    802045e8:	b9009beb 	str	w11, [sp, #152]
    802045ec:	14000004 	b	802045fc <_vfprintf_r+0x5fc>
    802045f0:	510042f7 	sub	w23, w23, #0x10
    802045f4:	710042ff 	cmp	w23, #0x10
    802045f8:	5400ba6d 	b.le	80205d44 <_vfprintf_r+0x1d44>
    802045fc:	91004000 	add	x0, x0, #0x10
    80204600:	11000421 	add	w1, w1, #0x1
    80204604:	a9006c58 	stp	x24, x27, [x2]
    80204608:	91004042 	add	x2, x2, #0x10
    8020460c:	b9019be1 	str	w1, [sp, #408]
    80204610:	f900d3e0 	str	x0, [sp, #416]
    80204614:	71001c3f 	cmp	w1, #0x7
    80204618:	54fffecd 	b.le	802045f0 <_vfprintf_r+0x5f0>
    8020461c:	910643e2 	add	x2, sp, #0x190
    80204620:	aa1503e1 	mov	x1, x21
    80204624:	aa1303e0 	mov	x0, x19
    80204628:	94000bb2 	bl	802074f0 <__sprint_r>
    8020462c:	350010a0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80204630:	f940d3e0 	ldr	x0, [sp, #416]
    80204634:	aa1603e2 	mov	x2, x22
    80204638:	b9419be1 	ldr	w1, [sp, #408]
    8020463c:	17ffffed 	b	802045f0 <_vfprintf_r+0x5f0>
    80204640:	9000006d 	adrp	x13, 80210000 <_wcsnrtombs_l+0x110>
    80204644:	b9419be1 	ldr	w1, [sp, #408]
    80204648:	913e81ad 	add	x13, x13, #0xfa0
    8020464c:	7100409f 	cmp	w4, #0x10
    80204650:	5400064d 	b.le	80204718 <_vfprintf_r+0x718>
    80204654:	aa1c03e2 	mov	x2, x28
    80204658:	d280020f 	mov	x15, #0x10                  	// #16
    8020465c:	aa0a03fc 	mov	x28, x10
    80204660:	b900bbf2 	str	w18, [sp, #184]
    80204664:	b900c3ee 	str	w14, [sp, #192]
    80204668:	b900cbe9 	str	w9, [sp, #200]
    8020466c:	b900d3e8 	str	w8, [sp, #208]
    80204670:	b900dbeb 	str	w11, [sp, #216]
    80204674:	b90113e7 	str	w7, [sp, #272]
    80204678:	b9011bf7 	str	w23, [sp, #280]
    8020467c:	2a0403f7 	mov	w23, w4
    80204680:	b90123f8 	str	w24, [sp, #288]
    80204684:	aa0d03f8 	mov	x24, x13
    80204688:	14000004 	b	80204698 <_vfprintf_r+0x698>
    8020468c:	510042f7 	sub	w23, w23, #0x10
    80204690:	710042ff 	cmp	w23, #0x10
    80204694:	540002ad 	b.le	802046e8 <_vfprintf_r+0x6e8>
    80204698:	91004000 	add	x0, x0, #0x10
    8020469c:	11000421 	add	w1, w1, #0x1
    802046a0:	a9003c58 	stp	x24, x15, [x2]
    802046a4:	91004042 	add	x2, x2, #0x10
    802046a8:	b9019be1 	str	w1, [sp, #408]
    802046ac:	f900d3e0 	str	x0, [sp, #416]
    802046b0:	71001c3f 	cmp	w1, #0x7
    802046b4:	54fffecd 	b.le	8020468c <_vfprintf_r+0x68c>
    802046b8:	910643e2 	add	x2, sp, #0x190
    802046bc:	aa1503e1 	mov	x1, x21
    802046c0:	aa1303e0 	mov	x0, x19
    802046c4:	94000b8b 	bl	802074f0 <__sprint_r>
    802046c8:	35000bc0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802046cc:	510042f7 	sub	w23, w23, #0x10
    802046d0:	b9419be1 	ldr	w1, [sp, #408]
    802046d4:	f940d3e0 	ldr	x0, [sp, #416]
    802046d8:	aa1603e2 	mov	x2, x22
    802046dc:	d280020f 	mov	x15, #0x10                  	// #16
    802046e0:	710042ff 	cmp	w23, #0x10
    802046e4:	54fffdac 	b.gt	80204698 <_vfprintf_r+0x698>
    802046e8:	2a1703e4 	mov	w4, w23
    802046ec:	aa1803ed 	mov	x13, x24
    802046f0:	b940bbf2 	ldr	w18, [sp, #184]
    802046f4:	aa1c03ea 	mov	x10, x28
    802046f8:	b940c3ee 	ldr	w14, [sp, #192]
    802046fc:	aa0203fc 	mov	x28, x2
    80204700:	b940cbe9 	ldr	w9, [sp, #200]
    80204704:	b940d3e8 	ldr	w8, [sp, #208]
    80204708:	b940dbeb 	ldr	w11, [sp, #216]
    8020470c:	b94113e7 	ldr	w7, [sp, #272]
    80204710:	b9411bf7 	ldr	w23, [sp, #280]
    80204714:	b94123f8 	ldr	w24, [sp, #288]
    80204718:	93407c84 	sxtw	x4, w4
    8020471c:	11000421 	add	w1, w1, #0x1
    80204720:	8b040000 	add	x0, x0, x4
    80204724:	a900138d 	stp	x13, x4, [x28]
    80204728:	b9019be1 	str	w1, [sp, #408]
    8020472c:	f900d3e0 	str	x0, [sp, #416]
    80204730:	71001c3f 	cmp	w1, #0x7
    80204734:	540092ac 	b.gt	80205988 <_vfprintf_r+0x1988>
    80204738:	39457fe1 	ldrb	w1, [sp, #351]
    8020473c:	9100439c 	add	x28, x28, #0x10
    80204740:	17fffeee 	b	802042f8 <_vfprintf_r+0x2f8>
    80204744:	b9416be2 	ldr	w2, [sp, #360]
    80204748:	7100005f 	cmp	w2, #0x0
    8020474c:	54005e4c 	b.gt	80205314 <_vfprintf_r+0x1314>
    80204750:	b9419be1 	ldr	w1, [sp, #408]
    80204754:	91000400 	add	x0, x0, #0x1
    80204758:	90000064 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    8020475c:	d2800027 	mov	x7, #0x1                   	// #1
    80204760:	91302084 	add	x4, x4, #0xc08
    80204764:	11000421 	add	w1, w1, #0x1
    80204768:	a9001f84 	stp	x4, x7, [x28]
    8020476c:	9100439c 	add	x28, x28, #0x10
    80204770:	b9019be1 	str	w1, [sp, #408]
    80204774:	f900d3e0 	str	x0, [sp, #416]
    80204778:	71001c3f 	cmp	w1, #0x7
    8020477c:	540107cc 	b.gt	80206874 <_vfprintf_r+0x2874>
    80204780:	b94097e1 	ldr	w1, [sp, #148]
    80204784:	2a020021 	orr	w1, w1, w2
    80204788:	3400d761 	cbz	w1, 80206274 <_vfprintf_r+0x2274>
    8020478c:	a94a93e3 	ldp	x3, x4, [sp, #168]
    80204790:	a9000f84 	stp	x4, x3, [x28]
    80204794:	b9419be1 	ldr	w1, [sp, #408]
    80204798:	91004386 	add	x6, x28, #0x10
    8020479c:	11000421 	add	w1, w1, #0x1
    802047a0:	b9019be1 	str	w1, [sp, #408]
    802047a4:	8b000060 	add	x0, x3, x0
    802047a8:	f900d3e0 	str	x0, [sp, #416]
    802047ac:	71001c3f 	cmp	w1, #0x7
    802047b0:	5400d78c 	b.gt	802062a0 <_vfprintf_r+0x22a0>
    802047b4:	37f91e42 	tbnz	w2, #31, 80206b7c <_vfprintf_r+0x2b7c>
    802047b8:	b98097e2 	ldrsw	x2, [sp, #148]
    802047bc:	11000421 	add	w1, w1, #0x1
    802047c0:	a90008db 	stp	x27, x2, [x6]
    802047c4:	910040dc 	add	x28, x6, #0x10
    802047c8:	8b000040 	add	x0, x2, x0
    802047cc:	b9019be1 	str	w1, [sp, #408]
    802047d0:	f900d3e0 	str	x0, [sp, #416]
    802047d4:	71001c3f 	cmp	w1, #0x7
    802047d8:	54ffde4d 	b.le	802043a0 <_vfprintf_r+0x3a0>
    802047dc:	d503201f 	nop
    802047e0:	910643e2 	add	x2, sp, #0x190
    802047e4:	aa1503e1 	mov	x1, x21
    802047e8:	aa1303e0 	mov	x0, x19
    802047ec:	b9008be9 	str	w9, [sp, #136]
    802047f0:	b9009beb 	str	w11, [sp, #152]
    802047f4:	f9005fea 	str	x10, [sp, #184]
    802047f8:	94000b3e 	bl	802074f0 <__sprint_r>
    802047fc:	35000220 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80204800:	f9405fea 	ldr	x10, [sp, #184]
    80204804:	aa1603fc 	mov	x28, x22
    80204808:	f940d3e0 	ldr	x0, [sp, #416]
    8020480c:	b9408be9 	ldr	w9, [sp, #136]
    80204810:	b9409beb 	ldr	w11, [sp, #152]
    80204814:	17fffee3 	b	802043a0 <_vfprintf_r+0x3a0>
    80204818:	39400348 	ldrb	w8, [x26]
    8020481c:	321c02f7 	orr	w23, w23, #0x10
    80204820:	17fffe93 	b	8020426c <_vfprintf_r+0x26c>
    80204824:	910643e2 	add	x2, sp, #0x190
    80204828:	aa1503e1 	mov	x1, x21
    8020482c:	aa1303e0 	mov	x0, x19
    80204830:	f90047ea 	str	x10, [sp, #136]
    80204834:	94000b2f 	bl	802074f0 <__sprint_r>
    80204838:	f94047ea 	ldr	x10, [sp, #136]
    8020483c:	34ffdc60 	cbz	w0, 802043c8 <_vfprintf_r+0x3c8>
    80204840:	aa1903e1 	mov	x1, x25
    80204844:	b4000061 	cbz	x1, 80204850 <_vfprintf_r+0x850>
    80204848:	aa1303e0 	mov	x0, x19
    8020484c:	940021ed 	bl	8020d000 <_free_r>
    80204850:	79c022a0 	ldrsh	w0, [x21, #16]
    80204854:	b940b2a1 	ldr	w1, [x21, #176]
    80204858:	36001781 	tbz	w1, #0, 80204b48 <_vfprintf_r+0xb48>
    8020485c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80204860:	a94573fb 	ldp	x27, x28, [sp, #80]
    80204864:	6d4627e8 	ldp	d8, d9, [sp, #96]
    80204868:	373117e0 	tbnz	w0, #6, 80206b64 <_vfprintf_r+0x2b64>
    8020486c:	a9407bfd 	ldp	x29, x30, [sp]
    80204870:	a94153f3 	ldp	x19, x20, [sp, #16]
    80204874:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80204878:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020487c:	b94077e0 	ldr	w0, [sp, #116]
    80204880:	910a43ff 	add	sp, sp, #0x290
    80204884:	d65f03c0 	ret
    80204888:	2a0003fa 	mov	w26, w0
    8020488c:	cb1802e0 	sub	x0, x23, x24
    80204890:	aa1803ea 	mov	x10, x24
    80204894:	2a0003fb 	mov	w27, w0
    80204898:	34ffcd60 	cbz	w0, 80204244 <_vfprintf_r+0x244>
    8020489c:	17fffe5b 	b	80204208 <_vfprintf_r+0x208>
    802048a0:	4b1a016d 	sub	w13, w11, w26
    802048a4:	710001bf 	cmp	w13, #0x0
    802048a8:	54ffd60d 	b.le	80204368 <_vfprintf_r+0x368>
    802048ac:	90000064 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    802048b0:	b9419be1 	ldr	w1, [sp, #408]
    802048b4:	913e4084 	add	x4, x4, #0xf90
    802048b8:	710041bf 	cmp	w13, #0x10
    802048bc:	540005cd 	b.le	80204974 <_vfprintf_r+0x974>
    802048c0:	aa1c03e2 	mov	x2, x28
    802048c4:	d280020e 	mov	x14, #0x10                  	// #16
    802048c8:	aa0a03fc 	mov	x28, x10
    802048cc:	b900bbe9 	str	w9, [sp, #184]
    802048d0:	b900c3e8 	str	w8, [sp, #192]
    802048d4:	b900cbeb 	str	w11, [sp, #200]
    802048d8:	b900d3e7 	str	w7, [sp, #208]
    802048dc:	b900dbf7 	str	w23, [sp, #216]
    802048e0:	2a0d03f7 	mov	w23, w13
    802048e4:	b90113f8 	str	w24, [sp, #272]
    802048e8:	aa0403f8 	mov	x24, x4
    802048ec:	14000004 	b	802048fc <_vfprintf_r+0x8fc>
    802048f0:	510042f7 	sub	w23, w23, #0x10
    802048f4:	710042ff 	cmp	w23, #0x10
    802048f8:	540002ad 	b.le	8020494c <_vfprintf_r+0x94c>
    802048fc:	91004000 	add	x0, x0, #0x10
    80204900:	11000421 	add	w1, w1, #0x1
    80204904:	a9003858 	stp	x24, x14, [x2]
    80204908:	91004042 	add	x2, x2, #0x10
    8020490c:	b9019be1 	str	w1, [sp, #408]
    80204910:	f900d3e0 	str	x0, [sp, #416]
    80204914:	71001c3f 	cmp	w1, #0x7
    80204918:	54fffecd 	b.le	802048f0 <_vfprintf_r+0x8f0>
    8020491c:	910643e2 	add	x2, sp, #0x190
    80204920:	aa1503e1 	mov	x1, x21
    80204924:	aa1303e0 	mov	x0, x19
    80204928:	94000af2 	bl	802074f0 <__sprint_r>
    8020492c:	35fff8a0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80204930:	510042f7 	sub	w23, w23, #0x10
    80204934:	b9419be1 	ldr	w1, [sp, #408]
    80204938:	f940d3e0 	ldr	x0, [sp, #416]
    8020493c:	aa1603e2 	mov	x2, x22
    80204940:	d280020e 	mov	x14, #0x10                  	// #16
    80204944:	710042ff 	cmp	w23, #0x10
    80204948:	54fffdac 	b.gt	802048fc <_vfprintf_r+0x8fc>
    8020494c:	2a1703ed 	mov	w13, w23
    80204950:	aa1803e4 	mov	x4, x24
    80204954:	b940bbe9 	ldr	w9, [sp, #184]
    80204958:	aa1c03ea 	mov	x10, x28
    8020495c:	b940c3e8 	ldr	w8, [sp, #192]
    80204960:	aa0203fc 	mov	x28, x2
    80204964:	b940cbeb 	ldr	w11, [sp, #200]
    80204968:	b940d3e7 	ldr	w7, [sp, #208]
    8020496c:	b940dbf7 	ldr	w23, [sp, #216]
    80204970:	b94113f8 	ldr	w24, [sp, #272]
    80204974:	93407dad 	sxtw	x13, w13
    80204978:	11000421 	add	w1, w1, #0x1
    8020497c:	8b0d0000 	add	x0, x0, x13
    80204980:	a9003784 	stp	x4, x13, [x28]
    80204984:	9100439c 	add	x28, x28, #0x10
    80204988:	b9019be1 	str	w1, [sp, #408]
    8020498c:	f900d3e0 	str	x0, [sp, #416]
    80204990:	71001c3f 	cmp	w1, #0x7
    80204994:	54ffcead 	b.le	80204368 <_vfprintf_r+0x368>
    80204998:	910643e2 	add	x2, sp, #0x190
    8020499c:	aa1503e1 	mov	x1, x21
    802049a0:	aa1303e0 	mov	x0, x19
    802049a4:	b900bbe9 	str	w9, [sp, #184]
    802049a8:	b900c3e8 	str	w8, [sp, #192]
    802049ac:	b900cbeb 	str	w11, [sp, #200]
    802049b0:	b900d3e7 	str	w7, [sp, #208]
    802049b4:	f9006fea 	str	x10, [sp, #216]
    802049b8:	94000ace 	bl	802074f0 <__sprint_r>
    802049bc:	35fff420 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802049c0:	f9406fea 	ldr	x10, [sp, #216]
    802049c4:	aa1603fc 	mov	x28, x22
    802049c8:	f940d3e0 	ldr	x0, [sp, #416]
    802049cc:	b940bbe9 	ldr	w9, [sp, #184]
    802049d0:	b940c3e8 	ldr	w8, [sp, #192]
    802049d4:	b940cbeb 	ldr	w11, [sp, #200]
    802049d8:	b940d3e7 	ldr	w7, [sp, #208]
    802049dc:	17fffe63 	b	80204368 <_vfprintf_r+0x368>
    802049e0:	b9419be1 	ldr	w1, [sp, #408]
    802049e4:	91000400 	add	x0, x0, #0x1
    802049e8:	b94097e3 	ldr	w3, [sp, #148]
    802049ec:	91004382 	add	x2, x28, #0x10
    802049f0:	11000421 	add	w1, w1, #0x1
    802049f4:	7100047f 	cmp	w3, #0x1
    802049f8:	5400118d 	b.le	80204c28 <_vfprintf_r+0xc28>
    802049fc:	d2800024 	mov	x4, #0x1                   	// #1
    80204a00:	a900139b 	stp	x27, x4, [x28]
    80204a04:	b9019be1 	str	w1, [sp, #408]
    80204a08:	f900d3e0 	str	x0, [sp, #416]
    80204a0c:	71001c3f 	cmp	w1, #0x7
    80204a10:	5400528c 	b.gt	80205460 <_vfprintf_r+0x1460>
    80204a14:	a94a93e3 	ldp	x3, x4, [sp, #168]
    80204a18:	11000421 	add	w1, w1, #0x1
    80204a1c:	a9000c44 	stp	x4, x3, [x2]
    80204a20:	91004042 	add	x2, x2, #0x10
    80204a24:	b9019be1 	str	w1, [sp, #408]
    80204a28:	8b030000 	add	x0, x0, x3
    80204a2c:	f900d3e0 	str	x0, [sp, #416]
    80204a30:	71001c3f 	cmp	w1, #0x7
    80204a34:	5400534c 	b.gt	8020549c <_vfprintf_r+0x149c>
    80204a38:	1e602108 	fcmp	d8, #0.0
    80204a3c:	b94097e3 	ldr	w3, [sp, #148]
    80204a40:	51000477 	sub	w23, w3, #0x1
    80204a44:	540011e0 	b.eq	80204c80 <_vfprintf_r+0xc80>  // b.none
    80204a48:	93407ef7 	sxtw	x23, w23
    80204a4c:	11000421 	add	w1, w1, #0x1
    80204a50:	8b170000 	add	x0, x0, x23
    80204a54:	b9019be1 	str	w1, [sp, #408]
    80204a58:	f900d3e0 	str	x0, [sp, #416]
    80204a5c:	91000765 	add	x5, x27, #0x1
    80204a60:	f9000045 	str	x5, [x2]
    80204a64:	f9000457 	str	x23, [x2, #8]
    80204a68:	71001c3f 	cmp	w1, #0x7
    80204a6c:	5400610c 	b.gt	8020568c <_vfprintf_r+0x168c>
    80204a70:	91004042 	add	x2, x2, #0x10
    80204a74:	b980f3e4 	ldrsw	x4, [sp, #240]
    80204a78:	11000421 	add	w1, w1, #0x1
    80204a7c:	9105c3e5 	add	x5, sp, #0x170
    80204a80:	a9001045 	stp	x5, x4, [x2]
    80204a84:	8b000080 	add	x0, x4, x0
    80204a88:	b9019be1 	str	w1, [sp, #408]
    80204a8c:	9100405c 	add	x28, x2, #0x10
    80204a90:	f900d3e0 	str	x0, [sp, #416]
    80204a94:	71001c3f 	cmp	w1, #0x7
    80204a98:	54ffc84d 	b.le	802043a0 <_vfprintf_r+0x3a0>
    80204a9c:	910643e2 	add	x2, sp, #0x190
    80204aa0:	aa1503e1 	mov	x1, x21
    80204aa4:	aa1303e0 	mov	x0, x19
    80204aa8:	b9008be9 	str	w9, [sp, #136]
    80204aac:	b9009beb 	str	w11, [sp, #152]
    80204ab0:	f9005fea 	str	x10, [sp, #184]
    80204ab4:	94000a8f 	bl	802074f0 <__sprint_r>
    80204ab8:	35ffec40 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80204abc:	f9405fea 	ldr	x10, [sp, #184]
    80204ac0:	aa1603fc 	mov	x28, x22
    80204ac4:	f940d3e0 	ldr	x0, [sp, #416]
    80204ac8:	b9408be9 	ldr	w9, [sp, #136]
    80204acc:	b9409beb 	ldr	w11, [sp, #152]
    80204ad0:	17fffe34 	b	802043a0 <_vfprintf_r+0x3a0>
    80204ad4:	910643e2 	add	x2, sp, #0x190
    80204ad8:	aa1503e1 	mov	x1, x21
    80204adc:	aa1303e0 	mov	x0, x19
    80204ae0:	94000a84 	bl	802074f0 <__sprint_r>
    80204ae4:	35ffeb60 	cbnz	w0, 80204850 <_vfprintf_r+0x850>
    80204ae8:	aa1603fc 	mov	x28, x22
    80204aec:	17fffdd2 	b	80204234 <_vfprintf_r+0x234>
    80204af0:	910643e2 	add	x2, sp, #0x190
    80204af4:	aa1503e1 	mov	x1, x21
    80204af8:	aa1303e0 	mov	x0, x19
    80204afc:	b900bbf2 	str	w18, [sp, #184]
    80204b00:	b900c3ee 	str	w14, [sp, #192]
    80204b04:	b900cbe9 	str	w9, [sp, #200]
    80204b08:	b900d3e8 	str	w8, [sp, #208]
    80204b0c:	b900dbeb 	str	w11, [sp, #216]
    80204b10:	b90113e7 	str	w7, [sp, #272]
    80204b14:	f9008fea 	str	x10, [sp, #280]
    80204b18:	94000a76 	bl	802074f0 <__sprint_r>
    80204b1c:	35ffe920 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80204b20:	f9408fea 	ldr	x10, [sp, #280]
    80204b24:	aa1603fc 	mov	x28, x22
    80204b28:	f940d3e0 	ldr	x0, [sp, #416]
    80204b2c:	b940bbf2 	ldr	w18, [sp, #184]
    80204b30:	b940c3ee 	ldr	w14, [sp, #192]
    80204b34:	b940cbe9 	ldr	w9, [sp, #200]
    80204b38:	b940d3e8 	ldr	w8, [sp, #208]
    80204b3c:	b940dbeb 	ldr	w11, [sp, #216]
    80204b40:	b94113e7 	ldr	w7, [sp, #272]
    80204b44:	17fffdfa 	b	8020432c <_vfprintf_r+0x32c>
    80204b48:	374fe8a0 	tbnz	w0, #9, 8020485c <_vfprintf_r+0x85c>
    80204b4c:	f94052a0 	ldr	x0, [x21, #160]
    80204b50:	9400142c 	bl	80209c00 <__retarget_lock_release_recursive>
    80204b54:	79c022a0 	ldrsh	w0, [x21, #16]
    80204b58:	17ffff41 	b	8020485c <_vfprintf_r+0x85c>
    80204b5c:	b940f7e0 	ldr	w0, [sp, #244]
    80204b60:	2a1703e9 	mov	w9, w23
    80204b64:	2a1803eb 	mov	w11, w24
    80204b68:	2a1903e7 	mov	w7, w25
    80204b6c:	aa1a03ea 	mov	x10, x26
    80204b70:	36184c89 	tbz	w9, #3, 80205500 <_vfprintf_r+0x1500>
    80204b74:	37f8d200 	tbnz	w0, #31, 802065b4 <_vfprintf_r+0x25b4>
    80204b78:	f9403fe0 	ldr	x0, [sp, #120]
    80204b7c:	91003c00 	add	x0, x0, #0xf
    80204b80:	927cec00 	and	x0, x0, #0xfffffffffffffff0
    80204b84:	91004001 	add	x1, x0, #0x10
    80204b88:	f9003fe1 	str	x1, [sp, #120]
    80204b8c:	3dc00000 	ldr	q0, [x0]
    80204b90:	b9008be9 	str	w9, [sp, #136]
    80204b94:	b9009be8 	str	w8, [sp, #152]
    80204b98:	b900bbeb 	str	w11, [sp, #184]
    80204b9c:	b900c3e7 	str	w7, [sp, #192]
    80204ba0:	f90067ea 	str	x10, [sp, #200]
    80204ba4:	94002ee7 	bl	80210740 <__trunctfdf2>
    80204ba8:	f94067ea 	ldr	x10, [sp, #200]
    80204bac:	1e604008 	fmov	d8, d0
    80204bb0:	b9408be9 	ldr	w9, [sp, #136]
    80204bb4:	b9409be8 	ldr	w8, [sp, #152]
    80204bb8:	b940bbeb 	ldr	w11, [sp, #184]
    80204bbc:	b940c3e7 	ldr	w7, [sp, #192]
    80204bc0:	1e60c100 	fabs	d0, d8
    80204bc4:	92f00200 	mov	x0, #0x7fefffffffffffff    	// #9218868437227405311
    80204bc8:	9e670001 	fmov	d1, x0
    80204bcc:	1e612000 	fcmp	d0, d1
    80204bd0:	5400710d 	b.le	802059f0 <_vfprintf_r+0x19f0>
    80204bd4:	1e602118 	fcmpe	d8, #0.0
    80204bd8:	5400ce64 	b.mi	802065a4 <_vfprintf_r+0x25a4>  // b.first
    80204bdc:	39457fe1 	ldrb	w1, [sp, #351]
    80204be0:	90000060 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    80204be4:	90000065 	adrp	x5, 80210000 <_wcsnrtombs_l+0x110>
    80204be8:	71011d1f 	cmp	w8, #0x47
    80204bec:	912ec000 	add	x0, x0, #0xbb0
    80204bf0:	912ee0a5 	add	x5, x5, #0xbb8
    80204bf4:	b9008bff 	str	wzr, [sp, #136]
    80204bf8:	5280007a 	mov	w26, #0x3                   	// #3
    80204bfc:	b9009bff 	str	wzr, [sp, #152]
    80204c00:	12187929 	and	w9, w9, #0xffffff7f
    80204c04:	9a80c0bb 	csel	x27, x5, x0, gt
    80204c08:	2a1a03f7 	mov	w23, w26
    80204c0c:	d2800019 	mov	x25, #0x0                   	// #0
    80204c10:	52800007 	mov	w7, #0x0                   	// #0
    80204c14:	52800018 	mov	w24, #0x0                   	// #0
    80204c18:	34ffb5c1 	cbz	w1, 802042d0 <_vfprintf_r+0x2d0>
    80204c1c:	d503201f 	nop
    80204c20:	1100075a 	add	w26, w26, #0x1
    80204c24:	17fffdab 	b	802042d0 <_vfprintf_r+0x2d0>
    80204c28:	3707eea9 	tbnz	w9, #0, 802049fc <_vfprintf_r+0x9fc>
    80204c2c:	d2800024 	mov	x4, #0x1                   	// #1
    80204c30:	a900139b 	stp	x27, x4, [x28]
    80204c34:	b9019be1 	str	w1, [sp, #408]
    80204c38:	f900d3e0 	str	x0, [sp, #416]
    80204c3c:	71001c3f 	cmp	w1, #0x7
    80204c40:	54fff1ad 	b.le	80204a74 <_vfprintf_r+0xa74>
    80204c44:	910643e2 	add	x2, sp, #0x190
    80204c48:	aa1503e1 	mov	x1, x21
    80204c4c:	aa1303e0 	mov	x0, x19
    80204c50:	b9008be9 	str	w9, [sp, #136]
    80204c54:	b9009beb 	str	w11, [sp, #152]
    80204c58:	f9005fea 	str	x10, [sp, #184]
    80204c5c:	94000a25 	bl	802074f0 <__sprint_r>
    80204c60:	35ffdf00 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80204c64:	f9405fea 	ldr	x10, [sp, #184]
    80204c68:	aa1603e2 	mov	x2, x22
    80204c6c:	f940d3e0 	ldr	x0, [sp, #416]
    80204c70:	b9408be9 	ldr	w9, [sp, #136]
    80204c74:	b9409beb 	ldr	w11, [sp, #152]
    80204c78:	b9419be1 	ldr	w1, [sp, #408]
    80204c7c:	17ffff7e 	b	80204a74 <_vfprintf_r+0xa74>
    80204c80:	b94097e3 	ldr	w3, [sp, #148]
    80204c84:	7100047f 	cmp	w3, #0x1
    80204c88:	54ffef6d 	b.le	80204a74 <_vfprintf_r+0xa74>
    80204c8c:	90000064 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    80204c90:	913e4084 	add	x4, x4, #0xf90
    80204c94:	7100447f 	cmp	w3, #0x11
    80204c98:	54004e8d 	b.le	80205668 <_vfprintf_r+0x1668>
    80204c9c:	2a0b03fc 	mov	w28, w11
    80204ca0:	aa0403f8 	mov	x24, x4
    80204ca4:	d280021b 	mov	x27, #0x10                  	// #16
    80204ca8:	b9008be9 	str	w9, [sp, #136]
    80204cac:	f9004fea 	str	x10, [sp, #152]
    80204cb0:	14000004 	b	80204cc0 <_vfprintf_r+0xcc0>
    80204cb4:	510042f7 	sub	w23, w23, #0x10
    80204cb8:	710042ff 	cmp	w23, #0x10
    80204cbc:	54004ced 	b.le	80205658 <_vfprintf_r+0x1658>
    80204cc0:	91004000 	add	x0, x0, #0x10
    80204cc4:	11000421 	add	w1, w1, #0x1
    80204cc8:	a9006c58 	stp	x24, x27, [x2]
    80204ccc:	91004042 	add	x2, x2, #0x10
    80204cd0:	b9019be1 	str	w1, [sp, #408]
    80204cd4:	f900d3e0 	str	x0, [sp, #416]
    80204cd8:	71001c3f 	cmp	w1, #0x7
    80204cdc:	54fffecd 	b.le	80204cb4 <_vfprintf_r+0xcb4>
    80204ce0:	910643e2 	add	x2, sp, #0x190
    80204ce4:	aa1503e1 	mov	x1, x21
    80204ce8:	aa1303e0 	mov	x0, x19
    80204cec:	94000a01 	bl	802074f0 <__sprint_r>
    80204cf0:	35ffda80 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80204cf4:	f940d3e0 	ldr	x0, [sp, #416]
    80204cf8:	aa1603e2 	mov	x2, x22
    80204cfc:	b9419be1 	ldr	w1, [sp, #408]
    80204d00:	17ffffed 	b	80204cb4 <_vfprintf_r+0xcb4>
    80204d04:	2a1703e9 	mov	w9, w23
    80204d08:	2a1803eb 	mov	w11, w24
    80204d0c:	aa1a03ea 	mov	x10, x26
    80204d10:	71010d1f 	cmp	w8, #0x43
    80204d14:	540054e0 	b.eq	802057b0 <_vfprintf_r+0x17b0>  // b.none
    80204d18:	372054c9 	tbnz	w9, #4, 802057b0 <_vfprintf_r+0x17b0>
    80204d1c:	b94093e0 	ldr	w0, [sp, #144]
    80204d20:	37f8e1e0 	tbnz	w0, #31, 8020695c <_vfprintf_r+0x295c>
    80204d24:	f9403fe0 	ldr	x0, [sp, #120]
    80204d28:	91002c01 	add	x1, x0, #0xb
    80204d2c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204d30:	f9003fe1 	str	x1, [sp, #120]
    80204d34:	b9400000 	ldr	w0, [x0]
    80204d38:	5280003a 	mov	w26, #0x1                   	// #1
    80204d3c:	9106a3f8 	add	x24, sp, #0x1a8
    80204d40:	2a1a03f7 	mov	w23, w26
    80204d44:	3906a3e0 	strb	w0, [sp, #424]
    80204d48:	aa1803fb 	mov	x27, x24
    80204d4c:	52800001 	mov	w1, #0x0                   	// #0
    80204d50:	d2800019 	mov	x25, #0x0                   	// #0
    80204d54:	52800007 	mov	w7, #0x0                   	// #0
    80204d58:	52800018 	mov	w24, #0x0                   	// #0
    80204d5c:	b9008bff 	str	wzr, [sp, #136]
    80204d60:	b9009bff 	str	wzr, [sp, #152]
    80204d64:	39057fff 	strb	wzr, [sp, #351]
    80204d68:	17fffd5a 	b	802042d0 <_vfprintf_r+0x2d0>
    80204d6c:	b94093e0 	ldr	w0, [sp, #144]
    80204d70:	2a1703e9 	mov	w9, w23
    80204d74:	2a1803eb 	mov	w11, w24
    80204d78:	2a1903e7 	mov	w7, w25
    80204d7c:	aa1a03ea 	mov	x10, x26
    80204d80:	37f84460 	tbnz	w0, #31, 8020560c <_vfprintf_r+0x160c>
    80204d84:	f9403fe0 	ldr	x0, [sp, #120]
    80204d88:	91003c01 	add	x1, x0, #0xf
    80204d8c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204d90:	f9003fe1 	str	x1, [sp, #120]
    80204d94:	f940001b 	ldr	x27, [x0]
    80204d98:	39057fff 	strb	wzr, [sp, #351]
    80204d9c:	b400841b 	cbz	x27, 80205e1c <_vfprintf_r+0x1e1c>
    80204da0:	71014d1f 	cmp	w8, #0x53
    80204da4:	540070c0 	b.eq	80205bbc <_vfprintf_r+0x1bbc>  // b.none
    80204da8:	121c0138 	and	w24, w9, #0x10
    80204dac:	37207089 	tbnz	w9, #4, 80205bbc <_vfprintf_r+0x1bbc>
    80204db0:	37f8b247 	tbnz	w7, #31, 802063f8 <_vfprintf_r+0x23f8>
    80204db4:	93407ce2 	sxtw	x2, w7
    80204db8:	aa1b03e0 	mov	x0, x27
    80204dbc:	52800001 	mov	w1, #0x0                   	// #0
    80204dc0:	b9008be7 	str	w7, [sp, #136]
    80204dc4:	b9009be9 	str	w9, [sp, #152]
    80204dc8:	b900bbeb 	str	w11, [sp, #184]
    80204dcc:	f90063ea 	str	x10, [sp, #192]
    80204dd0:	9400172c 	bl	8020aa80 <memchr>
    80204dd4:	f94063ea 	ldr	x10, [sp, #192]
    80204dd8:	aa0003f9 	mov	x25, x0
    80204ddc:	b9408be7 	ldr	w7, [sp, #136]
    80204de0:	b9409be9 	ldr	w9, [sp, #152]
    80204de4:	b940bbeb 	ldr	w11, [sp, #184]
    80204de8:	b4011040 	cbz	x0, 80206ff0 <_vfprintf_r+0x2ff0>
    80204dec:	39457fe1 	ldrb	w1, [sp, #351]
    80204df0:	cb1b0003 	sub	x3, x0, x27
    80204df4:	b9008bff 	str	wzr, [sp, #136]
    80204df8:	7100007f 	cmp	w3, #0x0
    80204dfc:	b9009bff 	str	wzr, [sp, #152]
    80204e00:	2a0303f7 	mov	w23, w3
    80204e04:	1a9fa07a 	csel	w26, w3, wzr, ge	// ge = tcont
    80204e08:	52800007 	mov	w7, #0x0                   	// #0
    80204e0c:	d2800019 	mov	x25, #0x0                   	// #0
    80204e10:	52800e68 	mov	w8, #0x73                  	// #115
    80204e14:	34ffa5e1 	cbz	w1, 802042d0 <_vfprintf_r+0x2d0>
    80204e18:	17ffff82 	b	80204c20 <_vfprintf_r+0xc20>
    80204e1c:	4b1803f8 	neg	w24, w24
    80204e20:	f9003fe0 	str	x0, [sp, #120]
    80204e24:	39400348 	ldrb	w8, [x26]
    80204e28:	321e02f7 	orr	w23, w23, #0x4
    80204e2c:	17fffd10 	b	8020426c <_vfprintf_r+0x26c>
    80204e30:	aa1a03e1 	mov	x1, x26
    80204e34:	38401428 	ldrb	w8, [x1], #1
    80204e38:	7100a91f 	cmp	w8, #0x2a
    80204e3c:	54011cc0 	b.eq	802071d4 <_vfprintf_r+0x31d4>  // b.none
    80204e40:	5100c100 	sub	w0, w8, #0x30
    80204e44:	aa0103fa 	mov	x26, x1
    80204e48:	52800007 	mov	w7, #0x0                   	// #0
    80204e4c:	52800019 	mov	w25, #0x0                   	// #0
    80204e50:	7100241f 	cmp	w0, #0x9
    80204e54:	54ffa0e8 	b.hi	80204270 <_vfprintf_r+0x270>  // b.pmore
    80204e58:	38401428 	ldrb	w8, [x1], #1
    80204e5c:	0b0708e7 	add	w7, w7, w7, lsl #2
    80204e60:	0b070407 	add	w7, w0, w7, lsl #1
    80204e64:	5100c100 	sub	w0, w8, #0x30
    80204e68:	7100241f 	cmp	w0, #0x9
    80204e6c:	54ffff69 	b.ls	80204e58 <_vfprintf_r+0xe58>  // b.plast
    80204e70:	710000ff 	cmp	w7, #0x0
    80204e74:	aa0103fa 	mov	x26, x1
    80204e78:	5a9fa0f9 	csinv	w25, w7, wzr, ge	// ge = tcont
    80204e7c:	17fffcfd 	b	80204270 <_vfprintf_r+0x270>
    80204e80:	52800560 	mov	w0, #0x2b                  	// #43
    80204e84:	39400348 	ldrb	w8, [x26]
    80204e88:	39057fe0 	strb	w0, [sp, #351]
    80204e8c:	17fffcf8 	b	8020426c <_vfprintf_r+0x26c>
    80204e90:	b94093e0 	ldr	w0, [sp, #144]
    80204e94:	37f83d00 	tbnz	w0, #31, 80205634 <_vfprintf_r+0x1634>
    80204e98:	f9403fe0 	ldr	x0, [sp, #120]
    80204e9c:	91002c00 	add	x0, x0, #0xb
    80204ea0:	927df000 	and	x0, x0, #0xfffffffffffffff8
    80204ea4:	f9403fe1 	ldr	x1, [sp, #120]
    80204ea8:	b9400038 	ldr	w24, [x1]
    80204eac:	37fffb98 	tbnz	w24, #31, 80204e1c <_vfprintf_r+0xe1c>
    80204eb0:	39400348 	ldrb	w8, [x26]
    80204eb4:	f9003fe0 	str	x0, [sp, #120]
    80204eb8:	17fffced 	b	8020426c <_vfprintf_r+0x26c>
    80204ebc:	aa1303e0 	mov	x0, x19
    80204ec0:	94001688 	bl	8020a8e0 <_localeconv_r>
    80204ec4:	f9400400 	ldr	x0, [x0, #8]
    80204ec8:	f90077e0 	str	x0, [sp, #232]
    80204ecc:	97fffa8d 	bl	80203900 <strlen>
    80204ed0:	aa0003e1 	mov	x1, x0
    80204ed4:	aa0103fb 	mov	x27, x1
    80204ed8:	aa1303e0 	mov	x0, x19
    80204edc:	f90083e1 	str	x1, [sp, #256]
    80204ee0:	94001680 	bl	8020a8e0 <_localeconv_r>
    80204ee4:	f9400800 	ldr	x0, [x0, #16]
    80204ee8:	f9007fe0 	str	x0, [sp, #248]
    80204eec:	f100037f 	cmp	x27, #0x0
    80204ef0:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
    80204ef4:	54003420 	b.eq	80205578 <_vfprintf_r+0x1578>  // b.none
    80204ef8:	39400001 	ldrb	w1, [x0]
    80204efc:	321602e0 	orr	w0, w23, #0x400
    80204f00:	39400348 	ldrb	w8, [x26]
    80204f04:	7100003f 	cmp	w1, #0x0
    80204f08:	1a971017 	csel	w23, w0, w23, ne	// ne = any
    80204f0c:	17fffcd8 	b	8020426c <_vfprintf_r+0x26c>
    80204f10:	39400348 	ldrb	w8, [x26]
    80204f14:	320002f7 	orr	w23, w23, #0x1
    80204f18:	17fffcd5 	b	8020426c <_vfprintf_r+0x26c>
    80204f1c:	39457fe0 	ldrb	w0, [sp, #351]
    80204f20:	39400348 	ldrb	w8, [x26]
    80204f24:	35ff9a40 	cbnz	w0, 8020426c <_vfprintf_r+0x26c>
    80204f28:	52800400 	mov	w0, #0x20                  	// #32
    80204f2c:	39057fe0 	strb	w0, [sp, #351]
    80204f30:	17fffccf 	b	8020426c <_vfprintf_r+0x26c>
    80204f34:	2a1803eb 	mov	w11, w24
    80204f38:	2a1903e7 	mov	w7, w25
    80204f3c:	aa1a03ea 	mov	x10, x26
    80204f40:	321c02e9 	orr	w9, w23, #0x10
    80204f44:	b94093e0 	ldr	w0, [sp, #144]
    80204f48:	37280049 	tbnz	w9, #5, 80204f50 <_vfprintf_r+0xf50>
    80204f4c:	36203329 	tbz	w9, #4, 802055b0 <_vfprintf_r+0x15b0>
    80204f50:	37f84f40 	tbnz	w0, #31, 80205938 <_vfprintf_r+0x1938>
    80204f54:	f9403fe0 	ldr	x0, [sp, #120]
    80204f58:	91003c01 	add	x1, x0, #0xf
    80204f5c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80204f60:	f9003fe1 	str	x1, [sp, #120]
    80204f64:	f9400000 	ldr	x0, [x0]
    80204f68:	1215793a 	and	w26, w9, #0xfffffbff
    80204f6c:	52800001 	mov	w1, #0x0                   	// #0
    80204f70:	52800002 	mov	w2, #0x0                   	// #0
    80204f74:	39057fe2 	strb	w2, [sp, #351]
    80204f78:	37f80e27 	tbnz	w7, #31, 8020513c <_vfprintf_r+0x113c>
    80204f7c:	f100001f 	cmp	x0, #0x0
    80204f80:	12187b49 	and	w9, w26, #0xffffff7f
    80204f84:	7a4008e0 	ccmp	w7, #0x0, #0x0, eq	// eq = none
    80204f88:	54000d81 	b.ne	80205138 <_vfprintf_r+0x1138>  // b.any
    80204f8c:	35000c81 	cbnz	w1, 8020511c <_vfprintf_r+0x111c>
    80204f90:	12000357 	and	w23, w26, #0x1
    80204f94:	36001bba 	tbz	w26, #0, 80205308 <_vfprintf_r+0x1308>
    80204f98:	91082ffb 	add	x27, sp, #0x20b
    80204f9c:	52800600 	mov	w0, #0x30                  	// #48
    80204fa0:	52800007 	mov	w7, #0x0                   	// #0
    80204fa4:	39082fe0 	strb	w0, [sp, #523]
    80204fa8:	39457fe1 	ldrb	w1, [sp, #351]
    80204fac:	6b1700ff 	cmp	w7, w23
    80204fb0:	b9008bff 	str	wzr, [sp, #136]
    80204fb4:	1a97a0fa 	csel	w26, w7, w23, ge	// ge = tcont
    80204fb8:	b9009bff 	str	wzr, [sp, #152]
    80204fbc:	d2800019 	mov	x25, #0x0                   	// #0
    80204fc0:	52800018 	mov	w24, #0x0                   	// #0
    80204fc4:	34ff9861 	cbz	w1, 802042d0 <_vfprintf_r+0x2d0>
    80204fc8:	17ffff16 	b	80204c20 <_vfprintf_r+0xc20>
    80204fcc:	39400348 	ldrb	w8, [x26]
    80204fd0:	321d02f7 	orr	w23, w23, #0x8
    80204fd4:	17fffca6 	b	8020426c <_vfprintf_r+0x26c>
    80204fd8:	aa1a03ea 	mov	x10, x26
    80204fdc:	2a1803eb 	mov	w11, w24
    80204fe0:	2a1903e7 	mov	w7, w25
    80204fe4:	321c02fa 	orr	w26, w23, #0x10
    80204fe8:	b94093e0 	ldr	w0, [sp, #144]
    80204fec:	3728005a 	tbnz	w26, #5, 80204ff4 <_vfprintf_r+0xff4>
    80204ff0:	3620297a 	tbz	w26, #4, 8020551c <_vfprintf_r+0x151c>
    80204ff4:	37f848e0 	tbnz	w0, #31, 80205910 <_vfprintf_r+0x1910>
    80204ff8:	f9403fe0 	ldr	x0, [sp, #120]
    80204ffc:	91003c01 	add	x1, x0, #0xf
    80205000:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205004:	f9003fe1 	str	x1, [sp, #120]
    80205008:	f9400000 	ldr	x0, [x0]
    8020500c:	52800021 	mov	w1, #0x1                   	// #1
    80205010:	17ffffd8 	b	80204f70 <_vfprintf_r+0xf70>
    80205014:	39400348 	ldrb	w8, [x26]
    80205018:	7101b11f 	cmp	w8, #0x6c
    8020501c:	54003720 	b.eq	80205700 <_vfprintf_r+0x1700>  // b.none
    80205020:	321c02f7 	orr	w23, w23, #0x10
    80205024:	17fffc92 	b	8020426c <_vfprintf_r+0x26c>
    80205028:	39400348 	ldrb	w8, [x26]
    8020502c:	7101a11f 	cmp	w8, #0x68
    80205030:	54003700 	b.eq	80205710 <_vfprintf_r+0x1710>  // b.none
    80205034:	321a02f7 	orr	w23, w23, #0x40
    80205038:	17fffc8d 	b	8020426c <_vfprintf_r+0x26c>
    8020503c:	39400348 	ldrb	w8, [x26]
    80205040:	321b02f7 	orr	w23, w23, #0x20
    80205044:	17fffc8a 	b	8020426c <_vfprintf_r+0x26c>
    80205048:	b94093e0 	ldr	w0, [sp, #144]
    8020504c:	2a1703e9 	mov	w9, w23
    80205050:	2a1803eb 	mov	w11, w24
    80205054:	2a1903e7 	mov	w7, w25
    80205058:	aa1a03ea 	mov	x10, x26
    8020505c:	37f82c40 	tbnz	w0, #31, 802055e4 <_vfprintf_r+0x15e4>
    80205060:	f9403fe0 	ldr	x0, [sp, #120]
    80205064:	91003c01 	add	x1, x0, #0xf
    80205068:	927df021 	and	x1, x1, #0xfffffffffffffff8
    8020506c:	f9003fe1 	str	x1, [sp, #120]
    80205070:	f9400000 	ldr	x0, [x0]
    80205074:	528f0602 	mov	w2, #0x7830                	// #30768
    80205078:	f0000043 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020507c:	321f013a 	orr	w26, w9, #0x2
    80205080:	912f4063 	add	x3, x3, #0xbd0
    80205084:	52800041 	mov	w1, #0x2                   	// #2
    80205088:	52800f08 	mov	w8, #0x78                  	// #120
    8020508c:	f90073e3 	str	x3, [sp, #224]
    80205090:	7902c3e2 	strh	w2, [sp, #352]
    80205094:	17ffffb7 	b	80204f70 <_vfprintf_r+0xf70>
    80205098:	b94093e0 	ldr	w0, [sp, #144]
    8020509c:	2a1703e9 	mov	w9, w23
    802050a0:	aa1a03ea 	mov	x10, x26
    802050a4:	362826e9 	tbz	w9, #5, 80205580 <_vfprintf_r+0x1580>
    802050a8:	37f86d40 	tbnz	w0, #31, 80205e50 <_vfprintf_r+0x1e50>
    802050ac:	f9403fe0 	ldr	x0, [sp, #120]
    802050b0:	91003c01 	add	x1, x0, #0xf
    802050b4:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802050b8:	f9003fe1 	str	x1, [sp, #120]
    802050bc:	f9400000 	ldr	x0, [x0]
    802050c0:	b98077e1 	ldrsw	x1, [sp, #116]
    802050c4:	f9000001 	str	x1, [x0]
    802050c8:	17fffc13 	b	80204114 <_vfprintf_r+0x114>
    802050cc:	2a1803eb 	mov	w11, w24
    802050d0:	2a1903e7 	mov	w7, w25
    802050d4:	aa1a03ea 	mov	x10, x26
    802050d8:	321c02e9 	orr	w9, w23, #0x10
    802050dc:	b94093e0 	ldr	w0, [sp, #144]
    802050e0:	37280049 	tbnz	w9, #5, 802050e8 <_vfprintf_r+0x10e8>
    802050e4:	362022e9 	tbz	w9, #4, 80205540 <_vfprintf_r+0x1540>
    802050e8:	37f843c0 	tbnz	w0, #31, 80205960 <_vfprintf_r+0x1960>
    802050ec:	f9403fe0 	ldr	x0, [sp, #120]
    802050f0:	91003c01 	add	x1, x0, #0xf
    802050f4:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802050f8:	f9003fe1 	str	x1, [sp, #120]
    802050fc:	f9400001 	ldr	x1, [x0]
    80205100:	aa0103e0 	mov	x0, x1
    80205104:	b7f82301 	tbnz	x1, #63, 80205564 <_vfprintf_r+0x1564>
    80205108:	37f80ee7 	tbnz	w7, #31, 802052e4 <_vfprintf_r+0x12e4>
    8020510c:	f100001f 	cmp	x0, #0x0
    80205110:	12187929 	and	w9, w9, #0xffffff7f
    80205114:	7a4008e0 	ccmp	w7, #0x0, #0x0, eq	// eq = none
    80205118:	54000e61 	b.ne	802052e4 <_vfprintf_r+0x12e4>  // b.any
    8020511c:	910833fb 	add	x27, sp, #0x20c
    80205120:	52800007 	mov	w7, #0x0                   	// #0
    80205124:	52800017 	mov	w23, #0x0                   	// #0
    80205128:	17ffffa0 	b	80204fa8 <_vfprintf_r+0xfa8>
    8020512c:	39400348 	ldrb	w8, [x26]
    80205130:	321902f7 	orr	w23, w23, #0x80
    80205134:	17fffc4e 	b	8020426c <_vfprintf_r+0x26c>
    80205138:	2a0903fa 	mov	w26, w9
    8020513c:	7100043f 	cmp	w1, #0x1
    80205140:	54000d40 	b.eq	802052e8 <_vfprintf_r+0x12e8>  // b.none
    80205144:	910833f7 	add	x23, sp, #0x20c
    80205148:	aa1703fb 	mov	x27, x23
    8020514c:	7100083f 	cmp	w1, #0x2
    80205150:	54000141 	b.ne	80205178 <_vfprintf_r+0x1178>  // b.any
    80205154:	f94073e2 	ldr	x2, [sp, #224]
    80205158:	92400c01 	and	x1, x0, #0xf
    8020515c:	d344fc00 	lsr	x0, x0, #4
    80205160:	38616841 	ldrb	w1, [x2, x1]
    80205164:	381fff61 	strb	w1, [x27, #-1]!
    80205168:	b5ffff80 	cbnz	x0, 80205158 <_vfprintf_r+0x1158>
    8020516c:	4b1b02f7 	sub	w23, w23, w27
    80205170:	2a1a03e9 	mov	w9, w26
    80205174:	17ffff8d 	b	80204fa8 <_vfprintf_r+0xfa8>
    80205178:	12000801 	and	w1, w0, #0x7
    8020517c:	aa1b03e2 	mov	x2, x27
    80205180:	1100c021 	add	w1, w1, #0x30
    80205184:	381fff61 	strb	w1, [x27, #-1]!
    80205188:	d343fc00 	lsr	x0, x0, #3
    8020518c:	b5ffff60 	cbnz	x0, 80205178 <_vfprintf_r+0x1178>
    80205190:	7100c03f 	cmp	w1, #0x30
    80205194:	1a9f07e0 	cset	w0, ne	// ne = any
    80205198:	6a00035f 	tst	w26, w0
    8020519c:	54fffe80 	b.eq	8020516c <_vfprintf_r+0x116c>  // b.none
    802051a0:	d1000842 	sub	x2, x2, #0x2
    802051a4:	52800600 	mov	w0, #0x30                  	// #48
    802051a8:	2a1a03e9 	mov	w9, w26
    802051ac:	4b0202f7 	sub	w23, w23, w2
    802051b0:	381ff360 	sturb	w0, [x27, #-1]
    802051b4:	aa0203fb 	mov	x27, x2
    802051b8:	17ffff7c 	b	80204fa8 <_vfprintf_r+0xfa8>
    802051bc:	910643e2 	add	x2, sp, #0x190
    802051c0:	aa1503e1 	mov	x1, x21
    802051c4:	aa1303e0 	mov	x0, x19
    802051c8:	b900bbee 	str	w14, [sp, #184]
    802051cc:	b900c3e9 	str	w9, [sp, #192]
    802051d0:	b900cbe8 	str	w8, [sp, #200]
    802051d4:	b900d3eb 	str	w11, [sp, #208]
    802051d8:	b900dbe7 	str	w7, [sp, #216]
    802051dc:	f9008bea 	str	x10, [sp, #272]
    802051e0:	940008c4 	bl	802074f0 <__sprint_r>
    802051e4:	35ffb2e0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802051e8:	f9408bea 	ldr	x10, [sp, #272]
    802051ec:	aa1603fc 	mov	x28, x22
    802051f0:	f940d3e0 	ldr	x0, [sp, #416]
    802051f4:	b940bbee 	ldr	w14, [sp, #184]
    802051f8:	b940c3e9 	ldr	w9, [sp, #192]
    802051fc:	b940cbe8 	ldr	w8, [sp, #200]
    80205200:	b940d3eb 	ldr	w11, [sp, #208]
    80205204:	b940dbe7 	ldr	w7, [sp, #216]
    80205208:	17fffc56 	b	80204360 <_vfprintf_r+0x360>
    8020520c:	f000004d 	adrp	x13, 80210000 <_wcsnrtombs_l+0x110>
    80205210:	b9419be1 	ldr	w1, [sp, #408]
    80205214:	913e81ad 	add	x13, x13, #0xfa0
    80205218:	710042ff 	cmp	w23, #0x10
    8020521c:	540003ed 	b.le	80205298 <_vfprintf_r+0x1298>
    80205220:	aa0d03f8 	mov	x24, x13
    80205224:	d280021b 	mov	x27, #0x10                  	// #16
    80205228:	b9008beb 	str	w11, [sp, #136]
    8020522c:	f9004fea 	str	x10, [sp, #152]
    80205230:	14000004 	b	80205240 <_vfprintf_r+0x1240>
    80205234:	510042f7 	sub	w23, w23, #0x10
    80205238:	710042ff 	cmp	w23, #0x10
    8020523c:	5400028d 	b.le	8020528c <_vfprintf_r+0x128c>
    80205240:	91004000 	add	x0, x0, #0x10
    80205244:	11000421 	add	w1, w1, #0x1
    80205248:	a9006f98 	stp	x24, x27, [x28]
    8020524c:	9100439c 	add	x28, x28, #0x10
    80205250:	b9019be1 	str	w1, [sp, #408]
    80205254:	f900d3e0 	str	x0, [sp, #416]
    80205258:	71001c3f 	cmp	w1, #0x7
    8020525c:	54fffecd 	b.le	80205234 <_vfprintf_r+0x1234>
    80205260:	910643e2 	add	x2, sp, #0x190
    80205264:	aa1503e1 	mov	x1, x21
    80205268:	aa1303e0 	mov	x0, x19
    8020526c:	940008a1 	bl	802074f0 <__sprint_r>
    80205270:	35ffae80 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80205274:	510042f7 	sub	w23, w23, #0x10
    80205278:	b9419be1 	ldr	w1, [sp, #408]
    8020527c:	f940d3e0 	ldr	x0, [sp, #416]
    80205280:	aa1603fc 	mov	x28, x22
    80205284:	710042ff 	cmp	w23, #0x10
    80205288:	54fffdcc 	b.gt	80205240 <_vfprintf_r+0x1240>
    8020528c:	f9404fea 	ldr	x10, [sp, #152]
    80205290:	aa1803ed 	mov	x13, x24
    80205294:	b9408beb 	ldr	w11, [sp, #136]
    80205298:	93407ef7 	sxtw	x23, w23
    8020529c:	11000421 	add	w1, w1, #0x1
    802052a0:	8b170000 	add	x0, x0, x23
    802052a4:	a9005f8d 	stp	x13, x23, [x28]
    802052a8:	b9019be1 	str	w1, [sp, #408]
    802052ac:	f900d3e0 	str	x0, [sp, #416]
    802052b0:	71001c3f 	cmp	w1, #0x7
    802052b4:	54ff87ed 	b.le	802043b0 <_vfprintf_r+0x3b0>
    802052b8:	910643e2 	add	x2, sp, #0x190
    802052bc:	aa1503e1 	mov	x1, x21
    802052c0:	aa1303e0 	mov	x0, x19
    802052c4:	b9008beb 	str	w11, [sp, #136]
    802052c8:	f9004fea 	str	x10, [sp, #152]
    802052cc:	94000889 	bl	802074f0 <__sprint_r>
    802052d0:	35ffab80 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802052d4:	f9404fea 	ldr	x10, [sp, #152]
    802052d8:	f940d3e0 	ldr	x0, [sp, #416]
    802052dc:	b9408beb 	ldr	w11, [sp, #136]
    802052e0:	17fffc34 	b	802043b0 <_vfprintf_r+0x3b0>
    802052e4:	2a0903fa 	mov	w26, w9
    802052e8:	f100241f 	cmp	x0, #0x9
    802052ec:	540054a8 	b.hi	80205d80 <_vfprintf_r+0x1d80>  // b.pmore
    802052f0:	1100c000 	add	w0, w0, #0x30
    802052f4:	2a1a03e9 	mov	w9, w26
    802052f8:	91082ffb 	add	x27, sp, #0x20b
    802052fc:	52800037 	mov	w23, #0x1                   	// #1
    80205300:	39082fe0 	strb	w0, [sp, #523]
    80205304:	17ffff29 	b	80204fa8 <_vfprintf_r+0xfa8>
    80205308:	910833fb 	add	x27, sp, #0x20c
    8020530c:	52800007 	mov	w7, #0x0                   	// #0
    80205310:	17ffff26 	b	80204fa8 <_vfprintf_r+0xfa8>
    80205314:	b94097e1 	ldr	w1, [sp, #148]
    80205318:	6b01031f 	cmp	w24, w1
    8020531c:	1a81d317 	csel	w23, w24, w1, le
    80205320:	93407c2c 	sxtw	x12, w1
    80205324:	710002ff 	cmp	w23, #0x0
    80205328:	5400016d 	b.le	80205354 <_vfprintf_r+0x1354>
    8020532c:	b9419be1 	ldr	w1, [sp, #408]
    80205330:	93407ee2 	sxtw	x2, w23
    80205334:	8b020000 	add	x0, x0, x2
    80205338:	a9000b9b 	stp	x27, x2, [x28]
    8020533c:	11000421 	add	w1, w1, #0x1
    80205340:	b9019be1 	str	w1, [sp, #408]
    80205344:	9100439c 	add	x28, x28, #0x10
    80205348:	f900d3e0 	str	x0, [sp, #416]
    8020534c:	71001c3f 	cmp	w1, #0x7
    80205350:	5400b3cc 	b.gt	802069c8 <_vfprintf_r+0x29c8>
    80205354:	710002ff 	cmp	w23, #0x0
    80205358:	1a9fa2e4 	csel	w4, w23, wzr, ge	// ge = tcont
    8020535c:	4b040317 	sub	w23, w24, w4
    80205360:	710002ff 	cmp	w23, #0x0
    80205364:	5400594c 	b.gt	80205e8c <_vfprintf_r+0x1e8c>
    80205368:	8b38c368 	add	x8, x27, w24, sxtw
    8020536c:	37509509 	tbnz	w9, #10, 8020660c <_vfprintf_r+0x260c>
    80205370:	b94097e1 	ldr	w1, [sp, #148]
    80205374:	b9416bf7 	ldr	w23, [sp, #360]
    80205378:	6b0102ff 	cmp	w23, w1
    8020537c:	5400266b 	b.lt	80205848 <_vfprintf_r+0x1848>  // b.tstop
    80205380:	37002649 	tbnz	w9, #0, 80205848 <_vfprintf_r+0x1848>
    80205384:	b94097e1 	ldr	w1, [sp, #148]
    80205388:	8b0c037b 	add	x27, x27, x12
    8020538c:	cb08037b 	sub	x27, x27, x8
    80205390:	4b170037 	sub	w23, w1, w23
    80205394:	6b1b02ff 	cmp	w23, w27
    80205398:	1a9bb2fb 	csel	w27, w23, w27, lt	// lt = tstop
    8020539c:	7100037f 	cmp	w27, #0x0
    802053a0:	5400016d 	b.le	802053cc <_vfprintf_r+0x13cc>
    802053a4:	b9419be1 	ldr	w1, [sp, #408]
    802053a8:	93407f62 	sxtw	x2, w27
    802053ac:	8b020000 	add	x0, x0, x2
    802053b0:	a9000b88 	stp	x8, x2, [x28]
    802053b4:	11000421 	add	w1, w1, #0x1
    802053b8:	b9019be1 	str	w1, [sp, #408]
    802053bc:	9100439c 	add	x28, x28, #0x10
    802053c0:	f900d3e0 	str	x0, [sp, #416]
    802053c4:	71001c3f 	cmp	w1, #0x7
    802053c8:	5400b6ec 	b.gt	80206aa4 <_vfprintf_r+0x2aa4>
    802053cc:	7100037f 	cmp	w27, #0x0
    802053d0:	1a9fa37b 	csel	w27, w27, wzr, ge	// ge = tcont
    802053d4:	4b1b02f7 	sub	w23, w23, w27
    802053d8:	710002ff 	cmp	w23, #0x0
    802053dc:	54ff7e2d 	b.le	802043a0 <_vfprintf_r+0x3a0>
    802053e0:	f0000044 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    802053e4:	b9419be1 	ldr	w1, [sp, #408]
    802053e8:	913e4084 	add	x4, x4, #0xf90
    802053ec:	710042ff 	cmp	w23, #0x10
    802053f0:	54004b4d 	b.le	80205d58 <_vfprintf_r+0x1d58>
    802053f4:	aa1c03e2 	mov	x2, x28
    802053f8:	aa0403f8 	mov	x24, x4
    802053fc:	aa0a03fc 	mov	x28, x10
    80205400:	d280021b 	mov	x27, #0x10                  	// #16
    80205404:	b9008be9 	str	w9, [sp, #136]
    80205408:	b9009beb 	str	w11, [sp, #152]
    8020540c:	14000004 	b	8020541c <_vfprintf_r+0x141c>
    80205410:	510042f7 	sub	w23, w23, #0x10
    80205414:	710042ff 	cmp	w23, #0x10
    80205418:	5400496d 	b.le	80205d44 <_vfprintf_r+0x1d44>
    8020541c:	91004000 	add	x0, x0, #0x10
    80205420:	11000421 	add	w1, w1, #0x1
    80205424:	a9006c58 	stp	x24, x27, [x2]
    80205428:	91004042 	add	x2, x2, #0x10
    8020542c:	b9019be1 	str	w1, [sp, #408]
    80205430:	f900d3e0 	str	x0, [sp, #416]
    80205434:	71001c3f 	cmp	w1, #0x7
    80205438:	54fffecd 	b.le	80205410 <_vfprintf_r+0x1410>
    8020543c:	910643e2 	add	x2, sp, #0x190
    80205440:	aa1503e1 	mov	x1, x21
    80205444:	aa1303e0 	mov	x0, x19
    80205448:	9400082a 	bl	802074f0 <__sprint_r>
    8020544c:	35ff9fa0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80205450:	f940d3e0 	ldr	x0, [sp, #416]
    80205454:	aa1603e2 	mov	x2, x22
    80205458:	b9419be1 	ldr	w1, [sp, #408]
    8020545c:	17ffffed 	b	80205410 <_vfprintf_r+0x1410>
    80205460:	910643e2 	add	x2, sp, #0x190
    80205464:	aa1503e1 	mov	x1, x21
    80205468:	aa1303e0 	mov	x0, x19
    8020546c:	b9008be9 	str	w9, [sp, #136]
    80205470:	b9009beb 	str	w11, [sp, #152]
    80205474:	f9005fea 	str	x10, [sp, #184]
    80205478:	9400081e 	bl	802074f0 <__sprint_r>
    8020547c:	35ff9e20 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80205480:	f9405fea 	ldr	x10, [sp, #184]
    80205484:	aa1603e2 	mov	x2, x22
    80205488:	f940d3e0 	ldr	x0, [sp, #416]
    8020548c:	b9408be9 	ldr	w9, [sp, #136]
    80205490:	b9409beb 	ldr	w11, [sp, #152]
    80205494:	b9419be1 	ldr	w1, [sp, #408]
    80205498:	17fffd5f 	b	80204a14 <_vfprintf_r+0xa14>
    8020549c:	910643e2 	add	x2, sp, #0x190
    802054a0:	aa1503e1 	mov	x1, x21
    802054a4:	aa1303e0 	mov	x0, x19
    802054a8:	b9008be9 	str	w9, [sp, #136]
    802054ac:	b9009beb 	str	w11, [sp, #152]
    802054b0:	f9005fea 	str	x10, [sp, #184]
    802054b4:	9400080f 	bl	802074f0 <__sprint_r>
    802054b8:	35ff9c40 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802054bc:	1e602108 	fcmp	d8, #0.0
    802054c0:	b94097e3 	ldr	w3, [sp, #148]
    802054c4:	f9405fea 	ldr	x10, [sp, #184]
    802054c8:	aa1603e2 	mov	x2, x22
    802054cc:	f940d3e0 	ldr	x0, [sp, #416]
    802054d0:	51000477 	sub	w23, w3, #0x1
    802054d4:	b9408be9 	ldr	w9, [sp, #136]
    802054d8:	b9409beb 	ldr	w11, [sp, #152]
    802054dc:	b9419be1 	ldr	w1, [sp, #408]
    802054e0:	54ffbd00 	b.eq	80204c80 <_vfprintf_r+0xc80>  // b.none
    802054e4:	17fffd59 	b	80204a48 <_vfprintf_r+0xa48>
    802054e8:	f94052a0 	ldr	x0, [x21, #160]
    802054ec:	940011b5 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    802054f0:	79c022a0 	ldrsh	w0, [x21, #16]
    802054f4:	17fffae7 	b	80204090 <_vfprintf_r+0x90>
    802054f8:	36077549 	tbz	w9, #0, 802043a0 <_vfprintf_r+0x3a0>
    802054fc:	17fffc23 	b	80204588 <_vfprintf_r+0x588>
    80205500:	37f88700 	tbnz	w0, #31, 802065e0 <_vfprintf_r+0x25e0>
    80205504:	f9403fe0 	ldr	x0, [sp, #120]
    80205508:	91003c01 	add	x1, x0, #0xf
    8020550c:	fd400008 	ldr	d8, [x0]
    80205510:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205514:	f9003fe1 	str	x1, [sp, #120]
    80205518:	17fffdaa 	b	80204bc0 <_vfprintf_r+0xbc0>
    8020551c:	36304ffa 	tbz	w26, #6, 80205f18 <_vfprintf_r+0x1f18>
    80205520:	37f87920 	tbnz	w0, #31, 80206444 <_vfprintf_r+0x2444>
    80205524:	f9403fe0 	ldr	x0, [sp, #120]
    80205528:	91002c01 	add	x1, x0, #0xb
    8020552c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205530:	f9003fe1 	str	x1, [sp, #120]
    80205534:	79400000 	ldrh	w0, [x0]
    80205538:	52800021 	mov	w1, #0x1                   	// #1
    8020553c:	17fffe8d 	b	80204f70 <_vfprintf_r+0xf70>
    80205540:	36305509 	tbz	w9, #6, 80205fe0 <_vfprintf_r+0x1fe0>
    80205544:	37f87260 	tbnz	w0, #31, 80206390 <_vfprintf_r+0x2390>
    80205548:	f9403fe0 	ldr	x0, [sp, #120]
    8020554c:	91002c01 	add	x1, x0, #0xb
    80205550:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205554:	f9003fe1 	str	x1, [sp, #120]
    80205558:	79800000 	ldrsh	x0, [x0]
    8020555c:	aa0003e1 	mov	x1, x0
    80205560:	b6ffdd41 	tbz	x1, #63, 80205108 <_vfprintf_r+0x1108>
    80205564:	cb0003e0 	neg	x0, x0
    80205568:	2a0903fa 	mov	w26, w9
    8020556c:	528005a2 	mov	w2, #0x2d                  	// #45
    80205570:	52800021 	mov	w1, #0x1                   	// #1
    80205574:	17fffe80 	b	80204f74 <_vfprintf_r+0xf74>
    80205578:	39400348 	ldrb	w8, [x26]
    8020557c:	17fffb3c 	b	8020426c <_vfprintf_r+0x26c>
    80205580:	3727d949 	tbnz	w9, #4, 802050a8 <_vfprintf_r+0x10a8>
    80205584:	37306b89 	tbnz	w9, #6, 802062f4 <_vfprintf_r+0x22f4>
    80205588:	3648bba9 	tbz	w9, #9, 80206cfc <_vfprintf_r+0x2cfc>
    8020558c:	37f8d6e0 	tbnz	w0, #31, 80207068 <_vfprintf_r+0x3068>
    80205590:	f9403fe0 	ldr	x0, [sp, #120]
    80205594:	91003c01 	add	x1, x0, #0xf
    80205598:	927df021 	and	x1, x1, #0xfffffffffffffff8
    8020559c:	f9003fe1 	str	x1, [sp, #120]
    802055a0:	f9400000 	ldr	x0, [x0]
    802055a4:	3941d3e1 	ldrb	w1, [sp, #116]
    802055a8:	39000001 	strb	w1, [x0]
    802055ac:	17fffada 	b	80204114 <_vfprintf_r+0x114>
    802055b0:	36304c69 	tbz	w9, #6, 80205f3c <_vfprintf_r+0x1f3c>
    802055b4:	37f870c0 	tbnz	w0, #31, 802063cc <_vfprintf_r+0x23cc>
    802055b8:	f9403fe0 	ldr	x0, [sp, #120]
    802055bc:	91002c01 	add	x1, x0, #0xb
    802055c0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802055c4:	79400000 	ldrh	w0, [x0]
    802055c8:	f9003fe1 	str	x1, [sp, #120]
    802055cc:	17fffe67 	b	80204f68 <_vfprintf_r+0xf68>
    802055d0:	2a1703e9 	mov	w9, w23
    802055d4:	2a1803eb 	mov	w11, w24
    802055d8:	2a1903e7 	mov	w7, w25
    802055dc:	aa1a03ea 	mov	x10, x26
    802055e0:	17fffebf 	b	802050dc <_vfprintf_r+0x10dc>
    802055e4:	b94093e0 	ldr	w0, [sp, #144]
    802055e8:	11002001 	add	w1, w0, #0x8
    802055ec:	7100003f 	cmp	w1, #0x0
    802055f0:	54009e2d 	b.le	802069b4 <_vfprintf_r+0x29b4>
    802055f4:	f9403fe0 	ldr	x0, [sp, #120]
    802055f8:	b90093e1 	str	w1, [sp, #144]
    802055fc:	91003c02 	add	x2, x0, #0xf
    80205600:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205604:	f9003fe1 	str	x1, [sp, #120]
    80205608:	17fffe9a 	b	80205070 <_vfprintf_r+0x1070>
    8020560c:	b94093e0 	ldr	w0, [sp, #144]
    80205610:	11002001 	add	w1, w0, #0x8
    80205614:	7100003f 	cmp	w1, #0x0
    80205618:	54009c4d 	b.le	802069a0 <_vfprintf_r+0x29a0>
    8020561c:	f9403fe0 	ldr	x0, [sp, #120]
    80205620:	b90093e1 	str	w1, [sp, #144]
    80205624:	91003c02 	add	x2, x0, #0xf
    80205628:	927df041 	and	x1, x2, #0xfffffffffffffff8
    8020562c:	f9003fe1 	str	x1, [sp, #120]
    80205630:	17fffdd9 	b	80204d94 <_vfprintf_r+0xd94>
    80205634:	b94093e0 	ldr	w0, [sp, #144]
    80205638:	11002001 	add	w1, w0, #0x8
    8020563c:	7100003f 	cmp	w1, #0x0
    80205640:	54009a2d 	b.le	80206984 <_vfprintf_r+0x2984>
    80205644:	f9403fe0 	ldr	x0, [sp, #120]
    80205648:	b90093e1 	str	w1, [sp, #144]
    8020564c:	91002c00 	add	x0, x0, #0xb
    80205650:	927df000 	and	x0, x0, #0xfffffffffffffff8
    80205654:	17fffe14 	b	80204ea4 <_vfprintf_r+0xea4>
    80205658:	f9404fea 	ldr	x10, [sp, #152]
    8020565c:	2a1c03eb 	mov	w11, w28
    80205660:	b9408be9 	ldr	w9, [sp, #136]
    80205664:	aa1803e4 	mov	x4, x24
    80205668:	93407ef7 	sxtw	x23, w23
    8020566c:	11000421 	add	w1, w1, #0x1
    80205670:	8b170000 	add	x0, x0, x23
    80205674:	b9019be1 	str	w1, [sp, #408]
    80205678:	f900d3e0 	str	x0, [sp, #416]
    8020567c:	f9000044 	str	x4, [x2]
    80205680:	f9000457 	str	x23, [x2, #8]
    80205684:	71001c3f 	cmp	w1, #0x7
    80205688:	54ff9f4d 	b.le	80204a70 <_vfprintf_r+0xa70>
    8020568c:	910643e2 	add	x2, sp, #0x190
    80205690:	aa1503e1 	mov	x1, x21
    80205694:	aa1303e0 	mov	x0, x19
    80205698:	b9008be9 	str	w9, [sp, #136]
    8020569c:	b9009beb 	str	w11, [sp, #152]
    802056a0:	f9005fea 	str	x10, [sp, #184]
    802056a4:	94000793 	bl	802074f0 <__sprint_r>
    802056a8:	35ff8cc0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802056ac:	f9405fea 	ldr	x10, [sp, #184]
    802056b0:	aa1603e2 	mov	x2, x22
    802056b4:	f940d3e0 	ldr	x0, [sp, #416]
    802056b8:	b9408be9 	ldr	w9, [sp, #136]
    802056bc:	b9409beb 	ldr	w11, [sp, #152]
    802056c0:	b9419be1 	ldr	w1, [sp, #408]
    802056c4:	17fffcec 	b	80204a74 <_vfprintf_r+0xa74>
    802056c8:	910643e2 	add	x2, sp, #0x190
    802056cc:	aa1503e1 	mov	x1, x21
    802056d0:	aa1303e0 	mov	x0, x19
    802056d4:	b9008be9 	str	w9, [sp, #136]
    802056d8:	b9009beb 	str	w11, [sp, #152]
    802056dc:	f9005fea 	str	x10, [sp, #184]
    802056e0:	94000784 	bl	802074f0 <__sprint_r>
    802056e4:	35ff8ae0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802056e8:	f9405fea 	ldr	x10, [sp, #184]
    802056ec:	aa1603fc 	mov	x28, x22
    802056f0:	f940d3e0 	ldr	x0, [sp, #416]
    802056f4:	b9408be9 	ldr	w9, [sp, #136]
    802056f8:	b9409beb 	ldr	w11, [sp, #152]
    802056fc:	17fffbad 	b	802045b0 <_vfprintf_r+0x5b0>
    80205700:	39400748 	ldrb	w8, [x26, #1]
    80205704:	321b02f7 	orr	w23, w23, #0x20
    80205708:	9100075a 	add	x26, x26, #0x1
    8020570c:	17fffad8 	b	8020426c <_vfprintf_r+0x26c>
    80205710:	39400748 	ldrb	w8, [x26, #1]
    80205714:	321702f7 	orr	w23, w23, #0x200
    80205718:	9100075a 	add	x26, x26, #0x1
    8020571c:	17fffad4 	b	8020426c <_vfprintf_r+0x26c>
    80205720:	aa1a03ea 	mov	x10, x26
    80205724:	2a1803eb 	mov	w11, w24
    80205728:	2a1903e7 	mov	w7, w25
    8020572c:	2a1703fa 	mov	w26, w23
    80205730:	17fffe2e 	b	80204fe8 <_vfprintf_r+0xfe8>
    80205734:	2a1703e9 	mov	w9, w23
    80205738:	2a1803eb 	mov	w11, w24
    8020573c:	2a1903e7 	mov	w7, w25
    80205740:	aa1a03ea 	mov	x10, x26
    80205744:	f0000040 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    80205748:	912fa000 	add	x0, x0, #0xbe8
    8020574c:	f90073e0 	str	x0, [sp, #224]
    80205750:	b94093e0 	ldr	w0, [sp, #144]
    80205754:	37280b09 	tbnz	w9, #5, 802058b4 <_vfprintf_r+0x18b4>
    80205758:	37200ae9 	tbnz	w9, #4, 802058b4 <_vfprintf_r+0x18b4>
    8020575c:	36304149 	tbz	w9, #6, 80205f84 <_vfprintf_r+0x1f84>
    80205760:	37f86860 	tbnz	w0, #31, 8020646c <_vfprintf_r+0x246c>
    80205764:	f9403fe0 	ldr	x0, [sp, #120]
    80205768:	91002c01 	add	x1, x0, #0xb
    8020576c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205770:	79400000 	ldrh	w0, [x0]
    80205774:	f9003fe1 	str	x1, [sp, #120]
    80205778:	14000055 	b	802058cc <_vfprintf_r+0x18cc>
    8020577c:	f0000040 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    80205780:	2a1703e9 	mov	w9, w23
    80205784:	912f4000 	add	x0, x0, #0xbd0
    80205788:	2a1803eb 	mov	w11, w24
    8020578c:	2a1903e7 	mov	w7, w25
    80205790:	aa1a03ea 	mov	x10, x26
    80205794:	f90073e0 	str	x0, [sp, #224]
    80205798:	17ffffee 	b	80205750 <_vfprintf_r+0x1750>
    8020579c:	2a1703e9 	mov	w9, w23
    802057a0:	2a1803eb 	mov	w11, w24
    802057a4:	2a1903e7 	mov	w7, w25
    802057a8:	aa1a03ea 	mov	x10, x26
    802057ac:	17fffde6 	b	80204f44 <_vfprintf_r+0xf44>
    802057b0:	910623e0 	add	x0, sp, #0x188
    802057b4:	d2800102 	mov	x2, #0x8                   	// #8
    802057b8:	52800001 	mov	w1, #0x0                   	// #0
    802057bc:	b9008be9 	str	w9, [sp, #136]
    802057c0:	b9009be8 	str	w8, [sp, #152]
    802057c4:	b900bbeb 	str	w11, [sp, #184]
    802057c8:	f90063ea 	str	x10, [sp, #192]
    802057cc:	97fff7bd 	bl	802036c0 <memset>
    802057d0:	b94093e0 	ldr	w0, [sp, #144]
    802057d4:	f94063ea 	ldr	x10, [sp, #192]
    802057d8:	b9408be9 	ldr	w9, [sp, #136]
    802057dc:	b9409be8 	ldr	w8, [sp, #152]
    802057e0:	b940bbeb 	ldr	w11, [sp, #184]
    802057e4:	37f83ea0 	tbnz	w0, #31, 80205fb8 <_vfprintf_r+0x1fb8>
    802057e8:	f9403fe0 	ldr	x0, [sp, #120]
    802057ec:	91002c01 	add	x1, x0, #0xb
    802057f0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802057f4:	f9003fe1 	str	x1, [sp, #120]
    802057f8:	b9400002 	ldr	w2, [x0]
    802057fc:	9106a3f8 	add	x24, sp, #0x1a8
    80205800:	910623e3 	add	x3, sp, #0x188
    80205804:	aa1803e1 	mov	x1, x24
    80205808:	aa1303e0 	mov	x0, x19
    8020580c:	b9008be9 	str	w9, [sp, #136]
    80205810:	b9009be8 	str	w8, [sp, #152]
    80205814:	b900bbeb 	str	w11, [sp, #184]
    80205818:	f90063ea 	str	x10, [sp, #192]
    8020581c:	94001089 	bl	80209a40 <_wcrtomb_r>
    80205820:	f94063ea 	ldr	x10, [sp, #192]
    80205824:	2a0003f7 	mov	w23, w0
    80205828:	b9408be9 	ldr	w9, [sp, #136]
    8020582c:	3100041f 	cmn	w0, #0x1
    80205830:	b9409be8 	ldr	w8, [sp, #152]
    80205834:	b940bbeb 	ldr	w11, [sp, #184]
    80205838:	5400c9a0 	b.eq	8020716c <_vfprintf_r+0x316c>  // b.none
    8020583c:	7100001f 	cmp	w0, #0x0
    80205840:	1a9fa01a 	csel	w26, w0, wzr, ge	// ge = tcont
    80205844:	17fffd41 	b	80204d48 <_vfprintf_r+0xd48>
    80205848:	a94a8fe2 	ldp	x2, x3, [sp, #168]
    8020584c:	a9000b83 	stp	x3, x2, [x28]
    80205850:	b9419be1 	ldr	w1, [sp, #408]
    80205854:	9100439c 	add	x28, x28, #0x10
    80205858:	11000421 	add	w1, w1, #0x1
    8020585c:	b9019be1 	str	w1, [sp, #408]
    80205860:	8b020000 	add	x0, x0, x2
    80205864:	f900d3e0 	str	x0, [sp, #416]
    80205868:	71001c3f 	cmp	w1, #0x7
    8020586c:	54ffd8cd 	b.le	80205384 <_vfprintf_r+0x1384>
    80205870:	910643e2 	add	x2, sp, #0x190
    80205874:	aa1503e1 	mov	x1, x21
    80205878:	aa1303e0 	mov	x0, x19
    8020587c:	f90047ec 	str	x12, [sp, #136]
    80205880:	b9009be9 	str	w9, [sp, #152]
    80205884:	b900bbeb 	str	w11, [sp, #184]
    80205888:	a90c2be8 	stp	x8, x10, [sp, #192]
    8020588c:	94000719 	bl	802074f0 <__sprint_r>
    80205890:	35ff7d80 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80205894:	f94047ec 	ldr	x12, [sp, #136]
    80205898:	aa1603fc 	mov	x28, x22
    8020589c:	a94c2be8 	ldp	x8, x10, [sp, #192]
    802058a0:	f940d3e0 	ldr	x0, [sp, #416]
    802058a4:	b9409be9 	ldr	w9, [sp, #152]
    802058a8:	b940bbeb 	ldr	w11, [sp, #184]
    802058ac:	b9416bf7 	ldr	w23, [sp, #360]
    802058b0:	17fffeb5 	b	80205384 <_vfprintf_r+0x1384>
    802058b4:	37f801a0 	tbnz	w0, #31, 802058e8 <_vfprintf_r+0x18e8>
    802058b8:	f9403fe0 	ldr	x0, [sp, #120]
    802058bc:	91003c01 	add	x1, x0, #0xf
    802058c0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    802058c4:	f9003fe1 	str	x1, [sp, #120]
    802058c8:	f9400000 	ldr	x0, [x0]
    802058cc:	f100001f 	cmp	x0, #0x0
    802058d0:	1a9f07e1 	cset	w1, ne	// ne = any
    802058d4:	6a01013f 	tst	w9, w1
    802058d8:	540014c1 	b.ne	80205b70 <_vfprintf_r+0x1b70>  // b.any
    802058dc:	1215793a 	and	w26, w9, #0xfffffbff
    802058e0:	52800041 	mov	w1, #0x2                   	// #2
    802058e4:	17fffda3 	b	80204f70 <_vfprintf_r+0xf70>
    802058e8:	b94093e0 	ldr	w0, [sp, #144]
    802058ec:	11002001 	add	w1, w0, #0x8
    802058f0:	7100003f 	cmp	w1, #0x0
    802058f4:	5400388d 	b.le	80206004 <_vfprintf_r+0x2004>
    802058f8:	f9403fe0 	ldr	x0, [sp, #120]
    802058fc:	b90093e1 	str	w1, [sp, #144]
    80205900:	91003c02 	add	x2, x0, #0xf
    80205904:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205908:	f9003fe1 	str	x1, [sp, #120]
    8020590c:	17ffffef 	b	802058c8 <_vfprintf_r+0x18c8>
    80205910:	b94093e0 	ldr	w0, [sp, #144]
    80205914:	11002001 	add	w1, w0, #0x8
    80205918:	7100003f 	cmp	w1, #0x0
    8020591c:	540032ad 	b.le	80205f70 <_vfprintf_r+0x1f70>
    80205920:	f9403fe0 	ldr	x0, [sp, #120]
    80205924:	b90093e1 	str	w1, [sp, #144]
    80205928:	91003c02 	add	x2, x0, #0xf
    8020592c:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205930:	f9003fe1 	str	x1, [sp, #120]
    80205934:	17fffdb5 	b	80205008 <_vfprintf_r+0x1008>
    80205938:	b94093e0 	ldr	w0, [sp, #144]
    8020593c:	11002001 	add	w1, w0, #0x8
    80205940:	7100003f 	cmp	w1, #0x0
    80205944:	5400330d 	b.le	80205fa4 <_vfprintf_r+0x1fa4>
    80205948:	f9403fe0 	ldr	x0, [sp, #120]
    8020594c:	b90093e1 	str	w1, [sp, #144]
    80205950:	91003c02 	add	x2, x0, #0xf
    80205954:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205958:	f9003fe1 	str	x1, [sp, #120]
    8020595c:	17fffd82 	b	80204f64 <_vfprintf_r+0xf64>
    80205960:	b94093e0 	ldr	w0, [sp, #144]
    80205964:	11002001 	add	w1, w0, #0x8
    80205968:	7100003f 	cmp	w1, #0x0
    8020596c:	54002f8d 	b.le	80205f5c <_vfprintf_r+0x1f5c>
    80205970:	f9403fe0 	ldr	x0, [sp, #120]
    80205974:	b90093e1 	str	w1, [sp, #144]
    80205978:	91003c02 	add	x2, x0, #0xf
    8020597c:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205980:	f9003fe1 	str	x1, [sp, #120]
    80205984:	17fffdde 	b	802050fc <_vfprintf_r+0x10fc>
    80205988:	910643e2 	add	x2, sp, #0x190
    8020598c:	aa1503e1 	mov	x1, x21
    80205990:	aa1303e0 	mov	x0, x19
    80205994:	b900bbf2 	str	w18, [sp, #184]
    80205998:	b900c3ee 	str	w14, [sp, #192]
    8020599c:	b900cbe9 	str	w9, [sp, #200]
    802059a0:	b900d3e8 	str	w8, [sp, #208]
    802059a4:	b900dbeb 	str	w11, [sp, #216]
    802059a8:	b90113e7 	str	w7, [sp, #272]
    802059ac:	f9008fea 	str	x10, [sp, #280]
    802059b0:	940006d0 	bl	802074f0 <__sprint_r>
    802059b4:	35ff7460 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802059b8:	f9408fea 	ldr	x10, [sp, #280]
    802059bc:	aa1603fc 	mov	x28, x22
    802059c0:	f940d3e0 	ldr	x0, [sp, #416]
    802059c4:	39457fe1 	ldrb	w1, [sp, #351]
    802059c8:	b940bbf2 	ldr	w18, [sp, #184]
    802059cc:	b940c3ee 	ldr	w14, [sp, #192]
    802059d0:	b940cbe9 	ldr	w9, [sp, #200]
    802059d4:	b940d3e8 	ldr	w8, [sp, #208]
    802059d8:	b940dbeb 	ldr	w11, [sp, #216]
    802059dc:	b94113e7 	ldr	w7, [sp, #272]
    802059e0:	17fffa46 	b	802042f8 <_vfprintf_r+0x2f8>
    802059e4:	aa1303e0 	mov	x0, x19
    802059e8:	97fff6fa 	bl	802035d0 <__sinit>
    802059ec:	17fff9a5 	b	80204080 <_vfprintf_r+0x80>
    802059f0:	1e682100 	fcmp	d8, d8
    802059f4:	54009ce6 	b.vs	80206d90 <_vfprintf_r+0x2d90>
    802059f8:	121a7917 	and	w23, w8, #0xffffffdf
    802059fc:	710106ff 	cmp	w23, #0x41
    80205a00:	540030c1 	b.ne	80206018 <_vfprintf_r+0x2018>  // b.any
    80205a04:	52800f01 	mov	w1, #0x78                  	// #120
    80205a08:	7101851f 	cmp	w8, #0x61
    80205a0c:	52800b00 	mov	w0, #0x58                  	// #88
    80205a10:	1a811000 	csel	w0, w0, w1, ne	// ne = any
    80205a14:	52800601 	mov	w1, #0x30                  	// #48
    80205a18:	390583e1 	strb	w1, [sp, #352]
    80205a1c:	390587e0 	strb	w0, [sp, #353]
    80205a20:	9106a3fb 	add	x27, sp, #0x1a8
    80205a24:	d2800019 	mov	x25, #0x0                   	// #0
    80205a28:	71018cff 	cmp	w7, #0x63
    80205a2c:	540054ec 	b.gt	802064c8 <_vfprintf_r+0x24c8>
    80205a30:	9e660100 	fmov	x0, d8
    80205a34:	d360fc00 	lsr	x0, x0, #32
    80205a38:	36f85420 	tbz	w0, #31, 802064bc <_vfprintf_r+0x24bc>
    80205a3c:	1e614100 	fneg	d0, d8
    80205a40:	528005a0 	mov	w0, #0x2d                  	// #45
    80205a44:	b900bbe0 	str	w0, [sp, #184]
    80205a48:	9105a3e0 	add	x0, sp, #0x168
    80205a4c:	b9008be9 	str	w9, [sp, #136]
    80205a50:	2912afe8 	stp	w8, w11, [sp, #148]
    80205a54:	f90063ea 	str	x10, [sp, #192]
    80205a58:	b900f3e7 	str	w7, [sp, #240]
    80205a5c:	94001ba5 	bl	8020c8f0 <frexp>
    80205a60:	1e681001 	fmov	d1, #1.250000000000000000e-01
    80205a64:	b9408be9 	ldr	w9, [sp, #136]
    80205a68:	f94063ea 	ldr	x10, [sp, #192]
    80205a6c:	1e610801 	fmul	d1, d0, d1
    80205a70:	2952afe8 	ldp	w8, w11, [sp, #148]
    80205a74:	b940f3e7 	ldr	w7, [sp, #240]
    80205a78:	1e602028 	fcmp	d1, #0.0
    80205a7c:	54000061 	b.ne	80205a88 <_vfprintf_r+0x1a88>  // b.any
    80205a80:	52800020 	mov	w0, #0x1                   	// #1
    80205a84:	b9016be0 	str	w0, [sp, #360]
    80205a88:	2a0703e3 	mov	w3, w7
    80205a8c:	7101851f 	cmp	w8, #0x61
    80205a90:	91000463 	add	x3, x3, #0x1
    80205a94:	f0000040 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    80205a98:	f0000042 	adrp	x2, 80210000 <_wcsnrtombs_l+0x110>
    80205a9c:	912f4000 	add	x0, x0, #0xbd0
    80205aa0:	912fa042 	add	x2, x2, #0xbe8
    80205aa4:	8b030363 	add	x3, x27, x3
    80205aa8:	9a801042 	csel	x2, x2, x0, ne	// ne = any
    80205aac:	1e661002 	fmov	d2, #1.600000000000000000e+01
    80205ab0:	aa1b03e0 	mov	x0, x27
    80205ab4:	14000003 	b	80205ac0 <_vfprintf_r+0x1ac0>
    80205ab8:	1e602028 	fcmp	d1, #0.0
    80205abc:	54009920 	b.eq	80206de0 <_vfprintf_r+0x2de0>  // b.none
    80205ac0:	1e620821 	fmul	d1, d1, d2
    80205ac4:	aa0003ec 	mov	x12, x0
    80205ac8:	1e780021 	fcvtzs	w1, d1
    80205acc:	1e620020 	scvtf	d0, w1
    80205ad0:	3861c844 	ldrb	w4, [x2, w1, sxtw]
    80205ad4:	38001404 	strb	w4, [x0], #1
    80205ad8:	1e603821 	fsub	d1, d1, d0
    80205adc:	eb00007f 	cmp	x3, x0
    80205ae0:	54fffec1 	b.ne	80205ab8 <_vfprintf_r+0x1ab8>  // b.any
    80205ae4:	1e6c1000 	fmov	d0, #5.000000000000000000e-01
    80205ae8:	1e602030 	fcmpe	d1, d0
    80205aec:	5400008c 	b.gt	80205afc <_vfprintf_r+0x1afc>
    80205af0:	1e602020 	fcmp	d1, d0
    80205af4:	540002a1 	b.ne	80205b48 <_vfprintf_r+0x1b48>  // b.any
    80205af8:	36000281 	tbz	w1, #0, 80205b48 <_vfprintf_r+0x1b48>
    80205afc:	f900c7ec 	str	x12, [sp, #392]
    80205b00:	aa0003e1 	mov	x1, x0
    80205b04:	39403c44 	ldrb	w4, [x2, #15]
    80205b08:	385ff003 	ldurb	w3, [x0, #-1]
    80205b0c:	6b04007f 	cmp	w3, w4
    80205b10:	54000121 	b.ne	80205b34 <_vfprintf_r+0x1b34>  // b.any
    80205b14:	52800607 	mov	w7, #0x30                  	// #48
    80205b18:	381ff027 	sturb	w7, [x1, #-1]
    80205b1c:	f940c7e1 	ldr	x1, [sp, #392]
    80205b20:	d1000423 	sub	x3, x1, #0x1
    80205b24:	f900c7e3 	str	x3, [sp, #392]
    80205b28:	385ff023 	ldurb	w3, [x1, #-1]
    80205b2c:	6b03009f 	cmp	w4, w3
    80205b30:	54ffff40 	b.eq	80205b18 <_vfprintf_r+0x1b18>  // b.none
    80205b34:	11000464 	add	w4, w3, #0x1
    80205b38:	12001c84 	and	w4, w4, #0xff
    80205b3c:	7100e47f 	cmp	w3, #0x39
    80205b40:	54004e80 	b.eq	80206510 <_vfprintf_r+0x2510>  // b.none
    80205b44:	381ff024 	sturb	w4, [x1, #-1]
    80205b48:	b9416bf8 	ldr	w24, [sp, #360]
    80205b4c:	4b1b0000 	sub	w0, w0, w27
    80205b50:	11003d01 	add	w1, w8, #0xf
    80205b54:	321f0129 	orr	w9, w9, #0x2
    80205b58:	12001c21 	and	w1, w1, #0xff
    80205b5c:	52800022 	mov	w2, #0x1                   	// #1
    80205b60:	b90097e0 	str	w0, [sp, #148]
    80205b64:	51000700 	sub	w0, w24, #0x1
    80205b68:	b9016be0 	str	w0, [sp, #360]
    80205b6c:	14000167 	b	80206108 <_vfprintf_r+0x2108>
    80205b70:	52800601 	mov	w1, #0x30                  	// #48
    80205b74:	321f0129 	orr	w9, w9, #0x2
    80205b78:	390583e1 	strb	w1, [sp, #352]
    80205b7c:	390587e8 	strb	w8, [sp, #353]
    80205b80:	17ffff57 	b	802058dc <_vfprintf_r+0x18dc>
    80205b84:	910643e2 	add	x2, sp, #0x190
    80205b88:	aa1503e1 	mov	x1, x21
    80205b8c:	aa1303e0 	mov	x0, x19
    80205b90:	b9008be9 	str	w9, [sp, #136]
    80205b94:	b9009beb 	str	w11, [sp, #152]
    80205b98:	f9005fea 	str	x10, [sp, #184]
    80205b9c:	94000655 	bl	802074f0 <__sprint_r>
    80205ba0:	35ff6500 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80205ba4:	f9405fea 	ldr	x10, [sp, #184]
    80205ba8:	aa1603fc 	mov	x28, x22
    80205bac:	f940d3e0 	ldr	x0, [sp, #416]
    80205bb0:	b9408be9 	ldr	w9, [sp, #136]
    80205bb4:	b9409beb 	ldr	w11, [sp, #152]
    80205bb8:	17fffa70 	b	80204578 <_vfprintf_r+0x578>
    80205bbc:	910603e0 	add	x0, sp, #0x180
    80205bc0:	d2800102 	mov	x2, #0x8                   	// #8
    80205bc4:	52800001 	mov	w1, #0x0                   	// #0
    80205bc8:	b9008be9 	str	w9, [sp, #136]
    80205bcc:	b9009be8 	str	w8, [sp, #152]
    80205bd0:	b900bbeb 	str	w11, [sp, #184]
    80205bd4:	b900c3e7 	str	w7, [sp, #192]
    80205bd8:	f90067ea 	str	x10, [sp, #200]
    80205bdc:	f900c7fb 	str	x27, [sp, #392]
    80205be0:	97fff6b8 	bl	802036c0 <memset>
    80205be4:	b940c3e7 	ldr	w7, [sp, #192]
    80205be8:	f94067ea 	ldr	x10, [sp, #200]
    80205bec:	b9408be9 	ldr	w9, [sp, #136]
    80205bf0:	b9409be8 	ldr	w8, [sp, #152]
    80205bf4:	b940bbeb 	ldr	w11, [sp, #184]
    80205bf8:	37f84b07 	tbnz	w7, #31, 80206558 <_vfprintf_r+0x2558>
    80205bfc:	d2800018 	mov	x24, #0x0                   	// #0
    80205c00:	52800017 	mov	w23, #0x0                   	// #0
    80205c04:	2a0803fa 	mov	w26, w8
    80205c08:	2a0703f9 	mov	w25, w7
    80205c0c:	f90047f5 	str	x21, [sp, #136]
    80205c10:	2a1703f5 	mov	w21, w23
    80205c14:	aa1803f7 	mov	x23, x24
    80205c18:	aa0a03f8 	mov	x24, x10
    80205c1c:	b9009be9 	str	w9, [sp, #152]
    80205c20:	b900bbeb 	str	w11, [sp, #184]
    80205c24:	1400000d 	b	80205c58 <_vfprintf_r+0x1c58>
    80205c28:	910603e3 	add	x3, sp, #0x180
    80205c2c:	9106a3e1 	add	x1, sp, #0x1a8
    80205c30:	aa1303e0 	mov	x0, x19
    80205c34:	94000f83 	bl	80209a40 <_wcrtomb_r>
    80205c38:	3100041f 	cmn	w0, #0x1
    80205c3c:	54008520 	b.eq	80206ce0 <_vfprintf_r+0x2ce0>  // b.none
    80205c40:	0b0002a0 	add	w0, w21, w0
    80205c44:	6b19001f 	cmp	w0, w25
    80205c48:	540000ec 	b.gt	80205c64 <_vfprintf_r+0x1c64>
    80205c4c:	910012f7 	add	x23, x23, #0x4
    80205c50:	54009320 	b.eq	80206eb4 <_vfprintf_r+0x2eb4>  // b.none
    80205c54:	2a0003f5 	mov	w21, w0
    80205c58:	f940c7e0 	ldr	x0, [sp, #392]
    80205c5c:	b8776802 	ldr	w2, [x0, x23]
    80205c60:	35fffe42 	cbnz	w2, 80205c28 <_vfprintf_r+0x1c28>
    80205c64:	2a1503f7 	mov	w23, w21
    80205c68:	b9409be9 	ldr	w9, [sp, #152]
    80205c6c:	f94047f5 	ldr	x21, [sp, #136]
    80205c70:	2a1a03e8 	mov	w8, w26
    80205c74:	b940bbeb 	ldr	w11, [sp, #184]
    80205c78:	aa1803ea 	mov	x10, x24
    80205c7c:	340063f7 	cbz	w23, 802068f8 <_vfprintf_r+0x28f8>
    80205c80:	71018eff 	cmp	w23, #0x63
    80205c84:	5400776d 	b.le	80206b70 <_vfprintf_r+0x2b70>
    80205c88:	110006e1 	add	w1, w23, #0x1
    80205c8c:	aa1303e0 	mov	x0, x19
    80205c90:	b9008be9 	str	w9, [sp, #136]
    80205c94:	93407c21 	sxtw	x1, w1
    80205c98:	b9009be8 	str	w8, [sp, #152]
    80205c9c:	b900bbeb 	str	w11, [sp, #184]
    80205ca0:	f90063ea 	str	x10, [sp, #192]
    80205ca4:	94000d67 	bl	80209240 <_malloc_r>
    80205ca8:	f94063ea 	ldr	x10, [sp, #192]
    80205cac:	aa0003fb 	mov	x27, x0
    80205cb0:	b9408be9 	ldr	w9, [sp, #136]
    80205cb4:	b9409be8 	ldr	w8, [sp, #152]
    80205cb8:	b940bbeb 	ldr	w11, [sp, #184]
    80205cbc:	b400b000 	cbz	x0, 802072bc <_vfprintf_r+0x32bc>
    80205cc0:	aa0003f9 	mov	x25, x0
    80205cc4:	d2800102 	mov	x2, #0x8                   	// #8
    80205cc8:	52800001 	mov	w1, #0x0                   	// #0
    80205ccc:	910603e0 	add	x0, sp, #0x180
    80205cd0:	b9008be9 	str	w9, [sp, #136]
    80205cd4:	b9009be8 	str	w8, [sp, #152]
    80205cd8:	b900bbeb 	str	w11, [sp, #184]
    80205cdc:	f90063ea 	str	x10, [sp, #192]
    80205ce0:	97fff678 	bl	802036c0 <memset>
    80205ce4:	93407ee0 	sxtw	x0, w23
    80205ce8:	910603e4 	add	x4, sp, #0x180
    80205cec:	aa0003f8 	mov	x24, x0
    80205cf0:	aa0003e3 	mov	x3, x0
    80205cf4:	910623e2 	add	x2, sp, #0x188
    80205cf8:	aa1b03e1 	mov	x1, x27
    80205cfc:	aa1303e0 	mov	x0, x19
    80205d00:	940014f4 	bl	8020b0d0 <_wcsrtombs_r>
    80205d04:	f94063ea 	ldr	x10, [sp, #192]
    80205d08:	eb00031f 	cmp	x24, x0
    80205d0c:	b9408be9 	ldr	w9, [sp, #136]
    80205d10:	b9409be8 	ldr	w8, [sp, #152]
    80205d14:	b940bbeb 	ldr	w11, [sp, #184]
    80205d18:	5400ac81 	b.ne	802072a8 <_vfprintf_r+0x32a8>  // b.any
    80205d1c:	3837cb7f 	strb	wzr, [x27, w23, sxtw]
    80205d20:	710002ff 	cmp	w23, #0x0
    80205d24:	b9008bff 	str	wzr, [sp, #136]
    80205d28:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    80205d2c:	39457fe1 	ldrb	w1, [sp, #351]
    80205d30:	52800007 	mov	w7, #0x0                   	// #0
    80205d34:	b9009bff 	str	wzr, [sp, #152]
    80205d38:	52800018 	mov	w24, #0x0                   	// #0
    80205d3c:	34ff2ca1 	cbz	w1, 802042d0 <_vfprintf_r+0x2d0>
    80205d40:	17fffbb8 	b	80204c20 <_vfprintf_r+0xc20>
    80205d44:	b9408be9 	ldr	w9, [sp, #136]
    80205d48:	aa1c03ea 	mov	x10, x28
    80205d4c:	b9409beb 	ldr	w11, [sp, #152]
    80205d50:	aa0203fc 	mov	x28, x2
    80205d54:	aa1803e4 	mov	x4, x24
    80205d58:	93407ef7 	sxtw	x23, w23
    80205d5c:	11000421 	add	w1, w1, #0x1
    80205d60:	8b170000 	add	x0, x0, x23
    80205d64:	b9019be1 	str	w1, [sp, #408]
    80205d68:	f900d3e0 	str	x0, [sp, #416]
    80205d6c:	a9005f84 	stp	x4, x23, [x28]
    80205d70:	71001c3f 	cmp	w1, #0x7
    80205d74:	54ff536c 	b.gt	802047e0 <_vfprintf_r+0x7e0>
    80205d78:	9100439c 	add	x28, x28, #0x10
    80205d7c:	17fff989 	b	802043a0 <_vfprintf_r+0x3a0>
    80205d80:	910833f7 	add	x23, sp, #0x20c
    80205d84:	12160343 	and	w3, w26, #0x400
    80205d88:	b202e7f8 	mov	x24, #0xcccccccccccccccc    	// #-3689348814741910324
    80205d8c:	aa1703e2 	mov	x2, x23
    80205d90:	aa1703e4 	mov	x4, x23
    80205d94:	52800005 	mov	w5, #0x0                   	// #0
    80205d98:	aa1303f7 	mov	x23, x19
    80205d9c:	f29999b8 	movk	x24, #0xcccd
    80205da0:	2a0303f3 	mov	w19, w3
    80205da4:	aa1503e3 	mov	x3, x21
    80205da8:	f9407ff5 	ldr	x21, [sp, #248]
    80205dac:	14000007 	b	80205dc8 <_vfprintf_r+0x1dc8>
    80205db0:	9bd87c19 	umulh	x25, x0, x24
    80205db4:	d343ff39 	lsr	x25, x25, #3
    80205db8:	f100241f 	cmp	x0, #0x9
    80205dbc:	54000249 	b.ls	80205e04 <_vfprintf_r+0x1e04>  // b.plast
    80205dc0:	aa1903e0 	mov	x0, x25
    80205dc4:	aa1b03e2 	mov	x2, x27
    80205dc8:	9bd87c19 	umulh	x25, x0, x24
    80205dcc:	110004a5 	add	w5, w5, #0x1
    80205dd0:	d100045b 	sub	x27, x2, #0x1
    80205dd4:	d343ff39 	lsr	x25, x25, #3
    80205dd8:	8b190b21 	add	x1, x25, x25, lsl #2
    80205ddc:	cb010401 	sub	x1, x0, x1, lsl #1
    80205de0:	1100c021 	add	w1, w1, #0x30
    80205de4:	381ff041 	sturb	w1, [x2, #-1]
    80205de8:	34fffe53 	cbz	w19, 80205db0 <_vfprintf_r+0x1db0>
    80205dec:	394002a1 	ldrb	w1, [x21]
    80205df0:	7103fc3f 	cmp	w1, #0xff
    80205df4:	7a451020 	ccmp	w1, w5, #0x0, ne	// ne = any
    80205df8:	54fffdc1 	b.ne	80205db0 <_vfprintf_r+0x1db0>  // b.any
    80205dfc:	f100241f 	cmp	x0, #0x9
    80205e00:	54006268 	b.hi	80206a4c <_vfprintf_r+0x2a4c>  // b.pmore
    80205e04:	aa1703f3 	mov	x19, x23
    80205e08:	aa0403f7 	mov	x23, x4
    80205e0c:	b90097e5 	str	w5, [sp, #148]
    80205e10:	f9007ff5 	str	x21, [sp, #248]
    80205e14:	aa0303f5 	mov	x21, x3
    80205e18:	17fffcd5 	b	8020516c <_vfprintf_r+0x116c>
    80205e1c:	710018ff 	cmp	w7, #0x6
    80205e20:	528000c3 	mov	w3, #0x6                   	// #6
    80205e24:	1a8390fa 	csel	w26, w7, w3, ls	// ls = plast
    80205e28:	f0000045 	adrp	x5, 80210000 <_wcsnrtombs_l+0x110>
    80205e2c:	2a1a03f7 	mov	w23, w26
    80205e30:	913000bb 	add	x27, x5, #0xc00
    80205e34:	d2800019 	mov	x25, #0x0                   	// #0
    80205e38:	52800001 	mov	w1, #0x0                   	// #0
    80205e3c:	52800007 	mov	w7, #0x0                   	// #0
    80205e40:	52800018 	mov	w24, #0x0                   	// #0
    80205e44:	b9008bff 	str	wzr, [sp, #136]
    80205e48:	b9009bff 	str	wzr, [sp, #152]
    80205e4c:	17fff921 	b	802042d0 <_vfprintf_r+0x2d0>
    80205e50:	b94093e0 	ldr	w0, [sp, #144]
    80205e54:	11002001 	add	w1, w0, #0x8
    80205e58:	7100003f 	cmp	w1, #0x0
    80205e5c:	5400242d 	b.le	802062e0 <_vfprintf_r+0x22e0>
    80205e60:	f9403fe0 	ldr	x0, [sp, #120]
    80205e64:	b90093e1 	str	w1, [sp, #144]
    80205e68:	91003c02 	add	x2, x0, #0xf
    80205e6c:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205e70:	f9003fe1 	str	x1, [sp, #120]
    80205e74:	17fffc92 	b	802050bc <_vfprintf_r+0x10bc>
    80205e78:	f940d3e0 	ldr	x0, [sp, #416]
    80205e7c:	b50030e0 	cbnz	x0, 80206498 <_vfprintf_r+0x2498>
    80205e80:	79c022a0 	ldrsh	w0, [x21, #16]
    80205e84:	b9019bff 	str	wzr, [sp, #408]
    80205e88:	17fffa73 	b	80204854 <_vfprintf_r+0x854>
    80205e8c:	f0000044 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    80205e90:	b9419be1 	ldr	w1, [sp, #408]
    80205e94:	913e4084 	add	x4, x4, #0xf90
    80205e98:	710042ff 	cmp	w23, #0x10
    80205e9c:	54001bad 	b.le	80206210 <_vfprintf_r+0x2210>
    80205ea0:	aa1c03e2 	mov	x2, x28
    80205ea4:	d2800208 	mov	x8, #0x10                  	// #16
    80205ea8:	aa0a03fc 	mov	x28, x10
    80205eac:	f9005fec 	str	x12, [sp, #184]
    80205eb0:	b900c3e9 	str	w9, [sp, #192]
    80205eb4:	b900cbeb 	str	w11, [sp, #200]
    80205eb8:	b900d3f8 	str	w24, [sp, #208]
    80205ebc:	aa0403f8 	mov	x24, x4
    80205ec0:	14000004 	b	80205ed0 <_vfprintf_r+0x1ed0>
    80205ec4:	510042f7 	sub	w23, w23, #0x10
    80205ec8:	710042ff 	cmp	w23, #0x10
    80205ecc:	5400194d 	b.le	802061f4 <_vfprintf_r+0x21f4>
    80205ed0:	91004000 	add	x0, x0, #0x10
    80205ed4:	11000421 	add	w1, w1, #0x1
    80205ed8:	a9002058 	stp	x24, x8, [x2]
    80205edc:	91004042 	add	x2, x2, #0x10
    80205ee0:	b9019be1 	str	w1, [sp, #408]
    80205ee4:	f900d3e0 	str	x0, [sp, #416]
    80205ee8:	71001c3f 	cmp	w1, #0x7
    80205eec:	54fffecd 	b.le	80205ec4 <_vfprintf_r+0x1ec4>
    80205ef0:	910643e2 	add	x2, sp, #0x190
    80205ef4:	aa1503e1 	mov	x1, x21
    80205ef8:	aa1303e0 	mov	x0, x19
    80205efc:	9400057d 	bl	802074f0 <__sprint_r>
    80205f00:	35ff4a00 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80205f04:	f940d3e0 	ldr	x0, [sp, #416]
    80205f08:	aa1603e2 	mov	x2, x22
    80205f0c:	b9419be1 	ldr	w1, [sp, #408]
    80205f10:	d2800208 	mov	x8, #0x10                  	// #16
    80205f14:	17ffffec 	b	80205ec4 <_vfprintf_r+0x1ec4>
    80205f18:	364820fa 	tbz	w26, #9, 80206334 <_vfprintf_r+0x2334>
    80205f1c:	37f88040 	tbnz	w0, #31, 80206f24 <_vfprintf_r+0x2f24>
    80205f20:	f9403fe0 	ldr	x0, [sp, #120]
    80205f24:	91002c01 	add	x1, x0, #0xb
    80205f28:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205f2c:	f9003fe1 	str	x1, [sp, #120]
    80205f30:	39400000 	ldrb	w0, [x0]
    80205f34:	52800021 	mov	w1, #0x1                   	// #1
    80205f38:	17fffc0e 	b	80204f70 <_vfprintf_r+0xf70>
    80205f3c:	364820c9 	tbz	w9, #9, 80206354 <_vfprintf_r+0x2354>
    80205f40:	37f87c80 	tbnz	w0, #31, 80206ed0 <_vfprintf_r+0x2ed0>
    80205f44:	f9403fe0 	ldr	x0, [sp, #120]
    80205f48:	91002c01 	add	x1, x0, #0xb
    80205f4c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205f50:	39400000 	ldrb	w0, [x0]
    80205f54:	f9003fe1 	str	x1, [sp, #120]
    80205f58:	17fffc04 	b	80204f68 <_vfprintf_r+0xf68>
    80205f5c:	f94053e2 	ldr	x2, [sp, #160]
    80205f60:	b94093e0 	ldr	w0, [sp, #144]
    80205f64:	b90093e1 	str	w1, [sp, #144]
    80205f68:	8b20c040 	add	x0, x2, w0, sxtw
    80205f6c:	17fffc64 	b	802050fc <_vfprintf_r+0x10fc>
    80205f70:	f94053e2 	ldr	x2, [sp, #160]
    80205f74:	b94093e0 	ldr	w0, [sp, #144]
    80205f78:	b90093e1 	str	w1, [sp, #144]
    80205f7c:	8b20c040 	add	x0, x2, w0, sxtw
    80205f80:	17fffc22 	b	80205008 <_vfprintf_r+0x1008>
    80205f84:	36481ca9 	tbz	w9, #9, 80206318 <_vfprintf_r+0x2318>
    80205f88:	37f86ee0 	tbnz	w0, #31, 80206d64 <_vfprintf_r+0x2d64>
    80205f8c:	f9403fe0 	ldr	x0, [sp, #120]
    80205f90:	91002c01 	add	x1, x0, #0xb
    80205f94:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205f98:	39400000 	ldrb	w0, [x0]
    80205f9c:	f9003fe1 	str	x1, [sp, #120]
    80205fa0:	17fffe4b 	b	802058cc <_vfprintf_r+0x18cc>
    80205fa4:	f94053e2 	ldr	x2, [sp, #160]
    80205fa8:	b94093e0 	ldr	w0, [sp, #144]
    80205fac:	b90093e1 	str	w1, [sp, #144]
    80205fb0:	8b20c040 	add	x0, x2, w0, sxtw
    80205fb4:	17fffbec 	b	80204f64 <_vfprintf_r+0xf64>
    80205fb8:	b94093e0 	ldr	w0, [sp, #144]
    80205fbc:	11002001 	add	w1, w0, #0x8
    80205fc0:	7100003f 	cmp	w1, #0x0
    80205fc4:	54001fad 	b.le	802063b8 <_vfprintf_r+0x23b8>
    80205fc8:	f9403fe0 	ldr	x0, [sp, #120]
    80205fcc:	b90093e1 	str	w1, [sp, #144]
    80205fd0:	91002c02 	add	x2, x0, #0xb
    80205fd4:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80205fd8:	f9003fe1 	str	x1, [sp, #120]
    80205fdc:	17fffe07 	b	802057f8 <_vfprintf_r+0x17f8>
    80205fe0:	36481c89 	tbz	w9, #9, 80206370 <_vfprintf_r+0x2370>
    80205fe4:	37f87dc0 	tbnz	w0, #31, 80206f9c <_vfprintf_r+0x2f9c>
    80205fe8:	f9403fe0 	ldr	x0, [sp, #120]
    80205fec:	91002c01 	add	x1, x0, #0xb
    80205ff0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80205ff4:	f9003fe1 	str	x1, [sp, #120]
    80205ff8:	39800000 	ldrsb	x0, [x0]
    80205ffc:	aa0003e1 	mov	x1, x0
    80206000:	17fffc41 	b	80205104 <_vfprintf_r+0x1104>
    80206004:	f94053e2 	ldr	x2, [sp, #160]
    80206008:	b94093e0 	ldr	w0, [sp, #144]
    8020600c:	b90093e1 	str	w1, [sp, #144]
    80206010:	8b20c040 	add	x0, x2, w0, sxtw
    80206014:	17fffe2d 	b	802058c8 <_vfprintf_r+0x18c8>
    80206018:	310004ff 	cmn	w7, #0x1
    8020601c:	54002760 	b.eq	80206508 <_vfprintf_r+0x2508>  // b.none
    80206020:	71011eff 	cmp	w23, #0x47
    80206024:	7a4008e0 	ccmp	w7, #0x0, #0x0, eq	// eq = none
    80206028:	1a9f14e7 	csinc	w7, w7, wzr, ne	// ne = any
    8020602c:	9e660100 	fmov	x0, d8
    80206030:	32180139 	orr	w25, w9, #0x100
    80206034:	d360fc00 	lsr	x0, x0, #32
    80206038:	37f879e0 	tbnz	w0, #31, 80206f74 <_vfprintf_r+0x2f74>
    8020603c:	1e604109 	fmov	d9, d8
    80206040:	b900bbff 	str	wzr, [sp, #184]
    80206044:	2912a3e9 	stp	w9, w8, [sp, #148]
    80206048:	1e604120 	fmov	d0, d9
    8020604c:	b900c3eb 	str	w11, [sp, #192]
    80206050:	f90067ea 	str	x10, [sp, #200]
    80206054:	71011aff 	cmp	w23, #0x46
    80206058:	540042c1 	b.ne	802068b0 <_vfprintf_r+0x28b0>  // b.any
    8020605c:	2a0703e2 	mov	w2, w7
    80206060:	52800061 	mov	w1, #0x3                   	// #3
    80206064:	910623e5 	add	x5, sp, #0x188
    80206068:	910603e4 	add	x4, sp, #0x180
    8020606c:	9105a3e3 	add	x3, sp, #0x168
    80206070:	aa1303e0 	mov	x0, x19
    80206074:	b9008be7 	str	w7, [sp, #136]
    80206078:	94001492 	bl	8020b2c0 <_dtoa_r>
    8020607c:	b9408be7 	ldr	w7, [sp, #136]
    80206080:	aa0003fb 	mov	x27, x0
    80206084:	39400001 	ldrb	w1, [x0]
    80206088:	f94067ea 	ldr	x10, [sp, #200]
    8020608c:	7100c03f 	cmp	w1, #0x30
    80206090:	2952a3e9 	ldp	w9, w8, [sp, #148]
    80206094:	8b27c000 	add	x0, x0, w7, sxtw
    80206098:	b940c3eb 	ldr	w11, [sp, #192]
    8020609c:	54005240 	b.eq	80206ae4 <_vfprintf_r+0x2ae4>  // b.none
    802060a0:	b9416be1 	ldr	w1, [sp, #360]
    802060a4:	8b21c001 	add	x1, x0, w1, sxtw
    802060a8:	1e602128 	fcmp	d9, #0.0
    802060ac:	54004f60 	b.eq	80206a98 <_vfprintf_r+0x2a98>  // b.none
    802060b0:	f940c7e0 	ldr	x0, [sp, #392]
    802060b4:	52800603 	mov	w3, #0x30                  	// #48
    802060b8:	eb00003f 	cmp	x1, x0
    802060bc:	540000e9 	b.ls	802060d8 <_vfprintf_r+0x20d8>  // b.plast
    802060c0:	91000402 	add	x2, x0, #0x1
    802060c4:	f900c7e2 	str	x2, [sp, #392]
    802060c8:	39000003 	strb	w3, [x0]
    802060cc:	f940c7e0 	ldr	x0, [sp, #392]
    802060d0:	eb00003f 	cmp	x1, x0
    802060d4:	54ffff68 	b.hi	802060c0 <_vfprintf_r+0x20c0>  // b.pmore
    802060d8:	b9416bf8 	ldr	w24, [sp, #360]
    802060dc:	cb1b0000 	sub	x0, x0, x27
    802060e0:	b90097e0 	str	w0, [sp, #148]
    802060e4:	71011eff 	cmp	w23, #0x47
    802060e8:	54002200 	b.eq	80206528 <_vfprintf_r+0x2528>  // b.none
    802060ec:	51000700 	sub	w0, w24, #0x1
    802060f0:	71011aff 	cmp	w23, #0x46
    802060f4:	54005040 	b.eq	80206afc <_vfprintf_r+0x2afc>  // b.none
    802060f8:	12001d01 	and	w1, w8, #0xff
    802060fc:	52800002 	mov	w2, #0x0                   	// #0
    80206100:	d2800019 	mov	x25, #0x0                   	// #0
    80206104:	b9016be0 	str	w0, [sp, #360]
    80206108:	3905c3e1 	strb	w1, [sp, #368]
    8020610c:	52800561 	mov	w1, #0x2b                  	// #43
    80206110:	36f80080 	tbz	w0, #31, 80206120 <_vfprintf_r+0x2120>
    80206114:	52800020 	mov	w0, #0x1                   	// #1
    80206118:	4b180000 	sub	w0, w0, w24
    8020611c:	528005a1 	mov	w1, #0x2d                  	// #45
    80206120:	3905c7e1 	strb	w1, [sp, #369]
    80206124:	7100241f 	cmp	w0, #0x9
    80206128:	54005bcd 	b.le	80206ca0 <_vfprintf_r+0x2ca0>
    8020612c:	91063fec 	add	x12, sp, #0x18f
    80206130:	529999ad 	mov	w13, #0xcccd                	// #52429
    80206134:	aa0c03e4 	mov	x4, x12
    80206138:	72b9998d 	movk	w13, #0xcccc, lsl #16
    8020613c:	9bad7c02 	umull	x2, w0, w13
    80206140:	aa0403e3 	mov	x3, x4
    80206144:	2a0003e5 	mov	w5, w0
    80206148:	d1000484 	sub	x4, x4, #0x1
    8020614c:	d363fc42 	lsr	x2, x2, #35
    80206150:	0b020841 	add	w1, w2, w2, lsl #2
    80206154:	4b010401 	sub	w1, w0, w1, lsl #1
    80206158:	2a0203e0 	mov	w0, w2
    8020615c:	1100c021 	add	w1, w1, #0x30
    80206160:	381ff061 	sturb	w1, [x3, #-1]
    80206164:	71018cbf 	cmp	w5, #0x63
    80206168:	54fffeac 	b.gt	8020613c <_vfprintf_r+0x213c>
    8020616c:	1100c040 	add	w0, w2, #0x30
    80206170:	381ff080 	sturb	w0, [x4, #-1]
    80206174:	d1000860 	sub	x0, x3, #0x2
    80206178:	eb0c001f 	cmp	x0, x12
    8020617c:	54007e82 	b.cs	8020714c <_vfprintf_r+0x314c>  // b.hs, b.nlast
    80206180:	9105cbe1 	add	x1, sp, #0x172
    80206184:	38401402 	ldrb	w2, [x0], #1
    80206188:	38001422 	strb	w2, [x1], #1
    8020618c:	eb0c001f 	cmp	x0, x12
    80206190:	54ffffa1 	b.ne	80206184 <_vfprintf_r+0x2184>  // b.any
    80206194:	910a43e0 	add	x0, sp, #0x290
    80206198:	cb030003 	sub	x3, x0, x3
    8020619c:	5103f460 	sub	w0, w3, #0xfd
    802061a0:	b900f3e0 	str	w0, [sp, #240]
    802061a4:	b94097e0 	ldr	w0, [sp, #148]
    802061a8:	b940f3e1 	ldr	w1, [sp, #240]
    802061ac:	0b010017 	add	w23, w0, w1
    802061b0:	7100041f 	cmp	w0, #0x1
    802061b4:	54005b6d 	b.le	80206d20 <_vfprintf_r+0x2d20>
    802061b8:	b940abe0 	ldr	w0, [sp, #168]
    802061bc:	0b0002f7 	add	w23, w23, w0
    802061c0:	12157929 	and	w9, w9, #0xfffffbff
    802061c4:	710002ff 	cmp	w23, #0x0
    802061c8:	32180129 	orr	w9, w9, #0x100
    802061cc:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    802061d0:	52800018 	mov	w24, #0x0                   	// #0
    802061d4:	b9008bff 	str	wzr, [sp, #136]
    802061d8:	b9009bff 	str	wzr, [sp, #152]
    802061dc:	b940bbe0 	ldr	w0, [sp, #184]
    802061e0:	35001b00 	cbnz	w0, 80206540 <_vfprintf_r+0x2540>
    802061e4:	39457fe1 	ldrb	w1, [sp, #351]
    802061e8:	52800007 	mov	w7, #0x0                   	// #0
    802061ec:	34ff0721 	cbz	w1, 802042d0 <_vfprintf_r+0x2d0>
    802061f0:	17fffa8c 	b	80204c20 <_vfprintf_r+0xc20>
    802061f4:	f9405fec 	ldr	x12, [sp, #184]
    802061f8:	aa1803e4 	mov	x4, x24
    802061fc:	b940c3e9 	ldr	w9, [sp, #192]
    80206200:	aa1c03ea 	mov	x10, x28
    80206204:	b940cbeb 	ldr	w11, [sp, #200]
    80206208:	aa0203fc 	mov	x28, x2
    8020620c:	b940d3f8 	ldr	w24, [sp, #208]
    80206210:	93407ee7 	sxtw	x7, w23
    80206214:	11000421 	add	w1, w1, #0x1
    80206218:	8b070000 	add	x0, x0, x7
    8020621c:	a9001f84 	stp	x4, x7, [x28]
    80206220:	9100439c 	add	x28, x28, #0x10
    80206224:	b9019be1 	str	w1, [sp, #408]
    80206228:	f900d3e0 	str	x0, [sp, #416]
    8020622c:	71001c3f 	cmp	w1, #0x7
    80206230:	54ff89cd 	b.le	80205368 <_vfprintf_r+0x1368>
    80206234:	910643e2 	add	x2, sp, #0x190
    80206238:	aa1503e1 	mov	x1, x21
    8020623c:	aa1303e0 	mov	x0, x19
    80206240:	f9005fec 	str	x12, [sp, #184]
    80206244:	b900c3e9 	str	w9, [sp, #192]
    80206248:	b900cbeb 	str	w11, [sp, #200]
    8020624c:	f9006bea 	str	x10, [sp, #208]
    80206250:	940004a8 	bl	802074f0 <__sprint_r>
    80206254:	35ff2f60 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80206258:	f9405fec 	ldr	x12, [sp, #184]
    8020625c:	aa1603fc 	mov	x28, x22
    80206260:	f9406bea 	ldr	x10, [sp, #208]
    80206264:	f940d3e0 	ldr	x0, [sp, #416]
    80206268:	b940c3e9 	ldr	w9, [sp, #192]
    8020626c:	b940cbeb 	ldr	w11, [sp, #200]
    80206270:	17fffc3e 	b	80205368 <_vfprintf_r+0x1368>
    80206274:	36070969 	tbz	w9, #0, 802043a0 <_vfprintf_r+0x3a0>
    80206278:	a94a8fe2 	ldp	x2, x3, [sp, #168]
    8020627c:	a9000b83 	stp	x3, x2, [x28]
    80206280:	b9419be1 	ldr	w1, [sp, #408]
    80206284:	91004386 	add	x6, x28, #0x10
    80206288:	11000421 	add	w1, w1, #0x1
    8020628c:	b9019be1 	str	w1, [sp, #408]
    80206290:	8b000040 	add	x0, x2, x0
    80206294:	f900d3e0 	str	x0, [sp, #416]
    80206298:	71001c3f 	cmp	w1, #0x7
    8020629c:	54ff28ed 	b.le	802047b8 <_vfprintf_r+0x7b8>
    802062a0:	910643e2 	add	x2, sp, #0x190
    802062a4:	aa1503e1 	mov	x1, x21
    802062a8:	aa1303e0 	mov	x0, x19
    802062ac:	b9008be9 	str	w9, [sp, #136]
    802062b0:	b9009beb 	str	w11, [sp, #152]
    802062b4:	f9005fea 	str	x10, [sp, #184]
    802062b8:	9400048e 	bl	802074f0 <__sprint_r>
    802062bc:	35ff2c20 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802062c0:	f9405fea 	ldr	x10, [sp, #184]
    802062c4:	aa1603e6 	mov	x6, x22
    802062c8:	f940d3e0 	ldr	x0, [sp, #416]
    802062cc:	b9408be9 	ldr	w9, [sp, #136]
    802062d0:	b9409beb 	ldr	w11, [sp, #152]
    802062d4:	b9416be2 	ldr	w2, [sp, #360]
    802062d8:	b9419be1 	ldr	w1, [sp, #408]
    802062dc:	17fff936 	b	802047b4 <_vfprintf_r+0x7b4>
    802062e0:	f94053e2 	ldr	x2, [sp, #160]
    802062e4:	b94093e0 	ldr	w0, [sp, #144]
    802062e8:	b90093e1 	str	w1, [sp, #144]
    802062ec:	8b20c040 	add	x0, x2, w0, sxtw
    802062f0:	17fffb73 	b	802050bc <_vfprintf_r+0x10bc>
    802062f4:	37f862c0 	tbnz	w0, #31, 80206f4c <_vfprintf_r+0x2f4c>
    802062f8:	f9403fe0 	ldr	x0, [sp, #120]
    802062fc:	91003c01 	add	x1, x0, #0xf
    80206300:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80206304:	f9003fe1 	str	x1, [sp, #120]
    80206308:	f9400000 	ldr	x0, [x0]
    8020630c:	7940ebe1 	ldrh	w1, [sp, #116]
    80206310:	79000001 	strh	w1, [x0]
    80206314:	17fff780 	b	80204114 <_vfprintf_r+0x114>
    80206318:	37f867e0 	tbnz	w0, #31, 80207014 <_vfprintf_r+0x3014>
    8020631c:	f9403fe0 	ldr	x0, [sp, #120]
    80206320:	91002c01 	add	x1, x0, #0xb
    80206324:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80206328:	b9400000 	ldr	w0, [x0]
    8020632c:	f9003fe1 	str	x1, [sp, #120]
    80206330:	17fffd67 	b	802058cc <_vfprintf_r+0x18cc>
    80206334:	37f85040 	tbnz	w0, #31, 80206d3c <_vfprintf_r+0x2d3c>
    80206338:	f9403fe0 	ldr	x0, [sp, #120]
    8020633c:	91002c01 	add	x1, x0, #0xb
    80206340:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80206344:	f9003fe1 	str	x1, [sp, #120]
    80206348:	b9400000 	ldr	w0, [x0]
    8020634c:	52800021 	mov	w1, #0x1                   	// #1
    80206350:	17fffb08 	b	80204f70 <_vfprintf_r+0xf70>
    80206354:	37f86380 	tbnz	w0, #31, 80206fc4 <_vfprintf_r+0x2fc4>
    80206358:	f9403fe0 	ldr	x0, [sp, #120]
    8020635c:	91002c01 	add	x1, x0, #0xb
    80206360:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80206364:	b9400000 	ldr	w0, [x0]
    80206368:	f9003fe1 	str	x1, [sp, #120]
    8020636c:	17fffaff 	b	80204f68 <_vfprintf_r+0xf68>
    80206370:	37f85c60 	tbnz	w0, #31, 80206efc <_vfprintf_r+0x2efc>
    80206374:	f9403fe0 	ldr	x0, [sp, #120]
    80206378:	91002c01 	add	x1, x0, #0xb
    8020637c:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80206380:	f9003fe1 	str	x1, [sp, #120]
    80206384:	b9800000 	ldrsw	x0, [x0]
    80206388:	aa0003e1 	mov	x1, x0
    8020638c:	17fffb5e 	b	80205104 <_vfprintf_r+0x1104>
    80206390:	b94093e0 	ldr	w0, [sp, #144]
    80206394:	11002001 	add	w1, w0, #0x8
    80206398:	7100003f 	cmp	w1, #0x0
    8020639c:	5400518d 	b.le	80206dcc <_vfprintf_r+0x2dcc>
    802063a0:	f9403fe0 	ldr	x0, [sp, #120]
    802063a4:	b90093e1 	str	w1, [sp, #144]
    802063a8:	91002c02 	add	x2, x0, #0xb
    802063ac:	927df041 	and	x1, x2, #0xfffffffffffffff8
    802063b0:	f9003fe1 	str	x1, [sp, #120]
    802063b4:	17fffc69 	b	80205558 <_vfprintf_r+0x1558>
    802063b8:	f94053e2 	ldr	x2, [sp, #160]
    802063bc:	b94093e0 	ldr	w0, [sp, #144]
    802063c0:	b90093e1 	str	w1, [sp, #144]
    802063c4:	8b20c040 	add	x0, x2, w0, sxtw
    802063c8:	17fffd0c 	b	802057f8 <_vfprintf_r+0x17f8>
    802063cc:	b94093e0 	ldr	w0, [sp, #144]
    802063d0:	11002001 	add	w1, w0, #0x8
    802063d4:	7100003f 	cmp	w1, #0x0
    802063d8:	54005d6d 	b.le	80206f84 <_vfprintf_r+0x2f84>
    802063dc:	f9403fe0 	ldr	x0, [sp, #120]
    802063e0:	b90093e1 	str	w1, [sp, #144]
    802063e4:	91002c02 	add	x2, x0, #0xb
    802063e8:	927df041 	and	x1, x2, #0xfffffffffffffff8
    802063ec:	79400000 	ldrh	w0, [x0]
    802063f0:	f9003fe1 	str	x1, [sp, #120]
    802063f4:	17fffadd 	b	80204f68 <_vfprintf_r+0xf68>
    802063f8:	aa1b03e0 	mov	x0, x27
    802063fc:	b900bbe9 	str	w9, [sp, #184]
    80206400:	b900c3eb 	str	w11, [sp, #192]
    80206404:	d2800019 	mov	x25, #0x0                   	// #0
    80206408:	f90067ea 	str	x10, [sp, #200]
    8020640c:	97fff53d 	bl	80203900 <strlen>
    80206410:	39457fe1 	ldrb	w1, [sp, #351]
    80206414:	7100001f 	cmp	w0, #0x0
    80206418:	b9008bff 	str	wzr, [sp, #136]
    8020641c:	2a0003f7 	mov	w23, w0
    80206420:	b9009bff 	str	wzr, [sp, #152]
    80206424:	1a9fa01a 	csel	w26, w0, wzr, ge	// ge = tcont
    80206428:	f94067ea 	ldr	x10, [sp, #200]
    8020642c:	52800007 	mov	w7, #0x0                   	// #0
    80206430:	b940bbe9 	ldr	w9, [sp, #184]
    80206434:	52800e68 	mov	w8, #0x73                  	// #115
    80206438:	b940c3eb 	ldr	w11, [sp, #192]
    8020643c:	34fef4a1 	cbz	w1, 802042d0 <_vfprintf_r+0x2d0>
    80206440:	17fff9f8 	b	80204c20 <_vfprintf_r+0xc20>
    80206444:	b94093e0 	ldr	w0, [sp, #144]
    80206448:	11002001 	add	w1, w0, #0x8
    8020644c:	7100003f 	cmp	w1, #0x0
    80206450:	54004dcd 	b.le	80206e08 <_vfprintf_r+0x2e08>
    80206454:	f9403fe0 	ldr	x0, [sp, #120]
    80206458:	b90093e1 	str	w1, [sp, #144]
    8020645c:	91002c02 	add	x2, x0, #0xb
    80206460:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206464:	f9003fe1 	str	x1, [sp, #120]
    80206468:	17fffc33 	b	80205534 <_vfprintf_r+0x1534>
    8020646c:	b94093e0 	ldr	w0, [sp, #144]
    80206470:	11002001 	add	w1, w0, #0x8
    80206474:	7100003f 	cmp	w1, #0x0
    80206478:	540049ed 	b.le	80206db4 <_vfprintf_r+0x2db4>
    8020647c:	f9403fe0 	ldr	x0, [sp, #120]
    80206480:	b90093e1 	str	w1, [sp, #144]
    80206484:	91002c02 	add	x2, x0, #0xb
    80206488:	927df041 	and	x1, x2, #0xfffffffffffffff8
    8020648c:	79400000 	ldrh	w0, [x0]
    80206490:	f9003fe1 	str	x1, [sp, #120]
    80206494:	17fffd0e 	b	802058cc <_vfprintf_r+0x18cc>
    80206498:	aa1303e0 	mov	x0, x19
    8020649c:	910643e2 	add	x2, sp, #0x190
    802064a0:	aa1503e1 	mov	x1, x21
    802064a4:	94000413 	bl	802074f0 <__sprint_r>
    802064a8:	34ffcec0 	cbz	w0, 80205e80 <_vfprintf_r+0x1e80>
    802064ac:	17fff8e9 	b	80204850 <_vfprintf_r+0x850>
    802064b0:	f94052a0 	ldr	x0, [x21, #160]
    802064b4:	94000dd3 	bl	80209c00 <__retarget_lock_release_recursive>
    802064b8:	17fff739 	b	8020419c <_vfprintf_r+0x19c>
    802064bc:	1e604100 	fmov	d0, d8
    802064c0:	b900bbff 	str	wzr, [sp, #184]
    802064c4:	17fffd61 	b	80205a48 <_vfprintf_r+0x1a48>
    802064c8:	110004e1 	add	w1, w7, #0x1
    802064cc:	aa1303e0 	mov	x0, x19
    802064d0:	b9008be7 	str	w7, [sp, #136]
    802064d4:	93407c21 	sxtw	x1, w1
    802064d8:	2912a3e9 	stp	w9, w8, [sp, #148]
    802064dc:	f9005fea 	str	x10, [sp, #184]
    802064e0:	b900f3eb 	str	w11, [sp, #240]
    802064e4:	94000b57 	bl	80209240 <_malloc_r>
    802064e8:	f9405fea 	ldr	x10, [sp, #184]
    802064ec:	aa0003fb 	mov	x27, x0
    802064f0:	b9408be7 	ldr	w7, [sp, #136]
    802064f4:	2952a3e9 	ldp	w9, w8, [sp, #148]
    802064f8:	b940f3eb 	ldr	w11, [sp, #240]
    802064fc:	b4006380 	cbz	x0, 8020716c <_vfprintf_r+0x316c>
    80206500:	aa0003f9 	mov	x25, x0
    80206504:	17fffd4b 	b	80205a30 <_vfprintf_r+0x1a30>
    80206508:	528000c7 	mov	w7, #0x6                   	// #6
    8020650c:	17fffec8 	b	8020602c <_vfprintf_r+0x202c>
    80206510:	39402844 	ldrb	w4, [x2, #10]
    80206514:	17fffd8c 	b	80205b44 <_vfprintf_r+0x1b44>
    80206518:	f940c7e0 	ldr	x0, [sp, #392]
    8020651c:	b9416bf8 	ldr	w24, [sp, #360]
    80206520:	cb1b0000 	sub	x0, x0, x27
    80206524:	b90097e0 	str	w0, [sp, #148]
    80206528:	6b07031f 	cmp	w24, w7
    8020652c:	3a43db01 	ccmn	w24, #0x3, #0x1, le
    80206530:	540017ea 	b.ge	8020682c <_vfprintf_r+0x282c>  // b.tcont
    80206534:	51000908 	sub	w8, w8, #0x2
    80206538:	51000700 	sub	w0, w24, #0x1
    8020653c:	17fffeef 	b	802060f8 <_vfprintf_r+0x20f8>
    80206540:	528005a0 	mov	w0, #0x2d                  	// #45
    80206544:	1100075a 	add	w26, w26, #0x1
    80206548:	528005a1 	mov	w1, #0x2d                  	// #45
    8020654c:	52800007 	mov	w7, #0x0                   	// #0
    80206550:	39057fe0 	strb	w0, [sp, #351]
    80206554:	17fff75f 	b	802042d0 <_vfprintf_r+0x2d0>
    80206558:	910603e4 	add	x4, sp, #0x180
    8020655c:	910623e2 	add	x2, sp, #0x188
    80206560:	aa1303e0 	mov	x0, x19
    80206564:	d2800003 	mov	x3, #0x0                   	// #0
    80206568:	d2800001 	mov	x1, #0x0                   	// #0
    8020656c:	b9008be9 	str	w9, [sp, #136]
    80206570:	b9009be8 	str	w8, [sp, #152]
    80206574:	b900bbeb 	str	w11, [sp, #184]
    80206578:	f90063ea 	str	x10, [sp, #192]
    8020657c:	940012d5 	bl	8020b0d0 <_wcsrtombs_r>
    80206580:	f94063ea 	ldr	x10, [sp, #192]
    80206584:	2a0003f7 	mov	w23, w0
    80206588:	b9408be9 	ldr	w9, [sp, #136]
    8020658c:	3100041f 	cmn	w0, #0x1
    80206590:	b9409be8 	ldr	w8, [sp, #152]
    80206594:	b940bbeb 	ldr	w11, [sp, #184]
    80206598:	54006920 	b.eq	802072bc <_vfprintf_r+0x32bc>  // b.none
    8020659c:	f900c7fb 	str	x27, [sp, #392]
    802065a0:	17fffdb7 	b	80205c7c <_vfprintf_r+0x1c7c>
    802065a4:	528005a0 	mov	w0, #0x2d                  	// #45
    802065a8:	528005a1 	mov	w1, #0x2d                  	// #45
    802065ac:	39057fe0 	strb	w0, [sp, #351]
    802065b0:	17fff98c 	b	80204be0 <_vfprintf_r+0xbe0>
    802065b4:	b940f7e0 	ldr	w0, [sp, #244]
    802065b8:	11004001 	add	w1, w0, #0x10
    802065bc:	7100003f 	cmp	w1, #0x0
    802065c0:	5400386d 	b.le	80206ccc <_vfprintf_r+0x2ccc>
    802065c4:	f9403fe0 	ldr	x0, [sp, #120]
    802065c8:	b900f7e1 	str	w1, [sp, #244]
    802065cc:	91003c00 	add	x0, x0, #0xf
    802065d0:	927cec00 	and	x0, x0, #0xfffffffffffffff0
    802065d4:	91004001 	add	x1, x0, #0x10
    802065d8:	f9003fe1 	str	x1, [sp, #120]
    802065dc:	17fff96c 	b	80204b8c <_vfprintf_r+0xb8c>
    802065e0:	b940f7e0 	ldr	w0, [sp, #244]
    802065e4:	11004001 	add	w1, w0, #0x10
    802065e8:	7100003f 	cmp	w1, #0x0
    802065ec:	540034ed 	b.le	80206c88 <_vfprintf_r+0x2c88>
    802065f0:	f9403fe0 	ldr	x0, [sp, #120]
    802065f4:	b900f7e1 	str	w1, [sp, #244]
    802065f8:	91003c02 	add	x2, x0, #0xf
    802065fc:	fd400008 	ldr	d8, [x0]
    80206600:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206604:	f9003fe1 	str	x1, [sp, #120]
    80206608:	17fff96e 	b	80204bc0 <_vfprintf_r+0xbc0>
    8020660c:	b9408be1 	ldr	w1, [sp, #136]
    80206610:	7100003f 	cmp	w1, #0x0
    80206614:	b9409be1 	ldr	w1, [sp, #152]
    80206618:	7a40d820 	ccmp	w1, #0x0, #0x0, le
    8020661c:	5400660d 	b.le	802072dc <_vfprintf_r+0x32dc>
    80206620:	8b0c036d 	add	x13, x27, x12
    80206624:	aa1c03e2 	mov	x2, x28
    80206628:	d0000044 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    8020662c:	2a0103fc 	mov	w28, w1
    80206630:	913e4084 	add	x4, x4, #0xf90
    80206634:	aa0d03f8 	mov	x24, x13
    80206638:	d2800217 	mov	x23, #0x10                  	// #16
    8020663c:	f9004ff3 	str	x19, [sp, #152]
    80206640:	f9005ff9 	str	x25, [sp, #184]
    80206644:	aa0803f9 	mov	x25, x8
    80206648:	f9006fec 	str	x12, [sp, #216]
    8020664c:	b90113e9 	str	w9, [sp, #272]
    80206650:	f9008ffb 	str	x27, [sp, #280]
    80206654:	b90123eb 	str	w11, [sp, #288]
    80206658:	b90127fa 	str	w26, [sp, #292]
    8020665c:	a94febfb 	ldp	x27, x26, [sp, #248]
    80206660:	f90097ea 	str	x10, [sp, #296]
    80206664:	14000028 	b	80206704 <_vfprintf_r+0x2704>
    80206668:	5100079c 	sub	w28, w28, #0x1
    8020666c:	b9419be1 	ldr	w1, [sp, #408]
    80206670:	8b1a0000 	add	x0, x0, x26
    80206674:	f94077e3 	ldr	x3, [sp, #232]
    80206678:	11000421 	add	w1, w1, #0x1
    8020667c:	a9006843 	stp	x3, x26, [x2]
    80206680:	91004042 	add	x2, x2, #0x10
    80206684:	b9019be1 	str	w1, [sp, #408]
    80206688:	f900d3e0 	str	x0, [sp, #416]
    8020668c:	71001c3f 	cmp	w1, #0x7
    80206690:	5400086c 	b.gt	8020679c <_vfprintf_r+0x279c>
    80206694:	39400361 	ldrb	w1, [x27]
    80206698:	cb190305 	sub	x5, x24, x25
    8020669c:	aa1803e3 	mov	x3, x24
    802066a0:	6b05003f 	cmp	w1, w5
    802066a4:	1a85b033 	csel	w19, w1, w5, lt	// lt = tstop
    802066a8:	7100027f 	cmp	w19, #0x0
    802066ac:	5400018d 	b.le	802066dc <_vfprintf_r+0x26dc>
    802066b0:	b9419be1 	ldr	w1, [sp, #408]
    802066b4:	93407e6a 	sxtw	x10, w19
    802066b8:	8b0a0000 	add	x0, x0, x10
    802066bc:	a9002859 	stp	x25, x10, [x2]
    802066c0:	11000421 	add	w1, w1, #0x1
    802066c4:	b9019be1 	str	w1, [sp, #408]
    802066c8:	f900d3e0 	str	x0, [sp, #416]
    802066cc:	71001c3f 	cmp	w1, #0x7
    802066d0:	5400094c 	b.gt	802067f8 <_vfprintf_r+0x27f8>
    802066d4:	39400361 	ldrb	w1, [x27]
    802066d8:	91004042 	add	x2, x2, #0x10
    802066dc:	7100027f 	cmp	w19, #0x0
    802066e0:	1a9fa265 	csel	w5, w19, wzr, ge	// ge = tcont
    802066e4:	4b050033 	sub	w19, w1, w5
    802066e8:	7100027f 	cmp	w19, #0x0
    802066ec:	540001ac 	b.gt	80206720 <_vfprintf_r+0x2720>
    802066f0:	b9408be5 	ldr	w5, [sp, #136]
    802066f4:	8b210339 	add	x25, x25, w1, uxtb
    802066f8:	710000bf 	cmp	w5, #0x0
    802066fc:	7a40db80 	ccmp	w28, #0x0, #0x0, le
    80206700:	54004d8d 	b.le	802070b0 <_vfprintf_r+0x30b0>
    80206704:	7100039f 	cmp	w28, #0x0
    80206708:	54fffb0c 	b.gt	80206668 <_vfprintf_r+0x2668>
    8020670c:	b9408be1 	ldr	w1, [sp, #136]
    80206710:	d100077b 	sub	x27, x27, #0x1
    80206714:	51000421 	sub	w1, w1, #0x1
    80206718:	b9008be1 	str	w1, [sp, #136]
    8020671c:	17ffffd4 	b	8020666c <_vfprintf_r+0x266c>
    80206720:	d000004a 	adrp	x10, 80210000 <_wcsnrtombs_l+0x110>
    80206724:	b9419be1 	ldr	w1, [sp, #408]
    80206728:	913e414a 	add	x10, x10, #0xf90
    8020672c:	7100427f 	cmp	w19, #0x10
    80206730:	540004ed 	b.le	802067cc <_vfprintf_r+0x27cc>
    80206734:	a90c13e3 	stp	x3, x4, [sp, #192]
    80206738:	f9006bf8 	str	x24, [sp, #208]
    8020673c:	f9404ff8 	ldr	x24, [sp, #152]
    80206740:	14000004 	b	80206750 <_vfprintf_r+0x2750>
    80206744:	51004273 	sub	w19, w19, #0x10
    80206748:	7100427f 	cmp	w19, #0x10
    8020674c:	540003cd 	b.le	802067c4 <_vfprintf_r+0x27c4>
    80206750:	91004000 	add	x0, x0, #0x10
    80206754:	11000421 	add	w1, w1, #0x1
    80206758:	a9005c44 	stp	x4, x23, [x2]
    8020675c:	91004042 	add	x2, x2, #0x10
    80206760:	b9019be1 	str	w1, [sp, #408]
    80206764:	f900d3e0 	str	x0, [sp, #416]
    80206768:	71001c3f 	cmp	w1, #0x7
    8020676c:	54fffecd 	b.le	80206744 <_vfprintf_r+0x2744>
    80206770:	910643e2 	add	x2, sp, #0x190
    80206774:	aa1503e1 	mov	x1, x21
    80206778:	aa1803e0 	mov	x0, x24
    8020677c:	9400035d 	bl	802074f0 <__sprint_r>
    80206780:	350015e0 	cbnz	w0, 80206a3c <_vfprintf_r+0x2a3c>
    80206784:	f940d3e0 	ldr	x0, [sp, #416]
    80206788:	d0000043 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020678c:	b9419be1 	ldr	w1, [sp, #408]
    80206790:	aa1603e2 	mov	x2, x22
    80206794:	913e4064 	add	x4, x3, #0xf90
    80206798:	17ffffeb 	b	80206744 <_vfprintf_r+0x2744>
    8020679c:	f9404fe0 	ldr	x0, [sp, #152]
    802067a0:	910643e2 	add	x2, sp, #0x190
    802067a4:	aa1503e1 	mov	x1, x21
    802067a8:	94000352 	bl	802074f0 <__sprint_r>
    802067ac:	35005620 	cbnz	w0, 80207270 <_vfprintf_r+0x3270>
    802067b0:	f940d3e0 	ldr	x0, [sp, #416]
    802067b4:	d0000041 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    802067b8:	aa1603e2 	mov	x2, x22
    802067bc:	913e4024 	add	x4, x1, #0xf90
    802067c0:	17ffffb5 	b	80206694 <_vfprintf_r+0x2694>
    802067c4:	a94c2be3 	ldp	x3, x10, [sp, #192]
    802067c8:	f9406bf8 	ldr	x24, [sp, #208]
    802067cc:	93407e65 	sxtw	x5, w19
    802067d0:	11000421 	add	w1, w1, #0x1
    802067d4:	8b050000 	add	x0, x0, x5
    802067d8:	a900144a 	stp	x10, x5, [x2]
    802067dc:	b9019be1 	str	w1, [sp, #408]
    802067e0:	f900d3e0 	str	x0, [sp, #416]
    802067e4:	71001c3f 	cmp	w1, #0x7
    802067e8:	5400110c 	b.gt	80206a08 <_vfprintf_r+0x2a08>
    802067ec:	39400361 	ldrb	w1, [x27]
    802067f0:	91004042 	add	x2, x2, #0x10
    802067f4:	17ffffbf 	b	802066f0 <_vfprintf_r+0x26f0>
    802067f8:	f9404fe0 	ldr	x0, [sp, #152]
    802067fc:	910643e2 	add	x2, sp, #0x190
    80206800:	aa1503e1 	mov	x1, x21
    80206804:	f90063f8 	str	x24, [sp, #192]
    80206808:	9400033a 	bl	802074f0 <__sprint_r>
    8020680c:	35005320 	cbnz	w0, 80207270 <_vfprintf_r+0x3270>
    80206810:	f94063e3 	ldr	x3, [sp, #192]
    80206814:	d0000044 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    80206818:	f940d3e0 	ldr	x0, [sp, #416]
    8020681c:	aa1603e2 	mov	x2, x22
    80206820:	39400361 	ldrb	w1, [x27]
    80206824:	913e4084 	add	x4, x4, #0xf90
    80206828:	17ffffad 	b	802066dc <_vfprintf_r+0x26dc>
    8020682c:	b94097e1 	ldr	w1, [sp, #148]
    80206830:	6b01031f 	cmp	w24, w1
    80206834:	540017ab 	b.lt	80206b28 <_vfprintf_r+0x2b28>  // b.tstop
    80206838:	b940abe0 	ldr	w0, [sp, #168]
    8020683c:	f240013f 	tst	x9, #0x1
    80206840:	0b00030c 	add	w12, w24, w0
    80206844:	1a981197 	csel	w23, w12, w24, ne	// ne = any
    80206848:	36500069 	tbz	w9, #10, 80206854 <_vfprintf_r+0x2854>
    8020684c:	7100031f 	cmp	w24, #0x0
    80206850:	54002f0c 	b.gt	80206e30 <_vfprintf_r+0x2e30>
    80206854:	710002ff 	cmp	w23, #0x0
    80206858:	52800ce8 	mov	w8, #0x67                  	// #103
    8020685c:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    80206860:	2a1903e9 	mov	w9, w25
    80206864:	d2800019 	mov	x25, #0x0                   	// #0
    80206868:	b9008bff 	str	wzr, [sp, #136]
    8020686c:	b9009bff 	str	wzr, [sp, #152]
    80206870:	17fffe5b 	b	802061dc <_vfprintf_r+0x21dc>
    80206874:	910643e2 	add	x2, sp, #0x190
    80206878:	aa1503e1 	mov	x1, x21
    8020687c:	aa1303e0 	mov	x0, x19
    80206880:	b9008be9 	str	w9, [sp, #136]
    80206884:	b9009beb 	str	w11, [sp, #152]
    80206888:	f9005fea 	str	x10, [sp, #184]
    8020688c:	94000319 	bl	802074f0 <__sprint_r>
    80206890:	35fefd80 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80206894:	f9405fea 	ldr	x10, [sp, #184]
    80206898:	aa1603fc 	mov	x28, x22
    8020689c:	f940d3e0 	ldr	x0, [sp, #416]
    802068a0:	b9408be9 	ldr	w9, [sp, #136]
    802068a4:	b9409beb 	ldr	w11, [sp, #152]
    802068a8:	b9416be2 	ldr	w2, [sp, #360]
    802068ac:	17fff7b5 	b	80204780 <_vfprintf_r+0x780>
    802068b0:	710116ff 	cmp	w23, #0x45
    802068b4:	54000341 	b.ne	8020691c <_vfprintf_r+0x291c>  // b.any
    802068b8:	110004f8 	add	w24, w7, #0x1
    802068bc:	52800041 	mov	w1, #0x2                   	// #2
    802068c0:	2a1803e2 	mov	w2, w24
    802068c4:	910623e5 	add	x5, sp, #0x188
    802068c8:	910603e4 	add	x4, sp, #0x180
    802068cc:	9105a3e3 	add	x3, sp, #0x168
    802068d0:	aa1303e0 	mov	x0, x19
    802068d4:	b9008be7 	str	w7, [sp, #136]
    802068d8:	9400127a 	bl	8020b2c0 <_dtoa_r>
    802068dc:	aa0003fb 	mov	x27, x0
    802068e0:	f94067ea 	ldr	x10, [sp, #200]
    802068e4:	8b38c001 	add	x1, x0, w24, sxtw
    802068e8:	b9408be7 	ldr	w7, [sp, #136]
    802068ec:	2952a3e9 	ldp	w9, w8, [sp, #148]
    802068f0:	b940c3eb 	ldr	w11, [sp, #192]
    802068f4:	17fffded 	b	802060a8 <_vfprintf_r+0x20a8>
    802068f8:	39457fe1 	ldrb	w1, [sp, #351]
    802068fc:	5280001a 	mov	w26, #0x0                   	// #0
    80206900:	b9008bff 	str	wzr, [sp, #136]
    80206904:	52800007 	mov	w7, #0x0                   	// #0
    80206908:	b9009bff 	str	wzr, [sp, #152]
    8020690c:	52800018 	mov	w24, #0x0                   	// #0
    80206910:	d2800019 	mov	x25, #0x0                   	// #0
    80206914:	34fecde1 	cbz	w1, 802042d0 <_vfprintf_r+0x2d0>
    80206918:	17fff8c2 	b	80204c20 <_vfprintf_r+0xc20>
    8020691c:	2a0703e2 	mov	w2, w7
    80206920:	910623e5 	add	x5, sp, #0x188
    80206924:	910603e4 	add	x4, sp, #0x180
    80206928:	9105a3e3 	add	x3, sp, #0x168
    8020692c:	aa1303e0 	mov	x0, x19
    80206930:	52800041 	mov	w1, #0x2                   	// #2
    80206934:	b9008be7 	str	w7, [sp, #136]
    80206938:	94001262 	bl	8020b2c0 <_dtoa_r>
    8020693c:	2952a3e9 	ldp	w9, w8, [sp, #148]
    80206940:	aa0003fb 	mov	x27, x0
    80206944:	f94067ea 	ldr	x10, [sp, #200]
    80206948:	b9408be7 	ldr	w7, [sp, #136]
    8020694c:	b940c3eb 	ldr	w11, [sp, #192]
    80206950:	3607de49 	tbz	w9, #0, 80206518 <_vfprintf_r+0x2518>
    80206954:	8b27c361 	add	x1, x27, w7, sxtw
    80206958:	17fffdd4 	b	802060a8 <_vfprintf_r+0x20a8>
    8020695c:	b94093e0 	ldr	w0, [sp, #144]
    80206960:	11002001 	add	w1, w0, #0x8
    80206964:	7100003f 	cmp	w1, #0x0
    80206968:	54001e0d 	b.le	80206d28 <_vfprintf_r+0x2d28>
    8020696c:	f9403fe0 	ldr	x0, [sp, #120]
    80206970:	b90093e1 	str	w1, [sp, #144]
    80206974:	91002c02 	add	x2, x0, #0xb
    80206978:	927df041 	and	x1, x2, #0xfffffffffffffff8
    8020697c:	f9003fe1 	str	x1, [sp, #120]
    80206980:	17fff8ed 	b	80204d34 <_vfprintf_r+0xd34>
    80206984:	f94053e2 	ldr	x2, [sp, #160]
    80206988:	b94093e0 	ldr	w0, [sp, #144]
    8020698c:	b90093e1 	str	w1, [sp, #144]
    80206990:	8b20c042 	add	x2, x2, w0, sxtw
    80206994:	f9403fe0 	ldr	x0, [sp, #120]
    80206998:	f9003fe2 	str	x2, [sp, #120]
    8020699c:	17fff942 	b	80204ea4 <_vfprintf_r+0xea4>
    802069a0:	f94053e2 	ldr	x2, [sp, #160]
    802069a4:	b94093e0 	ldr	w0, [sp, #144]
    802069a8:	b90093e1 	str	w1, [sp, #144]
    802069ac:	8b20c040 	add	x0, x2, w0, sxtw
    802069b0:	17fff8f9 	b	80204d94 <_vfprintf_r+0xd94>
    802069b4:	f94053e2 	ldr	x2, [sp, #160]
    802069b8:	b94093e0 	ldr	w0, [sp, #144]
    802069bc:	b90093e1 	str	w1, [sp, #144]
    802069c0:	8b20c040 	add	x0, x2, w0, sxtw
    802069c4:	17fff9ab 	b	80205070 <_vfprintf_r+0x1070>
    802069c8:	910643e2 	add	x2, sp, #0x190
    802069cc:	aa1503e1 	mov	x1, x21
    802069d0:	aa1303e0 	mov	x0, x19
    802069d4:	f9005fec 	str	x12, [sp, #184]
    802069d8:	b900c3e9 	str	w9, [sp, #192]
    802069dc:	b900cbeb 	str	w11, [sp, #200]
    802069e0:	f9006bea 	str	x10, [sp, #208]
    802069e4:	940002c3 	bl	802074f0 <__sprint_r>
    802069e8:	35fef2c0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    802069ec:	f9405fec 	ldr	x12, [sp, #184]
    802069f0:	aa1603fc 	mov	x28, x22
    802069f4:	f9406bea 	ldr	x10, [sp, #208]
    802069f8:	f940d3e0 	ldr	x0, [sp, #416]
    802069fc:	b940c3e9 	ldr	w9, [sp, #192]
    80206a00:	b940cbeb 	ldr	w11, [sp, #200]
    80206a04:	17fffa54 	b	80205354 <_vfprintf_r+0x1354>
    80206a08:	f9404fe0 	ldr	x0, [sp, #152]
    80206a0c:	910643e2 	add	x2, sp, #0x190
    80206a10:	aa1503e1 	mov	x1, x21
    80206a14:	f90063e3 	str	x3, [sp, #192]
    80206a18:	940002b6 	bl	802074f0 <__sprint_r>
    80206a1c:	350042a0 	cbnz	w0, 80207270 <_vfprintf_r+0x3270>
    80206a20:	f94063e3 	ldr	x3, [sp, #192]
    80206a24:	d0000044 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    80206a28:	f940d3e0 	ldr	x0, [sp, #416]
    80206a2c:	aa1603e2 	mov	x2, x22
    80206a30:	39400361 	ldrb	w1, [x27]
    80206a34:	913e4084 	add	x4, x4, #0xf90
    80206a38:	17ffff2e 	b	802066f0 <_vfprintf_r+0x26f0>
    80206a3c:	f9405fe1 	ldr	x1, [sp, #184]
    80206a40:	aa1803f3 	mov	x19, x24
    80206a44:	b5fef021 	cbnz	x1, 80204848 <_vfprintf_r+0x848>
    80206a48:	17fff782 	b	80204850 <_vfprintf_r+0x850>
    80206a4c:	f94077e1 	ldr	x1, [sp, #232]
    80206a50:	b9008be8 	str	w8, [sp, #136]
    80206a54:	f94083e0 	ldr	x0, [sp, #256]
    80206a58:	29129feb 	stp	w11, w7, [sp, #148]
    80206a5c:	a90babe3 	stp	x3, x10, [sp, #184]
    80206a60:	cb00037b 	sub	x27, x27, x0
    80206a64:	aa0003e2 	mov	x2, x0
    80206a68:	aa1b03e0 	mov	x0, x27
    80206a6c:	f90067e4 	str	x4, [sp, #200]
    80206a70:	94001b1c 	bl	8020d6e0 <strncpy>
    80206a74:	394006a0 	ldrb	w0, [x21, #1]
    80206a78:	52800005 	mov	w5, #0x0                   	// #0
    80206a7c:	a94babe3 	ldp	x3, x10, [sp, #184]
    80206a80:	7100001f 	cmp	w0, #0x0
    80206a84:	f94067e4 	ldr	x4, [sp, #200]
    80206a88:	9a9506b5 	cinc	x21, x21, ne	// ne = any
    80206a8c:	b9408be8 	ldr	w8, [sp, #136]
    80206a90:	29529feb 	ldp	w11, w7, [sp, #148]
    80206a94:	17fffccb 	b	80205dc0 <_vfprintf_r+0x1dc0>
    80206a98:	b9416bf8 	ldr	w24, [sp, #360]
    80206a9c:	aa0103e0 	mov	x0, x1
    80206aa0:	17fffd8f 	b	802060dc <_vfprintf_r+0x20dc>
    80206aa4:	910643e2 	add	x2, sp, #0x190
    80206aa8:	aa1503e1 	mov	x1, x21
    80206aac:	aa1303e0 	mov	x0, x19
    80206ab0:	b9008be9 	str	w9, [sp, #136]
    80206ab4:	b9009beb 	str	w11, [sp, #152]
    80206ab8:	f9005fea 	str	x10, [sp, #184]
    80206abc:	9400028d 	bl	802074f0 <__sprint_r>
    80206ac0:	35feec00 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80206ac4:	2952afe1 	ldp	w1, w11, [sp, #148]
    80206ac8:	aa1603fc 	mov	x28, x22
    80206acc:	b9416bf7 	ldr	w23, [sp, #360]
    80206ad0:	f9405fea 	ldr	x10, [sp, #184]
    80206ad4:	4b170037 	sub	w23, w1, w23
    80206ad8:	f940d3e0 	ldr	x0, [sp, #416]
    80206adc:	b9408be9 	ldr	w9, [sp, #136]
    80206ae0:	17fffa3b 	b	802053cc <_vfprintf_r+0x13cc>
    80206ae4:	1e602128 	fcmp	d9, #0.0
    80206ae8:	54003141 	b.ne	80207110 <_vfprintf_r+0x3110>  // b.any
    80206aec:	b9416bf8 	ldr	w24, [sp, #360]
    80206af0:	8b38c000 	add	x0, x0, w24, sxtw
    80206af4:	4b1b0000 	sub	w0, w0, w27
    80206af8:	b90097e0 	str	w0, [sp, #148]
    80206afc:	12000120 	and	w0, w9, #0x1
    80206b00:	2a070000 	orr	w0, w0, w7
    80206b04:	7100031f 	cmp	w24, #0x0
    80206b08:	540033ad 	b.le	8020717c <_vfprintf_r+0x317c>
    80206b0c:	35001880 	cbnz	w0, 80206e1c <_vfprintf_r+0x2e1c>
    80206b10:	2a1803f7 	mov	w23, w24
    80206b14:	52800cc8 	mov	w8, #0x66                  	// #102
    80206b18:	375018e9 	tbnz	w9, #10, 80206e34 <_vfprintf_r+0x2e34>
    80206b1c:	710002ff 	cmp	w23, #0x0
    80206b20:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    80206b24:	17ffff4f 	b	80206860 <_vfprintf_r+0x2860>
    80206b28:	b940abe1 	ldr	w1, [sp, #168]
    80206b2c:	52800ce8 	mov	w8, #0x67                  	// #103
    80206b30:	0b000037 	add	w23, w1, w0
    80206b34:	7100031f 	cmp	w24, #0x0
    80206b38:	54ffff0c 	b.gt	80206b18 <_vfprintf_r+0x2b18>
    80206b3c:	4b1802ec 	sub	w12, w23, w24
    80206b40:	31000597 	adds	w23, w12, #0x1
    80206b44:	1a9f52fa 	csel	w26, w23, wzr, pl	// pl = nfrst
    80206b48:	17ffff46 	b	80206860 <_vfprintf_r+0x2860>
    80206b4c:	b940b2a0 	ldr	w0, [x21, #176]
    80206b50:	370000a0 	tbnz	w0, #0, 80206b64 <_vfprintf_r+0x2b64>
    80206b54:	794022a0 	ldrh	w0, [x21, #16]
    80206b58:	37480060 	tbnz	w0, #9, 80206b64 <_vfprintf_r+0x2b64>
    80206b5c:	f94052a0 	ldr	x0, [x21, #160]
    80206b60:	94000c28 	bl	80209c00 <__retarget_lock_release_recursive>
    80206b64:	12800000 	mov	w0, #0xffffffff            	// #-1
    80206b68:	b90077e0 	str	w0, [sp, #116]
    80206b6c:	17fff740 	b	8020486c <_vfprintf_r+0x86c>
    80206b70:	9106a3fb 	add	x27, sp, #0x1a8
    80206b74:	d2800019 	mov	x25, #0x0                   	// #0
    80206b78:	17fffc53 	b	80205cc4 <_vfprintf_r+0x1cc4>
    80206b7c:	d0000044 	adrp	x4, 80210000 <_wcsnrtombs_l+0x110>
    80206b80:	4b0203f7 	neg	w23, w2
    80206b84:	913e4084 	add	x4, x4, #0xf90
    80206b88:	3100405f 	cmn	w2, #0x10
    80206b8c:	540004ea 	b.ge	80206c28 <_vfprintf_r+0x2c28>  // b.tcont
    80206b90:	aa1503e2 	mov	x2, x21
    80206b94:	2a0903fc 	mov	w28, w9
    80206b98:	2a1703f5 	mov	w21, w23
    80206b9c:	d2800218 	mov	x24, #0x10                  	// #16
    80206ba0:	aa0203f7 	mov	x23, x2
    80206ba4:	f90047f9 	str	x25, [sp, #136]
    80206ba8:	aa0403f9 	mov	x25, x4
    80206bac:	b9009beb 	str	w11, [sp, #152]
    80206bb0:	f9005fea 	str	x10, [sp, #184]
    80206bb4:	14000004 	b	80206bc4 <_vfprintf_r+0x2bc4>
    80206bb8:	510042b5 	sub	w21, w21, #0x10
    80206bbc:	710042bf 	cmp	w21, #0x10
    80206bc0:	5400024d 	b.le	80206c08 <_vfprintf_r+0x2c08>
    80206bc4:	91004000 	add	x0, x0, #0x10
    80206bc8:	11000421 	add	w1, w1, #0x1
    80206bcc:	a90060d9 	stp	x25, x24, [x6]
    80206bd0:	910040c6 	add	x6, x6, #0x10
    80206bd4:	b9019be1 	str	w1, [sp, #408]
    80206bd8:	f900d3e0 	str	x0, [sp, #416]
    80206bdc:	71001c3f 	cmp	w1, #0x7
    80206be0:	54fffecd 	b.le	80206bb8 <_vfprintf_r+0x2bb8>
    80206be4:	910643e2 	add	x2, sp, #0x190
    80206be8:	aa1703e1 	mov	x1, x23
    80206bec:	aa1303e0 	mov	x0, x19
    80206bf0:	94000240 	bl	802074f0 <__sprint_r>
    80206bf4:	35002560 	cbnz	w0, 802070a0 <_vfprintf_r+0x30a0>
    80206bf8:	f940d3e0 	ldr	x0, [sp, #416]
    80206bfc:	aa1603e6 	mov	x6, x22
    80206c00:	b9419be1 	ldr	w1, [sp, #408]
    80206c04:	17ffffed 	b	80206bb8 <_vfprintf_r+0x2bb8>
    80206c08:	f9405fea 	ldr	x10, [sp, #184]
    80206c0c:	aa1703e2 	mov	x2, x23
    80206c10:	aa1903e4 	mov	x4, x25
    80206c14:	b9409beb 	ldr	w11, [sp, #152]
    80206c18:	f94047f9 	ldr	x25, [sp, #136]
    80206c1c:	2a1503f7 	mov	w23, w21
    80206c20:	2a1c03e9 	mov	w9, w28
    80206c24:	aa0203f5 	mov	x21, x2
    80206c28:	93407ef7 	sxtw	x23, w23
    80206c2c:	11000421 	add	w1, w1, #0x1
    80206c30:	8b170000 	add	x0, x0, x23
    80206c34:	a9005cc4 	stp	x4, x23, [x6]
    80206c38:	910040c6 	add	x6, x6, #0x10
    80206c3c:	b9019be1 	str	w1, [sp, #408]
    80206c40:	f900d3e0 	str	x0, [sp, #416]
    80206c44:	71001c3f 	cmp	w1, #0x7
    80206c48:	54fedb8d 	b.le	802047b8 <_vfprintf_r+0x7b8>
    80206c4c:	910643e2 	add	x2, sp, #0x190
    80206c50:	aa1503e1 	mov	x1, x21
    80206c54:	aa1303e0 	mov	x0, x19
    80206c58:	b9008be9 	str	w9, [sp, #136]
    80206c5c:	b9009beb 	str	w11, [sp, #152]
    80206c60:	f9005fea 	str	x10, [sp, #184]
    80206c64:	94000223 	bl	802074f0 <__sprint_r>
    80206c68:	35fedec0 	cbnz	w0, 80204840 <_vfprintf_r+0x840>
    80206c6c:	f9405fea 	ldr	x10, [sp, #184]
    80206c70:	aa1603e6 	mov	x6, x22
    80206c74:	f940d3e0 	ldr	x0, [sp, #416]
    80206c78:	b9408be9 	ldr	w9, [sp, #136]
    80206c7c:	b9409beb 	ldr	w11, [sp, #152]
    80206c80:	b9419be1 	ldr	w1, [sp, #408]
    80206c84:	17fff6cd 	b	802047b8 <_vfprintf_r+0x7b8>
    80206c88:	f94087e2 	ldr	x2, [sp, #264]
    80206c8c:	b940f7e0 	ldr	w0, [sp, #244]
    80206c90:	b900f7e1 	str	w1, [sp, #244]
    80206c94:	8b20c040 	add	x0, x2, w0, sxtw
    80206c98:	fd400008 	ldr	d8, [x0]
    80206c9c:	17fff7c9 	b	80204bc0 <_vfprintf_r+0xbc0>
    80206ca0:	9105cbe1 	add	x1, sp, #0x172
    80206ca4:	35000082 	cbnz	w2, 80206cb4 <_vfprintf_r+0x2cb4>
    80206ca8:	9105cfe1 	add	x1, sp, #0x173
    80206cac:	52800602 	mov	w2, #0x30                  	// #48
    80206cb0:	3905cbe2 	strb	w2, [sp, #370]
    80206cb4:	1100c000 	add	w0, w0, #0x30
    80206cb8:	38001420 	strb	w0, [x1], #1
    80206cbc:	9105c3e2 	add	x2, sp, #0x170
    80206cc0:	4b020020 	sub	w0, w1, w2
    80206cc4:	b900f3e0 	str	w0, [sp, #240]
    80206cc8:	17fffd37 	b	802061a4 <_vfprintf_r+0x21a4>
    80206ccc:	f94087e2 	ldr	x2, [sp, #264]
    80206cd0:	b940f7e0 	ldr	w0, [sp, #244]
    80206cd4:	b900f7e1 	str	w1, [sp, #244]
    80206cd8:	8b20c040 	add	x0, x2, w0, sxtw
    80206cdc:	17fff7ac 	b	80204b8c <_vfprintf_r+0xb8c>
    80206ce0:	f94047f5 	ldr	x21, [sp, #136]
    80206ce4:	d2800001 	mov	x1, #0x0                   	// #0
    80206ce8:	79c022a0 	ldrsh	w0, [x21, #16]
    80206cec:	321a0000 	orr	w0, w0, #0x40
    80206cf0:	790022a0 	strh	w0, [x21, #16]
    80206cf4:	b5fedaa1 	cbnz	x1, 80204848 <_vfprintf_r+0x848>
    80206cf8:	17fff6d6 	b	80204850 <_vfprintf_r+0x850>
    80206cfc:	37f81a20 	tbnz	w0, #31, 80207040 <_vfprintf_r+0x3040>
    80206d00:	f9403fe0 	ldr	x0, [sp, #120]
    80206d04:	91003c01 	add	x1, x0, #0xf
    80206d08:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80206d0c:	f9003fe1 	str	x1, [sp, #120]
    80206d10:	f9400000 	ldr	x0, [x0]
    80206d14:	b94077e1 	ldr	w1, [sp, #116]
    80206d18:	b9000001 	str	w1, [x0]
    80206d1c:	17fff4fe 	b	80204114 <_vfprintf_r+0x114>
    80206d20:	3607a509 	tbz	w9, #0, 802061c0 <_vfprintf_r+0x21c0>
    80206d24:	17fffd25 	b	802061b8 <_vfprintf_r+0x21b8>
    80206d28:	f94053e2 	ldr	x2, [sp, #160]
    80206d2c:	b94093e0 	ldr	w0, [sp, #144]
    80206d30:	b90093e1 	str	w1, [sp, #144]
    80206d34:	8b20c040 	add	x0, x2, w0, sxtw
    80206d38:	17fff7ff 	b	80204d34 <_vfprintf_r+0xd34>
    80206d3c:	b94093e0 	ldr	w0, [sp, #144]
    80206d40:	11002001 	add	w1, w0, #0x8
    80206d44:	7100003f 	cmp	w1, #0x0
    80206d48:	54001ecd 	b.le	80207120 <_vfprintf_r+0x3120>
    80206d4c:	f9403fe0 	ldr	x0, [sp, #120]
    80206d50:	b90093e1 	str	w1, [sp, #144]
    80206d54:	91002c02 	add	x2, x0, #0xb
    80206d58:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206d5c:	f9003fe1 	str	x1, [sp, #120]
    80206d60:	17fffd7a 	b	80206348 <_vfprintf_r+0x2348>
    80206d64:	b94093e0 	ldr	w0, [sp, #144]
    80206d68:	11002001 	add	w1, w0, #0x8
    80206d6c:	7100003f 	cmp	w1, #0x0
    80206d70:	54001e2d 	b.le	80207134 <_vfprintf_r+0x3134>
    80206d74:	f9403fe0 	ldr	x0, [sp, #120]
    80206d78:	b90093e1 	str	w1, [sp, #144]
    80206d7c:	91002c02 	add	x2, x0, #0xb
    80206d80:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206d84:	39400000 	ldrb	w0, [x0]
    80206d88:	f9003fe1 	str	x1, [sp, #120]
    80206d8c:	17fffad0 	b	802058cc <_vfprintf_r+0x18cc>
    80206d90:	9e660100 	fmov	x0, d8
    80206d94:	b7f817e0 	tbnz	x0, #63, 80207090 <_vfprintf_r+0x3090>
    80206d98:	39457fe1 	ldrb	w1, [sp, #351]
    80206d9c:	d0000040 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    80206da0:	d0000045 	adrp	x5, 80210000 <_wcsnrtombs_l+0x110>
    80206da4:	71011d1f 	cmp	w8, #0x47
    80206da8:	912f0000 	add	x0, x0, #0xbc0
    80206dac:	912f20a5 	add	x5, x5, #0xbc8
    80206db0:	17fff791 	b	80204bf4 <_vfprintf_r+0xbf4>
    80206db4:	f94053e2 	ldr	x2, [sp, #160]
    80206db8:	b94093e0 	ldr	w0, [sp, #144]
    80206dbc:	b90093e1 	str	w1, [sp, #144]
    80206dc0:	8b20c040 	add	x0, x2, w0, sxtw
    80206dc4:	79400000 	ldrh	w0, [x0]
    80206dc8:	17fffac1 	b	802058cc <_vfprintf_r+0x18cc>
    80206dcc:	f94053e2 	ldr	x2, [sp, #160]
    80206dd0:	b94093e0 	ldr	w0, [sp, #144]
    80206dd4:	b90093e1 	str	w1, [sp, #144]
    80206dd8:	8b20c040 	add	x0, x2, w0, sxtw
    80206ddc:	17fff9df 	b	80205558 <_vfprintf_r+0x1558>
    80206de0:	0b1b00e1 	add	w1, w7, w27
    80206de4:	52800603 	mov	w3, #0x30                  	// #48
    80206de8:	4b000021 	sub	w1, w1, w0
    80206dec:	11000422 	add	w2, w1, #0x1
    80206df0:	8b22c002 	add	x2, x0, w2, sxtw
    80206df4:	37ff6aa1 	tbnz	w1, #31, 80205b48 <_vfprintf_r+0x1b48>
    80206df8:	38001403 	strb	w3, [x0], #1
    80206dfc:	eb00005f 	cmp	x2, x0
    80206e00:	54ffffc1 	b.ne	80206df8 <_vfprintf_r+0x2df8>  // b.any
    80206e04:	17fffb51 	b	80205b48 <_vfprintf_r+0x1b48>
    80206e08:	f94053e2 	ldr	x2, [sp, #160]
    80206e0c:	b94093e0 	ldr	w0, [sp, #144]
    80206e10:	b90093e1 	str	w1, [sp, #144]
    80206e14:	8b20c040 	add	x0, x2, w0, sxtw
    80206e18:	17fff9c7 	b	80205534 <_vfprintf_r+0x1534>
    80206e1c:	b940abe0 	ldr	w0, [sp, #168]
    80206e20:	52800cc8 	mov	w8, #0x66                  	// #102
    80206e24:	0b0000ec 	add	w12, w7, w0
    80206e28:	0b180197 	add	w23, w12, w24
    80206e2c:	17ffff3b 	b	80206b18 <_vfprintf_r+0x2b18>
    80206e30:	52800ce8 	mov	w8, #0x67                  	// #103
    80206e34:	f9407fe1 	ldr	x1, [sp, #248]
    80206e38:	39400020 	ldrb	w0, [x1]
    80206e3c:	7103fc1f 	cmp	w0, #0xff
    80206e40:	54002480 	b.eq	802072d0 <_vfprintf_r+0x32d0>  // b.none
    80206e44:	52800003 	mov	w3, #0x0                   	// #0
    80206e48:	52800002 	mov	w2, #0x0                   	// #0
    80206e4c:	14000005 	b	80206e60 <_vfprintf_r+0x2e60>
    80206e50:	11000442 	add	w2, w2, #0x1
    80206e54:	91000421 	add	x1, x1, #0x1
    80206e58:	7103fc1f 	cmp	w0, #0xff
    80206e5c:	54000120 	b.eq	80206e80 <_vfprintf_r+0x2e80>  // b.none
    80206e60:	6b18001f 	cmp	w0, w24
    80206e64:	540000ea 	b.ge	80206e80 <_vfprintf_r+0x2e80>  // b.tcont
    80206e68:	4b000318 	sub	w24, w24, w0
    80206e6c:	39400420 	ldrb	w0, [x1, #1]
    80206e70:	35ffff00 	cbnz	w0, 80206e50 <_vfprintf_r+0x2e50>
    80206e74:	39400020 	ldrb	w0, [x1]
    80206e78:	11000463 	add	w3, w3, #0x1
    80206e7c:	17fffff7 	b	80206e58 <_vfprintf_r+0x2e58>
    80206e80:	b9008be2 	str	w2, [sp, #136]
    80206e84:	b9009be3 	str	w3, [sp, #152]
    80206e88:	f9007fe1 	str	x1, [sp, #248]
    80206e8c:	b9408be1 	ldr	w1, [sp, #136]
    80206e90:	2a1903e9 	mov	w9, w25
    80206e94:	b9409be0 	ldr	w0, [sp, #152]
    80206e98:	d2800019 	mov	x25, #0x0                   	// #0
    80206e9c:	0b010000 	add	w0, w0, w1
    80206ea0:	b94103e1 	ldr	w1, [sp, #256]
    80206ea4:	1b015c17 	madd	w23, w0, w1, w23
    80206ea8:	710002ff 	cmp	w23, #0x0
    80206eac:	1a9fa2fa 	csel	w26, w23, wzr, ge	// ge = tcont
    80206eb0:	17fffccb 	b	802061dc <_vfprintf_r+0x21dc>
    80206eb4:	f94047f5 	ldr	x21, [sp, #136]
    80206eb8:	2a1a03e8 	mov	w8, w26
    80206ebc:	b9409be9 	ldr	w9, [sp, #152]
    80206ec0:	aa1803ea 	mov	x10, x24
    80206ec4:	b940bbeb 	ldr	w11, [sp, #184]
    80206ec8:	2a1903f7 	mov	w23, w25
    80206ecc:	17fffb6c 	b	80205c7c <_vfprintf_r+0x1c7c>
    80206ed0:	b94093e0 	ldr	w0, [sp, #144]
    80206ed4:	11002001 	add	w1, w0, #0x8
    80206ed8:	7100003f 	cmp	w1, #0x0
    80206edc:	5400166d 	b.le	802071a8 <_vfprintf_r+0x31a8>
    80206ee0:	f9403fe0 	ldr	x0, [sp, #120]
    80206ee4:	b90093e1 	str	w1, [sp, #144]
    80206ee8:	91002c02 	add	x2, x0, #0xb
    80206eec:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206ef0:	39400000 	ldrb	w0, [x0]
    80206ef4:	f9003fe1 	str	x1, [sp, #120]
    80206ef8:	17fff81c 	b	80204f68 <_vfprintf_r+0xf68>
    80206efc:	b94093e0 	ldr	w0, [sp, #144]
    80206f00:	11002001 	add	w1, w0, #0x8
    80206f04:	7100003f 	cmp	w1, #0x0
    80206f08:	540015cd 	b.le	802071c0 <_vfprintf_r+0x31c0>
    80206f0c:	f9403fe0 	ldr	x0, [sp, #120]
    80206f10:	b90093e1 	str	w1, [sp, #144]
    80206f14:	91002c02 	add	x2, x0, #0xb
    80206f18:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206f1c:	f9003fe1 	str	x1, [sp, #120]
    80206f20:	17fffd19 	b	80206384 <_vfprintf_r+0x2384>
    80206f24:	b94093e0 	ldr	w0, [sp, #144]
    80206f28:	11002001 	add	w1, w0, #0x8
    80206f2c:	7100003f 	cmp	w1, #0x0
    80206f30:	54000e6d 	b.le	802070fc <_vfprintf_r+0x30fc>
    80206f34:	f9403fe0 	ldr	x0, [sp, #120]
    80206f38:	b90093e1 	str	w1, [sp, #144]
    80206f3c:	91002c02 	add	x2, x0, #0xb
    80206f40:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206f44:	f9003fe1 	str	x1, [sp, #120]
    80206f48:	17fffbfa 	b	80205f30 <_vfprintf_r+0x1f30>
    80206f4c:	b94093e0 	ldr	w0, [sp, #144]
    80206f50:	11002001 	add	w1, w0, #0x8
    80206f54:	7100003f 	cmp	w1, #0x0
    80206f58:	540015ad 	b.le	8020720c <_vfprintf_r+0x320c>
    80206f5c:	f9403fe0 	ldr	x0, [sp, #120]
    80206f60:	b90093e1 	str	w1, [sp, #144]
    80206f64:	91003c02 	add	x2, x0, #0xf
    80206f68:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206f6c:	f9003fe1 	str	x1, [sp, #120]
    80206f70:	17fffce6 	b	80206308 <_vfprintf_r+0x2308>
    80206f74:	528005a0 	mov	w0, #0x2d                  	// #45
    80206f78:	1e614109 	fneg	d9, d8
    80206f7c:	b900bbe0 	str	w0, [sp, #184]
    80206f80:	17fffc31 	b	80206044 <_vfprintf_r+0x2044>
    80206f84:	f94053e2 	ldr	x2, [sp, #160]
    80206f88:	b94093e0 	ldr	w0, [sp, #144]
    80206f8c:	b90093e1 	str	w1, [sp, #144]
    80206f90:	8b20c040 	add	x0, x2, w0, sxtw
    80206f94:	79400000 	ldrh	w0, [x0]
    80206f98:	17fff7f4 	b	80204f68 <_vfprintf_r+0xf68>
    80206f9c:	b94093e0 	ldr	w0, [sp, #144]
    80206fa0:	11002001 	add	w1, w0, #0x8
    80206fa4:	7100003f 	cmp	w1, #0x0
    80206fa8:	54000a0d 	b.le	802070e8 <_vfprintf_r+0x30e8>
    80206fac:	f9403fe0 	ldr	x0, [sp, #120]
    80206fb0:	b90093e1 	str	w1, [sp, #144]
    80206fb4:	91002c02 	add	x2, x0, #0xb
    80206fb8:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206fbc:	f9003fe1 	str	x1, [sp, #120]
    80206fc0:	17fffc0e 	b	80205ff8 <_vfprintf_r+0x1ff8>
    80206fc4:	b94093e0 	ldr	w0, [sp, #144]
    80206fc8:	11002001 	add	w1, w0, #0x8
    80206fcc:	7100003f 	cmp	w1, #0x0
    80206fd0:	5400128d 	b.le	80207220 <_vfprintf_r+0x3220>
    80206fd4:	f9403fe0 	ldr	x0, [sp, #120]
    80206fd8:	b90093e1 	str	w1, [sp, #144]
    80206fdc:	91002c02 	add	x2, x0, #0xb
    80206fe0:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80206fe4:	b9400000 	ldr	w0, [x0]
    80206fe8:	f9003fe1 	str	x1, [sp, #120]
    80206fec:	17fff7df 	b	80204f68 <_vfprintf_r+0xf68>
    80206ff0:	39457fe1 	ldrb	w1, [sp, #351]
    80206ff4:	2a0703fa 	mov	w26, w7
    80206ff8:	b9008bff 	str	wzr, [sp, #136]
    80206ffc:	2a0703f7 	mov	w23, w7
    80207000:	b9009bff 	str	wzr, [sp, #152]
    80207004:	52800007 	mov	w7, #0x0                   	// #0
    80207008:	52800e68 	mov	w8, #0x73                  	// #115
    8020700c:	34fe9621 	cbz	w1, 802042d0 <_vfprintf_r+0x2d0>
    80207010:	17fff704 	b	80204c20 <_vfprintf_r+0xc20>
    80207014:	b94093e0 	ldr	w0, [sp, #144]
    80207018:	11002001 	add	w1, w0, #0x8
    8020701c:	7100003f 	cmp	w1, #0x0
    80207020:	540011cd 	b.le	80207258 <_vfprintf_r+0x3258>
    80207024:	f9403fe0 	ldr	x0, [sp, #120]
    80207028:	b90093e1 	str	w1, [sp, #144]
    8020702c:	91002c02 	add	x2, x0, #0xb
    80207030:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80207034:	b9400000 	ldr	w0, [x0]
    80207038:	f9003fe1 	str	x1, [sp, #120]
    8020703c:	17fffa24 	b	802058cc <_vfprintf_r+0x18cc>
    80207040:	b94093e0 	ldr	w0, [sp, #144]
    80207044:	11002001 	add	w1, w0, #0x8
    80207048:	7100003f 	cmp	w1, #0x0
    8020704c:	5400086d 	b.le	80207158 <_vfprintf_r+0x3158>
    80207050:	f9403fe0 	ldr	x0, [sp, #120]
    80207054:	b90093e1 	str	w1, [sp, #144]
    80207058:	91003c02 	add	x2, x0, #0xf
    8020705c:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80207060:	f9003fe1 	str	x1, [sp, #120]
    80207064:	17ffff2b 	b	80206d10 <_vfprintf_r+0x2d10>
    80207068:	b94093e0 	ldr	w0, [sp, #144]
    8020706c:	11002001 	add	w1, w0, #0x8
    80207070:	7100003f 	cmp	w1, #0x0
    80207074:	5400106d 	b.le	80207280 <_vfprintf_r+0x3280>
    80207078:	f9403fe0 	ldr	x0, [sp, #120]
    8020707c:	b90093e1 	str	w1, [sp, #144]
    80207080:	91003c02 	add	x2, x0, #0xf
    80207084:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80207088:	f9003fe1 	str	x1, [sp, #120]
    8020708c:	17fff945 	b	802055a0 <_vfprintf_r+0x15a0>
    80207090:	528005a0 	mov	w0, #0x2d                  	// #45
    80207094:	528005a1 	mov	w1, #0x2d                  	// #45
    80207098:	39057fe0 	strb	w0, [sp, #351]
    8020709c:	17ffff40 	b	80206d9c <_vfprintf_r+0x2d9c>
    802070a0:	f94047e1 	ldr	x1, [sp, #136]
    802070a4:	aa1703f5 	mov	x21, x23
    802070a8:	b5febd01 	cbnz	x1, 80204848 <_vfprintf_r+0x848>
    802070ac:	17fff5e9 	b	80204850 <_vfprintf_r+0x850>
    802070b0:	f9404ff3 	ldr	x19, [sp, #152]
    802070b4:	aa1903e8 	mov	x8, x25
    802070b8:	f9405ff9 	ldr	x25, [sp, #184]
    802070bc:	f9007ffb 	str	x27, [sp, #248]
    802070c0:	f9406fec 	ldr	x12, [sp, #216]
    802070c4:	aa0203fc 	mov	x28, x2
    802070c8:	f9408ffb 	ldr	x27, [sp, #280]
    802070cc:	f94097ea 	ldr	x10, [sp, #296]
    802070d0:	b94113e9 	ldr	w9, [sp, #272]
    802070d4:	b94123eb 	ldr	w11, [sp, #288]
    802070d8:	b94127fa 	ldr	w26, [sp, #292]
    802070dc:	eb03011f 	cmp	x8, x3
    802070e0:	9a839108 	csel	x8, x8, x3, ls	// ls = plast
    802070e4:	17fff8a3 	b	80205370 <_vfprintf_r+0x1370>
    802070e8:	f94053e2 	ldr	x2, [sp, #160]
    802070ec:	b94093e0 	ldr	w0, [sp, #144]
    802070f0:	b90093e1 	str	w1, [sp, #144]
    802070f4:	8b20c040 	add	x0, x2, w0, sxtw
    802070f8:	17fffbc0 	b	80205ff8 <_vfprintf_r+0x1ff8>
    802070fc:	f94053e2 	ldr	x2, [sp, #160]
    80207100:	b94093e0 	ldr	w0, [sp, #144]
    80207104:	b90093e1 	str	w1, [sp, #144]
    80207108:	8b20c040 	add	x0, x2, w0, sxtw
    8020710c:	17fffb89 	b	80205f30 <_vfprintf_r+0x1f30>
    80207110:	52800021 	mov	w1, #0x1                   	// #1
    80207114:	4b070021 	sub	w1, w1, w7
    80207118:	b9016be1 	str	w1, [sp, #360]
    8020711c:	17fffbe2 	b	802060a4 <_vfprintf_r+0x20a4>
    80207120:	f94053e2 	ldr	x2, [sp, #160]
    80207124:	b94093e0 	ldr	w0, [sp, #144]
    80207128:	b90093e1 	str	w1, [sp, #144]
    8020712c:	8b20c040 	add	x0, x2, w0, sxtw
    80207130:	17fffc86 	b	80206348 <_vfprintf_r+0x2348>
    80207134:	f94053e2 	ldr	x2, [sp, #160]
    80207138:	b94093e0 	ldr	w0, [sp, #144]
    8020713c:	b90093e1 	str	w1, [sp, #144]
    80207140:	8b20c040 	add	x0, x2, w0, sxtw
    80207144:	39400000 	ldrb	w0, [x0]
    80207148:	17fff9e1 	b	802058cc <_vfprintf_r+0x18cc>
    8020714c:	52800040 	mov	w0, #0x2                   	// #2
    80207150:	b900f3e0 	str	w0, [sp, #240]
    80207154:	17fffc14 	b	802061a4 <_vfprintf_r+0x21a4>
    80207158:	f94053e2 	ldr	x2, [sp, #160]
    8020715c:	b94093e0 	ldr	w0, [sp, #144]
    80207160:	b90093e1 	str	w1, [sp, #144]
    80207164:	8b20c040 	add	x0, x2, w0, sxtw
    80207168:	17fffeea 	b	80206d10 <_vfprintf_r+0x2d10>
    8020716c:	79c022a0 	ldrsh	w0, [x21, #16]
    80207170:	321a0000 	orr	w0, w0, #0x40
    80207174:	790022a0 	strh	w0, [x21, #16]
    80207178:	17fff5b7 	b	80204854 <_vfprintf_r+0x854>
    8020717c:	350000a0 	cbnz	w0, 80207190 <_vfprintf_r+0x3190>
    80207180:	5280003a 	mov	w26, #0x1                   	// #1
    80207184:	52800cc8 	mov	w8, #0x66                  	// #102
    80207188:	2a1a03f7 	mov	w23, w26
    8020718c:	17fffdb5 	b	80206860 <_vfprintf_r+0x2860>
    80207190:	b940abe0 	ldr	w0, [sp, #168]
    80207194:	52800cc8 	mov	w8, #0x66                  	// #102
    80207198:	1100040c 	add	w12, w0, #0x1
    8020719c:	2b070197 	adds	w23, w12, w7
    802071a0:	1a9f52fa 	csel	w26, w23, wzr, pl	// pl = nfrst
    802071a4:	17fffdaf 	b	80206860 <_vfprintf_r+0x2860>
    802071a8:	f94053e2 	ldr	x2, [sp, #160]
    802071ac:	b94093e0 	ldr	w0, [sp, #144]
    802071b0:	b90093e1 	str	w1, [sp, #144]
    802071b4:	8b20c040 	add	x0, x2, w0, sxtw
    802071b8:	39400000 	ldrb	w0, [x0]
    802071bc:	17fff76b 	b	80204f68 <_vfprintf_r+0xf68>
    802071c0:	f94053e2 	ldr	x2, [sp, #160]
    802071c4:	b94093e0 	ldr	w0, [sp, #144]
    802071c8:	b90093e1 	str	w1, [sp, #144]
    802071cc:	8b20c040 	add	x0, x2, w0, sxtw
    802071d0:	17fffc6d 	b	80206384 <_vfprintf_r+0x2384>
    802071d4:	b94093e2 	ldr	w2, [sp, #144]
    802071d8:	37f80302 	tbnz	w2, #31, 80207238 <_vfprintf_r+0x3238>
    802071dc:	f9403fe0 	ldr	x0, [sp, #120]
    802071e0:	91002c00 	add	x0, x0, #0xb
    802071e4:	927df000 	and	x0, x0, #0xfffffffffffffff8
    802071e8:	f9403fe3 	ldr	x3, [sp, #120]
    802071ec:	f9003fe0 	str	x0, [sp, #120]
    802071f0:	39400748 	ldrb	w8, [x26, #1]
    802071f4:	aa0103fa 	mov	x26, x1
    802071f8:	b90093e2 	str	w2, [sp, #144]
    802071fc:	b9400067 	ldr	w7, [x3]
    80207200:	710000ff 	cmp	w7, #0x0
    80207204:	5a9fa0f9 	csinv	w25, w7, wzr, ge	// ge = tcont
    80207208:	17fff419 	b	8020426c <_vfprintf_r+0x26c>
    8020720c:	f94053e2 	ldr	x2, [sp, #160]
    80207210:	b94093e0 	ldr	w0, [sp, #144]
    80207214:	b90093e1 	str	w1, [sp, #144]
    80207218:	8b20c040 	add	x0, x2, w0, sxtw
    8020721c:	17fffc3b 	b	80206308 <_vfprintf_r+0x2308>
    80207220:	f94053e2 	ldr	x2, [sp, #160]
    80207224:	b94093e0 	ldr	w0, [sp, #144]
    80207228:	b90093e1 	str	w1, [sp, #144]
    8020722c:	8b20c040 	add	x0, x2, w0, sxtw
    80207230:	b9400000 	ldr	w0, [x0]
    80207234:	17fff74d 	b	80204f68 <_vfprintf_r+0xf68>
    80207238:	b94093e0 	ldr	w0, [sp, #144]
    8020723c:	11002002 	add	w2, w0, #0x8
    80207240:	f9403fe0 	ldr	x0, [sp, #120]
    80207244:	7100005f 	cmp	w2, #0x0
    80207248:	5400026d 	b.le	80207294 <_vfprintf_r+0x3294>
    8020724c:	91002c00 	add	x0, x0, #0xb
    80207250:	927df000 	and	x0, x0, #0xfffffffffffffff8
    80207254:	17ffffe5 	b	802071e8 <_vfprintf_r+0x31e8>
    80207258:	f94053e2 	ldr	x2, [sp, #160]
    8020725c:	b94093e0 	ldr	w0, [sp, #144]
    80207260:	b90093e1 	str	w1, [sp, #144]
    80207264:	8b20c040 	add	x0, x2, w0, sxtw
    80207268:	b9400000 	ldr	w0, [x0]
    8020726c:	17fff998 	b	802058cc <_vfprintf_r+0x18cc>
    80207270:	f9405fe1 	ldr	x1, [sp, #184]
    80207274:	f9404ff3 	ldr	x19, [sp, #152]
    80207278:	b5feae81 	cbnz	x1, 80204848 <_vfprintf_r+0x848>
    8020727c:	17fff575 	b	80204850 <_vfprintf_r+0x850>
    80207280:	f94053e2 	ldr	x2, [sp, #160]
    80207284:	b94093e0 	ldr	w0, [sp, #144]
    80207288:	b90093e1 	str	w1, [sp, #144]
    8020728c:	8b20c040 	add	x0, x2, w0, sxtw
    80207290:	17fff8c4 	b	802055a0 <_vfprintf_r+0x15a0>
    80207294:	f94053e4 	ldr	x4, [sp, #160]
    80207298:	b94093e3 	ldr	w3, [sp, #144]
    8020729c:	8b23c083 	add	x3, x4, w3, sxtw
    802072a0:	f9003fe3 	str	x3, [sp, #120]
    802072a4:	17ffffd1 	b	802071e8 <_vfprintf_r+0x31e8>
    802072a8:	79c022a0 	ldrsh	w0, [x21, #16]
    802072ac:	aa1903e1 	mov	x1, x25
    802072b0:	321a0000 	orr	w0, w0, #0x40
    802072b4:	790022a0 	strh	w0, [x21, #16]
    802072b8:	17fffe8f 	b	80206cf4 <_vfprintf_r+0x2cf4>
    802072bc:	79c022a0 	ldrsh	w0, [x21, #16]
    802072c0:	d2800001 	mov	x1, #0x0                   	// #0
    802072c4:	321a0000 	orr	w0, w0, #0x40
    802072c8:	790022a0 	strh	w0, [x21, #16]
    802072cc:	17fffe8a 	b	80206cf4 <_vfprintf_r+0x2cf4>
    802072d0:	b9008bff 	str	wzr, [sp, #136]
    802072d4:	b9009bff 	str	wzr, [sp, #152]
    802072d8:	17fffeed 	b	80206e8c <_vfprintf_r+0x2e8c>
    802072dc:	8b0c0363 	add	x3, x27, x12
    802072e0:	17ffff7f 	b	802070dc <_vfprintf_r+0x30dc>
	...

00000000802072f0 <vfprintf>:
    802072f0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    802072f4:	d0000044 	adrp	x4, 80211000 <blanks.1+0x60>
    802072f8:	aa0003e3 	mov	x3, x0
    802072fc:	910003fd 	mov	x29, sp
    80207300:	ad400440 	ldp	q0, q1, [x2]
    80207304:	aa0103e2 	mov	x2, x1
    80207308:	f9438880 	ldr	x0, [x4, #1808]
    8020730c:	aa0303e1 	mov	x1, x3
    80207310:	910043e3 	add	x3, sp, #0x10
    80207314:	ad0087e0 	stp	q0, q1, [sp, #16]
    80207318:	97fff33a 	bl	80204000 <_vfprintf_r>
    8020731c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80207320:	d65f03c0 	ret
	...

0000000080207330 <__sbprintf>:
    80207330:	d11443ff 	sub	sp, sp, #0x510
    80207334:	a9007bfd 	stp	x29, x30, [sp]
    80207338:	910003fd 	mov	x29, sp
    8020733c:	a90153f3 	stp	x19, x20, [sp, #16]
    80207340:	aa0103f3 	mov	x19, x1
    80207344:	79402021 	ldrh	w1, [x1, #16]
    80207348:	aa0303f4 	mov	x20, x3
    8020734c:	910443e3 	add	x3, sp, #0x110
    80207350:	f9401a66 	ldr	x6, [x19, #48]
    80207354:	121e7821 	and	w1, w1, #0xfffffffd
    80207358:	f9402265 	ldr	x5, [x19, #64]
    8020735c:	a9025bf5 	stp	x21, x22, [sp, #32]
    80207360:	79402667 	ldrh	w7, [x19, #18]
    80207364:	b940b264 	ldr	w4, [x19, #176]
    80207368:	aa0203f6 	mov	x22, x2
    8020736c:	52808002 	mov	w2, #0x400                 	// #1024
    80207370:	aa0003f5 	mov	x21, x0
    80207374:	9103e3e0 	add	x0, sp, #0xf8
    80207378:	f9002fe3 	str	x3, [sp, #88]
    8020737c:	b90067e2 	str	w2, [sp, #100]
    80207380:	7900d3e1 	strh	w1, [sp, #104]
    80207384:	7900d7e7 	strh	w7, [sp, #106]
    80207388:	f9003be3 	str	x3, [sp, #112]
    8020738c:	b9007be2 	str	w2, [sp, #120]
    80207390:	b90083ff 	str	wzr, [sp, #128]
    80207394:	f90047e6 	str	x6, [sp, #136]
    80207398:	f9004fe5 	str	x5, [sp, #152]
    8020739c:	b9010be4 	str	w4, [sp, #264]
    802073a0:	940009f8 	bl	80209b80 <__retarget_lock_init_recursive>
    802073a4:	ad400680 	ldp	q0, q1, [x20]
    802073a8:	aa1603e2 	mov	x2, x22
    802073ac:	9100c3e3 	add	x3, sp, #0x30
    802073b0:	910163e1 	add	x1, sp, #0x58
    802073b4:	aa1503e0 	mov	x0, x21
    802073b8:	ad0187e0 	stp	q0, q1, [sp, #48]
    802073bc:	97fff311 	bl	80204000 <_vfprintf_r>
    802073c0:	2a0003f4 	mov	w20, w0
    802073c4:	37f800c0 	tbnz	w0, #31, 802073dc <__sbprintf+0xac>
    802073c8:	910163e1 	add	x1, sp, #0x58
    802073cc:	aa1503e0 	mov	x0, x21
    802073d0:	940014e8 	bl	8020c770 <_fflush_r>
    802073d4:	7100001f 	cmp	w0, #0x0
    802073d8:	5a9f0294 	csinv	w20, w20, wzr, eq	// eq = none
    802073dc:	7940d3e0 	ldrh	w0, [sp, #104]
    802073e0:	36300080 	tbz	w0, #6, 802073f0 <__sbprintf+0xc0>
    802073e4:	79402260 	ldrh	w0, [x19, #16]
    802073e8:	321a0000 	orr	w0, w0, #0x40
    802073ec:	79002260 	strh	w0, [x19, #16]
    802073f0:	f9407fe0 	ldr	x0, [sp, #248]
    802073f4:	940009eb 	bl	80209ba0 <__retarget_lock_close_recursive>
    802073f8:	a9407bfd 	ldp	x29, x30, [sp]
    802073fc:	2a1403e0 	mov	w0, w20
    80207400:	a94153f3 	ldp	x19, x20, [sp, #16]
    80207404:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80207408:	911443ff 	add	sp, sp, #0x510
    8020740c:	d65f03c0 	ret

0000000080207410 <__sprint_r.part.0>:
    80207410:	a9bb7bfd 	stp	x29, x30, [sp, #-80]!
    80207414:	910003fd 	mov	x29, sp
    80207418:	b940b023 	ldr	w3, [x1, #176]
    8020741c:	a90363f7 	stp	x23, x24, [sp, #48]
    80207420:	aa0203f8 	mov	x24, x2
    80207424:	36680563 	tbz	w3, #13, 802074d0 <__sprint_r.part.0+0xc0>
    80207428:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020742c:	aa0003f5 	mov	x21, x0
    80207430:	f9400840 	ldr	x0, [x2, #16]
    80207434:	a90153f3 	stp	x19, x20, [sp, #16]
    80207438:	aa0103f4 	mov	x20, x1
    8020743c:	a9046bf9 	stp	x25, x26, [sp, #64]
    80207440:	f940005a 	ldr	x26, [x2]
    80207444:	b40003c0 	cbz	x0, 802074bc <__sprint_r.part.0+0xac>
    80207448:	a9406756 	ldp	x22, x25, [x26]
    8020744c:	d342ff39 	lsr	x25, x25, #2
    80207450:	2a1903f7 	mov	w23, w25
    80207454:	7100033f 	cmp	w25, #0x0
    80207458:	540002ad 	b.le	802074ac <__sprint_r.part.0+0x9c>
    8020745c:	d2800013 	mov	x19, #0x0                   	// #0
    80207460:	14000003 	b	8020746c <__sprint_r.part.0+0x5c>
    80207464:	6b1302ff 	cmp	w23, w19
    80207468:	5400020d 	b.le	802074a8 <__sprint_r.part.0+0x98>
    8020746c:	b8737ac1 	ldr	w1, [x22, x19, lsl #2]
    80207470:	aa1403e2 	mov	x2, x20
    80207474:	aa1503e0 	mov	x0, x21
    80207478:	91000673 	add	x19, x19, #0x1
    8020747c:	94001a35 	bl	8020dd50 <_fputwc_r>
    80207480:	3100041f 	cmn	w0, #0x1
    80207484:	54ffff01 	b.ne	80207464 <__sprint_r.part.0+0x54>  // b.any
    80207488:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020748c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80207490:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80207494:	b9000b1f 	str	wzr, [x24, #8]
    80207498:	f9000b1f 	str	xzr, [x24, #16]
    8020749c:	a94363f7 	ldp	x23, x24, [sp, #48]
    802074a0:	a8c57bfd 	ldp	x29, x30, [sp], #80
    802074a4:	d65f03c0 	ret
    802074a8:	f9400b00 	ldr	x0, [x24, #16]
    802074ac:	cb39c800 	sub	x0, x0, w25, sxtw #2
    802074b0:	f9000b00 	str	x0, [x24, #16]
    802074b4:	9100435a 	add	x26, x26, #0x10
    802074b8:	b5fffc80 	cbnz	x0, 80207448 <__sprint_r.part.0+0x38>
    802074bc:	a94153f3 	ldp	x19, x20, [sp, #16]
    802074c0:	52800000 	mov	w0, #0x0                   	// #0
    802074c4:	a9425bf5 	ldp	x21, x22, [sp, #32]
    802074c8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    802074cc:	17fffff2 	b	80207494 <__sprint_r.part.0+0x84>
    802074d0:	97fff158 	bl	80203a30 <__sfvwrite_r>
    802074d4:	b9000b1f 	str	wzr, [x24, #8]
    802074d8:	f9000b1f 	str	xzr, [x24, #16]
    802074dc:	a94363f7 	ldp	x23, x24, [sp, #48]
    802074e0:	a8c57bfd 	ldp	x29, x30, [sp], #80
    802074e4:	d65f03c0 	ret
	...

00000000802074f0 <__sprint_r>:
    802074f0:	f9400844 	ldr	x4, [x2, #16]
    802074f4:	b4000044 	cbz	x4, 802074fc <__sprint_r+0xc>
    802074f8:	17ffffc6 	b	80207410 <__sprint_r.part.0>
    802074fc:	52800000 	mov	w0, #0x0                   	// #0
    80207500:	b900085f 	str	wzr, [x2, #8]
    80207504:	d65f03c0 	ret
	...

0000000080207510 <_vfiprintf_r>:
    80207510:	d10883ff 	sub	sp, sp, #0x220
    80207514:	a9007bfd 	stp	x29, x30, [sp]
    80207518:	910003fd 	mov	x29, sp
    8020751c:	a90153f3 	stp	x19, x20, [sp, #16]
    80207520:	aa0003f3 	mov	x19, x0
    80207524:	aa0303f4 	mov	x20, x3
    80207528:	a90363f7 	stp	x23, x24, [sp, #48]
    8020752c:	a9400077 	ldp	x23, x0, [x3]
    80207530:	a9025bf5 	stp	x21, x22, [sp, #32]
    80207534:	aa0103f5 	mov	x21, x1
    80207538:	b9401861 	ldr	w1, [x3, #24]
    8020753c:	a9046bf9 	stp	x25, x26, [sp, #64]
    80207540:	aa0203f9 	mov	x25, x2
    80207544:	d2800102 	mov	x2, #0x8                   	// #8
    80207548:	f90043e0 	str	x0, [sp, #128]
    8020754c:	910423e0 	add	x0, sp, #0x108
    80207550:	b900c3e1 	str	w1, [sp, #192]
    80207554:	52800001 	mov	w1, #0x0                   	// #0
    80207558:	97fff05a 	bl	802036c0 <memset>
    8020755c:	b4000073 	cbz	x19, 80207568 <_vfiprintf_r+0x58>
    80207560:	f9402660 	ldr	x0, [x19, #72]
    80207564:	b4009ac0 	cbz	x0, 802088bc <_vfiprintf_r+0x13ac>
    80207568:	b940b2a1 	ldr	w1, [x21, #176]
    8020756c:	79c022a0 	ldrsh	w0, [x21, #16]
    80207570:	37000041 	tbnz	w1, #0, 80207578 <_vfiprintf_r+0x68>
    80207574:	36487720 	tbz	w0, #9, 80208458 <_vfiprintf_r+0xf48>
    80207578:	376800c0 	tbnz	w0, #13, 80207590 <_vfiprintf_r+0x80>
    8020757c:	b940b2a1 	ldr	w1, [x21, #176]
    80207580:	32130000 	orr	w0, w0, #0x2000
    80207584:	790022a0 	strh	w0, [x21, #16]
    80207588:	12127821 	and	w1, w1, #0xffffdfff
    8020758c:	b900b2a1 	str	w1, [x21, #176]
    80207590:	361804e0 	tbz	w0, #3, 8020762c <_vfiprintf_r+0x11c>
    80207594:	f9400ea1 	ldr	x1, [x21, #24]
    80207598:	b40004a1 	cbz	x1, 8020762c <_vfiprintf_r+0x11c>
    8020759c:	52800341 	mov	w1, #0x1a                  	// #26
    802075a0:	0a010001 	and	w1, w0, w1
    802075a4:	7100283f 	cmp	w1, #0xa
    802075a8:	54000540 	b.eq	80207650 <_vfiprintf_r+0x140>  // b.none
    802075ac:	910683f6 	add	x22, sp, #0x1a0
    802075b0:	f0000054 	adrp	x20, 80212000 <__malloc_av_+0x760>
    802075b4:	91068294 	add	x20, x20, #0x1a0
    802075b8:	a90573fb 	stp	x27, x28, [sp, #80]
    802075bc:	aa1603fb 	mov	x27, x22
    802075c0:	b0000040 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    802075c4:	913ec000 	add	x0, x0, #0xfb0
    802075c8:	b9006fff 	str	wzr, [sp, #108]
    802075cc:	f9003fe0 	str	x0, [sp, #120]
    802075d0:	a90a7fff 	stp	xzr, xzr, [sp, #160]
    802075d4:	a90b7fff 	stp	xzr, xzr, [sp, #176]
    802075d8:	f90093f6 	str	x22, [sp, #288]
    802075dc:	b9012bff 	str	wzr, [sp, #296]
    802075e0:	f9009bff 	str	xzr, [sp, #304]
    802075e4:	aa1903fc 	mov	x28, x25
    802075e8:	f9407698 	ldr	x24, [x20, #232]
    802075ec:	94000cad 	bl	8020a8a0 <__locale_mb_cur_max>
    802075f0:	910423e4 	add	x4, sp, #0x108
    802075f4:	93407c03 	sxtw	x3, w0
    802075f8:	aa1c03e2 	mov	x2, x28
    802075fc:	910413e1 	add	x1, sp, #0x104
    80207600:	aa1303e0 	mov	x0, x19
    80207604:	d63f0300 	blr	x24
    80207608:	7100001f 	cmp	w0, #0x0
    8020760c:	340005a0 	cbz	w0, 802076c0 <_vfiprintf_r+0x1b0>
    80207610:	540004ab 	b.lt	802076a4 <_vfiprintf_r+0x194>  // b.tstop
    80207614:	b94107e1 	ldr	w1, [sp, #260]
    80207618:	7100943f 	cmp	w1, #0x25
    8020761c:	54001be0 	b.eq	80207998 <_vfiprintf_r+0x488>  // b.none
    80207620:	93407c00 	sxtw	x0, w0
    80207624:	8b00039c 	add	x28, x28, x0
    80207628:	17fffff0 	b	802075e8 <_vfiprintf_r+0xd8>
    8020762c:	aa1503e1 	mov	x1, x21
    80207630:	aa1303e0 	mov	x0, x19
    80207634:	94000d4b 	bl	8020ab60 <__swsetup_r>
    80207638:	3500b8a0 	cbnz	w0, 80208d4c <_vfiprintf_r+0x183c>
    8020763c:	79c022a0 	ldrsh	w0, [x21, #16]
    80207640:	52800341 	mov	w1, #0x1a                  	// #26
    80207644:	0a010001 	and	w1, w0, w1
    80207648:	7100283f 	cmp	w1, #0xa
    8020764c:	54fffb01 	b.ne	802075ac <_vfiprintf_r+0x9c>  // b.any
    80207650:	79c026a1 	ldrsh	w1, [x21, #18]
    80207654:	37fffac1 	tbnz	w1, #31, 802075ac <_vfiprintf_r+0x9c>
    80207658:	b940b2a1 	ldr	w1, [x21, #176]
    8020765c:	37000041 	tbnz	w1, #0, 80207664 <_vfiprintf_r+0x154>
    80207660:	3648ae00 	tbz	w0, #9, 80208c20 <_vfiprintf_r+0x1710>
    80207664:	ad400680 	ldp	q0, q1, [x20]
    80207668:	aa1903e2 	mov	x2, x25
    8020766c:	aa1503e1 	mov	x1, x21
    80207670:	910343e3 	add	x3, sp, #0xd0
    80207674:	aa1303e0 	mov	x0, x19
    80207678:	ad0687e0 	stp	q0, q1, [sp, #208]
    8020767c:	940006b9 	bl	80209160 <__sbprintf>
    80207680:	b9006fe0 	str	w0, [sp, #108]
    80207684:	a9407bfd 	ldp	x29, x30, [sp]
    80207688:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020768c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80207690:	a94363f7 	ldp	x23, x24, [sp, #48]
    80207694:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80207698:	b9406fe0 	ldr	w0, [sp, #108]
    8020769c:	910883ff 	add	sp, sp, #0x220
    802076a0:	d65f03c0 	ret
    802076a4:	910423e0 	add	x0, sp, #0x108
    802076a8:	d2800102 	mov	x2, #0x8                   	// #8
    802076ac:	52800001 	mov	w1, #0x0                   	// #0
    802076b0:	97fff004 	bl	802036c0 <memset>
    802076b4:	d2800020 	mov	x0, #0x1                   	// #1
    802076b8:	8b00039c 	add	x28, x28, x0
    802076bc:	17ffffcb 	b	802075e8 <_vfiprintf_r+0xd8>
    802076c0:	2a0003f8 	mov	w24, w0
    802076c4:	cb190380 	sub	x0, x28, x25
    802076c8:	2a0003fa 	mov	w26, w0
    802076cc:	340091e0 	cbz	w0, 80208908 <_vfiprintf_r+0x13f8>
    802076d0:	f9409be2 	ldr	x2, [sp, #304]
    802076d4:	93407f41 	sxtw	x1, w26
    802076d8:	b9412be0 	ldr	w0, [sp, #296]
    802076dc:	8b020022 	add	x2, x1, x2
    802076e0:	a9000779 	stp	x25, x1, [x27]
    802076e4:	11000400 	add	w0, w0, #0x1
    802076e8:	b9012be0 	str	w0, [sp, #296]
    802076ec:	9100437b 	add	x27, x27, #0x10
    802076f0:	f9009be2 	str	x2, [sp, #304]
    802076f4:	71001c1f 	cmp	w0, #0x7
    802076f8:	5400010d 	b.le	80207718 <_vfiprintf_r+0x208>
    802076fc:	b40066a2 	cbz	x2, 802083d0 <_vfiprintf_r+0xec0>
    80207700:	910483e2 	add	x2, sp, #0x120
    80207704:	aa1503e1 	mov	x1, x21
    80207708:	aa1303e0 	mov	x0, x19
    8020770c:	97ffff41 	bl	80207410 <__sprint_r.part.0>
    80207710:	35000420 	cbnz	w0, 80207794 <_vfiprintf_r+0x284>
    80207714:	aa1603fb 	mov	x27, x22
    80207718:	b9406fe0 	ldr	w0, [sp, #108]
    8020771c:	0b1a0000 	add	w0, w0, w26
    80207720:	b9006fe0 	str	w0, [sp, #108]
    80207724:	34008f38 	cbz	w24, 80208908 <_vfiprintf_r+0x13f8>
    80207728:	39400780 	ldrb	w0, [x28, #1]
    8020772c:	91000799 	add	x25, x28, #0x1
    80207730:	12800003 	mov	w3, #0xffffffff            	// #-1
    80207734:	52800008 	mov	w8, #0x0                   	// #0
    80207738:	2a0303fc 	mov	w28, w3
    8020773c:	2a0803fa 	mov	w26, w8
    80207740:	52800018 	mov	w24, #0x0                   	// #0
    80207744:	3903ffff 	strb	wzr, [sp, #255]
    80207748:	91000739 	add	x25, x25, #0x1
    8020774c:	51008001 	sub	w1, w0, #0x20
    80207750:	7101683f 	cmp	w1, #0x5a
    80207754:	540003a8 	b.hi	802077c8 <_vfiprintf_r+0x2b8>  // b.pmore
    80207758:	f9403fe2 	ldr	x2, [sp, #120]
    8020775c:	78615841 	ldrh	w1, [x2, w1, uxtw #1]
    80207760:	10000062 	adr	x2, 8020776c <_vfiprintf_r+0x25c>
    80207764:	8b21a841 	add	x1, x2, w1, sxth #2
    80207768:	d61f0020 	br	x1
    8020776c:	910483e2 	add	x2, sp, #0x120
    80207770:	aa1503e1 	mov	x1, x21
    80207774:	aa1303e0 	mov	x0, x19
    80207778:	97ffff26 	bl	80207410 <__sprint_r.part.0>
    8020777c:	34000e60 	cbz	w0, 80207948 <_vfiprintf_r+0x438>
    80207780:	f9403be0 	ldr	x0, [sp, #112]
    80207784:	b4000080 	cbz	x0, 80207794 <_vfiprintf_r+0x284>
    80207788:	f9403be1 	ldr	x1, [sp, #112]
    8020778c:	aa1303e0 	mov	x0, x19
    80207790:	9400161c 	bl	8020d000 <_free_r>
    80207794:	79c022a0 	ldrsh	w0, [x21, #16]
    80207798:	b940b2a1 	ldr	w1, [x21, #176]
    8020779c:	36003b81 	tbz	w1, #0, 80207f0c <_vfiprintf_r+0x9fc>
    802077a0:	a94573fb 	ldp	x27, x28, [sp, #80]
    802077a4:	3730ae00 	tbnz	w0, #6, 80208d64 <_vfiprintf_r+0x1854>
    802077a8:	a9407bfd 	ldp	x29, x30, [sp]
    802077ac:	a94153f3 	ldp	x19, x20, [sp, #16]
    802077b0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    802077b4:	a94363f7 	ldp	x23, x24, [sp, #48]
    802077b8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    802077bc:	b9406fe0 	ldr	w0, [sp, #108]
    802077c0:	910883ff 	add	sp, sp, #0x220
    802077c4:	d65f03c0 	ret
    802077c8:	2a1a03e8 	mov	w8, w26
    802077cc:	340089e0 	cbz	w0, 80208908 <_vfiprintf_r+0x13f8>
    802077d0:	52800024 	mov	w4, #0x1                   	// #1
    802077d4:	9104e3fc 	add	x28, sp, #0x138
    802077d8:	2a0403fa 	mov	w26, w4
    802077dc:	3903ffff 	strb	wzr, [sp, #255]
    802077e0:	3904e3e0 	strb	w0, [sp, #312]
    802077e4:	52800003 	mov	w3, #0x0                   	// #0
    802077e8:	5280000d 	mov	w13, #0x0                   	// #0
    802077ec:	f9003bff 	str	xzr, [sp, #112]
    802077f0:	b9412be1 	ldr	w1, [sp, #296]
    802077f4:	5280108c 	mov	w12, #0x84                  	// #132
    802077f8:	f9409be0 	ldr	x0, [sp, #304]
    802077fc:	11000422 	add	w2, w1, #0x1
    80207800:	6a0c030c 	ands	w12, w24, w12
    80207804:	2a0203eb 	mov	w11, w2
    80207808:	54000081 	b.ne	80207818 <_vfiprintf_r+0x308>  // b.any
    8020780c:	4b04010a 	sub	w10, w8, w4
    80207810:	7100015f 	cmp	w10, #0x0
    80207814:	5400252c 	b.gt	80207cb8 <_vfiprintf_r+0x7a8>
    80207818:	3943ffe2 	ldrb	w2, [sp, #255]
    8020781c:	340001a2 	cbz	w2, 80207850 <_vfiprintf_r+0x340>
    80207820:	9103ffe1 	add	x1, sp, #0xff
    80207824:	91000400 	add	x0, x0, #0x1
    80207828:	f9000361 	str	x1, [x27]
    8020782c:	d2800021 	mov	x1, #0x1                   	// #1
    80207830:	f9000761 	str	x1, [x27, #8]
    80207834:	b9012beb 	str	w11, [sp, #296]
    80207838:	f9009be0 	str	x0, [sp, #304]
    8020783c:	71001d7f 	cmp	w11, #0x7
    80207840:	54001fec 	b.gt	80207c3c <_vfiprintf_r+0x72c>
    80207844:	2a0b03e1 	mov	w1, w11
    80207848:	9100437b 	add	x27, x27, #0x10
    8020784c:	1100056b 	add	w11, w11, #0x1
    80207850:	3400038d 	cbz	w13, 802078c0 <_vfiprintf_r+0x3b0>
    80207854:	91000800 	add	x0, x0, #0x2
    80207858:	910403e2 	add	x2, sp, #0x100
    8020785c:	d2800041 	mov	x1, #0x2                   	// #2
    80207860:	a9000762 	stp	x2, x1, [x27]
    80207864:	b9012beb 	str	w11, [sp, #296]
    80207868:	f9009be0 	str	x0, [sp, #304]
    8020786c:	71001d7f 	cmp	w11, #0x7
    80207870:	540021cd 	b.le	80207ca8 <_vfiprintf_r+0x798>
    80207874:	b4005ba0 	cbz	x0, 802083e8 <_vfiprintf_r+0xed8>
    80207878:	910483e2 	add	x2, sp, #0x120
    8020787c:	aa1503e1 	mov	x1, x21
    80207880:	aa1303e0 	mov	x0, x19
    80207884:	b9008bec 	str	w12, [sp, #136]
    80207888:	b90093e8 	str	w8, [sp, #144]
    8020788c:	b9009be3 	str	w3, [sp, #152]
    80207890:	b900c7e4 	str	w4, [sp, #196]
    80207894:	97fffedf 	bl	80207410 <__sprint_r.part.0>
    80207898:	35fff740 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    8020789c:	b9412be1 	ldr	w1, [sp, #296]
    802078a0:	aa1603fb 	mov	x27, x22
    802078a4:	f9409be0 	ldr	x0, [sp, #304]
    802078a8:	1100042b 	add	w11, w1, #0x1
    802078ac:	b9408bec 	ldr	w12, [sp, #136]
    802078b0:	b94093e8 	ldr	w8, [sp, #144]
    802078b4:	b9409be3 	ldr	w3, [sp, #152]
    802078b8:	b940c7e4 	ldr	w4, [sp, #196]
    802078bc:	d503201f 	nop
    802078c0:	7102019f 	cmp	w12, #0x80
    802078c4:	54000860 	b.eq	802079d0 <_vfiprintf_r+0x4c0>  // b.none
    802078c8:	4b1a0063 	sub	w3, w3, w26
    802078cc:	7100007f 	cmp	w3, #0x0
    802078d0:	5400120c 	b.gt	80207b10 <_vfiprintf_r+0x600>
    802078d4:	93407f49 	sxtw	x9, w26
    802078d8:	a900277c 	stp	x28, x9, [x27]
    802078dc:	8b090000 	add	x0, x0, x9
    802078e0:	b9012beb 	str	w11, [sp, #296]
    802078e4:	f9009be0 	str	x0, [sp, #304]
    802078e8:	71001d7f 	cmp	w11, #0x7
    802078ec:	540006ed 	b.le	802079c8 <_vfiprintf_r+0x4b8>
    802078f0:	b40026c0 	cbz	x0, 80207dc8 <_vfiprintf_r+0x8b8>
    802078f4:	910483e2 	add	x2, sp, #0x120
    802078f8:	aa1503e1 	mov	x1, x21
    802078fc:	aa1303e0 	mov	x0, x19
    80207900:	b9008be8 	str	w8, [sp, #136]
    80207904:	b90093e4 	str	w4, [sp, #144]
    80207908:	97fffec2 	bl	80207410 <__sprint_r.part.0>
    8020790c:	35fff3a0 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80207910:	f9409be0 	ldr	x0, [sp, #304]
    80207914:	aa1603fb 	mov	x27, x22
    80207918:	b9408be8 	ldr	w8, [sp, #136]
    8020791c:	b94093e4 	ldr	w4, [sp, #144]
    80207920:	36100098 	tbz	w24, #2, 80207930 <_vfiprintf_r+0x420>
    80207924:	4b040118 	sub	w24, w8, w4
    80207928:	7100031f 	cmp	w24, #0x0
    8020792c:	540025ac 	b.gt	80207de0 <_vfiprintf_r+0x8d0>
    80207930:	b9406fe1 	ldr	w1, [sp, #108]
    80207934:	6b04011f 	cmp	w8, w4
    80207938:	1a84a104 	csel	w4, w8, w4, ge	// ge = tcont
    8020793c:	0b040021 	add	w1, w1, w4
    80207940:	b9006fe1 	str	w1, [sp, #108]
    80207944:	b5fff140 	cbnz	x0, 8020776c <_vfiprintf_r+0x25c>
    80207948:	f9403be0 	ldr	x0, [sp, #112]
    8020794c:	b9012bff 	str	wzr, [sp, #296]
    80207950:	b4000080 	cbz	x0, 80207960 <_vfiprintf_r+0x450>
    80207954:	aa0003e1 	mov	x1, x0
    80207958:	aa1303e0 	mov	x0, x19
    8020795c:	940015a9 	bl	8020d000 <_free_r>
    80207960:	aa1603fb 	mov	x27, x22
    80207964:	17ffff20 	b	802075e4 <_vfiprintf_r+0xd4>
    80207968:	5100c001 	sub	w1, w0, #0x30
    8020796c:	5280001a 	mov	w26, #0x0                   	// #0
    80207970:	38401720 	ldrb	w0, [x25], #1
    80207974:	0b1a0b48 	add	w8, w26, w26, lsl #2
    80207978:	0b08043a 	add	w26, w1, w8, lsl #1
    8020797c:	5100c001 	sub	w1, w0, #0x30
    80207980:	7100243f 	cmp	w1, #0x9
    80207984:	54ffff69 	b.ls	80207970 <_vfiprintf_r+0x460>  // b.plast
    80207988:	17ffff71 	b	8020774c <_vfiprintf_r+0x23c>
    8020798c:	39400320 	ldrb	w0, [x25]
    80207990:	321c0318 	orr	w24, w24, #0x10
    80207994:	17ffff6d 	b	80207748 <_vfiprintf_r+0x238>
    80207998:	2a0003f8 	mov	w24, w0
    8020799c:	cb190380 	sub	x0, x28, x25
    802079a0:	2a0003fa 	mov	w26, w0
    802079a4:	34ffec20 	cbz	w0, 80207728 <_vfiprintf_r+0x218>
    802079a8:	17ffff4a 	b	802076d0 <_vfiprintf_r+0x1c0>
    802079ac:	aa1603fb 	mov	x27, x22
    802079b0:	93407f40 	sxtw	x0, w26
    802079b4:	52800021 	mov	w1, #0x1                   	// #1
    802079b8:	b9012be1 	str	w1, [sp, #296]
    802079bc:	f9009be0 	str	x0, [sp, #304]
    802079c0:	a91a03fc 	stp	x28, x0, [sp, #416]
    802079c4:	d503201f 	nop
    802079c8:	9100437b 	add	x27, x27, #0x10
    802079cc:	17ffffd5 	b	80207920 <_vfiprintf_r+0x410>
    802079d0:	4b04010c 	sub	w12, w8, w4
    802079d4:	7100019f 	cmp	w12, #0x0
    802079d8:	54fff78d 	b.le	802078c8 <_vfiprintf_r+0x3b8>
    802079dc:	7100419f 	cmp	w12, #0x10
    802079e0:	54009aed 	b.le	80208d3c <_vfiprintf_r+0x182c>
    802079e4:	d000004a 	adrp	x10, 80211000 <blanks.1+0x60>
    802079e8:	9101c14a 	add	x10, x10, #0x70
    802079ec:	d280020b 	mov	x11, #0x10                  	// #16
    802079f0:	b9008bf8 	str	w24, [sp, #136]
    802079f4:	aa0a03f8 	mov	x24, x10
    802079f8:	b90093e8 	str	w8, [sp, #144]
    802079fc:	b9009be3 	str	w3, [sp, #152]
    80207a00:	aa1b03e3 	mov	x3, x27
    80207a04:	aa1903fb 	mov	x27, x25
    80207a08:	aa1703f9 	mov	x25, x23
    80207a0c:	2a0c03f7 	mov	w23, w12
    80207a10:	b900c7e4 	str	w4, [sp, #196]
    80207a14:	14000007 	b	80207a30 <_vfiprintf_r+0x520>
    80207a18:	1100082d 	add	w13, w1, #0x2
    80207a1c:	91004063 	add	x3, x3, #0x10
    80207a20:	2a0203e1 	mov	w1, w2
    80207a24:	510042f7 	sub	w23, w23, #0x10
    80207a28:	710042ff 	cmp	w23, #0x10
    80207a2c:	540002cd 	b.le	80207a84 <_vfiprintf_r+0x574>
    80207a30:	91004000 	add	x0, x0, #0x10
    80207a34:	11000422 	add	w2, w1, #0x1
    80207a38:	a9002c78 	stp	x24, x11, [x3]
    80207a3c:	b9012be2 	str	w2, [sp, #296]
    80207a40:	f9009be0 	str	x0, [sp, #304]
    80207a44:	71001c5f 	cmp	w2, #0x7
    80207a48:	54fffe8d 	b.le	80207a18 <_vfiprintf_r+0x508>
    80207a4c:	b4004a80 	cbz	x0, 8020839c <_vfiprintf_r+0xe8c>
    80207a50:	910483e2 	add	x2, sp, #0x120
    80207a54:	aa1503e1 	mov	x1, x21
    80207a58:	aa1303e0 	mov	x0, x19
    80207a5c:	97fffe6d 	bl	80207410 <__sprint_r.part.0>
    80207a60:	35ffe900 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80207a64:	b9412be1 	ldr	w1, [sp, #296]
    80207a68:	510042f7 	sub	w23, w23, #0x10
    80207a6c:	f9409be0 	ldr	x0, [sp, #304]
    80207a70:	aa1603e3 	mov	x3, x22
    80207a74:	1100042d 	add	w13, w1, #0x1
    80207a78:	d280020b 	mov	x11, #0x10                  	// #16
    80207a7c:	710042ff 	cmp	w23, #0x10
    80207a80:	54fffd8c 	b.gt	80207a30 <_vfiprintf_r+0x520>
    80207a84:	2a1703ec 	mov	w12, w23
    80207a88:	aa1803ea 	mov	x10, x24
    80207a8c:	aa1903f7 	mov	x23, x25
    80207a90:	b9408bf8 	ldr	w24, [sp, #136]
    80207a94:	aa1b03f9 	mov	x25, x27
    80207a98:	b94093e8 	ldr	w8, [sp, #144]
    80207a9c:	aa0303fb 	mov	x27, x3
    80207aa0:	b940c7e4 	ldr	w4, [sp, #196]
    80207aa4:	b9409be3 	ldr	w3, [sp, #152]
    80207aa8:	93407d81 	sxtw	x1, w12
    80207aac:	a900076a 	stp	x10, x1, [x27]
    80207ab0:	8b010000 	add	x0, x0, x1
    80207ab4:	b9012bed 	str	w13, [sp, #296]
    80207ab8:	f9009be0 	str	x0, [sp, #304]
    80207abc:	71001dbf 	cmp	w13, #0x7
    80207ac0:	54004d4d 	b.le	80208468 <_vfiprintf_r+0xf58>
    80207ac4:	b4007f20 	cbz	x0, 80208aa8 <_vfiprintf_r+0x1598>
    80207ac8:	910483e2 	add	x2, sp, #0x120
    80207acc:	aa1503e1 	mov	x1, x21
    80207ad0:	aa1303e0 	mov	x0, x19
    80207ad4:	b9008be8 	str	w8, [sp, #136]
    80207ad8:	b90093e3 	str	w3, [sp, #144]
    80207adc:	b9009be4 	str	w4, [sp, #152]
    80207ae0:	97fffe4c 	bl	80207410 <__sprint_r.part.0>
    80207ae4:	35ffe4e0 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80207ae8:	b94093e3 	ldr	w3, [sp, #144]
    80207aec:	aa1603fb 	mov	x27, x22
    80207af0:	b9412be1 	ldr	w1, [sp, #296]
    80207af4:	4b1a0063 	sub	w3, w3, w26
    80207af8:	b9408be8 	ldr	w8, [sp, #136]
    80207afc:	f9409be0 	ldr	x0, [sp, #304]
    80207b00:	1100042b 	add	w11, w1, #0x1
    80207b04:	b9409be4 	ldr	w4, [sp, #152]
    80207b08:	7100007f 	cmp	w3, #0x0
    80207b0c:	54ffee4d 	b.le	802078d4 <_vfiprintf_r+0x3c4>
    80207b10:	d000004a 	adrp	x10, 80211000 <blanks.1+0x60>
    80207b14:	9101c14a 	add	x10, x10, #0x70
    80207b18:	7100407f 	cmp	w3, #0x10
    80207b1c:	540005cd 	b.le	80207bd4 <_vfiprintf_r+0x6c4>
    80207b20:	d280020c 	mov	x12, #0x10                  	// #16
    80207b24:	b9008bf8 	str	w24, [sp, #136]
    80207b28:	aa0a03f8 	mov	x24, x10
    80207b2c:	b90093e8 	str	w8, [sp, #144]
    80207b30:	b9009be4 	str	w4, [sp, #152]
    80207b34:	aa1b03e4 	mov	x4, x27
    80207b38:	aa1903fb 	mov	x27, x25
    80207b3c:	aa1703f9 	mov	x25, x23
    80207b40:	2a0303f7 	mov	w23, w3
    80207b44:	14000007 	b	80207b60 <_vfiprintf_r+0x650>
    80207b48:	1100082b 	add	w11, w1, #0x2
    80207b4c:	91004084 	add	x4, x4, #0x10
    80207b50:	2a0203e1 	mov	w1, w2
    80207b54:	510042f7 	sub	w23, w23, #0x10
    80207b58:	710042ff 	cmp	w23, #0x10
    80207b5c:	540002cd 	b.le	80207bb4 <_vfiprintf_r+0x6a4>
    80207b60:	91004000 	add	x0, x0, #0x10
    80207b64:	11000422 	add	w2, w1, #0x1
    80207b68:	a9003098 	stp	x24, x12, [x4]
    80207b6c:	b9012be2 	str	w2, [sp, #296]
    80207b70:	f9009be0 	str	x0, [sp, #304]
    80207b74:	71001c5f 	cmp	w2, #0x7
    80207b78:	54fffe8d 	b.le	80207b48 <_vfiprintf_r+0x638>
    80207b7c:	b4000580 	cbz	x0, 80207c2c <_vfiprintf_r+0x71c>
    80207b80:	910483e2 	add	x2, sp, #0x120
    80207b84:	aa1503e1 	mov	x1, x21
    80207b88:	aa1303e0 	mov	x0, x19
    80207b8c:	97fffe21 	bl	80207410 <__sprint_r.part.0>
    80207b90:	35ffdf80 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80207b94:	b9412be1 	ldr	w1, [sp, #296]
    80207b98:	510042f7 	sub	w23, w23, #0x10
    80207b9c:	f9409be0 	ldr	x0, [sp, #304]
    80207ba0:	aa1603e4 	mov	x4, x22
    80207ba4:	1100042b 	add	w11, w1, #0x1
    80207ba8:	d280020c 	mov	x12, #0x10                  	// #16
    80207bac:	710042ff 	cmp	w23, #0x10
    80207bb0:	54fffd8c 	b.gt	80207b60 <_vfiprintf_r+0x650>
    80207bb4:	2a1703e3 	mov	w3, w23
    80207bb8:	aa1803ea 	mov	x10, x24
    80207bbc:	aa1903f7 	mov	x23, x25
    80207bc0:	b9408bf8 	ldr	w24, [sp, #136]
    80207bc4:	aa1b03f9 	mov	x25, x27
    80207bc8:	b94093e8 	ldr	w8, [sp, #144]
    80207bcc:	aa0403fb 	mov	x27, x4
    80207bd0:	b9409be4 	ldr	w4, [sp, #152]
    80207bd4:	93407c63 	sxtw	x3, w3
    80207bd8:	a9000f6a 	stp	x10, x3, [x27]
    80207bdc:	8b030000 	add	x0, x0, x3
    80207be0:	b9012beb 	str	w11, [sp, #296]
    80207be4:	f9009be0 	str	x0, [sp, #304]
    80207be8:	71001d7f 	cmp	w11, #0x7
    80207bec:	540018ad 	b.le	80207f00 <_vfiprintf_r+0x9f0>
    80207bf0:	b4ffede0 	cbz	x0, 802079ac <_vfiprintf_r+0x49c>
    80207bf4:	910483e2 	add	x2, sp, #0x120
    80207bf8:	aa1503e1 	mov	x1, x21
    80207bfc:	aa1303e0 	mov	x0, x19
    80207c00:	b9008be8 	str	w8, [sp, #136]
    80207c04:	b90093e4 	str	w4, [sp, #144]
    80207c08:	97fffe02 	bl	80207410 <__sprint_r.part.0>
    80207c0c:	35ffdba0 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80207c10:	b9412beb 	ldr	w11, [sp, #296]
    80207c14:	aa1603fb 	mov	x27, x22
    80207c18:	f9409be0 	ldr	x0, [sp, #304]
    80207c1c:	1100056b 	add	w11, w11, #0x1
    80207c20:	b9408be8 	ldr	w8, [sp, #136]
    80207c24:	b94093e4 	ldr	w4, [sp, #144]
    80207c28:	17ffff2b 	b	802078d4 <_vfiprintf_r+0x3c4>
    80207c2c:	aa1603e4 	mov	x4, x22
    80207c30:	5280002b 	mov	w11, #0x1                   	// #1
    80207c34:	52800001 	mov	w1, #0x0                   	// #0
    80207c38:	17ffffc7 	b	80207b54 <_vfiprintf_r+0x644>
    80207c3c:	b4000260 	cbz	x0, 80207c88 <_vfiprintf_r+0x778>
    80207c40:	910483e2 	add	x2, sp, #0x120
    80207c44:	aa1503e1 	mov	x1, x21
    80207c48:	aa1303e0 	mov	x0, x19
    80207c4c:	b9008bed 	str	w13, [sp, #136]
    80207c50:	b90093ec 	str	w12, [sp, #144]
    80207c54:	b9009be8 	str	w8, [sp, #152]
    80207c58:	291893e3 	stp	w3, w4, [sp, #196]
    80207c5c:	97fffded 	bl	80207410 <__sprint_r.part.0>
    80207c60:	35ffd900 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80207c64:	b9412be1 	ldr	w1, [sp, #296]
    80207c68:	aa1603fb 	mov	x27, x22
    80207c6c:	f9409be0 	ldr	x0, [sp, #304]
    80207c70:	1100042b 	add	w11, w1, #0x1
    80207c74:	b9408bed 	ldr	w13, [sp, #136]
    80207c78:	b94093ec 	ldr	w12, [sp, #144]
    80207c7c:	b9409be8 	ldr	w8, [sp, #152]
    80207c80:	295893e3 	ldp	w3, w4, [sp, #196]
    80207c84:	17fffef3 	b	80207850 <_vfiprintf_r+0x340>
    80207c88:	340042ad 	cbz	w13, 802084dc <_vfiprintf_r+0xfcc>
    80207c8c:	910403e0 	add	x0, sp, #0x100
    80207c90:	d2800041 	mov	x1, #0x2                   	// #2
    80207c94:	aa1603fb 	mov	x27, x22
    80207c98:	a91a07e0 	stp	x0, x1, [sp, #416]
    80207c9c:	aa0103e0 	mov	x0, x1
    80207ca0:	5280002b 	mov	w11, #0x1                   	// #1
    80207ca4:	d503201f 	nop
    80207ca8:	2a0b03e1 	mov	w1, w11
    80207cac:	9100437b 	add	x27, x27, #0x10
    80207cb0:	1100056b 	add	w11, w11, #0x1
    80207cb4:	17ffff03 	b	802078c0 <_vfiprintf_r+0x3b0>
    80207cb8:	7100415f 	cmp	w10, #0x10
    80207cbc:	540081ad 	b.le	80208cf0 <_vfiprintf_r+0x17e0>
    80207cc0:	d000004b 	adrp	x11, 80211000 <blanks.1+0x60>
    80207cc4:	9102016b 	add	x11, x11, #0x80
    80207cc8:	d280020e 	mov	x14, #0x10                  	// #16
    80207ccc:	b9008bf8 	str	w24, [sp, #136]
    80207cd0:	aa0b03f8 	mov	x24, x11
    80207cd4:	b90093ed 	str	w13, [sp, #144]
    80207cd8:	b9009bec 	str	w12, [sp, #152]
    80207cdc:	29188fe8 	stp	w8, w3, [sp, #196]
    80207ce0:	aa1b03e3 	mov	x3, x27
    80207ce4:	aa1903fb 	mov	x27, x25
    80207ce8:	aa1703f9 	mov	x25, x23
    80207cec:	2a0a03f7 	mov	w23, w10
    80207cf0:	b900cfe4 	str	w4, [sp, #204]
    80207cf4:	14000008 	b	80207d14 <_vfiprintf_r+0x804>
    80207cf8:	1100082f 	add	w15, w1, #0x2
    80207cfc:	91004063 	add	x3, x3, #0x10
    80207d00:	2a0203e1 	mov	w1, w2
    80207d04:	510042f7 	sub	w23, w23, #0x10
    80207d08:	710042ff 	cmp	w23, #0x10
    80207d0c:	540002cd 	b.le	80207d64 <_vfiprintf_r+0x854>
    80207d10:	11000422 	add	w2, w1, #0x1
    80207d14:	91004000 	add	x0, x0, #0x10
    80207d18:	a9003878 	stp	x24, x14, [x3]
    80207d1c:	b9012be2 	str	w2, [sp, #296]
    80207d20:	f9009be0 	str	x0, [sp, #304]
    80207d24:	71001c5f 	cmp	w2, #0x7
    80207d28:	54fffe8d 	b.le	80207cf8 <_vfiprintf_r+0x7e8>
    80207d2c:	b4000460 	cbz	x0, 80207db8 <_vfiprintf_r+0x8a8>
    80207d30:	910483e2 	add	x2, sp, #0x120
    80207d34:	aa1503e1 	mov	x1, x21
    80207d38:	aa1303e0 	mov	x0, x19
    80207d3c:	97fffdb5 	bl	80207410 <__sprint_r.part.0>
    80207d40:	35ffd200 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80207d44:	b9412be1 	ldr	w1, [sp, #296]
    80207d48:	510042f7 	sub	w23, w23, #0x10
    80207d4c:	f9409be0 	ldr	x0, [sp, #304]
    80207d50:	aa1603e3 	mov	x3, x22
    80207d54:	1100042f 	add	w15, w1, #0x1
    80207d58:	d280020e 	mov	x14, #0x10                  	// #16
    80207d5c:	710042ff 	cmp	w23, #0x10
    80207d60:	54fffd8c 	b.gt	80207d10 <_vfiprintf_r+0x800>
    80207d64:	2a1703ea 	mov	w10, w23
    80207d68:	aa1803eb 	mov	x11, x24
    80207d6c:	aa1903f7 	mov	x23, x25
    80207d70:	b9408bf8 	ldr	w24, [sp, #136]
    80207d74:	aa1b03f9 	mov	x25, x27
    80207d78:	b94093ed 	ldr	w13, [sp, #144]
    80207d7c:	aa0303fb 	mov	x27, x3
    80207d80:	b9409bec 	ldr	w12, [sp, #152]
    80207d84:	29588fe8 	ldp	w8, w3, [sp, #196]
    80207d88:	b940cfe4 	ldr	w4, [sp, #204]
    80207d8c:	93407d4a 	sxtw	x10, w10
    80207d90:	a9002b6b 	stp	x11, x10, [x27]
    80207d94:	8b0a0000 	add	x0, x0, x10
    80207d98:	b9012bef 	str	w15, [sp, #296]
    80207d9c:	f9009be0 	str	x0, [sp, #304]
    80207da0:	71001dff 	cmp	w15, #0x7
    80207da4:	5400334c 	b.gt	8020840c <_vfiprintf_r+0xefc>
    80207da8:	9100437b 	add	x27, x27, #0x10
    80207dac:	110005eb 	add	w11, w15, #0x1
    80207db0:	2a0f03e1 	mov	w1, w15
    80207db4:	17fffe99 	b	80207818 <_vfiprintf_r+0x308>
    80207db8:	aa1603e3 	mov	x3, x22
    80207dbc:	52800001 	mov	w1, #0x0                   	// #0
    80207dc0:	5280002f 	mov	w15, #0x1                   	// #1
    80207dc4:	17ffffd0 	b	80207d04 <_vfiprintf_r+0x7f4>
    80207dc8:	b9012bff 	str	wzr, [sp, #296]
    80207dcc:	361008f8 	tbz	w24, #2, 80207ee8 <_vfiprintf_r+0x9d8>
    80207dd0:	4b040118 	sub	w24, w8, w4
    80207dd4:	7100031f 	cmp	w24, #0x0
    80207dd8:	5400088d 	b.le	80207ee8 <_vfiprintf_r+0x9d8>
    80207ddc:	aa1603fb 	mov	x27, x22
    80207de0:	b9412be2 	ldr	w2, [sp, #296]
    80207de4:	7100431f 	cmp	w24, #0x10
    80207de8:	540078cd 	b.le	80208d00 <_vfiprintf_r+0x17f0>
    80207dec:	d000004b 	adrp	x11, 80211000 <blanks.1+0x60>
    80207df0:	9102016b 	add	x11, x11, #0x80
    80207df4:	2a0803fc 	mov	w28, w8
    80207df8:	d280021a 	mov	x26, #0x10                  	// #16
    80207dfc:	b9008be4 	str	w4, [sp, #136]
    80207e00:	f9004bf7 	str	x23, [sp, #144]
    80207e04:	2a1803f7 	mov	w23, w24
    80207e08:	aa0b03f8 	mov	x24, x11
    80207e0c:	14000007 	b	80207e28 <_vfiprintf_r+0x918>
    80207e10:	11000846 	add	w6, w2, #0x2
    80207e14:	9100437b 	add	x27, x27, #0x10
    80207e18:	2a0103e2 	mov	w2, w1
    80207e1c:	510042f7 	sub	w23, w23, #0x10
    80207e20:	710042ff 	cmp	w23, #0x10
    80207e24:	540002ad 	b.le	80207e78 <_vfiprintf_r+0x968>
    80207e28:	91004000 	add	x0, x0, #0x10
    80207e2c:	11000441 	add	w1, w2, #0x1
    80207e30:	a9006b78 	stp	x24, x26, [x27]
    80207e34:	b9012be1 	str	w1, [sp, #296]
    80207e38:	f9009be0 	str	x0, [sp, #304]
    80207e3c:	71001c3f 	cmp	w1, #0x7
    80207e40:	54fffe8d 	b.le	80207e10 <_vfiprintf_r+0x900>
    80207e44:	b40004a0 	cbz	x0, 80207ed8 <_vfiprintf_r+0x9c8>
    80207e48:	910483e2 	add	x2, sp, #0x120
    80207e4c:	aa1503e1 	mov	x1, x21
    80207e50:	aa1303e0 	mov	x0, x19
    80207e54:	97fffd6f 	bl	80207410 <__sprint_r.part.0>
    80207e58:	35ffc940 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80207e5c:	b9412be2 	ldr	w2, [sp, #296]
    80207e60:	510042f7 	sub	w23, w23, #0x10
    80207e64:	f9409be0 	ldr	x0, [sp, #304]
    80207e68:	aa1603fb 	mov	x27, x22
    80207e6c:	11000446 	add	w6, w2, #0x1
    80207e70:	710042ff 	cmp	w23, #0x10
    80207e74:	54fffdac 	b.gt	80207e28 <_vfiprintf_r+0x918>
    80207e78:	aa1803eb 	mov	x11, x24
    80207e7c:	b9408be4 	ldr	w4, [sp, #136]
    80207e80:	2a1703f8 	mov	w24, w23
    80207e84:	2a1c03e8 	mov	w8, w28
    80207e88:	f9404bf7 	ldr	x23, [sp, #144]
    80207e8c:	93407f03 	sxtw	x3, w24
    80207e90:	8b030000 	add	x0, x0, x3
    80207e94:	a9000f6b 	stp	x11, x3, [x27]
    80207e98:	b9012be6 	str	w6, [sp, #296]
    80207e9c:	f9009be0 	str	x0, [sp, #304]
    80207ea0:	71001cdf 	cmp	w6, #0x7
    80207ea4:	54ffd46d 	b.le	80207930 <_vfiprintf_r+0x420>
    80207ea8:	b4000200 	cbz	x0, 80207ee8 <_vfiprintf_r+0x9d8>
    80207eac:	910483e2 	add	x2, sp, #0x120
    80207eb0:	aa1503e1 	mov	x1, x21
    80207eb4:	aa1303e0 	mov	x0, x19
    80207eb8:	b9008be8 	str	w8, [sp, #136]
    80207ebc:	b90093e4 	str	w4, [sp, #144]
    80207ec0:	97fffd54 	bl	80207410 <__sprint_r.part.0>
    80207ec4:	35ffc5e0 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80207ec8:	f9409be0 	ldr	x0, [sp, #304]
    80207ecc:	b9408be8 	ldr	w8, [sp, #136]
    80207ed0:	b94093e4 	ldr	w4, [sp, #144]
    80207ed4:	17fffe97 	b	80207930 <_vfiprintf_r+0x420>
    80207ed8:	aa1603fb 	mov	x27, x22
    80207edc:	52800026 	mov	w6, #0x1                   	// #1
    80207ee0:	52800002 	mov	w2, #0x0                   	// #0
    80207ee4:	17ffffce 	b	80207e1c <_vfiprintf_r+0x90c>
    80207ee8:	b9406fe0 	ldr	w0, [sp, #108]
    80207eec:	6b04011f 	cmp	w8, w4
    80207ef0:	1a84a104 	csel	w4, w8, w4, ge	// ge = tcont
    80207ef4:	0b040000 	add	w0, w0, w4
    80207ef8:	b9006fe0 	str	w0, [sp, #108]
    80207efc:	17fffe93 	b	80207948 <_vfiprintf_r+0x438>
    80207f00:	9100437b 	add	x27, x27, #0x10
    80207f04:	1100056b 	add	w11, w11, #0x1
    80207f08:	17fffe73 	b	802078d4 <_vfiprintf_r+0x3c4>
    80207f0c:	374fc4a0 	tbnz	w0, #9, 802077a0 <_vfiprintf_r+0x290>
    80207f10:	f94052a0 	ldr	x0, [x21, #160]
    80207f14:	9400073b 	bl	80209c00 <__retarget_lock_release_recursive>
    80207f18:	79c022a0 	ldrsh	w0, [x21, #16]
    80207f1c:	17fffe21 	b	802077a0 <_vfiprintf_r+0x290>
    80207f20:	b940c3e1 	ldr	w1, [sp, #192]
    80207f24:	2a1a03e8 	mov	w8, w26
    80207f28:	2a1c03e3 	mov	w3, w28
    80207f2c:	37f82f61 	tbnz	w1, #31, 80208518 <_vfiprintf_r+0x1008>
    80207f30:	91003ee1 	add	x1, x23, #0xf
    80207f34:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80207f38:	f90047e1 	str	x1, [sp, #136]
    80207f3c:	f94002fc 	ldr	x28, [x23]
    80207f40:	3903ffff 	strb	wzr, [sp, #255]
    80207f44:	b4004d3c 	cbz	x28, 802088e8 <_vfiprintf_r+0x13d8>
    80207f48:	71014c1f 	cmp	w0, #0x53
    80207f4c:	54003e60 	b.eq	80208718 <_vfiprintf_r+0x1208>  // b.none
    80207f50:	37203e58 	tbnz	w24, #4, 80208718 <_vfiprintf_r+0x1208>
    80207f54:	37f86bc3 	tbnz	w3, #31, 80208ccc <_vfiprintf_r+0x17bc>
    80207f58:	93407c62 	sxtw	x2, w3
    80207f5c:	aa1c03e0 	mov	x0, x28
    80207f60:	52800001 	mov	w1, #0x0                   	// #0
    80207f64:	b90093e3 	str	w3, [sp, #144]
    80207f68:	b9009be8 	str	w8, [sp, #152]
    80207f6c:	94000ac5 	bl	8020aa80 <memchr>
    80207f70:	f9003be0 	str	x0, [sp, #112]
    80207f74:	b94093e3 	ldr	w3, [sp, #144]
    80207f78:	b9409be8 	ldr	w8, [sp, #152]
    80207f7c:	b4006580 	cbz	x0, 80208c2c <_vfiprintf_r+0x171c>
    80207f80:	cb1c0004 	sub	x4, x0, x28
    80207f84:	f9003bff 	str	xzr, [sp, #112]
    80207f88:	7100009f 	cmp	w4, #0x0
    80207f8c:	2a0403fa 	mov	w26, w4
    80207f90:	1a9fa084 	csel	w4, w4, wzr, ge	// ge = tcont
    80207f94:	140002ac 	b	80208a44 <_vfiprintf_r+0x1534>
    80207f98:	2a1a03e8 	mov	w8, w26
    80207f9c:	71010c1f 	cmp	w0, #0x43
    80207fa0:	54000040 	b.eq	80207fa8 <_vfiprintf_r+0xa98>  // b.none
    80207fa4:	36202df8 	tbz	w24, #4, 80208560 <_vfiprintf_r+0x1050>
    80207fa8:	910463e0 	add	x0, sp, #0x118
    80207fac:	d2800102 	mov	x2, #0x8                   	// #8
    80207fb0:	52800001 	mov	w1, #0x0                   	// #0
    80207fb4:	b90073e8 	str	w8, [sp, #112]
    80207fb8:	97ffedc2 	bl	802036c0 <memset>
    80207fbc:	b940c3e0 	ldr	w0, [sp, #192]
    80207fc0:	b94073e8 	ldr	w8, [sp, #112]
    80207fc4:	37f85100 	tbnz	w0, #31, 802089e4 <_vfiprintf_r+0x14d4>
    80207fc8:	91002ee1 	add	x1, x23, #0xb
    80207fcc:	aa1703e0 	mov	x0, x23
    80207fd0:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80207fd4:	b9400002 	ldr	w2, [x0]
    80207fd8:	9104e3fc 	add	x28, sp, #0x138
    80207fdc:	910463e3 	add	x3, sp, #0x118
    80207fe0:	aa1c03e1 	mov	x1, x28
    80207fe4:	aa1303e0 	mov	x0, x19
    80207fe8:	b90073e8 	str	w8, [sp, #112]
    80207fec:	94000695 	bl	80209a40 <_wcrtomb_r>
    80207ff0:	2a0003fa 	mov	w26, w0
    80207ff4:	b94073e8 	ldr	w8, [sp, #112]
    80207ff8:	3100041f 	cmn	w0, #0x1
    80207ffc:	54008320 	b.eq	80209060 <_vfiprintf_r+0x1b50>  // b.none
    80208000:	7100001f 	cmp	w0, #0x0
    80208004:	3903ffff 	strb	wzr, [sp, #255]
    80208008:	1a9fa004 	csel	w4, w0, wzr, ge	// ge = tcont
    8020800c:	17fffdf6 	b	802077e4 <_vfiprintf_r+0x2d4>
    80208010:	4b1a03fa 	neg	w26, w26
    80208014:	aa0003f7 	mov	x23, x0
    80208018:	39400320 	ldrb	w0, [x25]
    8020801c:	321e0318 	orr	w24, w24, #0x4
    80208020:	17fffdca 	b	80207748 <_vfiprintf_r+0x238>
    80208024:	52800560 	mov	w0, #0x2b                  	// #43
    80208028:	3903ffe0 	strb	w0, [sp, #255]
    8020802c:	39400320 	ldrb	w0, [x25]
    80208030:	17fffdc6 	b	80207748 <_vfiprintf_r+0x238>
    80208034:	39400320 	ldrb	w0, [x25]
    80208038:	32190318 	orr	w24, w24, #0x80
    8020803c:	17fffdc3 	b	80207748 <_vfiprintf_r+0x238>
    80208040:	aa1903e2 	mov	x2, x25
    80208044:	38401440 	ldrb	w0, [x2], #1
    80208048:	7100a81f 	cmp	w0, #0x2a
    8020804c:	54007b40 	b.eq	80208fb4 <_vfiprintf_r+0x1aa4>  // b.none
    80208050:	5100c001 	sub	w1, w0, #0x30
    80208054:	aa0203f9 	mov	x25, x2
    80208058:	52800003 	mov	w3, #0x0                   	// #0
    8020805c:	5280001c 	mov	w28, #0x0                   	// #0
    80208060:	7100243f 	cmp	w1, #0x9
    80208064:	54ffb748 	b.hi	8020774c <_vfiprintf_r+0x23c>  // b.pmore
    80208068:	38401440 	ldrb	w0, [x2], #1
    8020806c:	0b030863 	add	w3, w3, w3, lsl #2
    80208070:	0b030423 	add	w3, w1, w3, lsl #1
    80208074:	5100c001 	sub	w1, w0, #0x30
    80208078:	7100243f 	cmp	w1, #0x9
    8020807c:	54ffff69 	b.ls	80208068 <_vfiprintf_r+0xb58>  // b.plast
    80208080:	7100007f 	cmp	w3, #0x0
    80208084:	aa0203f9 	mov	x25, x2
    80208088:	5a9fa07c 	csinv	w28, w3, wzr, ge	// ge = tcont
    8020808c:	17fffdb0 	b	8020774c <_vfiprintf_r+0x23c>
    80208090:	b940c3e0 	ldr	w0, [sp, #192]
    80208094:	37f82320 	tbnz	w0, #31, 802084f8 <_vfiprintf_r+0xfe8>
    80208098:	91002ee0 	add	x0, x23, #0xb
    8020809c:	927df000 	and	x0, x0, #0xfffffffffffffff8
    802080a0:	b94002fa 	ldr	w26, [x23]
    802080a4:	37fffb7a 	tbnz	w26, #31, 80208010 <_vfiprintf_r+0xb00>
    802080a8:	aa0003f7 	mov	x23, x0
    802080ac:	39400320 	ldrb	w0, [x25]
    802080b0:	17fffda6 	b	80207748 <_vfiprintf_r+0x238>
    802080b4:	aa1303e0 	mov	x0, x19
    802080b8:	94000a0a 	bl	8020a8e0 <_localeconv_r>
    802080bc:	f9400400 	ldr	x0, [x0, #8]
    802080c0:	f9005fe0 	str	x0, [sp, #184]
    802080c4:	97ffee0f 	bl	80203900 <strlen>
    802080c8:	aa0003e1 	mov	x1, x0
    802080cc:	aa1303e0 	mov	x0, x19
    802080d0:	f90057e1 	str	x1, [sp, #168]
    802080d4:	94000a03 	bl	8020a8e0 <_localeconv_r>
    802080d8:	f94057e1 	ldr	x1, [sp, #168]
    802080dc:	f9400800 	ldr	x0, [x0, #16]
    802080e0:	f9005be0 	str	x0, [sp, #176]
    802080e4:	f100003f 	cmp	x1, #0x0
    802080e8:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
    802080ec:	54001c60 	b.eq	80208478 <_vfiprintf_r+0xf68>  // b.none
    802080f0:	39400000 	ldrb	w0, [x0]
    802080f4:	32160301 	orr	w1, w24, #0x400
    802080f8:	7100001f 	cmp	w0, #0x0
    802080fc:	39400320 	ldrb	w0, [x25]
    80208100:	1a981038 	csel	w24, w1, w24, ne	// ne = any
    80208104:	17fffd91 	b	80207748 <_vfiprintf_r+0x238>
    80208108:	39400320 	ldrb	w0, [x25]
    8020810c:	32000318 	orr	w24, w24, #0x1
    80208110:	17fffd8e 	b	80207748 <_vfiprintf_r+0x238>
    80208114:	3943ffe1 	ldrb	w1, [sp, #255]
    80208118:	39400320 	ldrb	w0, [x25]
    8020811c:	35ffb161 	cbnz	w1, 80207748 <_vfiprintf_r+0x238>
    80208120:	52800401 	mov	w1, #0x20                  	// #32
    80208124:	3903ffe1 	strb	w1, [sp, #255]
    80208128:	17fffd88 	b	80207748 <_vfiprintf_r+0x238>
    8020812c:	2a1a03e8 	mov	w8, w26
    80208130:	2a1c03e3 	mov	w3, w28
    80208134:	321c0318 	orr	w24, w24, #0x10
    80208138:	b940c3e0 	ldr	w0, [sp, #192]
    8020813c:	37280058 	tbnz	w24, #5, 80208144 <_vfiprintf_r+0xc34>
    80208140:	36201b18 	tbz	w24, #4, 802084a0 <_vfiprintf_r+0xf90>
    80208144:	37f82ce0 	tbnz	w0, #31, 802086e0 <_vfiprintf_r+0x11d0>
    80208148:	91003ee1 	add	x1, x23, #0xf
    8020814c:	aa1703e0 	mov	x0, x23
    80208150:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208154:	f9400001 	ldr	x1, [x0]
    80208158:	12157b04 	and	w4, w24, #0xfffffbff
    8020815c:	52800000 	mov	w0, #0x0                   	// #0
    80208160:	52800002 	mov	w2, #0x0                   	// #0
    80208164:	3903ffe2 	strb	w2, [sp, #255]
    80208168:	37f80da3 	tbnz	w3, #31, 8020831c <_vfiprintf_r+0xe0c>
    8020816c:	f100003f 	cmp	x1, #0x0
    80208170:	12187898 	and	w24, w4, #0xffffff7f
    80208174:	7a400860 	ccmp	w3, #0x0, #0x0, eq	// eq = none
    80208178:	54000d01 	b.ne	80208318 <_vfiprintf_r+0xe08>  // b.any
    8020817c:	35000620 	cbnz	w0, 80208240 <_vfiprintf_r+0xd30>
    80208180:	1200009a 	and	w26, w4, #0x1
    80208184:	360012c4 	tbz	w4, #0, 802083dc <_vfiprintf_r+0xecc>
    80208188:	91066ffc 	add	x28, sp, #0x19b
    8020818c:	52800600 	mov	w0, #0x30                  	// #48
    80208190:	52800003 	mov	w3, #0x0                   	// #0
    80208194:	39066fe0 	strb	w0, [sp, #411]
    80208198:	3943ffe0 	ldrb	w0, [sp, #255]
    8020819c:	6b1a007f 	cmp	w3, w26
    802081a0:	f9003bff 	str	xzr, [sp, #112]
    802081a4:	1a9aa064 	csel	w4, w3, w26, ge	// ge = tcont
    802081a8:	34000040 	cbz	w0, 802081b0 <_vfiprintf_r+0xca0>
    802081ac:	11000484 	add	w4, w4, #0x1
    802081b0:	121f030d 	and	w13, w24, #0x2
    802081b4:	360fb1f8 	tbz	w24, #1, 802077f0 <_vfiprintf_r+0x2e0>
    802081b8:	11000884 	add	w4, w4, #0x2
    802081bc:	5280004d 	mov	w13, #0x2                   	// #2
    802081c0:	17fffd8c 	b	802077f0 <_vfiprintf_r+0x2e0>
    802081c4:	2a1a03e8 	mov	w8, w26
    802081c8:	2a1c03e3 	mov	w3, w28
    802081cc:	321c0304 	orr	w4, w24, #0x10
    802081d0:	b940c3e0 	ldr	w0, [sp, #192]
    802081d4:	37280044 	tbnz	w4, #5, 802081dc <_vfiprintf_r+0xccc>
    802081d8:	36201544 	tbz	w4, #4, 80208480 <_vfiprintf_r+0xf70>
    802081dc:	37f82700 	tbnz	w0, #31, 802086bc <_vfiprintf_r+0x11ac>
    802081e0:	91003ee1 	add	x1, x23, #0xf
    802081e4:	aa1703e0 	mov	x0, x23
    802081e8:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802081ec:	f9400001 	ldr	x1, [x0]
    802081f0:	52800020 	mov	w0, #0x1                   	// #1
    802081f4:	17ffffdb 	b	80208160 <_vfiprintf_r+0xc50>
    802081f8:	2a1a03e8 	mov	w8, w26
    802081fc:	2a1c03e3 	mov	w3, w28
    80208200:	321c0318 	orr	w24, w24, #0x10
    80208204:	b940c3e0 	ldr	w0, [sp, #192]
    80208208:	37280058 	tbnz	w24, #5, 80208210 <_vfiprintf_r+0xd00>
    8020820c:	36201598 	tbz	w24, #4, 802084bc <_vfiprintf_r+0xfac>
    80208210:	37f82440 	tbnz	w0, #31, 80208698 <_vfiprintf_r+0x1188>
    80208214:	91003ee1 	add	x1, x23, #0xf
    80208218:	aa1703e0 	mov	x0, x23
    8020821c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208220:	f9400000 	ldr	x0, [x0]
    80208224:	aa0003e1 	mov	x1, x0
    80208228:	b7f80e80 	tbnz	x0, #63, 802083f8 <_vfiprintf_r+0xee8>
    8020822c:	7100007f 	cmp	w3, #0x0
    80208230:	54000beb 	b.lt	802083ac <_vfiprintf_r+0xe9c>  // b.tstop
    80208234:	12187b18 	and	w24, w24, #0xffffff7f
    80208238:	fa400820 	ccmp	x1, #0x0, #0x0, eq	// eq = none
    8020823c:	54000b81 	b.ne	802083ac <_vfiprintf_r+0xe9c>  // b.any
    80208240:	910673fc 	add	x28, sp, #0x19c
    80208244:	52800003 	mov	w3, #0x0                   	// #0
    80208248:	5280001a 	mov	w26, #0x0                   	// #0
    8020824c:	17ffffd3 	b	80208198 <_vfiprintf_r+0xc88>
    80208250:	b940c3e0 	ldr	w0, [sp, #192]
    80208254:	37280198 	tbnz	w24, #5, 80208284 <_vfiprintf_r+0xd74>
    80208258:	37200178 	tbnz	w24, #4, 80208284 <_vfiprintf_r+0xd74>
    8020825c:	373042f8 	tbnz	w24, #6, 80208ab8 <_vfiprintf_r+0x15a8>
    80208260:	36486138 	tbz	w24, #9, 80208e84 <_vfiprintf_r+0x1974>
    80208264:	37f86960 	tbnz	w0, #31, 80208f90 <_vfiprintf_r+0x1a80>
    80208268:	91003ee1 	add	x1, x23, #0xf
    8020826c:	aa1703e0 	mov	x0, x23
    80208270:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208274:	f9400000 	ldr	x0, [x0]
    80208278:	3941b3e1 	ldrb	w1, [sp, #108]
    8020827c:	39000001 	strb	w1, [x0]
    80208280:	17fffcd9 	b	802075e4 <_vfiprintf_r+0xd4>
    80208284:	37f81860 	tbnz	w0, #31, 80208590 <_vfiprintf_r+0x1080>
    80208288:	91003ee1 	add	x1, x23, #0xf
    8020828c:	aa1703e0 	mov	x0, x23
    80208290:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208294:	f9400000 	ldr	x0, [x0]
    80208298:	b9806fe1 	ldrsw	x1, [sp, #108]
    8020829c:	f9000001 	str	x1, [x0]
    802082a0:	17fffcd1 	b	802075e4 <_vfiprintf_r+0xd4>
    802082a4:	39400320 	ldrb	w0, [x25]
    802082a8:	7101b01f 	cmp	w0, #0x6c
    802082ac:	540030e0 	b.eq	802088c8 <_vfiprintf_r+0x13b8>  // b.none
    802082b0:	321c0318 	orr	w24, w24, #0x10
    802082b4:	17fffd25 	b	80207748 <_vfiprintf_r+0x238>
    802082b8:	39400320 	ldrb	w0, [x25]
    802082bc:	7101a01f 	cmp	w0, #0x68
    802082c0:	540030c0 	b.eq	802088d8 <_vfiprintf_r+0x13c8>  // b.none
    802082c4:	321a0318 	orr	w24, w24, #0x40
    802082c8:	17fffd20 	b	80207748 <_vfiprintf_r+0x238>
    802082cc:	39400320 	ldrb	w0, [x25]
    802082d0:	321b0318 	orr	w24, w24, #0x20
    802082d4:	17fffd1d 	b	80207748 <_vfiprintf_r+0x238>
    802082d8:	b940c3e0 	ldr	w0, [sp, #192]
    802082dc:	2a1a03e8 	mov	w8, w26
    802082e0:	2a1c03e3 	mov	w3, w28
    802082e4:	37f812c0 	tbnz	w0, #31, 8020853c <_vfiprintf_r+0x102c>
    802082e8:	91003ee1 	add	x1, x23, #0xf
    802082ec:	aa1703e0 	mov	x0, x23
    802082f0:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802082f4:	f9400001 	ldr	x1, [x0]
    802082f8:	528f0600 	mov	w0, #0x7830                	// #30768
    802082fc:	90000042 	adrp	x2, 80210000 <_wcsnrtombs_l+0x110>
    80208300:	321f0304 	orr	w4, w24, #0x2
    80208304:	912f4042 	add	x2, x2, #0xbd0
    80208308:	f90053e2 	str	x2, [sp, #160]
    8020830c:	790203e0 	strh	w0, [sp, #256]
    80208310:	52800040 	mov	w0, #0x2                   	// #2
    80208314:	17ffff93 	b	80208160 <_vfiprintf_r+0xc50>
    80208318:	2a1803e4 	mov	w4, w24
    8020831c:	7100041f 	cmp	w0, #0x1
    80208320:	54000480 	b.eq	802083b0 <_vfiprintf_r+0xea0>  // b.none
    80208324:	910673fa 	add	x26, sp, #0x19c
    80208328:	aa1a03fc 	mov	x28, x26
    8020832c:	7100081f 	cmp	w0, #0x2
    80208330:	54000141 	b.ne	80208358 <_vfiprintf_r+0xe48>  // b.any
    80208334:	f94053e2 	ldr	x2, [sp, #160]
    80208338:	92400c20 	and	x0, x1, #0xf
    8020833c:	d344fc21 	lsr	x1, x1, #4
    80208340:	38606840 	ldrb	w0, [x2, x0]
    80208344:	381fff80 	strb	w0, [x28, #-1]!
    80208348:	b5ffff81 	cbnz	x1, 80208338 <_vfiprintf_r+0xe28>
    8020834c:	4b1c035a 	sub	w26, w26, w28
    80208350:	2a0403f8 	mov	w24, w4
    80208354:	17ffff91 	b	80208198 <_vfiprintf_r+0xc88>
    80208358:	12000820 	and	w0, w1, #0x7
    8020835c:	aa1c03e2 	mov	x2, x28
    80208360:	1100c000 	add	w0, w0, #0x30
    80208364:	381fff80 	strb	w0, [x28, #-1]!
    80208368:	d343fc21 	lsr	x1, x1, #3
    8020836c:	b5ffff61 	cbnz	x1, 80208358 <_vfiprintf_r+0xe48>
    80208370:	7100c01f 	cmp	w0, #0x30
    80208374:	1a9f07e0 	cset	w0, ne	// ne = any
    80208378:	6a00009f 	tst	w4, w0
    8020837c:	54fffe80 	b.eq	8020834c <_vfiprintf_r+0xe3c>  // b.none
    80208380:	d1000842 	sub	x2, x2, #0x2
    80208384:	52800600 	mov	w0, #0x30                  	// #48
    80208388:	2a0403f8 	mov	w24, w4
    8020838c:	4b02035a 	sub	w26, w26, w2
    80208390:	381ff380 	sturb	w0, [x28, #-1]
    80208394:	aa0203fc 	mov	x28, x2
    80208398:	17ffff80 	b	80208198 <_vfiprintf_r+0xc88>
    8020839c:	aa1603e3 	mov	x3, x22
    802083a0:	5280002d 	mov	w13, #0x1                   	// #1
    802083a4:	52800001 	mov	w1, #0x0                   	// #0
    802083a8:	17fffd9f 	b	80207a24 <_vfiprintf_r+0x514>
    802083ac:	2a1803e4 	mov	w4, w24
    802083b0:	f100243f 	cmp	x1, #0x9
    802083b4:	54002308 	b.hi	80208814 <_vfiprintf_r+0x1304>  // b.pmore
    802083b8:	1100c021 	add	w1, w1, #0x30
    802083bc:	2a0403f8 	mov	w24, w4
    802083c0:	91066ffc 	add	x28, sp, #0x19b
    802083c4:	5280003a 	mov	w26, #0x1                   	// #1
    802083c8:	39066fe1 	strb	w1, [sp, #411]
    802083cc:	17ffff73 	b	80208198 <_vfiprintf_r+0xc88>
    802083d0:	aa1603fb 	mov	x27, x22
    802083d4:	b9012bff 	str	wzr, [sp, #296]
    802083d8:	17fffcd0 	b	80207718 <_vfiprintf_r+0x208>
    802083dc:	910673fc 	add	x28, sp, #0x19c
    802083e0:	52800003 	mov	w3, #0x0                   	// #0
    802083e4:	17ffff6d 	b	80208198 <_vfiprintf_r+0xc88>
    802083e8:	aa1603fb 	mov	x27, x22
    802083ec:	5280002b 	mov	w11, #0x1                   	// #1
    802083f0:	52800001 	mov	w1, #0x0                   	// #0
    802083f4:	17fffd33 	b	802078c0 <_vfiprintf_r+0x3b0>
    802083f8:	cb0103e1 	neg	x1, x1
    802083fc:	2a1803e4 	mov	w4, w24
    80208400:	528005a2 	mov	w2, #0x2d                  	// #45
    80208404:	52800020 	mov	w0, #0x1                   	// #1
    80208408:	17ffff57 	b	80208164 <_vfiprintf_r+0xc54>
    8020840c:	b4000d40 	cbz	x0, 802085b4 <_vfiprintf_r+0x10a4>
    80208410:	910483e2 	add	x2, sp, #0x120
    80208414:	aa1503e1 	mov	x1, x21
    80208418:	aa1303e0 	mov	x0, x19
    8020841c:	b9008bed 	str	w13, [sp, #136]
    80208420:	b90093ec 	str	w12, [sp, #144]
    80208424:	b9009be8 	str	w8, [sp, #152]
    80208428:	291893e3 	stp	w3, w4, [sp, #196]
    8020842c:	97fffbf9 	bl	80207410 <__sprint_r.part.0>
    80208430:	35ff9a80 	cbnz	w0, 80207780 <_vfiprintf_r+0x270>
    80208434:	b9412be1 	ldr	w1, [sp, #296]
    80208438:	aa1603fb 	mov	x27, x22
    8020843c:	f9409be0 	ldr	x0, [sp, #304]
    80208440:	1100042b 	add	w11, w1, #0x1
    80208444:	b9408bed 	ldr	w13, [sp, #136]
    80208448:	b94093ec 	ldr	w12, [sp, #144]
    8020844c:	b9409be8 	ldr	w8, [sp, #152]
    80208450:	295893e3 	ldp	w3, w4, [sp, #196]
    80208454:	17fffcf1 	b	80207818 <_vfiprintf_r+0x308>
    80208458:	f94052a0 	ldr	x0, [x21, #160]
    8020845c:	940005d9 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    80208460:	79c022a0 	ldrsh	w0, [x21, #16]
    80208464:	17fffc45 	b	80207578 <_vfiprintf_r+0x68>
    80208468:	9100437b 	add	x27, x27, #0x10
    8020846c:	110005ab 	add	w11, w13, #0x1
    80208470:	2a0d03e1 	mov	w1, w13
    80208474:	17fffd15 	b	802078c8 <_vfiprintf_r+0x3b8>
    80208478:	39400320 	ldrb	w0, [x25]
    8020847c:	17fffcb3 	b	80207748 <_vfiprintf_r+0x238>
    80208480:	363024e4 	tbz	w4, #6, 8020891c <_vfiprintf_r+0x140c>
    80208484:	37f83640 	tbnz	w0, #31, 80208b4c <_vfiprintf_r+0x163c>
    80208488:	91002ee1 	add	x1, x23, #0xb
    8020848c:	aa1703e0 	mov	x0, x23
    80208490:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208494:	79400001 	ldrh	w1, [x0]
    80208498:	52800020 	mov	w0, #0x1                   	// #1
    8020849c:	17ffff31 	b	80208160 <_vfiprintf_r+0xc50>
    802084a0:	363024f8 	tbz	w24, #6, 8020893c <_vfiprintf_r+0x142c>
    802084a4:	37f83960 	tbnz	w0, #31, 80208bd0 <_vfiprintf_r+0x16c0>
    802084a8:	aa1703e0 	mov	x0, x23
    802084ac:	91002ee1 	add	x1, x23, #0xb
    802084b0:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802084b4:	79400001 	ldrh	w1, [x0]
    802084b8:	17ffff28 	b	80208158 <_vfiprintf_r+0xc48>
    802084bc:	363027b8 	tbz	w24, #6, 802089b0 <_vfiprintf_r+0x14a0>
    802084c0:	37f83760 	tbnz	w0, #31, 80208bac <_vfiprintf_r+0x169c>
    802084c4:	91002ee1 	add	x1, x23, #0xb
    802084c8:	aa1703e0 	mov	x0, x23
    802084cc:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802084d0:	79800001 	ldrsh	x1, [x0]
    802084d4:	aa0103e0 	mov	x0, x1
    802084d8:	17ffff54 	b	80208228 <_vfiprintf_r+0xd18>
    802084dc:	aa1603fb 	mov	x27, x22
    802084e0:	52800001 	mov	w1, #0x0                   	// #0
    802084e4:	5280002b 	mov	w11, #0x1                   	// #1
    802084e8:	17fffcf6 	b	802078c0 <_vfiprintf_r+0x3b0>
    802084ec:	2a1a03e8 	mov	w8, w26
    802084f0:	2a1c03e3 	mov	w3, w28
    802084f4:	17ffff44 	b	80208204 <_vfiprintf_r+0xcf4>
    802084f8:	b940c3e0 	ldr	w0, [sp, #192]
    802084fc:	11002001 	add	w1, w0, #0x8
    80208500:	7100003f 	cmp	w1, #0x0
    80208504:	54002b6d 	b.le	80208a70 <_vfiprintf_r+0x1560>
    80208508:	91002ee0 	add	x0, x23, #0xb
    8020850c:	b900c3e1 	str	w1, [sp, #192]
    80208510:	927df000 	and	x0, x0, #0xfffffffffffffff8
    80208514:	17fffee3 	b	802080a0 <_vfiprintf_r+0xb90>
    80208518:	b940c3e1 	ldr	w1, [sp, #192]
    8020851c:	11002021 	add	w1, w1, #0x8
    80208520:	7100003f 	cmp	w1, #0x0
    80208524:	54002b4d 	b.le	80208a8c <_vfiprintf_r+0x157c>
    80208528:	91003ee2 	add	x2, x23, #0xf
    8020852c:	b900c3e1 	str	w1, [sp, #192]
    80208530:	927df041 	and	x1, x2, #0xfffffffffffffff8
    80208534:	f90047e1 	str	x1, [sp, #136]
    80208538:	17fffe81 	b	80207f3c <_vfiprintf_r+0xa2c>
    8020853c:	b940c3e0 	ldr	w0, [sp, #192]
    80208540:	11002001 	add	w1, w0, #0x8
    80208544:	7100003f 	cmp	w1, #0x0
    80208548:	540028ad 	b.le	80208a5c <_vfiprintf_r+0x154c>
    8020854c:	91003ee2 	add	x2, x23, #0xf
    80208550:	aa1703e0 	mov	x0, x23
    80208554:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208558:	b900c3e1 	str	w1, [sp, #192]
    8020855c:	17ffff66 	b	802082f4 <_vfiprintf_r+0xde4>
    80208560:	b940c3e0 	ldr	w0, [sp, #192]
    80208564:	37f836a0 	tbnz	w0, #31, 80208c38 <_vfiprintf_r+0x1728>
    80208568:	91002ee1 	add	x1, x23, #0xb
    8020856c:	aa1703e0 	mov	x0, x23
    80208570:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208574:	b9400000 	ldr	w0, [x0]
    80208578:	52800024 	mov	w4, #0x1                   	// #1
    8020857c:	9104e3fc 	add	x28, sp, #0x138
    80208580:	2a0403fa 	mov	w26, w4
    80208584:	3903ffff 	strb	wzr, [sp, #255]
    80208588:	3904e3e0 	strb	w0, [sp, #312]
    8020858c:	17fffc96 	b	802077e4 <_vfiprintf_r+0x2d4>
    80208590:	b940c3e0 	ldr	w0, [sp, #192]
    80208594:	11002001 	add	w1, w0, #0x8
    80208598:	7100003f 	cmp	w1, #0x0
    8020859c:	540038ed 	b.le	80208cb8 <_vfiprintf_r+0x17a8>
    802085a0:	91003ee2 	add	x2, x23, #0xf
    802085a4:	aa1703e0 	mov	x0, x23
    802085a8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802085ac:	b900c3e1 	str	w1, [sp, #192]
    802085b0:	17ffff39 	b	80208294 <_vfiprintf_r+0xd84>
    802085b4:	3943ffe1 	ldrb	w1, [sp, #255]
    802085b8:	340029e1 	cbz	w1, 80208af4 <_vfiprintf_r+0x15e4>
    802085bc:	d2800020 	mov	x0, #0x1                   	// #1
    802085c0:	9103ffe1 	add	x1, sp, #0xff
    802085c4:	aa1603fb 	mov	x27, x22
    802085c8:	2a0003eb 	mov	w11, w0
    802085cc:	a91a03e1 	stp	x1, x0, [sp, #416]
    802085d0:	17fffc9d 	b	80207844 <_vfiprintf_r+0x334>
    802085d4:	2a1a03e8 	mov	w8, w26
    802085d8:	2a1c03e3 	mov	w3, w28
    802085dc:	90000041 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    802085e0:	912fa021 	add	x1, x1, #0xbe8
    802085e4:	f90053e1 	str	x1, [sp, #160]
    802085e8:	b940c3e1 	ldr	w1, [sp, #192]
    802085ec:	372802d8 	tbnz	w24, #5, 80208644 <_vfiprintf_r+0x1134>
    802085f0:	372002b8 	tbnz	w24, #4, 80208644 <_vfiprintf_r+0x1134>
    802085f4:	36301bd8 	tbz	w24, #6, 8020896c <_vfiprintf_r+0x145c>
    802085f8:	37f82bc1 	tbnz	w1, #31, 80208b70 <_vfiprintf_r+0x1660>
    802085fc:	aa1703e1 	mov	x1, x23
    80208600:	91002ee2 	add	x2, x23, #0xb
    80208604:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208608:	79400021 	ldrh	w1, [x1]
    8020860c:	14000013 	b	80208658 <_vfiprintf_r+0x1148>
    80208610:	2a1a03e8 	mov	w8, w26
    80208614:	2a1c03e3 	mov	w3, w28
    80208618:	2a1803e4 	mov	w4, w24
    8020861c:	17fffeed 	b	802081d0 <_vfiprintf_r+0xcc0>
    80208620:	90000041 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    80208624:	2a1a03e8 	mov	w8, w26
    80208628:	912f4021 	add	x1, x1, #0xbd0
    8020862c:	2a1c03e3 	mov	w3, w28
    80208630:	f90053e1 	str	x1, [sp, #160]
    80208634:	17ffffed 	b	802085e8 <_vfiprintf_r+0x10d8>
    80208638:	2a1a03e8 	mov	w8, w26
    8020863c:	2a1c03e3 	mov	w3, w28
    80208640:	17fffebe 	b	80208138 <_vfiprintf_r+0xc28>
    80208644:	37f80181 	tbnz	w1, #31, 80208674 <_vfiprintf_r+0x1164>
    80208648:	91003ee2 	add	x2, x23, #0xf
    8020864c:	aa1703e1 	mov	x1, x23
    80208650:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208654:	f9400021 	ldr	x1, [x1]
    80208658:	f100003f 	cmp	x1, #0x0
    8020865c:	1a9f07e2 	cset	w2, ne	// ne = any
    80208660:	6a02031f 	tst	w24, w2
    80208664:	54000501 	b.ne	80208704 <_vfiprintf_r+0x11f4>  // b.any
    80208668:	12157b04 	and	w4, w24, #0xfffffbff
    8020866c:	52800040 	mov	w0, #0x2                   	// #2
    80208670:	17fffebc 	b	80208160 <_vfiprintf_r+0xc50>
    80208674:	b940c3e1 	ldr	w1, [sp, #192]
    80208678:	11002022 	add	w2, w1, #0x8
    8020867c:	7100005f 	cmp	w2, #0x0
    80208680:	540016cd 	b.le	80208958 <_vfiprintf_r+0x1448>
    80208684:	91003ee4 	add	x4, x23, #0xf
    80208688:	aa1703e1 	mov	x1, x23
    8020868c:	927df097 	and	x23, x4, #0xfffffffffffffff8
    80208690:	b900c3e2 	str	w2, [sp, #192]
    80208694:	17fffff0 	b	80208654 <_vfiprintf_r+0x1144>
    80208698:	b940c3e0 	ldr	w0, [sp, #192]
    8020869c:	11002001 	add	w1, w0, #0x8
    802086a0:	7100003f 	cmp	w1, #0x0
    802086a4:	540017cd 	b.le	8020899c <_vfiprintf_r+0x148c>
    802086a8:	91003ee2 	add	x2, x23, #0xf
    802086ac:	aa1703e0 	mov	x0, x23
    802086b0:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802086b4:	b900c3e1 	str	w1, [sp, #192]
    802086b8:	17fffeda 	b	80208220 <_vfiprintf_r+0xd10>
    802086bc:	b940c3e0 	ldr	w0, [sp, #192]
    802086c0:	11002001 	add	w1, w0, #0x8
    802086c4:	7100003f 	cmp	w1, #0x0
    802086c8:	5400184d 	b.le	802089d0 <_vfiprintf_r+0x14c0>
    802086cc:	91003ee2 	add	x2, x23, #0xf
    802086d0:	aa1703e0 	mov	x0, x23
    802086d4:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802086d8:	b900c3e1 	str	w1, [sp, #192]
    802086dc:	17fffec4 	b	802081ec <_vfiprintf_r+0xcdc>
    802086e0:	b940c3e0 	ldr	w0, [sp, #192]
    802086e4:	11002001 	add	w1, w0, #0x8
    802086e8:	7100003f 	cmp	w1, #0x0
    802086ec:	540014ed 	b.le	80208988 <_vfiprintf_r+0x1478>
    802086f0:	91003ee2 	add	x2, x23, #0xf
    802086f4:	aa1703e0 	mov	x0, x23
    802086f8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    802086fc:	b900c3e1 	str	w1, [sp, #192]
    80208700:	17fffe95 	b	80208154 <_vfiprintf_r+0xc44>
    80208704:	321f0318 	orr	w24, w24, #0x2
    80208708:	390407e0 	strb	w0, [sp, #257]
    8020870c:	52800600 	mov	w0, #0x30                  	// #48
    80208710:	390403e0 	strb	w0, [sp, #256]
    80208714:	17ffffd5 	b	80208668 <_vfiprintf_r+0x1158>
    80208718:	910443e0 	add	x0, sp, #0x110
    8020871c:	d2800102 	mov	x2, #0x8                   	// #8
    80208720:	52800001 	mov	w1, #0x0                   	// #0
    80208724:	b90073e8 	str	w8, [sp, #112]
    80208728:	b90093e3 	str	w3, [sp, #144]
    8020872c:	f9008ffc 	str	x28, [sp, #280]
    80208730:	97ffebe4 	bl	802036c0 <memset>
    80208734:	b94093e3 	ldr	w3, [sp, #144]
    80208738:	b94073e8 	ldr	w8, [sp, #112]
    8020873c:	37f81663 	tbnz	w3, #31, 80208a08 <_vfiprintf_r+0x14f8>
    80208740:	5280001a 	mov	w26, #0x0                   	// #0
    80208744:	d2800017 	mov	x23, #0x0                   	// #0
    80208748:	b90073f8 	str	w24, [sp, #112]
    8020874c:	2a1a03f8 	mov	w24, w26
    80208750:	aa1903fa 	mov	x26, x25
    80208754:	aa1503f9 	mov	x25, x21
    80208758:	2a0303f5 	mov	w21, w3
    8020875c:	b90093e8 	str	w8, [sp, #144]
    80208760:	1400000d 	b	80208794 <_vfiprintf_r+0x1284>
    80208764:	910443e3 	add	x3, sp, #0x110
    80208768:	9104e3e1 	add	x1, sp, #0x138
    8020876c:	aa1303e0 	mov	x0, x19
    80208770:	940004b4 	bl	80209a40 <_wcrtomb_r>
    80208774:	3100041f 	cmn	w0, #0x1
    80208778:	54003560 	b.eq	80208e24 <_vfiprintf_r+0x1914>  // b.none
    8020877c:	0b000300 	add	w0, w24, w0
    80208780:	6b15001f 	cmp	w0, w21
    80208784:	540000ec 	b.gt	802087a0 <_vfiprintf_r+0x1290>
    80208788:	910012f7 	add	x23, x23, #0x4
    8020878c:	540033e0 	b.eq	80208e08 <_vfiprintf_r+0x18f8>  // b.none
    80208790:	2a0003f8 	mov	w24, w0
    80208794:	f9408fe0 	ldr	x0, [sp, #280]
    80208798:	b8776802 	ldr	w2, [x0, x23]
    8020879c:	35fffe42 	cbnz	w2, 80208764 <_vfiprintf_r+0x1254>
    802087a0:	aa1903f5 	mov	x21, x25
    802087a4:	b94093e8 	ldr	w8, [sp, #144]
    802087a8:	aa1a03f9 	mov	x25, x26
    802087ac:	2a1803fa 	mov	w26, w24
    802087b0:	b94073f8 	ldr	w24, [sp, #112]
    802087b4:	3400145a 	cbz	w26, 80208a3c <_vfiprintf_r+0x152c>
    802087b8:	71018f5f 	cmp	w26, #0x63
    802087bc:	540021ec 	b.gt	80208bf8 <_vfiprintf_r+0x16e8>
    802087c0:	9104e3fc 	add	x28, sp, #0x138
    802087c4:	f9003bff 	str	xzr, [sp, #112]
    802087c8:	93407f57 	sxtw	x23, w26
    802087cc:	d2800102 	mov	x2, #0x8                   	// #8
    802087d0:	52800001 	mov	w1, #0x0                   	// #0
    802087d4:	910443e0 	add	x0, sp, #0x110
    802087d8:	b90093e8 	str	w8, [sp, #144]
    802087dc:	97ffebb9 	bl	802036c0 <memset>
    802087e0:	910443e4 	add	x4, sp, #0x110
    802087e4:	aa1703e3 	mov	x3, x23
    802087e8:	910463e2 	add	x2, sp, #0x118
    802087ec:	aa1c03e1 	mov	x1, x28
    802087f0:	aa1303e0 	mov	x0, x19
    802087f4:	94000a37 	bl	8020b0d0 <_wcsrtombs_r>
    802087f8:	b94093e8 	ldr	w8, [sp, #144]
    802087fc:	eb0002ff 	cmp	x23, x0
    80208800:	54004821 	b.ne	80209104 <_vfiprintf_r+0x1bf4>  // b.any
    80208804:	7100035f 	cmp	w26, #0x0
    80208808:	383acb9f 	strb	wzr, [x28, w26, sxtw]
    8020880c:	1a9fa344 	csel	w4, w26, wzr, ge	// ge = tcont
    80208810:	1400008d 	b	80208a44 <_vfiprintf_r+0x1534>
    80208814:	910673fa 	add	x26, sp, #0x19c
    80208818:	1216008a 	and	w10, w4, #0x400
    8020881c:	b202e7e6 	mov	x6, #0xcccccccccccccccc    	// #-3689348814741910324
    80208820:	aa1a03e2 	mov	x2, x26
    80208824:	aa1903e5 	mov	x5, x25
    80208828:	aa1a03e7 	mov	x7, x26
    8020882c:	aa1303f9 	mov	x25, x19
    80208830:	aa1503fa 	mov	x26, x21
    80208834:	f9405bf5 	ldr	x21, [sp, #176]
    80208838:	2a0a03f3 	mov	w19, w10
    8020883c:	5280000b 	mov	w11, #0x0                   	// #0
    80208840:	f29999a6 	movk	x6, #0xcccd
    80208844:	14000007 	b	80208860 <_vfiprintf_r+0x1350>
    80208848:	9bc67c38 	umulh	x24, x1, x6
    8020884c:	d343ff18 	lsr	x24, x24, #3
    80208850:	f100243f 	cmp	x1, #0x9
    80208854:	54000249 	b.ls	8020889c <_vfiprintf_r+0x138c>  // b.plast
    80208858:	aa1803e1 	mov	x1, x24
    8020885c:	aa1c03e2 	mov	x2, x28
    80208860:	9bc67c38 	umulh	x24, x1, x6
    80208864:	1100056b 	add	w11, w11, #0x1
    80208868:	d100045c 	sub	x28, x2, #0x1
    8020886c:	d343ff18 	lsr	x24, x24, #3
    80208870:	8b180b00 	add	x0, x24, x24, lsl #2
    80208874:	cb000420 	sub	x0, x1, x0, lsl #1
    80208878:	1100c000 	add	w0, w0, #0x30
    8020887c:	381ff040 	sturb	w0, [x2, #-1]
    80208880:	34fffe53 	cbz	w19, 80208848 <_vfiprintf_r+0x1338>
    80208884:	394002a0 	ldrb	w0, [x21]
    80208888:	7103fc1f 	cmp	w0, #0xff
    8020888c:	7a4b1000 	ccmp	w0, w11, #0x0, ne	// ne = any
    80208890:	54fffdc1 	b.ne	80208848 <_vfiprintf_r+0x1338>  // b.any
    80208894:	f100243f 	cmp	x1, #0x9
    80208898:	54001e28 	b.hi	80208c5c <_vfiprintf_r+0x174c>  // b.pmore
    8020889c:	f9005bf5 	str	x21, [sp, #176]
    802088a0:	aa1a03f5 	mov	x21, x26
    802088a4:	aa0703fa 	mov	x26, x7
    802088a8:	aa1903f3 	mov	x19, x25
    802088ac:	4b1c035a 	sub	w26, w26, w28
    802088b0:	aa0503f9 	mov	x25, x5
    802088b4:	2a0403f8 	mov	w24, w4
    802088b8:	17fffe38 	b	80208198 <_vfiprintf_r+0xc88>
    802088bc:	aa1303e0 	mov	x0, x19
    802088c0:	97ffeb44 	bl	802035d0 <__sinit>
    802088c4:	17fffb29 	b	80207568 <_vfiprintf_r+0x58>
    802088c8:	39400720 	ldrb	w0, [x25, #1]
    802088cc:	321b0318 	orr	w24, w24, #0x20
    802088d0:	91000739 	add	x25, x25, #0x1
    802088d4:	17fffb9d 	b	80207748 <_vfiprintf_r+0x238>
    802088d8:	39400720 	ldrb	w0, [x25, #1]
    802088dc:	32170318 	orr	w24, w24, #0x200
    802088e0:	91000739 	add	x25, x25, #0x1
    802088e4:	17fffb99 	b	80207748 <_vfiprintf_r+0x238>
    802088e8:	7100187f 	cmp	w3, #0x6
    802088ec:	528000c9 	mov	w9, #0x6                   	// #6
    802088f0:	1a89907a 	csel	w26, w3, w9, ls	// ls = plast
    802088f4:	90000047 	adrp	x7, 80210000 <_wcsnrtombs_l+0x110>
    802088f8:	f94047f7 	ldr	x23, [sp, #136]
    802088fc:	2a1a03e4 	mov	w4, w26
    80208900:	913000fc 	add	x28, x7, #0xc00
    80208904:	17fffbb8 	b	802077e4 <_vfiprintf_r+0x2d4>
    80208908:	f9409be0 	ldr	x0, [sp, #304]
    8020890c:	b5002020 	cbnz	x0, 80208d10 <_vfiprintf_r+0x1800>
    80208910:	79c022a0 	ldrsh	w0, [x21, #16]
    80208914:	b9012bff 	str	wzr, [sp, #296]
    80208918:	17fffba0 	b	80207798 <_vfiprintf_r+0x288>
    8020891c:	364810a4 	tbz	w4, #9, 80208b30 <_vfiprintf_r+0x1620>
    80208920:	37f824e0 	tbnz	w0, #31, 80208dbc <_vfiprintf_r+0x18ac>
    80208924:	91002ee1 	add	x1, x23, #0xb
    80208928:	aa1703e0 	mov	x0, x23
    8020892c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208930:	39400001 	ldrb	w1, [x0]
    80208934:	52800020 	mov	w0, #0x1                   	// #1
    80208938:	17fffe0a 	b	80208160 <_vfiprintf_r+0xc50>
    8020893c:	36480e38 	tbz	w24, #9, 80208b00 <_vfiprintf_r+0x15f0>
    80208940:	37f82500 	tbnz	w0, #31, 80208de0 <_vfiprintf_r+0x18d0>
    80208944:	aa1703e0 	mov	x0, x23
    80208948:	91002ee1 	add	x1, x23, #0xb
    8020894c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208950:	39400001 	ldrb	w1, [x0]
    80208954:	17fffe01 	b	80208158 <_vfiprintf_r+0xc48>
    80208958:	f94043e4 	ldr	x4, [sp, #128]
    8020895c:	b940c3e1 	ldr	w1, [sp, #192]
    80208960:	b900c3e2 	str	w2, [sp, #192]
    80208964:	8b21c081 	add	x1, x4, w1, sxtw
    80208968:	17ffff3b 	b	80208654 <_vfiprintf_r+0x1144>
    8020896c:	36480d78 	tbz	w24, #9, 80208b18 <_vfiprintf_r+0x1608>
    80208970:	37f82001 	tbnz	w1, #31, 80208d70 <_vfiprintf_r+0x1860>
    80208974:	aa1703e1 	mov	x1, x23
    80208978:	91002ee2 	add	x2, x23, #0xb
    8020897c:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208980:	39400021 	ldrb	w1, [x1]
    80208984:	17ffff35 	b	80208658 <_vfiprintf_r+0x1148>
    80208988:	f94043e2 	ldr	x2, [sp, #128]
    8020898c:	b940c3e0 	ldr	w0, [sp, #192]
    80208990:	b900c3e1 	str	w1, [sp, #192]
    80208994:	8b20c040 	add	x0, x2, w0, sxtw
    80208998:	17fffdef 	b	80208154 <_vfiprintf_r+0xc44>
    8020899c:	f94043e2 	ldr	x2, [sp, #128]
    802089a0:	b940c3e0 	ldr	w0, [sp, #192]
    802089a4:	b900c3e1 	str	w1, [sp, #192]
    802089a8:	8b20c040 	add	x0, x2, w0, sxtw
    802089ac:	17fffe1d 	b	80208220 <_vfiprintf_r+0xd10>
    802089b0:	36480958 	tbz	w24, #9, 80208ad8 <_vfiprintf_r+0x15c8>
    802089b4:	37f82780 	tbnz	w0, #31, 80208ea4 <_vfiprintf_r+0x1994>
    802089b8:	91002ee1 	add	x1, x23, #0xb
    802089bc:	aa1703e0 	mov	x0, x23
    802089c0:	927df037 	and	x23, x1, #0xfffffffffffffff8
    802089c4:	39800001 	ldrsb	x1, [x0]
    802089c8:	aa0103e0 	mov	x0, x1
    802089cc:	17fffe17 	b	80208228 <_vfiprintf_r+0xd18>
    802089d0:	f94043e2 	ldr	x2, [sp, #128]
    802089d4:	b940c3e0 	ldr	w0, [sp, #192]
    802089d8:	b900c3e1 	str	w1, [sp, #192]
    802089dc:	8b20c040 	add	x0, x2, w0, sxtw
    802089e0:	17fffe03 	b	802081ec <_vfiprintf_r+0xcdc>
    802089e4:	b940c3e0 	ldr	w0, [sp, #192]
    802089e8:	11002001 	add	w1, w0, #0x8
    802089ec:	7100003f 	cmp	w1, #0x0
    802089f0:	54000d4d 	b.le	80208b98 <_vfiprintf_r+0x1688>
    802089f4:	91002ee2 	add	x2, x23, #0xb
    802089f8:	aa1703e0 	mov	x0, x23
    802089fc:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208a00:	b900c3e1 	str	w1, [sp, #192]
    80208a04:	17fffd74 	b	80207fd4 <_vfiprintf_r+0xac4>
    80208a08:	910443e4 	add	x4, sp, #0x110
    80208a0c:	910463e2 	add	x2, sp, #0x118
    80208a10:	aa1303e0 	mov	x0, x19
    80208a14:	d2800003 	mov	x3, #0x0                   	// #0
    80208a18:	d2800001 	mov	x1, #0x0                   	// #0
    80208a1c:	b90073e8 	str	w8, [sp, #112]
    80208a20:	940009ac 	bl	8020b0d0 <_wcsrtombs_r>
    80208a24:	2a0003fa 	mov	w26, w0
    80208a28:	b94073e8 	ldr	w8, [sp, #112]
    80208a2c:	3100041f 	cmn	w0, #0x1
    80208a30:	54003180 	b.eq	80209060 <_vfiprintf_r+0x1b50>  // b.none
    80208a34:	f9008ffc 	str	x28, [sp, #280]
    80208a38:	17ffff5f 	b	802087b4 <_vfiprintf_r+0x12a4>
    80208a3c:	52800004 	mov	w4, #0x0                   	// #0
    80208a40:	f9003bff 	str	xzr, [sp, #112]
    80208a44:	3943ffe0 	ldrb	w0, [sp, #255]
    80208a48:	52800003 	mov	w3, #0x0                   	// #0
    80208a4c:	f94047f7 	ldr	x23, [sp, #136]
    80208a50:	5280000d 	mov	w13, #0x0                   	// #0
    80208a54:	35ffbac0 	cbnz	w0, 802081ac <_vfiprintf_r+0xc9c>
    80208a58:	17fffb66 	b	802077f0 <_vfiprintf_r+0x2e0>
    80208a5c:	f94043e2 	ldr	x2, [sp, #128]
    80208a60:	b940c3e0 	ldr	w0, [sp, #192]
    80208a64:	b900c3e1 	str	w1, [sp, #192]
    80208a68:	8b20c040 	add	x0, x2, w0, sxtw
    80208a6c:	17fffe22 	b	802082f4 <_vfiprintf_r+0xde4>
    80208a70:	f94043e2 	ldr	x2, [sp, #128]
    80208a74:	b940c3e0 	ldr	w0, [sp, #192]
    80208a78:	b900c3e1 	str	w1, [sp, #192]
    80208a7c:	8b20c042 	add	x2, x2, w0, sxtw
    80208a80:	aa1703e0 	mov	x0, x23
    80208a84:	aa0203f7 	mov	x23, x2
    80208a88:	17fffd86 	b	802080a0 <_vfiprintf_r+0xb90>
    80208a8c:	f94043e4 	ldr	x4, [sp, #128]
    80208a90:	f90047f7 	str	x23, [sp, #136]
    80208a94:	b940c3e2 	ldr	w2, [sp, #192]
    80208a98:	b900c3e1 	str	w1, [sp, #192]
    80208a9c:	8b22c082 	add	x2, x4, w2, sxtw
    80208aa0:	aa0203f7 	mov	x23, x2
    80208aa4:	17fffd26 	b	80207f3c <_vfiprintf_r+0xa2c>
    80208aa8:	aa1603fb 	mov	x27, x22
    80208aac:	5280002b 	mov	w11, #0x1                   	// #1
    80208ab0:	52800001 	mov	w1, #0x0                   	// #0
    80208ab4:	17fffb85 	b	802078c8 <_vfiprintf_r+0x3b8>
    80208ab8:	37f81700 	tbnz	w0, #31, 80208d98 <_vfiprintf_r+0x1888>
    80208abc:	91003ee1 	add	x1, x23, #0xf
    80208ac0:	aa1703e0 	mov	x0, x23
    80208ac4:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208ac8:	f9400000 	ldr	x0, [x0]
    80208acc:	7940dbe1 	ldrh	w1, [sp, #108]
    80208ad0:	79000001 	strh	w1, [x0]
    80208ad4:	17fffac4 	b	802075e4 <_vfiprintf_r+0xd4>
    80208ad8:	37f81f80 	tbnz	w0, #31, 80208ec8 <_vfiprintf_r+0x19b8>
    80208adc:	91002ee1 	add	x1, x23, #0xb
    80208ae0:	aa1703e0 	mov	x0, x23
    80208ae4:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208ae8:	b9800001 	ldrsw	x1, [x0]
    80208aec:	aa0103e0 	mov	x0, x1
    80208af0:	17fffdce 	b	80208228 <_vfiprintf_r+0xd18>
    80208af4:	aa1603fb 	mov	x27, x22
    80208af8:	5280002b 	mov	w11, #0x1                   	// #1
    80208afc:	17fffb55 	b	80207850 <_vfiprintf_r+0x340>
    80208b00:	37f81ae0 	tbnz	w0, #31, 80208e5c <_vfiprintf_r+0x194c>
    80208b04:	aa1703e0 	mov	x0, x23
    80208b08:	91002ee1 	add	x1, x23, #0xb
    80208b0c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208b10:	b9400001 	ldr	w1, [x0]
    80208b14:	17fffd91 	b	80208158 <_vfiprintf_r+0xc48>
    80208b18:	37f81ea1 	tbnz	w1, #31, 80208eec <_vfiprintf_r+0x19dc>
    80208b1c:	aa1703e1 	mov	x1, x23
    80208b20:	91002ee2 	add	x2, x23, #0xb
    80208b24:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208b28:	b9400021 	ldr	w1, [x1]
    80208b2c:	17fffecb 	b	80208658 <_vfiprintf_r+0x1148>
    80208b30:	37f81840 	tbnz	w0, #31, 80208e38 <_vfiprintf_r+0x1928>
    80208b34:	91002ee1 	add	x1, x23, #0xb
    80208b38:	aa1703e0 	mov	x0, x23
    80208b3c:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208b40:	b9400001 	ldr	w1, [x0]
    80208b44:	52800020 	mov	w0, #0x1                   	// #1
    80208b48:	17fffd86 	b	80208160 <_vfiprintf_r+0xc50>
    80208b4c:	b940c3e0 	ldr	w0, [sp, #192]
    80208b50:	11002001 	add	w1, w0, #0x8
    80208b54:	7100003f 	cmp	w1, #0x0
    80208b58:	54001e8d 	b.le	80208f28 <_vfiprintf_r+0x1a18>
    80208b5c:	91002ee2 	add	x2, x23, #0xb
    80208b60:	aa1703e0 	mov	x0, x23
    80208b64:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208b68:	b900c3e1 	str	w1, [sp, #192]
    80208b6c:	17fffe4a 	b	80208494 <_vfiprintf_r+0xf84>
    80208b70:	b940c3e1 	ldr	w1, [sp, #192]
    80208b74:	11002022 	add	w2, w1, #0x8
    80208b78:	7100005f 	cmp	w2, #0x0
    80208b7c:	54001ecd 	b.le	80208f54 <_vfiprintf_r+0x1a44>
    80208b80:	aa1703e1 	mov	x1, x23
    80208b84:	91002ee4 	add	x4, x23, #0xb
    80208b88:	927df097 	and	x23, x4, #0xfffffffffffffff8
    80208b8c:	b900c3e2 	str	w2, [sp, #192]
    80208b90:	79400021 	ldrh	w1, [x1]
    80208b94:	17fffeb1 	b	80208658 <_vfiprintf_r+0x1148>
    80208b98:	f94043e2 	ldr	x2, [sp, #128]
    80208b9c:	b940c3e0 	ldr	w0, [sp, #192]
    80208ba0:	b900c3e1 	str	w1, [sp, #192]
    80208ba4:	8b20c040 	add	x0, x2, w0, sxtw
    80208ba8:	17fffd0b 	b	80207fd4 <_vfiprintf_r+0xac4>
    80208bac:	b940c3e0 	ldr	w0, [sp, #192]
    80208bb0:	11002001 	add	w1, w0, #0x8
    80208bb4:	7100003f 	cmp	w1, #0x0
    80208bb8:	54001aed 	b.le	80208f14 <_vfiprintf_r+0x1a04>
    80208bbc:	91002ee2 	add	x2, x23, #0xb
    80208bc0:	aa1703e0 	mov	x0, x23
    80208bc4:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208bc8:	b900c3e1 	str	w1, [sp, #192]
    80208bcc:	17fffe41 	b	802084d0 <_vfiprintf_r+0xfc0>
    80208bd0:	b940c3e0 	ldr	w0, [sp, #192]
    80208bd4:	11002001 	add	w1, w0, #0x8
    80208bd8:	7100003f 	cmp	w1, #0x0
    80208bdc:	54001b0d 	b.le	80208f3c <_vfiprintf_r+0x1a2c>
    80208be0:	aa1703e0 	mov	x0, x23
    80208be4:	91002ee2 	add	x2, x23, #0xb
    80208be8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208bec:	b900c3e1 	str	w1, [sp, #192]
    80208bf0:	79400001 	ldrh	w1, [x0]
    80208bf4:	17fffd59 	b	80208158 <_vfiprintf_r+0xc48>
    80208bf8:	11000741 	add	w1, w26, #0x1
    80208bfc:	aa1303e0 	mov	x0, x19
    80208c00:	b90073e8 	str	w8, [sp, #112]
    80208c04:	93407c21 	sxtw	x1, w1
    80208c08:	9400018e 	bl	80209240 <_malloc_r>
    80208c0c:	b94073e8 	ldr	w8, [sp, #112]
    80208c10:	aa0003fc 	mov	x28, x0
    80208c14:	b4002260 	cbz	x0, 80209060 <_vfiprintf_r+0x1b50>
    80208c18:	f9003be0 	str	x0, [sp, #112]
    80208c1c:	17fffeeb 	b	802087c8 <_vfiprintf_r+0x12b8>
    80208c20:	f94052a0 	ldr	x0, [x21, #160]
    80208c24:	940003f7 	bl	80209c00 <__retarget_lock_release_recursive>
    80208c28:	17fffa8f 	b	80207664 <_vfiprintf_r+0x154>
    80208c2c:	2a0303e4 	mov	w4, w3
    80208c30:	2a0303fa 	mov	w26, w3
    80208c34:	17ffff84 	b	80208a44 <_vfiprintf_r+0x1534>
    80208c38:	b940c3e0 	ldr	w0, [sp, #192]
    80208c3c:	11002001 	add	w1, w0, #0x8
    80208c40:	7100003f 	cmp	w1, #0x0
    80208c44:	5400072d 	b.le	80208d28 <_vfiprintf_r+0x1818>
    80208c48:	91002ee2 	add	x2, x23, #0xb
    80208c4c:	aa1703e0 	mov	x0, x23
    80208c50:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208c54:	b900c3e1 	str	w1, [sp, #192]
    80208c58:	17fffe47 	b	80208574 <_vfiprintf_r+0x1064>
    80208c5c:	f94057e0 	ldr	x0, [sp, #168]
    80208c60:	b90073e4 	str	w4, [sp, #112]
    80208c64:	f9405fe1 	ldr	x1, [sp, #184]
    80208c68:	cb00039c 	sub	x28, x28, x0
    80208c6c:	aa0003e2 	mov	x2, x0
    80208c70:	aa1c03e0 	mov	x0, x28
    80208c74:	b9008be8 	str	w8, [sp, #136]
    80208c78:	b90093e3 	str	w3, [sp, #144]
    80208c7c:	f9004fe5 	str	x5, [sp, #152]
    80208c80:	f9005be7 	str	x7, [sp, #176]
    80208c84:	94001297 	bl	8020d6e0 <strncpy>
    80208c88:	394006a0 	ldrb	w0, [x21, #1]
    80208c8c:	b202e7e6 	mov	x6, #0xcccccccccccccccc    	// #-3689348814741910324
    80208c90:	f9404fe5 	ldr	x5, [sp, #152]
    80208c94:	7100001f 	cmp	w0, #0x0
    80208c98:	f9405be7 	ldr	x7, [sp, #176]
    80208c9c:	9a9506b5 	cinc	x21, x21, ne	// ne = any
    80208ca0:	b94073e4 	ldr	w4, [sp, #112]
    80208ca4:	5280000b 	mov	w11, #0x0                   	// #0
    80208ca8:	b9408be8 	ldr	w8, [sp, #136]
    80208cac:	f29999a6 	movk	x6, #0xcccd
    80208cb0:	b94093e3 	ldr	w3, [sp, #144]
    80208cb4:	17fffee9 	b	80208858 <_vfiprintf_r+0x1348>
    80208cb8:	f94043e2 	ldr	x2, [sp, #128]
    80208cbc:	b940c3e0 	ldr	w0, [sp, #192]
    80208cc0:	b900c3e1 	str	w1, [sp, #192]
    80208cc4:	8b20c040 	add	x0, x2, w0, sxtw
    80208cc8:	17fffd73 	b	80208294 <_vfiprintf_r+0xd84>
    80208ccc:	aa1c03e0 	mov	x0, x28
    80208cd0:	b90093e8 	str	w8, [sp, #144]
    80208cd4:	97ffeb0b 	bl	80203900 <strlen>
    80208cd8:	7100001f 	cmp	w0, #0x0
    80208cdc:	b94093e8 	ldr	w8, [sp, #144]
    80208ce0:	2a0003fa 	mov	w26, w0
    80208ce4:	1a9fa004 	csel	w4, w0, wzr, ge	// ge = tcont
    80208ce8:	f9003bff 	str	xzr, [sp, #112]
    80208cec:	17ffff56 	b	80208a44 <_vfiprintf_r+0x1534>
    80208cf0:	b000004b 	adrp	x11, 80211000 <blanks.1+0x60>
    80208cf4:	2a0203ef 	mov	w15, w2
    80208cf8:	9102016b 	add	x11, x11, #0x80
    80208cfc:	17fffc24 	b	80207d8c <_vfiprintf_r+0x87c>
    80208d00:	b000004b 	adrp	x11, 80211000 <blanks.1+0x60>
    80208d04:	11000446 	add	w6, w2, #0x1
    80208d08:	9102016b 	add	x11, x11, #0x80
    80208d0c:	17fffc60 	b	80207e8c <_vfiprintf_r+0x97c>
    80208d10:	aa1303e0 	mov	x0, x19
    80208d14:	910483e2 	add	x2, sp, #0x120
    80208d18:	aa1503e1 	mov	x1, x21
    80208d1c:	97fff9bd 	bl	80207410 <__sprint_r.part.0>
    80208d20:	34ffdf80 	cbz	w0, 80208910 <_vfiprintf_r+0x1400>
    80208d24:	17fffa9c 	b	80207794 <_vfiprintf_r+0x284>
    80208d28:	f94043e2 	ldr	x2, [sp, #128]
    80208d2c:	b940c3e0 	ldr	w0, [sp, #192]
    80208d30:	b900c3e1 	str	w1, [sp, #192]
    80208d34:	8b20c040 	add	x0, x2, w0, sxtw
    80208d38:	17fffe0f 	b	80208574 <_vfiprintf_r+0x1064>
    80208d3c:	b000004a 	adrp	x10, 80211000 <blanks.1+0x60>
    80208d40:	2a0b03ed 	mov	w13, w11
    80208d44:	9101c14a 	add	x10, x10, #0x70
    80208d48:	17fffb58 	b	80207aa8 <_vfiprintf_r+0x598>
    80208d4c:	b940b2a0 	ldr	w0, [x21, #176]
    80208d50:	370000a0 	tbnz	w0, #0, 80208d64 <_vfiprintf_r+0x1854>
    80208d54:	794022a0 	ldrh	w0, [x21, #16]
    80208d58:	37480060 	tbnz	w0, #9, 80208d64 <_vfiprintf_r+0x1854>
    80208d5c:	f94052a0 	ldr	x0, [x21, #160]
    80208d60:	940003a8 	bl	80209c00 <__retarget_lock_release_recursive>
    80208d64:	12800000 	mov	w0, #0xffffffff            	// #-1
    80208d68:	b9006fe0 	str	w0, [sp, #108]
    80208d6c:	17fffa8f 	b	802077a8 <_vfiprintf_r+0x298>
    80208d70:	b940c3e1 	ldr	w1, [sp, #192]
    80208d74:	11002022 	add	w2, w1, #0x8
    80208d78:	7100005f 	cmp	w2, #0x0
    80208d7c:	5400150d 	b.le	8020901c <_vfiprintf_r+0x1b0c>
    80208d80:	aa1703e1 	mov	x1, x23
    80208d84:	91002ee4 	add	x4, x23, #0xb
    80208d88:	927df097 	and	x23, x4, #0xfffffffffffffff8
    80208d8c:	b900c3e2 	str	w2, [sp, #192]
    80208d90:	39400021 	ldrb	w1, [x1]
    80208d94:	17fffe31 	b	80208658 <_vfiprintf_r+0x1148>
    80208d98:	b940c3e0 	ldr	w0, [sp, #192]
    80208d9c:	11002001 	add	w1, w0, #0x8
    80208da0:	7100003f 	cmp	w1, #0x0
    80208da4:	5400148d 	b.le	80209034 <_vfiprintf_r+0x1b24>
    80208da8:	91003ee2 	add	x2, x23, #0xf
    80208dac:	aa1703e0 	mov	x0, x23
    80208db0:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208db4:	b900c3e1 	str	w1, [sp, #192]
    80208db8:	17ffff44 	b	80208ac8 <_vfiprintf_r+0x15b8>
    80208dbc:	b940c3e0 	ldr	w0, [sp, #192]
    80208dc0:	11002001 	add	w1, w0, #0x8
    80208dc4:	7100003f 	cmp	w1, #0x0
    80208dc8:	5400154d 	b.le	80209070 <_vfiprintf_r+0x1b60>
    80208dcc:	91002ee2 	add	x2, x23, #0xb
    80208dd0:	aa1703e0 	mov	x0, x23
    80208dd4:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208dd8:	b900c3e1 	str	w1, [sp, #192]
    80208ddc:	17fffed5 	b	80208930 <_vfiprintf_r+0x1420>
    80208de0:	b940c3e0 	ldr	w0, [sp, #192]
    80208de4:	11002001 	add	w1, w0, #0x8
    80208de8:	7100003f 	cmp	w1, #0x0
    80208dec:	5400160d 	b.le	802090ac <_vfiprintf_r+0x1b9c>
    80208df0:	aa1703e0 	mov	x0, x23
    80208df4:	91002ee2 	add	x2, x23, #0xb
    80208df8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208dfc:	b900c3e1 	str	w1, [sp, #192]
    80208e00:	39400001 	ldrb	w1, [x0]
    80208e04:	17fffcd5 	b	80208158 <_vfiprintf_r+0xc48>
    80208e08:	2a1503e3 	mov	w3, w21
    80208e0c:	b94073f8 	ldr	w24, [sp, #112]
    80208e10:	aa1903f5 	mov	x21, x25
    80208e14:	b94093e8 	ldr	w8, [sp, #144]
    80208e18:	aa1a03f9 	mov	x25, x26
    80208e1c:	2a0303fa 	mov	w26, w3
    80208e20:	17fffe65 	b	802087b4 <_vfiprintf_r+0x12a4>
    80208e24:	79c02320 	ldrsh	w0, [x25, #16]
    80208e28:	aa1903f5 	mov	x21, x25
    80208e2c:	321a0000 	orr	w0, w0, #0x40
    80208e30:	79002320 	strh	w0, [x25, #16]
    80208e34:	17fffa59 	b	80207798 <_vfiprintf_r+0x288>
    80208e38:	b940c3e0 	ldr	w0, [sp, #192]
    80208e3c:	11002001 	add	w1, w0, #0x8
    80208e40:	7100003f 	cmp	w1, #0x0
    80208e44:	5400120d 	b.le	80209084 <_vfiprintf_r+0x1b74>
    80208e48:	91002ee2 	add	x2, x23, #0xb
    80208e4c:	aa1703e0 	mov	x0, x23
    80208e50:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208e54:	b900c3e1 	str	w1, [sp, #192]
    80208e58:	17ffff3a 	b	80208b40 <_vfiprintf_r+0x1630>
    80208e5c:	b940c3e0 	ldr	w0, [sp, #192]
    80208e60:	11002001 	add	w1, w0, #0x8
    80208e64:	7100003f 	cmp	w1, #0x0
    80208e68:	5400138d 	b.le	802090d8 <_vfiprintf_r+0x1bc8>
    80208e6c:	aa1703e0 	mov	x0, x23
    80208e70:	91002ee2 	add	x2, x23, #0xb
    80208e74:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208e78:	b900c3e1 	str	w1, [sp, #192]
    80208e7c:	b9400001 	ldr	w1, [x0]
    80208e80:	17fffcb6 	b	80208158 <_vfiprintf_r+0xc48>
    80208e84:	37f80740 	tbnz	w0, #31, 80208f6c <_vfiprintf_r+0x1a5c>
    80208e88:	91003ee1 	add	x1, x23, #0xf
    80208e8c:	aa1703e0 	mov	x0, x23
    80208e90:	927df037 	and	x23, x1, #0xfffffffffffffff8
    80208e94:	f9400000 	ldr	x0, [x0]
    80208e98:	b9406fe1 	ldr	w1, [sp, #108]
    80208e9c:	b9000001 	str	w1, [x0]
    80208ea0:	17fff9d1 	b	802075e4 <_vfiprintf_r+0xd4>
    80208ea4:	b940c3e0 	ldr	w0, [sp, #192]
    80208ea8:	11002001 	add	w1, w0, #0x8
    80208eac:	7100003f 	cmp	w1, #0x0
    80208eb0:	540010ad 	b.le	802090c4 <_vfiprintf_r+0x1bb4>
    80208eb4:	91002ee2 	add	x2, x23, #0xb
    80208eb8:	aa1703e0 	mov	x0, x23
    80208ebc:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208ec0:	b900c3e1 	str	w1, [sp, #192]
    80208ec4:	17fffec0 	b	802089c4 <_vfiprintf_r+0x14b4>
    80208ec8:	b940c3e0 	ldr	w0, [sp, #192]
    80208ecc:	11002001 	add	w1, w0, #0x8
    80208ed0:	7100003f 	cmp	w1, #0x0
    80208ed4:	54000e2d 	b.le	80209098 <_vfiprintf_r+0x1b88>
    80208ed8:	91002ee2 	add	x2, x23, #0xb
    80208edc:	aa1703e0 	mov	x0, x23
    80208ee0:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208ee4:	b900c3e1 	str	w1, [sp, #192]
    80208ee8:	17ffff00 	b	80208ae8 <_vfiprintf_r+0x15d8>
    80208eec:	b940c3e1 	ldr	w1, [sp, #192]
    80208ef0:	11002022 	add	w2, w1, #0x8
    80208ef4:	7100005f 	cmp	w2, #0x0
    80208ef8:	54000a8d 	b.le	80209048 <_vfiprintf_r+0x1b38>
    80208efc:	aa1703e1 	mov	x1, x23
    80208f00:	91002ee4 	add	x4, x23, #0xb
    80208f04:	927df097 	and	x23, x4, #0xfffffffffffffff8
    80208f08:	b900c3e2 	str	w2, [sp, #192]
    80208f0c:	b9400021 	ldr	w1, [x1]
    80208f10:	17fffdd2 	b	80208658 <_vfiprintf_r+0x1148>
    80208f14:	f94043e2 	ldr	x2, [sp, #128]
    80208f18:	b940c3e0 	ldr	w0, [sp, #192]
    80208f1c:	b900c3e1 	str	w1, [sp, #192]
    80208f20:	8b20c040 	add	x0, x2, w0, sxtw
    80208f24:	17fffd6b 	b	802084d0 <_vfiprintf_r+0xfc0>
    80208f28:	f94043e2 	ldr	x2, [sp, #128]
    80208f2c:	b940c3e0 	ldr	w0, [sp, #192]
    80208f30:	b900c3e1 	str	w1, [sp, #192]
    80208f34:	8b20c040 	add	x0, x2, w0, sxtw
    80208f38:	17fffd57 	b	80208494 <_vfiprintf_r+0xf84>
    80208f3c:	f94043e2 	ldr	x2, [sp, #128]
    80208f40:	b940c3e0 	ldr	w0, [sp, #192]
    80208f44:	b900c3e1 	str	w1, [sp, #192]
    80208f48:	8b20c040 	add	x0, x2, w0, sxtw
    80208f4c:	79400001 	ldrh	w1, [x0]
    80208f50:	17fffc82 	b	80208158 <_vfiprintf_r+0xc48>
    80208f54:	f94043e4 	ldr	x4, [sp, #128]
    80208f58:	b940c3e1 	ldr	w1, [sp, #192]
    80208f5c:	b900c3e2 	str	w2, [sp, #192]
    80208f60:	8b21c081 	add	x1, x4, w1, sxtw
    80208f64:	79400021 	ldrh	w1, [x1]
    80208f68:	17fffdbc 	b	80208658 <_vfiprintf_r+0x1148>
    80208f6c:	b940c3e0 	ldr	w0, [sp, #192]
    80208f70:	11002001 	add	w1, w0, #0x8
    80208f74:	7100003f 	cmp	w1, #0x0
    80208f78:	54000bcd 	b.le	802090f0 <_vfiprintf_r+0x1be0>
    80208f7c:	91003ee2 	add	x2, x23, #0xf
    80208f80:	aa1703e0 	mov	x0, x23
    80208f84:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208f88:	b900c3e1 	str	w1, [sp, #192]
    80208f8c:	17ffffc2 	b	80208e94 <_vfiprintf_r+0x1984>
    80208f90:	b940c3e0 	ldr	w0, [sp, #192]
    80208f94:	11002001 	add	w1, w0, #0x8
    80208f98:	7100003f 	cmp	w1, #0x0
    80208f9c:	5400024d 	b.le	80208fe4 <_vfiprintf_r+0x1ad4>
    80208fa0:	91003ee2 	add	x2, x23, #0xf
    80208fa4:	aa1703e0 	mov	x0, x23
    80208fa8:	927df057 	and	x23, x2, #0xfffffffffffffff8
    80208fac:	b900c3e1 	str	w1, [sp, #192]
    80208fb0:	17fffcb1 	b	80208274 <_vfiprintf_r+0xd64>
    80208fb4:	b940c3e0 	ldr	w0, [sp, #192]
    80208fb8:	37f80200 	tbnz	w0, #31, 80208ff8 <_vfiprintf_r+0x1ae8>
    80208fbc:	91002ee1 	add	x1, x23, #0xb
    80208fc0:	927df021 	and	x1, x1, #0xfffffffffffffff8
    80208fc4:	b94002e3 	ldr	w3, [x23]
    80208fc8:	aa0103f7 	mov	x23, x1
    80208fcc:	b900c3e0 	str	w0, [sp, #192]
    80208fd0:	7100007f 	cmp	w3, #0x0
    80208fd4:	39400720 	ldrb	w0, [x25, #1]
    80208fd8:	5a9fa07c 	csinv	w28, w3, wzr, ge	// ge = tcont
    80208fdc:	aa0203f9 	mov	x25, x2
    80208fe0:	17fff9da 	b	80207748 <_vfiprintf_r+0x238>
    80208fe4:	f94043e2 	ldr	x2, [sp, #128]
    80208fe8:	b940c3e0 	ldr	w0, [sp, #192]
    80208fec:	b900c3e1 	str	w1, [sp, #192]
    80208ff0:	8b20c040 	add	x0, x2, w0, sxtw
    80208ff4:	17fffca0 	b	80208274 <_vfiprintf_r+0xd64>
    80208ff8:	b940c3e0 	ldr	w0, [sp, #192]
    80208ffc:	11002000 	add	w0, w0, #0x8
    80209000:	7100001f 	cmp	w0, #0x0
    80209004:	54fffdcc 	b.gt	80208fbc <_vfiprintf_r+0x1aac>
    80209008:	f94043e4 	ldr	x4, [sp, #128]
    8020900c:	aa1703e1 	mov	x1, x23
    80209010:	b940c3e3 	ldr	w3, [sp, #192]
    80209014:	8b23c097 	add	x23, x4, w3, sxtw
    80209018:	17ffffeb 	b	80208fc4 <_vfiprintf_r+0x1ab4>
    8020901c:	f94043e4 	ldr	x4, [sp, #128]
    80209020:	b940c3e1 	ldr	w1, [sp, #192]
    80209024:	b900c3e2 	str	w2, [sp, #192]
    80209028:	8b21c081 	add	x1, x4, w1, sxtw
    8020902c:	39400021 	ldrb	w1, [x1]
    80209030:	17fffd8a 	b	80208658 <_vfiprintf_r+0x1148>
    80209034:	f94043e2 	ldr	x2, [sp, #128]
    80209038:	b940c3e0 	ldr	w0, [sp, #192]
    8020903c:	b900c3e1 	str	w1, [sp, #192]
    80209040:	8b20c040 	add	x0, x2, w0, sxtw
    80209044:	17fffea1 	b	80208ac8 <_vfiprintf_r+0x15b8>
    80209048:	f94043e4 	ldr	x4, [sp, #128]
    8020904c:	b940c3e1 	ldr	w1, [sp, #192]
    80209050:	b900c3e2 	str	w2, [sp, #192]
    80209054:	8b21c081 	add	x1, x4, w1, sxtw
    80209058:	b9400021 	ldr	w1, [x1]
    8020905c:	17fffd7f 	b	80208658 <_vfiprintf_r+0x1148>
    80209060:	79c022a0 	ldrsh	w0, [x21, #16]
    80209064:	321a0000 	orr	w0, w0, #0x40
    80209068:	790022a0 	strh	w0, [x21, #16]
    8020906c:	17fff9cb 	b	80207798 <_vfiprintf_r+0x288>
    80209070:	f94043e2 	ldr	x2, [sp, #128]
    80209074:	b940c3e0 	ldr	w0, [sp, #192]
    80209078:	b900c3e1 	str	w1, [sp, #192]
    8020907c:	8b20c040 	add	x0, x2, w0, sxtw
    80209080:	17fffe2c 	b	80208930 <_vfiprintf_r+0x1420>
    80209084:	f94043e2 	ldr	x2, [sp, #128]
    80209088:	b940c3e0 	ldr	w0, [sp, #192]
    8020908c:	b900c3e1 	str	w1, [sp, #192]
    80209090:	8b20c040 	add	x0, x2, w0, sxtw
    80209094:	17fffeab 	b	80208b40 <_vfiprintf_r+0x1630>
    80209098:	f94043e2 	ldr	x2, [sp, #128]
    8020909c:	b940c3e0 	ldr	w0, [sp, #192]
    802090a0:	b900c3e1 	str	w1, [sp, #192]
    802090a4:	8b20c040 	add	x0, x2, w0, sxtw
    802090a8:	17fffe90 	b	80208ae8 <_vfiprintf_r+0x15d8>
    802090ac:	f94043e2 	ldr	x2, [sp, #128]
    802090b0:	b940c3e0 	ldr	w0, [sp, #192]
    802090b4:	b900c3e1 	str	w1, [sp, #192]
    802090b8:	8b20c040 	add	x0, x2, w0, sxtw
    802090bc:	39400001 	ldrb	w1, [x0]
    802090c0:	17fffc26 	b	80208158 <_vfiprintf_r+0xc48>
    802090c4:	f94043e2 	ldr	x2, [sp, #128]
    802090c8:	b940c3e0 	ldr	w0, [sp, #192]
    802090cc:	b900c3e1 	str	w1, [sp, #192]
    802090d0:	8b20c040 	add	x0, x2, w0, sxtw
    802090d4:	17fffe3c 	b	802089c4 <_vfiprintf_r+0x14b4>
    802090d8:	f94043e2 	ldr	x2, [sp, #128]
    802090dc:	b940c3e0 	ldr	w0, [sp, #192]
    802090e0:	b900c3e1 	str	w1, [sp, #192]
    802090e4:	8b20c040 	add	x0, x2, w0, sxtw
    802090e8:	b9400001 	ldr	w1, [x0]
    802090ec:	17fffc1b 	b	80208158 <_vfiprintf_r+0xc48>
    802090f0:	f94043e2 	ldr	x2, [sp, #128]
    802090f4:	b940c3e0 	ldr	w0, [sp, #192]
    802090f8:	b900c3e1 	str	w1, [sp, #192]
    802090fc:	8b20c040 	add	x0, x2, w0, sxtw
    80209100:	17ffff65 	b	80208e94 <_vfiprintf_r+0x1984>
    80209104:	794022a0 	ldrh	w0, [x21, #16]
    80209108:	321a0000 	orr	w0, w0, #0x40
    8020910c:	790022a0 	strh	w0, [x21, #16]
    80209110:	17fff99c 	b	80207780 <_vfiprintf_r+0x270>
	...

0000000080209120 <vfiprintf>:
    80209120:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80209124:	90000044 	adrp	x4, 80211000 <blanks.1+0x60>
    80209128:	aa0003e3 	mov	x3, x0
    8020912c:	910003fd 	mov	x29, sp
    80209130:	ad400440 	ldp	q0, q1, [x2]
    80209134:	aa0103e2 	mov	x2, x1
    80209138:	f9438880 	ldr	x0, [x4, #1808]
    8020913c:	aa0303e1 	mov	x1, x3
    80209140:	910043e3 	add	x3, sp, #0x10
    80209144:	ad0087e0 	stp	q0, q1, [sp, #16]
    80209148:	97fff8f2 	bl	80207510 <_vfiprintf_r>
    8020914c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80209150:	d65f03c0 	ret
	...

0000000080209160 <__sbprintf>:
    80209160:	d11443ff 	sub	sp, sp, #0x510
    80209164:	a9007bfd 	stp	x29, x30, [sp]
    80209168:	910003fd 	mov	x29, sp
    8020916c:	a90153f3 	stp	x19, x20, [sp, #16]
    80209170:	aa0103f3 	mov	x19, x1
    80209174:	79402021 	ldrh	w1, [x1, #16]
    80209178:	aa0303f4 	mov	x20, x3
    8020917c:	910443e3 	add	x3, sp, #0x110
    80209180:	f9401a66 	ldr	x6, [x19, #48]
    80209184:	121e7821 	and	w1, w1, #0xfffffffd
    80209188:	f9402265 	ldr	x5, [x19, #64]
    8020918c:	a9025bf5 	stp	x21, x22, [sp, #32]
    80209190:	79402667 	ldrh	w7, [x19, #18]
    80209194:	b940b264 	ldr	w4, [x19, #176]
    80209198:	aa0203f6 	mov	x22, x2
    8020919c:	52808002 	mov	w2, #0x400                 	// #1024
    802091a0:	aa0003f5 	mov	x21, x0
    802091a4:	9103e3e0 	add	x0, sp, #0xf8
    802091a8:	f9002fe3 	str	x3, [sp, #88]
    802091ac:	b90067e2 	str	w2, [sp, #100]
    802091b0:	7900d3e1 	strh	w1, [sp, #104]
    802091b4:	7900d7e7 	strh	w7, [sp, #106]
    802091b8:	f9003be3 	str	x3, [sp, #112]
    802091bc:	b9007be2 	str	w2, [sp, #120]
    802091c0:	b90083ff 	str	wzr, [sp, #128]
    802091c4:	f90047e6 	str	x6, [sp, #136]
    802091c8:	f9004fe5 	str	x5, [sp, #152]
    802091cc:	b9010be4 	str	w4, [sp, #264]
    802091d0:	9400026c 	bl	80209b80 <__retarget_lock_init_recursive>
    802091d4:	ad400680 	ldp	q0, q1, [x20]
    802091d8:	aa1603e2 	mov	x2, x22
    802091dc:	9100c3e3 	add	x3, sp, #0x30
    802091e0:	910163e1 	add	x1, sp, #0x58
    802091e4:	aa1503e0 	mov	x0, x21
    802091e8:	ad0187e0 	stp	q0, q1, [sp, #48]
    802091ec:	97fff8c9 	bl	80207510 <_vfiprintf_r>
    802091f0:	2a0003f4 	mov	w20, w0
    802091f4:	37f800c0 	tbnz	w0, #31, 8020920c <__sbprintf+0xac>
    802091f8:	910163e1 	add	x1, sp, #0x58
    802091fc:	aa1503e0 	mov	x0, x21
    80209200:	94000d5c 	bl	8020c770 <_fflush_r>
    80209204:	7100001f 	cmp	w0, #0x0
    80209208:	5a9f0294 	csinv	w20, w20, wzr, eq	// eq = none
    8020920c:	7940d3e0 	ldrh	w0, [sp, #104]
    80209210:	36300080 	tbz	w0, #6, 80209220 <__sbprintf+0xc0>
    80209214:	79402260 	ldrh	w0, [x19, #16]
    80209218:	321a0000 	orr	w0, w0, #0x40
    8020921c:	79002260 	strh	w0, [x19, #16]
    80209220:	f9407fe0 	ldr	x0, [sp, #248]
    80209224:	9400025f 	bl	80209ba0 <__retarget_lock_close_recursive>
    80209228:	a9407bfd 	ldp	x29, x30, [sp]
    8020922c:	2a1403e0 	mov	w0, w20
    80209230:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209234:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209238:	911443ff 	add	sp, sp, #0x510
    8020923c:	d65f03c0 	ret

0000000080209240 <_malloc_r>:
    80209240:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    80209244:	910003fd 	mov	x29, sp
    80209248:	a90153f3 	stp	x19, x20, [sp, #16]
    8020924c:	91005c34 	add	x20, x1, #0x17
    80209250:	a9025bf5 	stp	x21, x22, [sp, #32]
    80209254:	aa0003f5 	mov	x21, x0
    80209258:	f100ba9f 	cmp	x20, #0x2e
    8020925c:	54000ca8 	b.hi	802093f0 <_malloc_r+0x1b0>  // b.pmore
    80209260:	f100803f 	cmp	x1, #0x20
    80209264:	54001988 	b.hi	80209594 <_malloc_r+0x354>  // b.pmore
    80209268:	94000792 	bl	8020b0b0 <__malloc_lock>
    8020926c:	d2800414 	mov	x20, #0x20                  	// #32
    80209270:	d2800a01 	mov	x1, #0x50                  	// #80
    80209274:	52800080 	mov	w0, #0x4                   	// #4
    80209278:	90000056 	adrp	x22, 80211000 <blanks.1+0x60>
    8020927c:	912282d6 	add	x22, x22, #0x8a0
    80209280:	8b0102c1 	add	x1, x22, x1
    80209284:	11000800 	add	w0, w0, #0x2
    80209288:	d1004021 	sub	x1, x1, #0x10
    8020928c:	f9400c33 	ldr	x19, [x1, #24]
    80209290:	eb01027f 	cmp	x19, x1
    80209294:	54001dc1 	b.ne	8020964c <_malloc_r+0x40c>  // b.any
    80209298:	f94012d3 	ldr	x19, [x22, #32]
    8020929c:	90000046 	adrp	x6, 80211000 <blanks.1+0x60>
    802092a0:	9122c0c6 	add	x6, x6, #0x8b0
    802092a4:	eb06027f 	cmp	x19, x6
    802092a8:	54000f60 	b.eq	80209494 <_malloc_r+0x254>  // b.none
    802092ac:	f9400661 	ldr	x1, [x19, #8]
    802092b0:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    802092b4:	cb140022 	sub	x2, x1, x20
    802092b8:	f1007c5f 	cmp	x2, #0x1f
    802092bc:	540027ac 	b.gt	802097b0 <_malloc_r+0x570>
    802092c0:	a9021ac6 	stp	x6, x6, [x22, #32]
    802092c4:	b6f81782 	tbz	x2, #63, 802095b4 <_malloc_r+0x374>
    802092c8:	f94006c5 	ldr	x5, [x22, #8]
    802092cc:	f107fc3f 	cmp	x1, #0x1ff
    802092d0:	54001ec8 	b.hi	802096a8 <_malloc_r+0x468>  // b.pmore
    802092d4:	d343fc22 	lsr	x2, x1, #3
    802092d8:	d2800023 	mov	x3, #0x1                   	// #1
    802092dc:	11000441 	add	w1, w2, #0x1
    802092e0:	13027c42 	asr	w2, w2, #2
    802092e4:	531f7821 	lsl	w1, w1, #1
    802092e8:	9ac22062 	lsl	x2, x3, x2
    802092ec:	aa0200a5 	orr	x5, x5, x2
    802092f0:	8b21cec1 	add	x1, x22, w1, sxtw #3
    802092f4:	f85f0422 	ldr	x2, [x1], #-16
    802092f8:	f90006c5 	str	x5, [x22, #8]
    802092fc:	a9010662 	stp	x2, x1, [x19, #16]
    80209300:	f9000833 	str	x19, [x1, #16]
    80209304:	f9000c53 	str	x19, [x2, #24]
    80209308:	13027c01 	asr	w1, w0, #2
    8020930c:	d2800024 	mov	x4, #0x1                   	// #1
    80209310:	9ac12084 	lsl	x4, x4, x1
    80209314:	eb05009f 	cmp	x4, x5
    80209318:	54000ca8 	b.hi	802094ac <_malloc_r+0x26c>  // b.pmore
    8020931c:	ea05009f 	tst	x4, x5
    80209320:	540000c1 	b.ne	80209338 <_malloc_r+0xf8>  // b.any
    80209324:	121e7400 	and	w0, w0, #0xfffffffc
    80209328:	d37ff884 	lsl	x4, x4, #1
    8020932c:	11001000 	add	w0, w0, #0x4
    80209330:	ea05009f 	tst	x4, x5
    80209334:	54ffffa0 	b.eq	80209328 <_malloc_r+0xe8>  // b.none
    80209338:	928001e9 	mov	x9, #0xfffffffffffffff0    	// #-16
    8020933c:	11000407 	add	w7, w0, #0x1
    80209340:	2a0003e8 	mov	w8, w0
    80209344:	531f78e7 	lsl	w7, w7, #1
    80209348:	8b27cd27 	add	x7, x9, w7, sxtw #3
    8020934c:	8b0702c7 	add	x7, x22, x7
    80209350:	aa0703e5 	mov	x5, x7
    80209354:	f9400ca1 	ldr	x1, [x5, #24]
    80209358:	14000009 	b	8020937c <_malloc_r+0x13c>
    8020935c:	f9400422 	ldr	x2, [x1, #8]
    80209360:	aa0103f3 	mov	x19, x1
    80209364:	f9400c21 	ldr	x1, [x1, #24]
    80209368:	927ef442 	and	x2, x2, #0xfffffffffffffffc
    8020936c:	cb140043 	sub	x3, x2, x20
    80209370:	f1007c7f 	cmp	x3, #0x1f
    80209374:	54001e2c 	b.gt	80209738 <_malloc_r+0x4f8>
    80209378:	b6f81fe3 	tbz	x3, #63, 80209774 <_malloc_r+0x534>
    8020937c:	eb0100bf 	cmp	x5, x1
    80209380:	54fffee1 	b.ne	8020935c <_malloc_r+0x11c>  // b.any
    80209384:	7100f91f 	cmp	w8, #0x3e
    80209388:	5400242d 	b.le	8020980c <_malloc_r+0x5cc>
    8020938c:	910040a5 	add	x5, x5, #0x10
    80209390:	11000508 	add	w8, w8, #0x1
    80209394:	f240051f 	tst	x8, #0x3
    80209398:	54fffde1 	b.ne	80209354 <_malloc_r+0x114>  // b.any
    8020939c:	14000005 	b	802093b0 <_malloc_r+0x170>
    802093a0:	f85f04e1 	ldr	x1, [x7], #-16
    802093a4:	51000400 	sub	w0, w0, #0x1
    802093a8:	eb07003f 	cmp	x1, x7
    802093ac:	54003401 	b.ne	80209a2c <_malloc_r+0x7ec>  // b.any
    802093b0:	f240041f 	tst	x0, #0x3
    802093b4:	54ffff61 	b.ne	802093a0 <_malloc_r+0x160>  // b.any
    802093b8:	f94006c0 	ldr	x0, [x22, #8]
    802093bc:	8a240000 	bic	x0, x0, x4
    802093c0:	f90006c0 	str	x0, [x22, #8]
    802093c4:	d37ff884 	lsl	x4, x4, #1
    802093c8:	d1000481 	sub	x1, x4, #0x1
    802093cc:	eb00003f 	cmp	x1, x0
    802093d0:	54000083 	b.cc	802093e0 <_malloc_r+0x1a0>  // b.lo, b.ul, b.last
    802093d4:	14000036 	b	802094ac <_malloc_r+0x26c>
    802093d8:	d37ff884 	lsl	x4, x4, #1
    802093dc:	11001108 	add	w8, w8, #0x4
    802093e0:	ea00009f 	tst	x4, x0
    802093e4:	54ffffa0 	b.eq	802093d8 <_malloc_r+0x198>  // b.none
    802093e8:	2a0803e0 	mov	w0, w8
    802093ec:	17ffffd4 	b	8020933c <_malloc_r+0xfc>
    802093f0:	927cee94 	and	x20, x20, #0xfffffffffffffff0
    802093f4:	b2407be2 	mov	x2, #0x7fffffff            	// #2147483647
    802093f8:	eb02029f 	cmp	x20, x2
    802093fc:	fa549022 	ccmp	x1, x20, #0x2, ls	// ls = plast
    80209400:	54000ca8 	b.hi	80209594 <_malloc_r+0x354>  // b.pmore
    80209404:	9400072b 	bl	8020b0b0 <__malloc_lock>
    80209408:	f107de9f 	cmp	x20, #0x1f7
    8020940c:	54001c89 	b.ls	8020979c <_malloc_r+0x55c>  // b.plast
    80209410:	d349fe81 	lsr	x1, x20, #9
    80209414:	b4000c81 	cbz	x1, 802095a4 <_malloc_r+0x364>
    80209418:	f100103f 	cmp	x1, #0x4
    8020941c:	540017a8 	b.hi	80209710 <_malloc_r+0x4d0>  // b.pmore
    80209420:	d346fe81 	lsr	x1, x20, #6
    80209424:	1100e420 	add	w0, w1, #0x39
    80209428:	1100e025 	add	w5, w1, #0x38
    8020942c:	531f7804 	lsl	w4, w0, #1
    80209430:	937d7c84 	sbfiz	x4, x4, #3, #32
    80209434:	90000056 	adrp	x22, 80211000 <blanks.1+0x60>
    80209438:	912282d6 	add	x22, x22, #0x8a0
    8020943c:	8b0402c4 	add	x4, x22, x4
    80209440:	d1004084 	sub	x4, x4, #0x10
    80209444:	f9400c93 	ldr	x19, [x4, #24]
    80209448:	eb13009f 	cmp	x4, x19
    8020944c:	540000e1 	b.ne	80209468 <_malloc_r+0x228>  // b.any
    80209450:	17ffff92 	b	80209298 <_malloc_r+0x58>
    80209454:	f9400e63 	ldr	x3, [x19, #24]
    80209458:	b6f811c2 	tbz	x2, #63, 80209690 <_malloc_r+0x450>
    8020945c:	aa0303f3 	mov	x19, x3
    80209460:	eb03009f 	cmp	x4, x3
    80209464:	54fff1a0 	b.eq	80209298 <_malloc_r+0x58>  // b.none
    80209468:	f9400661 	ldr	x1, [x19, #8]
    8020946c:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    80209470:	cb140022 	sub	x2, x1, x20
    80209474:	f1007c5f 	cmp	x2, #0x1f
    80209478:	54fffeed 	b.le	80209454 <_malloc_r+0x214>
    8020947c:	f94012d3 	ldr	x19, [x22, #32]
    80209480:	90000046 	adrp	x6, 80211000 <blanks.1+0x60>
    80209484:	9122c0c6 	add	x6, x6, #0x8b0
    80209488:	2a0503e0 	mov	w0, w5
    8020948c:	eb06027f 	cmp	x19, x6
    80209490:	54fff0e1 	b.ne	802092ac <_malloc_r+0x6c>  // b.any
    80209494:	f94006c5 	ldr	x5, [x22, #8]
    80209498:	13027c01 	asr	w1, w0, #2
    8020949c:	d2800024 	mov	x4, #0x1                   	// #1
    802094a0:	9ac12084 	lsl	x4, x4, x1
    802094a4:	eb05009f 	cmp	x4, x5
    802094a8:	54fff3a9 	b.ls	8020931c <_malloc_r+0xdc>  // b.plast
    802094ac:	f9400ad3 	ldr	x19, [x22, #16]
    802094b0:	a90363f7 	stp	x23, x24, [sp, #48]
    802094b4:	f9400677 	ldr	x23, [x19, #8]
    802094b8:	927ef6f7 	and	x23, x23, #0xfffffffffffffffc
    802094bc:	cb1402e0 	sub	x0, x23, x20
    802094c0:	f1007c1f 	cmp	x0, #0x1f
    802094c4:	fa54c2e0 	ccmp	x23, x20, #0x0, gt
    802094c8:	54000a42 	b.cs	80209610 <_malloc_r+0x3d0>  // b.hs, b.nlast
    802094cc:	900003c1 	adrp	x1, 80281000 <__sf+0x38>
    802094d0:	a90573fb 	stp	x27, x28, [sp, #80]
    802094d4:	9000005c 	adrp	x28, 80211000 <blanks.1+0x60>
    802094d8:	f9411821 	ldr	x1, [x1, #560]
    802094dc:	d28203e3 	mov	x3, #0x101f                	// #4127
    802094e0:	f9444782 	ldr	x2, [x28, #2184]
    802094e4:	8b010281 	add	x1, x20, x1
    802094e8:	8b030038 	add	x24, x1, x3
    802094ec:	91008021 	add	x1, x1, #0x20
    802094f0:	b100045f 	cmn	x2, #0x1
    802094f4:	9274cf18 	and	x24, x24, #0xfffffffffffff000
    802094f8:	9a811318 	csel	x24, x24, x1, ne	// ne = any
    802094fc:	aa1503e0 	mov	x0, x21
    80209500:	aa1803e1 	mov	x1, x24
    80209504:	8b17027b 	add	x27, x19, x23
    80209508:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020950c:	9400133d 	bl	8020e200 <_sbrk_r>
    80209510:	aa0003f9 	mov	x25, x0
    80209514:	b100041f 	cmn	x0, #0x1
    80209518:	540006a0 	b.eq	802095ec <_malloc_r+0x3ac>  // b.none
    8020951c:	eb00037f 	cmp	x27, x0
    80209520:	54000628 	b.hi	802095e4 <_malloc_r+0x3a4>  // b.pmore
    80209524:	900003da 	adrp	x26, 80281000 <__sf+0x38>
    80209528:	b941fb41 	ldr	w1, [x26, #504]
    8020952c:	0b180021 	add	w1, w1, w24
    80209530:	b901fb41 	str	w1, [x26, #504]
    80209534:	2a0103e0 	mov	w0, w1
    80209538:	54001781 	b.ne	80209828 <_malloc_r+0x5e8>  // b.any
    8020953c:	f2402f7f 	tst	x27, #0xfff
    80209540:	54001741 	b.ne	80209828 <_malloc_r+0x5e8>  // b.any
    80209544:	f9400ac2 	ldr	x2, [x22, #16]
    80209548:	8b1802e0 	add	x0, x23, x24
    8020954c:	b2400000 	orr	x0, x0, #0x1
    80209550:	f9000440 	str	x0, [x2, #8]
    80209554:	d503201f 	nop
    80209558:	900003c0 	adrp	x0, 80281000 <__sf+0x38>
    8020955c:	93407c21 	sxtw	x1, w1
    80209560:	f9411402 	ldr	x2, [x0, #552]
    80209564:	eb02003f 	cmp	x1, x2
    80209568:	54000049 	b.ls	80209570 <_malloc_r+0x330>  // b.plast
    8020956c:	f9011401 	str	x1, [x0, #552]
    80209570:	900003c0 	adrp	x0, 80281000 <__sf+0x38>
    80209574:	f9400ad3 	ldr	x19, [x22, #16]
    80209578:	f9411002 	ldr	x2, [x0, #544]
    8020957c:	eb02003f 	cmp	x1, x2
    80209580:	54000049 	b.ls	80209588 <_malloc_r+0x348>  // b.plast
    80209584:	f9011001 	str	x1, [x0, #544]
    80209588:	f9400660 	ldr	x0, [x19, #8]
    8020958c:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    80209590:	1400001a 	b	802095f8 <_malloc_r+0x3b8>
    80209594:	52800180 	mov	w0, #0xc                   	// #12
    80209598:	d2800013 	mov	x19, #0x0                   	// #0
    8020959c:	b90002a0 	str	w0, [x21]
    802095a0:	1400000c 	b	802095d0 <_malloc_r+0x390>
    802095a4:	d2808004 	mov	x4, #0x400                 	// #1024
    802095a8:	52800800 	mov	w0, #0x40                  	// #64
    802095ac:	528007e5 	mov	w5, #0x3f                  	// #63
    802095b0:	17ffffa1 	b	80209434 <_malloc_r+0x1f4>
    802095b4:	8b010261 	add	x1, x19, x1
    802095b8:	aa1503e0 	mov	x0, x21
    802095bc:	91004273 	add	x19, x19, #0x10
    802095c0:	f9400422 	ldr	x2, [x1, #8]
    802095c4:	b2400042 	orr	x2, x2, #0x1
    802095c8:	f9000422 	str	x2, [x1, #8]
    802095cc:	940006bd 	bl	8020b0c0 <__malloc_unlock>
    802095d0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    802095d4:	aa1303e0 	mov	x0, x19
    802095d8:	a94153f3 	ldp	x19, x20, [sp, #16]
    802095dc:	a8c67bfd 	ldp	x29, x30, [sp], #96
    802095e0:	d65f03c0 	ret
    802095e4:	eb16027f 	cmp	x19, x22
    802095e8:	54001180 	b.eq	80209818 <_malloc_r+0x5d8>  // b.none
    802095ec:	f9400ad3 	ldr	x19, [x22, #16]
    802095f0:	f9400660 	ldr	x0, [x19, #8]
    802095f4:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    802095f8:	eb00029f 	cmp	x20, x0
    802095fc:	cb140000 	sub	x0, x0, x20
    80209600:	fa5f9804 	ccmp	x0, #0x1f, #0x4, ls	// ls = plast
    80209604:	540019ad 	b.le	80209938 <_malloc_r+0x6f8>
    80209608:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020960c:	a94573fb 	ldp	x27, x28, [sp, #80]
    80209610:	8b140262 	add	x2, x19, x20
    80209614:	b2400294 	orr	x20, x20, #0x1
    80209618:	f9000674 	str	x20, [x19, #8]
    8020961c:	b2400001 	orr	x1, x0, #0x1
    80209620:	f9000ac2 	str	x2, [x22, #16]
    80209624:	f9000441 	str	x1, [x2, #8]
    80209628:	aa1503e0 	mov	x0, x21
    8020962c:	91004273 	add	x19, x19, #0x10
    80209630:	940006a4 	bl	8020b0c0 <__malloc_unlock>
    80209634:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209638:	aa1303e0 	mov	x0, x19
    8020963c:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209640:	a94363f7 	ldp	x23, x24, [sp, #48]
    80209644:	a8c67bfd 	ldp	x29, x30, [sp], #96
    80209648:	d65f03c0 	ret
    8020964c:	a9409261 	ldp	x1, x4, [x19, #8]
    80209650:	aa1503e0 	mov	x0, x21
    80209654:	f9400e63 	ldr	x3, [x19, #24]
    80209658:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    8020965c:	8b010261 	add	x1, x19, x1
    80209660:	f9400422 	ldr	x2, [x1, #8]
    80209664:	f9000c83 	str	x3, [x4, #24]
    80209668:	b2400042 	orr	x2, x2, #0x1
    8020966c:	f9000864 	str	x4, [x3, #16]
    80209670:	f9000422 	str	x2, [x1, #8]
    80209674:	91004273 	add	x19, x19, #0x10
    80209678:	94000692 	bl	8020b0c0 <__malloc_unlock>
    8020967c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209680:	aa1303e0 	mov	x0, x19
    80209684:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209688:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020968c:	d65f03c0 	ret
    80209690:	f9400a64 	ldr	x4, [x19, #16]
    80209694:	8b010261 	add	x1, x19, x1
    80209698:	aa1503e0 	mov	x0, x21
    8020969c:	f9400422 	ldr	x2, [x1, #8]
    802096a0:	f9000c83 	str	x3, [x4, #24]
    802096a4:	17fffff1 	b	80209668 <_malloc_r+0x428>
    802096a8:	d349fc22 	lsr	x2, x1, #9
    802096ac:	f127fc3f 	cmp	x1, #0x9ff
    802096b0:	54000989 	b.ls	802097e0 <_malloc_r+0x5a0>  // b.plast
    802096b4:	f100505f 	cmp	x2, #0x14
    802096b8:	540014e8 	b.hi	80209954 <_malloc_r+0x714>  // b.pmore
    802096bc:	11017044 	add	w4, w2, #0x5c
    802096c0:	11016c43 	add	w3, w2, #0x5b
    802096c4:	531f7884 	lsl	w4, w4, #1
    802096c8:	937d7c84 	sbfiz	x4, x4, #3, #32
    802096cc:	8b0402c4 	add	x4, x22, x4
    802096d0:	f85f0482 	ldr	x2, [x4], #-16
    802096d4:	eb02009f 	cmp	x4, x2
    802096d8:	540000a1 	b.ne	802096ec <_malloc_r+0x4ac>  // b.any
    802096dc:	14000085 	b	802098f0 <_malloc_r+0x6b0>
    802096e0:	f9400842 	ldr	x2, [x2, #16]
    802096e4:	eb02009f 	cmp	x4, x2
    802096e8:	540000a0 	b.eq	802096fc <_malloc_r+0x4bc>  // b.none
    802096ec:	f9400443 	ldr	x3, [x2, #8]
    802096f0:	927ef463 	and	x3, x3, #0xfffffffffffffffc
    802096f4:	eb01007f 	cmp	x3, x1
    802096f8:	54ffff48 	b.hi	802096e0 <_malloc_r+0x4a0>  // b.pmore
    802096fc:	f9400c44 	ldr	x4, [x2, #24]
    80209700:	a9011262 	stp	x2, x4, [x19, #16]
    80209704:	f9000893 	str	x19, [x4, #16]
    80209708:	f9000c53 	str	x19, [x2, #24]
    8020970c:	17fffeff 	b	80209308 <_malloc_r+0xc8>
    80209710:	f100503f 	cmp	x1, #0x14
    80209714:	54000729 	b.ls	802097f8 <_malloc_r+0x5b8>  // b.plast
    80209718:	f101503f 	cmp	x1, #0x54
    8020971c:	540012c8 	b.hi	80209974 <_malloc_r+0x734>  // b.pmore
    80209720:	d34cfe81 	lsr	x1, x20, #12
    80209724:	1101bc20 	add	w0, w1, #0x6f
    80209728:	1101b825 	add	w5, w1, #0x6e
    8020972c:	531f7804 	lsl	w4, w0, #1
    80209730:	937d7c84 	sbfiz	x4, x4, #3, #32
    80209734:	17ffff40 	b	80209434 <_malloc_r+0x1f4>
    80209738:	f9400a64 	ldr	x4, [x19, #16]
    8020973c:	b2400280 	orr	x0, x20, #0x1
    80209740:	f9000660 	str	x0, [x19, #8]
    80209744:	8b140274 	add	x20, x19, x20
    80209748:	b2400065 	orr	x5, x3, #0x1
    8020974c:	aa1503e0 	mov	x0, x21
    80209750:	f9000c81 	str	x1, [x4, #24]
    80209754:	f9000824 	str	x4, [x1, #16]
    80209758:	a90252d4 	stp	x20, x20, [x22, #32]
    8020975c:	a9009a85 	stp	x5, x6, [x20, #8]
    80209760:	f9000e86 	str	x6, [x20, #24]
    80209764:	f8226a63 	str	x3, [x19, x2]
    80209768:	91004273 	add	x19, x19, #0x10
    8020976c:	94000655 	bl	8020b0c0 <__malloc_unlock>
    80209770:	17ffff98 	b	802095d0 <_malloc_r+0x390>
    80209774:	8b020262 	add	x2, x19, x2
    80209778:	aa1503e0 	mov	x0, x21
    8020977c:	f8410e64 	ldr	x4, [x19, #16]!
    80209780:	f9400443 	ldr	x3, [x2, #8]
    80209784:	b2400063 	orr	x3, x3, #0x1
    80209788:	f9000443 	str	x3, [x2, #8]
    8020978c:	f9000c81 	str	x1, [x4, #24]
    80209790:	f9000824 	str	x4, [x1, #16]
    80209794:	9400064b 	bl	8020b0c0 <__malloc_unlock>
    80209798:	17ffff8e 	b	802095d0 <_malloc_r+0x390>
    8020979c:	d343fe80 	lsr	x0, x20, #3
    802097a0:	11000401 	add	w1, w0, #0x1
    802097a4:	531f7821 	lsl	w1, w1, #1
    802097a8:	937d7c21 	sbfiz	x1, x1, #3, #32
    802097ac:	17fffeb3 	b	80209278 <_malloc_r+0x38>
    802097b0:	8b140263 	add	x3, x19, x20
    802097b4:	b2400294 	orr	x20, x20, #0x1
    802097b8:	f9000674 	str	x20, [x19, #8]
    802097bc:	b2400044 	orr	x4, x2, #0x1
    802097c0:	a9020ec3 	stp	x3, x3, [x22, #32]
    802097c4:	aa1503e0 	mov	x0, x21
    802097c8:	a9009864 	stp	x4, x6, [x3, #8]
    802097cc:	f9000c66 	str	x6, [x3, #24]
    802097d0:	f8216a62 	str	x2, [x19, x1]
    802097d4:	91004273 	add	x19, x19, #0x10
    802097d8:	9400063a 	bl	8020b0c0 <__malloc_unlock>
    802097dc:	17ffff7d 	b	802095d0 <_malloc_r+0x390>
    802097e0:	d346fc22 	lsr	x2, x1, #6
    802097e4:	1100e444 	add	w4, w2, #0x39
    802097e8:	1100e043 	add	w3, w2, #0x38
    802097ec:	531f7884 	lsl	w4, w4, #1
    802097f0:	937d7c84 	sbfiz	x4, x4, #3, #32
    802097f4:	17ffffb6 	b	802096cc <_malloc_r+0x48c>
    802097f8:	11017020 	add	w0, w1, #0x5c
    802097fc:	11016c25 	add	w5, w1, #0x5b
    80209800:	531f7804 	lsl	w4, w0, #1
    80209804:	937d7c84 	sbfiz	x4, x4, #3, #32
    80209808:	17ffff0b 	b	80209434 <_malloc_r+0x1f4>
    8020980c:	11000508 	add	w8, w8, #0x1
    80209810:	910080a5 	add	x5, x5, #0x20
    80209814:	17fffedf 	b	80209390 <_malloc_r+0x150>
    80209818:	900003da 	adrp	x26, 80281000 <__sf+0x38>
    8020981c:	b941fb40 	ldr	w0, [x26, #504]
    80209820:	0b180000 	add	w0, w0, w24
    80209824:	b901fb40 	str	w0, [x26, #504]
    80209828:	f9444781 	ldr	x1, [x28, #2184]
    8020982c:	b100043f 	cmn	x1, #0x1
    80209830:	54000b20 	b.eq	80209994 <_malloc_r+0x754>  // b.none
    80209834:	cb1b033b 	sub	x27, x25, x27
    80209838:	0b1b0000 	add	w0, w0, w27
    8020983c:	b901fb40 	str	w0, [x26, #504]
    80209840:	f2400f3c 	ands	x28, x25, #0xf
    80209844:	54000620 	b.eq	80209908 <_malloc_r+0x6c8>  // b.none
    80209848:	cb1c0339 	sub	x25, x25, x28
    8020984c:	d282021b 	mov	x27, #0x1010                	// #4112
    80209850:	91004339 	add	x25, x25, #0x10
    80209854:	cb1c037b 	sub	x27, x27, x28
    80209858:	8b180338 	add	x24, x25, x24
    8020985c:	aa1503e0 	mov	x0, x21
    80209860:	cb18037b 	sub	x27, x27, x24
    80209864:	92402f7b 	and	x27, x27, #0xfff
    80209868:	aa1b03e1 	mov	x1, x27
    8020986c:	94001265 	bl	8020e200 <_sbrk_r>
    80209870:	b100041f 	cmn	x0, #0x1
    80209874:	54000b40 	b.eq	802099dc <_malloc_r+0x79c>  // b.none
    80209878:	cb190000 	sub	x0, x0, x25
    8020987c:	2a1b03e2 	mov	w2, w27
    80209880:	8b1b0018 	add	x24, x0, x27
    80209884:	b941fb40 	ldr	w0, [x26, #504]
    80209888:	b2400318 	orr	x24, x24, #0x1
    8020988c:	f9000ad9 	str	x25, [x22, #16]
    80209890:	0b000041 	add	w1, w2, w0
    80209894:	b901fb41 	str	w1, [x26, #504]
    80209898:	f9000738 	str	x24, [x25, #8]
    8020989c:	eb16027f 	cmp	x19, x22
    802098a0:	54ffe5c0 	b.eq	80209558 <_malloc_r+0x318>  // b.none
    802098a4:	f1007eff 	cmp	x23, #0x1f
    802098a8:	54000449 	b.ls	80209930 <_malloc_r+0x6f0>  // b.plast
    802098ac:	f9400662 	ldr	x2, [x19, #8]
    802098b0:	90000043 	adrp	x3, 80211000 <blanks.1+0x60>
    802098b4:	d10062e0 	sub	x0, x23, #0x18
    802098b8:	3dc02460 	ldr	q0, [x3, #144]
    802098bc:	927cec00 	and	x0, x0, #0xfffffffffffffff0
    802098c0:	8b000263 	add	x3, x19, x0
    802098c4:	92400042 	and	x2, x2, #0x1
    802098c8:	aa000042 	orr	x2, x2, x0
    802098cc:	f9000662 	str	x2, [x19, #8]
    802098d0:	3c808060 	stur	q0, [x3, #8]
    802098d4:	f1007c1f 	cmp	x0, #0x1f
    802098d8:	54ffe409 	b.ls	80209558 <_malloc_r+0x318>  // b.plast
    802098dc:	91004261 	add	x1, x19, #0x10
    802098e0:	aa1503e0 	mov	x0, x21
    802098e4:	94000dc7 	bl	8020d000 <_free_r>
    802098e8:	b941fb41 	ldr	w1, [x26, #504]
    802098ec:	17ffff1b 	b	80209558 <_malloc_r+0x318>
    802098f0:	13027c63 	asr	w3, w3, #2
    802098f4:	d2800021 	mov	x1, #0x1                   	// #1
    802098f8:	9ac32021 	lsl	x1, x1, x3
    802098fc:	aa0100a5 	orr	x5, x5, x1
    80209900:	f90006c5 	str	x5, [x22, #8]
    80209904:	17ffff7f 	b	80209700 <_malloc_r+0x4c0>
    80209908:	8b18033b 	add	x27, x25, x24
    8020990c:	aa1503e0 	mov	x0, x21
    80209910:	cb1b03fb 	neg	x27, x27
    80209914:	92402f7b 	and	x27, x27, #0xfff
    80209918:	aa1b03e1 	mov	x1, x27
    8020991c:	94001239 	bl	8020e200 <_sbrk_r>
    80209920:	52800002 	mov	w2, #0x0                   	// #0
    80209924:	b100041f 	cmn	x0, #0x1
    80209928:	54fffa81 	b.ne	80209878 <_malloc_r+0x638>  // b.any
    8020992c:	17ffffd6 	b	80209884 <_malloc_r+0x644>
    80209930:	d2800020 	mov	x0, #0x1                   	// #1
    80209934:	f9000720 	str	x0, [x25, #8]
    80209938:	aa1503e0 	mov	x0, x21
    8020993c:	d2800013 	mov	x19, #0x0                   	// #0
    80209940:	940005e0 	bl	8020b0c0 <__malloc_unlock>
    80209944:	a94363f7 	ldp	x23, x24, [sp, #48]
    80209948:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020994c:	a94573fb 	ldp	x27, x28, [sp, #80]
    80209950:	17ffff20 	b	802095d0 <_malloc_r+0x390>
    80209954:	f101505f 	cmp	x2, #0x54
    80209958:	54000228 	b.hi	8020999c <_malloc_r+0x75c>  // b.pmore
    8020995c:	d34cfc22 	lsr	x2, x1, #12
    80209960:	1101bc44 	add	w4, w2, #0x6f
    80209964:	1101b843 	add	w3, w2, #0x6e
    80209968:	531f7884 	lsl	w4, w4, #1
    8020996c:	937d7c84 	sbfiz	x4, x4, #3, #32
    80209970:	17ffff57 	b	802096cc <_malloc_r+0x48c>
    80209974:	f105503f 	cmp	x1, #0x154
    80209978:	54000228 	b.hi	802099bc <_malloc_r+0x77c>  // b.pmore
    8020997c:	d34ffe81 	lsr	x1, x20, #15
    80209980:	1101e020 	add	w0, w1, #0x78
    80209984:	1101dc25 	add	w5, w1, #0x77
    80209988:	531f7804 	lsl	w4, w0, #1
    8020998c:	937d7c84 	sbfiz	x4, x4, #3, #32
    80209990:	17fffea9 	b	80209434 <_malloc_r+0x1f4>
    80209994:	f9044799 	str	x25, [x28, #2184]
    80209998:	17ffffaa 	b	80209840 <_malloc_r+0x600>
    8020999c:	f105505f 	cmp	x2, #0x154
    802099a0:	54000288 	b.hi	802099f0 <_malloc_r+0x7b0>  // b.pmore
    802099a4:	d34ffc22 	lsr	x2, x1, #15
    802099a8:	1101e044 	add	w4, w2, #0x78
    802099ac:	1101dc43 	add	w3, w2, #0x77
    802099b0:	531f7884 	lsl	w4, w4, #1
    802099b4:	937d7c84 	sbfiz	x4, x4, #3, #32
    802099b8:	17ffff45 	b	802096cc <_malloc_r+0x48c>
    802099bc:	f115503f 	cmp	x1, #0x554
    802099c0:	54000288 	b.hi	80209a10 <_malloc_r+0x7d0>  // b.pmore
    802099c4:	d352fe81 	lsr	x1, x20, #18
    802099c8:	1101f420 	add	w0, w1, #0x7d
    802099cc:	1101f025 	add	w5, w1, #0x7c
    802099d0:	531f7804 	lsl	w4, w0, #1
    802099d4:	937d7c84 	sbfiz	x4, x4, #3, #32
    802099d8:	17fffe97 	b	80209434 <_malloc_r+0x1f4>
    802099dc:	d100439c 	sub	x28, x28, #0x10
    802099e0:	52800002 	mov	w2, #0x0                   	// #0
    802099e4:	8b1c0318 	add	x24, x24, x28
    802099e8:	cb190318 	sub	x24, x24, x25
    802099ec:	17ffffa6 	b	80209884 <_malloc_r+0x644>
    802099f0:	f115505f 	cmp	x2, #0x554
    802099f4:	54000168 	b.hi	80209a20 <_malloc_r+0x7e0>  // b.pmore
    802099f8:	d352fc22 	lsr	x2, x1, #18
    802099fc:	1101f444 	add	w4, w2, #0x7d
    80209a00:	1101f043 	add	w3, w2, #0x7c
    80209a04:	531f7884 	lsl	w4, w4, #1
    80209a08:	937d7c84 	sbfiz	x4, x4, #3, #32
    80209a0c:	17ffff30 	b	802096cc <_malloc_r+0x48c>
    80209a10:	d280fe04 	mov	x4, #0x7f0                 	// #2032
    80209a14:	52800fe0 	mov	w0, #0x7f                  	// #127
    80209a18:	52800fc5 	mov	w5, #0x7e                  	// #126
    80209a1c:	17fffe86 	b	80209434 <_malloc_r+0x1f4>
    80209a20:	d280fe04 	mov	x4, #0x7f0                 	// #2032
    80209a24:	52800fc3 	mov	w3, #0x7e                  	// #126
    80209a28:	17ffff29 	b	802096cc <_malloc_r+0x48c>
    80209a2c:	f94006c0 	ldr	x0, [x22, #8]
    80209a30:	17fffe65 	b	802093c4 <_malloc_r+0x184>
	...

0000000080209a40 <_wcrtomb_r>:
    80209a40:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80209a44:	9104f004 	add	x4, x0, #0x13c
    80209a48:	910003fd 	mov	x29, sp
    80209a4c:	a90153f3 	stp	x19, x20, [sp, #16]
    80209a50:	aa0303f3 	mov	x19, x3
    80209a54:	f100027f 	cmp	x19, #0x0
    80209a58:	b0000043 	adrp	x3, 80212000 <__malloc_av_+0x760>
    80209a5c:	9a930093 	csel	x19, x4, x19, eq	// eq = none
    80209a60:	aa0003f4 	mov	x20, x0
    80209a64:	f9414064 	ldr	x4, [x3, #640]
    80209a68:	aa1303e3 	mov	x3, x19
    80209a6c:	b4000121 	cbz	x1, 80209a90 <_wcrtomb_r+0x50>
    80209a70:	d63f0080 	blr	x4
    80209a74:	2a0003e1 	mov	w1, w0
    80209a78:	93407c20 	sxtw	x0, w1
    80209a7c:	3100043f 	cmn	w1, #0x1
    80209a80:	54000160 	b.eq	80209aac <_wcrtomb_r+0x6c>  // b.none
    80209a84:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209a88:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80209a8c:	d65f03c0 	ret
    80209a90:	910083e1 	add	x1, sp, #0x20
    80209a94:	52800002 	mov	w2, #0x0                   	// #0
    80209a98:	d63f0080 	blr	x4
    80209a9c:	2a0003e1 	mov	w1, w0
    80209aa0:	93407c20 	sxtw	x0, w1
    80209aa4:	3100043f 	cmn	w1, #0x1
    80209aa8:	54fffee1 	b.ne	80209a84 <_wcrtomb_r+0x44>  // b.any
    80209aac:	b900027f 	str	wzr, [x19]
    80209ab0:	52801141 	mov	w1, #0x8a                  	// #138
    80209ab4:	b9000281 	str	w1, [x20]
    80209ab8:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    80209abc:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209ac0:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80209ac4:	d65f03c0 	ret
	...

0000000080209ad0 <wcrtomb>:
    80209ad0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80209ad4:	90000044 	adrp	x4, 80211000 <blanks.1+0x60>
    80209ad8:	b0000043 	adrp	x3, 80212000 <__malloc_av_+0x760>
    80209adc:	910003fd 	mov	x29, sp
    80209ae0:	a90153f3 	stp	x19, x20, [sp, #16]
    80209ae4:	f100005f 	cmp	x2, #0x0
    80209ae8:	f9438894 	ldr	x20, [x4, #1808]
    80209aec:	9104f284 	add	x4, x20, #0x13c
    80209af0:	9a820093 	csel	x19, x4, x2, eq	// eq = none
    80209af4:	f9414064 	ldr	x4, [x3, #640]
    80209af8:	b40001a0 	cbz	x0, 80209b2c <wcrtomb+0x5c>
    80209afc:	2a0103e2 	mov	w2, w1
    80209b00:	aa0003e1 	mov	x1, x0
    80209b04:	aa1303e3 	mov	x3, x19
    80209b08:	aa1403e0 	mov	x0, x20
    80209b0c:	d63f0080 	blr	x4
    80209b10:	2a0003e1 	mov	w1, w0
    80209b14:	93407c20 	sxtw	x0, w1
    80209b18:	3100043f 	cmn	w1, #0x1
    80209b1c:	540001a0 	b.eq	80209b50 <wcrtomb+0x80>  // b.none
    80209b20:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209b24:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80209b28:	d65f03c0 	ret
    80209b2c:	910083e1 	add	x1, sp, #0x20
    80209b30:	aa1303e3 	mov	x3, x19
    80209b34:	aa1403e0 	mov	x0, x20
    80209b38:	52800002 	mov	w2, #0x0                   	// #0
    80209b3c:	d63f0080 	blr	x4
    80209b40:	2a0003e1 	mov	w1, w0
    80209b44:	93407c20 	sxtw	x0, w1
    80209b48:	3100043f 	cmn	w1, #0x1
    80209b4c:	54fffea1 	b.ne	80209b20 <wcrtomb+0x50>  // b.any
    80209b50:	b900027f 	str	wzr, [x19]
    80209b54:	52801141 	mov	w1, #0x8a                  	// #138
    80209b58:	b9000281 	str	w1, [x20]
    80209b5c:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    80209b60:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209b64:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80209b68:	d65f03c0 	ret
    80209b6c:	00000000 	udf	#0

0000000080209b70 <__retarget_lock_init>:
    80209b70:	d65f03c0 	ret
	...

0000000080209b80 <__retarget_lock_init_recursive>:
    80209b80:	d65f03c0 	ret
	...

0000000080209b90 <__retarget_lock_close>:
    80209b90:	d65f03c0 	ret
	...

0000000080209ba0 <__retarget_lock_close_recursive>:
    80209ba0:	d65f03c0 	ret
	...

0000000080209bb0 <__retarget_lock_acquire>:
    80209bb0:	d65f03c0 	ret
	...

0000000080209bc0 <__retarget_lock_acquire_recursive>:
    80209bc0:	d65f03c0 	ret
	...

0000000080209bd0 <__retarget_lock_try_acquire>:
    80209bd0:	52800020 	mov	w0, #0x1                   	// #1
    80209bd4:	d65f03c0 	ret
	...

0000000080209be0 <__retarget_lock_try_acquire_recursive>:
    80209be0:	52800020 	mov	w0, #0x1                   	// #1
    80209be4:	d65f03c0 	ret
	...

0000000080209bf0 <__retarget_lock_release>:
    80209bf0:	d65f03c0 	ret
	...

0000000080209c00 <__retarget_lock_release_recursive>:
    80209c00:	d65f03c0 	ret
	...

0000000080209c10 <currentlocale>:
    80209c10:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    80209c14:	910003fd 	mov	x29, sp
    80209c18:	a90153f3 	stp	x19, x20, [sp, #16]
    80209c1c:	b0000054 	adrp	x20, 80212000 <__malloc_av_+0x760>
    80209c20:	91068294 	add	x20, x20, #0x1a0
    80209c24:	a9025bf5 	stp	x21, x22, [sp, #32]
    80209c28:	b0000055 	adrp	x21, 80212000 <__malloc_av_+0x760>
    80209c2c:	910782b5 	add	x21, x21, #0x1e0
    80209c30:	f9001bf7 	str	x23, [sp, #48]
    80209c34:	b0000057 	adrp	x23, 80212000 <__malloc_av_+0x760>
    80209c38:	9102c2f7 	add	x23, x23, #0xb0
    80209c3c:	b0000056 	adrp	x22, 80212000 <__malloc_av_+0x760>
    80209c40:	aa1503f3 	mov	x19, x21
    80209c44:	910702c1 	add	x1, x22, #0x1c0
    80209c48:	91038294 	add	x20, x20, #0xe0
    80209c4c:	910702d6 	add	x22, x22, #0x1c0
    80209c50:	aa1703e0 	mov	x0, x23
    80209c54:	94000fbb 	bl	8020db40 <strcpy>
    80209c58:	aa1303e1 	mov	x1, x19
    80209c5c:	aa1603e0 	mov	x0, x22
    80209c60:	91008273 	add	x19, x19, #0x20
    80209c64:	94000f67 	bl	8020da00 <strcmp>
    80209c68:	35000120 	cbnz	w0, 80209c8c <currentlocale+0x7c>
    80209c6c:	eb14027f 	cmp	x19, x20
    80209c70:	54ffff41 	b.ne	80209c58 <currentlocale+0x48>  // b.any
    80209c74:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209c78:	aa1703e0 	mov	x0, x23
    80209c7c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209c80:	f9401bf7 	ldr	x23, [sp, #48]
    80209c84:	a8c47bfd 	ldp	x29, x30, [sp], #64
    80209c88:	d65f03c0 	ret
    80209c8c:	f0000033 	adrp	x19, 80210000 <_wcsnrtombs_l+0x110>
    80209c90:	91304273 	add	x19, x19, #0xc10
    80209c94:	d503201f 	nop
    80209c98:	aa1303e1 	mov	x1, x19
    80209c9c:	aa1703e0 	mov	x0, x23
    80209ca0:	94001434 	bl	8020ed70 <strcat>
    80209ca4:	aa1503e1 	mov	x1, x21
    80209ca8:	aa1703e0 	mov	x0, x23
    80209cac:	910082b5 	add	x21, x21, #0x20
    80209cb0:	94001430 	bl	8020ed70 <strcat>
    80209cb4:	eb1402bf 	cmp	x21, x20
    80209cb8:	54ffff01 	b.ne	80209c98 <currentlocale+0x88>  // b.any
    80209cbc:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209cc0:	aa1703e0 	mov	x0, x23
    80209cc4:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209cc8:	f9401bf7 	ldr	x23, [sp, #48]
    80209ccc:	a8c47bfd 	ldp	x29, x30, [sp], #64
    80209cd0:	d65f03c0 	ret
	...

0000000080209ce0 <__loadlocale>:
    80209ce0:	a9b67bfd 	stp	x29, x30, [sp, #-160]!
    80209ce4:	910003fd 	mov	x29, sp
    80209ce8:	a90153f3 	stp	x19, x20, [sp, #16]
    80209cec:	937b7c34 	sbfiz	x20, x1, #5, #32
    80209cf0:	8b140014 	add	x20, x0, x20
    80209cf4:	aa0203f3 	mov	x19, x2
    80209cf8:	a9025bf5 	stp	x21, x22, [sp, #32]
    80209cfc:	aa0003f6 	mov	x22, x0
    80209d00:	aa0203e0 	mov	x0, x2
    80209d04:	a90363f7 	stp	x23, x24, [sp, #48]
    80209d08:	2a0103f7 	mov	w23, w1
    80209d0c:	aa1403e1 	mov	x1, x20
    80209d10:	94000f3c 	bl	8020da00 <strcmp>
    80209d14:	350000e0 	cbnz	w0, 80209d30 <__loadlocale+0x50>
    80209d18:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209d1c:	aa1403e0 	mov	x0, x20
    80209d20:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209d24:	a94363f7 	ldp	x23, x24, [sp, #48]
    80209d28:	a8ca7bfd 	ldp	x29, x30, [sp], #160
    80209d2c:	d65f03c0 	ret
    80209d30:	aa1303e0 	mov	x0, x19
    80209d34:	f0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    80209d38:	f0000035 	adrp	x21, 80210000 <_wcsnrtombs_l+0x110>
    80209d3c:	91306021 	add	x1, x1, #0xc18
    80209d40:	913082b5 	add	x21, x21, #0xc20
    80209d44:	94000f2f 	bl	8020da00 <strcmp>
    80209d48:	340008e0 	cbz	w0, 80209e64 <__loadlocale+0x184>
    80209d4c:	aa1503e1 	mov	x1, x21
    80209d50:	aa1303e0 	mov	x0, x19
    80209d54:	94000f2b 	bl	8020da00 <strcmp>
    80209d58:	34000780 	cbz	w0, 80209e48 <__loadlocale+0x168>
    80209d5c:	39400260 	ldrb	w0, [x19]
    80209d60:	71010c1f 	cmp	w0, #0x43
    80209d64:	540008e0 	b.eq	80209e80 <__loadlocale+0x1a0>  // b.none
    80209d68:	51018400 	sub	w0, w0, #0x61
    80209d6c:	12001c00 	and	w0, w0, #0xff
    80209d70:	7100641f 	cmp	w0, #0x19
    80209d74:	54000668 	b.hi	80209e40 <__loadlocale+0x160>  // b.pmore
    80209d78:	39400660 	ldrb	w0, [x19, #1]
    80209d7c:	51018400 	sub	w0, w0, #0x61
    80209d80:	12001c00 	and	w0, w0, #0xff
    80209d84:	7100641f 	cmp	w0, #0x19
    80209d88:	540005c8 	b.hi	80209e40 <__loadlocale+0x160>  // b.pmore
    80209d8c:	39400a60 	ldrb	w0, [x19, #2]
    80209d90:	91000a78 	add	x24, x19, #0x2
    80209d94:	51018401 	sub	w1, w0, #0x61
    80209d98:	12001c21 	and	w1, w1, #0xff
    80209d9c:	7100643f 	cmp	w1, #0x19
    80209da0:	54000068 	b.hi	80209dac <__loadlocale+0xcc>  // b.pmore
    80209da4:	39400e60 	ldrb	w0, [x19, #3]
    80209da8:	91000e78 	add	x24, x19, #0x3
    80209dac:	71017c1f 	cmp	w0, #0x5f
    80209db0:	54000900 	b.eq	80209ed0 <__loadlocale+0x1f0>  // b.none
    80209db4:	7100b81f 	cmp	w0, #0x2e
    80209db8:	54002f60 	b.eq	8020a3a4 <__loadlocale+0x6c4>  // b.none
    80209dbc:	528017e1 	mov	w1, #0xbf                  	// #191
    80209dc0:	6a01001f 	tst	w0, w1
    80209dc4:	540003e1 	b.ne	80209e40 <__loadlocale+0x160>  // b.any
    80209dc8:	910203f5 	add	x21, sp, #0x80
    80209dcc:	f0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    80209dd0:	aa1503e0 	mov	x0, x21
    80209dd4:	9130c021 	add	x1, x1, #0xc30
    80209dd8:	a9046bf9 	stp	x25, x26, [sp, #64]
    80209ddc:	94000f59 	bl	8020db40 <strcpy>
    80209de0:	39400300 	ldrb	w0, [x24]
    80209de4:	7101001f 	cmp	w0, #0x40
    80209de8:	54002e40 	b.eq	8020a3b0 <__loadlocale+0x6d0>  // b.none
    80209dec:	52800018 	mov	w24, #0x0                   	// #0
    80209df0:	52800019 	mov	w25, #0x0                   	// #0
    80209df4:	5280001a 	mov	w26, #0x0                   	// #0
    80209df8:	394203e1 	ldrb	w1, [sp, #128]
    80209dfc:	51010421 	sub	w1, w1, #0x41
    80209e00:	7100d03f 	cmp	w1, #0x34
    80209e04:	54000388 	b.hi	80209e74 <__loadlocale+0x194>  // b.pmore
    80209e08:	90000040 	adrp	x0, 80211000 <blanks.1+0x60>
    80209e0c:	91028000 	add	x0, x0, #0xa0
    80209e10:	a90573fb 	stp	x27, x28, [sp, #80]
    80209e14:	78615800 	ldrh	w0, [x0, w1, uxtw #1]
    80209e18:	10000061 	adr	x1, 80209e24 <__loadlocale+0x144>
    80209e1c:	8b20a820 	add	x0, x1, w0, sxth #2
    80209e20:	d61f0000 	br	x0
    80209e24:	d10d4800 	sub	x0, x0, #0x352
    80209e28:	d28234a1 	mov	x1, #0x11a5                	// #4517
    80209e2c:	f2a00021 	movk	x1, #0x1, lsl #16
    80209e30:	9ac02420 	lsr	x0, x1, x0
    80209e34:	37000c60 	tbnz	w0, #0, 80209fc0 <__loadlocale+0x2e0>
    80209e38:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80209e3c:	a94573fb 	ldp	x27, x28, [sp, #80]
    80209e40:	d2800014 	mov	x20, #0x0                   	// #0
    80209e44:	17ffffb5 	b	80209d18 <__loadlocale+0x38>
    80209e48:	910203f5 	add	x21, sp, #0x80
    80209e4c:	f0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    80209e50:	aa1503e0 	mov	x0, x21
    80209e54:	9130a021 	add	x1, x1, #0xc28
    80209e58:	a9046bf9 	stp	x25, x26, [sp, #64]
    80209e5c:	94000f39 	bl	8020db40 <strcpy>
    80209e60:	17ffffe3 	b	80209dec <__loadlocale+0x10c>
    80209e64:	aa1503e1 	mov	x1, x21
    80209e68:	aa1303e0 	mov	x0, x19
    80209e6c:	94000f35 	bl	8020db40 <strcpy>
    80209e70:	17ffffb7 	b	80209d4c <__loadlocale+0x6c>
    80209e74:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80209e78:	d2800014 	mov	x20, #0x0                   	// #0
    80209e7c:	17ffffa7 	b	80209d18 <__loadlocale+0x38>
    80209e80:	39400660 	ldrb	w0, [x19, #1]
    80209e84:	5100b400 	sub	w0, w0, #0x2d
    80209e88:	12001c00 	and	w0, w0, #0xff
    80209e8c:	7100041f 	cmp	w0, #0x1
    80209e90:	54fffd88 	b.hi	80209e40 <__loadlocale+0x160>  // b.pmore
    80209e94:	91000a78 	add	x24, x19, #0x2
    80209e98:	a9046bf9 	stp	x25, x26, [sp, #64]
    80209e9c:	910203f5 	add	x21, sp, #0x80
    80209ea0:	aa1803e1 	mov	x1, x24
    80209ea4:	aa1503e0 	mov	x0, x21
    80209ea8:	94000f26 	bl	8020db40 <strcpy>
    80209eac:	aa1503e0 	mov	x0, x21
    80209eb0:	52800801 	mov	w1, #0x40                  	// #64
    80209eb4:	94000e93 	bl	8020d900 <strchr>
    80209eb8:	b4000040 	cbz	x0, 80209ec0 <__loadlocale+0x1e0>
    80209ebc:	3900001f 	strb	wzr, [x0]
    80209ec0:	aa1503e0 	mov	x0, x21
    80209ec4:	97ffe68f 	bl	80203900 <strlen>
    80209ec8:	8b000318 	add	x24, x24, x0
    80209ecc:	17ffffc5 	b	80209de0 <__loadlocale+0x100>
    80209ed0:	39400700 	ldrb	w0, [x24, #1]
    80209ed4:	51010400 	sub	w0, w0, #0x41
    80209ed8:	12001c00 	and	w0, w0, #0xff
    80209edc:	7100641f 	cmp	w0, #0x19
    80209ee0:	54fffb08 	b.hi	80209e40 <__loadlocale+0x160>  // b.pmore
    80209ee4:	39400b00 	ldrb	w0, [x24, #2]
    80209ee8:	51010400 	sub	w0, w0, #0x41
    80209eec:	12001c00 	and	w0, w0, #0xff
    80209ef0:	7100641f 	cmp	w0, #0x19
    80209ef4:	54fffa68 	b.hi	80209e40 <__loadlocale+0x160>  // b.pmore
    80209ef8:	39400f00 	ldrb	w0, [x24, #3]
    80209efc:	91000f18 	add	x24, x24, #0x3
    80209f00:	17ffffad 	b	80209db4 <__loadlocale+0xd4>
    80209f04:	f000003b 	adrp	x27, 80210000 <_wcsnrtombs_l+0x110>
    80209f08:	9131a37b 	add	x27, x27, #0xc68
    80209f0c:	aa1b03e1 	mov	x1, x27
    80209f10:	aa1503e0 	mov	x0, x21
    80209f14:	9400137b 	bl	8020ed00 <strcasecmp>
    80209f18:	340000c0 	cbz	w0, 80209f30 <__loadlocale+0x250>
    80209f1c:	f0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    80209f20:	aa1503e0 	mov	x0, x21
    80209f24:	9131c021 	add	x1, x1, #0xc70
    80209f28:	94001376 	bl	8020ed00 <strcasecmp>
    80209f2c:	35fff860 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    80209f30:	aa1b03e1 	mov	x1, x27
    80209f34:	aa1503e0 	mov	x0, x21
    80209f38:	94000f02 	bl	8020db40 <strcpy>
    80209f3c:	b000003b 	adrp	x27, 8020e000 <__sjis_wctomb>
    80209f40:	90000022 	adrp	x2, 8020d000 <_free_r>
    80209f44:	9118037b 	add	x27, x27, #0x600
    80209f48:	913c4042 	add	x2, x2, #0xf10
    80209f4c:	528000dc 	mov	w28, #0x6                   	// #6
    80209f50:	71000aff 	cmp	w23, #0x2
    80209f54:	54001fa0 	b.eq	8020a348 <__loadlocale+0x668>  // b.none
    80209f58:	71001aff 	cmp	w23, #0x6
    80209f5c:	54000081 	b.ne	80209f6c <__loadlocale+0x28c>  // b.any
    80209f60:	aa1503e1 	mov	x1, x21
    80209f64:	91060ac0 	add	x0, x22, #0x182
    80209f68:	94000ef6 	bl	8020db40 <strcpy>
    80209f6c:	aa1303e1 	mov	x1, x19
    80209f70:	aa1403e0 	mov	x0, x20
    80209f74:	94000ef3 	bl	8020db40 <strcpy>
    80209f78:	aa0003f4 	mov	x20, x0
    80209f7c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80209f80:	aa1403e0 	mov	x0, x20
    80209f84:	a94153f3 	ldp	x19, x20, [sp, #16]
    80209f88:	a94363f7 	ldp	x23, x24, [sp, #48]
    80209f8c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80209f90:	a94573fb 	ldp	x27, x28, [sp, #80]
    80209f94:	a8ca7bfd 	ldp	x29, x30, [sp], #160
    80209f98:	d65f03c0 	ret
    80209f9c:	f0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    80209fa0:	aa1503e0 	mov	x0, x21
    80209fa4:	91342021 	add	x1, x1, #0xd08
    80209fa8:	94001356 	bl	8020ed00 <strcasecmp>
    80209fac:	35fff460 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    80209fb0:	f0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    80209fb4:	aa1503e0 	mov	x0, x21
    80209fb8:	91344021 	add	x1, x1, #0xd10
    80209fbc:	94000ee1 	bl	8020db40 <strcpy>
    80209fc0:	b000003b 	adrp	x27, 8020e000 <__sjis_wctomb>
    80209fc4:	90000022 	adrp	x2, 8020d000 <_free_r>
    80209fc8:	9116c37b 	add	x27, x27, #0x5b0
    80209fcc:	913b4042 	add	x2, x2, #0xed0
    80209fd0:	5280003c 	mov	w28, #0x1                   	// #1
    80209fd4:	17ffffdf 	b	80209f50 <__loadlocale+0x270>
    80209fd8:	f0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    80209fdc:	aa1503e0 	mov	x0, x21
    80209fe0:	91332021 	add	x1, x1, #0xcc8
    80209fe4:	d2800082 	mov	x2, #0x4                   	// #4
    80209fe8:	94000d56 	bl	8020d540 <strncasecmp>
    80209fec:	35fff260 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    80209ff0:	394213e0 	ldrb	w0, [sp, #132]
    80209ff4:	394217e1 	ldrb	w1, [sp, #133]
    80209ff8:	7100b41f 	cmp	w0, #0x2d
    80209ffc:	1a800020 	csel	w0, w1, w0, eq	// eq = none
    8020a000:	51014800 	sub	w0, w0, #0x52
    8020a004:	12001c00 	and	w0, w0, #0xff
    8020a008:	71008c1f 	cmp	w0, #0x23
    8020a00c:	54fff168 	b.hi	80209e38 <__loadlocale+0x158>  // b.pmore
    8020a010:	d2800021 	mov	x1, #0x1                   	// #1
    8020a014:	9ac02020 	lsl	x0, x1, x0
    8020a018:	f21e001f 	tst	x0, #0x400000004
    8020a01c:	540020e1 	b.ne	8020a438 <__loadlocale+0x758>  // b.any
    8020a020:	f21d001f 	tst	x0, #0x800000008
    8020a024:	54002001 	b.ne	8020a424 <__loadlocale+0x744>  // b.any
    8020a028:	f200001f 	tst	x0, #0x100000001
    8020a02c:	54fff060 	b.eq	80209e38 <__loadlocale+0x158>  // b.none
    8020a030:	aa1503e0 	mov	x0, x21
    8020a034:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a038:	91334021 	add	x1, x1, #0xcd0
    8020a03c:	94000ec1 	bl	8020db40 <strcpy>
    8020a040:	17ffffe0 	b	80209fc0 <__loadlocale+0x2e0>
    8020a044:	d000003b 	adrp	x27, 80210000 <_wcsnrtombs_l+0x110>
    8020a048:	9131e37b 	add	x27, x27, #0xc78
    8020a04c:	aa1b03e1 	mov	x1, x27
    8020a050:	aa1503e0 	mov	x0, x21
    8020a054:	9400132b 	bl	8020ed00 <strcasecmp>
    8020a058:	35ffef00 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a05c:	aa1b03e1 	mov	x1, x27
    8020a060:	aa1503e0 	mov	x0, x21
    8020a064:	94000eb7 	bl	8020db40 <strcpy>
    8020a068:	9000003b 	adrp	x27, 8020e000 <__sjis_wctomb>
    8020a06c:	90000022 	adrp	x2, 8020e000 <__sjis_wctomb>
    8020a070:	912b037b 	add	x27, x27, #0xac0
    8020a074:	91050042 	add	x2, x2, #0x140
    8020a078:	5280011c 	mov	w28, #0x8                   	// #8
    8020a07c:	17ffffb5 	b	80209f50 <__loadlocale+0x270>
    8020a080:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a084:	aa1503e0 	mov	x0, x21
    8020a088:	91328021 	add	x1, x1, #0xca0
    8020a08c:	d2800062 	mov	x2, #0x3                   	// #3
    8020a090:	94000d2c 	bl	8020d540 <strncasecmp>
    8020a094:	35ffed20 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a098:	39420fe0 	ldrb	w0, [sp, #131]
    8020a09c:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a0a0:	d2800082 	mov	x2, #0x4                   	// #4
    8020a0a4:	9132a021 	add	x1, x1, #0xca8
    8020a0a8:	7100b41f 	cmp	w0, #0x2d
    8020a0ac:	910283e0 	add	x0, sp, #0xa0
    8020a0b0:	9a80141b 	cinc	x27, x0, eq	// eq = none
    8020a0b4:	d100777b 	sub	x27, x27, #0x1d
    8020a0b8:	aa1b03e0 	mov	x0, x27
    8020a0bc:	94000d21 	bl	8020d540 <strncasecmp>
    8020a0c0:	35ffebc0 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a0c4:	39401360 	ldrb	w0, [x27, #4]
    8020a0c8:	9101e3e1 	add	x1, sp, #0x78
    8020a0cc:	52800142 	mov	w2, #0xa                   	// #10
    8020a0d0:	7100b41f 	cmp	w0, #0x2d
    8020a0d4:	9a9b1760 	cinc	x0, x27, eq	// eq = none
    8020a0d8:	91001000 	add	x0, x0, #0x4
    8020a0dc:	94000d05 	bl	8020d4f0 <strtol>
    8020a0e0:	aa0003fb 	mov	x27, x0
    8020a0e4:	d1000400 	sub	x0, x0, #0x1
    8020a0e8:	f1003c1f 	cmp	x0, #0xf
    8020a0ec:	fa4c9b64 	ccmp	x27, #0xc, #0x4, ls	// ls = plast
    8020a0f0:	54ffea40 	b.eq	80209e38 <__loadlocale+0x158>  // b.none
    8020a0f4:	f9403fe0 	ldr	x0, [sp, #120]
    8020a0f8:	39400000 	ldrb	w0, [x0]
    8020a0fc:	35ffe9e0 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a100:	aa1503e0 	mov	x0, x21
    8020a104:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a108:	9132c021 	add	x1, x1, #0xcb0
    8020a10c:	94000e8d 	bl	8020db40 <strcpy>
    8020a110:	910227e2 	add	x2, sp, #0x89
    8020a114:	f1002b7f 	cmp	x27, #0xa
    8020a118:	5400008d 	b.le	8020a128 <__loadlocale+0x448>
    8020a11c:	91022be2 	add	x2, sp, #0x8a
    8020a120:	52800620 	mov	w0, #0x31                  	// #49
    8020a124:	390227e0 	strb	w0, [sp, #137]
    8020a128:	b203e7e1 	mov	x1, #0x6666666666666666    	// #7378697629483820646
    8020a12c:	3900045f 	strb	wzr, [x2, #1]
    8020a130:	f28ccce1 	movk	x1, #0x6667
    8020a134:	9b417f61 	smulh	x1, x27, x1
    8020a138:	9342fc21 	asr	x1, x1, #2
    8020a13c:	cb9bfc21 	sub	x1, x1, x27, asr #63
    8020a140:	8b010821 	add	x1, x1, x1, lsl #2
    8020a144:	cb010760 	sub	x0, x27, x1, lsl #1
    8020a148:	1100c000 	add	w0, w0, #0x30
    8020a14c:	39000040 	strb	w0, [x2]
    8020a150:	17ffff9c 	b	80209fc0 <__loadlocale+0x2e0>
    8020a154:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a158:	aa1503e0 	mov	x0, x21
    8020a15c:	91346021 	add	x1, x1, #0xd18
    8020a160:	d2800062 	mov	x2, #0x3                   	// #3
    8020a164:	94000cf7 	bl	8020d540 <strncasecmp>
    8020a168:	35ffe680 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a16c:	39420fe0 	ldrb	w0, [sp, #131]
    8020a170:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a174:	91348021 	add	x1, x1, #0xd20
    8020a178:	7100b41f 	cmp	w0, #0x2d
    8020a17c:	910283e0 	add	x0, sp, #0xa0
    8020a180:	9a801400 	cinc	x0, x0, eq	// eq = none
    8020a184:	d1007400 	sub	x0, x0, #0x1d
    8020a188:	94000e1e 	bl	8020da00 <strcmp>
    8020a18c:	35ffe560 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a190:	aa1503e0 	mov	x0, x21
    8020a194:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a198:	9134a021 	add	x1, x1, #0xd28
    8020a19c:	94000e69 	bl	8020db40 <strcpy>
    8020a1a0:	17ffff88 	b	80209fc0 <__loadlocale+0x2e0>
    8020a1a4:	d000003b 	adrp	x27, 80210000 <_wcsnrtombs_l+0x110>
    8020a1a8:	9132637b 	add	x27, x27, #0xc98
    8020a1ac:	aa1b03e1 	mov	x1, x27
    8020a1b0:	aa1503e0 	mov	x0, x21
    8020a1b4:	940012d3 	bl	8020ed00 <strcasecmp>
    8020a1b8:	35ffe400 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a1bc:	aa1b03e1 	mov	x1, x27
    8020a1c0:	aa1503e0 	mov	x0, x21
    8020a1c4:	94000e5f 	bl	8020db40 <strcpy>
    8020a1c8:	9000003b 	adrp	x27, 8020e000 <__sjis_wctomb>
    8020a1cc:	90000022 	adrp	x2, 8020e000 <__sjis_wctomb>
    8020a1d0:	9123037b 	add	x27, x27, #0x8c0
    8020a1d4:	91000042 	add	x2, x2, #0x0
    8020a1d8:	5280005c 	mov	w28, #0x2                   	// #2
    8020a1dc:	17ffff5d 	b	80209f50 <__loadlocale+0x270>
    8020a1e0:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a1e4:	aa1503e0 	mov	x0, x21
    8020a1e8:	9133a021 	add	x1, x1, #0xce8
    8020a1ec:	d2800102 	mov	x2, #0x8                   	// #8
    8020a1f0:	94000cd4 	bl	8020d540 <strncasecmp>
    8020a1f4:	35ffe220 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a1f8:	394223e0 	ldrb	w0, [sp, #136]
    8020a1fc:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a200:	9133e021 	add	x1, x1, #0xcf8
    8020a204:	7100b41f 	cmp	w0, #0x2d
    8020a208:	910283e0 	add	x0, sp, #0xa0
    8020a20c:	9a801400 	cinc	x0, x0, eq	// eq = none
    8020a210:	d1006000 	sub	x0, x0, #0x18
    8020a214:	940012bb 	bl	8020ed00 <strcasecmp>
    8020a218:	35ffe100 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a21c:	aa1503e0 	mov	x0, x21
    8020a220:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a224:	91340021 	add	x1, x1, #0xd00
    8020a228:	94000e46 	bl	8020db40 <strcpy>
    8020a22c:	17ffff65 	b	80209fc0 <__loadlocale+0x2e0>
    8020a230:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a234:	aa1503e0 	mov	x0, x21
    8020a238:	91320021 	add	x1, x1, #0xc80
    8020a23c:	d2800062 	mov	x2, #0x3                   	// #3
    8020a240:	94000cc0 	bl	8020d540 <strncasecmp>
    8020a244:	35ffdfa0 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a248:	39420fe0 	ldrb	w0, [sp, #131]
    8020a24c:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a250:	91322021 	add	x1, x1, #0xc88
    8020a254:	7100b41f 	cmp	w0, #0x2d
    8020a258:	910283e0 	add	x0, sp, #0xa0
    8020a25c:	9a801400 	cinc	x0, x0, eq	// eq = none
    8020a260:	d1007400 	sub	x0, x0, #0x1d
    8020a264:	940012a7 	bl	8020ed00 <strcasecmp>
    8020a268:	35ffde80 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a26c:	aa1503e0 	mov	x0, x21
    8020a270:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a274:	91324021 	add	x1, x1, #0xc90
    8020a278:	94000e32 	bl	8020db40 <strcpy>
    8020a27c:	9000003b 	adrp	x27, 8020e000 <__sjis_wctomb>
    8020a280:	90000022 	adrp	x2, 8020e000 <__sjis_wctomb>
    8020a284:	9126437b 	add	x27, x27, #0x990
    8020a288:	91024042 	add	x2, x2, #0x90
    8020a28c:	5280007c 	mov	w28, #0x3                   	// #3
    8020a290:	17ffff30 	b	80209f50 <__loadlocale+0x270>
    8020a294:	394207e0 	ldrb	w0, [sp, #129]
    8020a298:	121a7800 	and	w0, w0, #0xffffffdf
    8020a29c:	12001c00 	and	w0, w0, #0xff
    8020a2a0:	7101401f 	cmp	w0, #0x50
    8020a2a4:	54ffdca1 	b.ne	80209e38 <__loadlocale+0x158>  // b.any
    8020a2a8:	d2800042 	mov	x2, #0x2                   	// #2
    8020a2ac:	aa1503e0 	mov	x0, x21
    8020a2b0:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a2b4:	91330021 	add	x1, x1, #0xcc0
    8020a2b8:	94000d0a 	bl	8020d6e0 <strncpy>
    8020a2bc:	9101e3e1 	add	x1, sp, #0x78
    8020a2c0:	91020be0 	add	x0, sp, #0x82
    8020a2c4:	52800142 	mov	w2, #0xa                   	// #10
    8020a2c8:	94000c8a 	bl	8020d4f0 <strtol>
    8020a2cc:	f9403fe1 	ldr	x1, [sp, #120]
    8020a2d0:	39400021 	ldrb	w1, [x1]
    8020a2d4:	35ffdb21 	cbnz	w1, 80209e38 <__loadlocale+0x158>
    8020a2d8:	f10e901f 	cmp	x0, #0x3a4
    8020a2dc:	54fff760 	b.eq	8020a1c8 <__loadlocale+0x4e8>  // b.none
    8020a2e0:	54000b6c 	b.gt	8020a44c <__loadlocale+0x76c>
    8020a2e4:	f10d881f 	cmp	x0, #0x362
    8020a2e8:	54000bec 	b.gt	8020a464 <__loadlocale+0x784>
    8020a2ec:	f10d441f 	cmp	x0, #0x351
    8020a2f0:	54ffd9ac 	b.gt	80209e24 <__loadlocale+0x144>
    8020a2f4:	f106d41f 	cmp	x0, #0x1b5
    8020a2f8:	54ffe640 	b.eq	80209fc0 <__loadlocale+0x2e0>  // b.none
    8020a2fc:	d10b4000 	sub	x0, x0, #0x2d0
    8020a300:	f100dc1f 	cmp	x0, #0x37
    8020a304:	54ffd9a8 	b.hi	80209e38 <__loadlocale+0x158>  // b.pmore
    8020a308:	d2800021 	mov	x1, #0x1                   	// #1
    8020a30c:	f2a00041 	movk	x1, #0x2, lsl #16
    8020a310:	f2e01001 	movk	x1, #0x80, lsl #48
    8020a314:	9ac02420 	lsr	x0, x1, x0
    8020a318:	3707e540 	tbnz	w0, #0, 80209fc0 <__loadlocale+0x2e0>
    8020a31c:	17fffec7 	b	80209e38 <__loadlocale+0x158>
    8020a320:	d000003b 	adrp	x27, 80210000 <_wcsnrtombs_l+0x110>
    8020a324:	9130a37b 	add	x27, x27, #0xc28
    8020a328:	aa1b03e1 	mov	x1, x27
    8020a32c:	aa1503e0 	mov	x0, x21
    8020a330:	94001274 	bl	8020ed00 <strcasecmp>
    8020a334:	35ffd820 	cbnz	w0, 80209e38 <__loadlocale+0x158>
    8020a338:	aa1b03e1 	mov	x1, x27
    8020a33c:	aa1503e0 	mov	x0, x21
    8020a340:	94000e00 	bl	8020db40 <strcpy>
    8020a344:	17ffff1f 	b	80209fc0 <__loadlocale+0x2e0>
    8020a348:	aa1503e1 	mov	x1, x21
    8020a34c:	91058ac0 	add	x0, x22, #0x162
    8020a350:	f90037e2 	str	x2, [sp, #104]
    8020a354:	94000dfb 	bl	8020db40 <strcpy>
    8020a358:	f94037e2 	ldr	x2, [sp, #104]
    8020a35c:	a90e6ec2 	stp	x2, x27, [x22, #224]
    8020a360:	aa1503e1 	mov	x1, x21
    8020a364:	390582dc 	strb	w28, [x22, #352]
    8020a368:	aa1603e0 	mov	x0, x22
    8020a36c:	9400083d 	bl	8020c460 <__set_ctype>
    8020a370:	35000138 	cbnz	w24, 8020a394 <__loadlocale+0x6b4>
    8020a374:	7100079f 	cmp	w28, #0x1
    8020a378:	52000339 	eor	w25, w25, #0x1
    8020a37c:	1a9fd7e0 	cset	w0, gt
    8020a380:	6a00033f 	tst	w25, w0
    8020a384:	54000080 	b.eq	8020a394 <__loadlocale+0x6b4>  // b.none
    8020a388:	394203e0 	ldrb	w0, [sp, #128]
    8020a38c:	7101541f 	cmp	w0, #0x55
    8020a390:	1a9f07f8 	cset	w24, ne	// ne = any
    8020a394:	7100035f 	cmp	w26, #0x0
    8020a398:	5a9f0318 	csinv	w24, w24, wzr, eq	// eq = none
    8020a39c:	b900f2d8 	str	w24, [x22, #240]
    8020a3a0:	17fffef3 	b	80209f6c <__loadlocale+0x28c>
    8020a3a4:	91000718 	add	x24, x24, #0x1
    8020a3a8:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020a3ac:	17fffebc 	b	80209e9c <__loadlocale+0x1bc>
    8020a3b0:	a90573fb 	stp	x27, x28, [sp, #80]
    8020a3b4:	9100071b 	add	x27, x24, #0x1
    8020a3b8:	aa1b03e0 	mov	x0, x27
    8020a3bc:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a3c0:	52800018 	mov	w24, #0x0                   	// #0
    8020a3c4:	91310021 	add	x1, x1, #0xc40
    8020a3c8:	5280003a 	mov	w26, #0x1                   	// #1
    8020a3cc:	94000d8d 	bl	8020da00 <strcmp>
    8020a3d0:	2a0003f9 	mov	w25, w0
    8020a3d4:	35000060 	cbnz	w0, 8020a3e0 <__loadlocale+0x700>
    8020a3d8:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020a3dc:	17fffe87 	b	80209df8 <__loadlocale+0x118>
    8020a3e0:	aa1b03e0 	mov	x0, x27
    8020a3e4:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a3e8:	5280001a 	mov	w26, #0x0                   	// #0
    8020a3ec:	91314021 	add	x1, x1, #0xc50
    8020a3f0:	52800039 	mov	w25, #0x1                   	// #1
    8020a3f4:	94000d83 	bl	8020da00 <strcmp>
    8020a3f8:	2a0003f8 	mov	w24, w0
    8020a3fc:	34fffee0 	cbz	w0, 8020a3d8 <__loadlocale+0x6f8>
    8020a400:	aa1b03e0 	mov	x0, x27
    8020a404:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a408:	91318021 	add	x1, x1, #0xc60
    8020a40c:	94000d7d 	bl	8020da00 <strcmp>
    8020a410:	7100001f 	cmp	w0, #0x0
    8020a414:	52800019 	mov	w25, #0x0                   	// #0
    8020a418:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020a41c:	1a9f17f8 	cset	w24, eq	// eq = none
    8020a420:	17fffe76 	b	80209df8 <__loadlocale+0x118>
    8020a424:	aa1503e0 	mov	x0, x21
    8020a428:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a42c:	91336021 	add	x1, x1, #0xcd8
    8020a430:	94000dc4 	bl	8020db40 <strcpy>
    8020a434:	17fffee3 	b	80209fc0 <__loadlocale+0x2e0>
    8020a438:	aa1503e0 	mov	x0, x21
    8020a43c:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a440:	91338021 	add	x1, x1, #0xce0
    8020a444:	94000dbf 	bl	8020db40 <strcpy>
    8020a448:	17fffede 	b	80209fc0 <__loadlocale+0x2e0>
    8020a44c:	f111941f 	cmp	x0, #0x465
    8020a450:	54ffdb80 	b.eq	80209fc0 <__loadlocale+0x2e0>  // b.none
    8020a454:	d1138800 	sub	x0, x0, #0x4e2
    8020a458:	f100201f 	cmp	x0, #0x8
    8020a45c:	54ffdb29 	b.ls	80209fc0 <__loadlocale+0x2e0>  // b.plast
    8020a460:	17fffe76 	b	80209e38 <__loadlocale+0x158>
    8020a464:	f10da81f 	cmp	x0, #0x36a
    8020a468:	54ffce81 	b.ne	80209e38 <__loadlocale+0x158>  // b.any
    8020a46c:	17fffed5 	b	80209fc0 <__loadlocale+0x2e0>

000000008020a470 <__get_locale_env>:
    8020a470:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020a474:	910003fd 	mov	x29, sp
    8020a478:	a90153f3 	stp	x19, x20, [sp, #16]
    8020a47c:	2a0103f4 	mov	w20, w1
    8020a480:	aa0003f3 	mov	x19, x0
    8020a484:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a488:	9134c021 	add	x1, x1, #0xd30
    8020a48c:	94000c8d 	bl	8020d6c0 <_getenv_r>
    8020a490:	b4000060 	cbz	x0, 8020a49c <__get_locale_env+0x2c>
    8020a494:	39400001 	ldrb	w1, [x0]
    8020a498:	35000241 	cbnz	w1, 8020a4e0 <__get_locale_env+0x70>
    8020a49c:	f0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020a4a0:	910b0021 	add	x1, x1, #0x2c0
    8020a4a4:	aa1303e0 	mov	x0, x19
    8020a4a8:	f874d821 	ldr	x1, [x1, w20, sxtw #3]
    8020a4ac:	94000c85 	bl	8020d6c0 <_getenv_r>
    8020a4b0:	b4000060 	cbz	x0, 8020a4bc <__get_locale_env+0x4c>
    8020a4b4:	39400001 	ldrb	w1, [x0]
    8020a4b8:	35000141 	cbnz	w1, 8020a4e0 <__get_locale_env+0x70>
    8020a4bc:	d0000021 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020a4c0:	aa1303e0 	mov	x0, x19
    8020a4c4:	9134e021 	add	x1, x1, #0xd38
    8020a4c8:	94000c7e 	bl	8020d6c0 <_getenv_r>
    8020a4cc:	b4000060 	cbz	x0, 8020a4d8 <__get_locale_env+0x68>
    8020a4d0:	39400001 	ldrb	w1, [x0]
    8020a4d4:	35000061 	cbnz	w1, 8020a4e0 <__get_locale_env+0x70>
    8020a4d8:	90000040 	adrp	x0, 80212000 <__malloc_av_+0x760>
    8020a4dc:	910d4000 	add	x0, x0, #0x350
    8020a4e0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a4e4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020a4e8:	d65f03c0 	ret
    8020a4ec:	00000000 	udf	#0

000000008020a4f0 <_setlocale_r>:
    8020a4f0:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    8020a4f4:	910003fd 	mov	x29, sp
    8020a4f8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020a4fc:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020a500:	a90363f7 	stp	x23, x24, [sp, #48]
    8020a504:	aa0003f7 	mov	x23, x0
    8020a508:	7100183f 	cmp	w1, #0x6
    8020a50c:	54000c28 	b.hi	8020a690 <_setlocale_r+0x1a0>  // b.pmore
    8020a510:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020a514:	aa0203f9 	mov	x25, x2
    8020a518:	f9002bfb 	str	x27, [sp, #80]
    8020a51c:	2a0103fb 	mov	w27, w1
    8020a520:	b4001142 	cbz	x2, 8020a748 <_setlocale_r+0x258>
    8020a524:	f00003b6 	adrp	x22, 80281000 <__sf+0x38>
    8020a528:	90000055 	adrp	x21, 80212000 <__malloc_av_+0x760>
    8020a52c:	910e02d6 	add	x22, x22, #0x380
    8020a530:	910702b5 	add	x21, x21, #0x1c0
    8020a534:	f00003b8 	adrp	x24, 80281000 <__sf+0x38>
    8020a538:	910d8318 	add	x24, x24, #0x360
    8020a53c:	aa1603f3 	mov	x19, x22
    8020a540:	aa1503f4 	mov	x20, x21
    8020a544:	9103831a 	add	x26, x24, #0xe0
    8020a548:	aa1403e1 	mov	x1, x20
    8020a54c:	aa1303e0 	mov	x0, x19
    8020a550:	91008273 	add	x19, x19, #0x20
    8020a554:	94000d7b 	bl	8020db40 <strcpy>
    8020a558:	91008294 	add	x20, x20, #0x20
    8020a55c:	eb13035f 	cmp	x26, x19
    8020a560:	54ffff41 	b.ne	8020a548 <_setlocale_r+0x58>  // b.any
    8020a564:	39400320 	ldrb	w0, [x25]
    8020a568:	350005e0 	cbnz	w0, 8020a624 <_setlocale_r+0x134>
    8020a56c:	350010fb 	cbnz	w27, 8020a788 <_setlocale_r+0x298>
    8020a570:	aa1603f8 	mov	x24, x22
    8020a574:	52800033 	mov	w19, #0x1                   	// #1
    8020a578:	2a1303e1 	mov	w1, w19
    8020a57c:	aa1703e0 	mov	x0, x23
    8020a580:	97ffffbc 	bl	8020a470 <__get_locale_env>
    8020a584:	aa0003f4 	mov	x20, x0
    8020a588:	97ffe4de 	bl	80203900 <strlen>
    8020a58c:	aa0003e2 	mov	x2, x0
    8020a590:	aa1403e1 	mov	x1, x20
    8020a594:	aa1803e0 	mov	x0, x24
    8020a598:	f1007c5f 	cmp	x2, #0x1f
    8020a59c:	54000768 	b.hi	8020a688 <_setlocale_r+0x198>  // b.pmore
    8020a5a0:	11000673 	add	w19, w19, #0x1
    8020a5a4:	94000d67 	bl	8020db40 <strcpy>
    8020a5a8:	91008318 	add	x24, x24, #0x20
    8020a5ac:	71001e7f 	cmp	w19, #0x7
    8020a5b0:	54fffe41 	b.ne	8020a578 <_setlocale_r+0x88>  // b.any
    8020a5b4:	f00003ba 	adrp	x26, 80281000 <__sf+0x38>
    8020a5b8:	910a835a 	add	x26, x26, #0x2a0
    8020a5bc:	90000059 	adrp	x25, 80212000 <__malloc_av_+0x760>
    8020a5c0:	aa1a03f8 	mov	x24, x26
    8020a5c4:	aa1603f4 	mov	x20, x22
    8020a5c8:	91068339 	add	x25, x25, #0x1a0
    8020a5cc:	52800033 	mov	w19, #0x1                   	// #1
    8020a5d0:	aa1503e1 	mov	x1, x21
    8020a5d4:	aa1803e0 	mov	x0, x24
    8020a5d8:	94000d5a 	bl	8020db40 <strcpy>
    8020a5dc:	aa1403e2 	mov	x2, x20
    8020a5e0:	2a1303e1 	mov	w1, w19
    8020a5e4:	aa1903e0 	mov	x0, x25
    8020a5e8:	97fffdbe 	bl	80209ce0 <__loadlocale>
    8020a5ec:	b4000e80 	cbz	x0, 8020a7bc <_setlocale_r+0x2cc>
    8020a5f0:	11000673 	add	w19, w19, #0x1
    8020a5f4:	91008318 	add	x24, x24, #0x20
    8020a5f8:	910082b5 	add	x21, x21, #0x20
    8020a5fc:	91008294 	add	x20, x20, #0x20
    8020a600:	71001e7f 	cmp	w19, #0x7
    8020a604:	54fffe61 	b.ne	8020a5d0 <_setlocale_r+0xe0>  // b.any
    8020a608:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a60c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020a610:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020a614:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020a618:	f9402bfb 	ldr	x27, [sp, #80]
    8020a61c:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020a620:	17fffd7c 	b	80209c10 <currentlocale>
    8020a624:	340003fb 	cbz	w27, 8020a6a0 <_setlocale_r+0x1b0>
    8020a628:	aa1903e0 	mov	x0, x25
    8020a62c:	97ffe4b5 	bl	80203900 <strlen>
    8020a630:	f1007c1f 	cmp	x0, #0x1f
    8020a634:	540002a8 	b.hi	8020a688 <_setlocale_r+0x198>  // b.pmore
    8020a638:	937b7f73 	sbfiz	x19, x27, #5, #32
    8020a63c:	aa1903e1 	mov	x1, x25
    8020a640:	8b130313 	add	x19, x24, x19
    8020a644:	aa1303e0 	mov	x0, x19
    8020a648:	94000d3e 	bl	8020db40 <strcpy>
    8020a64c:	aa1303e2 	mov	x2, x19
    8020a650:	2a1b03e1 	mov	w1, w27
    8020a654:	90000040 	adrp	x0, 80212000 <__malloc_av_+0x760>
    8020a658:	91068000 	add	x0, x0, #0x1a0
    8020a65c:	97fffda1 	bl	80209ce0 <__loadlocale>
    8020a660:	aa0003f3 	mov	x19, x0
    8020a664:	97fffd6b 	bl	80209c10 <currentlocale>
    8020a668:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020a66c:	f9402bfb 	ldr	x27, [sp, #80]
    8020a670:	aa1303e0 	mov	x0, x19
    8020a674:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a678:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020a67c:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020a680:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020a684:	d65f03c0 	ret
    8020a688:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020a68c:	f9402bfb 	ldr	x27, [sp, #80]
    8020a690:	528002d5 	mov	w21, #0x16                  	// #22
    8020a694:	d2800013 	mov	x19, #0x0                   	// #0
    8020a698:	b90002f5 	str	w21, [x23]
    8020a69c:	17fffff5 	b	8020a670 <_setlocale_r+0x180>
    8020a6a0:	aa1903e0 	mov	x0, x25
    8020a6a4:	528005e1 	mov	w1, #0x2f                  	// #47
    8020a6a8:	94000c96 	bl	8020d900 <strchr>
    8020a6ac:	aa0003f3 	mov	x19, x0
    8020a6b0:	b5000060 	cbnz	x0, 8020a6bc <_setlocale_r+0x1cc>
    8020a6b4:	14000061 	b	8020a838 <_setlocale_r+0x348>
    8020a6b8:	91000673 	add	x19, x19, #0x1
    8020a6bc:	39400660 	ldrb	w0, [x19, #1]
    8020a6c0:	7100bc1f 	cmp	w0, #0x2f
    8020a6c4:	54ffffa0 	b.eq	8020a6b8 <_setlocale_r+0x1c8>  // b.none
    8020a6c8:	34fffe00 	cbz	w0, 8020a688 <_setlocale_r+0x198>
    8020a6cc:	aa1603fa 	mov	x26, x22
    8020a6d0:	52800034 	mov	w20, #0x1                   	// #1
    8020a6d4:	cb190262 	sub	x2, x19, x25
    8020a6d8:	71007c5f 	cmp	w2, #0x1f
    8020a6dc:	54fffd6c 	b.gt	8020a688 <_setlocale_r+0x198>
    8020a6e0:	11000442 	add	w2, w2, #0x1
    8020a6e4:	aa1903e1 	mov	x1, x25
    8020a6e8:	aa1a03e0 	mov	x0, x26
    8020a6ec:	11000694 	add	w20, w20, #0x1
    8020a6f0:	93407c42 	sxtw	x2, w2
    8020a6f4:	940009eb 	bl	8020cea0 <strlcpy>
    8020a6f8:	39400261 	ldrb	w1, [x19]
    8020a6fc:	7100bc3f 	cmp	w1, #0x2f
    8020a700:	540000a1 	b.ne	8020a714 <_setlocale_r+0x224>  // b.any
    8020a704:	d503201f 	nop
    8020a708:	38401e61 	ldrb	w1, [x19, #1]!
    8020a70c:	7100bc3f 	cmp	w1, #0x2f
    8020a710:	54ffffc0 	b.eq	8020a708 <_setlocale_r+0x218>  // b.none
    8020a714:	34000ac1 	cbz	w1, 8020a86c <_setlocale_r+0x37c>
    8020a718:	aa1303e3 	mov	x3, x19
    8020a71c:	d503201f 	nop
    8020a720:	38401c61 	ldrb	w1, [x3, #1]!
    8020a724:	7100bc3f 	cmp	w1, #0x2f
    8020a728:	7a401824 	ccmp	w1, #0x0, #0x4, ne	// ne = any
    8020a72c:	54ffffa1 	b.ne	8020a720 <_setlocale_r+0x230>  // b.any
    8020a730:	9100835a 	add	x26, x26, #0x20
    8020a734:	71001e9f 	cmp	w20, #0x7
    8020a738:	54fff3e0 	b.eq	8020a5b4 <_setlocale_r+0xc4>  // b.none
    8020a73c:	aa1303f9 	mov	x25, x19
    8020a740:	aa0303f3 	mov	x19, x3
    8020a744:	17ffffe4 	b	8020a6d4 <_setlocale_r+0x1e4>
    8020a748:	937b7c20 	sbfiz	x0, x1, #5, #32
    8020a74c:	90000041 	adrp	x1, 80212000 <__malloc_av_+0x760>
    8020a750:	91068021 	add	x1, x1, #0x1a0
    8020a754:	7100037f 	cmp	w27, #0x0
    8020a758:	8b010000 	add	x0, x0, x1
    8020a75c:	90000053 	adrp	x19, 80212000 <__malloc_av_+0x760>
    8020a760:	9102c273 	add	x19, x19, #0xb0
    8020a764:	9a800273 	csel	x19, x19, x0, eq	// eq = none
    8020a768:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020a76c:	aa1303e0 	mov	x0, x19
    8020a770:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a774:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020a778:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020a77c:	f9402bfb 	ldr	x27, [sp, #80]
    8020a780:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020a784:	d65f03c0 	ret
    8020a788:	2a1b03e1 	mov	w1, w27
    8020a78c:	aa1703e0 	mov	x0, x23
    8020a790:	97ffff38 	bl	8020a470 <__get_locale_env>
    8020a794:	aa0003f4 	mov	x20, x0
    8020a798:	97ffe45a 	bl	80203900 <strlen>
    8020a79c:	f1007c1f 	cmp	x0, #0x1f
    8020a7a0:	54fff748 	b.hi	8020a688 <_setlocale_r+0x198>  // b.pmore
    8020a7a4:	937b7f73 	sbfiz	x19, x27, #5, #32
    8020a7a8:	aa1403e1 	mov	x1, x20
    8020a7ac:	8b130313 	add	x19, x24, x19
    8020a7b0:	aa1303e0 	mov	x0, x19
    8020a7b4:	94000ce3 	bl	8020db40 <strcpy>
    8020a7b8:	17ffffa5 	b	8020a64c <_setlocale_r+0x15c>
    8020a7bc:	d0000020 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020a7c0:	b94002f5 	ldr	w21, [x23]
    8020a7c4:	91308018 	add	x24, x0, #0xc20
    8020a7c8:	52800034 	mov	w20, #0x1                   	// #1
    8020a7cc:	6b14027f 	cmp	w19, w20
    8020a7d0:	540000e1 	b.ne	8020a7ec <_setlocale_r+0x2fc>  // b.any
    8020a7d4:	14000016 	b	8020a82c <_setlocale_r+0x33c>
    8020a7d8:	11000694 	add	w20, w20, #0x1
    8020a7dc:	910082d6 	add	x22, x22, #0x20
    8020a7e0:	9100835a 	add	x26, x26, #0x20
    8020a7e4:	6b13029f 	cmp	w20, w19
    8020a7e8:	54000220 	b.eq	8020a82c <_setlocale_r+0x33c>  // b.none
    8020a7ec:	aa1a03e1 	mov	x1, x26
    8020a7f0:	aa1603e0 	mov	x0, x22
    8020a7f4:	94000cd3 	bl	8020db40 <strcpy>
    8020a7f8:	aa1603e2 	mov	x2, x22
    8020a7fc:	2a1403e1 	mov	w1, w20
    8020a800:	aa1903e0 	mov	x0, x25
    8020a804:	97fffd37 	bl	80209ce0 <__loadlocale>
    8020a808:	b5fffe80 	cbnz	x0, 8020a7d8 <_setlocale_r+0x2e8>
    8020a80c:	aa1803e1 	mov	x1, x24
    8020a810:	aa1603e0 	mov	x0, x22
    8020a814:	94000ccb 	bl	8020db40 <strcpy>
    8020a818:	aa1603e2 	mov	x2, x22
    8020a81c:	2a1403e1 	mov	w1, w20
    8020a820:	aa1903e0 	mov	x0, x25
    8020a824:	97fffd2f 	bl	80209ce0 <__loadlocale>
    8020a828:	17ffffec 	b	8020a7d8 <_setlocale_r+0x2e8>
    8020a82c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020a830:	f9402bfb 	ldr	x27, [sp, #80]
    8020a834:	17ffff98 	b	8020a694 <_setlocale_r+0x1a4>
    8020a838:	aa1903e0 	mov	x0, x25
    8020a83c:	97ffe431 	bl	80203900 <strlen>
    8020a840:	f1007c1f 	cmp	x0, #0x1f
    8020a844:	54fff228 	b.hi	8020a688 <_setlocale_r+0x198>  // b.pmore
    8020a848:	aa1603f3 	mov	x19, x22
    8020a84c:	d503201f 	nop
    8020a850:	aa1303e0 	mov	x0, x19
    8020a854:	aa1903e1 	mov	x1, x25
    8020a858:	91008273 	add	x19, x19, #0x20
    8020a85c:	94000cb9 	bl	8020db40 <strcpy>
    8020a860:	eb13035f 	cmp	x26, x19
    8020a864:	54ffff61 	b.ne	8020a850 <_setlocale_r+0x360>  // b.any
    8020a868:	17ffff53 	b	8020a5b4 <_setlocale_r+0xc4>
    8020a86c:	71001e9f 	cmp	w20, #0x7
    8020a870:	54ffea20 	b.eq	8020a5b4 <_setlocale_r+0xc4>  // b.none
    8020a874:	937b7e93 	sbfiz	x19, x20, #5, #32
    8020a878:	8b130313 	add	x19, x24, x19
    8020a87c:	d503201f 	nop
    8020a880:	d1008261 	sub	x1, x19, #0x20
    8020a884:	aa1303e0 	mov	x0, x19
    8020a888:	11000694 	add	w20, w20, #0x1
    8020a88c:	94000cad 	bl	8020db40 <strcpy>
    8020a890:	91008273 	add	x19, x19, #0x20
    8020a894:	71001e9f 	cmp	w20, #0x7
    8020a898:	54ffff41 	b.ne	8020a880 <_setlocale_r+0x390>  // b.any
    8020a89c:	17ffff46 	b	8020a5b4 <_setlocale_r+0xc4>

000000008020a8a0 <__locale_mb_cur_max>:
    8020a8a0:	90000040 	adrp	x0, 80212000 <__malloc_av_+0x760>
    8020a8a4:	394c0000 	ldrb	w0, [x0, #768]
    8020a8a8:	d65f03c0 	ret
    8020a8ac:	00000000 	udf	#0

000000008020a8b0 <setlocale>:
    8020a8b0:	f0000023 	adrp	x3, 80211000 <blanks.1+0x60>
    8020a8b4:	aa0103e2 	mov	x2, x1
    8020a8b8:	2a0003e1 	mov	w1, w0
    8020a8bc:	f9438860 	ldr	x0, [x3, #1808]
    8020a8c0:	17ffff0c 	b	8020a4f0 <_setlocale_r>
	...

000000008020a8d0 <__localeconv_l>:
    8020a8d0:	91040000 	add	x0, x0, #0x100
    8020a8d4:	d65f03c0 	ret
	...

000000008020a8e0 <_localeconv_r>:
    8020a8e0:	90000040 	adrp	x0, 80212000 <__malloc_av_+0x760>
    8020a8e4:	910a8000 	add	x0, x0, #0x2a0
    8020a8e8:	d65f03c0 	ret
    8020a8ec:	00000000 	udf	#0

000000008020a8f0 <localeconv>:
    8020a8f0:	90000040 	adrp	x0, 80212000 <__malloc_av_+0x760>
    8020a8f4:	910a8000 	add	x0, x0, #0x2a0
    8020a8f8:	d65f03c0 	ret
    8020a8fc:	00000000 	udf	#0

000000008020a900 <_fclose_r>:
    8020a900:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020a904:	910003fd 	mov	x29, sp
    8020a908:	f90013f5 	str	x21, [sp, #32]
    8020a90c:	b4000661 	cbz	x1, 8020a9d8 <_fclose_r+0xd8>
    8020a910:	a90153f3 	stp	x19, x20, [sp, #16]
    8020a914:	aa0103f3 	mov	x19, x1
    8020a918:	aa0003f4 	mov	x20, x0
    8020a91c:	b4000060 	cbz	x0, 8020a928 <_fclose_r+0x28>
    8020a920:	f9402401 	ldr	x1, [x0, #72]
    8020a924:	b4000641 	cbz	x1, 8020a9ec <_fclose_r+0xec>
    8020a928:	b940b260 	ldr	w0, [x19, #176]
    8020a92c:	79c02261 	ldrsh	w1, [x19, #16]
    8020a930:	37000500 	tbnz	w0, #0, 8020a9d0 <_fclose_r+0xd0>
    8020a934:	36480601 	tbz	w1, #9, 8020a9f4 <_fclose_r+0xf4>
    8020a938:	aa1303e1 	mov	x1, x19
    8020a93c:	aa1403e0 	mov	x0, x20
    8020a940:	9400070c 	bl	8020c570 <__sflush_r>
    8020a944:	2a0003f5 	mov	w21, w0
    8020a948:	f9402a62 	ldr	x2, [x19, #80]
    8020a94c:	b40000c2 	cbz	x2, 8020a964 <_fclose_r+0x64>
    8020a950:	f9401a61 	ldr	x1, [x19, #48]
    8020a954:	aa1403e0 	mov	x0, x20
    8020a958:	d63f0040 	blr	x2
    8020a95c:	7100001f 	cmp	w0, #0x0
    8020a960:	5a9fa2b5 	csinv	w21, w21, wzr, ge	// ge = tcont
    8020a964:	79402260 	ldrh	w0, [x19, #16]
    8020a968:	37380620 	tbnz	w0, #7, 8020aa2c <_fclose_r+0x12c>
    8020a96c:	f9402e61 	ldr	x1, [x19, #88]
    8020a970:	b40000e1 	cbz	x1, 8020a98c <_fclose_r+0x8c>
    8020a974:	9101d260 	add	x0, x19, #0x74
    8020a978:	eb00003f 	cmp	x1, x0
    8020a97c:	54000060 	b.eq	8020a988 <_fclose_r+0x88>  // b.none
    8020a980:	aa1403e0 	mov	x0, x20
    8020a984:	9400099f 	bl	8020d000 <_free_r>
    8020a988:	f9002e7f 	str	xzr, [x19, #88]
    8020a98c:	f9403e61 	ldr	x1, [x19, #120]
    8020a990:	b4000081 	cbz	x1, 8020a9a0 <_fclose_r+0xa0>
    8020a994:	aa1403e0 	mov	x0, x20
    8020a998:	9400099a 	bl	8020d000 <_free_r>
    8020a99c:	f9003e7f 	str	xzr, [x19, #120]
    8020a9a0:	97ffe328 	bl	80203640 <__sfp_lock_acquire>
    8020a9a4:	7900227f 	strh	wzr, [x19, #16]
    8020a9a8:	b940b260 	ldr	w0, [x19, #176]
    8020a9ac:	360003a0 	tbz	w0, #0, 8020aa20 <_fclose_r+0x120>
    8020a9b0:	f9405260 	ldr	x0, [x19, #160]
    8020a9b4:	97fffc7b 	bl	80209ba0 <__retarget_lock_close_recursive>
    8020a9b8:	97ffe326 	bl	80203650 <__sfp_lock_release>
    8020a9bc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a9c0:	2a1503e0 	mov	w0, w21
    8020a9c4:	f94013f5 	ldr	x21, [sp, #32]
    8020a9c8:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020a9cc:	d65f03c0 	ret
    8020a9d0:	35fffb41 	cbnz	w1, 8020a938 <_fclose_r+0x38>
    8020a9d4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020a9d8:	52800015 	mov	w21, #0x0                   	// #0
    8020a9dc:	2a1503e0 	mov	w0, w21
    8020a9e0:	f94013f5 	ldr	x21, [sp, #32]
    8020a9e4:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020a9e8:	d65f03c0 	ret
    8020a9ec:	97ffe2f9 	bl	802035d0 <__sinit>
    8020a9f0:	17ffffce 	b	8020a928 <_fclose_r+0x28>
    8020a9f4:	f9405260 	ldr	x0, [x19, #160]
    8020a9f8:	97fffc72 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    8020a9fc:	79c02260 	ldrsh	w0, [x19, #16]
    8020aa00:	35fff9c0 	cbnz	w0, 8020a938 <_fclose_r+0x38>
    8020aa04:	b940b260 	ldr	w0, [x19, #176]
    8020aa08:	3707fe60 	tbnz	w0, #0, 8020a9d4 <_fclose_r+0xd4>
    8020aa0c:	f9405260 	ldr	x0, [x19, #160]
    8020aa10:	52800015 	mov	w21, #0x0                   	// #0
    8020aa14:	97fffc7b 	bl	80209c00 <__retarget_lock_release_recursive>
    8020aa18:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020aa1c:	17fffff0 	b	8020a9dc <_fclose_r+0xdc>
    8020aa20:	f9405260 	ldr	x0, [x19, #160]
    8020aa24:	97fffc77 	bl	80209c00 <__retarget_lock_release_recursive>
    8020aa28:	17ffffe2 	b	8020a9b0 <_fclose_r+0xb0>
    8020aa2c:	f9400e61 	ldr	x1, [x19, #24]
    8020aa30:	aa1403e0 	mov	x0, x20
    8020aa34:	94000973 	bl	8020d000 <_free_r>
    8020aa38:	17ffffcd 	b	8020a96c <_fclose_r+0x6c>
    8020aa3c:	00000000 	udf	#0

000000008020aa40 <fclose>:
    8020aa40:	f0000022 	adrp	x2, 80211000 <blanks.1+0x60>
    8020aa44:	aa0003e1 	mov	x1, x0
    8020aa48:	f9438840 	ldr	x0, [x2, #1808]
    8020aa4c:	17ffffad 	b	8020a900 <_fclose_r>
	...

000000008020aa80 <memchr>:
    8020aa80:	d503245f 	bti	c
    8020aa84:	b4000682 	cbz	x2, 8020ab54 <memchr+0xd4>
    8020aa88:	52808025 	mov	w5, #0x401                 	// #1025
    8020aa8c:	72a80205 	movk	w5, #0x4010, lsl #16
    8020aa90:	4e010c20 	dup	v0.16b, w1
    8020aa94:	927be803 	and	x3, x0, #0xffffffffffffffe0
    8020aa98:	4e040ca5 	dup	v5.4s, w5
    8020aa9c:	f2401009 	ands	x9, x0, #0x1f
    8020aaa0:	9240104a 	and	x10, x2, #0x1f
    8020aaa4:	54000200 	b.eq	8020aae4 <memchr+0x64>  // b.none
    8020aaa8:	4cdfa061 	ld1	{v1.16b-v2.16b}, [x3], #32
    8020aaac:	d1008124 	sub	x4, x9, #0x20
    8020aab0:	ab040042 	adds	x2, x2, x4
    8020aab4:	6e208c23 	cmeq	v3.16b, v1.16b, v0.16b
    8020aab8:	6e208c44 	cmeq	v4.16b, v2.16b, v0.16b
    8020aabc:	4e251c63 	and	v3.16b, v3.16b, v5.16b
    8020aac0:	4e251c84 	and	v4.16b, v4.16b, v5.16b
    8020aac4:	4e24bc66 	addp	v6.16b, v3.16b, v4.16b
    8020aac8:	4e26bcc6 	addp	v6.16b, v6.16b, v6.16b
    8020aacc:	4e083cc6 	mov	x6, v6.d[0]
    8020aad0:	d37ff924 	lsl	x4, x9, #1
    8020aad4:	9ac424c6 	lsr	x6, x6, x4
    8020aad8:	9ac420c6 	lsl	x6, x6, x4
    8020aadc:	54000229 	b.ls	8020ab20 <memchr+0xa0>  // b.plast
    8020aae0:	b50002c6 	cbnz	x6, 8020ab38 <memchr+0xb8>
    8020aae4:	4cdfa061 	ld1	{v1.16b-v2.16b}, [x3], #32
    8020aae8:	f1008042 	subs	x2, x2, #0x20
    8020aaec:	6e208c23 	cmeq	v3.16b, v1.16b, v0.16b
    8020aaf0:	6e208c44 	cmeq	v4.16b, v2.16b, v0.16b
    8020aaf4:	540000a9 	b.ls	8020ab08 <memchr+0x88>  // b.plast
    8020aaf8:	4ea41c66 	orr	v6.16b, v3.16b, v4.16b
    8020aafc:	4ee6bcc6 	addp	v6.2d, v6.2d, v6.2d
    8020ab00:	4e083cc6 	mov	x6, v6.d[0]
    8020ab04:	b4ffff06 	cbz	x6, 8020aae4 <memchr+0x64>
    8020ab08:	4e251c63 	and	v3.16b, v3.16b, v5.16b
    8020ab0c:	4e251c84 	and	v4.16b, v4.16b, v5.16b
    8020ab10:	4e24bc66 	addp	v6.16b, v3.16b, v4.16b
    8020ab14:	4e26bcc6 	addp	v6.16b, v6.16b, v6.16b
    8020ab18:	4e083cc6 	mov	x6, v6.d[0]
    8020ab1c:	540000e2 	b.cs	8020ab38 <memchr+0xb8>  // b.hs, b.nlast
    8020ab20:	8b090144 	add	x4, x10, x9
    8020ab24:	92401084 	and	x4, x4, #0x1f
    8020ab28:	d1008084 	sub	x4, x4, #0x20
    8020ab2c:	cb0407e4 	neg	x4, x4, lsl #1
    8020ab30:	9ac420c6 	lsl	x6, x6, x4
    8020ab34:	9ac424c6 	lsr	x6, x6, x4
    8020ab38:	dac000c6 	rbit	x6, x6
    8020ab3c:	d1008063 	sub	x3, x3, #0x20
    8020ab40:	f10000df 	cmp	x6, #0x0
    8020ab44:	dac010c6 	clz	x6, x6
    8020ab48:	8b460460 	add	x0, x3, x6, lsr #1
    8020ab4c:	9a8003e0 	csel	x0, xzr, x0, eq	// eq = none
    8020ab50:	d65f03c0 	ret
    8020ab54:	d2800000 	mov	x0, #0x0                   	// #0
    8020ab58:	d65f03c0 	ret
    8020ab5c:	00000000 	udf	#0

000000008020ab60 <__swsetup_r>:
    8020ab60:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020ab64:	f0000022 	adrp	x2, 80211000 <blanks.1+0x60>
    8020ab68:	910003fd 	mov	x29, sp
    8020ab6c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020ab70:	aa0003f4 	mov	x20, x0
    8020ab74:	aa0103f3 	mov	x19, x1
    8020ab78:	f9438840 	ldr	x0, [x2, #1808]
    8020ab7c:	b4000060 	cbz	x0, 8020ab88 <__swsetup_r+0x28>
    8020ab80:	f9402401 	ldr	x1, [x0, #72]
    8020ab84:	b4000761 	cbz	x1, 8020ac70 <__swsetup_r+0x110>
    8020ab88:	79c02262 	ldrsh	w2, [x19, #16]
    8020ab8c:	36180462 	tbz	w2, #3, 8020ac18 <__swsetup_r+0xb8>
    8020ab90:	f9400e61 	ldr	x1, [x19, #24]
    8020ab94:	b40002c1 	cbz	x1, 8020abec <__swsetup_r+0x8c>
    8020ab98:	36000142 	tbz	w2, #0, 8020abc0 <__swsetup_r+0x60>
    8020ab9c:	b9402260 	ldr	w0, [x19, #32]
    8020aba0:	b9000e7f 	str	wzr, [x19, #12]
    8020aba4:	4b0003e0 	neg	w0, w0
    8020aba8:	b9002a60 	str	w0, [x19, #40]
    8020abac:	52800000 	mov	w0, #0x0                   	// #0
    8020abb0:	b4000141 	cbz	x1, 8020abd8 <__swsetup_r+0x78>
    8020abb4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020abb8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020abbc:	d65f03c0 	ret
    8020abc0:	52800000 	mov	w0, #0x0                   	// #0
    8020abc4:	37080042 	tbnz	w2, #1, 8020abcc <__swsetup_r+0x6c>
    8020abc8:	b9402260 	ldr	w0, [x19, #32]
    8020abcc:	b9000e60 	str	w0, [x19, #12]
    8020abd0:	52800000 	mov	w0, #0x0                   	// #0
    8020abd4:	b5ffff01 	cbnz	x1, 8020abb4 <__swsetup_r+0x54>
    8020abd8:	363ffee2 	tbz	w2, #7, 8020abb4 <__swsetup_r+0x54>
    8020abdc:	321a0042 	orr	w2, w2, #0x40
    8020abe0:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020abe4:	79002262 	strh	w2, [x19, #16]
    8020abe8:	17fffff3 	b	8020abb4 <__swsetup_r+0x54>
    8020abec:	52805000 	mov	w0, #0x280                 	// #640
    8020abf0:	0a000040 	and	w0, w2, w0
    8020abf4:	7108001f 	cmp	w0, #0x200
    8020abf8:	54fffd00 	b.eq	8020ab98 <__swsetup_r+0x38>  // b.none
    8020abfc:	aa1303e1 	mov	x1, x19
    8020ac00:	aa1403e0 	mov	x0, x20
    8020ac04:	94000023 	bl	8020ac90 <__smakebuf_r>
    8020ac08:	79c02262 	ldrsh	w2, [x19, #16]
    8020ac0c:	f9400e61 	ldr	x1, [x19, #24]
    8020ac10:	3607fd82 	tbz	w2, #0, 8020abc0 <__swsetup_r+0x60>
    8020ac14:	17ffffe2 	b	8020ab9c <__swsetup_r+0x3c>
    8020ac18:	36200302 	tbz	w2, #4, 8020ac78 <__swsetup_r+0x118>
    8020ac1c:	371000c2 	tbnz	w2, #2, 8020ac34 <__swsetup_r+0xd4>
    8020ac20:	f9400e61 	ldr	x1, [x19, #24]
    8020ac24:	321d0042 	orr	w2, w2, #0x8
    8020ac28:	79002262 	strh	w2, [x19, #16]
    8020ac2c:	b5fffb61 	cbnz	x1, 8020ab98 <__swsetup_r+0x38>
    8020ac30:	17ffffef 	b	8020abec <__swsetup_r+0x8c>
    8020ac34:	f9402e61 	ldr	x1, [x19, #88]
    8020ac38:	b4000101 	cbz	x1, 8020ac58 <__swsetup_r+0xf8>
    8020ac3c:	9101d260 	add	x0, x19, #0x74
    8020ac40:	eb00003f 	cmp	x1, x0
    8020ac44:	54000080 	b.eq	8020ac54 <__swsetup_r+0xf4>  // b.none
    8020ac48:	aa1403e0 	mov	x0, x20
    8020ac4c:	940008ed 	bl	8020d000 <_free_r>
    8020ac50:	79c02262 	ldrsh	w2, [x19, #16]
    8020ac54:	f9002e7f 	str	xzr, [x19, #88]
    8020ac58:	f9400e61 	ldr	x1, [x19, #24]
    8020ac5c:	12800480 	mov	w0, #0xffffffdb            	// #-37
    8020ac60:	0a000042 	and	w2, w2, w0
    8020ac64:	f9000261 	str	x1, [x19]
    8020ac68:	b9000a7f 	str	wzr, [x19, #8]
    8020ac6c:	17ffffee 	b	8020ac24 <__swsetup_r+0xc4>
    8020ac70:	97ffe258 	bl	802035d0 <__sinit>
    8020ac74:	17ffffc5 	b	8020ab88 <__swsetup_r+0x28>
    8020ac78:	52800120 	mov	w0, #0x9                   	// #9
    8020ac7c:	b9000280 	str	w0, [x20]
    8020ac80:	321a0042 	orr	w2, w2, #0x40
    8020ac84:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020ac88:	79002262 	strh	w2, [x19, #16]
    8020ac8c:	17ffffca 	b	8020abb4 <__swsetup_r+0x54>

000000008020ac90 <__smakebuf_r>:
    8020ac90:	a9b57bfd 	stp	x29, x30, [sp, #-176]!
    8020ac94:	910003fd 	mov	x29, sp
    8020ac98:	79c02022 	ldrsh	w2, [x1, #16]
    8020ac9c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020aca0:	aa0103f3 	mov	x19, x1
    8020aca4:	36080122 	tbz	w2, #1, 8020acc8 <__smakebuf_r+0x38>
    8020aca8:	9101dc20 	add	x0, x1, #0x77
    8020acac:	52800021 	mov	w1, #0x1                   	// #1
    8020acb0:	f9000260 	str	x0, [x19]
    8020acb4:	f9000e60 	str	x0, [x19, #24]
    8020acb8:	b9002261 	str	w1, [x19, #32]
    8020acbc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020acc0:	a8cb7bfd 	ldp	x29, x30, [sp], #176
    8020acc4:	d65f03c0 	ret
    8020acc8:	79c02421 	ldrsh	w1, [x1, #18]
    8020accc:	aa0003f4 	mov	x20, x0
    8020acd0:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020acd4:	f9001bf7 	str	x23, [sp, #48]
    8020acd8:	37f80381 	tbnz	w1, #31, 8020ad48 <__smakebuf_r+0xb8>
    8020acdc:	910123e2 	add	x2, sp, #0x48
    8020ace0:	94000aa4 	bl	8020d770 <_fstat_r>
    8020ace4:	37f80300 	tbnz	w0, #31, 8020ad44 <__smakebuf_r+0xb4>
    8020ace8:	b9404fe0 	ldr	w0, [sp, #76]
    8020acec:	d2808016 	mov	x22, #0x400                 	// #1024
    8020acf0:	52810015 	mov	w21, #0x800                 	// #2048
    8020acf4:	aa1603e1 	mov	x1, x22
    8020acf8:	12140c00 	and	w0, w0, #0xf000
    8020acfc:	7140081f 	cmp	w0, #0x2, lsl #12
    8020ad00:	aa1403e0 	mov	x0, x20
    8020ad04:	1a9f17f7 	cset	w23, eq	// eq = none
    8020ad08:	97fff94e 	bl	80209240 <_malloc_r>
    8020ad0c:	b5000320 	cbnz	x0, 8020ad70 <__smakebuf_r+0xe0>
    8020ad10:	79c02260 	ldrsh	w0, [x19, #16]
    8020ad14:	37480560 	tbnz	w0, #9, 8020adc0 <__smakebuf_r+0x130>
    8020ad18:	121e7400 	and	w0, w0, #0xfffffffc
    8020ad1c:	9101de61 	add	x1, x19, #0x77
    8020ad20:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020ad24:	321f0000 	orr	w0, w0, #0x2
    8020ad28:	f9401bf7 	ldr	x23, [sp, #48]
    8020ad2c:	52800022 	mov	w2, #0x1                   	// #1
    8020ad30:	f9000261 	str	x1, [x19]
    8020ad34:	79002260 	strh	w0, [x19, #16]
    8020ad38:	f9000e61 	str	x1, [x19, #24]
    8020ad3c:	b9002262 	str	w2, [x19, #32]
    8020ad40:	17ffffdf 	b	8020acbc <__smakebuf_r+0x2c>
    8020ad44:	79c02262 	ldrsh	w2, [x19, #16]
    8020ad48:	f279005f 	tst	x2, #0x80
    8020ad4c:	d2800800 	mov	x0, #0x40                  	// #64
    8020ad50:	d2808016 	mov	x22, #0x400                 	// #1024
    8020ad54:	9a8002d6 	csel	x22, x22, x0, eq	// eq = none
    8020ad58:	aa1603e1 	mov	x1, x22
    8020ad5c:	aa1403e0 	mov	x0, x20
    8020ad60:	52800017 	mov	w23, #0x0                   	// #0
    8020ad64:	52800015 	mov	w21, #0x0                   	// #0
    8020ad68:	97fff936 	bl	80209240 <_malloc_r>
    8020ad6c:	b4fffd20 	cbz	x0, 8020ad10 <__smakebuf_r+0x80>
    8020ad70:	79c02262 	ldrsh	w2, [x19, #16]
    8020ad74:	f9000260 	str	x0, [x19]
    8020ad78:	32190042 	orr	w2, w2, #0x80
    8020ad7c:	79002262 	strh	w2, [x19, #16]
    8020ad80:	f9000e60 	str	x0, [x19, #24]
    8020ad84:	b9002276 	str	w22, [x19, #32]
    8020ad88:	35000117 	cbnz	w23, 8020ada8 <__smakebuf_r+0x118>
    8020ad8c:	2a150042 	orr	w2, w2, w21
    8020ad90:	79002262 	strh	w2, [x19, #16]
    8020ad94:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ad98:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020ad9c:	f9401bf7 	ldr	x23, [sp, #48]
    8020ada0:	a8cb7bfd 	ldp	x29, x30, [sp], #176
    8020ada4:	d65f03c0 	ret
    8020ada8:	79c02661 	ldrsh	w1, [x19, #18]
    8020adac:	aa1403e0 	mov	x0, x20
    8020adb0:	94000a84 	bl	8020d7c0 <_isatty_r>
    8020adb4:	350000c0 	cbnz	w0, 8020adcc <__smakebuf_r+0x13c>
    8020adb8:	79c02262 	ldrsh	w2, [x19, #16]
    8020adbc:	17fffff4 	b	8020ad8c <__smakebuf_r+0xfc>
    8020adc0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020adc4:	f9401bf7 	ldr	x23, [sp, #48]
    8020adc8:	17ffffbd 	b	8020acbc <__smakebuf_r+0x2c>
    8020adcc:	79402262 	ldrh	w2, [x19, #16]
    8020add0:	121e7442 	and	w2, w2, #0xfffffffc
    8020add4:	32000042 	orr	w2, w2, #0x1
    8020add8:	13003c42 	sxth	w2, w2
    8020addc:	17ffffec 	b	8020ad8c <__smakebuf_r+0xfc>

000000008020ade0 <__swhatbuf_r>:
    8020ade0:	a9b67bfd 	stp	x29, x30, [sp, #-160]!
    8020ade4:	910003fd 	mov	x29, sp
    8020ade8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020adec:	aa0103f3 	mov	x19, x1
    8020adf0:	79c02421 	ldrsh	w1, [x1, #18]
    8020adf4:	f90013f5 	str	x21, [sp, #32]
    8020adf8:	aa0203f4 	mov	x20, x2
    8020adfc:	aa0303f5 	mov	x21, x3
    8020ae00:	37f80201 	tbnz	w1, #31, 8020ae40 <__swhatbuf_r+0x60>
    8020ae04:	9100e3e2 	add	x2, sp, #0x38
    8020ae08:	94000a5a 	bl	8020d770 <_fstat_r>
    8020ae0c:	37f801a0 	tbnz	w0, #31, 8020ae40 <__swhatbuf_r+0x60>
    8020ae10:	b9403fe2 	ldr	w2, [sp, #60]
    8020ae14:	d2808001 	mov	x1, #0x400                 	// #1024
    8020ae18:	52810000 	mov	w0, #0x800                 	// #2048
    8020ae1c:	12140c42 	and	w2, w2, #0xf000
    8020ae20:	7140085f 	cmp	w2, #0x2, lsl #12
    8020ae24:	1a9f17e2 	cset	w2, eq	// eq = none
    8020ae28:	b90002a2 	str	w2, [x21]
    8020ae2c:	f94013f5 	ldr	x21, [sp, #32]
    8020ae30:	f9000281 	str	x1, [x20]
    8020ae34:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ae38:	a8ca7bfd 	ldp	x29, x30, [sp], #160
    8020ae3c:	d65f03c0 	ret
    8020ae40:	79402264 	ldrh	w4, [x19, #16]
    8020ae44:	52800002 	mov	w2, #0x0                   	// #0
    8020ae48:	b90002a2 	str	w2, [x21]
    8020ae4c:	d2808003 	mov	x3, #0x400                 	// #1024
    8020ae50:	f94013f5 	ldr	x21, [sp, #32]
    8020ae54:	f279009f 	tst	x4, #0x80
    8020ae58:	d2800801 	mov	x1, #0x40                  	// #64
    8020ae5c:	9a831021 	csel	x1, x1, x3, ne	// ne = any
    8020ae60:	f9000281 	str	x1, [x20]
    8020ae64:	52800000 	mov	w0, #0x0                   	// #0
    8020ae68:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ae6c:	a8ca7bfd 	ldp	x29, x30, [sp], #160
    8020ae70:	d65f03c0 	ret
	...

000000008020ae80 <memcpy>:
    8020ae80:	d503245f 	bti	c
    8020ae84:	8b020024 	add	x4, x1, x2
    8020ae88:	8b020005 	add	x5, x0, x2
    8020ae8c:	f102005f 	cmp	x2, #0x80
    8020ae90:	54000788 	b.hi	8020af80 <memcpy+0x100>  // b.pmore
    8020ae94:	f100805f 	cmp	x2, #0x20
    8020ae98:	540003c8 	b.hi	8020af10 <memcpy+0x90>  // b.pmore
    8020ae9c:	f100405f 	cmp	x2, #0x10
    8020aea0:	540000c3 	b.cc	8020aeb8 <memcpy+0x38>  // b.lo, b.ul, b.last
    8020aea4:	a9401c26 	ldp	x6, x7, [x1]
    8020aea8:	a97f348c 	ldp	x12, x13, [x4, #-16]
    8020aeac:	a9001c06 	stp	x6, x7, [x0]
    8020aeb0:	a93f34ac 	stp	x12, x13, [x5, #-16]
    8020aeb4:	d65f03c0 	ret
    8020aeb8:	361800c2 	tbz	w2, #3, 8020aed0 <memcpy+0x50>
    8020aebc:	f9400026 	ldr	x6, [x1]
    8020aec0:	f85f8087 	ldur	x7, [x4, #-8]
    8020aec4:	f9000006 	str	x6, [x0]
    8020aec8:	f81f80a7 	stur	x7, [x5, #-8]
    8020aecc:	d65f03c0 	ret
    8020aed0:	361000c2 	tbz	w2, #2, 8020aee8 <memcpy+0x68>
    8020aed4:	b9400026 	ldr	w6, [x1]
    8020aed8:	b85fc088 	ldur	w8, [x4, #-4]
    8020aedc:	b9000006 	str	w6, [x0]
    8020aee0:	b81fc0a8 	stur	w8, [x5, #-4]
    8020aee4:	d65f03c0 	ret
    8020aee8:	b4000102 	cbz	x2, 8020af08 <memcpy+0x88>
    8020aeec:	d341fc4e 	lsr	x14, x2, #1
    8020aef0:	39400026 	ldrb	w6, [x1]
    8020aef4:	385ff08a 	ldurb	w10, [x4, #-1]
    8020aef8:	386e6828 	ldrb	w8, [x1, x14]
    8020aefc:	39000006 	strb	w6, [x0]
    8020af00:	382e6808 	strb	w8, [x0, x14]
    8020af04:	381ff0aa 	sturb	w10, [x5, #-1]
    8020af08:	d65f03c0 	ret
    8020af0c:	d503201f 	nop
    8020af10:	a9401c26 	ldp	x6, x7, [x1]
    8020af14:	a9412428 	ldp	x8, x9, [x1, #16]
    8020af18:	a97e2c8a 	ldp	x10, x11, [x4, #-32]
    8020af1c:	a97f348c 	ldp	x12, x13, [x4, #-16]
    8020af20:	f101005f 	cmp	x2, #0x40
    8020af24:	540000e8 	b.hi	8020af40 <memcpy+0xc0>  // b.pmore
    8020af28:	a9001c06 	stp	x6, x7, [x0]
    8020af2c:	a9012408 	stp	x8, x9, [x0, #16]
    8020af30:	a93e2caa 	stp	x10, x11, [x5, #-32]
    8020af34:	a93f34ac 	stp	x12, x13, [x5, #-16]
    8020af38:	d65f03c0 	ret
    8020af3c:	d503201f 	nop
    8020af40:	a9423c2e 	ldp	x14, x15, [x1, #32]
    8020af44:	a9434430 	ldp	x16, x17, [x1, #48]
    8020af48:	f101805f 	cmp	x2, #0x60
    8020af4c:	540000a9 	b.ls	8020af60 <memcpy+0xe0>  // b.plast
    8020af50:	a97c0c82 	ldp	x2, x3, [x4, #-64]
    8020af54:	a97d1081 	ldp	x1, x4, [x4, #-48]
    8020af58:	a93c0ca2 	stp	x2, x3, [x5, #-64]
    8020af5c:	a93d10a1 	stp	x1, x4, [x5, #-48]
    8020af60:	a9001c06 	stp	x6, x7, [x0]
    8020af64:	a9012408 	stp	x8, x9, [x0, #16]
    8020af68:	a9023c0e 	stp	x14, x15, [x0, #32]
    8020af6c:	a9034410 	stp	x16, x17, [x0, #48]
    8020af70:	a93e2caa 	stp	x10, x11, [x5, #-32]
    8020af74:	a93f34ac 	stp	x12, x13, [x5, #-16]
    8020af78:	d65f03c0 	ret
    8020af7c:	d503201f 	nop
    8020af80:	cb01000e 	sub	x14, x0, x1
    8020af84:	b4fffc2e 	cbz	x14, 8020af08 <memcpy+0x88>
    8020af88:	eb0201df 	cmp	x14, x2
    8020af8c:	540004a3 	b.cc	8020b020 <memcpy+0x1a0>  // b.lo, b.ul, b.last
    8020af90:	a940342c 	ldp	x12, x13, [x1]
    8020af94:	92400c0e 	and	x14, x0, #0xf
    8020af98:	927cec03 	and	x3, x0, #0xfffffffffffffff0
    8020af9c:	cb0e0021 	sub	x1, x1, x14
    8020afa0:	8b0e0042 	add	x2, x2, x14
    8020afa4:	a9411c26 	ldp	x6, x7, [x1, #16]
    8020afa8:	a900340c 	stp	x12, x13, [x0]
    8020afac:	a9422428 	ldp	x8, x9, [x1, #32]
    8020afb0:	a9432c2a 	ldp	x10, x11, [x1, #48]
    8020afb4:	a9c4342c 	ldp	x12, x13, [x1, #64]!
    8020afb8:	f1024042 	subs	x2, x2, #0x90
    8020afbc:	54000169 	b.ls	8020afe8 <memcpy+0x168>  // b.plast
    8020afc0:	a9011c66 	stp	x6, x7, [x3, #16]
    8020afc4:	a9411c26 	ldp	x6, x7, [x1, #16]
    8020afc8:	a9022468 	stp	x8, x9, [x3, #32]
    8020afcc:	a9422428 	ldp	x8, x9, [x1, #32]
    8020afd0:	a9032c6a 	stp	x10, x11, [x3, #48]
    8020afd4:	a9432c2a 	ldp	x10, x11, [x1, #48]
    8020afd8:	a984346c 	stp	x12, x13, [x3, #64]!
    8020afdc:	a9c4342c 	ldp	x12, x13, [x1, #64]!
    8020afe0:	f1010042 	subs	x2, x2, #0x40
    8020afe4:	54fffee8 	b.hi	8020afc0 <memcpy+0x140>  // b.pmore
    8020afe8:	a97c3c8e 	ldp	x14, x15, [x4, #-64]
    8020afec:	a9011c66 	stp	x6, x7, [x3, #16]
    8020aff0:	a97d1c86 	ldp	x6, x7, [x4, #-48]
    8020aff4:	a9022468 	stp	x8, x9, [x3, #32]
    8020aff8:	a97e2488 	ldp	x8, x9, [x4, #-32]
    8020affc:	a9032c6a 	stp	x10, x11, [x3, #48]
    8020b000:	a97f2c8a 	ldp	x10, x11, [x4, #-16]
    8020b004:	a904346c 	stp	x12, x13, [x3, #64]
    8020b008:	a93c3cae 	stp	x14, x15, [x5, #-64]
    8020b00c:	a93d1ca6 	stp	x6, x7, [x5, #-48]
    8020b010:	a93e24a8 	stp	x8, x9, [x5, #-32]
    8020b014:	a93f2caa 	stp	x10, x11, [x5, #-16]
    8020b018:	d65f03c0 	ret
    8020b01c:	d503201f 	nop
    8020b020:	a97f348c 	ldp	x12, x13, [x4, #-16]
    8020b024:	92400cae 	and	x14, x5, #0xf
    8020b028:	cb0e0084 	sub	x4, x4, x14
    8020b02c:	cb0e0042 	sub	x2, x2, x14
    8020b030:	a97f1c86 	ldp	x6, x7, [x4, #-16]
    8020b034:	a93f34ac 	stp	x12, x13, [x5, #-16]
    8020b038:	a97e2488 	ldp	x8, x9, [x4, #-32]
    8020b03c:	a97d2c8a 	ldp	x10, x11, [x4, #-48]
    8020b040:	a9fc348c 	ldp	x12, x13, [x4, #-64]!
    8020b044:	cb0e00a5 	sub	x5, x5, x14
    8020b048:	f1020042 	subs	x2, x2, #0x80
    8020b04c:	54000169 	b.ls	8020b078 <memcpy+0x1f8>  // b.plast
    8020b050:	a93f1ca6 	stp	x6, x7, [x5, #-16]
    8020b054:	a97f1c86 	ldp	x6, x7, [x4, #-16]
    8020b058:	a93e24a8 	stp	x8, x9, [x5, #-32]
    8020b05c:	a97e2488 	ldp	x8, x9, [x4, #-32]
    8020b060:	a93d2caa 	stp	x10, x11, [x5, #-48]
    8020b064:	a97d2c8a 	ldp	x10, x11, [x4, #-48]
    8020b068:	a9bc34ac 	stp	x12, x13, [x5, #-64]!
    8020b06c:	a9fc348c 	ldp	x12, x13, [x4, #-64]!
    8020b070:	f1010042 	subs	x2, x2, #0x40
    8020b074:	54fffee8 	b.hi	8020b050 <memcpy+0x1d0>  // b.pmore
    8020b078:	a9430c22 	ldp	x2, x3, [x1, #48]
    8020b07c:	a93f1ca6 	stp	x6, x7, [x5, #-16]
    8020b080:	a9421c26 	ldp	x6, x7, [x1, #32]
    8020b084:	a93e24a8 	stp	x8, x9, [x5, #-32]
    8020b088:	a9412428 	ldp	x8, x9, [x1, #16]
    8020b08c:	a93d2caa 	stp	x10, x11, [x5, #-48]
    8020b090:	a9402c2a 	ldp	x10, x11, [x1]
    8020b094:	a93c34ac 	stp	x12, x13, [x5, #-64]
    8020b098:	a9030c02 	stp	x2, x3, [x0, #48]
    8020b09c:	a9021c06 	stp	x6, x7, [x0, #32]
    8020b0a0:	a9012408 	stp	x8, x9, [x0, #16]
    8020b0a4:	a9002c0a 	stp	x10, x11, [x0]
    8020b0a8:	d65f03c0 	ret
    8020b0ac:	00000000 	udf	#0

000000008020b0b0 <__malloc_lock>:
    8020b0b0:	d00003a0 	adrp	x0, 80281000 <__sf+0x38>
    8020b0b4:	91096000 	add	x0, x0, #0x258
    8020b0b8:	17fffac2 	b	80209bc0 <__retarget_lock_acquire_recursive>
    8020b0bc:	00000000 	udf	#0

000000008020b0c0 <__malloc_unlock>:
    8020b0c0:	d00003a0 	adrp	x0, 80281000 <__sf+0x38>
    8020b0c4:	91096000 	add	x0, x0, #0x258
    8020b0c8:	17ffface 	b	80209c00 <__retarget_lock_release_recursive>
    8020b0cc:	00000000 	udf	#0

000000008020b0d0 <_wcsrtombs_r>:
    8020b0d0:	aa0403e5 	mov	x5, x4
    8020b0d4:	aa0303e4 	mov	x4, x3
    8020b0d8:	92800003 	mov	x3, #0xffffffffffffffff    	// #-1
    8020b0dc:	140013f1 	b	802100a0 <_wcsnrtombs_r>

000000008020b0e0 <wcsrtombs>:
    8020b0e0:	d0000026 	adrp	x6, 80211000 <blanks.1+0x60>
    8020b0e4:	aa0003e4 	mov	x4, x0
    8020b0e8:	aa0103e5 	mov	x5, x1
    8020b0ec:	aa0403e1 	mov	x1, x4
    8020b0f0:	f94388c0 	ldr	x0, [x6, #1808]
    8020b0f4:	aa0203e4 	mov	x4, x2
    8020b0f8:	aa0503e2 	mov	x2, x5
    8020b0fc:	aa0303e5 	mov	x5, x3
    8020b100:	92800003 	mov	x3, #0xffffffffffffffff    	// #-1
    8020b104:	140013e7 	b	802100a0 <_wcsnrtombs_r>
	...

000000008020b110 <quorem>:
    8020b110:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020b114:	910003fd 	mov	x29, sp
    8020b118:	a90153f3 	stp	x19, x20, [sp, #16]
    8020b11c:	b9401434 	ldr	w20, [x1, #20]
    8020b120:	a90363f7 	stp	x23, x24, [sp, #48]
    8020b124:	aa0003f8 	mov	x24, x0
    8020b128:	b9401400 	ldr	w0, [x0, #20]
    8020b12c:	6b14001f 	cmp	w0, w20
    8020b130:	54000b8b 	b.lt	8020b2a0 <quorem+0x190>  // b.tstop
    8020b134:	51000694 	sub	w20, w20, #0x1
    8020b138:	91006033 	add	x19, x1, #0x18
    8020b13c:	91006317 	add	x23, x24, #0x18
    8020b140:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020b144:	93407e8a 	sxtw	x10, w20
    8020b148:	937e7e80 	sbfiz	x0, x20, #2, #32
    8020b14c:	8b000276 	add	x22, x19, x0
    8020b150:	8b0002eb 	add	x11, x23, x0
    8020b154:	b86a7a62 	ldr	w2, [x19, x10, lsl #2]
    8020b158:	b86a7ae3 	ldr	w3, [x23, x10, lsl #2]
    8020b15c:	11000442 	add	w2, w2, #0x1
    8020b160:	1ac20875 	udiv	w21, w3, w2
    8020b164:	6b02007f 	cmp	w3, w2
    8020b168:	540004c3 	b.cc	8020b200 <quorem+0xf0>  // b.lo, b.ul, b.last
    8020b16c:	aa1303e7 	mov	x7, x19
    8020b170:	aa1703e6 	mov	x6, x23
    8020b174:	52800009 	mov	w9, #0x0                   	// #0
    8020b178:	52800008 	mov	w8, #0x0                   	// #0
    8020b17c:	d503201f 	nop
    8020b180:	b84044e3 	ldr	w3, [x7], #4
    8020b184:	b94000c4 	ldr	w4, [x6]
    8020b188:	12003c65 	and	w5, w3, #0xffff
    8020b18c:	53107c63 	lsr	w3, w3, #16
    8020b190:	12003c82 	and	w2, w4, #0xffff
    8020b194:	1b1524a5 	madd	w5, w5, w21, w9
    8020b198:	53107ca9 	lsr	w9, w5, #16
    8020b19c:	4b252042 	sub	w2, w2, w5, uxth
    8020b1a0:	0b080042 	add	w2, w2, w8
    8020b1a4:	1b152463 	madd	w3, w3, w21, w9
    8020b1a8:	13107c40 	asr	w0, w2, #16
    8020b1ac:	4b232000 	sub	w0, w0, w3, uxth
    8020b1b0:	53107c69 	lsr	w9, w3, #16
    8020b1b4:	0b444003 	add	w3, w0, w4, lsr #16
    8020b1b8:	33103c62 	bfi	w2, w3, #16, #16
    8020b1bc:	b80044c2 	str	w2, [x6], #4
    8020b1c0:	13107c68 	asr	w8, w3, #16
    8020b1c4:	eb0702df 	cmp	x22, x7
    8020b1c8:	54fffdc2 	b.cs	8020b180 <quorem+0x70>  // b.hs, b.nlast
    8020b1cc:	b86a7ae0 	ldr	w0, [x23, x10, lsl #2]
    8020b1d0:	35000180 	cbnz	w0, 8020b200 <quorem+0xf0>
    8020b1d4:	d1001160 	sub	x0, x11, #0x4
    8020b1d8:	eb0002ff 	cmp	x23, x0
    8020b1dc:	540000a3 	b.cc	8020b1f0 <quorem+0xe0>  // b.lo, b.ul, b.last
    8020b1e0:	14000007 	b	8020b1fc <quorem+0xec>
    8020b1e4:	51000694 	sub	w20, w20, #0x1
    8020b1e8:	eb0002ff 	cmp	x23, x0
    8020b1ec:	54000082 	b.cs	8020b1fc <quorem+0xec>  // b.hs, b.nlast
    8020b1f0:	b9400002 	ldr	w2, [x0]
    8020b1f4:	d1001000 	sub	x0, x0, #0x4
    8020b1f8:	34ffff62 	cbz	w2, 8020b1e4 <quorem+0xd4>
    8020b1fc:	b9001714 	str	w20, [x24, #20]
    8020b200:	aa1803e0 	mov	x0, x24
    8020b204:	9400114f 	bl	8020f740 <__mcmp>
    8020b208:	37f80400 	tbnz	w0, #31, 8020b288 <quorem+0x178>
    8020b20c:	aa1703e0 	mov	x0, x23
    8020b210:	52800004 	mov	w4, #0x0                   	// #0
    8020b214:	d503201f 	nop
    8020b218:	b8404663 	ldr	w3, [x19], #4
    8020b21c:	b9400002 	ldr	w2, [x0]
    8020b220:	12003c41 	and	w1, w2, #0xffff
    8020b224:	4b232021 	sub	w1, w1, w3, uxth
    8020b228:	0b040021 	add	w1, w1, w4
    8020b22c:	13107c24 	asr	w4, w1, #16
    8020b230:	4b434083 	sub	w3, w4, w3, lsr #16
    8020b234:	0b424062 	add	w2, w3, w2, lsr #16
    8020b238:	33103c41 	bfi	w1, w2, #16, #16
    8020b23c:	b8004401 	str	w1, [x0], #4
    8020b240:	13107c44 	asr	w4, w2, #16
    8020b244:	eb1302df 	cmp	x22, x19
    8020b248:	54fffe82 	b.cs	8020b218 <quorem+0x108>  // b.hs, b.nlast
    8020b24c:	b874dae1 	ldr	w1, [x23, w20, sxtw #2]
    8020b250:	8b34cae0 	add	x0, x23, w20, sxtw #2
    8020b254:	35000181 	cbnz	w1, 8020b284 <quorem+0x174>
    8020b258:	d1001000 	sub	x0, x0, #0x4
    8020b25c:	eb17001f 	cmp	x0, x23
    8020b260:	540000a8 	b.hi	8020b274 <quorem+0x164>  // b.pmore
    8020b264:	14000007 	b	8020b280 <quorem+0x170>
    8020b268:	51000694 	sub	w20, w20, #0x1
    8020b26c:	eb0002ff 	cmp	x23, x0
    8020b270:	54000082 	b.cs	8020b280 <quorem+0x170>  // b.hs, b.nlast
    8020b274:	b9400001 	ldr	w1, [x0]
    8020b278:	d1001000 	sub	x0, x0, #0x4
    8020b27c:	34ffff61 	cbz	w1, 8020b268 <quorem+0x158>
    8020b280:	b9001714 	str	w20, [x24, #20]
    8020b284:	110006b5 	add	w21, w21, #0x1
    8020b288:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020b28c:	2a1503e0 	mov	w0, w21
    8020b290:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020b294:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020b298:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020b29c:	d65f03c0 	ret
    8020b2a0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020b2a4:	52800000 	mov	w0, #0x0                   	// #0
    8020b2a8:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020b2ac:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020b2b0:	d65f03c0 	ret
	...

000000008020b2c0 <_dtoa_r>:
    8020b2c0:	a9b47bfd 	stp	x29, x30, [sp, #-192]!
    8020b2c4:	910003fd 	mov	x29, sp
    8020b2c8:	f9402806 	ldr	x6, [x0, #80]
    8020b2cc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020b2d0:	aa0003f3 	mov	x19, x0
    8020b2d4:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020b2d8:	aa0403f4 	mov	x20, x4
    8020b2dc:	a90363f7 	stp	x23, x24, [sp, #48]
    8020b2e0:	2a0103f7 	mov	w23, w1
    8020b2e4:	aa0503f8 	mov	x24, x5
    8020b2e8:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020b2ec:	2a0203fa 	mov	w26, w2
    8020b2f0:	a90573fb 	stp	x27, x28, [sp, #80]
    8020b2f4:	9e66001c 	fmov	x28, d0
    8020b2f8:	f90043e3 	str	x3, [sp, #128]
    8020b2fc:	6d0627e8 	stp	d8, d9, [sp, #96]
    8020b300:	1e604008 	fmov	d8, d0
    8020b304:	b4000106 	cbz	x6, 8020b324 <_dtoa_r+0x64>
    8020b308:	b9405803 	ldr	w3, [x0, #88]
    8020b30c:	52800022 	mov	w2, #0x1                   	// #1
    8020b310:	aa0603e1 	mov	x1, x6
    8020b314:	1ac32042 	lsl	w2, w2, w3
    8020b318:	290108c3 	stp	w3, w2, [x6, #8]
    8020b31c:	94000ed9 	bl	8020ee80 <_Bfree>
    8020b320:	f9002a7f 	str	xzr, [x19, #80]
    8020b324:	9e660100 	fmov	x0, d8
    8020b328:	1e604109 	fmov	d9, d8
    8020b32c:	52800001 	mov	w1, #0x0                   	// #0
    8020b330:	d360fc00 	lsr	x0, x0, #32
    8020b334:	2a0003f5 	mov	w21, w0
    8020b338:	36f800a0 	tbz	w0, #31, 8020b34c <_dtoa_r+0x8c>
    8020b33c:	12007815 	and	w21, w0, #0x7fffffff
    8020b340:	52800021 	mov	w1, #0x1                   	// #1
    8020b344:	b3607ebc 	bfi	x28, x21, #32, #32
    8020b348:	9e670389 	fmov	d9, x28
    8020b34c:	120c2aa2 	and	w2, w21, #0x7ff00000
    8020b350:	b9000281 	str	w1, [x20]
    8020b354:	52affe00 	mov	w0, #0x7ff00000            	// #2146435072
    8020b358:	6b00005f 	cmp	w2, w0
    8020b35c:	54000e80 	b.eq	8020b52c <_dtoa_r+0x26c>  // b.none
    8020b360:	1e602128 	fcmp	d9, #0.0
    8020b364:	54000261 	b.ne	8020b3b0 <_dtoa_r+0xf0>  // b.any
    8020b368:	f94043e1 	ldr	x1, [sp, #128]
    8020b36c:	52800020 	mov	w0, #0x1                   	// #1
    8020b370:	b9000020 	str	w0, [x1]
    8020b374:	b4000098 	cbz	x24, 8020b384 <_dtoa_r+0xc4>
    8020b378:	b0000020 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020b37c:	91302400 	add	x0, x0, #0xc09
    8020b380:	f9000300 	str	x0, [x24]
    8020b384:	b0000037 	adrp	x23, 80210000 <_wcsnrtombs_l+0x110>
    8020b388:	913022f7 	add	x23, x23, #0xc08
    8020b38c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020b390:	aa1703e0 	mov	x0, x23
    8020b394:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020b398:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020b39c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020b3a0:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020b3a4:	6d4627e8 	ldp	d8, d9, [sp, #96]
    8020b3a8:	a8cc7bfd 	ldp	x29, x30, [sp], #192
    8020b3ac:	d65f03c0 	ret
    8020b3b0:	1e604120 	fmov	d0, d9
    8020b3b4:	9102e3e2 	add	x2, sp, #0xb8
    8020b3b8:	9102f3e1 	add	x1, sp, #0xbc
    8020b3bc:	aa1303e0 	mov	x0, x19
    8020b3c0:	940011e4 	bl	8020fb50 <__d2b>
    8020b3c4:	aa0003f4 	mov	x20, x0
    8020b3c8:	53147ea0 	lsr	w0, w21, #20
    8020b3cc:	35000ca0 	cbnz	w0, 8020b560 <_dtoa_r+0x2a0>
    8020b3d0:	295707e3 	ldp	w3, w1, [sp, #184]
    8020b3d4:	9e660100 	fmov	x0, d8
    8020b3d8:	0b010061 	add	w1, w3, w1
    8020b3dc:	1110c822 	add	w2, w1, #0x432
    8020b3e0:	7100805f 	cmp	w2, #0x20
    8020b3e4:	54002ead 	b.le	8020b9b8 <_dtoa_r+0x6f8>
    8020b3e8:	11104825 	add	w5, w1, #0x412
    8020b3ec:	52800804 	mov	w4, #0x40                  	// #64
    8020b3f0:	4b020082 	sub	w2, w4, w2
    8020b3f4:	1ac52400 	lsr	w0, w0, w5
    8020b3f8:	1ac222b5 	lsl	w21, w21, w2
    8020b3fc:	2a0002a0 	orr	w0, w21, w0
    8020b400:	1e630000 	ucvtf	d0, w0
    8020b404:	51000420 	sub	w0, w1, #0x1
    8020b408:	52800021 	mov	w1, #0x1                   	// #1
    8020b40c:	b900a7e1 	str	w1, [sp, #164]
    8020b410:	52bfc204 	mov	w4, #0xfe100000            	// #-32505856
    8020b414:	9e660002 	fmov	x2, d0
    8020b418:	d360fc41 	lsr	x1, x2, #32
    8020b41c:	0b040021 	add	w1, w1, w4
    8020b420:	b3607c22 	bfi	x2, x1, #32, #32
    8020b424:	9e670042 	fmov	d2, x2
    8020b428:	1e6f1001 	fmov	d1, #1.500000000000000000e+00
    8020b42c:	d0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020b430:	1e620003 	scvtf	d3, w0
    8020b434:	1e613841 	fsub	d1, d2, d1
    8020b438:	fd417c24 	ldr	d4, [x1, #760]
    8020b43c:	d0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020b440:	fd418020 	ldr	d0, [x1, #768]
    8020b444:	d0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020b448:	1f440020 	fmadd	d0, d1, d4, d0
    8020b44c:	fd418422 	ldr	d2, [x1, #776]
    8020b450:	1f420060 	fmadd	d0, d3, d2, d0
    8020b454:	1e602018 	fcmpe	d0, #0.0
    8020b458:	1e780005 	fcvtzs	w5, d0
    8020b45c:	54002a44 	b.mi	8020b9a4 <_dtoa_r+0x6e4>  // b.first
    8020b460:	4b000060 	sub	w0, w3, w0
    8020b464:	51000406 	sub	w6, w0, #0x1
    8020b468:	710058bf 	cmp	w5, #0x16
    8020b46c:	54002808 	b.hi	8020b96c <_dtoa_r+0x6ac>  // b.pmore
    8020b470:	d0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020b474:	91150021 	add	x1, x1, #0x540
    8020b478:	fc65d820 	ldr	d0, [x1, w5, sxtw #3]
    8020b47c:	1e692010 	fcmpe	d0, d9
    8020b480:	54002d2c 	b.gt	8020ba24 <_dtoa_r+0x764>
    8020b484:	b900a3ff 	str	wzr, [sp, #160]
    8020b488:	52800007 	mov	w7, #0x0                   	// #0
    8020b48c:	7100001f 	cmp	w0, #0x0
    8020b490:	5400008c 	b.gt	8020b4a0 <_dtoa_r+0x1e0>
    8020b494:	52800027 	mov	w7, #0x1                   	// #1
    8020b498:	4b0000e7 	sub	w7, w7, w0
    8020b49c:	52800006 	mov	w6, #0x0                   	// #0
    8020b4a0:	0b0500c6 	add	w6, w6, w5
    8020b4a4:	5280001b 	mov	w27, #0x0                   	// #0
    8020b4a8:	b9008be5 	str	w5, [sp, #136]
    8020b4ac:	710026ff 	cmp	w23, #0x9
    8020b4b0:	54000768 	b.hi	8020b59c <_dtoa_r+0x2dc>  // b.pmore
    8020b4b4:	710016ff 	cmp	w23, #0x5
    8020b4b8:	5400286d 	b.le	8020b9c4 <_dtoa_r+0x704>
    8020b4bc:	510012f7 	sub	w23, w23, #0x4
    8020b4c0:	52800019 	mov	w25, #0x0                   	// #0
    8020b4c4:	71000eff 	cmp	w23, #0x3
    8020b4c8:	54005960 	b.eq	8020bff4 <_dtoa_r+0xd34>  // b.none
    8020b4cc:	54002f2d 	b.le	8020bab0 <_dtoa_r+0x7f0>
    8020b4d0:	710012ff 	cmp	w23, #0x4
    8020b4d4:	54002da1 	b.ne	8020ba88 <_dtoa_r+0x7c8>  // b.any
    8020b4d8:	52800020 	mov	w0, #0x1                   	// #1
    8020b4dc:	b9007be0 	str	w0, [sp, #120]
    8020b4e0:	7100035f 	cmp	w26, #0x0
    8020b4e4:	5400536d 	b.le	8020bf50 <_dtoa_r+0xc90>
    8020b4e8:	2a1a03f5 	mov	w21, w26
    8020b4ec:	2a1a03e0 	mov	w0, w26
    8020b4f0:	b900abfa 	str	w26, [sp, #168]
    8020b4f4:	93407c04 	sxtw	x4, w0
    8020b4f8:	71007c1f 	cmp	w0, #0x1f
    8020b4fc:	540005cd 	b.le	8020b5b4 <_dtoa_r+0x2f4>
    8020b500:	52800023 	mov	w3, #0x1                   	// #1
    8020b504:	52800082 	mov	w2, #0x4                   	// #4
    8020b508:	531f7842 	lsl	w2, w2, #1
    8020b50c:	2a0303e1 	mov	w1, w3
    8020b510:	11000463 	add	w3, w3, #0x1
    8020b514:	93407c40 	sxtw	x0, w2
    8020b518:	91007000 	add	x0, x0, #0x1c
    8020b51c:	eb04001f 	cmp	x0, x4
    8020b520:	54ffff49 	b.ls	8020b508 <_dtoa_r+0x248>  // b.plast
    8020b524:	b9005a61 	str	w1, [x19, #88]
    8020b528:	14000026 	b	8020b5c0 <_dtoa_r+0x300>
    8020b52c:	f94043e1 	ldr	x1, [sp, #128]
    8020b530:	5284e1e0 	mov	w0, #0x270f                	// #9999
    8020b534:	b9000020 	str	w0, [x1]
    8020b538:	9e660120 	fmov	x0, d9
    8020b53c:	f240cc1f 	tst	x0, #0xfffffffffffff
    8020b540:	54000201 	b.ne	8020b580 <_dtoa_r+0x2c0>  // b.any
    8020b544:	b0000037 	adrp	x23, 80210000 <_wcsnrtombs_l+0x110>
    8020b548:	b4006218 	cbz	x24, 8020c188 <_dtoa_r+0xec8>
    8020b54c:	b0000020 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020b550:	913682f7 	add	x23, x23, #0xda0
    8020b554:	9136a000 	add	x0, x0, #0xda8
    8020b558:	f9000300 	str	x0, [x24]
    8020b55c:	17ffff8c 	b	8020b38c <_dtoa_r+0xcc>
    8020b560:	9e660122 	fmov	x2, d9
    8020b564:	b940bbe3 	ldr	w3, [sp, #184]
    8020b568:	510ffc00 	sub	w0, w0, #0x3ff
    8020b56c:	b900a7ff 	str	wzr, [sp, #164]
    8020b570:	d360cc41 	ubfx	x1, x2, #32, #20
    8020b574:	320c2421 	orr	w1, w1, #0x3ff00000
    8020b578:	b3607c22 	bfi	x2, x1, #32, #32
    8020b57c:	17ffffaa 	b	8020b424 <_dtoa_r+0x164>
    8020b580:	b0000037 	adrp	x23, 80210000 <_wcsnrtombs_l+0x110>
    8020b584:	b4005ff8 	cbz	x24, 8020c180 <_dtoa_r+0xec0>
    8020b588:	b0000020 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020b58c:	9136c2f7 	add	x23, x23, #0xdb0
    8020b590:	9136cc00 	add	x0, x0, #0xdb3
    8020b594:	f9000300 	str	x0, [x24]
    8020b598:	17ffff7d 	b	8020b38c <_dtoa_r+0xcc>
    8020b59c:	52800039 	mov	w25, #0x1                   	// #1
    8020b5a0:	52800017 	mov	w23, #0x0                   	// #0
    8020b5a4:	12800015 	mov	w21, #0xffffffff            	// #-1
    8020b5a8:	5280001a 	mov	w26, #0x0                   	// #0
    8020b5ac:	b9007bf9 	str	w25, [sp, #120]
    8020b5b0:	b900abf5 	str	w21, [sp, #168]
    8020b5b4:	52800001 	mov	w1, #0x0                   	// #0
    8020b5b8:	b9005a7f 	str	wzr, [x19, #88]
    8020b5bc:	d503201f 	nop
    8020b5c0:	aa1303e0 	mov	x0, x19
    8020b5c4:	29119be7 	stp	w7, w6, [sp, #140]
    8020b5c8:	b9009be5 	str	w5, [sp, #152]
    8020b5cc:	94000e09 	bl	8020edf0 <_Balloc>
    8020b5d0:	29519be7 	ldp	w7, w6, [sp, #140]
    8020b5d4:	aa0003f6 	mov	x22, x0
    8020b5d8:	b9409be5 	ldr	w5, [sp, #152]
    8020b5dc:	b40072c0 	cbz	x0, 8020c434 <_dtoa_r+0x1174>
    8020b5e0:	71003abf 	cmp	w21, #0xe
    8020b5e4:	f9002a76 	str	x22, [x19, #80]
    8020b5e8:	1a9f87e0 	cset	w0, ls	// ls = plast
    8020b5ec:	2a1503e3 	mov	w3, w21
    8020b5f0:	0a190004 	and	w4, w0, w25
    8020b5f4:	6a19001f 	tst	w0, w25
    8020b5f8:	54000ae0 	b.eq	8020b754 <_dtoa_r+0x494>  // b.none
    8020b5fc:	b9408be0 	ldr	w0, [sp, #136]
    8020b600:	7100001f 	cmp	w0, #0x0
    8020b604:	5400446d 	b.le	8020be90 <_dtoa_r+0xbd0>
    8020b608:	2a0003e4 	mov	w4, w0
    8020b60c:	d0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020b610:	aa0403e0 	mov	x0, x4
    8020b614:	91150021 	add	x1, x1, #0x540
    8020b618:	92400c02 	and	x2, x0, #0xf
    8020b61c:	13047c80 	asr	w0, w4, #4
    8020b620:	fc627820 	ldr	d0, [x1, x2, lsl #3]
    8020b624:	aa0403e1 	mov	x1, x4
    8020b628:	36404e01 	tbz	w1, #8, 8020bfe8 <_dtoa_r+0xd28>
    8020b62c:	d0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020b630:	12000c00 	and	w0, w0, #0xf
    8020b634:	52800062 	mov	w2, #0x3                   	// #3
    8020b638:	fd429821 	ldr	d1, [x1, #1328]
    8020b63c:	1e611921 	fdiv	d1, d9, d1
    8020b640:	34000160 	cbz	w0, 8020b66c <_dtoa_r+0x3ac>
    8020b644:	d0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020b648:	91144021 	add	x1, x1, #0x510
    8020b64c:	d503201f 	nop
    8020b650:	36000080 	tbz	w0, #0, 8020b660 <_dtoa_r+0x3a0>
    8020b654:	fd400022 	ldr	d2, [x1]
    8020b658:	11000442 	add	w2, w2, #0x1
    8020b65c:	1e620800 	fmul	d0, d0, d2
    8020b660:	13017c00 	asr	w0, w0, #1
    8020b664:	91002021 	add	x1, x1, #0x8
    8020b668:	35ffff40 	cbnz	w0, 8020b650 <_dtoa_r+0x390>
    8020b66c:	1e601821 	fdiv	d1, d1, d0
    8020b670:	b940a3e0 	ldr	w0, [sp, #160]
    8020b674:	34000080 	cbz	w0, 8020b684 <_dtoa_r+0x3c4>
    8020b678:	1e6e1000 	fmov	d0, #1.000000000000000000e+00
    8020b67c:	1e602030 	fcmpe	d1, d0
    8020b680:	540054c4 	b.mi	8020c118 <_dtoa_r+0xe58>  // b.first
    8020b684:	1e620042 	scvtf	d2, w2
    8020b688:	1e639000 	fmov	d0, #7.000000000000000000e+00
    8020b68c:	52bf9802 	mov	w2, #0xfcc00000            	// #-54525952
    8020b690:	1f410040 	fmadd	d0, d2, d1, d0
    8020b694:	9e660000 	fmov	x0, d0
    8020b698:	d360fc01 	lsr	x1, x0, #32
    8020b69c:	0b020021 	add	w1, w1, w2
    8020b6a0:	b3607c20 	bfi	x0, x1, #32, #32
    8020b6a4:	34003e15 	cbz	w21, 8020be64 <_dtoa_r+0xba4>
    8020b6a8:	b9408bfc 	ldr	w28, [sp, #136]
    8020b6ac:	2a1503e4 	mov	w4, w21
    8020b6b0:	1e780021 	fcvtzs	w1, d1
    8020b6b4:	9e670002 	fmov	d2, x0
    8020b6b8:	51000482 	sub	w2, w4, #0x1
    8020b6bc:	d0000028 	adrp	x8, 80211000 <blanks.1+0x60>
    8020b6c0:	91150108 	add	x8, x8, #0x540
    8020b6c4:	910006c9 	add	x9, x22, #0x1
    8020b6c8:	1e620020 	scvtf	d0, w1
    8020b6cc:	1100c020 	add	w0, w1, #0x30
    8020b6d0:	b9407be1 	ldr	w1, [sp, #120]
    8020b6d4:	12001c00 	and	w0, w0, #0xff
    8020b6d8:	fc62d903 	ldr	d3, [x8, w2, sxtw #3]
    8020b6dc:	1e603821 	fsub	d1, d1, d0
    8020b6e0:	340048e1 	cbz	w1, 8020bffc <_dtoa_r+0xd3c>
    8020b6e4:	1e6c1000 	fmov	d0, #5.000000000000000000e-01
    8020b6e8:	390002c0 	strb	w0, [x22]
    8020b6ec:	1e631800 	fdiv	d0, d0, d3
    8020b6f0:	1e623800 	fsub	d0, d0, d2
    8020b6f4:	1e612010 	fcmpe	d0, d1
    8020b6f8:	5400684c 	b.gt	8020c400 <_dtoa_r+0x1140>
    8020b6fc:	52800022 	mov	w2, #0x1                   	// #1
    8020b700:	aa0903e0 	mov	x0, x9
    8020b704:	4b090042 	sub	w2, w2, w9
    8020b708:	1e6e1004 	fmov	d4, #1.000000000000000000e+00
    8020b70c:	1e649003 	fmov	d3, #1.000000000000000000e+01
    8020b710:	1400000a 	b	8020b738 <_dtoa_r+0x478>
    8020b714:	1e630821 	fmul	d1, d1, d3
    8020b718:	1e630800 	fmul	d0, d0, d3
    8020b71c:	1e780021 	fcvtzs	w1, d1
    8020b720:	1e620022 	scvtf	d2, w1
    8020b724:	1100c021 	add	w1, w1, #0x30
    8020b728:	38001401 	strb	w1, [x0], #1
    8020b72c:	1e623821 	fsub	d1, d1, d2
    8020b730:	1e602030 	fcmpe	d1, d0
    8020b734:	54005e24 	b.mi	8020c2f8 <_dtoa_r+0x1038>  // b.first
    8020b738:	1e613882 	fsub	d2, d4, d1
    8020b73c:	1e602050 	fcmpe	d2, d0
    8020b740:	540017c4 	b.mi	8020ba38 <_dtoa_r+0x778>  // b.first
    8020b744:	0b000041 	add	w1, w2, w0
    8020b748:	6b04003f 	cmp	w1, w4
    8020b74c:	54fffe4b 	b.lt	8020b714 <_dtoa_r+0x454>  // b.tstop
    8020b750:	9e66013c 	fmov	x28, d9
    8020b754:	b940bfe0 	ldr	w0, [sp, #188]
    8020b758:	b9408be1 	ldr	w1, [sp, #136]
    8020b75c:	7100001f 	cmp	w0, #0x0
    8020b760:	7a4ea820 	ccmp	w1, #0xe, #0x0, ge	// ge = tcont
    8020b764:	54003d6d 	b.le	8020bf10 <_dtoa_r+0xc50>
    8020b768:	b9407be1 	ldr	w1, [sp, #120]
    8020b76c:	34003c81 	cbz	w1, 8020befc <_dtoa_r+0xc3c>
    8020b770:	710006ff 	cmp	w23, #0x1
    8020b774:	54004f6d 	b.le	8020c160 <_dtoa_r+0xea0>
    8020b778:	510006a3 	sub	w3, w21, #0x1
    8020b77c:	6b03037f 	cmp	w27, w3
    8020b780:	5400520b 	b.lt	8020c1c0 <_dtoa_r+0xf00>  // b.tstop
    8020b784:	4b1500e0 	sub	w0, w7, w21
    8020b788:	b9008fe0 	str	w0, [sp, #140]
    8020b78c:	4b030363 	sub	w3, w27, w3
    8020b790:	36f85e75 	tbz	w21, #31, 8020c35c <_dtoa_r+0x109c>
    8020b794:	aa1303e0 	mov	x0, x19
    8020b798:	52800021 	mov	w1, #0x1                   	// #1
    8020b79c:	b90093e7 	str	w7, [sp, #144]
    8020b7a0:	b9009be6 	str	w6, [sp, #152]
    8020b7a4:	b900a7e5 	str	w5, [sp, #164]
    8020b7a8:	b900afe3 	str	w3, [sp, #172]
    8020b7ac:	94000e95 	bl	8020f200 <__i2b>
    8020b7b0:	b94093e7 	ldr	w7, [sp, #144]
    8020b7b4:	aa0003f9 	mov	x25, x0
    8020b7b8:	b9409be6 	ldr	w6, [sp, #152]
    8020b7bc:	b940a7e5 	ldr	w5, [sp, #164]
    8020b7c0:	b940afe3 	ldr	w3, [sp, #172]
    8020b7c4:	b9408fe1 	ldr	w1, [sp, #140]
    8020b7c8:	7100003f 	cmp	w1, #0x0
    8020b7cc:	7a40c8c4 	ccmp	w6, #0x0, #0x4, gt
    8020b7d0:	540000ed 	b.le	8020b7ec <_dtoa_r+0x52c>
    8020b7d4:	6b06003f 	cmp	w1, w6
    8020b7d8:	1a86d020 	csel	w0, w1, w6, le
    8020b7dc:	4b0000e7 	sub	w7, w7, w0
    8020b7e0:	4b0000c6 	sub	w6, w6, w0
    8020b7e4:	4b000021 	sub	w1, w1, w0
    8020b7e8:	b9008fe1 	str	w1, [sp, #140]
    8020b7ec:	340001fb 	cbz	w27, 8020b828 <_dtoa_r+0x568>
    8020b7f0:	b9407be0 	ldr	w0, [sp, #120]
    8020b7f4:	34004ce0 	cbz	w0, 8020c190 <_dtoa_r+0xed0>
    8020b7f8:	35005183 	cbnz	w3, 8020c228 <_dtoa_r+0xf68>
    8020b7fc:	aa1403e1 	mov	x1, x20
    8020b800:	2a1b03e2 	mov	w2, w27
    8020b804:	aa1303e0 	mov	x0, x19
    8020b808:	b90093e7 	str	w7, [sp, #144]
    8020b80c:	b9009be6 	str	w6, [sp, #152]
    8020b810:	b900a7e5 	str	w5, [sp, #164]
    8020b814:	94000f27 	bl	8020f4b0 <__pow5mult>
    8020b818:	b94093e7 	ldr	w7, [sp, #144]
    8020b81c:	aa0003f4 	mov	x20, x0
    8020b820:	b9409be6 	ldr	w6, [sp, #152]
    8020b824:	b940a7e5 	ldr	w5, [sp, #164]
    8020b828:	aa1303e0 	mov	x0, x19
    8020b82c:	52800021 	mov	w1, #0x1                   	// #1
    8020b830:	b90093e7 	str	w7, [sp, #144]
    8020b834:	b9009be6 	str	w6, [sp, #152]
    8020b838:	b900a7e5 	str	w5, [sp, #164]
    8020b83c:	94000e71 	bl	8020f200 <__i2b>
    8020b840:	b940a7e5 	ldr	w5, [sp, #164]
    8020b844:	aa0003fb 	mov	x27, x0
    8020b848:	b94093e7 	ldr	w7, [sp, #144]
    8020b84c:	b9409be6 	ldr	w6, [sp, #152]
    8020b850:	35003865 	cbnz	w5, 8020bf5c <_dtoa_r+0xc9c>
    8020b854:	710006ff 	cmp	w23, #0x1
    8020b858:	54001c8d 	b.le	8020bbe8 <_dtoa_r+0x928>
    8020b85c:	52800020 	mov	w0, #0x1                   	// #1
    8020b860:	0b0000c0 	add	w0, w6, w0
    8020b864:	72001000 	ands	w0, w0, #0x1f
    8020b868:	54003100 	b.eq	8020be88 <_dtoa_r+0xbc8>  // b.none
    8020b86c:	52800401 	mov	w1, #0x20                  	// #32
    8020b870:	4b000021 	sub	w1, w1, w0
    8020b874:	7100103f 	cmp	w1, #0x4
    8020b878:	5400442d 	b.le	8020c0fc <_dtoa_r+0xe3c>
    8020b87c:	52800381 	mov	w1, #0x1c                  	// #28
    8020b880:	4b000020 	sub	w0, w1, w0
    8020b884:	b9408fe1 	ldr	w1, [sp, #140]
    8020b888:	0b0000e7 	add	w7, w7, w0
    8020b88c:	0b0000c6 	add	w6, w6, w0
    8020b890:	0b000021 	add	w1, w1, w0
    8020b894:	b9008fe1 	str	w1, [sp, #140]
    8020b898:	710000ff 	cmp	w7, #0x0
    8020b89c:	5400014d 	b.le	8020b8c4 <_dtoa_r+0x604>
    8020b8a0:	aa1403e1 	mov	x1, x20
    8020b8a4:	2a0703e2 	mov	w2, w7
    8020b8a8:	aa1303e0 	mov	x0, x19
    8020b8ac:	b90093e6 	str	w6, [sp, #144]
    8020b8b0:	b9009be5 	str	w5, [sp, #152]
    8020b8b4:	94000f47 	bl	8020f5d0 <__lshift>
    8020b8b8:	b94093e6 	ldr	w6, [sp, #144]
    8020b8bc:	aa0003f4 	mov	x20, x0
    8020b8c0:	b9409be5 	ldr	w5, [sp, #152]
    8020b8c4:	710000df 	cmp	w6, #0x0
    8020b8c8:	5400010d 	b.le	8020b8e8 <_dtoa_r+0x628>
    8020b8cc:	aa1b03e1 	mov	x1, x27
    8020b8d0:	2a0603e2 	mov	w2, w6
    8020b8d4:	aa1303e0 	mov	x0, x19
    8020b8d8:	b90093e5 	str	w5, [sp, #144]
    8020b8dc:	94000f3d 	bl	8020f5d0 <__lshift>
    8020b8e0:	aa0003fb 	mov	x27, x0
    8020b8e4:	b94093e5 	ldr	w5, [sp, #144]
    8020b8e8:	b940a3e0 	ldr	w0, [sp, #160]
    8020b8ec:	71000aff 	cmp	w23, #0x2
    8020b8f0:	1a9fd7e4 	cset	w4, gt
    8020b8f4:	350018e0 	cbnz	w0, 8020bc10 <_dtoa_r+0x950>
    8020b8f8:	710002bf 	cmp	w21, #0x0
    8020b8fc:	7a40d884 	ccmp	w4, #0x0, #0x4, le
    8020b900:	54000de0 	b.eq	8020babc <_dtoa_r+0x7fc>  // b.none
    8020b904:	35002795 	cbnz	w21, 8020bdf4 <_dtoa_r+0xb34>
    8020b908:	52800003 	mov	w3, #0x0                   	// #0
    8020b90c:	528000a2 	mov	w2, #0x5                   	// #5
    8020b910:	aa1b03e1 	mov	x1, x27
    8020b914:	aa1303e0 	mov	x0, x19
    8020b918:	94000d62 	bl	8020eea0 <__multadd>
    8020b91c:	aa0003fb 	mov	x27, x0
    8020b920:	aa1b03e1 	mov	x1, x27
    8020b924:	aa1403e0 	mov	x0, x20
    8020b928:	aa1603f7 	mov	x23, x22
    8020b92c:	94000f85 	bl	8020f740 <__mcmp>
    8020b930:	7100001f 	cmp	w0, #0x0
    8020b934:	5400260d 	b.le	8020bdf4 <_dtoa_r+0xb34>
    8020b938:	b9408be0 	ldr	w0, [sp, #136]
    8020b93c:	910006d6 	add	x22, x22, #0x1
    8020b940:	1100041c 	add	w28, w0, #0x1
    8020b944:	52800620 	mov	w0, #0x31                  	// #49
    8020b948:	390002e0 	strb	w0, [x23]
    8020b94c:	aa1b03e1 	mov	x1, x27
    8020b950:	aa1303e0 	mov	x0, x19
    8020b954:	94000d4b 	bl	8020ee80 <_Bfree>
    8020b958:	b4000859 	cbz	x25, 8020ba60 <_dtoa_r+0x7a0>
    8020b95c:	aa1903e1 	mov	x1, x25
    8020b960:	aa1303e0 	mov	x0, x19
    8020b964:	94000d47 	bl	8020ee80 <_Bfree>
    8020b968:	1400003e 	b	8020ba60 <_dtoa_r+0x7a0>
    8020b96c:	52800021 	mov	w1, #0x1                   	// #1
    8020b970:	b900a3e1 	str	w1, [sp, #160]
    8020b974:	52800007 	mov	w7, #0x0                   	// #0
    8020b978:	37f800e6 	tbnz	w6, #31, 8020b994 <_dtoa_r+0x6d4>
    8020b97c:	36ffd925 	tbz	w5, #31, 8020b4a0 <_dtoa_r+0x1e0>
    8020b980:	4b0500e7 	sub	w7, w7, w5
    8020b984:	4b0503fb 	neg	w27, w5
    8020b988:	b9008be5 	str	w5, [sp, #136]
    8020b98c:	52800005 	mov	w5, #0x0                   	// #0
    8020b990:	17fffec7 	b	8020b4ac <_dtoa_r+0x1ec>
    8020b994:	52800027 	mov	w7, #0x1                   	// #1
    8020b998:	52800006 	mov	w6, #0x0                   	// #0
    8020b99c:	4b0000e7 	sub	w7, w7, w0
    8020b9a0:	17fffff7 	b	8020b97c <_dtoa_r+0x6bc>
    8020b9a4:	1e6200a1 	scvtf	d1, w5
    8020b9a8:	1e602020 	fcmp	d1, d0
    8020b9ac:	1a9f07e1 	cset	w1, ne	// ne = any
    8020b9b0:	4b0100a5 	sub	w5, w5, w1
    8020b9b4:	17fffeab 	b	8020b460 <_dtoa_r+0x1a0>
    8020b9b8:	4b0203e2 	neg	w2, w2
    8020b9bc:	1ac22000 	lsl	w0, w0, w2
    8020b9c0:	17fffe90 	b	8020b400 <_dtoa_r+0x140>
    8020b9c4:	52800039 	mov	w25, #0x1                   	// #1
    8020b9c8:	71000eff 	cmp	w23, #0x3
    8020b9cc:	54003140 	b.eq	8020bff4 <_dtoa_r+0xd34>  // b.none
    8020b9d0:	54ffd80c 	b.gt	8020b4d0 <_dtoa_r+0x210>
    8020b9d4:	71000aff 	cmp	w23, #0x2
    8020b9d8:	540053c0 	b.eq	8020c450 <_dtoa_r+0x1190>  // b.none
    8020b9dc:	b9005a7f 	str	wzr, [x19, #88]
    8020b9e0:	aa1303e0 	mov	x0, x19
    8020b9e4:	52800001 	mov	w1, #0x0                   	// #0
    8020b9e8:	b9007be7 	str	w7, [sp, #120]
    8020b9ec:	291197e6 	stp	w6, w5, [sp, #140]
    8020b9f0:	94000d00 	bl	8020edf0 <_Balloc>
    8020b9f4:	b9407be7 	ldr	w7, [sp, #120]
    8020b9f8:	aa0003f6 	mov	x22, x0
    8020b9fc:	295197e6 	ldp	w6, w5, [sp, #140]
    8020ba00:	b40051a0 	cbz	x0, 8020c434 <_dtoa_r+0x1174>
    8020ba04:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020ba08:	5280001a 	mov	w26, #0x0                   	// #0
    8020ba0c:	2a0003e3 	mov	w3, w0
    8020ba10:	2a0003f5 	mov	w21, w0
    8020ba14:	f9002a76 	str	x22, [x19, #80]
    8020ba18:	b9007bf9 	str	w25, [sp, #120]
    8020ba1c:	b900abe0 	str	w0, [sp, #168]
    8020ba20:	17ffff4d 	b	8020b754 <_dtoa_r+0x494>
    8020ba24:	510004a5 	sub	w5, w5, #0x1
    8020ba28:	b900a3ff 	str	wzr, [sp, #160]
    8020ba2c:	17ffffd2 	b	8020b974 <_dtoa_r+0x6b4>
    8020ba30:	eb16001f 	cmp	x0, x22
    8020ba34:	540042a0 	b.eq	8020c288 <_dtoa_r+0xfc8>  // b.none
    8020ba38:	aa0003e2 	mov	x2, x0
    8020ba3c:	385ffc01 	ldrb	w1, [x0, #-1]!
    8020ba40:	7100e43f 	cmp	w1, #0x39
    8020ba44:	54ffff60 	b.eq	8020ba30 <_dtoa_r+0x770>  // b.none
    8020ba48:	11000421 	add	w1, w1, #0x1
    8020ba4c:	12001c21 	and	w1, w1, #0xff
    8020ba50:	aa1603f7 	mov	x23, x22
    8020ba54:	aa0203f6 	mov	x22, x2
    8020ba58:	39000001 	strb	w1, [x0]
    8020ba5c:	d503201f 	nop
    8020ba60:	aa1403e1 	mov	x1, x20
    8020ba64:	aa1303e0 	mov	x0, x19
    8020ba68:	94000d06 	bl	8020ee80 <_Bfree>
    8020ba6c:	390002df 	strb	wzr, [x22]
    8020ba70:	f94043e1 	ldr	x1, [sp, #128]
    8020ba74:	11000780 	add	w0, w28, #0x1
    8020ba78:	b9000020 	str	w0, [x1]
    8020ba7c:	b4ffc898 	cbz	x24, 8020b38c <_dtoa_r+0xcc>
    8020ba80:	f9000316 	str	x22, [x24]
    8020ba84:	17fffe42 	b	8020b38c <_dtoa_r+0xcc>
    8020ba88:	52800020 	mov	w0, #0x1                   	// #1
    8020ba8c:	528000b7 	mov	w23, #0x5                   	// #5
    8020ba90:	b9007be0 	str	w0, [sp, #120]
    8020ba94:	b9408be0 	ldr	w0, [sp, #136]
    8020ba98:	0b000340 	add	w0, w26, w0
    8020ba9c:	b900abe0 	str	w0, [sp, #168]
    8020baa0:	11000415 	add	w21, w0, #0x1
    8020baa4:	710002bf 	cmp	w21, #0x0
    8020baa8:	1a9fc6a0 	csinc	w0, w21, wzr, gt
    8020baac:	17fffe92 	b	8020b4f4 <_dtoa_r+0x234>
    8020bab0:	52800057 	mov	w23, #0x2                   	// #2
    8020bab4:	b9007bff 	str	wzr, [sp, #120]
    8020bab8:	17fffe8a 	b	8020b4e0 <_dtoa_r+0x220>
    8020babc:	b9407be0 	ldr	w0, [sp, #120]
    8020bac0:	34000e00 	cbz	w0, 8020bc80 <_dtoa_r+0x9c0>
    8020bac4:	b9408fe2 	ldr	w2, [sp, #140]
    8020bac8:	7100005f 	cmp	w2, #0x0
    8020bacc:	540000ed 	b.le	8020bae8 <_dtoa_r+0x828>
    8020bad0:	aa1903e1 	mov	x1, x25
    8020bad4:	aa1303e0 	mov	x0, x19
    8020bad8:	b9007be5 	str	w5, [sp, #120]
    8020badc:	94000ebd 	bl	8020f5d0 <__lshift>
    8020bae0:	b9407be5 	ldr	w5, [sp, #120]
    8020bae4:	aa0003f9 	mov	x25, x0
    8020bae8:	f9003ff9 	str	x25, [sp, #120]
    8020baec:	35003e45 	cbnz	w5, 8020c2b4 <_dtoa_r+0xff4>
    8020baf0:	8b35c2d5 	add	x21, x22, w21, sxtw
    8020baf4:	12000380 	and	w0, w28, #0x1
    8020baf8:	f9004bf6 	str	x22, [sp, #144]
    8020bafc:	b900a7e0 	str	w0, [sp, #164]
    8020bb00:	aa1b03e1 	mov	x1, x27
    8020bb04:	aa1403e0 	mov	x0, x20
    8020bb08:	97fffd82 	bl	8020b110 <quorem>
    8020bb0c:	1100c01a 	add	w26, w0, #0x30
    8020bb10:	aa1903e1 	mov	x1, x25
    8020bb14:	b900a3e0 	str	w0, [sp, #160]
    8020bb18:	aa1403e0 	mov	x0, x20
    8020bb1c:	94000f09 	bl	8020f740 <__mcmp>
    8020bb20:	f9403fe2 	ldr	x2, [sp, #120]
    8020bb24:	aa1b03e1 	mov	x1, x27
    8020bb28:	b9008fe0 	str	w0, [sp, #140]
    8020bb2c:	aa1303e0 	mov	x0, x19
    8020bb30:	94000f18 	bl	8020f790 <__mdiff>
    8020bb34:	aa0003e1 	mov	x1, x0
    8020bb38:	b9401000 	ldr	w0, [x0, #16]
    8020bb3c:	35001180 	cbnz	w0, 8020bd6c <_dtoa_r+0xaac>
    8020bb40:	aa1403e0 	mov	x0, x20
    8020bb44:	f9004fe1 	str	x1, [sp, #152]
    8020bb48:	94000efe 	bl	8020f740 <__mcmp>
    8020bb4c:	2a0003e2 	mov	w2, w0
    8020bb50:	f9404fe1 	ldr	x1, [sp, #152]
    8020bb54:	aa1303e0 	mov	x0, x19
    8020bb58:	b9009be2 	str	w2, [sp, #152]
    8020bb5c:	94000cc9 	bl	8020ee80 <_Bfree>
    8020bb60:	b9409be2 	ldr	w2, [sp, #152]
    8020bb64:	2a0202e0 	orr	w0, w23, w2
    8020bb68:	350014c0 	cbnz	w0, 8020be00 <_dtoa_r+0xb40>
    8020bb6c:	b940a7e0 	ldr	w0, [sp, #164]
    8020bb70:	34003fe0 	cbz	w0, 8020c36c <_dtoa_r+0x10ac>
    8020bb74:	b9408fe0 	ldr	w0, [sp, #140]
    8020bb78:	37f81260 	tbnz	w0, #31, 8020bdc4 <_dtoa_r+0xb04>
    8020bb7c:	f9404be0 	ldr	x0, [sp, #144]
    8020bb80:	3800141a 	strb	w26, [x0], #1
    8020bb84:	f9004be0 	str	x0, [sp, #144]
    8020bb88:	eb0002bf 	cmp	x21, x0
    8020bb8c:	54003d00 	b.eq	8020c32c <_dtoa_r+0x106c>  // b.none
    8020bb90:	aa1403e1 	mov	x1, x20
    8020bb94:	52800003 	mov	w3, #0x0                   	// #0
    8020bb98:	52800142 	mov	w2, #0xa                   	// #10
    8020bb9c:	aa1303e0 	mov	x0, x19
    8020bba0:	94000cc0 	bl	8020eea0 <__multadd>
    8020bba4:	aa0003f4 	mov	x20, x0
    8020bba8:	f9403fe0 	ldr	x0, [sp, #120]
    8020bbac:	aa1903e1 	mov	x1, x25
    8020bbb0:	52800003 	mov	w3, #0x0                   	// #0
    8020bbb4:	52800142 	mov	w2, #0xa                   	// #10
    8020bbb8:	eb00033f 	cmp	x25, x0
    8020bbbc:	aa1303e0 	mov	x0, x19
    8020bbc0:	540010e0 	b.eq	8020bddc <_dtoa_r+0xb1c>  // b.none
    8020bbc4:	94000cb7 	bl	8020eea0 <__multadd>
    8020bbc8:	aa0003f9 	mov	x25, x0
    8020bbcc:	f9403fe1 	ldr	x1, [sp, #120]
    8020bbd0:	aa1303e0 	mov	x0, x19
    8020bbd4:	52800003 	mov	w3, #0x0                   	// #0
    8020bbd8:	52800142 	mov	w2, #0xa                   	// #10
    8020bbdc:	94000cb1 	bl	8020eea0 <__multadd>
    8020bbe0:	f9003fe0 	str	x0, [sp, #120]
    8020bbe4:	17ffffc7 	b	8020bb00 <_dtoa_r+0x840>
    8020bbe8:	f240cf9f 	tst	x28, #0xfffffffffffff
    8020bbec:	54ffe381 	b.ne	8020b85c <_dtoa_r+0x59c>  // b.any
    8020bbf0:	d360ff80 	lsr	x0, x28, #32
    8020bbf4:	f26c281f 	tst	x0, #0x7ff00000
    8020bbf8:	54ffe320 	b.eq	8020b85c <_dtoa_r+0x59c>  // b.none
    8020bbfc:	52800025 	mov	w5, #0x1                   	// #1
    8020bc00:	110004e7 	add	w7, w7, #0x1
    8020bc04:	110004c6 	add	w6, w6, #0x1
    8020bc08:	2a0503e0 	mov	w0, w5
    8020bc0c:	17ffff15 	b	8020b860 <_dtoa_r+0x5a0>
    8020bc10:	aa1b03e1 	mov	x1, x27
    8020bc14:	aa1403e0 	mov	x0, x20
    8020bc18:	b90093e5 	str	w5, [sp, #144]
    8020bc1c:	b9009be4 	str	w4, [sp, #152]
    8020bc20:	94000ec8 	bl	8020f740 <__mcmp>
    8020bc24:	b94093e5 	ldr	w5, [sp, #144]
    8020bc28:	b9409be4 	ldr	w4, [sp, #152]
    8020bc2c:	36ffe660 	tbz	w0, #31, 8020b8f8 <_dtoa_r+0x638>
    8020bc30:	b9408be0 	ldr	w0, [sp, #136]
    8020bc34:	aa1403e1 	mov	x1, x20
    8020bc38:	52800003 	mov	w3, #0x0                   	// #0
    8020bc3c:	52800142 	mov	w2, #0xa                   	// #10
    8020bc40:	51000400 	sub	w0, w0, #0x1
    8020bc44:	b9008be0 	str	w0, [sp, #136]
    8020bc48:	aa1303e0 	mov	x0, x19
    8020bc4c:	b90093e5 	str	w5, [sp, #144]
    8020bc50:	b9009be4 	str	w4, [sp, #152]
    8020bc54:	94000c93 	bl	8020eea0 <__multadd>
    8020bc58:	aa0003f4 	mov	x20, x0
    8020bc5c:	b9407be0 	ldr	w0, [sp, #120]
    8020bc60:	b94093e5 	ldr	w5, [sp, #144]
    8020bc64:	b9409be4 	ldr	w4, [sp, #152]
    8020bc68:	350039e0 	cbnz	w0, 8020c3a4 <_dtoa_r+0x10e4>
    8020bc6c:	b940abe0 	ldr	w0, [sp, #168]
    8020bc70:	7100001f 	cmp	w0, #0x0
    8020bc74:	2a0003f5 	mov	w21, w0
    8020bc78:	7a40d884 	ccmp	w4, #0x0, #0x4, le
    8020bc7c:	54ffe441 	b.ne	8020b904 <_dtoa_r+0x644>  // b.any
    8020bc80:	d2800017 	mov	x23, #0x0                   	// #0
    8020bc84:	14000007 	b	8020bca0 <_dtoa_r+0x9e0>
    8020bc88:	aa1403e1 	mov	x1, x20
    8020bc8c:	aa1303e0 	mov	x0, x19
    8020bc90:	52800003 	mov	w3, #0x0                   	// #0
    8020bc94:	52800142 	mov	w2, #0xa                   	// #10
    8020bc98:	94000c82 	bl	8020eea0 <__multadd>
    8020bc9c:	aa0003f4 	mov	x20, x0
    8020bca0:	aa1b03e1 	mov	x1, x27
    8020bca4:	aa1403e0 	mov	x0, x20
    8020bca8:	97fffd1a 	bl	8020b110 <quorem>
    8020bcac:	1100c01a 	add	w26, w0, #0x30
    8020bcb0:	38376ada 	strb	w26, [x22, x23]
    8020bcb4:	910006f7 	add	x23, x23, #0x1
    8020bcb8:	6b1702bf 	cmp	w21, w23
    8020bcbc:	54fffe6c 	b.gt	8020bc88 <_dtoa_r+0x9c8>
    8020bcc0:	710002bf 	cmp	w21, #0x0
    8020bcc4:	510006b5 	sub	w21, w21, #0x1
    8020bcc8:	d2800020 	mov	x0, #0x1                   	// #1
    8020bccc:	9a95d415 	csinc	x21, x0, x21, le
    8020bcd0:	8b1502d5 	add	x21, x22, x21
    8020bcd4:	d2800017 	mov	x23, #0x0                   	// #0
    8020bcd8:	52800022 	mov	w2, #0x1                   	// #1
    8020bcdc:	aa1403e1 	mov	x1, x20
    8020bce0:	aa1303e0 	mov	x0, x19
    8020bce4:	94000e3b 	bl	8020f5d0 <__lshift>
    8020bce8:	aa1b03e1 	mov	x1, x27
    8020bcec:	aa0003f4 	mov	x20, x0
    8020bcf0:	94000e94 	bl	8020f740 <__mcmp>
    8020bcf4:	7100001f 	cmp	w0, #0x0
    8020bcf8:	5400008c 	b.gt	8020bd08 <_dtoa_r+0xa48>
    8020bcfc:	1400013d 	b	8020c1f0 <_dtoa_r+0xf30>
    8020bd00:	eb1602bf 	cmp	x21, x22
    8020bd04:	54002880 	b.eq	8020c214 <_dtoa_r+0xf54>  // b.none
    8020bd08:	aa1503e2 	mov	x2, x21
    8020bd0c:	d10006b5 	sub	x21, x21, #0x1
    8020bd10:	385ff040 	ldurb	w0, [x2, #-1]
    8020bd14:	7100e41f 	cmp	w0, #0x39
    8020bd18:	54ffff40 	b.eq	8020bd00 <_dtoa_r+0xa40>  // b.none
    8020bd1c:	b9408bfc 	ldr	w28, [sp, #136]
    8020bd20:	11000400 	add	w0, w0, #0x1
    8020bd24:	390002a0 	strb	w0, [x21]
    8020bd28:	aa1b03e1 	mov	x1, x27
    8020bd2c:	aa1303e0 	mov	x0, x19
    8020bd30:	f9003fe2 	str	x2, [sp, #120]
    8020bd34:	94000c53 	bl	8020ee80 <_Bfree>
    8020bd38:	f9403fe2 	ldr	x2, [sp, #120]
    8020bd3c:	b4001db9 	cbz	x25, 8020c0f0 <_dtoa_r+0xe30>
    8020bd40:	f10002ff 	cmp	x23, #0x0
    8020bd44:	fa5912e4 	ccmp	x23, x25, #0x4, ne	// ne = any
    8020bd48:	540000c0 	b.eq	8020bd60 <_dtoa_r+0xaa0>  // b.none
    8020bd4c:	aa1703e1 	mov	x1, x23
    8020bd50:	aa1303e0 	mov	x0, x19
    8020bd54:	f9003fe2 	str	x2, [sp, #120]
    8020bd58:	94000c4a 	bl	8020ee80 <_Bfree>
    8020bd5c:	f9403fe2 	ldr	x2, [sp, #120]
    8020bd60:	aa1603f7 	mov	x23, x22
    8020bd64:	aa0203f6 	mov	x22, x2
    8020bd68:	17fffefd 	b	8020b95c <_dtoa_r+0x69c>
    8020bd6c:	aa1303e0 	mov	x0, x19
    8020bd70:	94000c44 	bl	8020ee80 <_Bfree>
    8020bd74:	b9408fe0 	ldr	w0, [sp, #140]
    8020bd78:	37f800c0 	tbnz	w0, #31, 8020bd90 <_dtoa_r+0xad0>
    8020bd7c:	b9408fe0 	ldr	w0, [sp, #140]
    8020bd80:	1200039c 	and	w28, w28, #0x1
    8020bd84:	2a0002e0 	orr	w0, w23, w0
    8020bd88:	2a00039c 	orr	w28, w28, w0
    8020bd8c:	350004bc 	cbnz	w28, 8020be20 <_dtoa_r+0xb60>
    8020bd90:	52800022 	mov	w2, #0x1                   	// #1
    8020bd94:	aa1403e1 	mov	x1, x20
    8020bd98:	aa1303e0 	mov	x0, x19
    8020bd9c:	94000e0d 	bl	8020f5d0 <__lshift>
    8020bda0:	aa1b03e1 	mov	x1, x27
    8020bda4:	aa0003f4 	mov	x20, x0
    8020bda8:	94000e66 	bl	8020f740 <__mcmp>
    8020bdac:	7100001f 	cmp	w0, #0x0
    8020bdb0:	5400318d 	b.le	8020c3e0 <_dtoa_r+0x1120>
    8020bdb4:	7100e75f 	cmp	w26, #0x39
    8020bdb8:	54002c00 	b.eq	8020c338 <_dtoa_r+0x1078>  // b.none
    8020bdbc:	b940a3e0 	ldr	w0, [sp, #160]
    8020bdc0:	1100c41a 	add	w26, w0, #0x31
    8020bdc4:	f9404be2 	ldr	x2, [sp, #144]
    8020bdc8:	aa1903f7 	mov	x23, x25
    8020bdcc:	f9403ff9 	ldr	x25, [sp, #120]
    8020bdd0:	b9408bfc 	ldr	w28, [sp, #136]
    8020bdd4:	3800145a 	strb	w26, [x2], #1
    8020bdd8:	17ffffd4 	b	8020bd28 <_dtoa_r+0xa68>
    8020bddc:	94000c31 	bl	8020eea0 <__multadd>
    8020bde0:	aa0003f9 	mov	x25, x0
    8020bde4:	f9003fe0 	str	x0, [sp, #120]
    8020bde8:	17ffff46 	b	8020bb00 <_dtoa_r+0x840>
    8020bdec:	d280001b 	mov	x27, #0x0                   	// #0
    8020bdf0:	d2800019 	mov	x25, #0x0                   	// #0
    8020bdf4:	2a3a03fc 	mvn	w28, w26
    8020bdf8:	aa1603f7 	mov	x23, x22
    8020bdfc:	17fffed4 	b	8020b94c <_dtoa_r+0x68c>
    8020be00:	b9408fe0 	ldr	w0, [sp, #140]
    8020be04:	37f83040 	tbnz	w0, #31, 8020c40c <_dtoa_r+0x114c>
    8020be08:	b940a7e1 	ldr	w1, [sp, #164]
    8020be0c:	2a0002e0 	orr	w0, w23, w0
    8020be10:	2a000020 	orr	w0, w1, w0
    8020be14:	34002fc0 	cbz	w0, 8020c40c <_dtoa_r+0x114c>
    8020be18:	7100005f 	cmp	w2, #0x0
    8020be1c:	54ffeb0d 	b.le	8020bb7c <_dtoa_r+0x8bc>
    8020be20:	7100e75f 	cmp	w26, #0x39
    8020be24:	540028a0 	b.eq	8020c338 <_dtoa_r+0x1078>  // b.none
    8020be28:	f9404be2 	ldr	x2, [sp, #144]
    8020be2c:	1100075a 	add	w26, w26, #0x1
    8020be30:	aa1903f7 	mov	x23, x25
    8020be34:	b9408bfc 	ldr	w28, [sp, #136]
    8020be38:	f9403ff9 	ldr	x25, [sp, #120]
    8020be3c:	3800145a 	strb	w26, [x2], #1
    8020be40:	17ffffba 	b	8020bd28 <_dtoa_r+0xa68>
    8020be44:	1e620042 	scvtf	d2, w2
    8020be48:	1e639000 	fmov	d0, #7.000000000000000000e+00
    8020be4c:	52bf9802 	mov	w2, #0xfcc00000            	// #-54525952
    8020be50:	1f410040 	fmadd	d0, d2, d1, d0
    8020be54:	9e660000 	fmov	x0, d0
    8020be58:	d360fc01 	lsr	x1, x0, #32
    8020be5c:	0b020021 	add	w1, w1, w2
    8020be60:	b3607c20 	bfi	x0, x1, #32, #32
    8020be64:	1e629002 	fmov	d2, #5.000000000000000000e+00
    8020be68:	9e670000 	fmov	d0, x0
    8020be6c:	1e623821 	fsub	d1, d1, d2
    8020be70:	1e602030 	fcmpe	d1, d0
    8020be74:	5400066c 	b.gt	8020bf40 <_dtoa_r+0xc80>
    8020be78:	1e614000 	fneg	d0, d0
    8020be7c:	1e602030 	fcmpe	d1, d0
    8020be80:	54fffb64 	b.mi	8020bdec <_dtoa_r+0xb2c>  // b.first
    8020be84:	17fffe33 	b	8020b750 <_dtoa_r+0x490>
    8020be88:	52800380 	mov	w0, #0x1c                  	// #28
    8020be8c:	17fffe7e 	b	8020b884 <_dtoa_r+0x5c4>
    8020be90:	540013e0 	b.eq	8020c10c <_dtoa_r+0xe4c>  // b.none
    8020be94:	b9408be0 	ldr	w0, [sp, #136]
    8020be98:	d0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020be9c:	91150021 	add	x1, x1, #0x540
    8020bea0:	4b0003e0 	neg	w0, w0
    8020bea4:	92400c02 	and	x2, x0, #0xf
    8020bea8:	13047c00 	asr	w0, w0, #4
    8020beac:	fc627822 	ldr	d2, [x1, x2, lsl #3]
    8020beb0:	1e620922 	fmul	d2, d9, d2
    8020beb4:	340029c0 	cbz	w0, 8020c3ec <_dtoa_r+0x112c>
    8020beb8:	1e604041 	fmov	d1, d2
    8020bebc:	d0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020bec0:	91144021 	add	x1, x1, #0x510
    8020bec4:	52800008 	mov	w8, #0x0                   	// #0
    8020bec8:	52800042 	mov	w2, #0x2                   	// #2
    8020becc:	d503201f 	nop
    8020bed0:	360000a0 	tbz	w0, #0, 8020bee4 <_dtoa_r+0xc24>
    8020bed4:	fd400020 	ldr	d0, [x1]
    8020bed8:	11000442 	add	w2, w2, #0x1
    8020bedc:	2a0403e8 	mov	w8, w4
    8020bee0:	1e600821 	fmul	d1, d1, d0
    8020bee4:	13017c00 	asr	w0, w0, #1
    8020bee8:	91002021 	add	x1, x1, #0x8
    8020beec:	35ffff20 	cbnz	w0, 8020bed0 <_dtoa_r+0xc10>
    8020bef0:	7100011f 	cmp	w8, #0x0
    8020bef4:	1e621c21 	fcsel	d1, d1, d2, ne	// ne = any
    8020bef8:	17fffdde 	b	8020b670 <_dtoa_r+0x3b0>
    8020befc:	2a1b03e3 	mov	w3, w27
    8020bf00:	d2800019 	mov	x25, #0x0                   	// #0
    8020bf04:	b9007bff 	str	wzr, [sp, #120]
    8020bf08:	b9008fe7 	str	w7, [sp, #140]
    8020bf0c:	17fffe2e 	b	8020b7c4 <_dtoa_r+0x504>
    8020bf10:	d0000020 	adrp	x0, 80211000 <blanks.1+0x60>
    8020bf14:	91150000 	add	x0, x0, #0x540
    8020bf18:	7100035f 	cmp	w26, #0x0
    8020bf1c:	7a40baa0 	ccmp	w21, #0x0, #0x0, lt	// lt = tstop
    8020bf20:	fc61d801 	ldr	d1, [x0, w1, sxtw #3]
    8020bf24:	540015ec 	b.gt	8020c1e0 <_dtoa_r+0xf20>
    8020bf28:	35fff635 	cbnz	w21, 8020bdec <_dtoa_r+0xb2c>
    8020bf2c:	1e629000 	fmov	d0, #5.000000000000000000e+00
    8020bf30:	1e600821 	fmul	d1, d1, d0
    8020bf34:	9e670380 	fmov	d0, x28
    8020bf38:	1e602030 	fcmpe	d1, d0
    8020bf3c:	54fff58a 	b.ge	8020bdec <_dtoa_r+0xb2c>  // b.tcont
    8020bf40:	aa1603f7 	mov	x23, x22
    8020bf44:	d280001b 	mov	x27, #0x0                   	// #0
    8020bf48:	d2800019 	mov	x25, #0x0                   	// #0
    8020bf4c:	17fffe7b 	b	8020b938 <_dtoa_r+0x678>
    8020bf50:	5280003a 	mov	w26, #0x1                   	// #1
    8020bf54:	2a1a03f5 	mov	w21, w26
    8020bf58:	17fffd96 	b	8020b5b0 <_dtoa_r+0x2f0>
    8020bf5c:	aa0003e1 	mov	x1, x0
    8020bf60:	2a0503e2 	mov	w2, w5
    8020bf64:	aa1303e0 	mov	x0, x19
    8020bf68:	b90093e7 	str	w7, [sp, #144]
    8020bf6c:	b9009be6 	str	w6, [sp, #152]
    8020bf70:	94000d50 	bl	8020f4b0 <__pow5mult>
    8020bf74:	b94093e7 	ldr	w7, [sp, #144]
    8020bf78:	aa0003fb 	mov	x27, x0
    8020bf7c:	b9409be6 	ldr	w6, [sp, #152]
    8020bf80:	710006ff 	cmp	w23, #0x1
    8020bf84:	5400020d 	b.le	8020bfc4 <_dtoa_r+0xd04>
    8020bf88:	52800005 	mov	w5, #0x0                   	// #0
    8020bf8c:	b9401760 	ldr	w0, [x27, #20]
    8020bf90:	b90093e7 	str	w7, [sp, #144]
    8020bf94:	51000400 	sub	w0, w0, #0x1
    8020bf98:	b9009be6 	str	w6, [sp, #152]
    8020bf9c:	b900a7e5 	str	w5, [sp, #164]
    8020bfa0:	8b20cb60 	add	x0, x27, w0, sxtw #2
    8020bfa4:	b9401800 	ldr	w0, [x0, #24]
    8020bfa8:	94000c4e 	bl	8020f0e0 <__hi0bits>
    8020bfac:	52800401 	mov	w1, #0x20                  	// #32
    8020bfb0:	b94093e7 	ldr	w7, [sp, #144]
    8020bfb4:	b9409be6 	ldr	w6, [sp, #152]
    8020bfb8:	4b000020 	sub	w0, w1, w0
    8020bfbc:	b940a7e5 	ldr	w5, [sp, #164]
    8020bfc0:	17fffe28 	b	8020b860 <_dtoa_r+0x5a0>
    8020bfc4:	f240cf9f 	tst	x28, #0xfffffffffffff
    8020bfc8:	54fffe01 	b.ne	8020bf88 <_dtoa_r+0xcc8>  // b.any
    8020bfcc:	d360ff80 	lsr	x0, x28, #32
    8020bfd0:	f26c281f 	tst	x0, #0x7ff00000
    8020bfd4:	54fffda0 	b.eq	8020bf88 <_dtoa_r+0xcc8>  // b.none
    8020bfd8:	110004e7 	add	w7, w7, #0x1
    8020bfdc:	110004c6 	add	w6, w6, #0x1
    8020bfe0:	52800025 	mov	w5, #0x1                   	// #1
    8020bfe4:	17ffffea 	b	8020bf8c <_dtoa_r+0xccc>
    8020bfe8:	1e604121 	fmov	d1, d9
    8020bfec:	52800042 	mov	w2, #0x2                   	// #2
    8020bff0:	17fffd94 	b	8020b640 <_dtoa_r+0x380>
    8020bff4:	b9007bff 	str	wzr, [sp, #120]
    8020bff8:	17fffea7 	b	8020ba94 <_dtoa_r+0x7d4>
    8020bffc:	390002c0 	strb	w0, [x22]
    8020c000:	1e630842 	fmul	d2, d2, d3
    8020c004:	8b2442c0 	add	x0, x22, w4, uxtw
    8020c008:	aa0903e2 	mov	x2, x9
    8020c00c:	1e649003 	fmov	d3, #1.000000000000000000e+01
    8020c010:	7100049f 	cmp	w4, #0x1
    8020c014:	54001c40 	b.eq	8020c39c <_dtoa_r+0x10dc>  // b.none
    8020c018:	1e630821 	fmul	d1, d1, d3
    8020c01c:	1e780021 	fcvtzs	w1, d1
    8020c020:	1e620020 	scvtf	d0, w1
    8020c024:	1100c021 	add	w1, w1, #0x30
    8020c028:	38001441 	strb	w1, [x2], #1
    8020c02c:	1e603821 	fsub	d1, d1, d0
    8020c030:	eb02001f 	cmp	x0, x2
    8020c034:	54ffff21 	b.ne	8020c018 <_dtoa_r+0xd58>  // b.any
    8020c038:	1e6c1000 	fmov	d0, #5.000000000000000000e-01
    8020c03c:	1e602843 	fadd	d3, d2, d0
    8020c040:	1e612070 	fcmpe	d3, d1
    8020c044:	54ffcfa4 	b.mi	8020ba38 <_dtoa_r+0x778>  // b.first
    8020c048:	1e623800 	fsub	d0, d0, d2
    8020c04c:	1e612010 	fcmpe	d0, d1
    8020c050:	5400048c 	b.gt	8020c0e0 <_dtoa_r+0xe20>
    8020c054:	b940bfe0 	ldr	w0, [sp, #188]
    8020c058:	9e66013c 	fmov	x28, d9
    8020c05c:	7100001f 	cmp	w0, #0x0
    8020c060:	b9408be0 	ldr	w0, [sp, #136]
    8020c064:	7a4ea800 	ccmp	w0, #0xe, #0x0, ge	// ge = tcont
    8020c068:	54fff4ac 	b.gt	8020befc <_dtoa_r+0xc3c>
    8020c06c:	b9408be0 	ldr	w0, [sp, #136]
    8020c070:	aa1603f7 	mov	x23, x22
    8020c074:	aa0903f6 	mov	x22, x9
    8020c078:	fc60d901 	ldr	d1, [x8, w0, sxtw #3]
    8020c07c:	1e611920 	fdiv	d0, d9, d1
    8020c080:	51000460 	sub	w0, w3, #0x1
    8020c084:	8b0002c0 	add	x0, x22, x0
    8020c088:	1e649003 	fmov	d3, #1.000000000000000000e+01
    8020c08c:	1e780001 	fcvtzs	w1, d0
    8020c090:	1e620020 	scvtf	d0, w1
    8020c094:	1100c022 	add	w2, w1, #0x30
    8020c098:	390002e2 	strb	w2, [x23]
    8020c09c:	1f41a400 	fmsub	d0, d0, d1, d9
    8020c0a0:	710006bf 	cmp	w21, #0x1
    8020c0a4:	54000141 	b.ne	8020c0cc <_dtoa_r+0xe0c>  // b.any
    8020c0a8:	14000097 	b	8020c304 <_dtoa_r+0x1044>
    8020c0ac:	1e611802 	fdiv	d2, d0, d1
    8020c0b0:	1e780041 	fcvtzs	w1, d2
    8020c0b4:	1e620022 	scvtf	d2, w1
    8020c0b8:	1100c022 	add	w2, w1, #0x30
    8020c0bc:	380016c2 	strb	w2, [x22], #1
    8020c0c0:	1f418040 	fmsub	d0, d2, d1, d0
    8020c0c4:	eb16001f 	cmp	x0, x22
    8020c0c8:	54001200 	b.eq	8020c308 <_dtoa_r+0x1048>  // b.none
    8020c0cc:	1e630800 	fmul	d0, d0, d3
    8020c0d0:	1e602008 	fcmp	d0, #0.0
    8020c0d4:	54fffec1 	b.ne	8020c0ac <_dtoa_r+0xdec>  // b.any
    8020c0d8:	b9408bfc 	ldr	w28, [sp, #136]
    8020c0dc:	17fffe61 	b	8020ba60 <_dtoa_r+0x7a0>
    8020c0e0:	aa0003e2 	mov	x2, x0
    8020c0e4:	385ffc01 	ldrb	w1, [x0, #-1]!
    8020c0e8:	7100c03f 	cmp	w1, #0x30
    8020c0ec:	54ffffa0 	b.eq	8020c0e0 <_dtoa_r+0xe20>  // b.none
    8020c0f0:	aa1603f7 	mov	x23, x22
    8020c0f4:	aa0203f6 	mov	x22, x2
    8020c0f8:	17fffe5a 	b	8020ba60 <_dtoa_r+0x7a0>
    8020c0fc:	52800781 	mov	w1, #0x3c                  	// #60
    8020c100:	4b000020 	sub	w0, w1, w0
    8020c104:	54ffbca0 	b.eq	8020b898 <_dtoa_r+0x5d8>  // b.none
    8020c108:	17fffddf 	b	8020b884 <_dtoa_r+0x5c4>
    8020c10c:	1e604121 	fmov	d1, d9
    8020c110:	52800042 	mov	w2, #0x2                   	// #2
    8020c114:	17fffd57 	b	8020b670 <_dtoa_r+0x3b0>
    8020c118:	34ffe975 	cbz	w21, 8020be44 <_dtoa_r+0xb84>
    8020c11c:	b940abe4 	ldr	w4, [sp, #168]
    8020c120:	7100009f 	cmp	w4, #0x0
    8020c124:	54ffb16d 	b.le	8020b750 <_dtoa_r+0x490>
    8020c128:	11000442 	add	w2, w2, #0x1
    8020c12c:	1e649003 	fmov	d3, #1.000000000000000000e+01
    8020c130:	1e639000 	fmov	d0, #7.000000000000000000e+00
    8020c134:	b9408be0 	ldr	w0, [sp, #136]
    8020c138:	1e620042 	scvtf	d2, w2
    8020c13c:	1e630821 	fmul	d1, d1, d3
    8020c140:	5100041c 	sub	w28, w0, #0x1
    8020c144:	52bf9808 	mov	w8, #0xfcc00000            	// #-54525952
    8020c148:	1f420020 	fmadd	d0, d1, d2, d0
    8020c14c:	9e660000 	fmov	x0, d0
    8020c150:	d360fc01 	lsr	x1, x0, #32
    8020c154:	0b080021 	add	w1, w1, w8
    8020c158:	b3607c20 	bfi	x0, x1, #32, #32
    8020c15c:	17fffd55 	b	8020b6b0 <_dtoa_r+0x3f0>
    8020c160:	b940a7e1 	ldr	w1, [sp, #164]
    8020c164:	34000981 	cbz	w1, 8020c294 <_dtoa_r+0xfd4>
    8020c168:	1110cc00 	add	w0, w0, #0x433
    8020c16c:	2a1b03e3 	mov	w3, w27
    8020c170:	0b0000c6 	add	w6, w6, w0
    8020c174:	b9008fe7 	str	w7, [sp, #140]
    8020c178:	0b0000e7 	add	w7, w7, w0
    8020c17c:	17fffd86 	b	8020b794 <_dtoa_r+0x4d4>
    8020c180:	9136c2f7 	add	x23, x23, #0xdb0
    8020c184:	17fffc82 	b	8020b38c <_dtoa_r+0xcc>
    8020c188:	913682f7 	add	x23, x23, #0xda0
    8020c18c:	17fffc80 	b	8020b38c <_dtoa_r+0xcc>
    8020c190:	aa1403e1 	mov	x1, x20
    8020c194:	2a1b03e2 	mov	w2, w27
    8020c198:	aa1303e0 	mov	x0, x19
    8020c19c:	b90093e7 	str	w7, [sp, #144]
    8020c1a0:	b9009be6 	str	w6, [sp, #152]
    8020c1a4:	b900a7e5 	str	w5, [sp, #164]
    8020c1a8:	94000cc2 	bl	8020f4b0 <__pow5mult>
    8020c1ac:	b94093e7 	ldr	w7, [sp, #144]
    8020c1b0:	aa0003f4 	mov	x20, x0
    8020c1b4:	b9409be6 	ldr	w6, [sp, #152]
    8020c1b8:	b940a7e5 	ldr	w5, [sp, #164]
    8020c1bc:	17fffd9b 	b	8020b828 <_dtoa_r+0x568>
    8020c1c0:	4b1b0060 	sub	w0, w3, w27
    8020c1c4:	0b1500c6 	add	w6, w6, w21
    8020c1c8:	2a0303fb 	mov	w27, w3
    8020c1cc:	0b0000a5 	add	w5, w5, w0
    8020c1d0:	52800003 	mov	w3, #0x0                   	// #0
    8020c1d4:	b9008fe7 	str	w7, [sp, #140]
    8020c1d8:	0b0702a7 	add	w7, w21, w7
    8020c1dc:	17fffd6e 	b	8020b794 <_dtoa_r+0x4d4>
    8020c1e0:	aa1603f7 	mov	x23, x22
    8020c1e4:	9e670389 	fmov	d9, x28
    8020c1e8:	910006d6 	add	x22, x22, #0x1
    8020c1ec:	17ffffa4 	b	8020c07c <_dtoa_r+0xdbc>
    8020c1f0:	54000041 	b.ne	8020c1f8 <_dtoa_r+0xf38>  // b.any
    8020c1f4:	3707d8ba 	tbnz	w26, #0, 8020bd08 <_dtoa_r+0xa48>
    8020c1f8:	aa1503e2 	mov	x2, x21
    8020c1fc:	d10006b5 	sub	x21, x21, #0x1
    8020c200:	385ff040 	ldurb	w0, [x2, #-1]
    8020c204:	7100c01f 	cmp	w0, #0x30
    8020c208:	54ffff80 	b.eq	8020c1f8 <_dtoa_r+0xf38>  // b.none
    8020c20c:	b9408bfc 	ldr	w28, [sp, #136]
    8020c210:	17fffec6 	b	8020bd28 <_dtoa_r+0xa68>
    8020c214:	b9408be0 	ldr	w0, [sp, #136]
    8020c218:	1100041c 	add	w28, w0, #0x1
    8020c21c:	52800620 	mov	w0, #0x31                  	// #49
    8020c220:	390002c0 	strb	w0, [x22]
    8020c224:	17fffec1 	b	8020bd28 <_dtoa_r+0xa68>
    8020c228:	2a0303e2 	mov	w2, w3
    8020c22c:	aa1903e1 	mov	x1, x25
    8020c230:	aa1303e0 	mov	x0, x19
    8020c234:	b90093e3 	str	w3, [sp, #144]
    8020c238:	b9009be7 	str	w7, [sp, #152]
    8020c23c:	b900a7e6 	str	w6, [sp, #164]
    8020c240:	b900afe5 	str	w5, [sp, #172]
    8020c244:	94000c9b 	bl	8020f4b0 <__pow5mult>
    8020c248:	aa1403e2 	mov	x2, x20
    8020c24c:	aa0003f9 	mov	x25, x0
    8020c250:	aa1903e1 	mov	x1, x25
    8020c254:	aa1303e0 	mov	x0, x19
    8020c258:	94000c1a 	bl	8020f2c0 <__multiply>
    8020c25c:	aa1403e1 	mov	x1, x20
    8020c260:	aa0003f4 	mov	x20, x0
    8020c264:	aa1303e0 	mov	x0, x19
    8020c268:	94000b06 	bl	8020ee80 <_Bfree>
    8020c26c:	b94093e3 	ldr	w3, [sp, #144]
    8020c270:	b9409be7 	ldr	w7, [sp, #152]
    8020c274:	b940a7e6 	ldr	w6, [sp, #164]
    8020c278:	6b03037b 	subs	w27, w27, w3
    8020c27c:	b940afe5 	ldr	w5, [sp, #172]
    8020c280:	54ffad40 	b.eq	8020b828 <_dtoa_r+0x568>  // b.none
    8020c284:	17fffd5e 	b	8020b7fc <_dtoa_r+0x53c>
    8020c288:	1100079c 	add	w28, w28, #0x1
    8020c28c:	52800621 	mov	w1, #0x31                  	// #49
    8020c290:	17fffdf0 	b	8020ba50 <_dtoa_r+0x790>
    8020c294:	b940bbe1 	ldr	w1, [sp, #184]
    8020c298:	528006c0 	mov	w0, #0x36                  	// #54
    8020c29c:	2a1b03e3 	mov	w3, w27
    8020c2a0:	b9008fe7 	str	w7, [sp, #140]
    8020c2a4:	4b010000 	sub	w0, w0, w1
    8020c2a8:	0b0000c6 	add	w6, w6, w0
    8020c2ac:	0b0000e7 	add	w7, w7, w0
    8020c2b0:	17fffd39 	b	8020b794 <_dtoa_r+0x4d4>
    8020c2b4:	b9400b21 	ldr	w1, [x25, #8]
    8020c2b8:	aa1303e0 	mov	x0, x19
    8020c2bc:	94000acd 	bl	8020edf0 <_Balloc>
    8020c2c0:	aa0003fa 	mov	x26, x0
    8020c2c4:	b4000aa0 	cbz	x0, 8020c418 <_dtoa_r+0x1158>
    8020c2c8:	b9801722 	ldrsw	x2, [x25, #20]
    8020c2cc:	91004321 	add	x1, x25, #0x10
    8020c2d0:	91004000 	add	x0, x0, #0x10
    8020c2d4:	91000842 	add	x2, x2, #0x2
    8020c2d8:	d37ef442 	lsl	x2, x2, #2
    8020c2dc:	97fffae9 	bl	8020ae80 <memcpy>
    8020c2e0:	aa1a03e1 	mov	x1, x26
    8020c2e4:	aa1303e0 	mov	x0, x19
    8020c2e8:	52800022 	mov	w2, #0x1                   	// #1
    8020c2ec:	94000cb9 	bl	8020f5d0 <__lshift>
    8020c2f0:	f9003fe0 	str	x0, [sp, #120]
    8020c2f4:	17fffdff 	b	8020baf0 <_dtoa_r+0x830>
    8020c2f8:	aa1603f7 	mov	x23, x22
    8020c2fc:	aa0003f6 	mov	x22, x0
    8020c300:	17fffdd8 	b	8020ba60 <_dtoa_r+0x7a0>
    8020c304:	aa1603e0 	mov	x0, x22
    8020c308:	1e602800 	fadd	d0, d0, d0
    8020c30c:	1e612010 	fcmpe	d0, d1
    8020c310:	5400020c 	b.gt	8020c350 <_dtoa_r+0x1090>
    8020c314:	1e612000 	fcmp	d0, d1
    8020c318:	54000041 	b.ne	8020c320 <_dtoa_r+0x1060>  // b.any
    8020c31c:	370001a1 	tbnz	w1, #0, 8020c350 <_dtoa_r+0x1090>
    8020c320:	b9408bfc 	ldr	w28, [sp, #136]
    8020c324:	aa0003f6 	mov	x22, x0
    8020c328:	17fffdce 	b	8020ba60 <_dtoa_r+0x7a0>
    8020c32c:	aa1903f7 	mov	x23, x25
    8020c330:	f9403ff9 	ldr	x25, [sp, #120]
    8020c334:	17fffe69 	b	8020bcd8 <_dtoa_r+0xa18>
    8020c338:	f9404bf5 	ldr	x21, [sp, #144]
    8020c33c:	aa1903f7 	mov	x23, x25
    8020c340:	f9403ff9 	ldr	x25, [sp, #120]
    8020c344:	52800720 	mov	w0, #0x39                  	// #57
    8020c348:	380016a0 	strb	w0, [x21], #1
    8020c34c:	17fffe6f 	b	8020bd08 <_dtoa_r+0xa48>
    8020c350:	b9408bfc 	ldr	w28, [sp, #136]
    8020c354:	aa1703f6 	mov	x22, x23
    8020c358:	17fffdb8 	b	8020ba38 <_dtoa_r+0x778>
    8020c35c:	0b1500c6 	add	w6, w6, w21
    8020c360:	b9008fe7 	str	w7, [sp, #140]
    8020c364:	0b0702a7 	add	w7, w21, w7
    8020c368:	17fffd0b 	b	8020b794 <_dtoa_r+0x4d4>
    8020c36c:	7100e75f 	cmp	w26, #0x39
    8020c370:	54fffe40 	b.eq	8020c338 <_dtoa_r+0x1078>  // b.none
    8020c374:	f9404be2 	ldr	x2, [sp, #144]
    8020c378:	aa1903f7 	mov	x23, x25
    8020c37c:	295107fc 	ldp	w28, w1, [sp, #136]
    8020c380:	b940a3e0 	ldr	w0, [sp, #160]
    8020c384:	7100003f 	cmp	w1, #0x0
    8020c388:	1100c400 	add	w0, w0, #0x31
    8020c38c:	f9403ff9 	ldr	x25, [sp, #120]
    8020c390:	1a9ac01a 	csel	w26, w0, w26, gt
    8020c394:	3800145a 	strb	w26, [x2], #1
    8020c398:	17fffe64 	b	8020bd28 <_dtoa_r+0xa68>
    8020c39c:	aa0903e0 	mov	x0, x9
    8020c3a0:	17ffff26 	b	8020c038 <_dtoa_r+0xd78>
    8020c3a4:	aa1903e1 	mov	x1, x25
    8020c3a8:	aa1303e0 	mov	x0, x19
    8020c3ac:	52800003 	mov	w3, #0x0                   	// #0
    8020c3b0:	52800142 	mov	w2, #0xa                   	// #10
    8020c3b4:	b9007be5 	str	w5, [sp, #120]
    8020c3b8:	b90093e4 	str	w4, [sp, #144]
    8020c3bc:	94000ab9 	bl	8020eea0 <__multadd>
    8020c3c0:	b940abf5 	ldr	w21, [sp, #168]
    8020c3c4:	aa0003f9 	mov	x25, x0
    8020c3c8:	b94093e4 	ldr	w4, [sp, #144]
    8020c3cc:	710002bf 	cmp	w21, #0x0
    8020c3d0:	7a40d884 	ccmp	w4, #0x0, #0x4, le
    8020c3d4:	54000121 	b.ne	8020c3f8 <_dtoa_r+0x1138>  // b.any
    8020c3d8:	b9407be5 	ldr	w5, [sp, #120]
    8020c3dc:	17fffdba 	b	8020bac4 <_dtoa_r+0x804>
    8020c3e0:	54ffcf21 	b.ne	8020bdc4 <_dtoa_r+0xb04>  // b.any
    8020c3e4:	3707ce9a 	tbnz	w26, #0, 8020bdb4 <_dtoa_r+0xaf4>
    8020c3e8:	17fffe77 	b	8020bdc4 <_dtoa_r+0xb04>
    8020c3ec:	1e604041 	fmov	d1, d2
    8020c3f0:	52800042 	mov	w2, #0x2                   	// #2
    8020c3f4:	17fffc9f 	b	8020b670 <_dtoa_r+0x3b0>
    8020c3f8:	b940abf5 	ldr	w21, [sp, #168]
    8020c3fc:	17fffd42 	b	8020b904 <_dtoa_r+0x644>
    8020c400:	aa1603f7 	mov	x23, x22
    8020c404:	aa0903f6 	mov	x22, x9
    8020c408:	17fffd96 	b	8020ba60 <_dtoa_r+0x7a0>
    8020c40c:	7100005f 	cmp	w2, #0x0
    8020c410:	54ffcc0c 	b.gt	8020bd90 <_dtoa_r+0xad0>
    8020c414:	17fffe6c 	b	8020bdc4 <_dtoa_r+0xb04>
    8020c418:	90000023 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020c41c:	90000020 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020c420:	9136e063 	add	x3, x3, #0xdb8
    8020c424:	91374000 	add	x0, x0, #0xdd0
    8020c428:	d2800002 	mov	x2, #0x0                   	// #0
    8020c42c:	52805de1 	mov	w1, #0x2ef                 	// #751
    8020c430:	94000a14 	bl	8020ec80 <__assert_func>
    8020c434:	90000023 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020c438:	90000020 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020c43c:	9136e063 	add	x3, x3, #0xdb8
    8020c440:	91374000 	add	x0, x0, #0xdd0
    8020c444:	d2800002 	mov	x2, #0x0                   	// #0
    8020c448:	528035e1 	mov	w1, #0x1af                 	// #431
    8020c44c:	94000a0d 	bl	8020ec80 <__assert_func>
    8020c450:	b9007bff 	str	wzr, [sp, #120]
    8020c454:	17fffc23 	b	8020b4e0 <_dtoa_r+0x220>
	...

000000008020c460 <__set_ctype>:
    8020c460:	b0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020c464:	910c8021 	add	x1, x1, #0x320
    8020c468:	f9007c01 	str	x1, [x0, #248]
    8020c46c:	d65f03c0 	ret

000000008020c470 <_close_r>:
    8020c470:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020c474:	910003fd 	mov	x29, sp
    8020c478:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c47c:	b00003b4 	adrp	x20, 80281000 <__sf+0x38>
    8020c480:	aa0003f3 	mov	x19, x0
    8020c484:	b9044a9f 	str	wzr, [x20, #1096]
    8020c488:	2a0103e0 	mov	w0, w1
    8020c48c:	97ffd135 	bl	80200960 <_close>
    8020c490:	3100041f 	cmn	w0, #0x1
    8020c494:	54000080 	b.eq	8020c4a4 <_close_r+0x34>  // b.none
    8020c498:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c49c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020c4a0:	d65f03c0 	ret
    8020c4a4:	b9444a81 	ldr	w1, [x20, #1096]
    8020c4a8:	34ffff81 	cbz	w1, 8020c498 <_close_r+0x28>
    8020c4ac:	b9000261 	str	w1, [x19]
    8020c4b0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c4b4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020c4b8:	d65f03c0 	ret
    8020c4bc:	00000000 	udf	#0

000000008020c4c0 <_reclaim_reent>:
    8020c4c0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020c4c4:	b0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020c4c8:	910003fd 	mov	x29, sp
    8020c4cc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c4d0:	aa0003f4 	mov	x20, x0
    8020c4d4:	f9438820 	ldr	x0, [x1, #1808]
    8020c4d8:	eb14001f 	cmp	x0, x20
    8020c4dc:	54000440 	b.eq	8020c564 <_reclaim_reent+0xa4>  // b.none
    8020c4e0:	f9403681 	ldr	x1, [x20, #104]
    8020c4e4:	b4000221 	cbz	x1, 8020c528 <_reclaim_reent+0x68>
    8020c4e8:	f90013f5 	str	x21, [sp, #32]
    8020c4ec:	d2800015 	mov	x21, #0x0                   	// #0
    8020c4f0:	f8756833 	ldr	x19, [x1, x21]
    8020c4f4:	b40000f3 	cbz	x19, 8020c510 <_reclaim_reent+0x50>
    8020c4f8:	aa1303e1 	mov	x1, x19
    8020c4fc:	aa1403e0 	mov	x0, x20
    8020c500:	f9400273 	ldr	x19, [x19]
    8020c504:	940002bf 	bl	8020d000 <_free_r>
    8020c508:	b5ffff93 	cbnz	x19, 8020c4f8 <_reclaim_reent+0x38>
    8020c50c:	f9403681 	ldr	x1, [x20, #104]
    8020c510:	910022b5 	add	x21, x21, #0x8
    8020c514:	f10802bf 	cmp	x21, #0x200
    8020c518:	54fffec1 	b.ne	8020c4f0 <_reclaim_reent+0x30>  // b.any
    8020c51c:	aa1403e0 	mov	x0, x20
    8020c520:	940002b8 	bl	8020d000 <_free_r>
    8020c524:	f94013f5 	ldr	x21, [sp, #32]
    8020c528:	f9402a81 	ldr	x1, [x20, #80]
    8020c52c:	b4000061 	cbz	x1, 8020c538 <_reclaim_reent+0x78>
    8020c530:	aa1403e0 	mov	x0, x20
    8020c534:	940002b3 	bl	8020d000 <_free_r>
    8020c538:	f9403e81 	ldr	x1, [x20, #120]
    8020c53c:	b4000061 	cbz	x1, 8020c548 <_reclaim_reent+0x88>
    8020c540:	aa1403e0 	mov	x0, x20
    8020c544:	940002af 	bl	8020d000 <_free_r>
    8020c548:	f9402681 	ldr	x1, [x20, #72]
    8020c54c:	b40000c1 	cbz	x1, 8020c564 <_reclaim_reent+0xa4>
    8020c550:	aa1403e0 	mov	x0, x20
    8020c554:	aa0103f0 	mov	x16, x1
    8020c558:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c55c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020c560:	d61f0200 	br	x16
    8020c564:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c568:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020c56c:	d65f03c0 	ret

000000008020c570 <__sflush_r>:
    8020c570:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020c574:	910003fd 	mov	x29, sp
    8020c578:	79c02022 	ldrsh	w2, [x1, #16]
    8020c57c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c580:	aa0103f3 	mov	x19, x1
    8020c584:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020c588:	aa0003f6 	mov	x22, x0
    8020c58c:	371807e2 	tbnz	w2, #3, 8020c688 <__sflush_r+0x118>
    8020c590:	32150040 	orr	w0, w2, #0x800
    8020c594:	79002020 	strh	w0, [x1, #16]
    8020c598:	b9400821 	ldr	w1, [x1, #8]
    8020c59c:	7100003f 	cmp	w1, #0x0
    8020c5a0:	54000b8d 	b.le	8020c710 <__sflush_r+0x1a0>
    8020c5a4:	f9402664 	ldr	x4, [x19, #72]
    8020c5a8:	b4000664 	cbz	x4, 8020c674 <__sflush_r+0x104>
    8020c5ac:	f9401a61 	ldr	x1, [x19, #48]
    8020c5b0:	b94002d4 	ldr	w20, [x22]
    8020c5b4:	b90002df 	str	wzr, [x22]
    8020c5b8:	37600b62 	tbnz	w2, #12, 8020c724 <__sflush_r+0x1b4>
    8020c5bc:	d2800002 	mov	x2, #0x0                   	// #0
    8020c5c0:	aa1603e0 	mov	x0, x22
    8020c5c4:	52800023 	mov	w3, #0x1                   	// #1
    8020c5c8:	d63f0080 	blr	x4
    8020c5cc:	aa0003e2 	mov	x2, x0
    8020c5d0:	b100041f 	cmn	x0, #0x1
    8020c5d4:	54000be0 	b.eq	8020c750 <__sflush_r+0x1e0>  // b.none
    8020c5d8:	f9401a61 	ldr	x1, [x19, #48]
    8020c5dc:	f9402664 	ldr	x4, [x19, #72]
    8020c5e0:	79c02260 	ldrsh	w0, [x19, #16]
    8020c5e4:	361000e0 	tbz	w0, #2, 8020c600 <__sflush_r+0x90>
    8020c5e8:	f9402e60 	ldr	x0, [x19, #88]
    8020c5ec:	b9800a63 	ldrsw	x3, [x19, #8]
    8020c5f0:	cb030042 	sub	x2, x2, x3
    8020c5f4:	b4000060 	cbz	x0, 8020c600 <__sflush_r+0x90>
    8020c5f8:	b9807260 	ldrsw	x0, [x19, #112]
    8020c5fc:	cb000042 	sub	x2, x2, x0
    8020c600:	aa1603e0 	mov	x0, x22
    8020c604:	52800003 	mov	w3, #0x0                   	// #0
    8020c608:	d63f0080 	blr	x4
    8020c60c:	b100041f 	cmn	x0, #0x1
    8020c610:	540008e1 	b.ne	8020c72c <__sflush_r+0x1bc>  // b.any
    8020c614:	b94002c3 	ldr	w3, [x22]
    8020c618:	79c02261 	ldrsh	w1, [x19, #16]
    8020c61c:	7100747f 	cmp	w3, #0x1d
    8020c620:	540006a8 	b.hi	8020c6f4 <__sflush_r+0x184>  // b.pmore
    8020c624:	d2800022 	mov	x2, #0x1                   	// #1
    8020c628:	f2a40802 	movk	x2, #0x2040, lsl #16
    8020c62c:	9ac32442 	lsr	x2, x2, x3
    8020c630:	36000622 	tbz	w2, #0, 8020c6f4 <__sflush_r+0x184>
    8020c634:	f9400e64 	ldr	x4, [x19, #24]
    8020c638:	12147822 	and	w2, w1, #0xfffff7ff
    8020c63c:	f9000264 	str	x4, [x19]
    8020c640:	b9000a7f 	str	wzr, [x19, #8]
    8020c644:	79002262 	strh	w2, [x19, #16]
    8020c648:	36600041 	tbz	w1, #12, 8020c650 <__sflush_r+0xe0>
    8020c64c:	340007e3 	cbz	w3, 8020c748 <__sflush_r+0x1d8>
    8020c650:	f9402e61 	ldr	x1, [x19, #88]
    8020c654:	b90002d4 	str	w20, [x22]
    8020c658:	b40000e1 	cbz	x1, 8020c674 <__sflush_r+0x104>
    8020c65c:	9101d260 	add	x0, x19, #0x74
    8020c660:	eb00003f 	cmp	x1, x0
    8020c664:	54000060 	b.eq	8020c670 <__sflush_r+0x100>  // b.none
    8020c668:	aa1603e0 	mov	x0, x22
    8020c66c:	94000265 	bl	8020d000 <_free_r>
    8020c670:	f9002e7f 	str	xzr, [x19, #88]
    8020c674:	52800000 	mov	w0, #0x0                   	// #0
    8020c678:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c67c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020c680:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020c684:	d65f03c0 	ret
    8020c688:	f9400c35 	ldr	x21, [x1, #24]
    8020c68c:	b4ffff55 	cbz	x21, 8020c674 <__sflush_r+0x104>
    8020c690:	f9400021 	ldr	x1, [x1]
    8020c694:	f9000275 	str	x21, [x19]
    8020c698:	52800000 	mov	w0, #0x0                   	// #0
    8020c69c:	cb150021 	sub	x1, x1, x21
    8020c6a0:	2a0103f4 	mov	w20, w1
    8020c6a4:	f240045f 	tst	x2, #0x3
    8020c6a8:	54000041 	b.ne	8020c6b0 <__sflush_r+0x140>  // b.any
    8020c6ac:	b9402260 	ldr	w0, [x19, #32]
    8020c6b0:	b9000e60 	str	w0, [x19, #12]
    8020c6b4:	7100003f 	cmp	w1, #0x0
    8020c6b8:	540000ac 	b.gt	8020c6cc <__sflush_r+0x15c>
    8020c6bc:	17ffffee 	b	8020c674 <__sflush_r+0x104>
    8020c6c0:	8b20c2b5 	add	x21, x21, w0, sxtw
    8020c6c4:	7100029f 	cmp	w20, #0x0
    8020c6c8:	54fffd6d 	b.le	8020c674 <__sflush_r+0x104>
    8020c6cc:	f9401a61 	ldr	x1, [x19, #48]
    8020c6d0:	2a1403e3 	mov	w3, w20
    8020c6d4:	f9402264 	ldr	x4, [x19, #64]
    8020c6d8:	aa1503e2 	mov	x2, x21
    8020c6dc:	aa1603e0 	mov	x0, x22
    8020c6e0:	d63f0080 	blr	x4
    8020c6e4:	4b000294 	sub	w20, w20, w0
    8020c6e8:	7100001f 	cmp	w0, #0x0
    8020c6ec:	54fffeac 	b.gt	8020c6c0 <__sflush_r+0x150>
    8020c6f0:	79c02261 	ldrsh	w1, [x19, #16]
    8020c6f4:	321a0021 	orr	w1, w1, #0x40
    8020c6f8:	79002261 	strh	w1, [x19, #16]
    8020c6fc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c700:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020c704:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020c708:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020c70c:	d65f03c0 	ret
    8020c710:	b9407261 	ldr	w1, [x19, #112]
    8020c714:	7100003f 	cmp	w1, #0x0
    8020c718:	54fff46c 	b.gt	8020c5a4 <__sflush_r+0x34>
    8020c71c:	52800000 	mov	w0, #0x0                   	// #0
    8020c720:	17ffffd6 	b	8020c678 <__sflush_r+0x108>
    8020c724:	f9404a62 	ldr	x2, [x19, #144]
    8020c728:	17ffffaf 	b	8020c5e4 <__sflush_r+0x74>
    8020c72c:	79c02261 	ldrsh	w1, [x19, #16]
    8020c730:	f9400e63 	ldr	x3, [x19, #24]
    8020c734:	12147822 	and	w2, w1, #0xfffff7ff
    8020c738:	f9000263 	str	x3, [x19]
    8020c73c:	b9000a7f 	str	wzr, [x19, #8]
    8020c740:	79002262 	strh	w2, [x19, #16]
    8020c744:	3667f861 	tbz	w1, #12, 8020c650 <__sflush_r+0xe0>
    8020c748:	f9004a60 	str	x0, [x19, #144]
    8020c74c:	17ffffc1 	b	8020c650 <__sflush_r+0xe0>
    8020c750:	b94002c0 	ldr	w0, [x22]
    8020c754:	34fff420 	cbz	w0, 8020c5d8 <__sflush_r+0x68>
    8020c758:	7100741f 	cmp	w0, #0x1d
    8020c75c:	7a561804 	ccmp	w0, #0x16, #0x4, ne	// ne = any
    8020c760:	54fffc81 	b.ne	8020c6f0 <__sflush_r+0x180>  // b.any
    8020c764:	52800000 	mov	w0, #0x0                   	// #0
    8020c768:	b90002d4 	str	w20, [x22]
    8020c76c:	17ffffc3 	b	8020c678 <__sflush_r+0x108>

000000008020c770 <_fflush_r>:
    8020c770:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020c774:	910003fd 	mov	x29, sp
    8020c778:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c77c:	aa0103f3 	mov	x19, x1
    8020c780:	aa0003f4 	mov	x20, x0
    8020c784:	f90013f5 	str	x21, [sp, #32]
    8020c788:	b4000060 	cbz	x0, 8020c794 <_fflush_r+0x24>
    8020c78c:	f9402401 	ldr	x1, [x0, #72]
    8020c790:	b4000481 	cbz	x1, 8020c820 <_fflush_r+0xb0>
    8020c794:	79c02260 	ldrsh	w0, [x19, #16]
    8020c798:	52800015 	mov	w21, #0x0                   	// #0
    8020c79c:	34000180 	cbz	w0, 8020c7cc <_fflush_r+0x5c>
    8020c7a0:	b940b261 	ldr	w1, [x19, #176]
    8020c7a4:	37000041 	tbnz	w1, #0, 8020c7ac <_fflush_r+0x3c>
    8020c7a8:	364801c0 	tbz	w0, #9, 8020c7e0 <_fflush_r+0x70>
    8020c7ac:	aa1303e1 	mov	x1, x19
    8020c7b0:	aa1403e0 	mov	x0, x20
    8020c7b4:	97ffff6f 	bl	8020c570 <__sflush_r>
    8020c7b8:	2a0003f5 	mov	w21, w0
    8020c7bc:	b940b261 	ldr	w1, [x19, #176]
    8020c7c0:	37000061 	tbnz	w1, #0, 8020c7cc <_fflush_r+0x5c>
    8020c7c4:	79402260 	ldrh	w0, [x19, #16]
    8020c7c8:	364801e0 	tbz	w0, #9, 8020c804 <_fflush_r+0x94>
    8020c7cc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c7d0:	2a1503e0 	mov	w0, w21
    8020c7d4:	f94013f5 	ldr	x21, [sp, #32]
    8020c7d8:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020c7dc:	d65f03c0 	ret
    8020c7e0:	f9405260 	ldr	x0, [x19, #160]
    8020c7e4:	97fff4f7 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    8020c7e8:	aa1303e1 	mov	x1, x19
    8020c7ec:	aa1403e0 	mov	x0, x20
    8020c7f0:	97ffff60 	bl	8020c570 <__sflush_r>
    8020c7f4:	2a0003f5 	mov	w21, w0
    8020c7f8:	b940b261 	ldr	w1, [x19, #176]
    8020c7fc:	3707fe81 	tbnz	w1, #0, 8020c7cc <_fflush_r+0x5c>
    8020c800:	17fffff1 	b	8020c7c4 <_fflush_r+0x54>
    8020c804:	f9405260 	ldr	x0, [x19, #160]
    8020c808:	97fff4fe 	bl	80209c00 <__retarget_lock_release_recursive>
    8020c80c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c810:	2a1503e0 	mov	w0, w21
    8020c814:	f94013f5 	ldr	x21, [sp, #32]
    8020c818:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020c81c:	d65f03c0 	ret
    8020c820:	97ffdb6c 	bl	802035d0 <__sinit>
    8020c824:	17ffffdc 	b	8020c794 <_fflush_r+0x24>
	...

000000008020c830 <fflush>:
    8020c830:	b40004e0 	cbz	x0, 8020c8cc <fflush+0x9c>
    8020c834:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020c838:	910003fd 	mov	x29, sp
    8020c83c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c840:	aa0003f3 	mov	x19, x0
    8020c844:	b0000020 	adrp	x0, 80211000 <blanks.1+0x60>
    8020c848:	f90013f5 	str	x21, [sp, #32]
    8020c84c:	f9438815 	ldr	x21, [x0, #1808]
    8020c850:	b4000075 	cbz	x21, 8020c85c <fflush+0x2c>
    8020c854:	f94026a0 	ldr	x0, [x21, #72]
    8020c858:	b4000280 	cbz	x0, 8020c8a8 <fflush+0x78>
    8020c85c:	79c02260 	ldrsh	w0, [x19, #16]
    8020c860:	52800014 	mov	w20, #0x0                   	// #0
    8020c864:	34000180 	cbz	w0, 8020c894 <fflush+0x64>
    8020c868:	b940b261 	ldr	w1, [x19, #176]
    8020c86c:	37000041 	tbnz	w1, #0, 8020c874 <fflush+0x44>
    8020c870:	36480220 	tbz	w0, #9, 8020c8b4 <fflush+0x84>
    8020c874:	aa1303e1 	mov	x1, x19
    8020c878:	aa1503e0 	mov	x0, x21
    8020c87c:	97ffff3d 	bl	8020c570 <__sflush_r>
    8020c880:	2a0003f4 	mov	w20, w0
    8020c884:	b940b261 	ldr	w1, [x19, #176]
    8020c888:	37000061 	tbnz	w1, #0, 8020c894 <fflush+0x64>
    8020c88c:	79402260 	ldrh	w0, [x19, #16]
    8020c890:	36480180 	tbz	w0, #9, 8020c8c0 <fflush+0x90>
    8020c894:	f94013f5 	ldr	x21, [sp, #32]
    8020c898:	2a1403e0 	mov	w0, w20
    8020c89c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020c8a0:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020c8a4:	d65f03c0 	ret
    8020c8a8:	aa1503e0 	mov	x0, x21
    8020c8ac:	97ffdb49 	bl	802035d0 <__sinit>
    8020c8b0:	17ffffeb 	b	8020c85c <fflush+0x2c>
    8020c8b4:	f9405260 	ldr	x0, [x19, #160]
    8020c8b8:	97fff4c2 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    8020c8bc:	17ffffee 	b	8020c874 <fflush+0x44>
    8020c8c0:	f9405260 	ldr	x0, [x19, #160]
    8020c8c4:	97fff4cf 	bl	80209c00 <__retarget_lock_release_recursive>
    8020c8c8:	17fffff3 	b	8020c894 <fflush+0x64>
    8020c8cc:	b0000022 	adrp	x2, 80211000 <blanks.1+0x60>
    8020c8d0:	90000001 	adrp	x1, 8020c000 <_dtoa_r+0xd40>
    8020c8d4:	b0000020 	adrp	x0, 80211000 <blanks.1+0x60>
    8020c8d8:	9121c042 	add	x2, x2, #0x870
    8020c8dc:	911dc021 	add	x1, x1, #0x770
    8020c8e0:	911c6000 	add	x0, x0, #0x718
    8020c8e4:	17ffdd87 	b	80203f00 <_fwalk_sglue>
	...

000000008020c8f0 <frexp>:
    8020c8f0:	9e660002 	fmov	x2, d0
    8020c8f4:	b900001f 	str	wzr, [x0]
    8020c8f8:	12b00204 	mov	w4, #0x7fefffff            	// #2146435071
    8020c8fc:	d360f841 	ubfx	x1, x2, #32, #31
    8020c900:	d360fc43 	lsr	x3, x2, #32
    8020c904:	6b04003f 	cmp	w1, w4
    8020c908:	540002e8 	b.hi	8020c964 <frexp+0x74>  // b.pmore
    8020c90c:	2a020022 	orr	w2, w1, w2
    8020c910:	340002a2 	cbz	w2, 8020c964 <frexp+0x74>
    8020c914:	52800004 	mov	w4, #0x0                   	// #0
    8020c918:	f26c287f 	tst	x3, #0x7ff00000
    8020c91c:	54000121 	b.ne	8020c940 <frexp+0x50>  // b.any
    8020c920:	d2e86a01 	mov	x1, #0x4350000000000000    	// #4850376798678024192
    8020c924:	9e670021 	fmov	d1, x1
    8020c928:	128006a4 	mov	w4, #0xffffffca            	// #-54
    8020c92c:	1e610800 	fmul	d0, d0, d1
    8020c930:	9e660001 	fmov	x1, d0
    8020c934:	d360fc21 	lsr	x1, x1, #32
    8020c938:	2a0103e3 	mov	w3, w1
    8020c93c:	12007821 	and	w1, w1, #0x7fffffff
    8020c940:	9e660002 	fmov	x2, d0
    8020c944:	12015063 	and	w3, w3, #0x800fffff
    8020c948:	13147c21 	asr	w1, w1, #20
    8020c94c:	320b2063 	orr	w3, w3, #0x3fe00000
    8020c950:	510ff821 	sub	w1, w1, #0x3fe
    8020c954:	0b040021 	add	w1, w1, w4
    8020c958:	b9000001 	str	w1, [x0]
    8020c95c:	b3607c62 	bfi	x2, x3, #32, #32
    8020c960:	9e670040 	fmov	d0, x2
    8020c964:	d65f03c0 	ret
	...

000000008020c970 <_realloc_r>:
    8020c970:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
    8020c974:	910003fd 	mov	x29, sp
    8020c978:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020c97c:	aa0203f5 	mov	x21, x2
    8020c980:	b4001021 	cbz	x1, 8020cb84 <_realloc_r+0x214>
    8020c984:	a90153f3 	stp	x19, x20, [sp, #16]
    8020c988:	aa0103f3 	mov	x19, x1
    8020c98c:	aa0003f6 	mov	x22, x0
    8020c990:	a90363f7 	stp	x23, x24, [sp, #48]
    8020c994:	d1004278 	sub	x24, x19, #0x10
    8020c998:	91005eb4 	add	x20, x21, #0x17
    8020c99c:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020c9a0:	97fff9c4 	bl	8020b0b0 <__malloc_lock>
    8020c9a4:	aa1803f9 	mov	x25, x24
    8020c9a8:	f9400700 	ldr	x0, [x24, #8]
    8020c9ac:	927ef417 	and	x23, x0, #0xfffffffffffffffc
    8020c9b0:	f100ba9f 	cmp	x20, #0x2e
    8020c9b4:	54000908 	b.hi	8020cad4 <_realloc_r+0x164>  // b.pmore
    8020c9b8:	52800001 	mov	w1, #0x0                   	// #0
    8020c9bc:	7100003f 	cmp	w1, #0x0
    8020c9c0:	d2800414 	mov	x20, #0x20                  	// #32
    8020c9c4:	fa550280 	ccmp	x20, x21, #0x0, eq	// eq = none
    8020c9c8:	54000943 	b.cc	8020caf0 <_realloc_r+0x180>  // b.lo, b.ul, b.last
    8020c9cc:	eb1402ff 	cmp	x23, x20
    8020c9d0:	54000a4a 	b.ge	8020cb18 <_realloc_r+0x1a8>  // b.tcont
    8020c9d4:	b0000021 	adrp	x1, 80211000 <blanks.1+0x60>
    8020c9d8:	a90573fb 	stp	x27, x28, [sp, #80]
    8020c9dc:	9122803c 	add	x28, x1, #0x8a0
    8020c9e0:	8b170302 	add	x2, x24, x23
    8020c9e4:	f9400b83 	ldr	x3, [x28, #16]
    8020c9e8:	f9400441 	ldr	x1, [x2, #8]
    8020c9ec:	eb02007f 	cmp	x3, x2
    8020c9f0:	54000ea0 	b.eq	8020cbc4 <_realloc_r+0x254>  // b.none
    8020c9f4:	927ff823 	and	x3, x1, #0xfffffffffffffffe
    8020c9f8:	8b030043 	add	x3, x2, x3
    8020c9fc:	f9400463 	ldr	x3, [x3, #8]
    8020ca00:	37000b63 	tbnz	w3, #0, 8020cb6c <_realloc_r+0x1fc>
    8020ca04:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    8020ca08:	8b0102e3 	add	x3, x23, x1
    8020ca0c:	eb03029f 	cmp	x20, x3
    8020ca10:	5400078d 	b.le	8020cb00 <_realloc_r+0x190>
    8020ca14:	37000180 	tbnz	w0, #0, 8020ca44 <_realloc_r+0xd4>
    8020ca18:	f85f027b 	ldur	x27, [x19, #-16]
    8020ca1c:	cb1b031b 	sub	x27, x24, x27
    8020ca20:	f9400760 	ldr	x0, [x27, #8]
    8020ca24:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020ca28:	8b000021 	add	x1, x1, x0
    8020ca2c:	8b17003a 	add	x26, x1, x23
    8020ca30:	eb1a029f 	cmp	x20, x26
    8020ca34:	540018ed 	b.le	8020cd50 <_realloc_r+0x3e0>
    8020ca38:	8b0002fa 	add	x26, x23, x0
    8020ca3c:	eb1a029f 	cmp	x20, x26
    8020ca40:	5400146d 	b.le	8020cccc <_realloc_r+0x35c>
    8020ca44:	aa1503e1 	mov	x1, x21
    8020ca48:	aa1603e0 	mov	x0, x22
    8020ca4c:	97fff1fd 	bl	80209240 <_malloc_r>
    8020ca50:	aa0003f5 	mov	x21, x0
    8020ca54:	b4001d20 	cbz	x0, 8020cdf8 <_realloc_r+0x488>
    8020ca58:	f9400701 	ldr	x1, [x24, #8]
    8020ca5c:	d1004002 	sub	x2, x0, #0x10
    8020ca60:	927ff821 	and	x1, x1, #0xfffffffffffffffe
    8020ca64:	8b010301 	add	x1, x24, x1
    8020ca68:	eb02003f 	cmp	x1, x2
    8020ca6c:	54001140 	b.eq	8020cc94 <_realloc_r+0x324>  // b.none
    8020ca70:	d10022e2 	sub	x2, x23, #0x8
    8020ca74:	f101205f 	cmp	x2, #0x48
    8020ca78:	54001668 	b.hi	8020cd44 <_realloc_r+0x3d4>  // b.pmore
    8020ca7c:	f1009c5f 	cmp	x2, #0x27
    8020ca80:	54001148 	b.hi	8020cca8 <_realloc_r+0x338>  // b.pmore
    8020ca84:	aa1303e1 	mov	x1, x19
    8020ca88:	f9400022 	ldr	x2, [x1]
    8020ca8c:	f9000002 	str	x2, [x0]
    8020ca90:	f9400422 	ldr	x2, [x1, #8]
    8020ca94:	f9000402 	str	x2, [x0, #8]
    8020ca98:	f9400821 	ldr	x1, [x1, #16]
    8020ca9c:	f9000801 	str	x1, [x0, #16]
    8020caa0:	aa1303e1 	mov	x1, x19
    8020caa4:	aa1603e0 	mov	x0, x22
    8020caa8:	94000156 	bl	8020d000 <_free_r>
    8020caac:	aa1603e0 	mov	x0, x22
    8020cab0:	97fff984 	bl	8020b0c0 <__malloc_unlock>
    8020cab4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020cab8:	aa1503e0 	mov	x0, x21
    8020cabc:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020cac0:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020cac4:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020cac8:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020cacc:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020cad0:	d65f03c0 	ret
    8020cad4:	927cee94 	and	x20, x20, #0xfffffffffffffff0
    8020cad8:	b2407be1 	mov	x1, #0x7fffffff            	// #2147483647
    8020cadc:	eb01029f 	cmp	x20, x1
    8020cae0:	1a9f97e1 	cset	w1, hi	// hi = pmore
    8020cae4:	7100003f 	cmp	w1, #0x0
    8020cae8:	fa550280 	ccmp	x20, x21, #0x0, eq	// eq = none
    8020caec:	54fff702 	b.cs	8020c9cc <_realloc_r+0x5c>  // b.hs, b.nlast
    8020caf0:	52800180 	mov	w0, #0xc                   	// #12
    8020caf4:	d2800015 	mov	x21, #0x0                   	// #0
    8020caf8:	b90002c0 	str	w0, [x22]
    8020cafc:	14000015 	b	8020cb50 <_realloc_r+0x1e0>
    8020cb00:	a9410041 	ldp	x1, x0, [x2, #16]
    8020cb04:	aa0303f7 	mov	x23, x3
    8020cb08:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020cb0c:	f9000c20 	str	x0, [x1, #24]
    8020cb10:	f9000801 	str	x1, [x0, #16]
    8020cb14:	d503201f 	nop
    8020cb18:	f9400721 	ldr	x1, [x25, #8]
    8020cb1c:	cb1402e0 	sub	x0, x23, x20
    8020cb20:	8b170322 	add	x2, x25, x23
    8020cb24:	92400021 	and	x1, x1, #0x1
    8020cb28:	f1007c1f 	cmp	x0, #0x1f
    8020cb2c:	54000348 	b.hi	8020cb94 <_realloc_r+0x224>  // b.pmore
    8020cb30:	aa0102e1 	orr	x1, x23, x1
    8020cb34:	f9000721 	str	x1, [x25, #8]
    8020cb38:	f9400440 	ldr	x0, [x2, #8]
    8020cb3c:	b2400000 	orr	x0, x0, #0x1
    8020cb40:	f9000440 	str	x0, [x2, #8]
    8020cb44:	aa1303f5 	mov	x21, x19
    8020cb48:	aa1603e0 	mov	x0, x22
    8020cb4c:	97fff95d 	bl	8020b0c0 <__malloc_unlock>
    8020cb50:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020cb54:	aa1503e0 	mov	x0, x21
    8020cb58:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020cb5c:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020cb60:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020cb64:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020cb68:	d65f03c0 	ret
    8020cb6c:	3707f6c0 	tbnz	w0, #0, 8020ca44 <_realloc_r+0xd4>
    8020cb70:	f85f027b 	ldur	x27, [x19, #-16]
    8020cb74:	cb1b031b 	sub	x27, x24, x27
    8020cb78:	f9400760 	ldr	x0, [x27, #8]
    8020cb7c:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020cb80:	17ffffae 	b	8020ca38 <_realloc_r+0xc8>
    8020cb84:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020cb88:	aa0203e1 	mov	x1, x2
    8020cb8c:	a8c67bfd 	ldp	x29, x30, [sp], #96
    8020cb90:	17fff1ac 	b	80209240 <_malloc_r>
    8020cb94:	8b140324 	add	x4, x25, x20
    8020cb98:	aa010281 	orr	x1, x20, x1
    8020cb9c:	f9000721 	str	x1, [x25, #8]
    8020cba0:	b2400003 	orr	x3, x0, #0x1
    8020cba4:	91004081 	add	x1, x4, #0x10
    8020cba8:	aa1603e0 	mov	x0, x22
    8020cbac:	f9000483 	str	x3, [x4, #8]
    8020cbb0:	f9400443 	ldr	x3, [x2, #8]
    8020cbb4:	b2400063 	orr	x3, x3, #0x1
    8020cbb8:	f9000443 	str	x3, [x2, #8]
    8020cbbc:	94000111 	bl	8020d000 <_free_r>
    8020cbc0:	17ffffe1 	b	8020cb44 <_realloc_r+0x1d4>
    8020cbc4:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    8020cbc8:	91008283 	add	x3, x20, #0x20
    8020cbcc:	8b170022 	add	x2, x1, x23
    8020cbd0:	eb03005f 	cmp	x2, x3
    8020cbd4:	54000e4a 	b.ge	8020cd9c <_realloc_r+0x42c>  // b.tcont
    8020cbd8:	3707f360 	tbnz	w0, #0, 8020ca44 <_realloc_r+0xd4>
    8020cbdc:	f85f027b 	ldur	x27, [x19, #-16]
    8020cbe0:	cb1b031b 	sub	x27, x24, x27
    8020cbe4:	f9400760 	ldr	x0, [x27, #8]
    8020cbe8:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020cbec:	8b000021 	add	x1, x1, x0
    8020cbf0:	8b17003a 	add	x26, x1, x23
    8020cbf4:	eb1a007f 	cmp	x3, x26
    8020cbf8:	54fff20c 	b.gt	8020ca38 <_realloc_r+0xc8>
    8020cbfc:	aa1b03f5 	mov	x21, x27
    8020cc00:	d10022e2 	sub	x2, x23, #0x8
    8020cc04:	f9400f60 	ldr	x0, [x27, #24]
    8020cc08:	f8410ea1 	ldr	x1, [x21, #16]!
    8020cc0c:	f9000c20 	str	x0, [x1, #24]
    8020cc10:	f9000801 	str	x1, [x0, #16]
    8020cc14:	f101205f 	cmp	x2, #0x48
    8020cc18:	54001168 	b.hi	8020ce44 <_realloc_r+0x4d4>  // b.pmore
    8020cc1c:	aa1503e0 	mov	x0, x21
    8020cc20:	f1009c5f 	cmp	x2, #0x27
    8020cc24:	54000129 	b.ls	8020cc48 <_realloc_r+0x2d8>  // b.plast
    8020cc28:	f9400260 	ldr	x0, [x19]
    8020cc2c:	f9000b60 	str	x0, [x27, #16]
    8020cc30:	f9400660 	ldr	x0, [x19, #8]
    8020cc34:	f9000f60 	str	x0, [x27, #24]
    8020cc38:	f100dc5f 	cmp	x2, #0x37
    8020cc3c:	540010c8 	b.hi	8020ce54 <_realloc_r+0x4e4>  // b.pmore
    8020cc40:	91004273 	add	x19, x19, #0x10
    8020cc44:	91008360 	add	x0, x27, #0x20
    8020cc48:	f9400261 	ldr	x1, [x19]
    8020cc4c:	f9000001 	str	x1, [x0]
    8020cc50:	f9400661 	ldr	x1, [x19, #8]
    8020cc54:	f9000401 	str	x1, [x0, #8]
    8020cc58:	f9400a61 	ldr	x1, [x19, #16]
    8020cc5c:	f9000801 	str	x1, [x0, #16]
    8020cc60:	8b140362 	add	x2, x27, x20
    8020cc64:	cb140341 	sub	x1, x26, x20
    8020cc68:	f9000b82 	str	x2, [x28, #16]
    8020cc6c:	b2400021 	orr	x1, x1, #0x1
    8020cc70:	aa1603e0 	mov	x0, x22
    8020cc74:	f9000441 	str	x1, [x2, #8]
    8020cc78:	f9400761 	ldr	x1, [x27, #8]
    8020cc7c:	92400021 	and	x1, x1, #0x1
    8020cc80:	aa140021 	orr	x1, x1, x20
    8020cc84:	f9000761 	str	x1, [x27, #8]
    8020cc88:	97fff90e 	bl	8020b0c0 <__malloc_unlock>
    8020cc8c:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020cc90:	17ffffb0 	b	8020cb50 <_realloc_r+0x1e0>
    8020cc94:	f9400420 	ldr	x0, [x1, #8]
    8020cc98:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020cc9c:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020cca0:	8b0002f7 	add	x23, x23, x0
    8020cca4:	17ffff9d 	b	8020cb18 <_realloc_r+0x1a8>
    8020cca8:	f9400260 	ldr	x0, [x19]
    8020ccac:	f90002a0 	str	x0, [x21]
    8020ccb0:	f9400660 	ldr	x0, [x19, #8]
    8020ccb4:	f90006a0 	str	x0, [x21, #8]
    8020ccb8:	f100dc5f 	cmp	x2, #0x37
    8020ccbc:	540005e8 	b.hi	8020cd78 <_realloc_r+0x408>  // b.pmore
    8020ccc0:	91004261 	add	x1, x19, #0x10
    8020ccc4:	910042a0 	add	x0, x21, #0x10
    8020ccc8:	17ffff70 	b	8020ca88 <_realloc_r+0x118>
    8020cccc:	aa1b03f5 	mov	x21, x27
    8020ccd0:	d10022e2 	sub	x2, x23, #0x8
    8020ccd4:	f8410ea1 	ldr	x1, [x21, #16]!
    8020ccd8:	f9400f60 	ldr	x0, [x27, #24]
    8020ccdc:	f9000c20 	str	x0, [x1, #24]
    8020cce0:	f9000801 	str	x1, [x0, #16]
    8020cce4:	f101205f 	cmp	x2, #0x48
    8020cce8:	54000408 	b.hi	8020cd68 <_realloc_r+0x3f8>  // b.pmore
    8020ccec:	aa1503e0 	mov	x0, x21
    8020ccf0:	f1009c5f 	cmp	x2, #0x27
    8020ccf4:	54000129 	b.ls	8020cd18 <_realloc_r+0x3a8>  // b.plast
    8020ccf8:	f9400260 	ldr	x0, [x19]
    8020ccfc:	f9000b60 	str	x0, [x27, #16]
    8020cd00:	f9400660 	ldr	x0, [x19, #8]
    8020cd04:	f9000f60 	str	x0, [x27, #24]
    8020cd08:	f100dc5f 	cmp	x2, #0x37
    8020cd0c:	54000648 	b.hi	8020cdd4 <_realloc_r+0x464>  // b.pmore
    8020cd10:	91004273 	add	x19, x19, #0x10
    8020cd14:	91008360 	add	x0, x27, #0x20
    8020cd18:	f9400261 	ldr	x1, [x19]
    8020cd1c:	f9000001 	str	x1, [x0]
    8020cd20:	f9400661 	ldr	x1, [x19, #8]
    8020cd24:	f9000401 	str	x1, [x0, #8]
    8020cd28:	f9400a61 	ldr	x1, [x19, #16]
    8020cd2c:	f9000801 	str	x1, [x0, #16]
    8020cd30:	aa1b03f9 	mov	x25, x27
    8020cd34:	aa1503f3 	mov	x19, x21
    8020cd38:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020cd3c:	aa1a03f7 	mov	x23, x26
    8020cd40:	17ffff76 	b	8020cb18 <_realloc_r+0x1a8>
    8020cd44:	aa1303e1 	mov	x1, x19
    8020cd48:	97fff84e 	bl	8020ae80 <memcpy>
    8020cd4c:	17ffff55 	b	8020caa0 <_realloc_r+0x130>
    8020cd50:	a9410041 	ldp	x1, x0, [x2, #16]
    8020cd54:	f9000c20 	str	x0, [x1, #24]
    8020cd58:	aa1b03f5 	mov	x21, x27
    8020cd5c:	d10022e2 	sub	x2, x23, #0x8
    8020cd60:	f9000801 	str	x1, [x0, #16]
    8020cd64:	17ffffdc 	b	8020ccd4 <_realloc_r+0x364>
    8020cd68:	aa1303e1 	mov	x1, x19
    8020cd6c:	aa1503e0 	mov	x0, x21
    8020cd70:	97fff844 	bl	8020ae80 <memcpy>
    8020cd74:	17ffffef 	b	8020cd30 <_realloc_r+0x3c0>
    8020cd78:	f9400a60 	ldr	x0, [x19, #16]
    8020cd7c:	f9000aa0 	str	x0, [x21, #16]
    8020cd80:	f9400e60 	ldr	x0, [x19, #24]
    8020cd84:	f9000ea0 	str	x0, [x21, #24]
    8020cd88:	f101205f 	cmp	x2, #0x48
    8020cd8c:	54000400 	b.eq	8020ce0c <_realloc_r+0x49c>  // b.none
    8020cd90:	91008261 	add	x1, x19, #0x20
    8020cd94:	910082a0 	add	x0, x21, #0x20
    8020cd98:	17ffff3c 	b	8020ca88 <_realloc_r+0x118>
    8020cd9c:	8b140303 	add	x3, x24, x20
    8020cda0:	cb140041 	sub	x1, x2, x20
    8020cda4:	f9000b83 	str	x3, [x28, #16]
    8020cda8:	b2400021 	orr	x1, x1, #0x1
    8020cdac:	aa1603e0 	mov	x0, x22
    8020cdb0:	aa1303f5 	mov	x21, x19
    8020cdb4:	f9000461 	str	x1, [x3, #8]
    8020cdb8:	f9400701 	ldr	x1, [x24, #8]
    8020cdbc:	92400021 	and	x1, x1, #0x1
    8020cdc0:	aa140021 	orr	x1, x1, x20
    8020cdc4:	f9000701 	str	x1, [x24, #8]
    8020cdc8:	97fff8be 	bl	8020b0c0 <__malloc_unlock>
    8020cdcc:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020cdd0:	17ffff60 	b	8020cb50 <_realloc_r+0x1e0>
    8020cdd4:	f9400a60 	ldr	x0, [x19, #16]
    8020cdd8:	f9001360 	str	x0, [x27, #32]
    8020cddc:	f9400e60 	ldr	x0, [x19, #24]
    8020cde0:	f9001760 	str	x0, [x27, #40]
    8020cde4:	f101205f 	cmp	x2, #0x48
    8020cde8:	54000200 	b.eq	8020ce28 <_realloc_r+0x4b8>  // b.none
    8020cdec:	91008273 	add	x19, x19, #0x20
    8020cdf0:	9100c360 	add	x0, x27, #0x30
    8020cdf4:	17ffffc9 	b	8020cd18 <_realloc_r+0x3a8>
    8020cdf8:	aa1603e0 	mov	x0, x22
    8020cdfc:	d2800015 	mov	x21, #0x0                   	// #0
    8020ce00:	97fff8b0 	bl	8020b0c0 <__malloc_unlock>
    8020ce04:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020ce08:	17ffff52 	b	8020cb50 <_realloc_r+0x1e0>
    8020ce0c:	f9401260 	ldr	x0, [x19, #32]
    8020ce10:	f90012a0 	str	x0, [x21, #32]
    8020ce14:	9100c261 	add	x1, x19, #0x30
    8020ce18:	9100c2a0 	add	x0, x21, #0x30
    8020ce1c:	f9401662 	ldr	x2, [x19, #40]
    8020ce20:	f90016a2 	str	x2, [x21, #40]
    8020ce24:	17ffff19 	b	8020ca88 <_realloc_r+0x118>
    8020ce28:	f9401260 	ldr	x0, [x19, #32]
    8020ce2c:	f9001b60 	str	x0, [x27, #48]
    8020ce30:	9100c273 	add	x19, x19, #0x30
    8020ce34:	91010360 	add	x0, x27, #0x40
    8020ce38:	f85f8261 	ldur	x1, [x19, #-8]
    8020ce3c:	f9001f61 	str	x1, [x27, #56]
    8020ce40:	17ffffb6 	b	8020cd18 <_realloc_r+0x3a8>
    8020ce44:	aa1303e1 	mov	x1, x19
    8020ce48:	aa1503e0 	mov	x0, x21
    8020ce4c:	97fff80d 	bl	8020ae80 <memcpy>
    8020ce50:	17ffff84 	b	8020cc60 <_realloc_r+0x2f0>
    8020ce54:	f9400a60 	ldr	x0, [x19, #16]
    8020ce58:	f9001360 	str	x0, [x27, #32]
    8020ce5c:	f9400e60 	ldr	x0, [x19, #24]
    8020ce60:	f9001760 	str	x0, [x27, #40]
    8020ce64:	f101205f 	cmp	x2, #0x48
    8020ce68:	54000080 	b.eq	8020ce78 <_realloc_r+0x508>  // b.none
    8020ce6c:	91008273 	add	x19, x19, #0x20
    8020ce70:	9100c360 	add	x0, x27, #0x30
    8020ce74:	17ffff75 	b	8020cc48 <_realloc_r+0x2d8>
    8020ce78:	f9401260 	ldr	x0, [x19, #32]
    8020ce7c:	f9001b60 	str	x0, [x27, #48]
    8020ce80:	9100c273 	add	x19, x19, #0x30
    8020ce84:	91010360 	add	x0, x27, #0x40
    8020ce88:	f85f8261 	ldur	x1, [x19, #-8]
    8020ce8c:	f9001f61 	str	x1, [x27, #56]
    8020ce90:	17ffff6e 	b	8020cc48 <_realloc_r+0x2d8>
	...

000000008020cea0 <strlcpy>:
    8020cea0:	aa0103e3 	mov	x3, x1
    8020cea4:	b50000a2 	cbnz	x2, 8020ceb8 <strlcpy+0x18>
    8020cea8:	14000008 	b	8020cec8 <strlcpy+0x28>
    8020ceac:	38401464 	ldrb	w4, [x3], #1
    8020ceb0:	38001404 	strb	w4, [x0], #1
    8020ceb4:	340000e4 	cbz	w4, 8020ced0 <strlcpy+0x30>
    8020ceb8:	f1000442 	subs	x2, x2, #0x1
    8020cebc:	54ffff81 	b.ne	8020ceac <strlcpy+0xc>  // b.any
    8020cec0:	3900001f 	strb	wzr, [x0]
    8020cec4:	d503201f 	nop
    8020cec8:	38401460 	ldrb	w0, [x3], #1
    8020cecc:	35ffffe0 	cbnz	w0, 8020cec8 <strlcpy+0x28>
    8020ced0:	cb010060 	sub	x0, x3, x1
    8020ced4:	d1000400 	sub	x0, x0, #0x1
    8020ced8:	d65f03c0 	ret
    8020cedc:	00000000 	udf	#0

000000008020cee0 <_malloc_trim_r>:
    8020cee0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020cee4:	910003fd 	mov	x29, sp
    8020cee8:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020ceec:	b0000036 	adrp	x22, 80211000 <blanks.1+0x60>
    8020cef0:	912282d6 	add	x22, x22, #0x8a0
    8020cef4:	aa0003f5 	mov	x21, x0
    8020cef8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020cefc:	f9001bf7 	str	x23, [sp, #48]
    8020cf00:	aa0103f7 	mov	x23, x1
    8020cf04:	97fff86b 	bl	8020b0b0 <__malloc_lock>
    8020cf08:	f9400ac0 	ldr	x0, [x22, #16]
    8020cf0c:	f9400414 	ldr	x20, [x0, #8]
    8020cf10:	927ef694 	and	x20, x20, #0xfffffffffffffffc
    8020cf14:	913f7e93 	add	x19, x20, #0xfdf
    8020cf18:	cb170273 	sub	x19, x19, x23
    8020cf1c:	9274ce73 	and	x19, x19, #0xfffffffffffff000
    8020cf20:	d1400673 	sub	x19, x19, #0x1, lsl #12
    8020cf24:	f13ffe7f 	cmp	x19, #0xfff
    8020cf28:	5400010d 	b.le	8020cf48 <_malloc_trim_r+0x68>
    8020cf2c:	d2800001 	mov	x1, #0x0                   	// #0
    8020cf30:	aa1503e0 	mov	x0, x21
    8020cf34:	940004b3 	bl	8020e200 <_sbrk_r>
    8020cf38:	f9400ac1 	ldr	x1, [x22, #16]
    8020cf3c:	8b140021 	add	x1, x1, x20
    8020cf40:	eb01001f 	cmp	x0, x1
    8020cf44:	54000120 	b.eq	8020cf68 <_malloc_trim_r+0x88>  // b.none
    8020cf48:	aa1503e0 	mov	x0, x21
    8020cf4c:	97fff85d 	bl	8020b0c0 <__malloc_unlock>
    8020cf50:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020cf54:	52800000 	mov	w0, #0x0                   	// #0
    8020cf58:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020cf5c:	f9401bf7 	ldr	x23, [sp, #48]
    8020cf60:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020cf64:	d65f03c0 	ret
    8020cf68:	cb1303e1 	neg	x1, x19
    8020cf6c:	aa1503e0 	mov	x0, x21
    8020cf70:	940004a4 	bl	8020e200 <_sbrk_r>
    8020cf74:	b100041f 	cmn	x0, #0x1
    8020cf78:	54000220 	b.eq	8020cfbc <_malloc_trim_r+0xdc>  // b.none
    8020cf7c:	b00003a2 	adrp	x2, 80281000 <__sf+0x38>
    8020cf80:	cb130294 	sub	x20, x20, x19
    8020cf84:	f9400ac3 	ldr	x3, [x22, #16]
    8020cf88:	b2400294 	orr	x20, x20, #0x1
    8020cf8c:	b941f841 	ldr	w1, [x2, #504]
    8020cf90:	aa1503e0 	mov	x0, x21
    8020cf94:	4b130021 	sub	w1, w1, w19
    8020cf98:	f9000474 	str	x20, [x3, #8]
    8020cf9c:	b901f841 	str	w1, [x2, #504]
    8020cfa0:	97fff848 	bl	8020b0c0 <__malloc_unlock>
    8020cfa4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020cfa8:	52800020 	mov	w0, #0x1                   	// #1
    8020cfac:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020cfb0:	f9401bf7 	ldr	x23, [sp, #48]
    8020cfb4:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020cfb8:	d65f03c0 	ret
    8020cfbc:	d2800001 	mov	x1, #0x0                   	// #0
    8020cfc0:	aa1503e0 	mov	x0, x21
    8020cfc4:	9400048f 	bl	8020e200 <_sbrk_r>
    8020cfc8:	f9400ac2 	ldr	x2, [x22, #16]
    8020cfcc:	cb020001 	sub	x1, x0, x2
    8020cfd0:	f1007c3f 	cmp	x1, #0x1f
    8020cfd4:	54fffbad 	b.le	8020cf48 <_malloc_trim_r+0x68>
    8020cfd8:	b0000024 	adrp	x4, 80211000 <blanks.1+0x60>
    8020cfdc:	b2400021 	orr	x1, x1, #0x1
    8020cfe0:	f9000441 	str	x1, [x2, #8]
    8020cfe4:	b00003a3 	adrp	x3, 80281000 <__sf+0x38>
    8020cfe8:	f9444481 	ldr	x1, [x4, #2184]
    8020cfec:	cb010000 	sub	x0, x0, x1
    8020cff0:	b901f860 	str	w0, [x3, #504]
    8020cff4:	17ffffd5 	b	8020cf48 <_malloc_trim_r+0x68>
	...

000000008020d000 <_free_r>:
    8020d000:	b4000a21 	cbz	x1, 8020d144 <_free_r+0x144>
    8020d004:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020d008:	910003fd 	mov	x29, sp
    8020d00c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d010:	aa0103f3 	mov	x19, x1
    8020d014:	aa0003f4 	mov	x20, x0
    8020d018:	97fff826 	bl	8020b0b0 <__malloc_lock>
    8020d01c:	f85f8265 	ldur	x5, [x19, #-8]
    8020d020:	d1004263 	sub	x3, x19, #0x10
    8020d024:	90000020 	adrp	x0, 80211000 <blanks.1+0x60>
    8020d028:	91228000 	add	x0, x0, #0x8a0
    8020d02c:	927ff8a2 	and	x2, x5, #0xfffffffffffffffe
    8020d030:	8b020064 	add	x4, x3, x2
    8020d034:	f9400806 	ldr	x6, [x0, #16]
    8020d038:	f9400481 	ldr	x1, [x4, #8]
    8020d03c:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    8020d040:	eb0400df 	cmp	x6, x4
    8020d044:	54000c00 	b.eq	8020d1c4 <_free_r+0x1c4>  // b.none
    8020d048:	f9000481 	str	x1, [x4, #8]
    8020d04c:	8b010086 	add	x6, x4, x1
    8020d050:	37000345 	tbnz	w5, #0, 8020d0b8 <_free_r+0xb8>
    8020d054:	f85f0267 	ldur	x7, [x19, #-16]
    8020d058:	90000025 	adrp	x5, 80211000 <blanks.1+0x60>
    8020d05c:	f94004c6 	ldr	x6, [x6, #8]
    8020d060:	cb070063 	sub	x3, x3, x7
    8020d064:	8b070042 	add	x2, x2, x7
    8020d068:	9122c0a5 	add	x5, x5, #0x8b0
    8020d06c:	924000c6 	and	x6, x6, #0x1
    8020d070:	f9400867 	ldr	x7, [x3, #16]
    8020d074:	eb0500ff 	cmp	x7, x5
    8020d078:	54000940 	b.eq	8020d1a0 <_free_r+0x1a0>  // b.none
    8020d07c:	f9400c68 	ldr	x8, [x3, #24]
    8020d080:	f9000ce8 	str	x8, [x7, #24]
    8020d084:	f9000907 	str	x7, [x8, #16]
    8020d088:	b50001c6 	cbnz	x6, 8020d0c0 <_free_r+0xc0>
    8020d08c:	8b010042 	add	x2, x2, x1
    8020d090:	f9400881 	ldr	x1, [x4, #16]
    8020d094:	eb05003f 	cmp	x1, x5
    8020d098:	54000ea0 	b.eq	8020d26c <_free_r+0x26c>  // b.none
    8020d09c:	f9400c85 	ldr	x5, [x4, #24]
    8020d0a0:	f9000c25 	str	x5, [x1, #24]
    8020d0a4:	b2400044 	orr	x4, x2, #0x1
    8020d0a8:	f90008a1 	str	x1, [x5, #16]
    8020d0ac:	f9000464 	str	x4, [x3, #8]
    8020d0b0:	f8226862 	str	x2, [x3, x2]
    8020d0b4:	14000006 	b	8020d0cc <_free_r+0xcc>
    8020d0b8:	f94004c5 	ldr	x5, [x6, #8]
    8020d0bc:	360006a5 	tbz	w5, #0, 8020d190 <_free_r+0x190>
    8020d0c0:	b2400041 	orr	x1, x2, #0x1
    8020d0c4:	f9000461 	str	x1, [x3, #8]
    8020d0c8:	f9000082 	str	x2, [x4]
    8020d0cc:	f107fc5f 	cmp	x2, #0x1ff
    8020d0d0:	540003c9 	b.ls	8020d148 <_free_r+0x148>  // b.plast
    8020d0d4:	d349fc41 	lsr	x1, x2, #9
    8020d0d8:	f127fc5f 	cmp	x2, #0x9ff
    8020d0dc:	540009c8 	b.hi	8020d214 <_free_r+0x214>  // b.pmore
    8020d0e0:	d346fc41 	lsr	x1, x2, #6
    8020d0e4:	1100e424 	add	w4, w1, #0x39
    8020d0e8:	1100e025 	add	w5, w1, #0x38
    8020d0ec:	531f7884 	lsl	w4, w4, #1
    8020d0f0:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020d0f4:	8b040004 	add	x4, x0, x4
    8020d0f8:	f85f0481 	ldr	x1, [x4], #-16
    8020d0fc:	eb01009f 	cmp	x4, x1
    8020d100:	540000a1 	b.ne	8020d114 <_free_r+0x114>  // b.any
    8020d104:	14000053 	b	8020d250 <_free_r+0x250>
    8020d108:	f9400821 	ldr	x1, [x1, #16]
    8020d10c:	eb01009f 	cmp	x4, x1
    8020d110:	540000a0 	b.eq	8020d124 <_free_r+0x124>  // b.none
    8020d114:	f9400420 	ldr	x0, [x1, #8]
    8020d118:	927ef400 	and	x0, x0, #0xfffffffffffffffc
    8020d11c:	eb02001f 	cmp	x0, x2
    8020d120:	54ffff48 	b.hi	8020d108 <_free_r+0x108>  // b.pmore
    8020d124:	f9400c24 	ldr	x4, [x1, #24]
    8020d128:	a9011061 	stp	x1, x4, [x3, #16]
    8020d12c:	aa1403e0 	mov	x0, x20
    8020d130:	f9000883 	str	x3, [x4, #16]
    8020d134:	f9000c23 	str	x3, [x1, #24]
    8020d138:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d13c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d140:	17fff7e0 	b	8020b0c0 <__malloc_unlock>
    8020d144:	d65f03c0 	ret
    8020d148:	d343fc44 	lsr	x4, x2, #3
    8020d14c:	d2800022 	mov	x2, #0x1                   	// #1
    8020d150:	11000481 	add	w1, w4, #0x1
    8020d154:	f9400405 	ldr	x5, [x0, #8]
    8020d158:	531f7821 	lsl	w1, w1, #1
    8020d15c:	13027c84 	asr	w4, w4, #2
    8020d160:	8b21cc01 	add	x1, x0, w1, sxtw #3
    8020d164:	9ac42042 	lsl	x2, x2, x4
    8020d168:	aa050042 	orr	x2, x2, x5
    8020d16c:	f9000402 	str	x2, [x0, #8]
    8020d170:	f85f0420 	ldr	x0, [x1], #-16
    8020d174:	a9010460 	stp	x0, x1, [x3, #16]
    8020d178:	f9000823 	str	x3, [x1, #16]
    8020d17c:	f9000c03 	str	x3, [x0, #24]
    8020d180:	aa1403e0 	mov	x0, x20
    8020d184:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d188:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d18c:	17fff7cd 	b	8020b0c0 <__malloc_unlock>
    8020d190:	90000025 	adrp	x5, 80211000 <blanks.1+0x60>
    8020d194:	8b010042 	add	x2, x2, x1
    8020d198:	9122c0a5 	add	x5, x5, #0x8b0
    8020d19c:	17ffffbd 	b	8020d090 <_free_r+0x90>
    8020d1a0:	b5000986 	cbnz	x6, 8020d2d0 <_free_r+0x2d0>
    8020d1a4:	a9410085 	ldp	x5, x0, [x4, #16]
    8020d1a8:	8b020021 	add	x1, x1, x2
    8020d1ac:	f9000ca0 	str	x0, [x5, #24]
    8020d1b0:	b2400022 	orr	x2, x1, #0x1
    8020d1b4:	f9000805 	str	x5, [x0, #16]
    8020d1b8:	f9000462 	str	x2, [x3, #8]
    8020d1bc:	f8216861 	str	x1, [x3, x1]
    8020d1c0:	17fffff0 	b	8020d180 <_free_r+0x180>
    8020d1c4:	8b010041 	add	x1, x2, x1
    8020d1c8:	370000e5 	tbnz	w5, #0, 8020d1e4 <_free_r+0x1e4>
    8020d1cc:	f85f0262 	ldur	x2, [x19, #-16]
    8020d1d0:	cb020063 	sub	x3, x3, x2
    8020d1d4:	8b020021 	add	x1, x1, x2
    8020d1d8:	a9410864 	ldp	x4, x2, [x3, #16]
    8020d1dc:	f9000c82 	str	x2, [x4, #24]
    8020d1e0:	f9000844 	str	x4, [x2, #16]
    8020d1e4:	90000022 	adrp	x2, 80211000 <blanks.1+0x60>
    8020d1e8:	b2400024 	orr	x4, x1, #0x1
    8020d1ec:	f9000464 	str	x4, [x3, #8]
    8020d1f0:	f9444842 	ldr	x2, [x2, #2192]
    8020d1f4:	f9000803 	str	x3, [x0, #16]
    8020d1f8:	eb01005f 	cmp	x2, x1
    8020d1fc:	54fffc28 	b.hi	8020d180 <_free_r+0x180>  // b.pmore
    8020d200:	900003a1 	adrp	x1, 80281000 <__sf+0x38>
    8020d204:	aa1403e0 	mov	x0, x20
    8020d208:	f9411821 	ldr	x1, [x1, #560]
    8020d20c:	97ffff35 	bl	8020cee0 <_malloc_trim_r>
    8020d210:	17ffffdc 	b	8020d180 <_free_r+0x180>
    8020d214:	f100503f 	cmp	x1, #0x14
    8020d218:	54000129 	b.ls	8020d23c <_free_r+0x23c>  // b.plast
    8020d21c:	f101503f 	cmp	x1, #0x54
    8020d220:	54000328 	b.hi	8020d284 <_free_r+0x284>  // b.pmore
    8020d224:	d34cfc41 	lsr	x1, x2, #12
    8020d228:	1101bc24 	add	w4, w1, #0x6f
    8020d22c:	1101b825 	add	w5, w1, #0x6e
    8020d230:	531f7884 	lsl	w4, w4, #1
    8020d234:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020d238:	17ffffaf 	b	8020d0f4 <_free_r+0xf4>
    8020d23c:	11017024 	add	w4, w1, #0x5c
    8020d240:	11016c25 	add	w5, w1, #0x5b
    8020d244:	531f7884 	lsl	w4, w4, #1
    8020d248:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020d24c:	17ffffaa 	b	8020d0f4 <_free_r+0xf4>
    8020d250:	f9400406 	ldr	x6, [x0, #8]
    8020d254:	13027ca5 	asr	w5, w5, #2
    8020d258:	d2800022 	mov	x2, #0x1                   	// #1
    8020d25c:	9ac52042 	lsl	x2, x2, x5
    8020d260:	aa060042 	orr	x2, x2, x6
    8020d264:	f9000402 	str	x2, [x0, #8]
    8020d268:	17ffffb0 	b	8020d128 <_free_r+0x128>
    8020d26c:	a9020c03 	stp	x3, x3, [x0, #32]
    8020d270:	b2400041 	orr	x1, x2, #0x1
    8020d274:	a9009461 	stp	x1, x5, [x3, #8]
    8020d278:	f9000c65 	str	x5, [x3, #24]
    8020d27c:	f8226862 	str	x2, [x3, x2]
    8020d280:	17ffffc0 	b	8020d180 <_free_r+0x180>
    8020d284:	f105503f 	cmp	x1, #0x154
    8020d288:	540000e8 	b.hi	8020d2a4 <_free_r+0x2a4>  // b.pmore
    8020d28c:	d34ffc41 	lsr	x1, x2, #15
    8020d290:	1101e024 	add	w4, w1, #0x78
    8020d294:	1101dc25 	add	w5, w1, #0x77
    8020d298:	531f7884 	lsl	w4, w4, #1
    8020d29c:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020d2a0:	17ffff95 	b	8020d0f4 <_free_r+0xf4>
    8020d2a4:	f115503f 	cmp	x1, #0x554
    8020d2a8:	540000e8 	b.hi	8020d2c4 <_free_r+0x2c4>  // b.pmore
    8020d2ac:	d352fc41 	lsr	x1, x2, #18
    8020d2b0:	1101f424 	add	w4, w1, #0x7d
    8020d2b4:	1101f025 	add	w5, w1, #0x7c
    8020d2b8:	531f7884 	lsl	w4, w4, #1
    8020d2bc:	937d7c84 	sbfiz	x4, x4, #3, #32
    8020d2c0:	17ffff8d 	b	8020d0f4 <_free_r+0xf4>
    8020d2c4:	d280fe04 	mov	x4, #0x7f0                 	// #2032
    8020d2c8:	52800fc5 	mov	w5, #0x7e                  	// #126
    8020d2cc:	17ffff8a 	b	8020d0f4 <_free_r+0xf4>
    8020d2d0:	b2400040 	orr	x0, x2, #0x1
    8020d2d4:	f9000460 	str	x0, [x3, #8]
    8020d2d8:	f9000082 	str	x2, [x4]
    8020d2dc:	17ffffa9 	b	8020d180 <_free_r+0x180>

000000008020d2e0 <_strtol_l.part.0>:
    8020d2e0:	90000027 	adrp	x7, 80211000 <blanks.1+0x60>
    8020d2e4:	aa0003ec 	mov	x12, x0
    8020d2e8:	aa0103e6 	mov	x6, x1
    8020d2ec:	910c84e7 	add	x7, x7, #0x321
    8020d2f0:	aa0603e8 	mov	x8, x6
    8020d2f4:	384014c5 	ldrb	w5, [x6], #1
    8020d2f8:	386548e4 	ldrb	w4, [x7, w5, uxtw]
    8020d2fc:	371fffa4 	tbnz	w4, #3, 8020d2f0 <_strtol_l.part.0+0x10>
    8020d300:	7100b4bf 	cmp	w5, #0x2d
    8020d304:	54000700 	b.eq	8020d3e4 <_strtol_l.part.0+0x104>  // b.none
    8020d308:	92f0000b 	mov	x11, #0x7fffffffffffffff    	// #9223372036854775807
    8020d30c:	5280000d 	mov	w13, #0x0                   	// #0
    8020d310:	7100acbf 	cmp	w5, #0x2b
    8020d314:	54000620 	b.eq	8020d3d8 <_strtol_l.part.0+0xf8>  // b.none
    8020d318:	93407c6a 	sxtw	x10, w3
    8020d31c:	721b787f 	tst	w3, #0xffffffef
    8020d320:	540000c1 	b.ne	8020d338 <_strtol_l.part.0+0x58>  // b.any
    8020d324:	7100c0bf 	cmp	w5, #0x30
    8020d328:	54000780 	b.eq	8020d418 <_strtol_l.part.0+0x138>  // b.none
    8020d32c:	35000963 	cbnz	w3, 8020d458 <_strtol_l.part.0+0x178>
    8020d330:	d280014a 	mov	x10, #0xa                   	// #10
    8020d334:	2a0a03e3 	mov	w3, w10
    8020d338:	9aca0968 	udiv	x8, x11, x10
    8020d33c:	52800007 	mov	w7, #0x0                   	// #0
    8020d340:	d2800000 	mov	x0, #0x0                   	// #0
    8020d344:	1b0aad09 	msub	w9, w8, w10, w11
    8020d348:	5100c0a4 	sub	w4, w5, #0x30
    8020d34c:	7100249f 	cmp	w4, #0x9
    8020d350:	540000a9 	b.ls	8020d364 <_strtol_l.part.0+0x84>  // b.plast
    8020d354:	510104a4 	sub	w4, w5, #0x41
    8020d358:	7100649f 	cmp	w4, #0x19
    8020d35c:	54000208 	b.hi	8020d39c <_strtol_l.part.0+0xbc>  // b.pmore
    8020d360:	5100dca4 	sub	w4, w5, #0x37
    8020d364:	6b04007f 	cmp	w3, w4
    8020d368:	5400028d 	b.le	8020d3b8 <_strtol_l.part.0+0xd8>
    8020d36c:	710000ff 	cmp	w7, #0x0
    8020d370:	12800007 	mov	w7, #0xffffffff            	// #-1
    8020d374:	fa40a100 	ccmp	x8, x0, #0x0, ge	// ge = tcont
    8020d378:	540000e3 	b.cc	8020d394 <_strtol_l.part.0+0xb4>  // b.lo, b.ul, b.last
    8020d37c:	eb00011f 	cmp	x8, x0
    8020d380:	7a440120 	ccmp	w9, w4, #0x0, eq	// eq = none
    8020d384:	5400008b 	b.lt	8020d394 <_strtol_l.part.0+0xb4>  // b.tstop
    8020d388:	93407c84 	sxtw	x4, w4
    8020d38c:	52800027 	mov	w7, #0x1                   	// #1
    8020d390:	9b0a1000 	madd	x0, x0, x10, x4
    8020d394:	384014c5 	ldrb	w5, [x6], #1
    8020d398:	17ffffec 	b	8020d348 <_strtol_l.part.0+0x68>
    8020d39c:	510184a4 	sub	w4, w5, #0x61
    8020d3a0:	7100649f 	cmp	w4, #0x19
    8020d3a4:	540000a8 	b.hi	8020d3b8 <_strtol_l.part.0+0xd8>  // b.pmore
    8020d3a8:	51015ca4 	sub	w4, w5, #0x57
    8020d3ac:	6b04007f 	cmp	w3, w4
    8020d3b0:	54fffdec 	b.gt	8020d36c <_strtol_l.part.0+0x8c>
    8020d3b4:	d503201f 	nop
    8020d3b8:	310004ff 	cmn	w7, #0x1
    8020d3bc:	540001e0 	b.eq	8020d3f8 <_strtol_l.part.0+0x118>  // b.none
    8020d3c0:	710001bf 	cmp	w13, #0x0
    8020d3c4:	da800400 	cneg	x0, x0, ne	// ne = any
    8020d3c8:	b4000062 	cbz	x2, 8020d3d4 <_strtol_l.part.0+0xf4>
    8020d3cc:	35000387 	cbnz	w7, 8020d43c <_strtol_l.part.0+0x15c>
    8020d3d0:	f9000041 	str	x1, [x2]
    8020d3d4:	d65f03c0 	ret
    8020d3d8:	394000c5 	ldrb	w5, [x6]
    8020d3dc:	91000906 	add	x6, x8, #0x2
    8020d3e0:	17ffffce 	b	8020d318 <_strtol_l.part.0+0x38>
    8020d3e4:	394000c5 	ldrb	w5, [x6]
    8020d3e8:	d2f0000b 	mov	x11, #0x8000000000000000    	// #-9223372036854775808
    8020d3ec:	91000906 	add	x6, x8, #0x2
    8020d3f0:	5280002d 	mov	w13, #0x1                   	// #1
    8020d3f4:	17ffffc9 	b	8020d318 <_strtol_l.part.0+0x38>
    8020d3f8:	52800440 	mov	w0, #0x22                  	// #34
    8020d3fc:	b9000180 	str	w0, [x12]
    8020d400:	aa0b03e0 	mov	x0, x11
    8020d404:	b4fffe82 	cbz	x2, 8020d3d4 <_strtol_l.part.0+0xf4>
    8020d408:	d10004c1 	sub	x1, x6, #0x1
    8020d40c:	aa0b03e0 	mov	x0, x11
    8020d410:	f9000041 	str	x1, [x2]
    8020d414:	17fffff0 	b	8020d3d4 <_strtol_l.part.0+0xf4>
    8020d418:	394000c0 	ldrb	w0, [x6]
    8020d41c:	121a7800 	and	w0, w0, #0xffffffdf
    8020d420:	12001c00 	and	w0, w0, #0xff
    8020d424:	7101601f 	cmp	w0, #0x58
    8020d428:	540000e0 	b.eq	8020d444 <_strtol_l.part.0+0x164>  // b.none
    8020d42c:	35000163 	cbnz	w3, 8020d458 <_strtol_l.part.0+0x178>
    8020d430:	d280010a 	mov	x10, #0x8                   	// #8
    8020d434:	2a0a03e3 	mov	w3, w10
    8020d438:	17ffffc0 	b	8020d338 <_strtol_l.part.0+0x58>
    8020d43c:	aa0003eb 	mov	x11, x0
    8020d440:	17fffff2 	b	8020d408 <_strtol_l.part.0+0x128>
    8020d444:	394004c5 	ldrb	w5, [x6, #1]
    8020d448:	d280020a 	mov	x10, #0x10                  	// #16
    8020d44c:	910008c6 	add	x6, x6, #0x2
    8020d450:	2a0a03e3 	mov	w3, w10
    8020d454:	17ffffb9 	b	8020d338 <_strtol_l.part.0+0x58>
    8020d458:	d280020a 	mov	x10, #0x10                  	// #16
    8020d45c:	2a0a03e3 	mov	w3, w10
    8020d460:	17ffffb6 	b	8020d338 <_strtol_l.part.0+0x58>
	...

000000008020d470 <_strtol_r>:
    8020d470:	7100907f 	cmp	w3, #0x24
    8020d474:	7a419864 	ccmp	w3, #0x1, #0x4, ls	// ls = plast
    8020d478:	54000040 	b.eq	8020d480 <_strtol_r+0x10>  // b.none
    8020d47c:	17ffff99 	b	8020d2e0 <_strtol_l.part.0>
    8020d480:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020d484:	910003fd 	mov	x29, sp
    8020d488:	97ffd6de 	bl	80203000 <__errno>
    8020d48c:	528002c1 	mov	w1, #0x16                  	// #22
    8020d490:	b9000001 	str	w1, [x0]
    8020d494:	d2800000 	mov	x0, #0x0                   	// #0
    8020d498:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020d49c:	d65f03c0 	ret

000000008020d4a0 <strtol_l>:
    8020d4a0:	90000024 	adrp	x4, 80211000 <blanks.1+0x60>
    8020d4a4:	7100905f 	cmp	w2, #0x24
    8020d4a8:	7a419844 	ccmp	w2, #0x1, #0x4, ls	// ls = plast
    8020d4ac:	f9438884 	ldr	x4, [x4, #1808]
    8020d4b0:	540000c0 	b.eq	8020d4c8 <strtol_l+0x28>  // b.none
    8020d4b4:	2a0203e3 	mov	w3, w2
    8020d4b8:	aa0103e2 	mov	x2, x1
    8020d4bc:	aa0003e1 	mov	x1, x0
    8020d4c0:	aa0403e0 	mov	x0, x4
    8020d4c4:	17ffff87 	b	8020d2e0 <_strtol_l.part.0>
    8020d4c8:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020d4cc:	910003fd 	mov	x29, sp
    8020d4d0:	97ffd6cc 	bl	80203000 <__errno>
    8020d4d4:	528002c1 	mov	w1, #0x16                  	// #22
    8020d4d8:	b9000001 	str	w1, [x0]
    8020d4dc:	d2800000 	mov	x0, #0x0                   	// #0
    8020d4e0:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020d4e4:	d65f03c0 	ret
	...

000000008020d4f0 <strtol>:
    8020d4f0:	90000024 	adrp	x4, 80211000 <blanks.1+0x60>
    8020d4f4:	7100905f 	cmp	w2, #0x24
    8020d4f8:	7a419844 	ccmp	w2, #0x1, #0x4, ls	// ls = plast
    8020d4fc:	f9438884 	ldr	x4, [x4, #1808]
    8020d500:	540000c0 	b.eq	8020d518 <strtol+0x28>  // b.none
    8020d504:	2a0203e3 	mov	w3, w2
    8020d508:	aa0103e2 	mov	x2, x1
    8020d50c:	aa0003e1 	mov	x1, x0
    8020d510:	aa0403e0 	mov	x0, x4
    8020d514:	17ffff73 	b	8020d2e0 <_strtol_l.part.0>
    8020d518:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020d51c:	910003fd 	mov	x29, sp
    8020d520:	97ffd6b8 	bl	80203000 <__errno>
    8020d524:	528002c1 	mov	w1, #0x16                  	// #22
    8020d528:	b9000001 	str	w1, [x0]
    8020d52c:	d2800000 	mov	x0, #0x0                   	// #0
    8020d530:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020d534:	d65f03c0 	ret
	...

000000008020d540 <strncasecmp>:
    8020d540:	aa0003e9 	mov	x9, x0
    8020d544:	b4000342 	cbz	x2, 8020d5ac <strncasecmp+0x6c>
    8020d548:	90000027 	adrp	x7, 80211000 <blanks.1+0x60>
    8020d54c:	d2800004 	mov	x4, #0x0                   	// #0
    8020d550:	910c84e7 	add	x7, x7, #0x321
    8020d554:	14000006 	b	8020d56c <strncasecmp+0x2c>
    8020d558:	6b000063 	subs	w3, w3, w0
    8020d55c:	540002c1 	b.ne	8020d5b4 <strncasecmp+0x74>  // b.any
    8020d560:	34000240 	cbz	w0, 8020d5a8 <strncasecmp+0x68>
    8020d564:	eb04005f 	cmp	x2, x4
    8020d568:	54000220 	b.eq	8020d5ac <strncasecmp+0x6c>  // b.none
    8020d56c:	38646923 	ldrb	w3, [x9, x4]
    8020d570:	38646820 	ldrb	w0, [x1, x4]
    8020d574:	91000484 	add	x4, x4, #0x1
    8020d578:	11008068 	add	w8, w3, #0x20
    8020d57c:	386348e6 	ldrb	w6, [x7, w3, uxtw]
    8020d580:	386048e5 	ldrb	w5, [x7, w0, uxtw]
    8020d584:	120004c6 	and	w6, w6, #0x3
    8020d588:	710004df 	cmp	w6, #0x1
    8020d58c:	120004a5 	and	w5, w5, #0x3
    8020d590:	1a830103 	csel	w3, w8, w3, eq	// eq = none
    8020d594:	710004bf 	cmp	w5, #0x1
    8020d598:	54fffe01 	b.ne	8020d558 <strncasecmp+0x18>  // b.any
    8020d59c:	11008000 	add	w0, w0, #0x20
    8020d5a0:	6b000060 	subs	w0, w3, w0
    8020d5a4:	54fffe00 	b.eq	8020d564 <strncasecmp+0x24>  // b.none
    8020d5a8:	d65f03c0 	ret
    8020d5ac:	52800000 	mov	w0, #0x0                   	// #0
    8020d5b0:	d65f03c0 	ret
    8020d5b4:	2a0303e0 	mov	w0, w3
    8020d5b8:	d65f03c0 	ret
    8020d5bc:	00000000 	udf	#0

000000008020d5c0 <_findenv_r>:
    8020d5c0:	a9bb7bfd 	stp	x29, x30, [sp, #-80]!
    8020d5c4:	910003fd 	mov	x29, sp
    8020d5c8:	a90363f7 	stp	x23, x24, [sp, #48]
    8020d5cc:	b0000038 	adrp	x24, 80212000 <__malloc_av_+0x760>
    8020d5d0:	aa0003f7 	mov	x23, x0
    8020d5d4:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d5d8:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020d5dc:	aa0103f5 	mov	x21, x1
    8020d5e0:	aa0203f6 	mov	x22, x2
    8020d5e4:	94000ac7 	bl	80210100 <__env_lock>
    8020d5e8:	f941bb14 	ldr	x20, [x24, #880]
    8020d5ec:	b40003f4 	cbz	x20, 8020d668 <_findenv_r+0xa8>
    8020d5f0:	394002a3 	ldrb	w3, [x21]
    8020d5f4:	aa1503f3 	mov	x19, x21
    8020d5f8:	7100f47f 	cmp	w3, #0x3d
    8020d5fc:	7a401864 	ccmp	w3, #0x0, #0x4, ne	// ne = any
    8020d600:	540000c0 	b.eq	8020d618 <_findenv_r+0x58>  // b.none
    8020d604:	d503201f 	nop
    8020d608:	38401e63 	ldrb	w3, [x19, #1]!
    8020d60c:	7100f47f 	cmp	w3, #0x3d
    8020d610:	7a401864 	ccmp	w3, #0x0, #0x4, ne	// ne = any
    8020d614:	54ffffa1 	b.ne	8020d608 <_findenv_r+0x48>  // b.any
    8020d618:	7100f47f 	cmp	w3, #0x3d
    8020d61c:	54000260 	b.eq	8020d668 <_findenv_r+0xa8>  // b.none
    8020d620:	f9400280 	ldr	x0, [x20]
    8020d624:	cb150273 	sub	x19, x19, x21
    8020d628:	b4000200 	cbz	x0, 8020d668 <_findenv_r+0xa8>
    8020d62c:	93407e73 	sxtw	x19, w19
    8020d630:	f90023f9 	str	x25, [sp, #64]
    8020d634:	d503201f 	nop
    8020d638:	aa1303e2 	mov	x2, x19
    8020d63c:	aa1503e1 	mov	x1, x21
    8020d640:	94000310 	bl	8020e280 <strncmp>
    8020d644:	350000c0 	cbnz	w0, 8020d65c <_findenv_r+0x9c>
    8020d648:	f9400280 	ldr	x0, [x20]
    8020d64c:	8b130019 	add	x25, x0, x19
    8020d650:	38736800 	ldrb	w0, [x0, x19]
    8020d654:	7100f41f 	cmp	w0, #0x3d
    8020d658:	54000180 	b.eq	8020d688 <_findenv_r+0xc8>  // b.none
    8020d65c:	f8408e80 	ldr	x0, [x20, #8]!
    8020d660:	b5fffec0 	cbnz	x0, 8020d638 <_findenv_r+0x78>
    8020d664:	f94023f9 	ldr	x25, [sp, #64]
    8020d668:	aa1703e0 	mov	x0, x23
    8020d66c:	94000aa9 	bl	80210110 <__env_unlock>
    8020d670:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d674:	d2800000 	mov	x0, #0x0                   	// #0
    8020d678:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020d67c:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020d680:	a8c57bfd 	ldp	x29, x30, [sp], #80
    8020d684:	d65f03c0 	ret
    8020d688:	f941bb01 	ldr	x1, [x24, #880]
    8020d68c:	aa1703e0 	mov	x0, x23
    8020d690:	cb010281 	sub	x1, x20, x1
    8020d694:	9343fc21 	asr	x1, x1, #3
    8020d698:	b90002c1 	str	w1, [x22]
    8020d69c:	94000a9d 	bl	80210110 <__env_unlock>
    8020d6a0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d6a4:	91000720 	add	x0, x25, #0x1
    8020d6a8:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020d6ac:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020d6b0:	f94023f9 	ldr	x25, [sp, #64]
    8020d6b4:	a8c57bfd 	ldp	x29, x30, [sp], #80
    8020d6b8:	d65f03c0 	ret
    8020d6bc:	00000000 	udf	#0

000000008020d6c0 <_getenv_r>:
    8020d6c0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020d6c4:	910003fd 	mov	x29, sp
    8020d6c8:	910073e2 	add	x2, sp, #0x1c
    8020d6cc:	97ffffbd 	bl	8020d5c0 <_findenv_r>
    8020d6d0:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d6d4:	d65f03c0 	ret
	...

000000008020d6e0 <strncpy>:
    8020d6e0:	aa000023 	orr	x3, x1, x0
    8020d6e4:	aa0003e4 	mov	x4, x0
    8020d6e8:	f240087f 	tst	x3, #0x7
    8020d6ec:	fa470840 	ccmp	x2, #0x7, #0x0, eq	// eq = none
    8020d6f0:	54000109 	b.ls	8020d710 <strncpy+0x30>  // b.plast
    8020d6f4:	14000011 	b	8020d738 <strncpy+0x58>
    8020d6f8:	38401425 	ldrb	w5, [x1], #1
    8020d6fc:	d1000446 	sub	x6, x2, #0x1
    8020d700:	38001465 	strb	w5, [x3], #1
    8020d704:	340000c5 	cbz	w5, 8020d71c <strncpy+0x3c>
    8020d708:	aa0303e4 	mov	x4, x3
    8020d70c:	aa0603e2 	mov	x2, x6
    8020d710:	aa0403e3 	mov	x3, x4
    8020d714:	b5ffff22 	cbnz	x2, 8020d6f8 <strncpy+0x18>
    8020d718:	d65f03c0 	ret
    8020d71c:	8b020084 	add	x4, x4, x2
    8020d720:	b4ffffc6 	cbz	x6, 8020d718 <strncpy+0x38>
    8020d724:	d503201f 	nop
    8020d728:	3800147f 	strb	wzr, [x3], #1
    8020d72c:	eb04007f 	cmp	x3, x4
    8020d730:	54ffffc1 	b.ne	8020d728 <strncpy+0x48>  // b.any
    8020d734:	d65f03c0 	ret
    8020d738:	b207dbe6 	mov	x6, #0xfefefefefefefefe    	// #-72340172838076674
    8020d73c:	f29fdfe6 	movk	x6, #0xfeff
    8020d740:	14000006 	b	8020d758 <strncpy+0x78>
    8020d744:	d1002042 	sub	x2, x2, #0x8
    8020d748:	f8008485 	str	x5, [x4], #8
    8020d74c:	91002021 	add	x1, x1, #0x8
    8020d750:	f1001c5f 	cmp	x2, #0x7
    8020d754:	54fffde9 	b.ls	8020d710 <strncpy+0x30>  // b.plast
    8020d758:	f9400025 	ldr	x5, [x1]
    8020d75c:	8b0600a3 	add	x3, x5, x6
    8020d760:	8a250063 	bic	x3, x3, x5
    8020d764:	f201c07f 	tst	x3, #0x8080808080808080
    8020d768:	54fffee0 	b.eq	8020d744 <strncpy+0x64>  // b.none
    8020d76c:	17ffffe9 	b	8020d710 <strncpy+0x30>

000000008020d770 <_fstat_r>:
    8020d770:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020d774:	910003fd 	mov	x29, sp
    8020d778:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d77c:	900003b4 	adrp	x20, 80281000 <__sf+0x38>
    8020d780:	aa0003f3 	mov	x19, x0
    8020d784:	b9044a9f 	str	wzr, [x20, #1096]
    8020d788:	2a0103e0 	mov	w0, w1
    8020d78c:	aa0203e1 	mov	x1, x2
    8020d790:	97ffcc78 	bl	80200970 <_fstat>
    8020d794:	3100041f 	cmn	w0, #0x1
    8020d798:	54000080 	b.eq	8020d7a8 <_fstat_r+0x38>  // b.none
    8020d79c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d7a0:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d7a4:	d65f03c0 	ret
    8020d7a8:	b9444a81 	ldr	w1, [x20, #1096]
    8020d7ac:	34ffff81 	cbz	w1, 8020d79c <_fstat_r+0x2c>
    8020d7b0:	b9000261 	str	w1, [x19]
    8020d7b4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d7b8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d7bc:	d65f03c0 	ret

000000008020d7c0 <_isatty_r>:
    8020d7c0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020d7c4:	910003fd 	mov	x29, sp
    8020d7c8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d7cc:	900003b4 	adrp	x20, 80281000 <__sf+0x38>
    8020d7d0:	aa0003f3 	mov	x19, x0
    8020d7d4:	b9044a9f 	str	wzr, [x20, #1096]
    8020d7d8:	2a0103e0 	mov	w0, w1
    8020d7dc:	97ffcc69 	bl	80200980 <_isatty>
    8020d7e0:	3100041f 	cmn	w0, #0x1
    8020d7e4:	54000080 	b.eq	8020d7f4 <_isatty_r+0x34>  // b.none
    8020d7e8:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d7ec:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d7f0:	d65f03c0 	ret
    8020d7f4:	b9444a81 	ldr	w1, [x20, #1096]
    8020d7f8:	34ffff81 	cbz	w1, 8020d7e8 <_isatty_r+0x28>
    8020d7fc:	b9000261 	str	w1, [x19]
    8020d800:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d804:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d808:	d65f03c0 	ret
    8020d80c:	00000000 	udf	#0

000000008020d810 <_lseek_r>:
    8020d810:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020d814:	910003fd 	mov	x29, sp
    8020d818:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d81c:	900003b4 	adrp	x20, 80281000 <__sf+0x38>
    8020d820:	aa0003f3 	mov	x19, x0
    8020d824:	b9044a9f 	str	wzr, [x20, #1096]
    8020d828:	2a0103e0 	mov	w0, w1
    8020d82c:	aa0203e1 	mov	x1, x2
    8020d830:	2a0303e2 	mov	w2, w3
    8020d834:	97ffcc40 	bl	80200934 <_lseek>
    8020d838:	b100041f 	cmn	x0, #0x1
    8020d83c:	54000080 	b.eq	8020d84c <_lseek_r+0x3c>  // b.none
    8020d840:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d844:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d848:	d65f03c0 	ret
    8020d84c:	b9444a81 	ldr	w1, [x20, #1096]
    8020d850:	34ffff81 	cbz	w1, 8020d840 <_lseek_r+0x30>
    8020d854:	b9000261 	str	w1, [x19]
    8020d858:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d85c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d860:	d65f03c0 	ret
	...

000000008020d870 <_read_r>:
    8020d870:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020d874:	910003fd 	mov	x29, sp
    8020d878:	a90153f3 	stp	x19, x20, [sp, #16]
    8020d87c:	900003b4 	adrp	x20, 80281000 <__sf+0x38>
    8020d880:	aa0003f3 	mov	x19, x0
    8020d884:	2a0103e0 	mov	w0, w1
    8020d888:	aa0203e1 	mov	x1, x2
    8020d88c:	b9044a9f 	str	wzr, [x20, #1096]
    8020d890:	aa0303e2 	mov	x2, x3
    8020d894:	97ffcbf7 	bl	80200870 <_read>
    8020d898:	93407c01 	sxtw	x1, w0
    8020d89c:	3100041f 	cmn	w0, #0x1
    8020d8a0:	540000a0 	b.eq	8020d8b4 <_read_r+0x44>  // b.none
    8020d8a4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d8a8:	aa0103e0 	mov	x0, x1
    8020d8ac:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d8b0:	d65f03c0 	ret
    8020d8b4:	b9444a80 	ldr	w0, [x20, #1096]
    8020d8b8:	34ffff60 	cbz	w0, 8020d8a4 <_read_r+0x34>
    8020d8bc:	b9000260 	str	w0, [x19]
    8020d8c0:	aa0103e0 	mov	x0, x1
    8020d8c4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020d8c8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020d8cc:	d65f03c0 	ret
	...

000000008020d900 <strchr>:
    8020d900:	d503245f 	bti	c
    8020d904:	52818064 	mov	w4, #0xc03                 	// #3075
    8020d908:	72b80604 	movk	w4, #0xc030, lsl #16
    8020d90c:	4e010c20 	dup	v0.16b, w1
    8020d910:	927be802 	and	x2, x0, #0xffffffffffffffe0
    8020d914:	4e040c90 	dup	v16.4s, w4
    8020d918:	f2401003 	ands	x3, x0, #0x1f
    8020d91c:	4eb08607 	add	v7.4s, v16.4s, v16.4s
    8020d920:	54000280 	b.eq	8020d970 <strchr+0x70>  // b.none
    8020d924:	4cdfa041 	ld1	{v1.16b-v2.16b}, [x2], #32
    8020d928:	cb0303e3 	neg	x3, x3
    8020d92c:	4e209823 	cmeq	v3.16b, v1.16b, #0
    8020d930:	6e208c25 	cmeq	v5.16b, v1.16b, v0.16b
    8020d934:	4e209844 	cmeq	v4.16b, v2.16b, #0
    8020d938:	6e208c46 	cmeq	v6.16b, v2.16b, v0.16b
    8020d93c:	6ee71ca3 	bif	v3.16b, v5.16b, v7.16b
    8020d940:	6ee71cc4 	bif	v4.16b, v6.16b, v7.16b
    8020d944:	4e301c71 	and	v17.16b, v3.16b, v16.16b
    8020d948:	4e301c92 	and	v18.16b, v4.16b, v16.16b
    8020d94c:	d37ff863 	lsl	x3, x3, #1
    8020d950:	4e32be31 	addp	v17.16b, v17.16b, v18.16b
    8020d954:	92800005 	mov	x5, #0xffffffffffffffff    	// #-1
    8020d958:	4e32be31 	addp	v17.16b, v17.16b, v18.16b
    8020d95c:	9ac324a3 	lsr	x3, x5, x3
    8020d960:	4e083e25 	mov	x5, v17.d[0]
    8020d964:	8a2300a3 	bic	x3, x5, x3
    8020d968:	b5000243 	cbnz	x3, 8020d9b0 <strchr+0xb0>
    8020d96c:	d503201f 	nop
    8020d970:	4cdfa041 	ld1	{v1.16b-v2.16b}, [x2], #32
    8020d974:	6e208c25 	cmeq	v5.16b, v1.16b, v0.16b
    8020d978:	6e208c46 	cmeq	v6.16b, v2.16b, v0.16b
    8020d97c:	6e213ca3 	cmhs	v3.16b, v5.16b, v1.16b
    8020d980:	6e223cc4 	cmhs	v4.16b, v6.16b, v2.16b
    8020d984:	4ea41c71 	orr	v17.16b, v3.16b, v4.16b
    8020d988:	6e31a631 	umaxp	v17.16b, v17.16b, v17.16b
    8020d98c:	4e083e23 	mov	x3, v17.d[0]
    8020d990:	b4ffff03 	cbz	x3, 8020d970 <strchr+0x70>
    8020d994:	6ee71ca3 	bif	v3.16b, v5.16b, v7.16b
    8020d998:	6ee71cc4 	bif	v4.16b, v6.16b, v7.16b
    8020d99c:	4e301c71 	and	v17.16b, v3.16b, v16.16b
    8020d9a0:	4e301c92 	and	v18.16b, v4.16b, v16.16b
    8020d9a4:	4e32be31 	addp	v17.16b, v17.16b, v18.16b
    8020d9a8:	4e32be31 	addp	v17.16b, v17.16b, v18.16b
    8020d9ac:	4e083e23 	mov	x3, v17.d[0]
    8020d9b0:	dac00063 	rbit	x3, x3
    8020d9b4:	d1008042 	sub	x2, x2, #0x20
    8020d9b8:	dac01063 	clz	x3, x3
    8020d9bc:	f240007f 	tst	x3, #0x1
    8020d9c0:	8b430440 	add	x0, x2, x3, lsr #1
    8020d9c4:	9a9f0000 	csel	x0, x0, xzr, eq	// eq = none
    8020d9c8:	d65f03c0 	ret
	...

000000008020da00 <strcmp>:
    8020da00:	d503245f 	bti	c
    8020da04:	cb00002a 	sub	x10, x1, x0
    8020da08:	b200c3e8 	mov	x8, #0x101010101010101     	// #72340172838076673
    8020da0c:	92400806 	and	x6, x0, #0x7
    8020da10:	f240095f 	tst	x10, #0x7
    8020da14:	54000401 	b.ne	8020da94 <strcmp+0x94>  // b.any
    8020da18:	b50002c6 	cbnz	x6, 8020da70 <strcmp+0x70>
    8020da1c:	d503201f 	nop
    8020da20:	f86a6803 	ldr	x3, [x0, x10]
    8020da24:	f8408402 	ldr	x2, [x0], #8
    8020da28:	cb080044 	sub	x4, x2, x8
    8020da2c:	b200d846 	orr	x6, x2, #0x7f7f7f7f7f7f7f7f
    8020da30:	ea260084 	bics	x4, x4, x6
    8020da34:	fa430040 	ccmp	x2, x3, #0x0, eq	// eq = none
    8020da38:	54ffff40 	b.eq	8020da20 <strcmp+0x20>  // b.none
    8020da3c:	ca030045 	eor	x5, x2, x3
    8020da40:	aa0400a6 	orr	x6, x5, x4
    8020da44:	dac00cc6 	rev	x6, x6
    8020da48:	dac00c42 	rev	x2, x2
    8020da4c:	dac00c63 	rev	x3, x3
    8020da50:	dac010c9 	clz	x9, x6
    8020da54:	9ac92042 	lsl	x2, x2, x9
    8020da58:	9ac92063 	lsl	x3, x3, x9
    8020da5c:	d378fc42 	lsr	x2, x2, #56
    8020da60:	cb43e040 	sub	x0, x2, x3, lsr #56
    8020da64:	d65f03c0 	ret
    8020da68:	d503201f 	nop
    8020da6c:	d503201f 	nop
    8020da70:	927df000 	and	x0, x0, #0xfffffffffffffff8
    8020da74:	f86a6803 	ldr	x3, [x0, x10]
    8020da78:	f8408402 	ldr	x2, [x0], #8
    8020da7c:	cb010fe9 	neg	x9, x1, lsl #3
    8020da80:	92800006 	mov	x6, #0xffffffffffffffff    	// #-1
    8020da84:	9ac924c6 	lsr	x6, x6, x9
    8020da88:	aa060042 	orr	x2, x2, x6
    8020da8c:	aa060063 	orr	x3, x3, x6
    8020da90:	17ffffe6 	b	8020da28 <strcmp+0x28>
    8020da94:	b4000106 	cbz	x6, 8020dab4 <strcmp+0xb4>
    8020da98:	38401402 	ldrb	w2, [x0], #1
    8020da9c:	38401423 	ldrb	w3, [x1], #1
    8020daa0:	7100005f 	cmp	w2, #0x0
    8020daa4:	7a431040 	ccmp	w2, w3, #0x0, ne	// ne = any
    8020daa8:	54000421 	b.ne	8020db2c <strcmp+0x12c>  // b.any
    8020daac:	f240081f 	tst	x0, #0x7
    8020dab0:	54ffff41 	b.ne	8020da98 <strcmp+0x98>  // b.any
    8020dab4:	cb010fe9 	neg	x9, x1, lsl #3
    8020dab8:	927df021 	and	x1, x1, #0xfffffffffffffff8
    8020dabc:	f8408427 	ldr	x7, [x1], #8
    8020dac0:	9ac92506 	lsr	x6, x8, x9
    8020dac4:	aa0600e7 	orr	x7, x7, x6
    8020dac8:	cb0800e4 	sub	x4, x7, x8
    8020dacc:	b200d8e6 	orr	x6, x7, #0x7f7f7f7f7f7f7f7f
    8020dad0:	ea260084 	bics	x4, x4, x6
    8020dad4:	540001e1 	b.ne	8020db10 <strcmp+0x110>  // b.any
    8020dad8:	cb000025 	sub	x5, x1, x0
    8020dadc:	d503201f 	nop
    8020dae0:	f8656807 	ldr	x7, [x0, x5]
    8020dae4:	f86a6803 	ldr	x3, [x0, x10]
    8020dae8:	cb0800e4 	sub	x4, x7, x8
    8020daec:	b200d8e6 	orr	x6, x7, #0x7f7f7f7f7f7f7f7f
    8020daf0:	f8408402 	ldr	x2, [x0], #8
    8020daf4:	ea260084 	bics	x4, x4, x6
    8020daf8:	fa430040 	ccmp	x2, x3, #0x0, eq	// eq = none
    8020dafc:	54ffff20 	b.eq	8020dae0 <strcmp+0xe0>  // b.none
    8020db00:	9ac92086 	lsl	x6, x4, x9
    8020db04:	ca030045 	eor	x5, x2, x3
    8020db08:	aa0600a6 	orr	x6, x5, x6
    8020db0c:	b5fff9c6 	cbnz	x6, 8020da44 <strcmp+0x44>
    8020db10:	f9400002 	ldr	x2, [x0]
    8020db14:	cb0903e9 	neg	x9, x9
    8020db18:	9ac924e3 	lsr	x3, x7, x9
    8020db1c:	9ac92484 	lsr	x4, x4, x9
    8020db20:	ca030045 	eor	x5, x2, x3
    8020db24:	aa0400a6 	orr	x6, x5, x4
    8020db28:	17ffffc7 	b	8020da44 <strcmp+0x44>
    8020db2c:	cb030040 	sub	x0, x2, x3
    8020db30:	d65f03c0 	ret
	...

000000008020db40 <strcpy>:
    8020db40:	d503245f 	bti	c
    8020db44:	927cec22 	and	x2, x1, #0xfffffffffffffff0
    8020db48:	4c407040 	ld1	{v0.16b}, [x2]
    8020db4c:	4e209801 	cmeq	v1.16b, v0.16b, #0
    8020db50:	d37ef425 	lsl	x5, x1, #2
    8020db54:	0f0c8422 	shrn	v2.8b, v1.8h, #4
    8020db58:	9e660044 	fmov	x4, d2
    8020db5c:	9ac52484 	lsr	x4, x4, x5
    8020db60:	b5000224 	cbnz	x4, 8020dba4 <strcpy+0x64>
    8020db64:	3cc10c40 	ldr	q0, [x2, #16]!
    8020db68:	4e209801 	cmeq	v1.16b, v0.16b, #0
    8020db6c:	0f0c8422 	shrn	v2.8b, v1.8h, #4
    8020db70:	9e660044 	fmov	x4, d2
    8020db74:	b4000464 	cbz	x4, 8020dc00 <strcpy+0xc0>
    8020db78:	dac00084 	rbit	x4, x4
    8020db7c:	cb010045 	sub	x5, x2, x1
    8020db80:	dac01084 	clz	x4, x4
    8020db84:	8b4408a4 	add	x4, x5, x4, lsr #2
    8020db88:	36200144 	tbz	w4, #4, 8020dbb0 <strcpy+0x70>
    8020db8c:	d1003c85 	sub	x5, x4, #0xf
    8020db90:	3dc00020 	ldr	q0, [x1]
    8020db94:	3ce56821 	ldr	q1, [x1, x5]
    8020db98:	3d800000 	str	q0, [x0]
    8020db9c:	3ca56801 	str	q1, [x0, x5]
    8020dba0:	d65f03c0 	ret
    8020dba4:	dac00084 	rbit	x4, x4
    8020dba8:	dac01084 	clz	x4, x4
    8020dbac:	d342fc84 	lsr	x4, x4, #2
    8020dbb0:	36180104 	tbz	w4, #3, 8020dbd0 <strcpy+0x90>
    8020dbb4:	d1001c85 	sub	x5, x4, #0x7
    8020dbb8:	f9400026 	ldr	x6, [x1]
    8020dbbc:	f8656827 	ldr	x7, [x1, x5]
    8020dbc0:	f9000006 	str	x6, [x0]
    8020dbc4:	f8256807 	str	x7, [x0, x5]
    8020dbc8:	d65f03c0 	ret
    8020dbcc:	d503201f 	nop
    8020dbd0:	f1000c85 	subs	x5, x4, #0x3
    8020dbd4:	540000c3 	b.cc	8020dbec <strcpy+0xac>  // b.lo, b.ul, b.last
    8020dbd8:	b9400026 	ldr	w6, [x1]
    8020dbdc:	b8656827 	ldr	w7, [x1, x5]
    8020dbe0:	b9000006 	str	w6, [x0]
    8020dbe4:	b8256807 	str	w7, [x0, x5]
    8020dbe8:	d65f03c0 	ret
    8020dbec:	b4000064 	cbz	x4, 8020dbf8 <strcpy+0xb8>
    8020dbf0:	79400026 	ldrh	w6, [x1]
    8020dbf4:	79000006 	strh	w6, [x0]
    8020dbf8:	3824681f 	strb	wzr, [x0, x4]
    8020dbfc:	d65f03c0 	ret
    8020dc00:	cb000025 	sub	x5, x1, x0
    8020dc04:	3dc00021 	ldr	q1, [x1]
    8020dc08:	cb050043 	sub	x3, x2, x5
    8020dc0c:	3d800001 	str	q1, [x0]
    8020dc10:	3c820460 	str	q0, [x3], #32
    8020dc14:	3dc00440 	ldr	q0, [x2, #16]
    8020dc18:	4e209801 	cmeq	v1.16b, v0.16b, #0
    8020dc1c:	6e21a422 	umaxp	v2.16b, v1.16b, v1.16b
    8020dc20:	9e660044 	fmov	x4, d2
    8020dc24:	b5000104 	cbnz	x4, 8020dc44 <strcpy+0x104>
    8020dc28:	3c9f0060 	stur	q0, [x3, #-16]
    8020dc2c:	3cc20c40 	ldr	q0, [x2, #32]!
    8020dc30:	4e209801 	cmeq	v1.16b, v0.16b, #0
    8020dc34:	6e21a422 	umaxp	v2.16b, v1.16b, v1.16b
    8020dc38:	9e660044 	fmov	x4, d2
    8020dc3c:	b4fffea4 	cbz	x4, 8020dc10 <strcpy+0xd0>
    8020dc40:	91004063 	add	x3, x3, #0x10
    8020dc44:	0f0c8422 	shrn	v2.8b, v1.8h, #4
    8020dc48:	9e660044 	fmov	x4, d2
    8020dc4c:	d1007c63 	sub	x3, x3, #0x1f
    8020dc50:	dac00084 	rbit	x4, x4
    8020dc54:	dac01084 	clz	x4, x4
    8020dc58:	d342fc84 	lsr	x4, x4, #2
    8020dc5c:	8b040063 	add	x3, x3, x4
    8020dc60:	3ce56860 	ldr	q0, [x3, x5]
    8020dc64:	3d800060 	str	q0, [x3]
    8020dc68:	d65f03c0 	ret
    8020dc6c:	00000000 	udf	#0

000000008020dc70 <__fputwc>:
    8020dc70:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020dc74:	910003fd 	mov	x29, sp
    8020dc78:	a90153f3 	stp	x19, x20, [sp, #16]
    8020dc7c:	2a0103f4 	mov	w20, w1
    8020dc80:	aa0203f3 	mov	x19, x2
    8020dc84:	f90013f5 	str	x21, [sp, #32]
    8020dc88:	aa0003f5 	mov	x21, x0
    8020dc8c:	97fff305 	bl	8020a8a0 <__locale_mb_cur_max>
    8020dc90:	7100041f 	cmp	w0, #0x1
    8020dc94:	54000081 	b.ne	8020dca4 <__fputwc+0x34>  // b.any
    8020dc98:	51000680 	sub	w0, w20, #0x1
    8020dc9c:	7103f81f 	cmp	w0, #0xfe
    8020dca0:	540004a9 	b.ls	8020dd34 <__fputwc+0xc4>  // b.plast
    8020dca4:	9102a263 	add	x3, x19, #0xa8
    8020dca8:	2a1403e2 	mov	w2, w20
    8020dcac:	9100e3e1 	add	x1, sp, #0x38
    8020dcb0:	aa1503e0 	mov	x0, x21
    8020dcb4:	97ffef63 	bl	80209a40 <_wcrtomb_r>
    8020dcb8:	b100041f 	cmn	x0, #0x1
    8020dcbc:	54000400 	b.eq	8020dd3c <__fputwc+0xcc>  // b.none
    8020dcc0:	b40001c0 	cbz	x0, 8020dcf8 <__fputwc+0x88>
    8020dcc4:	b9400e63 	ldr	w3, [x19, #12]
    8020dcc8:	3940e3e1 	ldrb	w1, [sp, #56]
    8020dccc:	51000463 	sub	w3, w3, #0x1
    8020dcd0:	b9000e63 	str	w3, [x19, #12]
    8020dcd4:	36f800a3 	tbz	w3, #31, 8020dce8 <__fputwc+0x78>
    8020dcd8:	b9402a64 	ldr	w4, [x19, #40]
    8020dcdc:	6b04007f 	cmp	w3, w4
    8020dce0:	7a4aa824 	ccmp	w1, #0xa, #0x4, ge	// ge = tcont
    8020dce4:	54000140 	b.eq	8020dd0c <__fputwc+0x9c>  // b.none
    8020dce8:	f9400263 	ldr	x3, [x19]
    8020dcec:	91000464 	add	x4, x3, #0x1
    8020dcf0:	f9000264 	str	x4, [x19]
    8020dcf4:	39000061 	strb	w1, [x3]
    8020dcf8:	f94013f5 	ldr	x21, [sp, #32]
    8020dcfc:	2a1403e0 	mov	w0, w20
    8020dd00:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020dd04:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020dd08:	d65f03c0 	ret
    8020dd0c:	aa1303e2 	mov	x2, x19
    8020dd10:	aa1503e0 	mov	x0, x21
    8020dd14:	940001cb 	bl	8020e440 <__swbuf_r>
    8020dd18:	3100041f 	cmn	w0, #0x1
    8020dd1c:	54fffee1 	b.ne	8020dcf8 <__fputwc+0x88>  // b.any
    8020dd20:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020dd24:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020dd28:	f94013f5 	ldr	x21, [sp, #32]
    8020dd2c:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020dd30:	d65f03c0 	ret
    8020dd34:	3900e3f4 	strb	w20, [sp, #56]
    8020dd38:	17ffffe3 	b	8020dcc4 <__fputwc+0x54>
    8020dd3c:	79402260 	ldrh	w0, [x19, #16]
    8020dd40:	321a0000 	orr	w0, w0, #0x40
    8020dd44:	79002260 	strh	w0, [x19, #16]
    8020dd48:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020dd4c:	17fffff6 	b	8020dd24 <__fputwc+0xb4>

000000008020dd50 <_fputwc_r>:
    8020dd50:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020dd54:	910003fd 	mov	x29, sp
    8020dd58:	a90153f3 	stp	x19, x20, [sp, #16]
    8020dd5c:	aa0003f4 	mov	x20, x0
    8020dd60:	b940b040 	ldr	w0, [x2, #176]
    8020dd64:	aa0203f3 	mov	x19, x2
    8020dd68:	79c02042 	ldrsh	w2, [x2, #16]
    8020dd6c:	37000040 	tbnz	w0, #0, 8020dd74 <_fputwc_r+0x24>
    8020dd70:	36480322 	tbz	w2, #9, 8020ddd4 <_fputwc_r+0x84>
    8020dd74:	376800c2 	tbnz	w2, #13, 8020dd8c <_fputwc_r+0x3c>
    8020dd78:	b940b260 	ldr	w0, [x19, #176]
    8020dd7c:	32130042 	orr	w2, w2, #0x2000
    8020dd80:	79002262 	strh	w2, [x19, #16]
    8020dd84:	32130000 	orr	w0, w0, #0x2000
    8020dd88:	b900b260 	str	w0, [x19, #176]
    8020dd8c:	aa1403e0 	mov	x0, x20
    8020dd90:	aa1303e2 	mov	x2, x19
    8020dd94:	97ffffb7 	bl	8020dc70 <__fputwc>
    8020dd98:	2a0003f4 	mov	w20, w0
    8020dd9c:	b940b261 	ldr	w1, [x19, #176]
    8020dda0:	37000061 	tbnz	w1, #0, 8020ddac <_fputwc_r+0x5c>
    8020dda4:	79402260 	ldrh	w0, [x19, #16]
    8020dda8:	364800a0 	tbz	w0, #9, 8020ddbc <_fputwc_r+0x6c>
    8020ddac:	2a1403e0 	mov	w0, w20
    8020ddb0:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ddb4:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020ddb8:	d65f03c0 	ret
    8020ddbc:	f9405260 	ldr	x0, [x19, #160]
    8020ddc0:	97ffef90 	bl	80209c00 <__retarget_lock_release_recursive>
    8020ddc4:	2a1403e0 	mov	w0, w20
    8020ddc8:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ddcc:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020ddd0:	d65f03c0 	ret
    8020ddd4:	f9405260 	ldr	x0, [x19, #160]
    8020ddd8:	b9002fe1 	str	w1, [sp, #44]
    8020dddc:	97ffef79 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    8020dde0:	79c02262 	ldrsh	w2, [x19, #16]
    8020dde4:	b9402fe1 	ldr	w1, [sp, #44]
    8020dde8:	17ffffe3 	b	8020dd74 <_fputwc_r+0x24>
    8020ddec:	00000000 	udf	#0

000000008020ddf0 <fputwc>:
    8020ddf0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020ddf4:	90000022 	adrp	x2, 80211000 <blanks.1+0x60>
    8020ddf8:	910003fd 	mov	x29, sp
    8020ddfc:	f90013f5 	str	x21, [sp, #32]
    8020de00:	f9438855 	ldr	x21, [x2, #1808]
    8020de04:	a90153f3 	stp	x19, x20, [sp, #16]
    8020de08:	2a0003f4 	mov	w20, w0
    8020de0c:	aa0103f3 	mov	x19, x1
    8020de10:	b4000075 	cbz	x21, 8020de1c <fputwc+0x2c>
    8020de14:	f94026a0 	ldr	x0, [x21, #72]
    8020de18:	b4000480 	cbz	x0, 8020dea8 <fputwc+0xb8>
    8020de1c:	b940b260 	ldr	w0, [x19, #176]
    8020de20:	79c02262 	ldrsh	w2, [x19, #16]
    8020de24:	37000040 	tbnz	w0, #0, 8020de2c <fputwc+0x3c>
    8020de28:	36480382 	tbz	w2, #9, 8020de98 <fputwc+0xa8>
    8020de2c:	376800c2 	tbnz	w2, #13, 8020de44 <fputwc+0x54>
    8020de30:	b940b260 	ldr	w0, [x19, #176]
    8020de34:	32130042 	orr	w2, w2, #0x2000
    8020de38:	79002262 	strh	w2, [x19, #16]
    8020de3c:	32130000 	orr	w0, w0, #0x2000
    8020de40:	b900b260 	str	w0, [x19, #176]
    8020de44:	2a1403e1 	mov	w1, w20
    8020de48:	aa1503e0 	mov	x0, x21
    8020de4c:	aa1303e2 	mov	x2, x19
    8020de50:	97ffff88 	bl	8020dc70 <__fputwc>
    8020de54:	b940b261 	ldr	w1, [x19, #176]
    8020de58:	2a0003f4 	mov	w20, w0
    8020de5c:	37000061 	tbnz	w1, #0, 8020de68 <fputwc+0x78>
    8020de60:	79402260 	ldrh	w0, [x19, #16]
    8020de64:	364800c0 	tbz	w0, #9, 8020de7c <fputwc+0x8c>
    8020de68:	f94013f5 	ldr	x21, [sp, #32]
    8020de6c:	2a1403e0 	mov	w0, w20
    8020de70:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020de74:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020de78:	d65f03c0 	ret
    8020de7c:	f9405260 	ldr	x0, [x19, #160]
    8020de80:	97ffef60 	bl	80209c00 <__retarget_lock_release_recursive>
    8020de84:	f94013f5 	ldr	x21, [sp, #32]
    8020de88:	2a1403e0 	mov	w0, w20
    8020de8c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020de90:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020de94:	d65f03c0 	ret
    8020de98:	f9405260 	ldr	x0, [x19, #160]
    8020de9c:	97ffef49 	bl	80209bc0 <__retarget_lock_acquire_recursive>
    8020dea0:	79c02262 	ldrsh	w2, [x19, #16]
    8020dea4:	17ffffe2 	b	8020de2c <fputwc+0x3c>
    8020dea8:	aa1503e0 	mov	x0, x21
    8020deac:	97ffd5c9 	bl	802035d0 <__sinit>
    8020deb0:	17ffffdb 	b	8020de1c <fputwc+0x2c>
	...

000000008020dec0 <_wctomb_r>:
    8020dec0:	b0000024 	adrp	x4, 80212000 <__malloc_av_+0x760>
    8020dec4:	f9414084 	ldr	x4, [x4, #640]
    8020dec8:	aa0403f0 	mov	x16, x4
    8020decc:	d61f0200 	br	x16

000000008020ded0 <__ascii_wctomb>:
    8020ded0:	aa0003e3 	mov	x3, x0
    8020ded4:	b4000141 	cbz	x1, 8020defc <__ascii_wctomb+0x2c>
    8020ded8:	7103fc5f 	cmp	w2, #0xff
    8020dedc:	54000088 	b.hi	8020deec <__ascii_wctomb+0x1c>  // b.pmore
    8020dee0:	52800020 	mov	w0, #0x1                   	// #1
    8020dee4:	39000022 	strb	w2, [x1]
    8020dee8:	d65f03c0 	ret
    8020deec:	52801141 	mov	w1, #0x8a                  	// #138
    8020def0:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020def4:	b9000061 	str	w1, [x3]
    8020def8:	d65f03c0 	ret
    8020defc:	52800000 	mov	w0, #0x0                   	// #0
    8020df00:	d65f03c0 	ret
	...

000000008020df10 <__utf8_wctomb>:
    8020df10:	aa0003e3 	mov	x3, x0
    8020df14:	b40004e1 	cbz	x1, 8020dfb0 <__utf8_wctomb+0xa0>
    8020df18:	7101fc5f 	cmp	w2, #0x7f
    8020df1c:	54000349 	b.ls	8020df84 <__utf8_wctomb+0x74>  // b.plast
    8020df20:	51020040 	sub	w0, w2, #0x80
    8020df24:	711dfc1f 	cmp	w0, #0x77f
    8020df28:	54000349 	b.ls	8020df90 <__utf8_wctomb+0x80>  // b.plast
    8020df2c:	51200044 	sub	w4, w2, #0x800
    8020df30:	529effe0 	mov	w0, #0xf7ff                	// #63487
    8020df34:	6b00009f 	cmp	w4, w0
    8020df38:	54000409 	b.ls	8020dfb8 <__utf8_wctomb+0xa8>  // b.plast
    8020df3c:	51404044 	sub	w4, w2, #0x10, lsl #12
    8020df40:	12bffe00 	mov	w0, #0xfffff               	// #1048575
    8020df44:	6b00009f 	cmp	w4, w0
    8020df48:	540004e8 	b.hi	8020dfe4 <__utf8_wctomb+0xd4>  // b.pmore
    8020df4c:	53127c45 	lsr	w5, w2, #18
    8020df50:	d34c4444 	ubfx	x4, x2, #12, #6
    8020df54:	d3462c43 	ubfx	x3, x2, #6, #6
    8020df58:	12001442 	and	w2, w2, #0x3f
    8020df5c:	321c6ca5 	orr	w5, w5, #0xfffffff0
    8020df60:	32196084 	orr	w4, w4, #0xffffff80
    8020df64:	32196063 	orr	w3, w3, #0xffffff80
    8020df68:	32196042 	orr	w2, w2, #0xffffff80
    8020df6c:	52800080 	mov	w0, #0x4                   	// #4
    8020df70:	39000025 	strb	w5, [x1]
    8020df74:	39000424 	strb	w4, [x1, #1]
    8020df78:	39000823 	strb	w3, [x1, #2]
    8020df7c:	39000c22 	strb	w2, [x1, #3]
    8020df80:	d65f03c0 	ret
    8020df84:	52800020 	mov	w0, #0x1                   	// #1
    8020df88:	39000022 	strb	w2, [x1]
    8020df8c:	d65f03c0 	ret
    8020df90:	53067c43 	lsr	w3, w2, #6
    8020df94:	12001442 	and	w2, w2, #0x3f
    8020df98:	321a6463 	orr	w3, w3, #0xffffffc0
    8020df9c:	32196042 	orr	w2, w2, #0xffffff80
    8020dfa0:	52800040 	mov	w0, #0x2                   	// #2
    8020dfa4:	39000023 	strb	w3, [x1]
    8020dfa8:	39000422 	strb	w2, [x1, #1]
    8020dfac:	d65f03c0 	ret
    8020dfb0:	52800000 	mov	w0, #0x0                   	// #0
    8020dfb4:	d65f03c0 	ret
    8020dfb8:	530c7c44 	lsr	w4, w2, #12
    8020dfbc:	d3462c43 	ubfx	x3, x2, #6, #6
    8020dfc0:	12001442 	and	w2, w2, #0x3f
    8020dfc4:	321b6884 	orr	w4, w4, #0xffffffe0
    8020dfc8:	32196063 	orr	w3, w3, #0xffffff80
    8020dfcc:	32196042 	orr	w2, w2, #0xffffff80
    8020dfd0:	52800060 	mov	w0, #0x3                   	// #3
    8020dfd4:	39000024 	strb	w4, [x1]
    8020dfd8:	39000423 	strb	w3, [x1, #1]
    8020dfdc:	39000822 	strb	w2, [x1, #2]
    8020dfe0:	d65f03c0 	ret
    8020dfe4:	52801141 	mov	w1, #0x8a                  	// #138
    8020dfe8:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020dfec:	b9000061 	str	w1, [x3]
    8020dff0:	d65f03c0 	ret
	...

000000008020e000 <__sjis_wctomb>:
    8020e000:	aa0003e5 	mov	x5, x0
    8020e004:	12001c44 	and	w4, w2, #0xff
    8020e008:	d3483c43 	ubfx	x3, x2, #8, #8
    8020e00c:	b4000301 	cbz	x1, 8020e06c <__sjis_wctomb+0x6c>
    8020e010:	34000283 	cbz	w3, 8020e060 <__sjis_wctomb+0x60>
    8020e014:	1101fc60 	add	w0, w3, #0x7f
    8020e018:	11008063 	add	w3, w3, #0x20
    8020e01c:	12001c00 	and	w0, w0, #0xff
    8020e020:	12001c63 	and	w3, w3, #0xff
    8020e024:	7100781f 	cmp	w0, #0x1e
    8020e028:	7a4f8860 	ccmp	w3, #0xf, #0x0, hi	// hi = pmore
    8020e02c:	54000248 	b.hi	8020e074 <__sjis_wctomb+0x74>  // b.pmore
    8020e030:	51010080 	sub	w0, w4, #0x40
    8020e034:	51020084 	sub	w4, w4, #0x80
    8020e038:	12001c00 	and	w0, w0, #0xff
    8020e03c:	12001c84 	and	w4, w4, #0xff
    8020e040:	7100f81f 	cmp	w0, #0x3e
    8020e044:	52800f80 	mov	w0, #0x7c                  	// #124
    8020e048:	7a408080 	ccmp	w4, w0, #0x0, hi	// hi = pmore
    8020e04c:	54000148 	b.hi	8020e074 <__sjis_wctomb+0x74>  // b.pmore
    8020e050:	5ac00442 	rev16	w2, w2
    8020e054:	52800040 	mov	w0, #0x2                   	// #2
    8020e058:	79000022 	strh	w2, [x1]
    8020e05c:	d65f03c0 	ret
    8020e060:	52800020 	mov	w0, #0x1                   	// #1
    8020e064:	39000024 	strb	w4, [x1]
    8020e068:	d65f03c0 	ret
    8020e06c:	52800000 	mov	w0, #0x0                   	// #0
    8020e070:	d65f03c0 	ret
    8020e074:	52801141 	mov	w1, #0x8a                  	// #138
    8020e078:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020e07c:	b90000a1 	str	w1, [x5]
    8020e080:	d65f03c0 	ret
	...

000000008020e090 <__eucjp_wctomb>:
    8020e090:	aa0003e4 	mov	x4, x0
    8020e094:	12001c43 	and	w3, w2, #0xff
    8020e098:	d3483c45 	ubfx	x5, x2, #8, #8
    8020e09c:	b40003a1 	cbz	x1, 8020e110 <__eucjp_wctomb+0x80>
    8020e0a0:	34000325 	cbz	w5, 8020e104 <__eucjp_wctomb+0x74>
    8020e0a4:	11017ca0 	add	w0, w5, #0x5f
    8020e0a8:	1101c8a6 	add	w6, w5, #0x72
    8020e0ac:	12001c00 	and	w0, w0, #0xff
    8020e0b0:	12001cc6 	and	w6, w6, #0xff
    8020e0b4:	7101741f 	cmp	w0, #0x5d
    8020e0b8:	7a4188c0 	ccmp	w6, #0x1, #0x0, hi	// hi = pmore
    8020e0bc:	54000368 	b.hi	8020e128 <__eucjp_wctomb+0x98>  // b.pmore
    8020e0c0:	11017c66 	add	w6, w3, #0x5f
    8020e0c4:	12001cc6 	and	w6, w6, #0xff
    8020e0c8:	710174df 	cmp	w6, #0x5d
    8020e0cc:	54000269 	b.ls	8020e118 <__eucjp_wctomb+0x88>  // b.plast
    8020e0d0:	7101741f 	cmp	w0, #0x5d
    8020e0d4:	540002a8 	b.hi	8020e128 <__eucjp_wctomb+0x98>  // b.pmore
    8020e0d8:	32190063 	orr	w3, w3, #0x80
    8020e0dc:	11017c60 	add	w0, w3, #0x5f
    8020e0e0:	12001c00 	and	w0, w0, #0xff
    8020e0e4:	7101741f 	cmp	w0, #0x5d
    8020e0e8:	54000208 	b.hi	8020e128 <__eucjp_wctomb+0x98>  // b.pmore
    8020e0ec:	12800e02 	mov	w2, #0xffffff8f            	// #-113
    8020e0f0:	52800060 	mov	w0, #0x3                   	// #3
    8020e0f4:	39000022 	strb	w2, [x1]
    8020e0f8:	39000425 	strb	w5, [x1, #1]
    8020e0fc:	39000823 	strb	w3, [x1, #2]
    8020e100:	d65f03c0 	ret
    8020e104:	52800020 	mov	w0, #0x1                   	// #1
    8020e108:	39000023 	strb	w3, [x1]
    8020e10c:	d65f03c0 	ret
    8020e110:	52800000 	mov	w0, #0x0                   	// #0
    8020e114:	d65f03c0 	ret
    8020e118:	5ac00442 	rev16	w2, w2
    8020e11c:	52800040 	mov	w0, #0x2                   	// #2
    8020e120:	79000022 	strh	w2, [x1]
    8020e124:	d65f03c0 	ret
    8020e128:	52801141 	mov	w1, #0x8a                  	// #138
    8020e12c:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020e130:	b9000081 	str	w1, [x4]
    8020e134:	d65f03c0 	ret
	...

000000008020e140 <__jis_wctomb>:
    8020e140:	aa0003e6 	mov	x6, x0
    8020e144:	12001c45 	and	w5, w2, #0xff
    8020e148:	d3483c44 	ubfx	x4, x2, #8, #8
    8020e14c:	b40004c1 	cbz	x1, 8020e1e4 <__jis_wctomb+0xa4>
    8020e150:	34000304 	cbz	w4, 8020e1b0 <__jis_wctomb+0x70>
    8020e154:	51008484 	sub	w4, w4, #0x21
    8020e158:	12001c84 	and	w4, w4, #0xff
    8020e15c:	7101749f 	cmp	w4, #0x5d
    8020e160:	54000468 	b.hi	8020e1ec <__jis_wctomb+0xac>  // b.pmore
    8020e164:	510084a5 	sub	w5, w5, #0x21
    8020e168:	12001ca5 	and	w5, w5, #0xff
    8020e16c:	710174bf 	cmp	w5, #0x5d
    8020e170:	540003e8 	b.hi	8020e1ec <__jis_wctomb+0xac>  // b.pmore
    8020e174:	b9400064 	ldr	w4, [x3]
    8020e178:	52800040 	mov	w0, #0x2                   	// #2
    8020e17c:	35000144 	cbnz	w4, 8020e1a4 <__jis_wctomb+0x64>
    8020e180:	aa0103e4 	mov	x4, x1
    8020e184:	52800020 	mov	w0, #0x1                   	// #1
    8020e188:	b9000060 	str	w0, [x3]
    8020e18c:	52848365 	mov	w5, #0x241b                	// #9243
    8020e190:	52800843 	mov	w3, #0x42                  	// #66
    8020e194:	528000a0 	mov	w0, #0x5                   	// #5
    8020e198:	78003485 	strh	w5, [x4], #3
    8020e19c:	39000823 	strb	w3, [x1, #2]
    8020e1a0:	aa0403e1 	mov	x1, x4
    8020e1a4:	5ac00442 	rev16	w2, w2
    8020e1a8:	79000022 	strh	w2, [x1]
    8020e1ac:	d65f03c0 	ret
    8020e1b0:	b9400062 	ldr	w2, [x3]
    8020e1b4:	52800020 	mov	w0, #0x1                   	// #1
    8020e1b8:	34000122 	cbz	w2, 8020e1dc <__jis_wctomb+0x9c>
    8020e1bc:	aa0103e2 	mov	x2, x1
    8020e1c0:	b900007f 	str	wzr, [x3]
    8020e1c4:	52850364 	mov	w4, #0x281b                	// #10267
    8020e1c8:	52800843 	mov	w3, #0x42                  	// #66
    8020e1cc:	52800080 	mov	w0, #0x4                   	// #4
    8020e1d0:	78003444 	strh	w4, [x2], #3
    8020e1d4:	39000823 	strb	w3, [x1, #2]
    8020e1d8:	aa0203e1 	mov	x1, x2
    8020e1dc:	39000025 	strb	w5, [x1]
    8020e1e0:	d65f03c0 	ret
    8020e1e4:	52800020 	mov	w0, #0x1                   	// #1
    8020e1e8:	d65f03c0 	ret
    8020e1ec:	52801141 	mov	w1, #0x8a                  	// #138
    8020e1f0:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020e1f4:	b90000c1 	str	w1, [x6]
    8020e1f8:	d65f03c0 	ret
    8020e1fc:	00000000 	udf	#0

000000008020e200 <_sbrk_r>:
    8020e200:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020e204:	910003fd 	mov	x29, sp
    8020e208:	a90153f3 	stp	x19, x20, [sp, #16]
    8020e20c:	f0000394 	adrp	x20, 80281000 <__sf+0x38>
    8020e210:	aa0003f3 	mov	x19, x0
    8020e214:	b9044a9f 	str	wzr, [x20, #1096]
    8020e218:	aa0103e0 	mov	x0, x1
    8020e21c:	97ffc9e2 	bl	802009a4 <_sbrk>
    8020e220:	b100041f 	cmn	x0, #0x1
    8020e224:	54000080 	b.eq	8020e234 <_sbrk_r+0x34>  // b.none
    8020e228:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020e22c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020e230:	d65f03c0 	ret
    8020e234:	b9444a81 	ldr	w1, [x20, #1096]
    8020e238:	34ffff81 	cbz	w1, 8020e228 <_sbrk_r+0x28>
    8020e23c:	b9000261 	str	w1, [x19]
    8020e240:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020e244:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020e248:	d65f03c0 	ret
	...

000000008020e280 <strncmp>:
    8020e280:	d503245f 	bti	c
    8020e284:	b4000d42 	cbz	x2, 8020e42c <strncmp+0x1ac>
    8020e288:	ca010008 	eor	x8, x0, x1
    8020e28c:	b200c3eb 	mov	x11, #0x101010101010101     	// #72340172838076673
    8020e290:	f240091f 	tst	x8, #0x7
    8020e294:	9240080d 	and	x13, x0, #0x7
    8020e298:	540004c1 	b.ne	8020e330 <strncmp+0xb0>  // b.any
    8020e29c:	b500030d 	cbnz	x13, 8020e2fc <strncmp+0x7c>
    8020e2a0:	f8408403 	ldr	x3, [x0], #8
    8020e2a4:	f8408424 	ldr	x4, [x1], #8
    8020e2a8:	f1002042 	subs	x2, x2, #0x8
    8020e2ac:	cb0b0068 	sub	x8, x3, x11
    8020e2b0:	b200d869 	orr	x9, x3, #0x7f7f7f7f7f7f7f7f
    8020e2b4:	ca040066 	eor	x6, x3, x4
    8020e2b8:	da9f80ce 	csinv	x14, x6, xzr, hi	// hi = pmore
    8020e2bc:	ea290105 	bics	x5, x8, x9
    8020e2c0:	fa4009c0 	ccmp	x14, #0x0, #0x0, eq	// eq = none
    8020e2c4:	54fffee0 	b.eq	8020e2a0 <strncmp+0x20>  // b.none
    8020e2c8:	aa0500c7 	orr	x7, x6, x5
    8020e2cc:	91002042 	add	x2, x2, #0x8
    8020e2d0:	dac00ce7 	rev	x7, x7
    8020e2d4:	dac00c63 	rev	x3, x3
    8020e2d8:	dac010ec 	clz	x12, x7
    8020e2dc:	dac00c84 	rev	x4, x4
    8020e2e0:	9acc2063 	lsl	x3, x3, x12
    8020e2e4:	eb4c0c5f 	cmp	x2, x12, lsr #3
    8020e2e8:	9acc2084 	lsl	x4, x4, x12
    8020e2ec:	d378fc63 	lsr	x3, x3, #56
    8020e2f0:	cb44e060 	sub	x0, x3, x4, lsr #56
    8020e2f4:	9a9f8000 	csel	x0, x0, xzr, hi	// hi = pmore
    8020e2f8:	d65f03c0 	ret
    8020e2fc:	927df000 	and	x0, x0, #0xfffffffffffffff8
    8020e300:	927df021 	and	x1, x1, #0xfffffffffffffff8
    8020e304:	f8408403 	ldr	x3, [x0], #8
    8020e308:	cb0d0fea 	neg	x10, x13, lsl #3
    8020e30c:	f8408424 	ldr	x4, [x1], #8
    8020e310:	92800009 	mov	x9, #0xffffffffffffffff    	// #-1
    8020e314:	9aca2529 	lsr	x9, x9, x10
    8020e318:	ab0d0042 	adds	x2, x2, x13
    8020e31c:	da9f3042 	csinv	x2, x2, xzr, cc	// cc = lo, ul, last
    8020e320:	aa090063 	orr	x3, x3, x9
    8020e324:	aa090084 	orr	x4, x4, x9
    8020e328:	17ffffe0 	b	8020e2a8 <strncmp+0x28>
    8020e32c:	d503201f 	nop
    8020e330:	f100405f 	cmp	x2, #0x10
    8020e334:	54000122 	b.cs	8020e358 <strncmp+0xd8>  // b.hs, b.nlast
    8020e338:	38401403 	ldrb	w3, [x0], #1
    8020e33c:	38401424 	ldrb	w4, [x1], #1
    8020e340:	f1000442 	subs	x2, x2, #0x1
    8020e344:	7a418860 	ccmp	w3, #0x1, #0x0, hi	// hi = pmore
    8020e348:	7a442060 	ccmp	w3, w4, #0x0, cs	// cs = hs, nlast
    8020e34c:	54ffff60 	b.eq	8020e338 <strncmp+0xb8>  // b.none
    8020e350:	cb040060 	sub	x0, x3, x4
    8020e354:	d65f03c0 	ret
    8020e358:	b400016d 	cbz	x13, 8020e384 <strncmp+0x104>
    8020e35c:	cb0d03ed 	neg	x13, x13
    8020e360:	924009ad 	and	x13, x13, #0x7
    8020e364:	cb0d0042 	sub	x2, x2, x13
    8020e368:	38401403 	ldrb	w3, [x0], #1
    8020e36c:	38401424 	ldrb	w4, [x1], #1
    8020e370:	7100047f 	cmp	w3, #0x1
    8020e374:	7a442060 	ccmp	w3, w4, #0x0, cs	// cs = hs, nlast
    8020e378:	54fffec1 	b.ne	8020e350 <strncmp+0xd0>  // b.any
    8020e37c:	f10005ad 	subs	x13, x13, #0x1
    8020e380:	54ffff48 	b.hi	8020e368 <strncmp+0xe8>  // b.pmore
    8020e384:	d37df02c 	lsl	x12, x1, #3
    8020e388:	927cec21 	and	x1, x1, #0xfffffffffffffff0
    8020e38c:	9280000d 	mov	x13, #0xffffffffffffffff    	// #-1
    8020e390:	cb0c03ef 	neg	x15, x12
    8020e394:	f8408403 	ldr	x3, [x0], #8
    8020e398:	a8c12428 	ldp	x8, x9, [x1], #16
    8020e39c:	9acf21ad 	lsl	x13, x13, x15
    8020e3a0:	924015ef 	and	x15, x15, #0x3f
    8020e3a4:	373001ac 	tbnz	w12, #6, 8020e3d8 <strncmp+0x158>
    8020e3a8:	9acc2504 	lsr	x4, x8, x12
    8020e3ac:	9acf2128 	lsl	x8, x9, x15
    8020e3b0:	f1002042 	subs	x2, x2, #0x8
    8020e3b4:	aa080084 	orr	x4, x4, x8
    8020e3b8:	cb0b0065 	sub	x5, x3, x11
    8020e3bc:	ca040066 	eor	x6, x3, x4
    8020e3c0:	b200d86a 	orr	x10, x3, #0x7f7f7f7f7f7f7f7f
    8020e3c4:	da9f80ce 	csinv	x14, x6, xzr, hi	// hi = pmore
    8020e3c8:	8a2a00a5 	bic	x5, x5, x10
    8020e3cc:	aa0501ca 	orr	x10, x14, x5
    8020e3d0:	b5fff7ca 	cbnz	x10, 8020e2c8 <strncmp+0x48>
    8020e3d4:	f8408403 	ldr	x3, [x0], #8
    8020e3d8:	9acc2524 	lsr	x4, x9, x12
    8020e3dc:	cb0b0065 	sub	x5, x3, x11
    8020e3e0:	b200d86a 	orr	x10, x3, #0x7f7f7f7f7f7f7f7f
    8020e3e4:	ca030086 	eor	x6, x4, x3
    8020e3e8:	8a2a00a5 	bic	x5, x5, x10
    8020e3ec:	eb4f0c5f 	cmp	x2, x15, lsr #3
    8020e3f0:	aa0500c7 	orr	x7, x6, x5
    8020e3f4:	8a2d00e7 	bic	x7, x7, x13
    8020e3f8:	da9f80ea 	csinv	x10, x7, xzr, hi	// hi = pmore
    8020e3fc:	b5fff6aa 	cbnz	x10, 8020e2d0 <strncmp+0x50>
    8020e400:	a8c12428 	ldp	x8, x9, [x1], #16
    8020e404:	f100205f 	cmp	x2, #0x8
    8020e408:	9acf2104 	lsl	x4, x8, x15
    8020e40c:	ca030086 	eor	x6, x4, x3
    8020e410:	aa0500c7 	orr	x7, x6, x5
    8020e414:	8a0d00e7 	and	x7, x7, x13
    8020e418:	da9f80ea 	csinv	x10, x7, xzr, hi	// hi = pmore
    8020e41c:	b5fff5aa 	cbnz	x10, 8020e2d0 <strncmp+0x50>
    8020e420:	f8408403 	ldr	x3, [x0], #8
    8020e424:	d1002042 	sub	x2, x2, #0x8
    8020e428:	17ffffe0 	b	8020e3a8 <strncmp+0x128>
    8020e42c:	d2800000 	mov	x0, #0x0                   	// #0
    8020e430:	d65f03c0 	ret
	...

000000008020e440 <__swbuf_r>:
    8020e440:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020e444:	910003fd 	mov	x29, sp
    8020e448:	a90153f3 	stp	x19, x20, [sp, #16]
    8020e44c:	2a0103f4 	mov	w20, w1
    8020e450:	aa0203f3 	mov	x19, x2
    8020e454:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020e458:	aa0003f5 	mov	x21, x0
    8020e45c:	b4000060 	cbz	x0, 8020e468 <__swbuf_r+0x28>
    8020e460:	f9402401 	ldr	x1, [x0, #72]
    8020e464:	b4000861 	cbz	x1, 8020e570 <__swbuf_r+0x130>
    8020e468:	79c02260 	ldrsh	w0, [x19, #16]
    8020e46c:	b9402a61 	ldr	w1, [x19, #40]
    8020e470:	b9000e61 	str	w1, [x19, #12]
    8020e474:	361803e0 	tbz	w0, #3, 8020e4f0 <__swbuf_r+0xb0>
    8020e478:	f9400e61 	ldr	x1, [x19, #24]
    8020e47c:	b40003a1 	cbz	x1, 8020e4f0 <__swbuf_r+0xb0>
    8020e480:	12001e96 	and	w22, w20, #0xff
    8020e484:	12001e94 	and	w20, w20, #0xff
    8020e488:	36680460 	tbz	w0, #13, 8020e514 <__swbuf_r+0xd4>
    8020e48c:	f9400260 	ldr	x0, [x19]
    8020e490:	b9402262 	ldr	w2, [x19, #32]
    8020e494:	cb010001 	sub	x1, x0, x1
    8020e498:	6b01005f 	cmp	w2, w1
    8020e49c:	5400050d 	b.le	8020e53c <__swbuf_r+0xfc>
    8020e4a0:	11000421 	add	w1, w1, #0x1
    8020e4a4:	b9400e62 	ldr	w2, [x19, #12]
    8020e4a8:	91000403 	add	x3, x0, #0x1
    8020e4ac:	f9000263 	str	x3, [x19]
    8020e4b0:	51000442 	sub	w2, w2, #0x1
    8020e4b4:	b9000e62 	str	w2, [x19, #12]
    8020e4b8:	39000016 	strb	w22, [x0]
    8020e4bc:	b9402260 	ldr	w0, [x19, #32]
    8020e4c0:	6b01001f 	cmp	w0, w1
    8020e4c4:	540004a0 	b.eq	8020e558 <__swbuf_r+0x118>  // b.none
    8020e4c8:	71002a9f 	cmp	w20, #0xa
    8020e4cc:	79402260 	ldrh	w0, [x19, #16]
    8020e4d0:	1a9f17e1 	cset	w1, eq	// eq = none
    8020e4d4:	6a00003f 	tst	w1, w0
    8020e4d8:	54000401 	b.ne	8020e558 <__swbuf_r+0x118>  // b.any
    8020e4dc:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020e4e0:	2a1403e0 	mov	w0, w20
    8020e4e4:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020e4e8:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020e4ec:	d65f03c0 	ret
    8020e4f0:	aa1303e1 	mov	x1, x19
    8020e4f4:	aa1503e0 	mov	x0, x21
    8020e4f8:	97fff19a 	bl	8020ab60 <__swsetup_r>
    8020e4fc:	35000360 	cbnz	w0, 8020e568 <__swbuf_r+0x128>
    8020e500:	79c02260 	ldrsh	w0, [x19, #16]
    8020e504:	12001e96 	and	w22, w20, #0xff
    8020e508:	f9400e61 	ldr	x1, [x19, #24]
    8020e50c:	12001e94 	and	w20, w20, #0xff
    8020e510:	376ffbe0 	tbnz	w0, #13, 8020e48c <__swbuf_r+0x4c>
    8020e514:	b940b262 	ldr	w2, [x19, #176]
    8020e518:	32130000 	orr	w0, w0, #0x2000
    8020e51c:	79002260 	strh	w0, [x19, #16]
    8020e520:	12127840 	and	w0, w2, #0xffffdfff
    8020e524:	b900b260 	str	w0, [x19, #176]
    8020e528:	f9400260 	ldr	x0, [x19]
    8020e52c:	b9402262 	ldr	w2, [x19, #32]
    8020e530:	cb010001 	sub	x1, x0, x1
    8020e534:	6b01005f 	cmp	w2, w1
    8020e538:	54fffb4c 	b.gt	8020e4a0 <__swbuf_r+0x60>
    8020e53c:	aa1303e1 	mov	x1, x19
    8020e540:	aa1503e0 	mov	x0, x21
    8020e544:	97fff88b 	bl	8020c770 <_fflush_r>
    8020e548:	35000100 	cbnz	w0, 8020e568 <__swbuf_r+0x128>
    8020e54c:	f9400260 	ldr	x0, [x19]
    8020e550:	52800021 	mov	w1, #0x1                   	// #1
    8020e554:	17ffffd4 	b	8020e4a4 <__swbuf_r+0x64>
    8020e558:	aa1303e1 	mov	x1, x19
    8020e55c:	aa1503e0 	mov	x0, x21
    8020e560:	97fff884 	bl	8020c770 <_fflush_r>
    8020e564:	34fffbc0 	cbz	w0, 8020e4dc <__swbuf_r+0x9c>
    8020e568:	12800014 	mov	w20, #0xffffffff            	// #-1
    8020e56c:	17ffffdc 	b	8020e4dc <__swbuf_r+0x9c>
    8020e570:	97ffd418 	bl	802035d0 <__sinit>
    8020e574:	17ffffbd 	b	8020e468 <__swbuf_r+0x28>
	...

000000008020e580 <__swbuf>:
    8020e580:	f0000003 	adrp	x3, 80211000 <blanks.1+0x60>
    8020e584:	aa0103e2 	mov	x2, x1
    8020e588:	2a0003e1 	mov	w1, w0
    8020e58c:	f9438860 	ldr	x0, [x3, #1808]
    8020e590:	17ffffac 	b	8020e440 <__swbuf_r>
	...

000000008020e5a0 <_mbtowc_r>:
    8020e5a0:	90000025 	adrp	x5, 80212000 <__malloc_av_+0x760>
    8020e5a4:	f94144a5 	ldr	x5, [x5, #648]
    8020e5a8:	aa0503f0 	mov	x16, x5
    8020e5ac:	d61f0200 	br	x16

000000008020e5b0 <__ascii_mbtowc>:
    8020e5b0:	d10043ff 	sub	sp, sp, #0x10
    8020e5b4:	f100003f 	cmp	x1, #0x0
    8020e5b8:	910033e0 	add	x0, sp, #0xc
    8020e5bc:	9a810001 	csel	x1, x0, x1, eq	// eq = none
    8020e5c0:	b4000122 	cbz	x2, 8020e5e4 <__ascii_mbtowc+0x34>
    8020e5c4:	b4000163 	cbz	x3, 8020e5f0 <__ascii_mbtowc+0x40>
    8020e5c8:	39400040 	ldrb	w0, [x2]
    8020e5cc:	b9000020 	str	w0, [x1]
    8020e5d0:	39400040 	ldrb	w0, [x2]
    8020e5d4:	7100001f 	cmp	w0, #0x0
    8020e5d8:	1a9f07e0 	cset	w0, ne	// ne = any
    8020e5dc:	910043ff 	add	sp, sp, #0x10
    8020e5e0:	d65f03c0 	ret
    8020e5e4:	52800000 	mov	w0, #0x0                   	// #0
    8020e5e8:	910043ff 	add	sp, sp, #0x10
    8020e5ec:	d65f03c0 	ret
    8020e5f0:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020e5f4:	17fffffa 	b	8020e5dc <__ascii_mbtowc+0x2c>
	...

000000008020e600 <__utf8_mbtowc>:
    8020e600:	d10043ff 	sub	sp, sp, #0x10
    8020e604:	f100003f 	cmp	x1, #0x0
    8020e608:	910033e5 	add	x5, sp, #0xc
    8020e60c:	9a8100a1 	csel	x1, x5, x1, eq	// eq = none
    8020e610:	b40004c2 	cbz	x2, 8020e6a8 <__utf8_mbtowc+0xa8>
    8020e614:	b4001223 	cbz	x3, 8020e858 <__utf8_mbtowc+0x258>
    8020e618:	b9400087 	ldr	w7, [x4]
    8020e61c:	aa0003e9 	mov	x9, x0
    8020e620:	350003a7 	cbnz	w7, 8020e694 <__utf8_mbtowc+0x94>
    8020e624:	39400045 	ldrb	w5, [x2]
    8020e628:	52800026 	mov	w6, #0x1                   	// #1
    8020e62c:	340003a5 	cbz	w5, 8020e6a0 <__utf8_mbtowc+0xa0>
    8020e630:	7101fcbf 	cmp	w5, #0x7f
    8020e634:	5400082d 	b.le	8020e738 <__utf8_mbtowc+0x138>
    8020e638:	510300a8 	sub	w8, w5, #0xc0
    8020e63c:	71007d1f 	cmp	w8, #0x1f
    8020e640:	540003a8 	b.hi	8020e6b4 <__utf8_mbtowc+0xb4>  // b.pmore
    8020e644:	39001085 	strb	w5, [x4, #4]
    8020e648:	350000a7 	cbnz	w7, 8020e65c <__utf8_mbtowc+0x5c>
    8020e64c:	52800020 	mov	w0, #0x1                   	// #1
    8020e650:	b9000080 	str	w0, [x4]
    8020e654:	f100047f 	cmp	x3, #0x1
    8020e658:	54001000 	b.eq	8020e858 <__utf8_mbtowc+0x258>  // b.none
    8020e65c:	3866c842 	ldrb	w2, [x2, w6, sxtw]
    8020e660:	110004c0 	add	w0, w6, #0x1
    8020e664:	51020043 	sub	w3, w2, #0x80
    8020e668:	7100fc7f 	cmp	w3, #0x3f
    8020e66c:	54000fe8 	b.hi	8020e868 <__utf8_mbtowc+0x268>  // b.pmore
    8020e670:	710304bf 	cmp	w5, #0xc1
    8020e674:	54000fad 	b.le	8020e868 <__utf8_mbtowc+0x268>
    8020e678:	12001442 	and	w2, w2, #0x3f
    8020e67c:	531a10a5 	ubfiz	w5, w5, #6, #5
    8020e680:	b900009f 	str	wzr, [x4]
    8020e684:	2a0200a5 	orr	w5, w5, w2
    8020e688:	b9000025 	str	w5, [x1]
    8020e68c:	910043ff 	add	sp, sp, #0x10
    8020e690:	d65f03c0 	ret
    8020e694:	39401085 	ldrb	w5, [x4, #4]
    8020e698:	52800006 	mov	w6, #0x0                   	// #0
    8020e69c:	35fffca5 	cbnz	w5, 8020e630 <__utf8_mbtowc+0x30>
    8020e6a0:	b900003f 	str	wzr, [x1]
    8020e6a4:	b900009f 	str	wzr, [x4]
    8020e6a8:	52800000 	mov	w0, #0x0                   	// #0
    8020e6ac:	910043ff 	add	sp, sp, #0x10
    8020e6b0:	d65f03c0 	ret
    8020e6b4:	510380a0 	sub	w0, w5, #0xe0
    8020e6b8:	71003c1f 	cmp	w0, #0xf
    8020e6bc:	54000488 	b.hi	8020e74c <__utf8_mbtowc+0x14c>  // b.pmore
    8020e6c0:	39001085 	strb	w5, [x4, #4]
    8020e6c4:	34000a07 	cbz	w7, 8020e804 <__utf8_mbtowc+0x204>
    8020e6c8:	b100047f 	cmn	x3, #0x1
    8020e6cc:	9a830463 	cinc	x3, x3, ne	// ne = any
    8020e6d0:	710004ff 	cmp	w7, #0x1
    8020e6d4:	54000a00 	b.eq	8020e814 <__utf8_mbtowc+0x214>  // b.none
    8020e6d8:	39401488 	ldrb	w8, [x4, #5]
    8020e6dc:	71027d1f 	cmp	w8, #0x9f
    8020e6e0:	52801c00 	mov	w0, #0xe0                  	// #224
    8020e6e4:	7a40d0a0 	ccmp	w5, w0, #0x0, le
    8020e6e8:	54000c00 	b.eq	8020e868 <__utf8_mbtowc+0x268>  // b.none
    8020e6ec:	51020100 	sub	w0, w8, #0x80
    8020e6f0:	7100fc1f 	cmp	w0, #0x3f
    8020e6f4:	54000ba8 	b.hi	8020e868 <__utf8_mbtowc+0x268>  // b.pmore
    8020e6f8:	39001488 	strb	w8, [x4, #5]
    8020e6fc:	710004ff 	cmp	w7, #0x1
    8020e700:	54000a20 	b.eq	8020e844 <__utf8_mbtowc+0x244>  // b.none
    8020e704:	3866c843 	ldrb	w3, [x2, w6, sxtw]
    8020e708:	110004c0 	add	w0, w6, #0x1
    8020e70c:	51020062 	sub	w2, w3, #0x80
    8020e710:	7100fc5f 	cmp	w2, #0x3f
    8020e714:	54000aa8 	b.hi	8020e868 <__utf8_mbtowc+0x268>  // b.pmore
    8020e718:	53140ca2 	ubfiz	w2, w5, #12, #4
    8020e71c:	531a1508 	ubfiz	w8, w8, #6, #6
    8020e720:	2a080042 	orr	w2, w2, w8
    8020e724:	12001463 	and	w3, w3, #0x3f
    8020e728:	b900009f 	str	wzr, [x4]
    8020e72c:	2a030042 	orr	w2, w2, w3
    8020e730:	b9000022 	str	w2, [x1]
    8020e734:	17ffffde 	b	8020e6ac <__utf8_mbtowc+0xac>
    8020e738:	b900009f 	str	wzr, [x4]
    8020e73c:	52800020 	mov	w0, #0x1                   	// #1
    8020e740:	b9000025 	str	w5, [x1]
    8020e744:	910043ff 	add	sp, sp, #0x10
    8020e748:	d65f03c0 	ret
    8020e74c:	5103c0a0 	sub	w0, w5, #0xf0
    8020e750:	7100101f 	cmp	w0, #0x4
    8020e754:	540008a8 	b.hi	8020e868 <__utf8_mbtowc+0x268>  // b.pmore
    8020e758:	39001085 	strb	w5, [x4, #4]
    8020e75c:	34000647 	cbz	w7, 8020e824 <__utf8_mbtowc+0x224>
    8020e760:	b100047f 	cmn	x3, #0x1
    8020e764:	9a830463 	cinc	x3, x3, ne	// ne = any
    8020e768:	710004ff 	cmp	w7, #0x1
    8020e76c:	54000640 	b.eq	8020e834 <__utf8_mbtowc+0x234>  // b.none
    8020e770:	39401488 	ldrb	w8, [x4, #5]
    8020e774:	7103c0bf 	cmp	w5, #0xf0
    8020e778:	54000740 	b.eq	8020e860 <__utf8_mbtowc+0x260>  // b.none
    8020e77c:	71023d1f 	cmp	w8, #0x8f
    8020e780:	52801e80 	mov	w0, #0xf4                  	// #244
    8020e784:	7a40c0a0 	ccmp	w5, w0, #0x0, gt
    8020e788:	54000700 	b.eq	8020e868 <__utf8_mbtowc+0x268>  // b.none
    8020e78c:	51020100 	sub	w0, w8, #0x80
    8020e790:	7100fc1f 	cmp	w0, #0x3f
    8020e794:	540006a8 	b.hi	8020e868 <__utf8_mbtowc+0x268>  // b.pmore
    8020e798:	39001488 	strb	w8, [x4, #5]
    8020e79c:	710004ff 	cmp	w7, #0x1
    8020e7a0:	540006c0 	b.eq	8020e878 <__utf8_mbtowc+0x278>  // b.none
    8020e7a4:	b9400080 	ldr	w0, [x4]
    8020e7a8:	b100047f 	cmn	x3, #0x1
    8020e7ac:	9a830463 	cinc	x3, x3, ne	// ne = any
    8020e7b0:	7100081f 	cmp	w0, #0x2
    8020e7b4:	540006a0 	b.eq	8020e888 <__utf8_mbtowc+0x288>  // b.none
    8020e7b8:	39401887 	ldrb	w7, [x4, #6]
    8020e7bc:	510200e0 	sub	w0, w7, #0x80
    8020e7c0:	7100fc1f 	cmp	w0, #0x3f
    8020e7c4:	54000528 	b.hi	8020e868 <__utf8_mbtowc+0x268>  // b.pmore
    8020e7c8:	3866c843 	ldrb	w3, [x2, w6, sxtw]
    8020e7cc:	110004c0 	add	w0, w6, #0x1
    8020e7d0:	51020062 	sub	w2, w3, #0x80
    8020e7d4:	7100fc5f 	cmp	w2, #0x3f
    8020e7d8:	54000488 	b.hi	8020e868 <__utf8_mbtowc+0x268>  // b.pmore
    8020e7dc:	530e08a2 	ubfiz	w2, w5, #18, #3
    8020e7e0:	53141508 	ubfiz	w8, w8, #12, #6
    8020e7e4:	531a14e7 	ubfiz	w7, w7, #6, #6
    8020e7e8:	12001463 	and	w3, w3, #0x3f
    8020e7ec:	2a080042 	orr	w2, w2, w8
    8020e7f0:	2a0300e7 	orr	w7, w7, w3
    8020e7f4:	2a070042 	orr	w2, w2, w7
    8020e7f8:	b9000022 	str	w2, [x1]
    8020e7fc:	b900009f 	str	wzr, [x4]
    8020e800:	17ffffab 	b	8020e6ac <__utf8_mbtowc+0xac>
    8020e804:	52800020 	mov	w0, #0x1                   	// #1
    8020e808:	b9000080 	str	w0, [x4]
    8020e80c:	f100047f 	cmp	x3, #0x1
    8020e810:	54000240 	b.eq	8020e858 <__utf8_mbtowc+0x258>  // b.none
    8020e814:	3866c848 	ldrb	w8, [x2, w6, sxtw]
    8020e818:	52800027 	mov	w7, #0x1                   	// #1
    8020e81c:	0b0700c6 	add	w6, w6, w7
    8020e820:	17ffffaf 	b	8020e6dc <__utf8_mbtowc+0xdc>
    8020e824:	52800020 	mov	w0, #0x1                   	// #1
    8020e828:	b9000080 	str	w0, [x4]
    8020e82c:	f100047f 	cmp	x3, #0x1
    8020e830:	54000140 	b.eq	8020e858 <__utf8_mbtowc+0x258>  // b.none
    8020e834:	3866c848 	ldrb	w8, [x2, w6, sxtw]
    8020e838:	52800027 	mov	w7, #0x1                   	// #1
    8020e83c:	0b0700c6 	add	w6, w6, w7
    8020e840:	17ffffcd 	b	8020e774 <__utf8_mbtowc+0x174>
    8020e844:	52800040 	mov	w0, #0x2                   	// #2
    8020e848:	b9000080 	str	w0, [x4]
    8020e84c:	f100087f 	cmp	x3, #0x2
    8020e850:	54fff5a1 	b.ne	8020e704 <__utf8_mbtowc+0x104>  // b.any
    8020e854:	d503201f 	nop
    8020e858:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020e85c:	17ffff94 	b	8020e6ac <__utf8_mbtowc+0xac>
    8020e860:	71023d1f 	cmp	w8, #0x8f
    8020e864:	54fff94c 	b.gt	8020e78c <__utf8_mbtowc+0x18c>
    8020e868:	52801141 	mov	w1, #0x8a                  	// #138
    8020e86c:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020e870:	b9000121 	str	w1, [x9]
    8020e874:	17ffff8e 	b	8020e6ac <__utf8_mbtowc+0xac>
    8020e878:	52800040 	mov	w0, #0x2                   	// #2
    8020e87c:	b9000080 	str	w0, [x4]
    8020e880:	f100087f 	cmp	x3, #0x2
    8020e884:	54fffea0 	b.eq	8020e858 <__utf8_mbtowc+0x258>  // b.none
    8020e888:	3866c847 	ldrb	w7, [x2, w6, sxtw]
    8020e88c:	110004c6 	add	w6, w6, #0x1
    8020e890:	510200e0 	sub	w0, w7, #0x80
    8020e894:	7100fc1f 	cmp	w0, #0x3f
    8020e898:	54fffe88 	b.hi	8020e868 <__utf8_mbtowc+0x268>  // b.pmore
    8020e89c:	52800060 	mov	w0, #0x3                   	// #3
    8020e8a0:	b9000080 	str	w0, [x4]
    8020e8a4:	39001887 	strb	w7, [x4, #6]
    8020e8a8:	f1000c7f 	cmp	x3, #0x3
    8020e8ac:	54fff8e1 	b.ne	8020e7c8 <__utf8_mbtowc+0x1c8>  // b.any
    8020e8b0:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020e8b4:	17ffff7e 	b	8020e6ac <__utf8_mbtowc+0xac>
	...

000000008020e8c0 <__sjis_mbtowc>:
    8020e8c0:	d10043ff 	sub	sp, sp, #0x10
    8020e8c4:	f100003f 	cmp	x1, #0x0
    8020e8c8:	910033e5 	add	x5, sp, #0xc
    8020e8cc:	9a8100a1 	csel	x1, x5, x1, eq	// eq = none
    8020e8d0:	b40004c2 	cbz	x2, 8020e968 <__sjis_mbtowc+0xa8>
    8020e8d4:	b4000503 	cbz	x3, 8020e974 <__sjis_mbtowc+0xb4>
    8020e8d8:	aa0003e6 	mov	x6, x0
    8020e8dc:	b9400080 	ldr	w0, [x4]
    8020e8e0:	39400045 	ldrb	w5, [x2]
    8020e8e4:	35000320 	cbnz	w0, 8020e948 <__sjis_mbtowc+0x88>
    8020e8e8:	510204a7 	sub	w7, w5, #0x81
    8020e8ec:	510380a0 	sub	w0, w5, #0xe0
    8020e8f0:	710078ff 	cmp	w7, #0x1e
    8020e8f4:	7a4f8800 	ccmp	w0, #0xf, #0x0, hi	// hi = pmore
    8020e8f8:	540002c8 	b.hi	8020e950 <__sjis_mbtowc+0x90>  // b.pmore
    8020e8fc:	52800020 	mov	w0, #0x1                   	// #1
    8020e900:	b9000080 	str	w0, [x4]
    8020e904:	39001085 	strb	w5, [x4, #4]
    8020e908:	f100047f 	cmp	x3, #0x1
    8020e90c:	54000340 	b.eq	8020e974 <__sjis_mbtowc+0xb4>  // b.none
    8020e910:	39400445 	ldrb	w5, [x2, #1]
    8020e914:	52800040 	mov	w0, #0x2                   	// #2
    8020e918:	510100a3 	sub	w3, w5, #0x40
    8020e91c:	510200a2 	sub	w2, w5, #0x80
    8020e920:	7100f87f 	cmp	w3, #0x3e
    8020e924:	52800f83 	mov	w3, #0x7c                  	// #124
    8020e928:	7a438040 	ccmp	w2, w3, #0x0, hi	// hi = pmore
    8020e92c:	54000288 	b.hi	8020e97c <__sjis_mbtowc+0xbc>  // b.pmore
    8020e930:	39401082 	ldrb	w2, [x4, #4]
    8020e934:	0b0220a2 	add	w2, w5, w2, lsl #8
    8020e938:	b9000022 	str	w2, [x1]
    8020e93c:	b900009f 	str	wzr, [x4]
    8020e940:	910043ff 	add	sp, sp, #0x10
    8020e944:	d65f03c0 	ret
    8020e948:	7100041f 	cmp	w0, #0x1
    8020e94c:	54fffe60 	b.eq	8020e918 <__sjis_mbtowc+0x58>  // b.none
    8020e950:	b9000025 	str	w5, [x1]
    8020e954:	39400040 	ldrb	w0, [x2]
    8020e958:	7100001f 	cmp	w0, #0x0
    8020e95c:	1a9f07e0 	cset	w0, ne	// ne = any
    8020e960:	910043ff 	add	sp, sp, #0x10
    8020e964:	d65f03c0 	ret
    8020e968:	52800000 	mov	w0, #0x0                   	// #0
    8020e96c:	910043ff 	add	sp, sp, #0x10
    8020e970:	d65f03c0 	ret
    8020e974:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020e978:	17fffffa 	b	8020e960 <__sjis_mbtowc+0xa0>
    8020e97c:	52801141 	mov	w1, #0x8a                  	// #138
    8020e980:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020e984:	b90000c1 	str	w1, [x6]
    8020e988:	17fffff6 	b	8020e960 <__sjis_mbtowc+0xa0>
    8020e98c:	00000000 	udf	#0

000000008020e990 <__eucjp_mbtowc>:
    8020e990:	d10043ff 	sub	sp, sp, #0x10
    8020e994:	f100003f 	cmp	x1, #0x0
    8020e998:	910033e6 	add	x6, sp, #0xc
    8020e99c:	9a8100c1 	csel	x1, x6, x1, eq	// eq = none
    8020e9a0:	b4000782 	cbz	x2, 8020ea90 <__eucjp_mbtowc+0x100>
    8020e9a4:	b40007c3 	cbz	x3, 8020ea9c <__eucjp_mbtowc+0x10c>
    8020e9a8:	aa0003e5 	mov	x5, x0
    8020e9ac:	b9400080 	ldr	w0, [x4]
    8020e9b0:	39400046 	ldrb	w6, [x2]
    8020e9b4:	35000380 	cbnz	w0, 8020ea24 <__eucjp_mbtowc+0x94>
    8020e9b8:	510284c7 	sub	w7, w6, #0xa1
    8020e9bc:	510238c0 	sub	w0, w6, #0x8e
    8020e9c0:	710174ff 	cmp	w7, #0x5d
    8020e9c4:	7a418800 	ccmp	w0, #0x1, #0x0, hi	// hi = pmore
    8020e9c8:	54000388 	b.hi	8020ea38 <__eucjp_mbtowc+0xa8>  // b.pmore
    8020e9cc:	52800020 	mov	w0, #0x1                   	// #1
    8020e9d0:	b9000080 	str	w0, [x4]
    8020e9d4:	39001086 	strb	w6, [x4, #4]
    8020e9d8:	f100047f 	cmp	x3, #0x1
    8020e9dc:	54000600 	b.eq	8020ea9c <__eucjp_mbtowc+0x10c>  // b.none
    8020e9e0:	39400447 	ldrb	w7, [x2, #1]
    8020e9e4:	52800040 	mov	w0, #0x2                   	// #2
    8020e9e8:	510284e6 	sub	w6, w7, #0xa1
    8020e9ec:	710174df 	cmp	w6, #0x5d
    8020e9f0:	540005a8 	b.hi	8020eaa4 <__eucjp_mbtowc+0x114>  // b.pmore
    8020e9f4:	39401086 	ldrb	w6, [x4, #4]
    8020e9f8:	71023cdf 	cmp	w6, #0x8f
    8020e9fc:	54000401 	b.ne	8020ea7c <__eucjp_mbtowc+0xec>  // b.any
    8020ea00:	52800048 	mov	w8, #0x2                   	// #2
    8020ea04:	93407c06 	sxtw	x6, w0
    8020ea08:	b9000088 	str	w8, [x4]
    8020ea0c:	39001487 	strb	w7, [x4, #5]
    8020ea10:	eb0300df 	cmp	x6, x3
    8020ea14:	54000442 	b.cs	8020ea9c <__eucjp_mbtowc+0x10c>  // b.hs, b.nlast
    8020ea18:	38666847 	ldrb	w7, [x2, x6]
    8020ea1c:	11000400 	add	w0, w0, #0x1
    8020ea20:	1400000d 	b	8020ea54 <__eucjp_mbtowc+0xc4>
    8020ea24:	2a0603e7 	mov	w7, w6
    8020ea28:	7100041f 	cmp	w0, #0x1
    8020ea2c:	54fffde0 	b.eq	8020e9e8 <__eucjp_mbtowc+0x58>  // b.none
    8020ea30:	7100081f 	cmp	w0, #0x2
    8020ea34:	540000e0 	b.eq	8020ea50 <__eucjp_mbtowc+0xc0>  // b.none
    8020ea38:	b9000026 	str	w6, [x1]
    8020ea3c:	39400040 	ldrb	w0, [x2]
    8020ea40:	7100001f 	cmp	w0, #0x0
    8020ea44:	1a9f07e0 	cset	w0, ne	// ne = any
    8020ea48:	910043ff 	add	sp, sp, #0x10
    8020ea4c:	d65f03c0 	ret
    8020ea50:	52800020 	mov	w0, #0x1                   	// #1
    8020ea54:	510284e2 	sub	w2, w7, #0xa1
    8020ea58:	7101745f 	cmp	w2, #0x5d
    8020ea5c:	54000248 	b.hi	8020eaa4 <__eucjp_mbtowc+0x114>  // b.pmore
    8020ea60:	39401482 	ldrb	w2, [x4, #5]
    8020ea64:	120018e7 	and	w7, w7, #0x7f
    8020ea68:	0b0220e2 	add	w2, w7, w2, lsl #8
    8020ea6c:	b9000022 	str	w2, [x1]
    8020ea70:	b900009f 	str	wzr, [x4]
    8020ea74:	910043ff 	add	sp, sp, #0x10
    8020ea78:	d65f03c0 	ret
    8020ea7c:	0b0620e6 	add	w6, w7, w6, lsl #8
    8020ea80:	b9000026 	str	w6, [x1]
    8020ea84:	b900009f 	str	wzr, [x4]
    8020ea88:	910043ff 	add	sp, sp, #0x10
    8020ea8c:	d65f03c0 	ret
    8020ea90:	52800000 	mov	w0, #0x0                   	// #0
    8020ea94:	910043ff 	add	sp, sp, #0x10
    8020ea98:	d65f03c0 	ret
    8020ea9c:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020eaa0:	17ffffea 	b	8020ea48 <__eucjp_mbtowc+0xb8>
    8020eaa4:	52801141 	mov	w1, #0x8a                  	// #138
    8020eaa8:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020eaac:	b90000a1 	str	w1, [x5]
    8020eab0:	17ffffe6 	b	8020ea48 <__eucjp_mbtowc+0xb8>
	...

000000008020eac0 <__jis_mbtowc>:
    8020eac0:	d10043ff 	sub	sp, sp, #0x10
    8020eac4:	f100003f 	cmp	x1, #0x0
    8020eac8:	910033e5 	add	x5, sp, #0xc
    8020eacc:	9a8100a1 	csel	x1, x5, x1, eq	// eq = none
    8020ead0:	b4000cc2 	cbz	x2, 8020ec68 <__jis_mbtowc+0x1a8>
    8020ead4:	b40008c3 	cbz	x3, 8020ebec <__jis_mbtowc+0x12c>
    8020ead8:	39400085 	ldrb	w5, [x4]
    8020eadc:	f000000c 	adrp	x12, 80211000 <blanks.1+0x60>
    8020eae0:	f000000b 	adrp	x11, 80211000 <blanks.1+0x60>
    8020eae4:	aa0003ed 	mov	x13, x0
    8020eae8:	9110c18c 	add	x12, x12, #0x430
    8020eaec:	9112016b 	add	x11, x11, #0x480
    8020eaf0:	aa0203ef 	mov	x15, x2
    8020eaf4:	52800009 	mov	w9, #0x0                   	// #0
    8020eaf8:	d2800008 	mov	x8, #0x0                   	// #0
    8020eafc:	38686847 	ldrb	w7, [x2, x8]
    8020eb00:	8b08004e 	add	x14, x2, x8
    8020eb04:	7100a0ff 	cmp	w7, #0x28
    8020eb08:	54000b80 	b.eq	8020ec78 <__jis_mbtowc+0x1b8>  // b.none
    8020eb0c:	54000388 	b.hi	8020eb7c <__jis_mbtowc+0xbc>  // b.pmore
    8020eb10:	52800006 	mov	w6, #0x0                   	// #0
    8020eb14:	71006cff 	cmp	w7, #0x1b
    8020eb18:	540000c0 	b.eq	8020eb30 <__jis_mbtowc+0x70>  // b.none
    8020eb1c:	52800026 	mov	w6, #0x1                   	// #1
    8020eb20:	710090ff 	cmp	w7, #0x24
    8020eb24:	54000060 	b.eq	8020eb30 <__jis_mbtowc+0x70>  // b.none
    8020eb28:	528000c6 	mov	w6, #0x6                   	// #6
    8020eb2c:	350003a7 	cbnz	w7, 8020eba0 <__jis_mbtowc+0xe0>
    8020eb30:	d37d1ca0 	ubfiz	x0, x5, #3, #8
    8020eb34:	8b250005 	add	x5, x0, w5, uxtb
    8020eb38:	8b050180 	add	x0, x12, x5
    8020eb3c:	8b050165 	add	x5, x11, x5
    8020eb40:	3866c80a 	ldrb	w10, [x0, w6, sxtw]
    8020eb44:	3866c8a5 	ldrb	w5, [x5, w6, sxtw]
    8020eb48:	71000d5f 	cmp	w10, #0x3
    8020eb4c:	54000420 	b.eq	8020ebd0 <__jis_mbtowc+0x110>  // b.none
    8020eb50:	54000528 	b.hi	8020ebf4 <__jis_mbtowc+0x134>  // b.pmore
    8020eb54:	7100055f 	cmp	w10, #0x1
    8020eb58:	54000600 	b.eq	8020ec18 <__jis_mbtowc+0x158>  // b.none
    8020eb5c:	7100095f 	cmp	w10, #0x2
    8020eb60:	54000720 	b.eq	8020ec44 <__jis_mbtowc+0x184>  // b.none
    8020eb64:	b900009f 	str	wzr, [x4]
    8020eb68:	11000520 	add	w0, w9, #0x1
    8020eb6c:	394001e2 	ldrb	w2, [x15]
    8020eb70:	b9000022 	str	w2, [x1]
    8020eb74:	910043ff 	add	sp, sp, #0x10
    8020eb78:	d65f03c0 	ret
    8020eb7c:	52800086 	mov	w6, #0x4                   	// #4
    8020eb80:	710108ff 	cmp	w7, #0x42
    8020eb84:	54fffd60 	b.eq	8020eb30 <__jis_mbtowc+0x70>  // b.none
    8020eb88:	528000a6 	mov	w6, #0x5                   	// #5
    8020eb8c:	710128ff 	cmp	w7, #0x4a
    8020eb90:	54fffd00 	b.eq	8020eb30 <__jis_mbtowc+0x70>  // b.none
    8020eb94:	52800066 	mov	w6, #0x3                   	// #3
    8020eb98:	710100ff 	cmp	w7, #0x40
    8020eb9c:	54fffca0 	b.eq	8020eb30 <__jis_mbtowc+0x70>  // b.none
    8020eba0:	510084e0 	sub	w0, w7, #0x21
    8020eba4:	7101741f 	cmp	w0, #0x5d
    8020eba8:	d37d1ca0 	ubfiz	x0, x5, #3, #8
    8020ebac:	8b250005 	add	x5, x0, w5, uxtb
    8020ebb0:	1a9f97e6 	cset	w6, hi	// hi = pmore
    8020ebb4:	11001cc6 	add	w6, w6, #0x7
    8020ebb8:	8b050180 	add	x0, x12, x5
    8020ebbc:	8b050165 	add	x5, x11, x5
    8020ebc0:	3866c80a 	ldrb	w10, [x0, w6, sxtw]
    8020ebc4:	3866c8a5 	ldrb	w5, [x5, w6, sxtw]
    8020ebc8:	71000d5f 	cmp	w10, #0x3
    8020ebcc:	54fffc21 	b.ne	8020eb50 <__jis_mbtowc+0x90>  // b.any
    8020ebd0:	91000508 	add	x8, x8, #0x1
    8020ebd4:	8b08004f 	add	x15, x2, x8
    8020ebd8:	11000528 	add	w8, w9, #0x1
    8020ebdc:	aa0803e9 	mov	x9, x8
    8020ebe0:	eb03011f 	cmp	x8, x3
    8020ebe4:	54fff8c3 	b.cc	8020eafc <__jis_mbtowc+0x3c>  // b.lo, b.ul, b.last
    8020ebe8:	b9000085 	str	w5, [x4]
    8020ebec:	12800020 	mov	w0, #0xfffffffe            	// #-2
    8020ebf0:	17ffffe1 	b	8020eb74 <__jis_mbtowc+0xb4>
    8020ebf4:	7100115f 	cmp	w10, #0x4
    8020ebf8:	54ffff00 	b.eq	8020ebd8 <__jis_mbtowc+0x118>  // b.none
    8020ebfc:	7100155f 	cmp	w10, #0x5
    8020ec00:	54000181 	b.ne	8020ec30 <__jis_mbtowc+0x170>  // b.any
    8020ec04:	b900009f 	str	wzr, [x4]
    8020ec08:	52800000 	mov	w0, #0x0                   	// #0
    8020ec0c:	b900003f 	str	wzr, [x1]
    8020ec10:	910043ff 	add	sp, sp, #0x10
    8020ec14:	d65f03c0 	ret
    8020ec18:	11000528 	add	w8, w9, #0x1
    8020ec1c:	39001087 	strb	w7, [x4, #4]
    8020ec20:	aa0803e9 	mov	x9, x8
    8020ec24:	eb03011f 	cmp	x8, x3
    8020ec28:	54fff6a3 	b.cc	8020eafc <__jis_mbtowc+0x3c>  // b.lo, b.ul, b.last
    8020ec2c:	17ffffef 	b	8020ebe8 <__jis_mbtowc+0x128>
    8020ec30:	52801141 	mov	w1, #0x8a                  	// #138
    8020ec34:	b90001a1 	str	w1, [x13]
    8020ec38:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020ec3c:	910043ff 	add	sp, sp, #0x10
    8020ec40:	d65f03c0 	ret
    8020ec44:	52800020 	mov	w0, #0x1                   	// #1
    8020ec48:	b9000080 	str	w0, [x4]
    8020ec4c:	39401082 	ldrb	w2, [x4, #4]
    8020ec50:	0b000120 	add	w0, w9, w0
    8020ec54:	394001c3 	ldrb	w3, [x14]
    8020ec58:	0b022062 	add	w2, w3, w2, lsl #8
    8020ec5c:	b9000022 	str	w2, [x1]
    8020ec60:	910043ff 	add	sp, sp, #0x10
    8020ec64:	d65f03c0 	ret
    8020ec68:	b900009f 	str	wzr, [x4]
    8020ec6c:	52800020 	mov	w0, #0x1                   	// #1
    8020ec70:	910043ff 	add	sp, sp, #0x10
    8020ec74:	d65f03c0 	ret
    8020ec78:	52800046 	mov	w6, #0x2                   	// #2
    8020ec7c:	17ffffad 	b	8020eb30 <__jis_mbtowc+0x70>

000000008020ec80 <__assert_func>:
    8020ec80:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020ec84:	f0000004 	adrp	x4, 80211000 <blanks.1+0x60>
    8020ec88:	aa0303e5 	mov	x5, x3
    8020ec8c:	910003fd 	mov	x29, sp
    8020ec90:	f9438887 	ldr	x7, [x4, #1808]
    8020ec94:	aa0003e3 	mov	x3, x0
    8020ec98:	aa0203e6 	mov	x6, x2
    8020ec9c:	2a0103e4 	mov	w4, w1
    8020eca0:	aa0503e2 	mov	x2, x5
    8020eca4:	f9400ce0 	ldr	x0, [x7, #24]
    8020eca8:	b40000e6 	cbz	x6, 8020ecc4 <__assert_func+0x44>
    8020ecac:	d0000005 	adrp	x5, 80210000 <_wcsnrtombs_l+0x110>
    8020ecb0:	9138c0a5 	add	x5, x5, #0xe30
    8020ecb4:	d0000001 	adrp	x1, 80210000 <_wcsnrtombs_l+0x110>
    8020ecb8:	91390021 	add	x1, x1, #0xe40
    8020ecbc:	94000535 	bl	80210190 <fiprintf>
    8020ecc0:	94000554 	bl	80210210 <abort>
    8020ecc4:	d0000005 	adrp	x5, 80210000 <_wcsnrtombs_l+0x110>
    8020ecc8:	913580a5 	add	x5, x5, #0xd60
    8020eccc:	aa0503e6 	mov	x6, x5
    8020ecd0:	17fffff9 	b	8020ecb4 <__assert_func+0x34>
	...

000000008020ece0 <__assert>:
    8020ece0:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020ece4:	aa0203e3 	mov	x3, x2
    8020ece8:	d2800002 	mov	x2, #0x0                   	// #0
    8020ecec:	910003fd 	mov	x29, sp
    8020ecf0:	97ffffe4 	bl	8020ec80 <__assert_func>
	...

000000008020ed00 <strcasecmp>:
    8020ed00:	f0000006 	adrp	x6, 80211000 <blanks.1+0x60>
    8020ed04:	aa0003e8 	mov	x8, x0
    8020ed08:	910c84c6 	add	x6, x6, #0x321
    8020ed0c:	d2800003 	mov	x3, #0x0                   	// #0
    8020ed10:	38636902 	ldrb	w2, [x8, x3]
    8020ed14:	38636820 	ldrb	w0, [x1, x3]
    8020ed18:	11008047 	add	w7, w2, #0x20
    8020ed1c:	386248c5 	ldrb	w5, [x6, w2, uxtw]
    8020ed20:	386048c4 	ldrb	w4, [x6, w0, uxtw]
    8020ed24:	120004a5 	and	w5, w5, #0x3
    8020ed28:	710004bf 	cmp	w5, #0x1
    8020ed2c:	12000484 	and	w4, w4, #0x3
    8020ed30:	1a8200e2 	csel	w2, w7, w2, eq	// eq = none
    8020ed34:	7100049f 	cmp	w4, #0x1
    8020ed38:	540000c0 	b.eq	8020ed50 <strcasecmp+0x50>  // b.none
    8020ed3c:	6b000042 	subs	w2, w2, w0
    8020ed40:	54000121 	b.ne	8020ed64 <strcasecmp+0x64>  // b.any
    8020ed44:	91000463 	add	x3, x3, #0x1
    8020ed48:	35fffe40 	cbnz	w0, 8020ed10 <strcasecmp+0x10>
    8020ed4c:	d65f03c0 	ret
    8020ed50:	11008000 	add	w0, w0, #0x20
    8020ed54:	91000463 	add	x3, x3, #0x1
    8020ed58:	6b000040 	subs	w0, w2, w0
    8020ed5c:	54fffda0 	b.eq	8020ed10 <strcasecmp+0x10>  // b.none
    8020ed60:	d65f03c0 	ret
    8020ed64:	2a0203e0 	mov	w0, w2
    8020ed68:	d65f03c0 	ret
    8020ed6c:	00000000 	udf	#0

000000008020ed70 <strcat>:
    8020ed70:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020ed74:	910003fd 	mov	x29, sp
    8020ed78:	f9000bf3 	str	x19, [sp, #16]
    8020ed7c:	aa0003f3 	mov	x19, x0
    8020ed80:	f240081f 	tst	x0, #0x7
    8020ed84:	540001c1 	b.ne	8020edbc <strcat+0x4c>  // b.any
    8020ed88:	f9400002 	ldr	x2, [x0]
    8020ed8c:	b207dbe4 	mov	x4, #0xfefefefefefefefe    	// #-72340172838076674
    8020ed90:	f29fdfe4 	movk	x4, #0xfeff
    8020ed94:	8b040043 	add	x3, x2, x4
    8020ed98:	8a220062 	bic	x2, x3, x2
    8020ed9c:	f201c05f 	tst	x2, #0x8080808080808080
    8020eda0:	540000e1 	b.ne	8020edbc <strcat+0x4c>  // b.any
    8020eda4:	d503201f 	nop
    8020eda8:	f8408c02 	ldr	x2, [x0, #8]!
    8020edac:	8b040043 	add	x3, x2, x4
    8020edb0:	8a220062 	bic	x2, x3, x2
    8020edb4:	f201c05f 	tst	x2, #0x8080808080808080
    8020edb8:	54ffff80 	b.eq	8020eda8 <strcat+0x38>  // b.none
    8020edbc:	39400002 	ldrb	w2, [x0]
    8020edc0:	34000082 	cbz	w2, 8020edd0 <strcat+0x60>
    8020edc4:	d503201f 	nop
    8020edc8:	38401c02 	ldrb	w2, [x0, #1]!
    8020edcc:	35ffffe2 	cbnz	w2, 8020edc8 <strcat+0x58>
    8020edd0:	97fffb5c 	bl	8020db40 <strcpy>
    8020edd4:	aa1303e0 	mov	x0, x19
    8020edd8:	f9400bf3 	ldr	x19, [sp, #16]
    8020eddc:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020ede0:	d65f03c0 	ret
	...

000000008020edf0 <_Balloc>:
    8020edf0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020edf4:	910003fd 	mov	x29, sp
    8020edf8:	f9403402 	ldr	x2, [x0, #104]
    8020edfc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020ee00:	aa0003f3 	mov	x19, x0
    8020ee04:	2a0103f4 	mov	w20, w1
    8020ee08:	b4000142 	cbz	x2, 8020ee30 <_Balloc+0x40>
    8020ee0c:	93407e81 	sxtw	x1, w20
    8020ee10:	f8617840 	ldr	x0, [x2, x1, lsl #3]
    8020ee14:	b40001e0 	cbz	x0, 8020ee50 <_Balloc+0x60>
    8020ee18:	f9400003 	ldr	x3, [x0]
    8020ee1c:	f8217843 	str	x3, [x2, x1, lsl #3]
    8020ee20:	f900081f 	str	xzr, [x0, #16]
    8020ee24:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ee28:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020ee2c:	d65f03c0 	ret
    8020ee30:	d2800822 	mov	x2, #0x41                  	// #65
    8020ee34:	d2800101 	mov	x1, #0x8                   	// #8
    8020ee38:	940003fe 	bl	8020fe30 <_calloc_r>
    8020ee3c:	f9003660 	str	x0, [x19, #104]
    8020ee40:	aa0003e2 	mov	x2, x0
    8020ee44:	b5fffe40 	cbnz	x0, 8020ee0c <_Balloc+0x1c>
    8020ee48:	d2800000 	mov	x0, #0x0                   	// #0
    8020ee4c:	17fffff6 	b	8020ee24 <_Balloc+0x34>
    8020ee50:	52800021 	mov	w1, #0x1                   	// #1
    8020ee54:	aa1303e0 	mov	x0, x19
    8020ee58:	1ad42033 	lsl	w19, w1, w20
    8020ee5c:	d2800021 	mov	x1, #0x1                   	// #1
    8020ee60:	93407e62 	sxtw	x2, w19
    8020ee64:	91001c42 	add	x2, x2, #0x7
    8020ee68:	d37ef442 	lsl	x2, x2, #2
    8020ee6c:	940003f1 	bl	8020fe30 <_calloc_r>
    8020ee70:	b4fffec0 	cbz	x0, 8020ee48 <_Balloc+0x58>
    8020ee74:	29014c14 	stp	w20, w19, [x0, #8]
    8020ee78:	17ffffea 	b	8020ee20 <_Balloc+0x30>
    8020ee7c:	00000000 	udf	#0

000000008020ee80 <_Bfree>:
    8020ee80:	b40000c1 	cbz	x1, 8020ee98 <_Bfree+0x18>
    8020ee84:	f9403400 	ldr	x0, [x0, #104]
    8020ee88:	b9800822 	ldrsw	x2, [x1, #8]
    8020ee8c:	f8627803 	ldr	x3, [x0, x2, lsl #3]
    8020ee90:	f9000023 	str	x3, [x1]
    8020ee94:	f8227801 	str	x1, [x0, x2, lsl #3]
    8020ee98:	d65f03c0 	ret
    8020ee9c:	00000000 	udf	#0

000000008020eea0 <__multadd>:
    8020eea0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020eea4:	91006027 	add	x7, x1, #0x18
    8020eea8:	d2800005 	mov	x5, #0x0                   	// #0
    8020eeac:	910003fd 	mov	x29, sp
    8020eeb0:	a90153f3 	stp	x19, x20, [sp, #16]
    8020eeb4:	2a0303f3 	mov	w19, w3
    8020eeb8:	b9401434 	ldr	w20, [x1, #20]
    8020eebc:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020eec0:	aa0103f5 	mov	x21, x1
    8020eec4:	aa0003f6 	mov	x22, x0
    8020eec8:	b86578e4 	ldr	w4, [x7, x5, lsl #2]
    8020eecc:	12003c83 	and	w3, w4, #0xffff
    8020eed0:	53107c84 	lsr	w4, w4, #16
    8020eed4:	1b024c63 	madd	w3, w3, w2, w19
    8020eed8:	12003c66 	and	w6, w3, #0xffff
    8020eedc:	53107c63 	lsr	w3, w3, #16
    8020eee0:	1b020c83 	madd	w3, w4, w2, w3
    8020eee4:	0b0340c4 	add	w4, w6, w3, lsl #16
    8020eee8:	b82578e4 	str	w4, [x7, x5, lsl #2]
    8020eeec:	910004a5 	add	x5, x5, #0x1
    8020eef0:	53107c73 	lsr	w19, w3, #16
    8020eef4:	6b05029f 	cmp	w20, w5
    8020eef8:	54fffe8c 	b.gt	8020eec8 <__multadd+0x28>
    8020eefc:	34000113 	cbz	w19, 8020ef1c <__multadd+0x7c>
    8020ef00:	b9400ea0 	ldr	w0, [x21, #12]
    8020ef04:	6b14001f 	cmp	w0, w20
    8020ef08:	5400014d 	b.le	8020ef30 <__multadd+0x90>
    8020ef0c:	8b34caa0 	add	x0, x21, w20, sxtw #2
    8020ef10:	11000694 	add	w20, w20, #0x1
    8020ef14:	b9001813 	str	w19, [x0, #24]
    8020ef18:	b90016b4 	str	w20, [x21, #20]
    8020ef1c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ef20:	aa1503e0 	mov	x0, x21
    8020ef24:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020ef28:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020ef2c:	d65f03c0 	ret
    8020ef30:	b9400aa1 	ldr	w1, [x21, #8]
    8020ef34:	aa1603e0 	mov	x0, x22
    8020ef38:	f9001bf7 	str	x23, [sp, #48]
    8020ef3c:	11000421 	add	w1, w1, #0x1
    8020ef40:	97ffffac 	bl	8020edf0 <_Balloc>
    8020ef44:	aa0003f7 	mov	x23, x0
    8020ef48:	b4000260 	cbz	x0, 8020ef94 <__multadd+0xf4>
    8020ef4c:	b98016a2 	ldrsw	x2, [x21, #20]
    8020ef50:	910042a1 	add	x1, x21, #0x10
    8020ef54:	91004000 	add	x0, x0, #0x10
    8020ef58:	91000842 	add	x2, x2, #0x2
    8020ef5c:	d37ef442 	lsl	x2, x2, #2
    8020ef60:	97ffefc8 	bl	8020ae80 <memcpy>
    8020ef64:	f94036c0 	ldr	x0, [x22, #104]
    8020ef68:	b9800aa1 	ldrsw	x1, [x21, #8]
    8020ef6c:	f8617802 	ldr	x2, [x0, x1, lsl #3]
    8020ef70:	f90002a2 	str	x2, [x21]
    8020ef74:	f8217815 	str	x21, [x0, x1, lsl #3]
    8020ef78:	aa1703f5 	mov	x21, x23
    8020ef7c:	8b34caa0 	add	x0, x21, w20, sxtw #2
    8020ef80:	11000694 	add	w20, w20, #0x1
    8020ef84:	f9401bf7 	ldr	x23, [sp, #48]
    8020ef88:	b9001813 	str	w19, [x0, #24]
    8020ef8c:	b90016b4 	str	w20, [x21, #20]
    8020ef90:	17ffffe3 	b	8020ef1c <__multadd+0x7c>
    8020ef94:	d0000003 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020ef98:	d0000000 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020ef9c:	9136e063 	add	x3, x3, #0xdb8
    8020efa0:	9139c000 	add	x0, x0, #0xe70
    8020efa4:	d2800002 	mov	x2, #0x0                   	// #0
    8020efa8:	52801741 	mov	w1, #0xba                  	// #186
    8020efac:	97ffff35 	bl	8020ec80 <__assert_func>

000000008020efb0 <__s2b>:
    8020efb0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020efb4:	5291c725 	mov	w5, #0x8e39                	// #36409
    8020efb8:	72a71c65 	movk	w5, #0x38e3, lsl #16
    8020efbc:	910003fd 	mov	x29, sp
    8020efc0:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020efc4:	2a0303f5 	mov	w21, w3
    8020efc8:	11002063 	add	w3, w3, #0x8
    8020efcc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020efd0:	2a0203f6 	mov	w22, w2
    8020efd4:	aa0003f4 	mov	x20, x0
    8020efd8:	9b257c65 	smull	x5, w3, w5
    8020efdc:	a90363f7 	stp	x23, x24, [sp, #48]
    8020efe0:	aa0103f3 	mov	x19, x1
    8020efe4:	2a0403f7 	mov	w23, w4
    8020efe8:	9361fca5 	asr	x5, x5, #33
    8020efec:	4b837ca2 	sub	w2, w5, w3, asr #31
    8020eff0:	710026bf 	cmp	w21, #0x9
    8020eff4:	5400064d 	b.le	8020f0bc <__s2b+0x10c>
    8020eff8:	52800020 	mov	w0, #0x1                   	// #1
    8020effc:	52800001 	mov	w1, #0x0                   	// #0
    8020f000:	531f7800 	lsl	w0, w0, #1
    8020f004:	11000421 	add	w1, w1, #0x1
    8020f008:	6b00005f 	cmp	w2, w0
    8020f00c:	54ffffac 	b.gt	8020f000 <__s2b+0x50>
    8020f010:	aa1403e0 	mov	x0, x20
    8020f014:	97ffff77 	bl	8020edf0 <_Balloc>
    8020f018:	aa0003e1 	mov	x1, x0
    8020f01c:	b4000540 	cbz	x0, 8020f0c4 <__s2b+0x114>
    8020f020:	52800020 	mov	w0, #0x1                   	// #1
    8020f024:	2902dc20 	stp	w0, w23, [x1, #20]
    8020f028:	710026df 	cmp	w22, #0x9
    8020f02c:	540002ac 	b.gt	8020f080 <__s2b+0xd0>
    8020f030:	91002a73 	add	x19, x19, #0xa
    8020f034:	52800136 	mov	w22, #0x9                   	// #9
    8020f038:	6b1602bf 	cmp	w21, w22
    8020f03c:	5400016d 	b.le	8020f068 <__s2b+0xb8>
    8020f040:	4b1602b5 	sub	w21, w21, w22
    8020f044:	8b150275 	add	x21, x19, x21
    8020f048:	38401663 	ldrb	w3, [x19], #1
    8020f04c:	aa1403e0 	mov	x0, x20
    8020f050:	52800142 	mov	w2, #0xa                   	// #10
    8020f054:	5100c063 	sub	w3, w3, #0x30
    8020f058:	97ffff92 	bl	8020eea0 <__multadd>
    8020f05c:	aa0003e1 	mov	x1, x0
    8020f060:	eb15027f 	cmp	x19, x21
    8020f064:	54ffff21 	b.ne	8020f048 <__s2b+0x98>  // b.any
    8020f068:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f06c:	aa0103e0 	mov	x0, x1
    8020f070:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020f074:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020f078:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020f07c:	d65f03c0 	ret
    8020f080:	91002678 	add	x24, x19, #0x9
    8020f084:	8b364273 	add	x19, x19, w22, uxtw
    8020f088:	aa1803f7 	mov	x23, x24
    8020f08c:	d503201f 	nop
    8020f090:	384016e3 	ldrb	w3, [x23], #1
    8020f094:	aa1403e0 	mov	x0, x20
    8020f098:	52800142 	mov	w2, #0xa                   	// #10
    8020f09c:	5100c063 	sub	w3, w3, #0x30
    8020f0a0:	97ffff80 	bl	8020eea0 <__multadd>
    8020f0a4:	aa0003e1 	mov	x1, x0
    8020f0a8:	eb1302ff 	cmp	x23, x19
    8020f0ac:	54ffff21 	b.ne	8020f090 <__s2b+0xe0>  // b.any
    8020f0b0:	510022d3 	sub	w19, w22, #0x8
    8020f0b4:	8b130313 	add	x19, x24, x19
    8020f0b8:	17ffffe0 	b	8020f038 <__s2b+0x88>
    8020f0bc:	52800001 	mov	w1, #0x0                   	// #0
    8020f0c0:	17ffffd4 	b	8020f010 <__s2b+0x60>
    8020f0c4:	b0000003 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020f0c8:	b0000000 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020f0cc:	9136e063 	add	x3, x3, #0xdb8
    8020f0d0:	9139c000 	add	x0, x0, #0xe70
    8020f0d4:	d2800002 	mov	x2, #0x0                   	// #0
    8020f0d8:	52801a61 	mov	w1, #0xd3                  	// #211
    8020f0dc:	97fffee9 	bl	8020ec80 <__assert_func>

000000008020f0e0 <__hi0bits>:
    8020f0e0:	2a0003e1 	mov	w1, w0
    8020f0e4:	529fffe2 	mov	w2, #0xffff                	// #65535
    8020f0e8:	52800000 	mov	w0, #0x0                   	// #0
    8020f0ec:	6b02003f 	cmp	w1, w2
    8020f0f0:	54000068 	b.hi	8020f0fc <__hi0bits+0x1c>  // b.pmore
    8020f0f4:	53103c21 	lsl	w1, w1, #16
    8020f0f8:	52800200 	mov	w0, #0x10                  	// #16
    8020f0fc:	12bfe002 	mov	w2, #0xffffff              	// #16777215
    8020f100:	6b02003f 	cmp	w1, w2
    8020f104:	54000068 	b.hi	8020f110 <__hi0bits+0x30>  // b.pmore
    8020f108:	11002000 	add	w0, w0, #0x8
    8020f10c:	53185c21 	lsl	w1, w1, #8
    8020f110:	12be0002 	mov	w2, #0xfffffff             	// #268435455
    8020f114:	6b02003f 	cmp	w1, w2
    8020f118:	54000068 	b.hi	8020f124 <__hi0bits+0x44>  // b.pmore
    8020f11c:	11001000 	add	w0, w0, #0x4
    8020f120:	531c6c21 	lsl	w1, w1, #4
    8020f124:	12b80002 	mov	w2, #0x3fffffff            	// #1073741823
    8020f128:	6b02003f 	cmp	w1, w2
    8020f12c:	54000089 	b.ls	8020f13c <__hi0bits+0x5c>  // b.plast
    8020f130:	2a2103e1 	mvn	w1, w1
    8020f134:	0b417c00 	add	w0, w0, w1, lsr #31
    8020f138:	d65f03c0 	ret
    8020f13c:	531e7422 	lsl	w2, w1, #2
    8020f140:	37e800c1 	tbnz	w1, #29, 8020f158 <__hi0bits+0x78>
    8020f144:	f262005f 	tst	x2, #0x40000000
    8020f148:	11000c00 	add	w0, w0, #0x3
    8020f14c:	52800401 	mov	w1, #0x20                  	// #32
    8020f150:	1a811000 	csel	w0, w0, w1, ne	// ne = any
    8020f154:	d65f03c0 	ret
    8020f158:	11000800 	add	w0, w0, #0x2
    8020f15c:	d65f03c0 	ret

000000008020f160 <__lo0bits>:
    8020f160:	aa0003e2 	mov	x2, x0
    8020f164:	52800000 	mov	w0, #0x0                   	// #0
    8020f168:	b9400041 	ldr	w1, [x2]
    8020f16c:	f240083f 	tst	x1, #0x7
    8020f170:	540000e0 	b.eq	8020f18c <__lo0bits+0x2c>  // b.none
    8020f174:	370000a1 	tbnz	w1, #0, 8020f188 <__lo0bits+0x28>
    8020f178:	360803a1 	tbz	w1, #1, 8020f1ec <__lo0bits+0x8c>
    8020f17c:	53017c21 	lsr	w1, w1, #1
    8020f180:	52800020 	mov	w0, #0x1                   	// #1
    8020f184:	b9000041 	str	w1, [x2]
    8020f188:	d65f03c0 	ret
    8020f18c:	72003c3f 	tst	w1, #0xffff
    8020f190:	54000061 	b.ne	8020f19c <__lo0bits+0x3c>  // b.any
    8020f194:	53107c21 	lsr	w1, w1, #16
    8020f198:	52800200 	mov	w0, #0x10                  	// #16
    8020f19c:	72001c3f 	tst	w1, #0xff
    8020f1a0:	54000061 	b.ne	8020f1ac <__lo0bits+0x4c>  // b.any
    8020f1a4:	11002000 	add	w0, w0, #0x8
    8020f1a8:	53087c21 	lsr	w1, w1, #8
    8020f1ac:	f2400c3f 	tst	x1, #0xf
    8020f1b0:	54000061 	b.ne	8020f1bc <__lo0bits+0x5c>  // b.any
    8020f1b4:	11001000 	add	w0, w0, #0x4
    8020f1b8:	53047c21 	lsr	w1, w1, #4
    8020f1bc:	f240043f 	tst	x1, #0x3
    8020f1c0:	54000061 	b.ne	8020f1cc <__lo0bits+0x6c>  // b.any
    8020f1c4:	11000800 	add	w0, w0, #0x2
    8020f1c8:	53027c21 	lsr	w1, w1, #2
    8020f1cc:	37000081 	tbnz	w1, #0, 8020f1dc <__lo0bits+0x7c>
    8020f1d0:	11000400 	add	w0, w0, #0x1
    8020f1d4:	53017c21 	lsr	w1, w1, #1
    8020f1d8:	34000061 	cbz	w1, 8020f1e4 <__lo0bits+0x84>
    8020f1dc:	b9000041 	str	w1, [x2]
    8020f1e0:	d65f03c0 	ret
    8020f1e4:	52800400 	mov	w0, #0x20                  	// #32
    8020f1e8:	d65f03c0 	ret
    8020f1ec:	53027c21 	lsr	w1, w1, #2
    8020f1f0:	52800040 	mov	w0, #0x2                   	// #2
    8020f1f4:	b9000041 	str	w1, [x2]
    8020f1f8:	d65f03c0 	ret
    8020f1fc:	00000000 	udf	#0

000000008020f200 <__i2b>:
    8020f200:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020f204:	910003fd 	mov	x29, sp
    8020f208:	f9403402 	ldr	x2, [x0, #104]
    8020f20c:	a90153f3 	stp	x19, x20, [sp, #16]
    8020f210:	aa0003f3 	mov	x19, x0
    8020f214:	2a0103f4 	mov	w20, w1
    8020f218:	b4000182 	cbz	x2, 8020f248 <__i2b+0x48>
    8020f21c:	f9400440 	ldr	x0, [x2, #8]
    8020f220:	b40002e0 	cbz	x0, 8020f27c <__i2b+0x7c>
    8020f224:	f9400001 	ldr	x1, [x0]
    8020f228:	f9000441 	str	x1, [x2, #8]
    8020f22c:	d0000001 	adrp	x1, 80211000 <blanks.1+0x60>
    8020f230:	b9001814 	str	w20, [x0, #24]
    8020f234:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f238:	fd418c20 	ldr	d0, [x1, #792]
    8020f23c:	fd000800 	str	d0, [x0, #16]
    8020f240:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020f244:	d65f03c0 	ret
    8020f248:	d2800822 	mov	x2, #0x41                  	// #65
    8020f24c:	d2800101 	mov	x1, #0x8                   	// #8
    8020f250:	940002f8 	bl	8020fe30 <_calloc_r>
    8020f254:	f9003660 	str	x0, [x19, #104]
    8020f258:	aa0003e2 	mov	x2, x0
    8020f25c:	b5fffe00 	cbnz	x0, 8020f21c <__i2b+0x1c>
    8020f260:	b0000003 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020f264:	b0000000 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020f268:	9136e063 	add	x3, x3, #0xdb8
    8020f26c:	9139c000 	add	x0, x0, #0xe70
    8020f270:	d2800002 	mov	x2, #0x0                   	// #0
    8020f274:	528028a1 	mov	w1, #0x145                 	// #325
    8020f278:	97fffe82 	bl	8020ec80 <__assert_func>
    8020f27c:	aa1303e0 	mov	x0, x19
    8020f280:	d2800482 	mov	x2, #0x24                  	// #36
    8020f284:	d2800021 	mov	x1, #0x1                   	// #1
    8020f288:	940002ea 	bl	8020fe30 <_calloc_r>
    8020f28c:	b4fffea0 	cbz	x0, 8020f260 <__i2b+0x60>
    8020f290:	d0000001 	adrp	x1, 80211000 <blanks.1+0x60>
    8020f294:	b9001814 	str	w20, [x0, #24]
    8020f298:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f29c:	fd418820 	ldr	d0, [x1, #784]
    8020f2a0:	d0000001 	adrp	x1, 80211000 <blanks.1+0x60>
    8020f2a4:	fd000400 	str	d0, [x0, #8]
    8020f2a8:	fd418c20 	ldr	d0, [x1, #792]
    8020f2ac:	fd000800 	str	d0, [x0, #16]
    8020f2b0:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020f2b4:	d65f03c0 	ret
	...

000000008020f2c0 <__multiply>:
    8020f2c0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020f2c4:	910003fd 	mov	x29, sp
    8020f2c8:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020f2cc:	aa0103f5 	mov	x21, x1
    8020f2d0:	b9401436 	ldr	w22, [x1, #20]
    8020f2d4:	f9001bf7 	str	x23, [sp, #48]
    8020f2d8:	b9401457 	ldr	w23, [x2, #20]
    8020f2dc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020f2e0:	aa0203f4 	mov	x20, x2
    8020f2e4:	6b1702df 	cmp	w22, w23
    8020f2e8:	540000eb 	b.lt	8020f304 <__multiply+0x44>  // b.tstop
    8020f2ec:	2a1703e2 	mov	w2, w23
    8020f2f0:	aa1403e1 	mov	x1, x20
    8020f2f4:	2a1603f7 	mov	w23, w22
    8020f2f8:	aa1503f4 	mov	x20, x21
    8020f2fc:	2a0203f6 	mov	w22, w2
    8020f300:	aa0103f5 	mov	x21, x1
    8020f304:	29410a81 	ldp	w1, w2, [x20, #8]
    8020f308:	0b1602f3 	add	w19, w23, w22
    8020f30c:	6b13005f 	cmp	w2, w19
    8020f310:	1a81a421 	cinc	w1, w1, lt	// lt = tstop
    8020f314:	97fffeb7 	bl	8020edf0 <_Balloc>
    8020f318:	b4000b80 	cbz	x0, 8020f488 <__multiply+0x1c8>
    8020f31c:	91006007 	add	x7, x0, #0x18
    8020f320:	8b33c8e8 	add	x8, x7, w19, sxtw #2
    8020f324:	aa0703e3 	mov	x3, x7
    8020f328:	eb0800ff 	cmp	x7, x8
    8020f32c:	54000082 	b.cs	8020f33c <__multiply+0x7c>  // b.hs, b.nlast
    8020f330:	b800447f 	str	wzr, [x3], #4
    8020f334:	eb03011f 	cmp	x8, x3
    8020f338:	54ffffc8 	b.hi	8020f330 <__multiply+0x70>  // b.pmore
    8020f33c:	910062a6 	add	x6, x21, #0x18
    8020f340:	9100628b 	add	x11, x20, #0x18
    8020f344:	8b36c8c9 	add	x9, x6, w22, sxtw #2
    8020f348:	8b37c965 	add	x5, x11, w23, sxtw #2
    8020f34c:	eb0900df 	cmp	x6, x9
    8020f350:	54000822 	b.cs	8020f454 <__multiply+0x194>  // b.hs, b.nlast
    8020f354:	cb1400aa 	sub	x10, x5, x20
    8020f358:	91006694 	add	x20, x20, #0x19
    8020f35c:	d100654a 	sub	x10, x10, #0x19
    8020f360:	d2800081 	mov	x1, #0x4                   	// #4
    8020f364:	927ef54a 	and	x10, x10, #0xfffffffffffffffc
    8020f368:	eb1400bf 	cmp	x5, x20
    8020f36c:	8b01014a 	add	x10, x10, x1
    8020f370:	9a81214a 	csel	x10, x10, x1, cs	// cs = hs, nlast
    8020f374:	14000007 	b	8020f390 <__multiply+0xd0>
    8020f378:	53107c63 	lsr	w3, w3, #16
    8020f37c:	350003c3 	cbnz	w3, 8020f3f4 <__multiply+0x134>
    8020f380:	910010c6 	add	x6, x6, #0x4
    8020f384:	910010e7 	add	x7, x7, #0x4
    8020f388:	eb06013f 	cmp	x9, x6
    8020f38c:	54000649 	b.ls	8020f454 <__multiply+0x194>  // b.plast
    8020f390:	b94000c3 	ldr	w3, [x6]
    8020f394:	72003c6d 	ands	w13, w3, #0xffff
    8020f398:	54ffff00 	b.eq	8020f378 <__multiply+0xb8>  // b.none
    8020f39c:	aa0703ec 	mov	x12, x7
    8020f3a0:	aa0b03e4 	mov	x4, x11
    8020f3a4:	5280000e 	mov	w14, #0x0                   	// #0
    8020f3a8:	b8404481 	ldr	w1, [x4], #4
    8020f3ac:	b9400183 	ldr	w3, [x12]
    8020f3b0:	12003c22 	and	w2, w1, #0xffff
    8020f3b4:	12003c6f 	and	w15, w3, #0xffff
    8020f3b8:	53107c21 	lsr	w1, w1, #16
    8020f3bc:	53107c63 	lsr	w3, w3, #16
    8020f3c0:	1b0d3c42 	madd	w2, w2, w13, w15
    8020f3c4:	1b0d0c21 	madd	w1, w1, w13, w3
    8020f3c8:	0b0e0042 	add	w2, w2, w14
    8020f3cc:	0b424021 	add	w1, w1, w2, lsr #16
    8020f3d0:	33103c22 	bfi	w2, w1, #16, #16
    8020f3d4:	b8004582 	str	w2, [x12], #4
    8020f3d8:	53107c2e 	lsr	w14, w1, #16
    8020f3dc:	eb0400bf 	cmp	x5, x4
    8020f3e0:	54fffe48 	b.hi	8020f3a8 <__multiply+0xe8>  // b.pmore
    8020f3e4:	b82a68ee 	str	w14, [x7, x10]
    8020f3e8:	b94000c3 	ldr	w3, [x6]
    8020f3ec:	53107c63 	lsr	w3, w3, #16
    8020f3f0:	34fffc83 	cbz	w3, 8020f380 <__multiply+0xc0>
    8020f3f4:	b94000e1 	ldr	w1, [x7]
    8020f3f8:	aa0703ed 	mov	x13, x7
    8020f3fc:	aa0b03e4 	mov	x4, x11
    8020f400:	5280000e 	mov	w14, #0x0                   	// #0
    8020f404:	2a0103ec 	mov	w12, w1
    8020f408:	79400082 	ldrh	w2, [x4]
    8020f40c:	1b033842 	madd	w2, w2, w3, w14
    8020f410:	0b4c4042 	add	w2, w2, w12, lsr #16
    8020f414:	33103c41 	bfi	w1, w2, #16, #16
    8020f418:	b80045a1 	str	w1, [x13], #4
    8020f41c:	b8404481 	ldr	w1, [x4], #4
    8020f420:	b94001ac 	ldr	w12, [x13]
    8020f424:	53107c21 	lsr	w1, w1, #16
    8020f428:	12003d8e 	and	w14, w12, #0xffff
    8020f42c:	1b033821 	madd	w1, w1, w3, w14
    8020f430:	0b424021 	add	w1, w1, w2, lsr #16
    8020f434:	53107c2e 	lsr	w14, w1, #16
    8020f438:	eb0400bf 	cmp	x5, x4
    8020f43c:	54fffe68 	b.hi	8020f408 <__multiply+0x148>  // b.pmore
    8020f440:	910010c6 	add	x6, x6, #0x4
    8020f444:	b82a68e1 	str	w1, [x7, x10]
    8020f448:	910010e7 	add	x7, x7, #0x4
    8020f44c:	eb06013f 	cmp	x9, x6
    8020f450:	54fffa08 	b.hi	8020f390 <__multiply+0xd0>  // b.pmore
    8020f454:	7100027f 	cmp	w19, #0x0
    8020f458:	5400008c 	b.gt	8020f468 <__multiply+0x1a8>
    8020f45c:	14000005 	b	8020f470 <__multiply+0x1b0>
    8020f460:	71000673 	subs	w19, w19, #0x1
    8020f464:	54000060 	b.eq	8020f470 <__multiply+0x1b0>  // b.none
    8020f468:	b85fcd01 	ldr	w1, [x8, #-4]!
    8020f46c:	34ffffa1 	cbz	w1, 8020f460 <__multiply+0x1a0>
    8020f470:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020f474:	f9401bf7 	ldr	x23, [sp, #48]
    8020f478:	b9001413 	str	w19, [x0, #20]
    8020f47c:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f480:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020f484:	d65f03c0 	ret
    8020f488:	b0000003 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020f48c:	b0000000 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020f490:	9136e063 	add	x3, x3, #0xdb8
    8020f494:	9139c000 	add	x0, x0, #0xe70
    8020f498:	d2800002 	mov	x2, #0x0                   	// #0
    8020f49c:	52802c41 	mov	w1, #0x162                 	// #354
    8020f4a0:	97fffdf8 	bl	8020ec80 <__assert_func>
	...

000000008020f4b0 <__pow5mult>:
    8020f4b0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020f4b4:	910003fd 	mov	x29, sp
    8020f4b8:	a90153f3 	stp	x19, x20, [sp, #16]
    8020f4bc:	2a0203f3 	mov	w19, w2
    8020f4c0:	72000442 	ands	w2, w2, #0x3
    8020f4c4:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020f4c8:	aa0003f6 	mov	x22, x0
    8020f4cc:	aa0103f5 	mov	x21, x1
    8020f4d0:	540004c1 	b.ne	8020f568 <__pow5mult+0xb8>  // b.any
    8020f4d4:	13027e73 	asr	w19, w19, #2
    8020f4d8:	340002f3 	cbz	w19, 8020f534 <__pow5mult+0x84>
    8020f4dc:	f94032d4 	ldr	x20, [x22, #96]
    8020f4e0:	b4000554 	cbz	x20, 8020f588 <__pow5mult+0xd8>
    8020f4e4:	370000f3 	tbnz	w19, #0, 8020f500 <__pow5mult+0x50>
    8020f4e8:	13017e73 	asr	w19, w19, #1
    8020f4ec:	34000253 	cbz	w19, 8020f534 <__pow5mult+0x84>
    8020f4f0:	f9400280 	ldr	x0, [x20]
    8020f4f4:	b40002a0 	cbz	x0, 8020f548 <__pow5mult+0x98>
    8020f4f8:	aa0003f4 	mov	x20, x0
    8020f4fc:	3607ff73 	tbz	w19, #0, 8020f4e8 <__pow5mult+0x38>
    8020f500:	aa1403e2 	mov	x2, x20
    8020f504:	aa1503e1 	mov	x1, x21
    8020f508:	aa1603e0 	mov	x0, x22
    8020f50c:	97ffff6d 	bl	8020f2c0 <__multiply>
    8020f510:	b40000d5 	cbz	x21, 8020f528 <__pow5mult+0x78>
    8020f514:	f94036c1 	ldr	x1, [x22, #104]
    8020f518:	b9800aa2 	ldrsw	x2, [x21, #8]
    8020f51c:	f8627823 	ldr	x3, [x1, x2, lsl #3]
    8020f520:	f90002a3 	str	x3, [x21]
    8020f524:	f8227835 	str	x21, [x1, x2, lsl #3]
    8020f528:	aa0003f5 	mov	x21, x0
    8020f52c:	13017e73 	asr	w19, w19, #1
    8020f530:	35fffe13 	cbnz	w19, 8020f4f0 <__pow5mult+0x40>
    8020f534:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f538:	aa1503e0 	mov	x0, x21
    8020f53c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020f540:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020f544:	d65f03c0 	ret
    8020f548:	aa1403e2 	mov	x2, x20
    8020f54c:	aa1403e1 	mov	x1, x20
    8020f550:	aa1603e0 	mov	x0, x22
    8020f554:	97ffff5b 	bl	8020f2c0 <__multiply>
    8020f558:	f9000280 	str	x0, [x20]
    8020f55c:	aa0003f4 	mov	x20, x0
    8020f560:	f900001f 	str	xzr, [x0]
    8020f564:	17ffffe6 	b	8020f4fc <__pow5mult+0x4c>
    8020f568:	51000442 	sub	w2, w2, #0x1
    8020f56c:	d0000004 	adrp	x4, 80211000 <blanks.1+0x60>
    8020f570:	91132084 	add	x4, x4, #0x4c8
    8020f574:	52800003 	mov	w3, #0x0                   	// #0
    8020f578:	b862d882 	ldr	w2, [x4, w2, sxtw #2]
    8020f57c:	97fffe49 	bl	8020eea0 <__multadd>
    8020f580:	aa0003f5 	mov	x21, x0
    8020f584:	17ffffd4 	b	8020f4d4 <__pow5mult+0x24>
    8020f588:	aa1603e0 	mov	x0, x22
    8020f58c:	52800021 	mov	w1, #0x1                   	// #1
    8020f590:	97fffe18 	bl	8020edf0 <_Balloc>
    8020f594:	aa0003f4 	mov	x20, x0
    8020f598:	b40000e0 	cbz	x0, 8020f5b4 <__pow5mult+0x104>
    8020f59c:	d2800020 	mov	x0, #0x1                   	// #1
    8020f5a0:	f2c04e20 	movk	x0, #0x271, lsl #32
    8020f5a4:	f8014280 	stur	x0, [x20, #20]
    8020f5a8:	f90032d4 	str	x20, [x22, #96]
    8020f5ac:	f900029f 	str	xzr, [x20]
    8020f5b0:	17ffffcd 	b	8020f4e4 <__pow5mult+0x34>
    8020f5b4:	b0000003 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020f5b8:	b0000000 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020f5bc:	9136e063 	add	x3, x3, #0xdb8
    8020f5c0:	9139c000 	add	x0, x0, #0xe70
    8020f5c4:	d2800002 	mov	x2, #0x0                   	// #0
    8020f5c8:	528028a1 	mov	w1, #0x145                 	// #325
    8020f5cc:	97fffdad 	bl	8020ec80 <__assert_func>

000000008020f5d0 <__lshift>:
    8020f5d0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020f5d4:	910003fd 	mov	x29, sp
    8020f5d8:	a90363f7 	stp	x23, x24, [sp, #48]
    8020f5dc:	13057c58 	asr	w24, w2, #5
    8020f5e0:	b9401437 	ldr	w23, [x1, #20]
    8020f5e4:	b9400c23 	ldr	w3, [x1, #12]
    8020f5e8:	0b170317 	add	w23, w24, w23
    8020f5ec:	a90153f3 	stp	x19, x20, [sp, #16]
    8020f5f0:	aa0103f4 	mov	x20, x1
    8020f5f4:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020f5f8:	110006f5 	add	w21, w23, #0x1
    8020f5fc:	b9400821 	ldr	w1, [x1, #8]
    8020f600:	2a0203f3 	mov	w19, w2
    8020f604:	aa0003f6 	mov	x22, x0
    8020f608:	6b0302bf 	cmp	w21, w3
    8020f60c:	540000ad 	b.le	8020f620 <__lshift+0x50>
    8020f610:	531f7863 	lsl	w3, w3, #1
    8020f614:	11000421 	add	w1, w1, #0x1
    8020f618:	6b0302bf 	cmp	w21, w3
    8020f61c:	54ffffac 	b.gt	8020f610 <__lshift+0x40>
    8020f620:	aa1603e0 	mov	x0, x22
    8020f624:	97fffdf3 	bl	8020edf0 <_Balloc>
    8020f628:	b40007a0 	cbz	x0, 8020f71c <__lshift+0x14c>
    8020f62c:	91006005 	add	x5, x0, #0x18
    8020f630:	7100031f 	cmp	w24, #0x0
    8020f634:	5400012d 	b.le	8020f658 <__lshift+0x88>
    8020f638:	11001b04 	add	w4, w24, #0x6
    8020f63c:	aa0503e3 	mov	x3, x5
    8020f640:	8b24c804 	add	x4, x0, w4, sxtw #2
    8020f644:	d503201f 	nop
    8020f648:	b800447f 	str	wzr, [x3], #4
    8020f64c:	eb04007f 	cmp	x3, x4
    8020f650:	54ffffc1 	b.ne	8020f648 <__lshift+0x78>  // b.any
    8020f654:	8b3848a5 	add	x5, x5, w24, uxtw #2
    8020f658:	b9801686 	ldrsw	x6, [x20, #20]
    8020f65c:	91006283 	add	x3, x20, #0x18
    8020f660:	72001267 	ands	w7, w19, #0x1f
    8020f664:	8b060866 	add	x6, x3, x6, lsl #2
    8020f668:	54000480 	b.eq	8020f6f8 <__lshift+0x128>  // b.none
    8020f66c:	52800408 	mov	w8, #0x20                  	// #32
    8020f670:	aa0503e1 	mov	x1, x5
    8020f674:	4b070108 	sub	w8, w8, w7
    8020f678:	52800004 	mov	w4, #0x0                   	// #0
    8020f67c:	d503201f 	nop
    8020f680:	b9400062 	ldr	w2, [x3]
    8020f684:	1ac72042 	lsl	w2, w2, w7
    8020f688:	2a040042 	orr	w2, w2, w4
    8020f68c:	b8004422 	str	w2, [x1], #4
    8020f690:	b8404464 	ldr	w4, [x3], #4
    8020f694:	1ac82484 	lsr	w4, w4, w8
    8020f698:	eb0300df 	cmp	x6, x3
    8020f69c:	54ffff28 	b.hi	8020f680 <__lshift+0xb0>  // b.pmore
    8020f6a0:	cb1400c1 	sub	x1, x6, x20
    8020f6a4:	91006682 	add	x2, x20, #0x19
    8020f6a8:	d1006421 	sub	x1, x1, #0x19
    8020f6ac:	eb0200df 	cmp	x6, x2
    8020f6b0:	927ef421 	and	x1, x1, #0xfffffffffffffffc
    8020f6b4:	d2800082 	mov	x2, #0x4                   	// #4
    8020f6b8:	8b020021 	add	x1, x1, x2
    8020f6bc:	9a822021 	csel	x1, x1, x2, cs	// cs = hs, nlast
    8020f6c0:	b82168a4 	str	w4, [x5, x1]
    8020f6c4:	35000044 	cbnz	w4, 8020f6cc <__lshift+0xfc>
    8020f6c8:	2a1703f5 	mov	w21, w23
    8020f6cc:	f94036c1 	ldr	x1, [x22, #104]
    8020f6d0:	b9800a82 	ldrsw	x2, [x20, #8]
    8020f6d4:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020f6d8:	f8627823 	ldr	x3, [x1, x2, lsl #3]
    8020f6dc:	b9001415 	str	w21, [x0, #20]
    8020f6e0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020f6e4:	f9000283 	str	x3, [x20]
    8020f6e8:	f8227834 	str	x20, [x1, x2, lsl #3]
    8020f6ec:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f6f0:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020f6f4:	d65f03c0 	ret
    8020f6f8:	b8404461 	ldr	w1, [x3], #4
    8020f6fc:	b80044a1 	str	w1, [x5], #4
    8020f700:	eb0300df 	cmp	x6, x3
    8020f704:	54fffe29 	b.ls	8020f6c8 <__lshift+0xf8>  // b.plast
    8020f708:	b8404461 	ldr	w1, [x3], #4
    8020f70c:	b80044a1 	str	w1, [x5], #4
    8020f710:	eb0300df 	cmp	x6, x3
    8020f714:	54ffff28 	b.hi	8020f6f8 <__lshift+0x128>  // b.pmore
    8020f718:	17ffffec 	b	8020f6c8 <__lshift+0xf8>
    8020f71c:	b0000003 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020f720:	b0000000 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020f724:	9136e063 	add	x3, x3, #0xdb8
    8020f728:	9139c000 	add	x0, x0, #0xe70
    8020f72c:	d2800002 	mov	x2, #0x0                   	// #0
    8020f730:	52803bc1 	mov	w1, #0x1de                 	// #478
    8020f734:	97fffd53 	bl	8020ec80 <__assert_func>
	...

000000008020f740 <__mcmp>:
    8020f740:	b9401422 	ldr	w2, [x1, #20]
    8020f744:	aa0003e5 	mov	x5, x0
    8020f748:	b9401400 	ldr	w0, [x0, #20]
    8020f74c:	6b020000 	subs	w0, w0, w2
    8020f750:	540001e1 	b.ne	8020f78c <__mcmp+0x4c>  // b.any
    8020f754:	937e7c43 	sbfiz	x3, x2, #2, #32
    8020f758:	910060a5 	add	x5, x5, #0x18
    8020f75c:	91006021 	add	x1, x1, #0x18
    8020f760:	8b0300a2 	add	x2, x5, x3
    8020f764:	8b030021 	add	x1, x1, x3
    8020f768:	14000003 	b	8020f774 <__mcmp+0x34>
    8020f76c:	eb0200bf 	cmp	x5, x2
    8020f770:	540000e2 	b.cs	8020f78c <__mcmp+0x4c>  // b.hs, b.nlast
    8020f774:	b85fcc44 	ldr	w4, [x2, #-4]!
    8020f778:	b85fcc23 	ldr	w3, [x1, #-4]!
    8020f77c:	6b03009f 	cmp	w4, w3
    8020f780:	54ffff60 	b.eq	8020f76c <__mcmp+0x2c>  // b.none
    8020f784:	12800000 	mov	w0, #0xffffffff            	// #-1
    8020f788:	1a9f3400 	csinc	w0, w0, wzr, cc	// cc = lo, ul, last
    8020f78c:	d65f03c0 	ret

000000008020f790 <__mdiff>:
    8020f790:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    8020f794:	910003fd 	mov	x29, sp
    8020f798:	a90153f3 	stp	x19, x20, [sp, #16]
    8020f79c:	aa0103f3 	mov	x19, x1
    8020f7a0:	aa0203f4 	mov	x20, x2
    8020f7a4:	b9401421 	ldr	w1, [x1, #20]
    8020f7a8:	b9401442 	ldr	w2, [x2, #20]
    8020f7ac:	f90013f5 	str	x21, [sp, #32]
    8020f7b0:	6b020021 	subs	w1, w1, w2
    8020f7b4:	35000241 	cbnz	w1, 8020f7fc <__mdiff+0x6c>
    8020f7b8:	937e7c42 	sbfiz	x2, x2, #2, #32
    8020f7bc:	91006261 	add	x1, x19, #0x18
    8020f7c0:	91006284 	add	x4, x20, #0x18
    8020f7c4:	8b020023 	add	x3, x1, x2
    8020f7c8:	8b020084 	add	x4, x4, x2
    8020f7cc:	14000003 	b	8020f7d8 <__mdiff+0x48>
    8020f7d0:	eb03003f 	cmp	x1, x3
    8020f7d4:	54000a62 	b.cs	8020f920 <__mdiff+0x190>  // b.hs, b.nlast
    8020f7d8:	b85fcc66 	ldr	w6, [x3, #-4]!
    8020f7dc:	b85fcc85 	ldr	w5, [x4, #-4]!
    8020f7e0:	6b0500df 	cmp	w6, w5
    8020f7e4:	54ffff60 	b.eq	8020f7d0 <__mdiff+0x40>  // b.none
    8020f7e8:	aa1403e1 	mov	x1, x20
    8020f7ec:	1a9f27f5 	cset	w21, cc	// cc = lo, ul, last
    8020f7f0:	9a933294 	csel	x20, x20, x19, cc	// cc = lo, ul, last
    8020f7f4:	9a813273 	csel	x19, x19, x1, cc	// cc = lo, ul, last
    8020f7f8:	14000005 	b	8020f80c <__mdiff+0x7c>
    8020f7fc:	aa1403e1 	mov	x1, x20
    8020f800:	1a9f57f5 	cset	w21, mi	// mi = first
    8020f804:	9a934294 	csel	x20, x20, x19, mi	// mi = first
    8020f808:	9a814273 	csel	x19, x19, x1, mi	// mi = first
    8020f80c:	b9400a81 	ldr	w1, [x20, #8]
    8020f810:	97fffd78 	bl	8020edf0 <_Balloc>
    8020f814:	b4000b00 	cbz	x0, 8020f974 <__mdiff+0x1e4>
    8020f818:	b9801668 	ldrsw	x8, [x19, #20]
    8020f81c:	91006289 	add	x9, x20, #0x18
    8020f820:	b9401687 	ldr	w7, [x20, #20]
    8020f824:	91006262 	add	x2, x19, #0x18
    8020f828:	9100600b 	add	x11, x0, #0x18
    8020f82c:	d2800305 	mov	x5, #0x18                  	// #24
    8020f830:	8b080848 	add	x8, x2, x8, lsl #2
    8020f834:	52800001 	mov	w1, #0x0                   	// #0
    8020f838:	8b27c92a 	add	x10, x9, w7, sxtw #2
    8020f83c:	b9001015 	str	w21, [x0, #16]
    8020f840:	b8656a86 	ldr	w6, [x20, x5]
    8020f844:	b8656a64 	ldr	w4, [x19, x5]
    8020f848:	12003cc3 	and	w3, w6, #0xffff
    8020f84c:	53107cc6 	lsr	w6, w6, #16
    8020f850:	4b242063 	sub	w3, w3, w4, uxth
    8020f854:	4b4440c4 	sub	w4, w6, w4, lsr #16
    8020f858:	0b010063 	add	w3, w3, w1
    8020f85c:	0b834084 	add	w4, w4, w3, asr #16
    8020f860:	33103c83 	bfi	w3, w4, #16, #16
    8020f864:	b8256803 	str	w3, [x0, x5]
    8020f868:	910010a5 	add	x5, x5, #0x4
    8020f86c:	13107c81 	asr	w1, w4, #16
    8020f870:	8b050264 	add	x4, x19, x5
    8020f874:	eb04011f 	cmp	x8, x4
    8020f878:	54fffe48 	b.hi	8020f840 <__mdiff+0xb0>  // b.pmore
    8020f87c:	cb130104 	sub	x4, x8, x19
    8020f880:	91006662 	add	x2, x19, #0x19
    8020f884:	d1006484 	sub	x4, x4, #0x19
    8020f888:	eb02011f 	cmp	x8, x2
    8020f88c:	1a9f37e6 	cset	w6, cs	// cs = hs, nlast
    8020f890:	d2800088 	mov	x8, #0x4                   	// #4
    8020f894:	d342fc82 	lsr	x2, x4, #2
    8020f898:	710000df 	cmp	w6, #0x0
    8020f89c:	91000445 	add	x5, x2, #0x1
    8020f8a0:	d37ef4a5 	lsl	x5, x5, #2
    8020f8a4:	9a8810a5 	csel	x5, x5, x8, ne	// ne = any
    8020f8a8:	8b050128 	add	x8, x9, x5
    8020f8ac:	8b050165 	add	x5, x11, x5
    8020f8b0:	eb08015f 	cmp	x10, x8
    8020f8b4:	54000489 	b.ls	8020f944 <__mdiff+0x1b4>  // b.plast
    8020f8b8:	d100054a 	sub	x10, x10, #0x1
    8020f8bc:	d2800004 	mov	x4, #0x0                   	// #0
    8020f8c0:	cb08014a 	sub	x10, x10, x8
    8020f8c4:	d342fd49 	lsr	x9, x10, #2
    8020f8c8:	b8647902 	ldr	w2, [x8, x4, lsl #2]
    8020f8cc:	eb04013f 	cmp	x9, x4
    8020f8d0:	0b010043 	add	w3, w2, w1
    8020f8d4:	0b222021 	add	w1, w1, w2, uxth
    8020f8d8:	53107c42 	lsr	w2, w2, #16
    8020f8dc:	0b814041 	add	w1, w2, w1, asr #16
    8020f8e0:	33103c23 	bfi	w3, w1, #16, #16
    8020f8e4:	b82478a3 	str	w3, [x5, x4, lsl #2]
    8020f8e8:	13107c21 	asr	w1, w1, #16
    8020f8ec:	91000484 	add	x4, x4, #0x1
    8020f8f0:	54fffec1 	b.ne	8020f8c8 <__mdiff+0x138>  // b.any
    8020f8f4:	927ef54a 	and	x10, x10, #0xfffffffffffffffc
    8020f8f8:	8b0a00a1 	add	x1, x5, x10
    8020f8fc:	35000083 	cbnz	w3, 8020f90c <__mdiff+0x17c>
    8020f900:	b85fcc22 	ldr	w2, [x1, #-4]!
    8020f904:	510004e7 	sub	w7, w7, #0x1
    8020f908:	34ffffc2 	cbz	w2, 8020f900 <__mdiff+0x170>
    8020f90c:	b9001407 	str	w7, [x0, #20]
    8020f910:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f914:	f94013f5 	ldr	x21, [sp, #32]
    8020f918:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020f91c:	d65f03c0 	ret
    8020f920:	52800001 	mov	w1, #0x0                   	// #0
    8020f924:	97fffd33 	bl	8020edf0 <_Balloc>
    8020f928:	b4000180 	cbz	x0, 8020f958 <__mdiff+0x1c8>
    8020f92c:	d2800021 	mov	x1, #0x1                   	// #1
    8020f930:	f8014001 	stur	x1, [x0, #20]
    8020f934:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020f938:	f94013f5 	ldr	x21, [sp, #32]
    8020f93c:	a8c37bfd 	ldp	x29, x30, [sp], #48
    8020f940:	d65f03c0 	ret
    8020f944:	d37ef442 	lsl	x2, x2, #2
    8020f948:	710000df 	cmp	w6, #0x0
    8020f94c:	9a9f1042 	csel	x2, x2, xzr, ne	// ne = any
    8020f950:	8b020161 	add	x1, x11, x2
    8020f954:	17ffffea 	b	8020f8fc <__mdiff+0x16c>
    8020f958:	b0000003 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020f95c:	b0000000 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020f960:	9136e063 	add	x3, x3, #0xdb8
    8020f964:	9139c000 	add	x0, x0, #0xe70
    8020f968:	d2800002 	mov	x2, #0x0                   	// #0
    8020f96c:	528046e1 	mov	w1, #0x237                 	// #567
    8020f970:	97fffcc4 	bl	8020ec80 <__assert_func>
    8020f974:	b0000003 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020f978:	b0000000 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020f97c:	9136e063 	add	x3, x3, #0xdb8
    8020f980:	9139c000 	add	x0, x0, #0xe70
    8020f984:	d2800002 	mov	x2, #0x0                   	// #0
    8020f988:	528048a1 	mov	w1, #0x245                 	// #581
    8020f98c:	97fffcbd 	bl	8020ec80 <__assert_func>

000000008020f990 <__ulp>:
    8020f990:	9e660000 	fmov	x0, d0
    8020f994:	52bf9801 	mov	w1, #0xfcc00000            	// #-54525952
    8020f998:	d360fc00 	lsr	x0, x0, #32
    8020f99c:	120c2800 	and	w0, w0, #0x7ff00000
    8020f9a0:	0b010000 	add	w0, w0, w1
    8020f9a4:	52800001 	mov	w1, #0x0                   	// #0
    8020f9a8:	7100001f 	cmp	w0, #0x0
    8020f9ac:	540000ad 	b.le	8020f9c0 <__ulp+0x30>
    8020f9b0:	2a0103e1 	mov	w1, w1
    8020f9b4:	aa008020 	orr	x0, x1, x0, lsl #32
    8020f9b8:	9e670000 	fmov	d0, x0
    8020f9bc:	d65f03c0 	ret
    8020f9c0:	4b0003e0 	neg	w0, w0
    8020f9c4:	13147c00 	asr	w0, w0, #20
    8020f9c8:	71004c1f 	cmp	w0, #0x13
    8020f9cc:	5400010c 	b.gt	8020f9ec <__ulp+0x5c>
    8020f9d0:	52a00102 	mov	w2, #0x80000               	// #524288
    8020f9d4:	52800001 	mov	w1, #0x0                   	// #0
    8020f9d8:	1ac02840 	asr	w0, w2, w0
    8020f9dc:	2a0103e1 	mov	w1, w1
    8020f9e0:	aa008020 	orr	x0, x1, x0, lsl #32
    8020f9e4:	9e670000 	fmov	d0, x0
    8020f9e8:	d65f03c0 	ret
    8020f9ec:	51005002 	sub	w2, w0, #0x14
    8020f9f0:	52b00001 	mov	w1, #0x80000000            	// #-2147483648
    8020f9f4:	71007c5f 	cmp	w2, #0x1f
    8020f9f8:	52800000 	mov	w0, #0x0                   	// #0
    8020f9fc:	1ac22421 	lsr	w1, w1, w2
    8020fa00:	1a9fb421 	csinc	w1, w1, wzr, lt	// lt = tstop
    8020fa04:	2a0103e1 	mov	w1, w1
    8020fa08:	aa008020 	orr	x0, x1, x0, lsl #32
    8020fa0c:	9e670000 	fmov	d0, x0
    8020fa10:	d65f03c0 	ret
	...

000000008020fa20 <__b2d>:
    8020fa20:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    8020fa24:	91006006 	add	x6, x0, #0x18
    8020fa28:	aa0103e5 	mov	x5, x1
    8020fa2c:	910003fd 	mov	x29, sp
    8020fa30:	b9801404 	ldrsw	x4, [x0, #20]
    8020fa34:	8b0408c4 	add	x4, x6, x4, lsl #2
    8020fa38:	d1001087 	sub	x7, x4, #0x4
    8020fa3c:	b85fc083 	ldur	w3, [x4, #-4]
    8020fa40:	2a0303e0 	mov	w0, w3
    8020fa44:	97fffda7 	bl	8020f0e0 <__hi0bits>
    8020fa48:	52800401 	mov	w1, #0x20                  	// #32
    8020fa4c:	4b000022 	sub	w2, w1, w0
    8020fa50:	b90000a2 	str	w2, [x5]
    8020fa54:	7100281f 	cmp	w0, #0xa
    8020fa58:	5400056d 	b.le	8020fb04 <__b2d+0xe4>
    8020fa5c:	51002c05 	sub	w5, w0, #0xb
    8020fa60:	eb0700df 	cmp	x6, x7
    8020fa64:	540002a2 	b.cs	8020fab8 <__b2d+0x98>  // b.hs, b.nlast
    8020fa68:	b85f8080 	ldur	w0, [x4, #-8]
    8020fa6c:	340003e5 	cbz	w5, 8020fae8 <__b2d+0xc8>
    8020fa70:	4b050022 	sub	w2, w1, w5
    8020fa74:	1ac52063 	lsl	w3, w3, w5
    8020fa78:	d2800001 	mov	x1, #0x0                   	// #0
    8020fa7c:	d1002087 	sub	x7, x4, #0x8
    8020fa80:	1ac22408 	lsr	w8, w0, w2
    8020fa84:	2a080063 	orr	w3, w3, w8
    8020fa88:	320c2463 	orr	w3, w3, #0x3ff00000
    8020fa8c:	1ac52000 	lsl	w0, w0, w5
    8020fa90:	b3607c61 	bfi	x1, x3, #32, #32
    8020fa94:	eb0700df 	cmp	x6, x7
    8020fa98:	540002e2 	b.cs	8020faf4 <__b2d+0xd4>  // b.hs, b.nlast
    8020fa9c:	b85f4083 	ldur	w3, [x4, #-12]
    8020faa0:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020faa4:	1ac22462 	lsr	w2, w3, w2
    8020faa8:	2a020000 	orr	w0, w0, w2
    8020faac:	b3407c01 	bfxil	x1, x0, #0, #32
    8020fab0:	9e670020 	fmov	d0, x1
    8020fab4:	d65f03c0 	ret
    8020fab8:	71002c1f 	cmp	w0, #0xb
    8020fabc:	54000140 	b.eq	8020fae4 <__b2d+0xc4>  // b.none
    8020fac0:	1ac52063 	lsl	w3, w3, w5
    8020fac4:	320c2463 	orr	w3, w3, #0x3ff00000
    8020fac8:	d2800001 	mov	x1, #0x0                   	// #0
    8020facc:	52800000 	mov	w0, #0x0                   	// #0
    8020fad0:	b3607c61 	bfi	x1, x3, #32, #32
    8020fad4:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020fad8:	b3407c01 	bfxil	x1, x0, #0, #32
    8020fadc:	9e670020 	fmov	d0, x1
    8020fae0:	d65f03c0 	ret
    8020fae4:	52800000 	mov	w0, #0x0                   	// #0
    8020fae8:	320c2463 	orr	w3, w3, #0x3ff00000
    8020faec:	d2800001 	mov	x1, #0x0                   	// #0
    8020faf0:	b3607c61 	bfi	x1, x3, #32, #32
    8020faf4:	b3407c01 	bfxil	x1, x0, #0, #32
    8020faf8:	9e670020 	fmov	d0, x1
    8020fafc:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020fb00:	d65f03c0 	ret
    8020fb04:	52800165 	mov	w5, #0xb                   	// #11
    8020fb08:	4b0000a5 	sub	w5, w5, w0
    8020fb0c:	d2800001 	mov	x1, #0x0                   	// #0
    8020fb10:	52800002 	mov	w2, #0x0                   	// #0
    8020fb14:	1ac52468 	lsr	w8, w3, w5
    8020fb18:	320c2508 	orr	w8, w8, #0x3ff00000
    8020fb1c:	b3607d01 	bfi	x1, x8, #32, #32
    8020fb20:	eb0700df 	cmp	x6, x7
    8020fb24:	54000062 	b.cs	8020fb30 <__b2d+0x110>  // b.hs, b.nlast
    8020fb28:	b85f8082 	ldur	w2, [x4, #-8]
    8020fb2c:	1ac52442 	lsr	w2, w2, w5
    8020fb30:	11005400 	add	w0, w0, #0x15
    8020fb34:	a8c17bfd 	ldp	x29, x30, [sp], #16
    8020fb38:	1ac02063 	lsl	w3, w3, w0
    8020fb3c:	2a020060 	orr	w0, w3, w2
    8020fb40:	b3407c01 	bfxil	x1, x0, #0, #32
    8020fb44:	9e670020 	fmov	d0, x1
    8020fb48:	d65f03c0 	ret
    8020fb4c:	00000000 	udf	#0

000000008020fb50 <__d2b>:
    8020fb50:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
    8020fb54:	910003fd 	mov	x29, sp
    8020fb58:	fd0013e8 	str	d8, [sp, #32]
    8020fb5c:	1e604008 	fmov	d8, d0
    8020fb60:	a90153f3 	stp	x19, x20, [sp, #16]
    8020fb64:	aa0103f4 	mov	x20, x1
    8020fb68:	aa0203f3 	mov	x19, x2
    8020fb6c:	52800021 	mov	w1, #0x1                   	// #1
    8020fb70:	97fffca0 	bl	8020edf0 <_Balloc>
    8020fb74:	b40007e0 	cbz	x0, 8020fc70 <__d2b+0x120>
    8020fb78:	9e660103 	fmov	x3, d8
    8020fb7c:	aa0003e4 	mov	x4, x0
    8020fb80:	d374f865 	ubfx	x5, x3, #52, #11
    8020fb84:	d360cc60 	ubfx	x0, x3, #32, #20
    8020fb88:	320c0001 	orr	w1, w0, #0x100000
    8020fb8c:	710000bf 	cmp	w5, #0x0
    8020fb90:	1a801020 	csel	w0, w1, w0, ne	// ne = any
    8020fb94:	b9003fe0 	str	w0, [sp, #60]
    8020fb98:	35000283 	cbnz	w3, 8020fbe8 <__d2b+0x98>
    8020fb9c:	9100f3e0 	add	x0, sp, #0x3c
    8020fba0:	97fffd70 	bl	8020f160 <__lo0bits>
    8020fba4:	b9403fe1 	ldr	w1, [sp, #60]
    8020fba8:	52800023 	mov	w3, #0x1                   	// #1
    8020fbac:	b9001483 	str	w3, [x4, #20]
    8020fbb0:	11008000 	add	w0, w0, #0x20
    8020fbb4:	b9001881 	str	w1, [x4, #24]
    8020fbb8:	340003a5 	cbz	w5, 8020fc2c <__d2b+0xdc>
    8020fbbc:	5110cca5 	sub	w5, w5, #0x433
    8020fbc0:	fd4013e8 	ldr	d8, [sp, #32]
    8020fbc4:	0b0000a5 	add	w5, w5, w0
    8020fbc8:	b9000285 	str	w5, [x20]
    8020fbcc:	528006a3 	mov	w3, #0x35                  	// #53
    8020fbd0:	4b000063 	sub	w3, w3, w0
    8020fbd4:	b9000263 	str	w3, [x19]
    8020fbd8:	aa0403e0 	mov	x0, x4
    8020fbdc:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fbe0:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020fbe4:	d65f03c0 	ret
    8020fbe8:	9100e3e0 	add	x0, sp, #0x38
    8020fbec:	bd003be8 	str	s8, [sp, #56]
    8020fbf0:	97fffd5c 	bl	8020f160 <__lo0bits>
    8020fbf4:	b9403fe1 	ldr	w1, [sp, #60]
    8020fbf8:	34000380 	cbz	w0, 8020fc68 <__d2b+0x118>
    8020fbfc:	b9403be3 	ldr	w3, [sp, #56]
    8020fc00:	4b0003e2 	neg	w2, w0
    8020fc04:	1ac22022 	lsl	w2, w1, w2
    8020fc08:	2a030042 	orr	w2, w2, w3
    8020fc0c:	1ac02421 	lsr	w1, w1, w0
    8020fc10:	b9003fe1 	str	w1, [sp, #60]
    8020fc14:	7100003f 	cmp	w1, #0x0
    8020fc18:	29030482 	stp	w2, w1, [x4, #24]
    8020fc1c:	1a9f07e3 	cset	w3, ne	// ne = any
    8020fc20:	11000463 	add	w3, w3, #0x1
    8020fc24:	b9001483 	str	w3, [x4, #20]
    8020fc28:	35fffca5 	cbnz	w5, 8020fbbc <__d2b+0x6c>
    8020fc2c:	92800061 	mov	x1, #0xfffffffffffffffc    	// #-4
    8020fc30:	5110c800 	sub	w0, w0, #0x432
    8020fc34:	8b23c821 	add	x1, x1, w3, sxtw #2
    8020fc38:	b9000280 	str	w0, [x20]
    8020fc3c:	8b010080 	add	x0, x4, x1
    8020fc40:	531b6863 	lsl	w3, w3, #5
    8020fc44:	b9401800 	ldr	w0, [x0, #24]
    8020fc48:	97fffd26 	bl	8020f0e0 <__hi0bits>
    8020fc4c:	fd4013e8 	ldr	d8, [sp, #32]
    8020fc50:	4b000063 	sub	w3, w3, w0
    8020fc54:	b9000263 	str	w3, [x19]
    8020fc58:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020fc5c:	aa0403e0 	mov	x0, x4
    8020fc60:	a8c47bfd 	ldp	x29, x30, [sp], #64
    8020fc64:	d65f03c0 	ret
    8020fc68:	b9403be2 	ldr	w2, [sp, #56]
    8020fc6c:	17ffffea 	b	8020fc14 <__d2b+0xc4>
    8020fc70:	b0000003 	adrp	x3, 80210000 <_wcsnrtombs_l+0x110>
    8020fc74:	b0000000 	adrp	x0, 80210000 <_wcsnrtombs_l+0x110>
    8020fc78:	9136e063 	add	x3, x3, #0xdb8
    8020fc7c:	9139c000 	add	x0, x0, #0xe70
    8020fc80:	d2800002 	mov	x2, #0x0                   	// #0
    8020fc84:	528061e1 	mov	w1, #0x30f                 	// #783
    8020fc88:	97fffbfe 	bl	8020ec80 <__assert_func>
    8020fc8c:	00000000 	udf	#0

000000008020fc90 <__ratio>:
    8020fc90:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020fc94:	aa0103e9 	mov	x9, x1
    8020fc98:	aa0003ea 	mov	x10, x0
    8020fc9c:	910003fd 	mov	x29, sp
    8020fca0:	910063e1 	add	x1, sp, #0x18
    8020fca4:	97ffff5f 	bl	8020fa20 <__b2d>
    8020fca8:	910073e1 	add	x1, sp, #0x1c
    8020fcac:	aa0903e0 	mov	x0, x9
    8020fcb0:	1e604001 	fmov	d1, d0
    8020fcb4:	9e66000b 	fmov	x11, d0
    8020fcb8:	97ffff5a 	bl	8020fa20 <__b2d>
    8020fcbc:	b9401523 	ldr	w3, [x9, #20]
    8020fcc0:	b9401540 	ldr	w0, [x10, #20]
    8020fcc4:	29430be1 	ldp	w1, w2, [sp, #24]
    8020fcc8:	4b030000 	sub	w0, w0, w3
    8020fccc:	4b020021 	sub	w1, w1, w2
    8020fcd0:	0b001420 	add	w0, w1, w0, lsl #5
    8020fcd4:	7100001f 	cmp	w0, #0x0
    8020fcd8:	5400010d 	b.le	8020fcf8 <__ratio+0x68>
    8020fcdc:	d360fd61 	lsr	x1, x11, #32
    8020fce0:	0b005020 	add	w0, w1, w0, lsl #20
    8020fce4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fce8:	b3607c0b 	bfi	x11, x0, #32, #32
    8020fcec:	9e670161 	fmov	d1, x11
    8020fcf0:	1e601820 	fdiv	d0, d1, d0
    8020fcf4:	d65f03c0 	ret
    8020fcf8:	9e660001 	fmov	x1, d0
    8020fcfc:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fd00:	d360fc22 	lsr	x2, x1, #32
    8020fd04:	4b005040 	sub	w0, w2, w0, lsl #20
    8020fd08:	b3607c01 	bfi	x1, x0, #32, #32
    8020fd0c:	9e670020 	fmov	d0, x1
    8020fd10:	1e601820 	fdiv	d0, d1, d0
    8020fd14:	d65f03c0 	ret
	...

000000008020fd20 <_mprec_log10>:
    8020fd20:	1e6e1000 	fmov	d0, #1.000000000000000000e+00
    8020fd24:	1e649001 	fmov	d1, #1.000000000000000000e+01
    8020fd28:	71005c1f 	cmp	w0, #0x17
    8020fd2c:	540000ad 	b.le	8020fd40 <_mprec_log10+0x20>
    8020fd30:	1e610800 	fmul	d0, d0, d1
    8020fd34:	71000400 	subs	w0, w0, #0x1
    8020fd38:	54ffffc1 	b.ne	8020fd30 <_mprec_log10+0x10>  // b.any
    8020fd3c:	d65f03c0 	ret
    8020fd40:	d0000001 	adrp	x1, 80211000 <blanks.1+0x60>
    8020fd44:	91150021 	add	x1, x1, #0x540
    8020fd48:	fc60d820 	ldr	d0, [x1, w0, sxtw #3]
    8020fd4c:	d65f03c0 	ret

000000008020fd50 <__copybits>:
    8020fd50:	51000421 	sub	w1, w1, #0x1
    8020fd54:	91006046 	add	x6, x2, #0x18
    8020fd58:	13057c24 	asr	w4, w1, #5
    8020fd5c:	b9801441 	ldrsw	x1, [x2, #20]
    8020fd60:	11000484 	add	w4, w4, #0x1
    8020fd64:	8b0108c1 	add	x1, x6, x1, lsl #2
    8020fd68:	8b24c804 	add	x4, x0, w4, sxtw #2
    8020fd6c:	eb0100df 	cmp	x6, x1
    8020fd70:	540001e2 	b.cs	8020fdac <__copybits+0x5c>  // b.hs, b.nlast
    8020fd74:	cb020023 	sub	x3, x1, x2
    8020fd78:	d2800001 	mov	x1, #0x0                   	// #0
    8020fd7c:	d1006463 	sub	x3, x3, #0x19
    8020fd80:	d342fc63 	lsr	x3, x3, #2
    8020fd84:	91000467 	add	x7, x3, #0x1
    8020fd88:	b86178c5 	ldr	w5, [x6, x1, lsl #2]
    8020fd8c:	eb03003f 	cmp	x1, x3
    8020fd90:	b8217805 	str	w5, [x0, x1, lsl #2]
    8020fd94:	91000421 	add	x1, x1, #0x1
    8020fd98:	54ffff81 	b.ne	8020fd88 <__copybits+0x38>  // b.any
    8020fd9c:	8b070800 	add	x0, x0, x7, lsl #2
    8020fda0:	eb00009f 	cmp	x4, x0
    8020fda4:	54000089 	b.ls	8020fdb4 <__copybits+0x64>  // b.plast
    8020fda8:	b800441f 	str	wzr, [x0], #4
    8020fdac:	eb00009f 	cmp	x4, x0
    8020fdb0:	54ffffc8 	b.hi	8020fda8 <__copybits+0x58>  // b.pmore
    8020fdb4:	d65f03c0 	ret
	...

000000008020fdc0 <__any_on>:
    8020fdc0:	91006003 	add	x3, x0, #0x18
    8020fdc4:	b9401400 	ldr	w0, [x0, #20]
    8020fdc8:	13057c22 	asr	w2, w1, #5
    8020fdcc:	6b02001f 	cmp	w0, w2
    8020fdd0:	5400012a 	b.ge	8020fdf4 <__any_on+0x34>  // b.tcont
    8020fdd4:	8b20c862 	add	x2, x3, w0, sxtw #2
    8020fdd8:	14000003 	b	8020fde4 <__any_on+0x24>
    8020fddc:	b85fcc40 	ldr	w0, [x2, #-4]!
    8020fde0:	35000220 	cbnz	w0, 8020fe24 <__any_on+0x64>
    8020fde4:	eb03005f 	cmp	x2, x3
    8020fde8:	54ffffa8 	b.hi	8020fddc <__any_on+0x1c>  // b.pmore
    8020fdec:	52800000 	mov	w0, #0x0                   	// #0
    8020fdf0:	d65f03c0 	ret
    8020fdf4:	93407c40 	sxtw	x0, w2
    8020fdf8:	8b22c862 	add	x2, x3, w2, sxtw #2
    8020fdfc:	54ffff4d 	b.le	8020fde4 <__any_on+0x24>
    8020fe00:	72001021 	ands	w1, w1, #0x1f
    8020fe04:	54ffff00 	b.eq	8020fde4 <__any_on+0x24>  // b.none
    8020fe08:	b8607865 	ldr	w5, [x3, x0, lsl #2]
    8020fe0c:	52800020 	mov	w0, #0x1                   	// #1
    8020fe10:	1ac124a4 	lsr	w4, w5, w1
    8020fe14:	1ac12081 	lsl	w1, w4, w1
    8020fe18:	6b0100bf 	cmp	w5, w1
    8020fe1c:	54fffe40 	b.eq	8020fde4 <__any_on+0x24>  // b.none
    8020fe20:	d65f03c0 	ret
    8020fe24:	52800020 	mov	w0, #0x1                   	// #1
    8020fe28:	d65f03c0 	ret
    8020fe2c:	00000000 	udf	#0

000000008020fe30 <_calloc_r>:
    8020fe30:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    8020fe34:	9bc27c23 	umulh	x3, x1, x2
    8020fe38:	9b027c21 	mul	x1, x1, x2
    8020fe3c:	910003fd 	mov	x29, sp
    8020fe40:	f9000bf3 	str	x19, [sp, #16]
    8020fe44:	b5000463 	cbnz	x3, 8020fed0 <_calloc_r+0xa0>
    8020fe48:	97ffe4fe 	bl	80209240 <_malloc_r>
    8020fe4c:	aa0003f3 	mov	x19, x0
    8020fe50:	b4000460 	cbz	x0, 8020fedc <_calloc_r+0xac>
    8020fe54:	f85f8002 	ldur	x2, [x0, #-8]
    8020fe58:	927ef442 	and	x2, x2, #0xfffffffffffffffc
    8020fe5c:	d1002042 	sub	x2, x2, #0x8
    8020fe60:	f101205f 	cmp	x2, #0x48
    8020fe64:	540001c8 	b.hi	8020fe9c <_calloc_r+0x6c>  // b.pmore
    8020fe68:	f1009c5f 	cmp	x2, #0x27
    8020fe6c:	540000c9 	b.ls	8020fe84 <_calloc_r+0x54>  // b.plast
    8020fe70:	4f000400 	movi	v0.4s, #0x0
    8020fe74:	91004000 	add	x0, x0, #0x10
    8020fe78:	3c9f0000 	stur	q0, [x0, #-16]
    8020fe7c:	f100dc5f 	cmp	x2, #0x37
    8020fe80:	540001a8 	b.hi	8020feb4 <_calloc_r+0x84>  // b.pmore
    8020fe84:	a9007c1f 	stp	xzr, xzr, [x0]
    8020fe88:	f900081f 	str	xzr, [x0, #16]
    8020fe8c:	aa1303e0 	mov	x0, x19
    8020fe90:	f9400bf3 	ldr	x19, [sp, #16]
    8020fe94:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020fe98:	d65f03c0 	ret
    8020fe9c:	52800001 	mov	w1, #0x0                   	// #0
    8020fea0:	97ffce08 	bl	802036c0 <memset>
    8020fea4:	aa1303e0 	mov	x0, x19
    8020fea8:	f9400bf3 	ldr	x19, [sp, #16]
    8020feac:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020feb0:	d65f03c0 	ret
    8020feb4:	3d800660 	str	q0, [x19, #16]
    8020feb8:	91008260 	add	x0, x19, #0x20
    8020febc:	f101205f 	cmp	x2, #0x48
    8020fec0:	54fffe21 	b.ne	8020fe84 <_calloc_r+0x54>  // b.any
    8020fec4:	9100c260 	add	x0, x19, #0x30
    8020fec8:	3d800a60 	str	q0, [x19, #32]
    8020fecc:	17ffffee 	b	8020fe84 <_calloc_r+0x54>
    8020fed0:	97ffcc4c 	bl	80203000 <__errno>
    8020fed4:	52800181 	mov	w1, #0xc                   	// #12
    8020fed8:	b9000001 	str	w1, [x0]
    8020fedc:	d2800013 	mov	x19, #0x0                   	// #0
    8020fee0:	aa1303e0 	mov	x0, x19
    8020fee4:	f9400bf3 	ldr	x19, [sp, #16]
    8020fee8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8020feec:	d65f03c0 	ret

000000008020fef0 <_wcsnrtombs_l>:
    8020fef0:	a9b87bfd 	stp	x29, x30, [sp, #-128]!
    8020fef4:	f10000bf 	cmp	x5, #0x0
    8020fef8:	910003fd 	mov	x29, sp
    8020fefc:	a90153f3 	stp	x19, x20, [sp, #16]
    8020ff00:	aa0003f4 	mov	x20, x0
    8020ff04:	91051000 	add	x0, x0, #0x144
    8020ff08:	a9025bf5 	stp	x21, x22, [sp, #32]
    8020ff0c:	aa0203f6 	mov	x22, x2
    8020ff10:	aa0103f5 	mov	x21, x1
    8020ff14:	a90363f7 	stp	x23, x24, [sp, #48]
    8020ff18:	aa0603f7 	mov	x23, x6
    8020ff1c:	a9046bf9 	stp	x25, x26, [sp, #64]
    8020ff20:	9a850019 	csel	x25, x0, x5, eq	// eq = none
    8020ff24:	a90573fb 	stp	x27, x28, [sp, #80]
    8020ff28:	f940005c 	ldr	x28, [x2]
    8020ff2c:	b4000901 	cbz	x1, 8021004c <_wcsnrtombs_l+0x15c>
    8020ff30:	aa0403f3 	mov	x19, x4
    8020ff34:	b4000a84 	cbz	x4, 80210084 <_wcsnrtombs_l+0x194>
    8020ff38:	d100047a 	sub	x26, x3, #0x1
    8020ff3c:	b4000a43 	cbz	x3, 80210084 <_wcsnrtombs_l+0x194>
    8020ff40:	d280001b 	mov	x27, #0x0                   	// #0
    8020ff44:	f90037f5 	str	x21, [sp, #104]
    8020ff48:	1400000a 	b	8020ff70 <_wcsnrtombs_l+0x80>
    8020ff4c:	b50003f5 	cbnz	x21, 8020ffc8 <_wcsnrtombs_l+0xd8>
    8020ff50:	b8404780 	ldr	w0, [x28], #4
    8020ff54:	34000640 	cbz	w0, 8021001c <_wcsnrtombs_l+0x12c>
    8020ff58:	eb13009f 	cmp	x4, x19
    8020ff5c:	54000982 	b.cs	8021008c <_wcsnrtombs_l+0x19c>  // b.hs, b.nlast
    8020ff60:	d100075a 	sub	x26, x26, #0x1
    8020ff64:	aa0403fb 	mov	x27, x4
    8020ff68:	b100075f 	cmn	x26, #0x1
    8020ff6c:	540001e0 	b.eq	8020ffa8 <_wcsnrtombs_l+0xb8>  // b.none
    8020ff70:	f94072e4 	ldr	x4, [x23, #224]
    8020ff74:	aa1903e3 	mov	x3, x25
    8020ff78:	b9400382 	ldr	w2, [x28]
    8020ff7c:	9101c3e1 	add	x1, sp, #0x70
    8020ff80:	f9400338 	ldr	x24, [x25]
    8020ff84:	aa1403e0 	mov	x0, x20
    8020ff88:	d63f0080 	blr	x4
    8020ff8c:	3100041f 	cmn	w0, #0x1
    8020ff90:	54000620 	b.eq	80210054 <_wcsnrtombs_l+0x164>  // b.none
    8020ff94:	93407c01 	sxtw	x1, w0
    8020ff98:	8b1b0024 	add	x4, x1, x27
    8020ff9c:	eb13009f 	cmp	x4, x19
    8020ffa0:	54fffd69 	b.ls	8020ff4c <_wcsnrtombs_l+0x5c>  // b.plast
    8020ffa4:	f9000338 	str	x24, [x25]
    8020ffa8:	a94153f3 	ldp	x19, x20, [sp, #16]
    8020ffac:	aa1b03e0 	mov	x0, x27
    8020ffb0:	a9425bf5 	ldp	x21, x22, [sp, #32]
    8020ffb4:	a94363f7 	ldp	x23, x24, [sp, #48]
    8020ffb8:	a9446bf9 	ldp	x25, x26, [sp, #64]
    8020ffbc:	a94573fb 	ldp	x27, x28, [sp, #80]
    8020ffc0:	a8c87bfd 	ldp	x29, x30, [sp], #128
    8020ffc4:	d65f03c0 	ret
    8020ffc8:	7100001f 	cmp	w0, #0x0
    8020ffcc:	540001ed 	b.le	80210008 <_wcsnrtombs_l+0x118>
    8020ffd0:	f94037e2 	ldr	x2, [sp, #104]
    8020ffd4:	d2800027 	mov	x7, #0x1                   	// #1
    8020ffd8:	d1000443 	sub	x3, x2, #0x1
    8020ffdc:	d503201f 	nop
    8020ffe0:	9101c3e2 	add	x2, sp, #0x70
    8020ffe4:	eb07003f 	cmp	x1, x7
    8020ffe8:	8b070042 	add	x2, x2, x7
    8020ffec:	385ff042 	ldurb	w2, [x2, #-1]
    8020fff0:	38276862 	strb	w2, [x3, x7]
    8020fff4:	910004e7 	add	x7, x7, #0x1
    8020fff8:	54ffff41 	b.ne	8020ffe0 <_wcsnrtombs_l+0xf0>  // b.any
    8020fffc:	f94037e1 	ldr	x1, [sp, #104]
    80210000:	8b204020 	add	x0, x1, w0, uxtw
    80210004:	f90037e0 	str	x0, [sp, #104]
    80210008:	f94002c0 	ldr	x0, [x22]
    8021000c:	91001000 	add	x0, x0, #0x4
    80210010:	f90002c0 	str	x0, [x22]
    80210014:	b8404780 	ldr	w0, [x28], #4
    80210018:	35fffa00 	cbnz	w0, 8020ff58 <_wcsnrtombs_l+0x68>
    8021001c:	b4000055 	cbz	x21, 80210024 <_wcsnrtombs_l+0x134>
    80210020:	f90002df 	str	xzr, [x22]
    80210024:	b900033f 	str	wzr, [x25]
    80210028:	d100049b 	sub	x27, x4, #0x1
    8021002c:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210030:	aa1b03e0 	mov	x0, x27
    80210034:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80210038:	a94363f7 	ldp	x23, x24, [sp, #48]
    8021003c:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80210040:	a94573fb 	ldp	x27, x28, [sp, #80]
    80210044:	a8c87bfd 	ldp	x29, x30, [sp], #128
    80210048:	d65f03c0 	ret
    8021004c:	92800013 	mov	x19, #0xffffffffffffffff    	// #-1
    80210050:	17ffffba 	b	8020ff38 <_wcsnrtombs_l+0x48>
    80210054:	52801140 	mov	w0, #0x8a                  	// #138
    80210058:	b9000280 	str	w0, [x20]
    8021005c:	b900033f 	str	wzr, [x25]
    80210060:	9280001b 	mov	x27, #0xffffffffffffffff    	// #-1
    80210064:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210068:	aa1b03e0 	mov	x0, x27
    8021006c:	a9425bf5 	ldp	x21, x22, [sp, #32]
    80210070:	a94363f7 	ldp	x23, x24, [sp, #48]
    80210074:	a9446bf9 	ldp	x25, x26, [sp, #64]
    80210078:	a94573fb 	ldp	x27, x28, [sp, #80]
    8021007c:	a8c87bfd 	ldp	x29, x30, [sp], #128
    80210080:	d65f03c0 	ret
    80210084:	d280001b 	mov	x27, #0x0                   	// #0
    80210088:	17ffffc8 	b	8020ffa8 <_wcsnrtombs_l+0xb8>
    8021008c:	aa0403fb 	mov	x27, x4
    80210090:	17ffffc6 	b	8020ffa8 <_wcsnrtombs_l+0xb8>
	...

00000000802100a0 <_wcsnrtombs_r>:
    802100a0:	b0000000 	adrp	x0, 80211000 <blanks.1+0x60>
    802100a4:	d0000006 	adrp	x6, 80212000 <__malloc_av_+0x760>
    802100a8:	910680c6 	add	x6, x6, #0x1a0
    802100ac:	f9438800 	ldr	x0, [x0, #1808]
    802100b0:	17ffff90 	b	8020fef0 <_wcsnrtombs_l>
	...

00000000802100c0 <wcsnrtombs>:
    802100c0:	b0000006 	adrp	x6, 80211000 <blanks.1+0x60>
    802100c4:	aa0003e8 	mov	x8, x0
    802100c8:	aa0103e7 	mov	x7, x1
    802100cc:	aa0203e5 	mov	x5, x2
    802100d0:	f94388c0 	ldr	x0, [x6, #1808]
    802100d4:	aa0303e6 	mov	x6, x3
    802100d8:	aa0803e1 	mov	x1, x8
    802100dc:	aa0503e3 	mov	x3, x5
    802100e0:	aa0703e2 	mov	x2, x7
    802100e4:	aa0403e5 	mov	x5, x4
    802100e8:	aa0603e4 	mov	x4, x6
    802100ec:	d0000006 	adrp	x6, 80212000 <__malloc_av_+0x760>
    802100f0:	910680c6 	add	x6, x6, #0x1a0
    802100f4:	17ffff7f 	b	8020fef0 <_wcsnrtombs_l>
	...

0000000080210100 <__env_lock>:
    80210100:	b0000380 	adrp	x0, 80281000 <__sf+0x38>
    80210104:	91094000 	add	x0, x0, #0x250
    80210108:	17ffe6ae 	b	80209bc0 <__retarget_lock_acquire_recursive>
    8021010c:	00000000 	udf	#0

0000000080210110 <__env_unlock>:
    80210110:	b0000380 	adrp	x0, 80281000 <__sf+0x38>
    80210114:	91094000 	add	x0, x0, #0x250
    80210118:	17ffe6ba 	b	80209c00 <__retarget_lock_release_recursive>
    8021011c:	00000000 	udf	#0

0000000080210120 <_fiprintf_r>:
    80210120:	a9b07bfd 	stp	x29, x30, [sp, #-256]!
    80210124:	128004e9 	mov	w9, #0xffffffd8            	// #-40
    80210128:	12800fe8 	mov	w8, #0xffffff80            	// #-128
    8021012c:	910003fd 	mov	x29, sp
    80210130:	910343ea 	add	x10, sp, #0xd0
    80210134:	910403eb 	add	x11, sp, #0x100
    80210138:	a9032feb 	stp	x11, x11, [sp, #48]
    8021013c:	f90023ea 	str	x10, [sp, #64]
    80210140:	290923e9 	stp	w9, w8, [sp, #72]
    80210144:	3d8017e0 	str	q0, [sp, #80]
    80210148:	ad41c3e0 	ldp	q0, q16, [sp, #48]
    8021014c:	3d801be1 	str	q1, [sp, #96]
    80210150:	3d801fe2 	str	q2, [sp, #112]
    80210154:	ad00c3e0 	stp	q0, q16, [sp, #16]
    80210158:	3d8023e3 	str	q3, [sp, #128]
    8021015c:	3d8027e4 	str	q4, [sp, #144]
    80210160:	3d802be5 	str	q5, [sp, #160]
    80210164:	3d802fe6 	str	q6, [sp, #176]
    80210168:	3d8033e7 	str	q7, [sp, #192]
    8021016c:	a90d93e3 	stp	x3, x4, [sp, #216]
    80210170:	910043e3 	add	x3, sp, #0x10
    80210174:	a90e9be5 	stp	x5, x6, [sp, #232]
    80210178:	f9007fe7 	str	x7, [sp, #248]
    8021017c:	97ffdce5 	bl	80207510 <_vfiprintf_r>
    80210180:	a8d07bfd 	ldp	x29, x30, [sp], #256
    80210184:	d65f03c0 	ret
	...

0000000080210190 <fiprintf>:
    80210190:	a9b07bfd 	stp	x29, x30, [sp, #-256]!
    80210194:	128005eb 	mov	w11, #0xffffffd0            	// #-48
    80210198:	12800fea 	mov	w10, #0xffffff80            	// #-128
    8021019c:	910003fd 	mov	x29, sp
    802101a0:	910403ec 	add	x12, sp, #0x100
    802101a4:	910343e8 	add	x8, sp, #0xd0
    802101a8:	b0000009 	adrp	x9, 80211000 <blanks.1+0x60>
    802101ac:	a90333ec 	stp	x12, x12, [sp, #48]
    802101b0:	f90023e8 	str	x8, [sp, #64]
    802101b4:	aa0103e8 	mov	x8, x1
    802101b8:	29092beb 	stp	w11, w10, [sp, #72]
    802101bc:	aa0003e1 	mov	x1, x0
    802101c0:	f9438920 	ldr	x0, [x9, #1808]
    802101c4:	3d8017e0 	str	q0, [sp, #80]
    802101c8:	ad41c3e0 	ldp	q0, q16, [sp, #48]
    802101cc:	3d801be1 	str	q1, [sp, #96]
    802101d0:	3d801fe2 	str	q2, [sp, #112]
    802101d4:	ad00c3e0 	stp	q0, q16, [sp, #16]
    802101d8:	3d8023e3 	str	q3, [sp, #128]
    802101dc:	3d8027e4 	str	q4, [sp, #144]
    802101e0:	3d802be5 	str	q5, [sp, #160]
    802101e4:	3d802fe6 	str	q6, [sp, #176]
    802101e8:	3d8033e7 	str	q7, [sp, #192]
    802101ec:	a90d0fe2 	stp	x2, x3, [sp, #208]
    802101f0:	910043e3 	add	x3, sp, #0x10
    802101f4:	aa0803e2 	mov	x2, x8
    802101f8:	a90e17e4 	stp	x4, x5, [sp, #224]
    802101fc:	a90f1fe6 	stp	x6, x7, [sp, #240]
    80210200:	97ffdcc4 	bl	80207510 <_vfiprintf_r>
    80210204:	a8d07bfd 	ldp	x29, x30, [sp], #256
    80210208:	d65f03c0 	ret
    8021020c:	00000000 	udf	#0

0000000080210210 <abort>:
    80210210:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
    80210214:	528000c0 	mov	w0, #0x6                   	// #6
    80210218:	910003fd 	mov	x29, sp
    8021021c:	94000099 	bl	80210480 <raise>
    80210220:	52800020 	mov	w0, #0x1                   	// #1
    80210224:	97ffc1e7 	bl	802009c0 <_exit>
	...

0000000080210230 <_init_signal_r>:
    80210230:	f940a801 	ldr	x1, [x0, #336]
    80210234:	b4000061 	cbz	x1, 80210240 <_init_signal_r+0x10>
    80210238:	52800000 	mov	w0, #0x0                   	// #0
    8021023c:	d65f03c0 	ret
    80210240:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80210244:	d2802001 	mov	x1, #0x100                 	// #256
    80210248:	910003fd 	mov	x29, sp
    8021024c:	f9000bf3 	str	x19, [sp, #16]
    80210250:	aa0003f3 	mov	x19, x0
    80210254:	97ffe3fb 	bl	80209240 <_malloc_r>
    80210258:	f900aa60 	str	x0, [x19, #336]
    8021025c:	b4000140 	cbz	x0, 80210284 <_init_signal_r+0x54>
    80210260:	91040001 	add	x1, x0, #0x100
    80210264:	d503201f 	nop
    80210268:	f800841f 	str	xzr, [x0], #8
    8021026c:	eb01001f 	cmp	x0, x1
    80210270:	54ffffc1 	b.ne	80210268 <_init_signal_r+0x38>  // b.any
    80210274:	52800000 	mov	w0, #0x0                   	// #0
    80210278:	f9400bf3 	ldr	x19, [sp, #16]
    8021027c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210280:	d65f03c0 	ret
    80210284:	12800000 	mov	w0, #0xffffffff            	// #-1
    80210288:	17fffffc 	b	80210278 <_init_signal_r+0x48>
    8021028c:	00000000 	udf	#0

0000000080210290 <_signal_r>:
    80210290:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80210294:	910003fd 	mov	x29, sp
    80210298:	a90153f3 	stp	x19, x20, [sp, #16]
    8021029c:	93407c33 	sxtw	x19, w1
    802102a0:	aa0003f4 	mov	x20, x0
    802102a4:	71007e7f 	cmp	w19, #0x1f
    802102a8:	54000108 	b.hi	802102c8 <_signal_r+0x38>  // b.pmore
    802102ac:	f940a801 	ldr	x1, [x0, #336]
    802102b0:	b4000141 	cbz	x1, 802102d8 <_signal_r+0x48>
    802102b4:	f8737820 	ldr	x0, [x1, x19, lsl #3]
    802102b8:	f8337822 	str	x2, [x1, x19, lsl #3]
    802102bc:	a94153f3 	ldp	x19, x20, [sp, #16]
    802102c0:	a8c37bfd 	ldp	x29, x30, [sp], #48
    802102c4:	d65f03c0 	ret
    802102c8:	528002c0 	mov	w0, #0x16                  	// #22
    802102cc:	b9000280 	str	w0, [x20]
    802102d0:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    802102d4:	17fffffa 	b	802102bc <_signal_r+0x2c>
    802102d8:	d2802001 	mov	x1, #0x100                 	// #256
    802102dc:	f90017e2 	str	x2, [sp, #40]
    802102e0:	97ffe3d8 	bl	80209240 <_malloc_r>
    802102e4:	f900aa80 	str	x0, [x20, #336]
    802102e8:	f94017e2 	ldr	x2, [sp, #40]
    802102ec:	aa0003e1 	mov	x1, x0
    802102f0:	b4ffff00 	cbz	x0, 802102d0 <_signal_r+0x40>
    802102f4:	91040003 	add	x3, x0, #0x100
    802102f8:	f800841f 	str	xzr, [x0], #8
    802102fc:	eb03001f 	cmp	x0, x3
    80210300:	54ffffc1 	b.ne	802102f8 <_signal_r+0x68>  // b.any
    80210304:	17ffffec 	b	802102b4 <_signal_r+0x24>
	...

0000000080210310 <_raise_r>:
    80210310:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80210314:	910003fd 	mov	x29, sp
    80210318:	a90153f3 	stp	x19, x20, [sp, #16]
    8021031c:	aa0003f4 	mov	x20, x0
    80210320:	71007c3f 	cmp	w1, #0x1f
    80210324:	54000408 	b.hi	802103a4 <_raise_r+0x94>  // b.pmore
    80210328:	f940a800 	ldr	x0, [x0, #336]
    8021032c:	2a0103f3 	mov	w19, w1
    80210330:	b40001e0 	cbz	x0, 8021036c <_raise_r+0x5c>
    80210334:	93407c22 	sxtw	x2, w1
    80210338:	f8627801 	ldr	x1, [x0, x2, lsl #3]
    8021033c:	b4000181 	cbz	x1, 8021036c <_raise_r+0x5c>
    80210340:	f100043f 	cmp	x1, #0x1
    80210344:	540000c0 	b.eq	8021035c <_raise_r+0x4c>  // b.none
    80210348:	b100043f 	cmn	x1, #0x1
    8021034c:	54000200 	b.eq	8021038c <_raise_r+0x7c>  // b.none
    80210350:	f822781f 	str	xzr, [x0, x2, lsl #3]
    80210354:	2a1303e0 	mov	w0, w19
    80210358:	d63f0020 	blr	x1
    8021035c:	52800000 	mov	w0, #0x0                   	// #0
    80210360:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210364:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210368:	d65f03c0 	ret
    8021036c:	aa1403e0 	mov	x0, x20
    80210370:	940000f0 	bl	80210730 <_getpid_r>
    80210374:	2a1303e2 	mov	w2, w19
    80210378:	2a0003e1 	mov	w1, w0
    8021037c:	aa1403e0 	mov	x0, x20
    80210380:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210384:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210388:	140000d6 	b	802106e0 <_kill_r>
    8021038c:	528002c1 	mov	w1, #0x16                  	// #22
    80210390:	b9000281 	str	w1, [x20]
    80210394:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210398:	52800020 	mov	w0, #0x1                   	// #1
    8021039c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802103a0:	d65f03c0 	ret
    802103a4:	528002c1 	mov	w1, #0x16                  	// #22
    802103a8:	12800000 	mov	w0, #0xffffffff            	// #-1
    802103ac:	b9000281 	str	w1, [x20]
    802103b0:	17ffffec 	b	80210360 <_raise_r+0x50>
	...

00000000802103c0 <__sigtramp_r>:
    802103c0:	71007c3f 	cmp	w1, #0x1f
    802103c4:	540005a8 	b.hi	80210478 <__sigtramp_r+0xb8>  // b.pmore
    802103c8:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    802103cc:	910003fd 	mov	x29, sp
    802103d0:	a90153f3 	stp	x19, x20, [sp, #16]
    802103d4:	2a0103f3 	mov	w19, w1
    802103d8:	aa0003f4 	mov	x20, x0
    802103dc:	f940a801 	ldr	x1, [x0, #336]
    802103e0:	b4000321 	cbz	x1, 80210444 <__sigtramp_r+0x84>
    802103e4:	f873d822 	ldr	x2, [x1, w19, sxtw #3]
    802103e8:	8b33cc21 	add	x1, x1, w19, sxtw #3
    802103ec:	b4000182 	cbz	x2, 8021041c <__sigtramp_r+0x5c>
    802103f0:	b100045f 	cmn	x2, #0x1
    802103f4:	54000240 	b.eq	8021043c <__sigtramp_r+0x7c>  // b.none
    802103f8:	f100045f 	cmp	x2, #0x1
    802103fc:	54000180 	b.eq	8021042c <__sigtramp_r+0x6c>  // b.none
    80210400:	f900003f 	str	xzr, [x1]
    80210404:	2a1303e0 	mov	w0, w19
    80210408:	d63f0040 	blr	x2
    8021040c:	52800000 	mov	w0, #0x0                   	// #0
    80210410:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210414:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210418:	d65f03c0 	ret
    8021041c:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210420:	52800020 	mov	w0, #0x1                   	// #1
    80210424:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210428:	d65f03c0 	ret
    8021042c:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210430:	52800060 	mov	w0, #0x3                   	// #3
    80210434:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210438:	d65f03c0 	ret
    8021043c:	52800040 	mov	w0, #0x2                   	// #2
    80210440:	17fffff4 	b	80210410 <__sigtramp_r+0x50>
    80210444:	d2802001 	mov	x1, #0x100                 	// #256
    80210448:	97ffe37e 	bl	80209240 <_malloc_r>
    8021044c:	f900aa80 	str	x0, [x20, #336]
    80210450:	aa0003e1 	mov	x1, x0
    80210454:	b40000e0 	cbz	x0, 80210470 <__sigtramp_r+0xb0>
    80210458:	91040002 	add	x2, x0, #0x100
    8021045c:	d503201f 	nop
    80210460:	f800841f 	str	xzr, [x0], #8
    80210464:	eb02001f 	cmp	x0, x2
    80210468:	54ffffc1 	b.ne	80210460 <__sigtramp_r+0xa0>  // b.any
    8021046c:	17ffffde 	b	802103e4 <__sigtramp_r+0x24>
    80210470:	12800000 	mov	w0, #0xffffffff            	// #-1
    80210474:	17ffffe7 	b	80210410 <__sigtramp_r+0x50>
    80210478:	12800000 	mov	w0, #0xffffffff            	// #-1
    8021047c:	d65f03c0 	ret

0000000080210480 <raise>:
    80210480:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80210484:	b0000001 	adrp	x1, 80211000 <blanks.1+0x60>
    80210488:	910003fd 	mov	x29, sp
    8021048c:	a90153f3 	stp	x19, x20, [sp, #16]
    80210490:	f9438834 	ldr	x20, [x1, #1808]
    80210494:	71007c1f 	cmp	w0, #0x1f
    80210498:	540003e8 	b.hi	80210514 <raise+0x94>  // b.pmore
    8021049c:	f940aa82 	ldr	x2, [x20, #336]
    802104a0:	2a0003f3 	mov	w19, w0
    802104a4:	b40001c2 	cbz	x2, 802104dc <raise+0x5c>
    802104a8:	93407c03 	sxtw	x3, w0
    802104ac:	f8637841 	ldr	x1, [x2, x3, lsl #3]
    802104b0:	b4000161 	cbz	x1, 802104dc <raise+0x5c>
    802104b4:	f100043f 	cmp	x1, #0x1
    802104b8:	540000a0 	b.eq	802104cc <raise+0x4c>  // b.none
    802104bc:	b100043f 	cmn	x1, #0x1
    802104c0:	540001e0 	b.eq	802104fc <raise+0x7c>  // b.none
    802104c4:	f823785f 	str	xzr, [x2, x3, lsl #3]
    802104c8:	d63f0020 	blr	x1
    802104cc:	52800000 	mov	w0, #0x0                   	// #0
    802104d0:	a94153f3 	ldp	x19, x20, [sp, #16]
    802104d4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802104d8:	d65f03c0 	ret
    802104dc:	aa1403e0 	mov	x0, x20
    802104e0:	94000094 	bl	80210730 <_getpid_r>
    802104e4:	2a1303e2 	mov	w2, w19
    802104e8:	2a0003e1 	mov	w1, w0
    802104ec:	aa1403e0 	mov	x0, x20
    802104f0:	a94153f3 	ldp	x19, x20, [sp, #16]
    802104f4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802104f8:	1400007a 	b	802106e0 <_kill_r>
    802104fc:	528002c1 	mov	w1, #0x16                  	// #22
    80210500:	b9000281 	str	w1, [x20]
    80210504:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210508:	52800020 	mov	w0, #0x1                   	// #1
    8021050c:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210510:	d65f03c0 	ret
    80210514:	528002c1 	mov	w1, #0x16                  	// #22
    80210518:	12800000 	mov	w0, #0xffffffff            	// #-1
    8021051c:	b9000281 	str	w1, [x20]
    80210520:	17ffffec 	b	802104d0 <raise+0x50>
	...

0000000080210530 <signal>:
    80210530:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
    80210534:	b0000002 	adrp	x2, 80211000 <blanks.1+0x60>
    80210538:	910003fd 	mov	x29, sp
    8021053c:	a90153f3 	stp	x19, x20, [sp, #16]
    80210540:	93407c13 	sxtw	x19, w0
    80210544:	f90013f5 	str	x21, [sp, #32]
    80210548:	f9438855 	ldr	x21, [x2, #1808]
    8021054c:	71007e7f 	cmp	w19, #0x1f
    80210550:	54000148 	b.hi	80210578 <signal+0x48>  // b.pmore
    80210554:	aa0103f4 	mov	x20, x1
    80210558:	f940aaa1 	ldr	x1, [x21, #336]
    8021055c:	b4000161 	cbz	x1, 80210588 <signal+0x58>
    80210560:	f8737820 	ldr	x0, [x1, x19, lsl #3]
    80210564:	f8337834 	str	x20, [x1, x19, lsl #3]
    80210568:	a94153f3 	ldp	x19, x20, [sp, #16]
    8021056c:	f94013f5 	ldr	x21, [sp, #32]
    80210570:	a8c37bfd 	ldp	x29, x30, [sp], #48
    80210574:	d65f03c0 	ret
    80210578:	528002c0 	mov	w0, #0x16                  	// #22
    8021057c:	b90002a0 	str	w0, [x21]
    80210580:	92800000 	mov	x0, #0xffffffffffffffff    	// #-1
    80210584:	17fffff9 	b	80210568 <signal+0x38>
    80210588:	d2802001 	mov	x1, #0x100                 	// #256
    8021058c:	aa1503e0 	mov	x0, x21
    80210590:	97ffe32c 	bl	80209240 <_malloc_r>
    80210594:	f900aaa0 	str	x0, [x21, #336]
    80210598:	aa0003e1 	mov	x1, x0
    8021059c:	b4ffff20 	cbz	x0, 80210580 <signal+0x50>
    802105a0:	91040002 	add	x2, x0, #0x100
    802105a4:	d503201f 	nop
    802105a8:	f800841f 	str	xzr, [x0], #8
    802105ac:	eb00005f 	cmp	x2, x0
    802105b0:	54ffffc1 	b.ne	802105a8 <signal+0x78>  // b.any
    802105b4:	17ffffeb 	b	80210560 <signal+0x30>
	...

00000000802105c0 <_init_signal>:
    802105c0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    802105c4:	b0000000 	adrp	x0, 80211000 <blanks.1+0x60>
    802105c8:	910003fd 	mov	x29, sp
    802105cc:	f9000bf3 	str	x19, [sp, #16]
    802105d0:	f9438813 	ldr	x19, [x0, #1808]
    802105d4:	f940aa60 	ldr	x0, [x19, #336]
    802105d8:	b40000a0 	cbz	x0, 802105ec <_init_signal+0x2c>
    802105dc:	52800000 	mov	w0, #0x0                   	// #0
    802105e0:	f9400bf3 	ldr	x19, [sp, #16]
    802105e4:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802105e8:	d65f03c0 	ret
    802105ec:	aa1303e0 	mov	x0, x19
    802105f0:	d2802001 	mov	x1, #0x100                 	// #256
    802105f4:	97ffe313 	bl	80209240 <_malloc_r>
    802105f8:	f900aa60 	str	x0, [x19, #336]
    802105fc:	b40000e0 	cbz	x0, 80210618 <_init_signal+0x58>
    80210600:	91040001 	add	x1, x0, #0x100
    80210604:	d503201f 	nop
    80210608:	f800841f 	str	xzr, [x0], #8
    8021060c:	eb01001f 	cmp	x0, x1
    80210610:	54ffffc1 	b.ne	80210608 <_init_signal+0x48>  // b.any
    80210614:	17fffff2 	b	802105dc <_init_signal+0x1c>
    80210618:	12800000 	mov	w0, #0xffffffff            	// #-1
    8021061c:	17fffff1 	b	802105e0 <_init_signal+0x20>

0000000080210620 <__sigtramp>:
    80210620:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80210624:	b0000001 	adrp	x1, 80211000 <blanks.1+0x60>
    80210628:	910003fd 	mov	x29, sp
    8021062c:	a90153f3 	stp	x19, x20, [sp, #16]
    80210630:	f9438834 	ldr	x20, [x1, #1808]
    80210634:	71007c1f 	cmp	w0, #0x1f
    80210638:	54000508 	b.hi	802106d8 <__sigtramp+0xb8>  // b.pmore
    8021063c:	2a0003f3 	mov	w19, w0
    80210640:	f940aa80 	ldr	x0, [x20, #336]
    80210644:	b4000320 	cbz	x0, 802106a8 <__sigtramp+0x88>
    80210648:	f873d801 	ldr	x1, [x0, w19, sxtw #3]
    8021064c:	8b33cc00 	add	x0, x0, w19, sxtw #3
    80210650:	b4000181 	cbz	x1, 80210680 <__sigtramp+0x60>
    80210654:	b100043f 	cmn	x1, #0x1
    80210658:	54000240 	b.eq	802106a0 <__sigtramp+0x80>  // b.none
    8021065c:	f100043f 	cmp	x1, #0x1
    80210660:	54000180 	b.eq	80210690 <__sigtramp+0x70>  // b.none
    80210664:	f900001f 	str	xzr, [x0]
    80210668:	2a1303e0 	mov	w0, w19
    8021066c:	d63f0020 	blr	x1
    80210670:	52800000 	mov	w0, #0x0                   	// #0
    80210674:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210678:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8021067c:	d65f03c0 	ret
    80210680:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210684:	52800020 	mov	w0, #0x1                   	// #1
    80210688:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8021068c:	d65f03c0 	ret
    80210690:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210694:	52800060 	mov	w0, #0x3                   	// #3
    80210698:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8021069c:	d65f03c0 	ret
    802106a0:	52800040 	mov	w0, #0x2                   	// #2
    802106a4:	17fffff4 	b	80210674 <__sigtramp+0x54>
    802106a8:	aa1403e0 	mov	x0, x20
    802106ac:	d2802001 	mov	x1, #0x100                 	// #256
    802106b0:	97ffe2e4 	bl	80209240 <_malloc_r>
    802106b4:	f900aa80 	str	x0, [x20, #336]
    802106b8:	b4000100 	cbz	x0, 802106d8 <__sigtramp+0xb8>
    802106bc:	aa0003e1 	mov	x1, x0
    802106c0:	91040002 	add	x2, x0, #0x100
    802106c4:	d503201f 	nop
    802106c8:	f800843f 	str	xzr, [x1], #8
    802106cc:	eb01005f 	cmp	x2, x1
    802106d0:	54ffffc1 	b.ne	802106c8 <__sigtramp+0xa8>  // b.any
    802106d4:	17ffffdd 	b	80210648 <__sigtramp+0x28>
    802106d8:	12800000 	mov	w0, #0xffffffff            	// #-1
    802106dc:	17ffffe6 	b	80210674 <__sigtramp+0x54>

00000000802106e0 <_kill_r>:
    802106e0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    802106e4:	910003fd 	mov	x29, sp
    802106e8:	a90153f3 	stp	x19, x20, [sp, #16]
    802106ec:	b0000394 	adrp	x20, 80281000 <__sf+0x38>
    802106f0:	aa0003f3 	mov	x19, x0
    802106f4:	b9044a9f 	str	wzr, [x20, #1096]
    802106f8:	2a0103e0 	mov	w0, w1
    802106fc:	2a0203e1 	mov	w1, w2
    80210700:	97ffc0b8 	bl	802009e0 <_kill>
    80210704:	3100041f 	cmn	w0, #0x1
    80210708:	54000080 	b.eq	80210718 <_kill_r+0x38>  // b.none
    8021070c:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210710:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210714:	d65f03c0 	ret
    80210718:	b9444a81 	ldr	w1, [x20, #1096]
    8021071c:	34ffff81 	cbz	w1, 8021070c <_kill_r+0x2c>
    80210720:	b9000261 	str	w1, [x19]
    80210724:	a94153f3 	ldp	x19, x20, [sp, #16]
    80210728:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8021072c:	d65f03c0 	ret

0000000080210730 <_getpid_r>:
    80210730:	17ffc0a8 	b	802009d0 <_getpid>
	...

0000000080210740 <__trunctfdf2>:
    80210740:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
    80210744:	9e660002 	fmov	x2, d0
    80210748:	9eae0003 	fmov	x3, v0.d[1]
    8021074c:	910003fd 	mov	x29, sp
    80210750:	f9000bf3 	str	x19, [sp, #16]
    80210754:	d53b4404 	mrs	x4, fpcr
    80210758:	aa0303e0 	mov	x0, x3
    8021075c:	d37ffc61 	lsr	x1, x3, #63
    80210760:	d370f863 	ubfx	x3, x3, #48, #15
    80210764:	aa0103e5 	mov	x5, x1
    80210768:	d37dbc00 	ubfiz	x0, x0, #3, #48
    8021076c:	91000467 	add	x7, x3, #0x1
    80210770:	12001c26 	and	w6, w1, #0xff
    80210774:	aa0103e8 	mov	x8, x1
    80210778:	aa42f400 	orr	x0, x0, x2, lsr #61
    8021077c:	d37df041 	lsl	x1, x2, #3
    80210780:	f27f34ff 	tst	x7, #0x7ffe
    80210784:	54000920 	b.eq	802108a8 <__trunctfdf2+0x168>  // b.none
    80210788:	92877fe7 	mov	x7, #0xffffffffffffc400    	// #-15360
    8021078c:	8b070063 	add	x3, x3, x7
    80210790:	f11ff87f 	cmp	x3, #0x7fe
    80210794:	540002ed 	b.le	802107f0 <__trunctfdf2+0xb0>
    80210798:	f26a0484 	ands	x4, x4, #0xc00000
    8021079c:	540007c0 	b.eq	80210894 <__trunctfdf2+0x154>  // b.none
    802107a0:	f150009f 	cmp	x4, #0x400, lsl #12
    802107a4:	54001520 	b.eq	80210a48 <__trunctfdf2+0x308>  // b.none
    802107a8:	f160009f 	cmp	x4, #0x800, lsl #12
    802107ac:	1a9f17e0 	cset	w0, eq	// eq = none
    802107b0:	6a0000df 	tst	w6, w0
    802107b4:	54000701 	b.ne	80210894 <__trunctfdf2+0x154>  // b.any
    802107b8:	f150009f 	cmp	x4, #0x400, lsl #12
    802107bc:	540015c0 	b.eq	80210a74 <__trunctfdf2+0x334>  // b.none
    802107c0:	f160009f 	cmp	x4, #0x800, lsl #12
    802107c4:	1a9f17e0 	cset	w0, eq	// eq = none
    802107c8:	6a0000df 	tst	w6, w0
    802107cc:	54000641 	b.ne	80210894 <__trunctfdf2+0x154>  // b.any
    802107d0:	92f00213 	mov	x19, #0x7fefffffffffffff    	// #9218868437227405311
    802107d4:	52800280 	mov	w0, #0x14                  	// #20
    802107d8:	aa05fe73 	orr	x19, x19, x5, lsl #63
    802107dc:	940000cd 	bl	80210b10 <__sfp_handle_exceptions>
    802107e0:	9e670260 	fmov	d0, x19
    802107e4:	f9400bf3 	ldr	x19, [sp, #16]
    802107e8:	a8c27bfd 	ldp	x29, x30, [sp], #32
    802107ec:	d65f03c0 	ret
    802107f0:	f100007f 	cmp	x3, #0x0
    802107f4:	54000aad 	b.le	80210948 <__trunctfdf2+0x208>
    802107f8:	eb021fff 	cmp	xzr, x2, lsl #7
    802107fc:	52800002 	mov	w2, #0x0                   	// #0
    80210800:	9a9f07e7 	cset	x7, ne	// ne = any
    80210804:	aa41f0e1 	orr	x1, x7, x1, lsr #60
    80210808:	aa001021 	orr	x1, x1, x0, lsl #4
    8021080c:	f100003f 	cmp	x1, #0x0
    80210810:	1a9f07e0 	cset	w0, ne	// ne = any
    80210814:	0a000040 	and	w0, w2, w0
    80210818:	f240083f 	tst	x1, #0x7
    8021081c:	540015c0 	b.eq	80210ad4 <__trunctfdf2+0x394>  // b.none
    80210820:	926a0484 	and	x4, x4, #0xc00000
    80210824:	f150009f 	cmp	x4, #0x400, lsl #12
    80210828:	54000240 	b.eq	80210870 <__trunctfdf2+0x130>  // b.none
    8021082c:	f160009f 	cmp	x4, #0x800, lsl #12
    80210830:	54000d00 	b.eq	802109d0 <__trunctfdf2+0x290>  // b.none
    80210834:	b5000c84 	cbnz	x4, 802109c4 <__trunctfdf2+0x284>
    80210838:	92400c22 	and	x2, x1, #0xf
    8021083c:	f100105f 	cmp	x2, #0x4
    80210840:	54000aa1 	b.ne	80210994 <__trunctfdf2+0x254>  // b.any
    80210844:	d343d821 	ubfx	x1, x1, #3, #52
    80210848:	12002863 	and	w3, w3, #0x7ff
    8021084c:	d2800002 	mov	x2, #0x0                   	// #0
    80210850:	34001260 	cbz	w0, 80210a9c <__trunctfdf2+0x35c>
    80210854:	b340cc22 	bfxil	x2, x1, #0, #52
    80210858:	52800300 	mov	w0, #0x18                  	// #24
    8021085c:	b34c2862 	bfi	x2, x3, #52, #11
    80210860:	b34100c2 	bfi	x2, x6, #63, #1
    80210864:	aa0203f3 	mov	x19, x2
    80210868:	940000aa 	bl	80210b10 <__sfp_handle_exceptions>
    8021086c:	17ffffdd 	b	802107e0 <__trunctfdf2+0xa0>
    80210870:	b5000bc5 	cbnz	x5, 802109e8 <__trunctfdf2+0x2a8>
    80210874:	91002021 	add	x1, x1, #0x8
    80210878:	92490022 	and	x2, x1, #0x80000000000000
    8021087c:	35000920 	cbnz	w0, 802109a0 <__trunctfdf2+0x260>
    80210880:	b4000b62 	cbz	x2, 802109ec <__trunctfdf2+0x2ac>
    80210884:	91000462 	add	x2, x3, #0x1
    80210888:	f11ff87f 	cmp	x3, #0x7fe
    8021088c:	54001161 	b.ne	80210ab8 <__trunctfdf2+0x378>  // b.any
    80210890:	b5fff944 	cbnz	x4, 802107b8 <__trunctfdf2+0x78>
    80210894:	d34100b3 	lsl	x19, x5, #63
    80210898:	52800280 	mov	w0, #0x14                  	// #20
    8021089c:	b24c2a73 	orr	x19, x19, #0x7ff0000000000000
    802108a0:	9400009c 	bl	80210b10 <__sfp_handle_exceptions>
    802108a4:	17ffffcf 	b	802107e0 <__trunctfdf2+0xa0>
    802108a8:	aa010002 	orr	x2, x0, x1
    802108ac:	b5000203 	cbnz	x3, 802108ec <__trunctfdf2+0x1ac>
    802108b0:	d34100b3 	lsl	x19, x5, #63
    802108b4:	b4fff962 	cbz	x2, 802107e0 <__trunctfdf2+0xa0>
    802108b8:	926a0484 	and	x4, x4, #0xc00000
    802108bc:	f150009f 	cmp	x4, #0x400, lsl #12
    802108c0:	54000ce0 	b.eq	80210a5c <__trunctfdf2+0x31c>  // b.none
    802108c4:	f160009f 	cmp	x4, #0x800, lsl #12
    802108c8:	54000b60 	b.eq	80210a34 <__trunctfdf2+0x2f4>  // b.none
    802108cc:	f100009f 	cmp	x4, #0x0
    802108d0:	d28000a0 	mov	x0, #0x5                   	// #5
    802108d4:	9a9f0401 	csinc	x1, x0, xzr, eq	// eq = none
    802108d8:	d2800008 	mov	x8, #0x0                   	// #0
    802108dc:	d343d821 	ubfx	x1, x1, #3, #52
    802108e0:	12002908 	and	w8, w8, #0x7ff
    802108e4:	52800300 	mov	w0, #0x18                  	// #24
    802108e8:	14000033 	b	802109b4 <__trunctfdf2+0x274>
    802108ec:	b4000222 	cbz	x2, 80210930 <__trunctfdf2+0x1f0>
    802108f0:	d28fffe2 	mov	x2, #0x7fff                	// #32767
    802108f4:	93c1f001 	extr	x1, x0, x1, #60
    802108f8:	d372fc00 	lsr	x0, x0, #50
    802108fc:	eb02007f 	cmp	x3, x2
    80210900:	d343fc21 	lsr	x1, x1, #3
    80210904:	52000000 	eor	w0, w0, #0x1
    80210908:	b24d0021 	orr	x1, x1, #0x8000000000000
    8021090c:	1a9f0000 	csel	w0, w0, wzr, eq	// eq = none
    80210910:	5280fff3 	mov	w19, #0x7ff                 	// #2047
    80210914:	aa13d033 	orr	x19, x1, x19, lsl #52
    80210918:	aa05fe73 	orr	x19, x19, x5, lsl #63
    8021091c:	35fff600 	cbnz	w0, 802107dc <__trunctfdf2+0x9c>
    80210920:	9e670260 	fmov	d0, x19
    80210924:	f9400bf3 	ldr	x19, [sp, #16]
    80210928:	a8c27bfd 	ldp	x29, x30, [sp], #32
    8021092c:	d65f03c0 	ret
    80210930:	d34100b3 	lsl	x19, x5, #63
    80210934:	b24c2a73 	orr	x19, x19, #0x7ff0000000000000
    80210938:	9e670260 	fmov	d0, x19
    8021093c:	f9400bf3 	ldr	x19, [sp, #16]
    80210940:	a8c27bfd 	ldp	x29, x30, [sp], #32
    80210944:	d65f03c0 	ret
    80210948:	b100d07f 	cmn	x3, #0x34
    8021094c:	54fffb6b 	b.lt	802108b8 <__trunctfdf2+0x178>  // b.tstop
    80210950:	d28007a7 	mov	x7, #0x3d                  	// #61
    80210954:	cb0300e8 	sub	x8, x7, x3
    80210958:	b24d0000 	orr	x0, x0, #0x8000000000000
    8021095c:	f100fd1f 	cmp	x8, #0x3f
    80210960:	540004ec 	b.gt	802109fc <__trunctfdf2+0x2bc>
    80210964:	11000c68 	add	w8, w3, #0x3
    80210968:	4b0300e7 	sub	w7, w7, w3
    8021096c:	52800022 	mov	w2, #0x1                   	// #1
    80210970:	d2800003 	mov	x3, #0x0                   	// #0
    80210974:	9ac82029 	lsl	x9, x1, x8
    80210978:	f100013f 	cmp	x9, #0x0
    8021097c:	9a9f07e9 	cset	x9, ne	// ne = any
    80210980:	9ac72421 	lsr	x1, x1, x7
    80210984:	aa090021 	orr	x1, x1, x9
    80210988:	9ac82000 	lsl	x0, x0, x8
    8021098c:	aa010001 	orr	x1, x0, x1
    80210990:	17ffff9f 	b	8021080c <__trunctfdf2+0xcc>
    80210994:	91001021 	add	x1, x1, #0x4
    80210998:	92490022 	and	x2, x1, #0x80000000000000
    8021099c:	34fff720 	cbz	w0, 80210880 <__trunctfdf2+0x140>
    802109a0:	b4000142 	cbz	x2, 802109c8 <__trunctfdf2+0x288>
    802109a4:	91000468 	add	x8, x3, #0x1
    802109a8:	d2800001 	mov	x1, #0x0                   	// #0
    802109ac:	12002908 	and	w8, w8, #0x7ff
    802109b0:	52800300 	mov	w0, #0x18                  	// #24
    802109b4:	aa08d028 	orr	x8, x1, x8, lsl #52
    802109b8:	aa05fd13 	orr	x19, x8, x5, lsl #63
    802109bc:	94000055 	bl	80210b10 <__sfp_handle_exceptions>
    802109c0:	17ffff88 	b	802107e0 <__trunctfdf2+0xa0>
    802109c4:	34000140 	cbz	w0, 802109ec <__trunctfdf2+0x2ac>
    802109c8:	aa0303e8 	mov	x8, x3
    802109cc:	17ffffc4 	b	802108dc <__trunctfdf2+0x19c>
    802109d0:	b5fff525 	cbnz	x5, 80210874 <__trunctfdf2+0x134>
    802109d4:	340000c0 	cbz	w0, 802109ec <__trunctfdf2+0x2ac>
    802109d8:	aa0303e8 	mov	x8, x3
    802109dc:	aa0803e3 	mov	x3, x8
    802109e0:	aa0303e8 	mov	x8, x3
    802109e4:	17ffffbe 	b	802108dc <__trunctfdf2+0x19c>
    802109e8:	35ffff00 	cbnz	w0, 802109c8 <__trunctfdf2+0x288>
    802109ec:	d343d821 	ubfx	x1, x1, #3, #52
    802109f0:	12002868 	and	w8, w3, #0x7ff
    802109f4:	52800200 	mov	w0, #0x10                  	// #16
    802109f8:	17ffffef 	b	802109b4 <__trunctfdf2+0x274>
    802109fc:	11010c62 	add	w2, w3, #0x43
    80210a00:	f101011f 	cmp	x8, #0x40
    80210a04:	12800047 	mov	w7, #0xfffffffd            	// #-3
    80210a08:	4b0300e3 	sub	w3, w7, w3
    80210a0c:	9ac22002 	lsl	x2, x0, x2
    80210a10:	aa020022 	orr	x2, x1, x2
    80210a14:	9a811041 	csel	x1, x2, x1, ne	// ne = any
    80210a18:	9ac32400 	lsr	x0, x0, x3
    80210a1c:	f100003f 	cmp	x1, #0x0
    80210a20:	52800022 	mov	w2, #0x1                   	// #1
    80210a24:	9a9f07e1 	cset	x1, ne	// ne = any
    80210a28:	d2800003 	mov	x3, #0x0                   	// #0
    80210a2c:	aa000021 	orr	x1, x1, x0
    80210a30:	17ffff77 	b	8021080c <__trunctfdf2+0xcc>
    80210a34:	d2800021 	mov	x1, #0x1                   	// #1
    80210a38:	b4fffd25 	cbz	x5, 802109dc <__trunctfdf2+0x29c>
    80210a3c:	d2800008 	mov	x8, #0x0                   	// #0
    80210a40:	d2800121 	mov	x1, #0x9                   	// #9
    80210a44:	17ffffa6 	b	802108dc <__trunctfdf2+0x19c>
    80210a48:	b5000165 	cbnz	x5, 80210a74 <__trunctfdf2+0x334>
    80210a4c:	d2effe13 	mov	x19, #0x7ff0000000000000    	// #9218868437227405312
    80210a50:	52800280 	mov	w0, #0x14                  	// #20
    80210a54:	9400002f 	bl	80210b10 <__sfp_handle_exceptions>
    80210a58:	17ffff62 	b	802107e0 <__trunctfdf2+0xa0>
    80210a5c:	d2800121 	mov	x1, #0x9                   	// #9
    80210a60:	b4fff3e5 	cbz	x5, 802108dc <__trunctfdf2+0x19c>
    80210a64:	d2800003 	mov	x3, #0x0                   	// #0
    80210a68:	d2800021 	mov	x1, #0x1                   	// #1
    80210a6c:	aa0303e8 	mov	x8, x3
    80210a70:	17ffff9b 	b	802108dc <__trunctfdf2+0x19c>
    80210a74:	f10000bf 	cmp	x5, #0x0
    80210a78:	92e00200 	mov	x0, #0xffefffffffffffff    	// #-4503599627370497
    80210a7c:	d2effe01 	mov	x1, #0x7ff0000000000000    	// #9218868437227405312
    80210a80:	9e670000 	fmov	d0, x0
    80210a84:	9e670021 	fmov	d1, x1
    80210a88:	52800280 	mov	w0, #0x14                  	// #20
    80210a8c:	1e611c00 	fcsel	d0, d0, d1, ne	// ne = any
    80210a90:	9e660013 	fmov	x19, d0
    80210a94:	9400001f 	bl	80210b10 <__sfp_handle_exceptions>
    80210a98:	17ffff52 	b	802107e0 <__trunctfdf2+0xa0>
    80210a9c:	b340cc22 	bfxil	x2, x1, #0, #52
    80210aa0:	52800200 	mov	w0, #0x10                  	// #16
    80210aa4:	b34c2862 	bfi	x2, x3, #52, #11
    80210aa8:	b34100c2 	bfi	x2, x6, #63, #1
    80210aac:	aa0203f3 	mov	x19, x2
    80210ab0:	94000018 	bl	80210b10 <__sfp_handle_exceptions>
    80210ab4:	17ffff4b 	b	802107e0 <__trunctfdf2+0xa0>
    80210ab8:	92fc0203 	mov	x3, #0x1fefffffffffffff    	// #2301339409586323455
    80210abc:	52800200 	mov	w0, #0x10                  	// #16
    80210ac0:	8a410c61 	and	x1, x3, x1, lsr #3
    80210ac4:	aa02d022 	orr	x2, x1, x2, lsl #52
    80210ac8:	aa05fc53 	orr	x19, x2, x5, lsl #63
    80210acc:	94000011 	bl	80210b10 <__sfp_handle_exceptions>
    80210ad0:	17ffff44 	b	802107e0 <__trunctfdf2+0xa0>
    80210ad4:	d343d821 	ubfx	x1, x1, #3, #52
    80210ad8:	12002873 	and	w19, w3, #0x7ff
    80210adc:	350000e0 	cbnz	w0, 80210af8 <__trunctfdf2+0x3b8>
    80210ae0:	d2800002 	mov	x2, #0x0                   	// #0
    80210ae4:	b340cc22 	bfxil	x2, x1, #0, #52
    80210ae8:	b34c2a62 	bfi	x2, x19, #52, #11
    80210aec:	b34100c2 	bfi	x2, x6, #63, #1
    80210af0:	aa0203f3 	mov	x19, x2
    80210af4:	17ffff3b 	b	802107e0 <__trunctfdf2+0xa0>
    80210af8:	530b2c80 	ubfx	w0, w4, #11, #1
    80210afc:	531d7000 	lsl	w0, w0, #3
    80210b00:	17ffff85 	b	80210914 <__trunctfdf2+0x1d4>
	...

0000000080210b10 <__sfp_handle_exceptions>:
    80210b10:	36000080 	tbz	w0, #0, 80210b20 <__sfp_handle_exceptions+0x10>
    80210b14:	0f000401 	movi	v1.2s, #0x0
    80210b18:	1e211820 	fdiv	s0, s1, s1
    80210b1c:	d53b4421 	mrs	x1, fpsr
    80210b20:	360800a0 	tbz	w0, #1, 80210b34 <__sfp_handle_exceptions+0x24>
    80210b24:	1e2e1001 	fmov	s1, #1.000000000000000000e+00
    80210b28:	0f000402 	movi	v2.2s, #0x0
    80210b2c:	1e221820 	fdiv	s0, s1, s2
    80210b30:	d53b4421 	mrs	x1, fpsr
    80210b34:	36100100 	tbz	w0, #2, 80210b54 <__sfp_handle_exceptions+0x44>
    80210b38:	5298b5c2 	mov	w2, #0xc5ae                	// #50606
    80210b3c:	12b01001 	mov	w1, #0x7f7fffff            	// #2139095039
    80210b40:	72ae93a2 	movk	w2, #0x749d, lsl #16
    80210b44:	1e270021 	fmov	s1, w1
    80210b48:	1e270042 	fmov	s2, w2
    80210b4c:	1e222820 	fadd	s0, s1, s2
    80210b50:	d53b4421 	mrs	x1, fpsr
    80210b54:	36180080 	tbz	w0, #3, 80210b64 <__sfp_handle_exceptions+0x54>
    80210b58:	0f044401 	movi	v1.2s, #0x80, lsl #16
    80210b5c:	1e210820 	fmul	s0, s1, s1
    80210b60:	d53b4421 	mrs	x1, fpsr
    80210b64:	362000c0 	tbz	w0, #4, 80210b7c <__sfp_handle_exceptions+0x6c>
    80210b68:	12b01000 	mov	w0, #0x7f7fffff            	// #2139095039
    80210b6c:	1e2e1002 	fmov	s2, #1.000000000000000000e+00
    80210b70:	1e270001 	fmov	s1, w0
    80210b74:	1e223820 	fsub	s0, s1, s2
    80210b78:	d53b4420 	mrs	x0, fpsr
    80210b7c:	d65f03c0 	ret
