/**
 * Bao, a Lightweight Static Partitioning Hypervisor
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      Jose Martins <jose.martins@bao-project.org>
 *      Angelo Ruocco <angeloruocco90@gmail.com>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details.
 *
 */

#ifndef __GIC_H__
#define __GIC_H__

#include <core.h>
#include <bit.h>
#include <plat.h>

#define GICV2 (2)
#define GICV3 (3)

#define GIC_MAX_INTERUPTS 1024
#define GIC_MAX_SGIS 16
#define GIC_MAX_PPIS 16
#define GIC_CPU_PRIV (GIC_MAX_SGIS + GIC_MAX_PPIS)
#define GIC_MAX_SPIS (GIC_MAX_INTERUPTS - GIC_CPU_PRIV)
#define GIC_PRIO_BITS 8
#define GIC_TARGET_BITS 8
#define GIC_MAX_TARGETS GIC_TARGET_BITS
#define GIC_CONFIG_BITS 2
#define GIC_SEC_BITS 2
#define GIC_SGI_BITS 8

#define GIC_INT_REG(NINT) (NINT / (sizeof(uint32_t) * 8))
#define GIC_INT_MASK(NINT) (1U << NINT % (sizeof(uint32_t) * 8))
#define GIC_NUM_INT_REGS(NINT) GIC_INT_REG(NINT)
#define GIC_NUM_PRIVINT_REGS (GIC_CPU_PRIV / (sizeof(uint32_t) * 8))

#define GIC_PRIO_REG(NINT) ((NINT * GIC_PRIO_BITS) / (sizeof(uint32_t) * 8))
#define GIC_NUM_PRIO_REGS(NINT) GIC_PRIO_REG(NINT)
#define GIC_PRIO_OFF(NINT) (NINT * GIC_PRIO_BITS) % (sizeof(uint32_t) * 8)

#define GIC_TARGET_REG(NINT) ((NINT * GIC_TARGET_BITS) / (sizeof(uint32_t) * 8))
#define GIC_NUM_TARGET_REGS(NINT) GIC_TARGET_REG(NINT)
#define GIC_TARGET_OFF(NINT) (NINT * GIC_TARGET_BITS) % (sizeof(uint32_t) * 8)

#define GIC_CONFIG_REG(NINT) ((NINT * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8))
#define GIC_NUM_CONFIG_REGS(NINT) GIC_CONFIG_REG(NINT)
#define GIC_CONFIG_OFF(NINT) (NINT * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8)

#define GIC_NUM_SEC_REGS(NINT) ((NINT * GIC_SEC_BITS) / (sizeof(uint32_t) * 8))

#define GIC_NUM_SGI_REGS \
    ((GIC_MAX_SGIS * GIC_SGI_BITS) / (sizeof(uint32_t) * 8))
#define GICD_SGI_REG(NINT) (NINT / 4)
#define GICD_SGI_OFF(NINT) ((NINT % 4) * 8)

#define GIC_NUM_APR_REGS ((1UL << (GIC_PRIO_BITS - 1)) / (sizeof(uint32_t) * 8))
#define GIC_NUM_LIST_REGS (64)

/* Distributor Control Register, GICD_CTLR */

#define GICD_CTLR_EN_BIT (0x1)
#define GICD_CTLR_ENA_BIT (0x2)
#define GICD_CTLR_ARE_NS_BIT (0x10)

/*  Interrupt Controller Type Register, GICD_TYPER */

#define GICD_TYPER_ITLINENUM_OFF (0)
#define GICD_TYPER_ITLINENUM_LEN (5)
#define GICD_TYPER_CPUNUM_OFF (5)
#define GICD_TYPER_CPUNUM_LEN (3)
#define GICD_TYPER_SECUREXT_BIT (1UL << 10)
#define GICD_TYPER_LSPI_OFF (11)
#define GICD_TYPER_LSPI_LEN (6)

/* Software Generated Interrupt Register, GICD_SGIR */

#define GICD_TYPER_ITLN_OFF 0
#define GICD_TYPER_ITLN_LEN 5
#define GICD_TYPER_ITLN_MSK BIT_MASK(GICD_TYPER_ITLN_OFF, GICD_TYPER_ITLN_LEN)
#define GICD_TYPER_CPUN_OFF 5
#define GICD_TYPER_CPUN_LEN 3
#define GICD_TYPER_CPUN_MSK BIT_MASK(GICD_TYPER_CPUN_OFF, GICD_TYPER_CPUN_LEN)

#define GICD_SGIR_SGIINTID_OFF 0
#define GICD_SGIR_SGIINTID_LEN 4
#define GICD_SGIR_SGIINTID_MSK \
    (BIT_MASK(GICD_SGIR_SGIINTID_OFF, GICD_SGIR_SGIINTID_LEN))
#define GICD_SGIR_SGIINTID(sgir) \
    bit_extract(sgir, GICD_SGIR_SGIINTID_OFF, GICD_SGIR_SGIINTID_LEN)
#define GICD_SGIR_CPUTRGLST_OFF 16
#define GICD_SGIR_CPUTRGLST_LEN 8
#define GICD_SGIR_CPUTRGLST(sgir) \
    bit_extract(sgir, GICD_SGIR_CPUTRGLST_OFF, GICD_SGIR_CPUTRGLST_LEN)
#define GICD_SGIR_TRGLSTFLT_OFF 24
#define GICD_SGIR_TRGLSTFLT_LEN 2
#define GICD_SGIR_TRGLSTFLT(sgir) \
    bit_extract(sgir, GICD_SGIR_TRGLSTFLT_OFF, GICD_SGIR_TRGLSTFLT_LEN)

typedef struct {
    uint32_t CTLR;
    uint32_t TYPER;
    uint32_t IIDR;
    uint8_t pad0[0x0010 - 0x000C];
    uint32_t STATUSR;
    uint8_t pad1[0x0040 - 0x0014];
    uint32_t SETSPI_NSR;
    uint8_t pad2[0x0048 - 0x0044];
    uint32_t CLRSPI_NSR;
    uint8_t pad3[0x0050 - 0x004C];
    uint32_t SETSPI_SR;
    uint8_t pad4[0x0058 - 0x0054];
    uint32_t CLRSPI_SR;
    uint8_t pad9[0x0080 - 0x005C];
    uint32_t IGROUPR[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];  // banked CPU
    uint32_t ISENABLER[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ICENABLER[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ISPENDR[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ICPENDR[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ISACTIVER[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ICACTIVER[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint32_t IPRIORITYR[GIC_NUM_PRIO_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ITARGETSR[GIC_NUM_TARGET_REGS(GIC_MAX_INTERUPTS)];
    uint32_t ICFGR[GIC_NUM_CONFIG_REGS(GIC_MAX_INTERUPTS)];
    uint32_t IGPRMODR[GIC_NUM_INT_REGS(GIC_MAX_INTERUPTS)];
    uint8_t pad5[0x0E00 - 0x0D80];
    uint32_t NSACR[GIC_NUM_SEC_REGS(GIC_MAX_INTERUPTS)];
    uint32_t SGIR;
    uint8_t pad6[0x0F10 - 0x0F04];
    uint32_t CPENDSGIR[GIC_NUM_SGI_REGS];
    uint32_t SPENDSGIR[GIC_NUM_SGI_REGS];
    uint8_t pad7[0x6000 - 0x0F30];
    uint64_t IROUTER[GIC_MAX_INTERUPTS];
    uint8_t pad8[0xFFD0 - 0x8000];
    uint32_t ID[(0x10000 - 0xFFD0) / sizeof(uint32_t)];
} __attribute__((__packed__, aligned(0x10000))) gicd_t;

/* Redistributor Wake Register, GICD_WAKER */

#define GICR_CTRL_DS_BIT (1 << 6)
#define GICR_ProcessorSleep_BIT (0x2)
#define GICR_ChildrenASleep_BIT (0x4)
typedef struct {
    /* RD_base frame */
    uint32_t CTLR;
    uint32_t IIDR;
    uint64_t TYPER;
    uint32_t STATUSR;
    uint32_t WAKER;
    uint8_t pad0[0x0040 - 0x0018];
    uint64_t SETLPIR;
    uint64_t CLRLPIR;
    uint8_t pad1[0x0070 - 0x0050];
    uint64_t PROPBASER;
    uint64_t PENDBASER;
    uint8_t pad2[0x00A0 - 0x0080];
    uint64_t INVLPIR;
    uint8_t pad3[0x00B0 - 0x00A8];
    uint64_t INVALLR;
    uint8_t pad4[0x00c0 - 0x00b8];
    uint64_t SYNCR;
    uint8_t pad5[0xFFD0 - 0x00c8];
    uint32_t ID[(0x10000 - 0xFFD0) / sizeof(uint32_t)];

    /* SGI_base frame */
    uint8_t sgi_base[0] __attribute__((aligned(0x10000)));
    uint8_t pad6[0x0080 - 0x000];
    uint32_t IGROUPR0;
    uint8_t pad7[0x0100 - 0x084];
    uint32_t ISENABLER0;
    uint8_t pad8[0x0180 - 0x104];
    uint32_t ICENABLER0;
    uint8_t pad9[0x0200 - 0x184];
    uint32_t ISPENDR0;
    uint8_t pad10[0x0280 - 0x204];
    uint32_t ICPENDR0;
    uint8_t pad11[0x0300 - 0x284];
    uint32_t ISACTIVER0;
    uint8_t pad12[0x0380 - 0x304];
    uint32_t ICACTIVER0;
    uint8_t pad13[0x0400 - 0x384];
    uint32_t IPRIORITYR[GIC_NUM_PRIO_REGS(GIC_CPU_PRIV)];
    uint8_t pad14[0x0c00 - 0x420];
    uint32_t ICFGR0;
    uint32_t ICFGR1;
    uint8_t pad15[0x0D00 - 0xc08];
    uint32_t IGRPMODR0;
    uint8_t pad16[0x0e00 - 0xd04];
    uint32_t NSACR;
} __attribute__((__packed__, aligned(0x10000))) gicr_t;

/* CPU Interface Control Register, GICC_CTLR */

#define GICC_CTLR_EN_BIT (0x1)
#define GICC_CTLR_EOImodeNS_BIT (1UL << 9)
#define GICC_CTLR_WR_MSK (0x1)
#define GICC_IAR_ID_OFF (0)
#define GICC_IAR_ID_LEN (10)
#define GICC_IAR_ID_MSK (BIT_MASK(GICC_IAR_ID_OFF, GICC_IAR_ID_LEN))
#define GICC_IAR_CPU_OFF (10)
#define GICC_IAR_CPU_LEN (3)
#define GICC_IAR_CPU_MSK (BIT_MASK(GICC_IAR_CPU_OFF, GICC_IAR_CPU_LEN))

typedef struct {
    uint32_t CTLR;
    uint32_t PMR;
    uint32_t BPR;
    uint32_t IAR;
    uint32_t EOIR;
    uint32_t RPR;
    uint32_t HPPIR;
    uint32_t ABPR;
    uint32_t AIAR;
    uint32_t AEOIR;
    uint32_t AHPPIR;
    uint8_t pad0[0x00D0 - 0x002C];
    uint32_t APR[GIC_NUM_APR_REGS];
    uint32_t NSAPR[GIC_NUM_APR_REGS];
    uint8_t pad1[0x00FC - 0x00F0];
    uint32_t IIDR;
    uint8_t pad2[0x1000 - 0x0100];
    uint32_t DIR;
} __attribute__((__packed__, aligned(0x1000))) gicc_t;

#define GICH_HCR_En_BIT (1 << 0)
#define GICH_HCR_UIE_BIT (1 << 1)
#define GICH_HCR_LRENPIE_BIT (1 << 2)
#define GICH_HCR_NPIE_BIT (1 << 3)
#define GICH_HCR_VGrp0DIE_BIT (1 << 4)
#define GICH_HCR_VGrp0EIE_BIT (1 << 5)
#define GICH_HCR_VGrp1EIE_BIT (1 << 6)
#define GICH_HCR_VGrp1DIE_BIT (1 << 7)
#define GICH_HCR_EOICount_OFF (27)
#define GICH_HCR_EOICount_LEN (5)
#define GICH_HCR_EOICount_MASK \
    BIT_MASK(GICH_HCR_EOICount_OFF, GICH_HCR_EOICount_LEN)

#define GICH_VTR_OFF (0)
#define GICH_VTR_LEN (6)
#define GICH_VTR_MSK BIT_MASK(GICH_VTR_OFF, GICH_VTR_LEN)

#define GICH_LR_VID_OFF (0)
#define GICH_LR_VID_LEN (10)
#define GICH_LR_VID_MSK BIT_MASK(GICH_LR_VID_OFF, GICH_LR_VID_LEN)
#define GICH_LR_VID(LR) (bit_extract(LR, GICH_LR_VID_OFF, GICH_LR_VID_LEN))

#define GICH_LR_PID_OFF (10)
#define GICH_LR_PID_LEN (10)
#define GICH_LR_PID_MSK BIT_MASK(GICH_LR_PID_OFF, GICH_LR_PID_LEN)
#define GICH_LR_CPUID_OFF (10)
#define GICH_LR_CPUID_LEN (3)
#define GICH_LR_CPUID_MSK BIT_MASK(GICH_LR_CPUID_OFF, GICH_LR_CPUID_LEN)
#define GICH_LR_CPUID(LR) \
    (bit_extract(LR, GICH_LR_CPUID_OFF, GICH_LR_CPUID_LEN))
#define GICH_LR_PRIO_OFF (23)
#define GICH_LR_PRIO_LEN (5)
#define GICH_LR_PRIO_MSK BIT_MASK(GICH_LR_PRIO_OFF, GICH_LR_PRIO_LEN)
#define GICH_LR_STATE_OFF (28)
#define GICH_LR_STATE_LEN (2)
#define GICH_LR_STATE_MSK BIT_MASK(GICH_LR_STATE_OFF, GICH_LR_STATE_LEN)
#define GICH_LR_STATE(LR) \
    (bit_extract(LR, GICH_LR_STATE_OFF, GICH_LR_STATE_LEN))

#define GICH_LR_STATE_INV ((0 << GICH_LR_STATE_OFF) & GICH_LR_STATE_MSK)
#define GICH_LR_STATE_PND ((1 << GICH_LR_STATE_OFF) & GICH_LR_STATE_MSK)
#define GICH_LR_STATE_ACT ((2 << GICH_LR_STATE_OFF) & GICH_LR_STATE_MSK)
#define GICH_LR_STATE_ACTPEND ((3 << GICH_LR_STATE_OFF) & GICH_LR_STATE_MSK)

#define GICH_LR_HW_BIT (1U << 31)
#define GICH_LR_EOI_BIT (1U << 19)

#define GICH_MISR_EOI (1U << 0)
#define GICH_MISR_U (1U << 1)
#define GICH_MISR_LRPEN (1U << 2)
#define GICH_MISR_NP (1U << 3)
#define GICH_MISR_VGrp0E (1U << 4)
#define GICH_MISR_VGrp0D (1U << 5)
#define GICH_MISR_VGrp1E (1U << 6)
#define GICH_MISR_VGrp1D (1U << 7)

enum int_state { INV, PEND, ACT, PENDACT };

void gic_init();
void gic_cpu_init();
void gic_send_sgi(unsigned long cpu_target, unsigned long sgi_num);

void gic_set_enable(unsigned long int_id, bool en);
void gic_set_prio(unsigned long int_id, uint8_t prio);
void gic_set_icfgr(unsigned long int_id, uint8_t cfg);
void gic_set_act(unsigned long int_id, bool act);
void gic_set_state(unsigned long int_id, enum int_state state);
void gic_set_trgt(unsigned long int_id, uint8_t trgt);
void gic_set_route(unsigned long int_id, unsigned long trgt);
unsigned long gic_get_prio(unsigned long int_id);
uint8_t gic_get_trgt(unsigned long int_id);
enum int_state gic_get_state(unsigned long int_id);

void gicd_set_enable(unsigned long int_id, bool en);
void gicd_set_prio(unsigned long int_id, uint8_t prio);
void gicd_set_icfgr(unsigned long int_id, uint8_t cfg);
void gicd_set_act(unsigned long int_id, bool act);
void gicd_set_state(unsigned long int_id, enum int_state state);
void gicd_set_trgt(unsigned long int_id, uint8_t trgt);
void gicd_set_route(unsigned long int_id, unsigned long trgt);
unsigned long gicd_get_prio(unsigned long int_id);
enum int_state gicd_get_state(unsigned long int_id);
unsigned long gic_num_irqs();

void gicr_set_enable(unsigned long int_id, bool en, uint32_t gicr_id);
void gicr_set_prio(unsigned long int_id, uint8_t prio, uint32_t gicr_id);
void gicr_set_icfgr(unsigned long int_id, uint8_t cfg, uint32_t gicr_id);
void gicr_set_act(unsigned long int_id, bool act, uint32_t gicr_id);
void gicr_set_state(unsigned long int_id, enum int_state state, uint32_t gicr_id);
void gicr_set_trgt(unsigned long int_id, uint8_t trgt, uint32_t gicr_id);
void gicr_set_route(unsigned long int_id, uint8_t trgt, uint32_t gicr_id);
unsigned long gicr_get_prio(unsigned long int_id, uint32_t gicr_id);
enum int_state gicr_get_state(unsigned long int_id, uint32_t gicr_id);

/*LPI support*/
void gicr_set_propbaser(uint64_t propbaser,uint8_t rdist_id);
void gicr_set_pendbaser(uint64_t pendbaser,uint8_t rdist_id);
void gicr_disable_lpi(uint8_t rdist_id);
void gicr_enable_lpi(uint8_t rdist_id);

static inline bool gic_is_sgi(unsigned long int_id)
{
    return int_id < GIC_MAX_SGIS;
}

static inline bool gic_is_priv(unsigned long int_id)
{
    return int_id < GIC_CPU_PRIV;
}

#ifdef STD_ADDR_SPACE
#undef PLAT_GICD_BASE_ADDR
#undef PLAT_GICC_BASE_ADDR
#undef PLAT_GICR_BASE_ADDR
#endif

#ifndef PLAT_GICD_BASE_ADDR
#define PLAT_GICD_BASE_ADDR (0xF9010000)
#endif

#ifndef PLAT_GICC_BASE_ADDR
#define PLAT_GICC_BASE_ADDR (0xF9020000)
#endif

#ifndef PLAT_GICR_BASE_ADDR
#define PLAT_GICR_BASE_ADDR (0xF9020000)
#endif



#define GIC_MAX_TTD (0x8)

/* GITS */
typedef struct gits_hw {
    /*ITS_CTRL_base frame*/
    uint32_t CTLR;
    uint32_t IIDR;
    uint64_t TYPER;
    uint8_t pad0[0x80 - 0x10];
    uint64_t CBASER;
    uint64_t CWRITER;
    uint64_t CREADR;
    uint8_t pad1[0x100 - 0x98];
    uint64_t BASER[GIC_MAX_TTD];
    uint8_t pad2[0xFFD0 - 0x140];   
    uint32_t ID[(0x10000 - 0xFFD0) / sizeof(uint32_t)];

    /*translation_base frame - ITS_base + 0x10000*/
    uint8_t transl_base[0] __attribute__((aligned(0x10000)));
    uint8_t pad3[0x40 - 0x0];
    uint32_t TRANSLATER;
    uint8_t pad4[0x10000 - 0x44];
} __attribute__((__packed__, aligned(0x10000))) gits_t;

#define GITS_BASER_PHY_OFF                  (12)
#define GITS_BASER_PHY_LEN                  (36)
#define GITS_BASER_SHAREABILITY_OFF         (10)
#define GITS_BASER_INNERCACHE_OFF           (59)
#define GITS_BASER_InnerShareable           (1ULL << GITS_BASER_SHAREABILITY_OFF)
#define GITS_BASER_RaWaWb                   (7ULL << GITS_BASER_INNERCACHE_OFF)
#define GITS_BASER_NonCache                 (1ULL << GITS_BASER_INNERCACHE_OFF)
#define GITS_BASER_VAL_BIT                  (1ULL << 63)

#define GICR_PROPBASER_PHY_OFF                  (12)
#define GICR_PROPBASER_PHY_LEN                  (40)
#define GICR_PROPBASER_SHAREABILITY_OFF         (10)
#define GICR_PROPBASER_INNERCACHE_OFF           (7)
#define GICR_PROPBASER_InnerShareable           (1ULL << GICR_PROPBASER_SHAREABILITY_OFF)
#define GICR_PROPBASER_RaWaWb                   (7ULL << GICR_PROPBASER_INNERCACHE_OFF)
#define GICR_PROPBASER_NonCache                 (1ULL << GICR_PROPBASER_INNERCACHE_OFF)

#define GITS_BASER_VALID_BIT            (1ULL << 63)
#define GITS_BASER_PHY_ADDR_OFF         (12)
#define GITS_BASER_PHY_ADDR_LEN         (36)
#define GITS_BASER_PHY_ADDR_MSK         (BIT_MASK(GITS_BASER_PHY_ADDR_OFF,GITS_BASER_PHY_ADDR_LEN))
#define GITS_BASER_TYPE_OFF             (56)
#define GITS_BASER_TYPE_LEN             (3)
#define GITS_BASER_TYPE_MASK            (BIT_MASK(GITS_BASER_TYPE_OFF,GITS_BASER_TYPE_LEN))
#define GITS_BASER_ENTRY_SZ_OFF         (48)
#define GITS_BASER_ENTRY_SZ_LEN         (5)
#define GITS_BASER_ENTRY_SZ_MASK        (BIT_MASK(GITS_BASER_ENTRY_SZ_OFF,GITS_BASER_ENTRY_SZ_LEN))
#define GITS_BASER_PAGE_SZ_OFF          (56)
#define GITS_BASER_PAGE_SZ_LEN          (3)
#define GITS_BASER_PAGE_SZ_MASK         (BIT_MASK(GITS_BASER_PAGE_SZ_OFF,GITS_BASER_PAGE_SZ_LEN))
#define GITS_BASER_RO_MASK              (GITS_BASER_TYPE_MASK | GITS_BASER_ENTRY_SZ_MASK | GITS_BASER_PAGE_SZ_MASK)

#define GITS_BASER_PHY_OFF                  (12)
#define GITS_BASER_PHY_LEN                  (36)
#define GITS_BASER_SHAREABILITY_OFF         (10)
#define GITS_BASER_INNERCACHE_OFF           (59)
#define GITS_BASER_InnerShareable           (1ULL << GITS_BASER_SHAREABILITY_OFF)
#define GITS_BASER_RaWaWb                   (7ULL << GITS_BASER_INNERCACHE_OFF)
#define GITS_BASER_VAL_BIT                   (1ULL << 63)

int its_init();
void its_trigger_lpi();
uint64_t get_cqueue();


/*PMU*/
extern volatile uint64_t prev_timer_val;

uint64_t pmu_get_cycle_count();

#endif /* __GIC_H__ */
