#ifndef IRQ_H
#define IRQ_H

#include <core.h>
#include <arch/irq.h>

typedef void (*irq_handler_t)(unsigned id);

void irq_handle(unsigned id);
void irq_set_handler(unsigned id, irq_handler_t handler);
void irq_enable(unsigned id);
void irq_disable(unsigned id);
void irq_set_prio(unsigned id, unsigned prio);
void irq_send_ipi(unsigned long target_cpu_mask);

#endif // IRQ_H
