#include <core.h>
#include <irq.h>

irq_handler_t irq_handlers[IRQ_NUM]; 

void irq_set_handler(unsigned id, irq_handler_t handler){
    if(id < IRQ_NUM)
        irq_handlers[id] = handler;
    else if (id == IRQ_LPI_MIN)
        irq_handlers[250] = handler;    //Aleatory id just for test measurements
}

void irq_handle(unsigned id){
    if(id < IRQ_NUM && irq_handlers[id] != NULL)
        irq_handlers[id](id);
    else{
        irq_handlers[250](id);
    }
}
