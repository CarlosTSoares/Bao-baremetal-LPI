/** 
 * Bao, a Lightweight Static Partitioning Hypervisor 
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      Jose Martins <jose.martins@bao-project.org>
 *      Sandro Pinto <sandro.pinto@bao-project.org>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details. 
 *
 */

#include <core.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <cpu.h>
#include <wfi.h>
#include <spinlock.h>
#include <plat.h>
#include <irq.h>
#include <uart.h>
#include <timer.h>
#include <gic.h>

#define TIMER_INTERVAL (TIME_S(1))

spinlock_t print_lock = SPINLOCK_INITVAL;

// char* strnchr(const char* s, size_t n, char c) {
//     for (size_t i = 0; i < n; i++) {
//         if (s[i] == c) {
//             return (char*)s + i;
//         }
//     }
//     return NULL;
// }


void lpi_handler(unsigned id){
    printf("LPI %d received by cpu%d: %s\n",id, get_cpuid(), __func__);
}

void main(void){

    static volatile bool master_done = false;

    if(cpu_is_master()){
         spin_lock(&print_lock);
         printf("Bao bare-metal test guest1\n");
         printf("Bao bare-metal test guest2\n");
         spin_unlock(&print_lock);

        irq_set_handler(8192, lpi_handler);

        //spin_lock(&print_lock);
        /*Trigger eventID 0 attached to Device ID 0, Collection ID 0, Redistributor 0 and phy INT ID 8192*/
        printf("Baremetal: Before trigger LPI\n");
        its_trigger_lpi();
        printf("Baremetal: After trigger LPI\n");
        
        //spin_unlock(&print_lock);   

        master_done = true;
    }

    while(!master_done);
    spin_lock(&print_lock);
    printf("cpu %d up\n", get_cpuid());
    spin_unlock(&print_lock);

    while(1) wfi();
}
