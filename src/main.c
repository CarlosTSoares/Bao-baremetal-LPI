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

#define TIMER_INTERVAL (TIME_MS(200))

spinlock_t print_lock = SPINLOCK_INITVAL;

volatile uint8_t lpi_handled = 1;
volatile uint8_t test_done = 0;
volatile uint64_t test[501];
volatile uint32_t index_test = 0;

// char* strnchr(const char* s, size_t n, char c) {
//     for (size_t i = 0; i < n; i++) {
//         if (s[i] == c) {
//             return (char*)s + i;
//         }
//     }
//     return NULL;
// }

uint32_t get_counter_frequency() {
    uint32_t frequency;
    asm volatile("mrs %0, CNTFRQ_EL0" : "=r"(frequency));
    return frequency;
}

//#include <math.h>

// void calculate_stats(volatile uint64_t array[], size_t size, uint64_t *min, uint64_t *max, uint64_t *average, uint64_t *std_dev) {
//     if (size == 0) {
//         *min = 0;
//         *max = 0;
//         *average = 0.0;
//         *std_dev = 0.0;
//         return;
//     }

//     uint64_t sum = 0;
//     *min = 0xffffffffffffffff; // Max possible uint64_t value
//     *max = 0;

//     // First pass: calculate sum, min, and max
//     for (size_t i = 0; i < size; i++) {
//         uint64_t value = array[i];
//         sum += value;

//         if (value < *min) {
//             *min = value;
//         }
//         if (value > *max) {
//             *max = value;
//         }
//     }

//     *average = sum / size;

//     // Second pass: calculate variance
//     uint64_t variance_sum = 0.0;
//     for (size_t i = 0; i < size; i++) {
//         uint64_t diff = array[i] - *average;
//         variance_sum += diff * diff;
//     }

//     uint64_t variance = variance_sum / size;
//     *std_dev = sqrt(variance); // Standard deviation is the square root of variance
// }

void timer_handler(){
    //printf("cpu%d: %s\n", get_cpuid(), __func__);
    // uint64_t curr_timer_val = pmu_get_cycle_count();
    // printf("Cqueue val 0x%lx\n",get_cqueue());
    // uint32_t *ptr = 0x51a2C000;
    // printf("Value of trk ctlr is 0x%x",*ptr);
    // ptr++;
    // printf(" Value of trk status is 0x%x",*ptr);
    // ptr++;
    // printf(" Value of trkdidr is 0x%x",*ptr);
    // ptr++;
    // printf(" Value of trkpidr is 0x%x",*ptr);
    // ptr++;
    // printf(" Value of trkvidr is 0x%x\n",*ptr);
    if(lpi_handled)
    {
        if(index_test < 502){
        if(index_test)
            printf("Value of sample %d is %d\n",index_test -1,test[index_test -1]);
        lpi_handled = 0;
        //irq_disable(TIMER_IRQ_ID);
        if(index_test < 501)
            its_trigger_lpi();
        } else {
        uint64_t max,min;
        uint64_t avg,std_dev;
        //calculate_stats(test,500,&min,&max,&avg,&std_dev);
        // uint64_t frequency = get_counter_frequency();
        // printf("Test done for frequency %d:\nMinimum: %d ticks\n" \
        //         "Maximum: %d ticks\n" \
        //         "Avereage: %d ticks\n",frequency, min, max, avg);
        printf("Done\n");
        timer_set(TIME_S(60));
        }
    }
    // else{
    //     for(int i = 0;i<101;i++)
    //         printf("Value of sample %d is %d\n",i,test[i]);
    // }
}



void lpi_handler(unsigned id){
    uint64_t curr_timer_val = pmu_get_cycle_count();
    //printf("LPI %d received: timer val %d\n",id,curr_timer_val-prev_timer_val);
    test[index_test++] = curr_timer_val-prev_timer_val;
    timer_set(TIMER_INTERVAL);
    lpi_handled = 1;
    // irq_enable(TIMER_IRQ_ID);
}

void main(void){

    static volatile bool master_done = false;

    if(cpu_is_master()){

        /*Maybe missing some initialization*/



         //spin_lock(&print_lock);
         //printf("Bao bare-metal test guest1\n");
         //printf("Bao bare-metal test guest2\n");
         //spin_unlock(&print_lock);
        irq_set_handler(TIMER_IRQ_ID, timer_handler);

        timer_set(TIMER_INTERVAL);
        irq_enable(TIMER_IRQ_ID);
        irq_set_prio(TIMER_IRQ_ID, IRQ_MAX_PRIO);



        irq_set_handler(8192, lpi_handler);

        //spin_lock(&print_lock);
        /*Trigger eventID 0 attached to Device ID 0, Collection ID 0, Redistributor 0 and phy INT ID 8192*/
        //printf("Timer frequency is %d\n",get_counter_frequency());


            
        
        //spin_unlock(&print_lock);   

        master_done = true;
    }
    // spin_lock(&print_lock);
    // printf("Here\n");
    // spin_unlock(&print_lock);
    while(!master_done);
    //if (!cpu_is_master()){
        spin_lock(&print_lock);
        //printf("cpu %d up\n", get_cpuid());
        //printf("Here\n");
        spin_unlock(&print_lock);
    //}

    while(1) wfi();
}
