#include <gic.h>
#include <irq.h>
#include <spinlock.h>
#include <stdio.h>

#define CMD_QUEUE_SZ        (16)
#define DEVICE_TABLE_SZ     (4)
#define ITT_TABLE_SZ        (4)
#define PAGE_SZ             (4096)
#define LPI_IDS             (1)
#define PROP_SZ             (4)


volatile gits_t* gits = (void*)PLAT_GITS_BASE_ADDR;

spinlock_t gits_lock = SPINLOCK_INITVAL;

//Missing the aligment requirements

volatile uint8_t cmd_queue[CMD_QUEUE_SZ * PAGE_SZ] __attribute__((aligned(0x10000)));
volatile uint8_t device_table[DEVICE_TABLE_SZ * PAGE_SZ] __attribute__((aligned(0x10000)));         //size defined by hardware
// uint8_t coll_table[CMD_QUEUE_SZ];  /*Don't needed in imx8qm board*/
volatile uint8_t itt_table[ITT_TABLE_SZ * PAGE_SZ] __attribute__((aligned(0x10000)));         //size defined by hardware

volatile uint8_t prop_table[PROP_SZ * PAGE_SZ] __attribute__((aligned(0x1000)));            //4KB-aligned physical addr
volatile uint8_t pend_table[PROP_SZ * PAGE_SZ] __attribute__((aligned(0x10000)));           //64KB-aligned physical addr


struct its {
    uint64_t cmd_queue;
    uint64_t *device_table;
    uint64_t *itt_table;
    uint8_t *prop_table;   //Configuration for one core only
    uint8_t *pend_table;
};

struct its its;

uint32_t cmd_off;

/*
 * The ITS command block, which is what the ITS actually parses.
 */
struct its_cmd_block {
	uint64_t cmd[4];
};

/* Command Generation*/

void its_send_mapc(){

    /*Point to the next cmd in the cmd queue*/
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);

    /*MAP Coll ID 0 to redistributor 0*/

    its_cmd->cmd[0] = 0x09;
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x8000000000000000;
    its_cmd->cmd[3] = 0x00;


}

void its_send_invall(){

    /*Point to the next cmd in the cmd qeueu*/
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);

    its_cmd->cmd[0] = 0x0d;
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    its_cmd->cmd[3] = 0x00;

}

void its_send_int(){
    /*Point to the next cmd in the cmd qeueu*/
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);

    /*Generate lpi associated to the eventID 0 and device ID 0*/

    its_cmd->cmd[0] = 0x03;
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    its_cmd->cmd[3] = 0x00;

}

void its_send_sync(){

    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);

    /*Sync redistributor 0*/

    its_cmd->cmd[0] = 0x05;
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    its_cmd->cmd[3] = 0x00;

}

void its_send_mapd(){

    uint64_t itt_addr = (uint64_t)its.itt_table;
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);

    /*Map device id 0 to ITT address*/

    its_cmd->cmd[0] = 0x08;
    its_cmd->cmd[1] = 0x01;       /*1 bit size*/
    its_cmd->cmd[2] = (1ULL << 63) | itt_addr;        /*Verify alignment*/
    its_cmd->cmd[3] = 0x00;

}

void its_send_mapti(){

    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);

    its_cmd->cmd[0] = 0x0a;
    its_cmd->cmd[1] = 0x200000000000;       /*8192 pINTID*/
    its_cmd->cmd[2] = 0x00;                 /*Coll ID 0*/
    its_cmd->cmd[3] = 0x00;



}

void its_send_inv(){
    struct its_cmd_block *its_cmd = (struct its_cmd_block *)(its.cmd_queue + cmd_off);

    /*Cache consistent with LPI tables held in memory*/

    its_cmd->cmd[0] = 0x0c;
    its_cmd->cmd[1] = 0x00;
    its_cmd->cmd[2] = 0x00;
    its_cmd->cmd[3] = 0x00;
}


void its_cpu_init_collections(){

    /*Bind the Collection ID with the target redistributor*/
    /*For this configuration, collection ID 0 is hardwired to redistributor 0*/

    cmd_off = gits->CWRITER;
    its_send_mapc();
    cmd_off += 0x20;
	its_send_sync();
    cmd_off += 0x20;

    //flush


    /*Increment CWRITTER*/
    gits->CWRITER = cmd_off;

    its_send_invall();
    cmd_off += 0x20;
    its_send_sync();
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;

}


int its_cpu_init(void)
{
    int ret;

    /*UPDATE Collection table*/
	its_cpu_init_collections();

	return 0;
}


static int its_setup_lpi_prop_table(void){

    uint16_t lpi_id_bits;
    int err;
    uint64_t propbaser;

    /*LPI ID bits is the same as GICD TYPER.idbits*/
    lpi_id_bits = 0xf;

    /*4KB alignment*/

    propbaser = (uint64_t)its.prop_table | GICR_PROPBASER_InnerShareable | GICR_PROPBASER_RaWaWb | lpi_id_bits;

    gicr_set_propbaser(propbaser,0);

    return 0;
}

static int its_setup_lpi_pend_table(void){

    /*Get the lpi_ID bits*/

    uint64_t pendbaser = (uint64_t)its.pend_table | GICR_PROPBASER_InnerShareable | GICR_PROPBASER_RaWaWb;

    gicr_set_pendbaser(pendbaser,0);

    return 0;
}

static int allocate_lpi_tables(void){

    uint64_t pendbaser;
    uint64_t cbaser;
    uint64_t baser;
    uint8_t err;

    /* Disable LPIs in gicr and gist*/
    gits->CTLR &= 0xfffe;
    gicr_disable_lpi(0);


    /* Set Command Queue Table*/
    gits->CBASER = (uint64_t)its.cmd_queue | GITS_BASER_InnerShareable | GITS_BASER_RaWaWb | 0xf;
    gits->CBASER |= 1ULL << 63; //add valid

    /* Set BASER with deevice table addr*/
    for (size_t index = 0; index < 8; index++) {
        //TODO -  Verify if flat tables are supported and manage Indirect bit
        if(bit_extract(gits->BASER[index], GITS_BASER_TYPE_OFF, GITS_BASER_TYPE_LEN) == 0x1) //Equal device table type
        {
            gits->BASER[index] = (uint64_t)its.itt_table | GITS_BASER_InnerShareable | GITS_BASER_RaWaWb;

            gits->BASER[index] |= (1ULL << 63);  //set valid bit
        }
    }
    

    err = its_setup_lpi_prop_table();
	if (err)
		return err;


    /*Alloc the pend table of each avaiable redistributor*/
    //In this case, for test purposes, only one core is required

    err = its_setup_lpi_pend_table();
    if(err)
        return err;

    gicr_enable_lpi(0);
    /* Enable LPIs */
    gits->CTLR |= 0x1;
    uint32_t *ptr = 0x51a2C000;
    *ptr = 0x2;
}

static void its_enable_lpi(uint64_t pINTID){

    uint8_t val;

    val = (0x1 | 0xa0); /*Enable LPI 8192 with fixed priority 0xa0*/

    /*base_addr + (N-8192)*/
    its.prop_table[pINTID - 8192] = val;

    printf("Value of prop 0 is 0x%x\n",its.prop_table[0]);

}

/*
    Device specific initialization
*/

int its_device_init(){

    /*Map the itt_addr to the device_ID in device table*/
    cmd_off = gits->CWRITER;
    its_send_mapd();
    //its_send_sync(); // ???
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;

    /*Map the eventID and deviceID to collection ID int the itt table*/
    its_send_mapti();
    cmd_off += 0x20;
    its_send_sync();
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;


    /*Sync LPI config tables in the redistributor*/
    its_enable_lpi(8192);

    its_send_inv();
    cmd_off += 0x20;
    its_send_sync();    //all the ITS operations globally observed
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;

    return 0;
}

void its_trigger_lpi(){
    cmd_off = gits->CWRITER;
    its_send_int();
    cmd_off += 0x20;
    gits->CWRITER = cmd_off;

    while(gits->CREADR != gits->CWRITER);

    its_send_sync();
    cmd_off += 0x20;

    gits->CWRITER = cmd_off;
}

int its_init(void){

    int err;

    /*store table addrs in its data structure*/
    its.cmd_queue = (uint64_t)cmd_queue;
    its.device_table = device_table;
    its.itt_table = itt_table;
    its.prop_table = prop_table;
    its.pend_table = pend_table;

    printf("Value of cmd queue addr is 0x%lx",its.cmd_queue);

    err = allocate_lpi_tables();
    if(err)
        return err;

    err = its_cpu_init();
    if(err)
        return err;


    err = its_device_init();
    if(err)
        return err;

    // uint32_t *ptr = 0x51a2C004;
    // printf("Value of trk ctlr is 0x%x",*ptr);
    // ptr++;
    // printf("Value of trkdidr is 0x%x",*ptr);
    // ptr++;
    // printf("Value of trkpidr is 0x%x",*ptr);
    // ptr++;
    // printf("Value of trkvidr is 0x%x",*ptr);

    printf("ITS initialization finished\n");
}