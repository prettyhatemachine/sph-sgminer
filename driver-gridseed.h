#ifndef INCLUDE_DRIVER_GRIDSEED_H
#define INCLUDE_DRIVER_GRIDSEED_H

#ifdef USE_GRIDSEED

#include "util.h"

#define GRIDSEED_MINER_THREADS		1
#define GRIDSEED_LATENCY		4

#define GRIDSEED_DEFAULT_BAUD		115200
#define GRIDSEED_DEFAULT_FREQUENCY	750
#define GRIDSEED_DEFAULT_CHIPS		5
#define GRIDSEED_DEFAULT_USEFIFO	0
#define GRIDSEED_DEFAULT_BTCORE		16

#define GRIDSEED_COMMAND_DELAY		20
#define GRIDSEED_READ_SIZE		12
#define GRIDSEED_MCU_QUEUE_LEN		0
#define GRIDSEED_SOFT_QUEUE_LEN		(GRIDSEED_MCU_QUEUE_LEN+2)
#define GRIDSEED_READBUF_SIZE		8192
#define GRIDSEED_HASH_SPEED		((double)0.0851128926)  // in ms
#define GRIDSEED_F_IN			25  // input frequency

#define GRIDSEED_PROXY_PORT		3350

#define GRIDSEED_PERIPH_BASE		((uint32_t)0x40000000)
#define GRIDSEED_APB2PERIPH_BASE	(GRIDSEED_PERIPH_BASE + 0x10000)
#define GRIDSEED_GPIOA_BASE		(GRIDSEED_APB2PERIPH_BASE + 0x0800)
#define GRIDSEED_CRL_OFFSET		0x00
#define GRIDSEED_ODR_OFFSET		0x0c

#define transfer(gridseed, request_type, bRequest, wValue, wIndex, cmd) \
		_transfer(gridseed, request_type, bRequest, wValue, wIndex, NULL, 0, cmd)

#endif

extern struct device_drv gridseed_drv;

#endif /* INCLUDE_DRIVER_GRIDSEED_H */
