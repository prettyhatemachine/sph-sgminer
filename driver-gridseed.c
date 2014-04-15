/*
 * Copyright 2013 Faster <develop@gridseed.com>
 * Copyright 2012-2013 Andrew Smith
 * Copyright 2012 Luke Dashjr
 * Copyright 2012 Con Kolivas <kernel@kolivas.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>

#include "miner.h"
#include "usbutils.h"
#include "util.h"

#ifdef WIN32
  #include "compat.h"
  #include <windows.h>
  #include <winsock2.h>
  #include <io.h>
#else
  #include <sys/select.h>
  #include <termios.h>
  #include <sys/stat.h>
  #include <fcntl.h>
#endif /* WIN32 */

#include "elist.h"
#include "miner.h"
#include "usbutils.h"
#include "driver-gridseed.h"
#include "hexdump.c"
#include "util.h"

static const char *gridseed_version = "v3.8.5.20140210.02";

typedef struct s_gridseed_info {
	enum sub_ident	ident;
	uint32_t	fw_version;
	struct timeval	scanhash_time;
	int		nonce_count[8];  // per chip
	int		error_count[8];  // per chip
	char		*serial;
	// options
	int		baud;
	int		freq;
	unsigned char	freq_cmd[8];
	int		chips; //chips per module
	int		voltage;
	int		per_chip_stats;
} GRIDSEED_INFO;

/* commands to set core frequency */
static const int opt_frequency[] = {
        700,  706,  713,  719,  725,  731,  738,  744,
        750,  756,  763,  769,  775,  781,  788,  794,
        800,  813,  825,  838,  850,  863,  875,  888,
        900,  913,  925,  938,  950,  963,  975,  988,
       1000, 1013, 1025, 1038, 1050, 1063, 1075, 1088,
       1100, 1113, 1125, 1138, 1150, 1163, 1175, 1188,
       1200, 1213, 1225, 1238, 1250, 1263, 1275, 1288,
       1300, 1313, 1325, 1338, 1350, 1363, 1375, 1388,
       1400,
         -1
};

static const char *bin_frequency[] = {
        "\x55\xaa\xef\x00\x05\x00\x60\x83",
        "\x55\xaa\xef\x00\x05\x00\x03\x8e",
        "\x55\xaa\xef\x00\x05\x00\x01\x87",
        "\x55\xaa\xef\x00\x05\x00\x43\x8e",
        "\x55\xaa\xef\x00\x05\x00\x80\x83",
        "\x55\xaa\xef\x00\x05\x00\x83\x8e",
        "\x55\xaa\xef\x00\x05\x00\x41\x87",
        "\x55\xaa\xef\x00\x05\x00\xc3\x8e",

        "\x55\xaa\xef\x00\x05\x00\xa0\x83",
        "\x55\xaa\xef\x00\x05\x00\x03\x8f",
        "\x55\xaa\xef\x00\x05\x00\x81\x87",
        "\x55\xaa\xef\x00\x05\x00\x43\x8f",
        "\x55\xaa\xef\x00\x05\x00\xc0\x83",
        "\x55\xaa\xef\x00\x05\x00\x83\x8f",
        "\x55\xaa\xef\x00\x05\x00\xc1\x87",
        "\x55\xaa\xef\x00\x05\x00\xc3\x8f",

        "\x55\xaa\xef\x00\x05\x00\xe0\x83",
        "\x55\xaa\xef\x00\x05\x00\x01\x88",
        "\x55\xaa\xef\x00\x05\x00\x00\x84",
        "\x55\xaa\xef\x00\x05\x00\x41\x88",
        "\x55\xaa\xef\x00\x05\x00\x20\x84",
        "\x55\xaa\xef\x00\x05\x00\x81\x88",
        "\x55\xaa\xef\x00\x05\x00\x40\x84",
        "\x55\xaa\xef\x00\x05\x00\xc1\x88",

        "\x55\xaa\xef\x00\x05\x00\x60\x84",
        "\x55\xaa\xef\x00\x05\x00\x01\x89",
        "\x55\xaa\xef\x00\x05\x00\x80\x84",
        "\x55\xaa\xef\x00\x05\x00\x41\x89",
        "\x55\xaa\xef\x00\x05\x00\xa0\x84",
        "\x55\xaa\xef\x00\x05\x00\x81\x89",
        "\x55\xaa\xef\x00\x05\x00\xc0\x84",
        "\x55\xaa\xef\x00\x05\x00\xc1\x89",

        "\x55\xaa\xef\x00\x05\x00\xe0\x84",
        "\x55\xaa\xef\x00\x05\x00\x01\x8a",
        "\x55\xaa\xef\x00\x05\x00\x00\x85",
        "\x55\xaa\xef\x00\x05\x00\x41\x8a",
        "\x55\xaa\xef\x00\x05\x00\x20\x85",
        "\x55\xaa\xef\x00\x05\x00\x81\x8a",
        "\x55\xaa\xef\x00\x05\x00\x40\x85",
        "\x55\xaa\xef\x00\x05\x00\xc1\x8a",

        "\x55\xaa\xef\x00\x05\x00\x60\x85",
        "\x55\xaa\xef\x00\x05\x00\x01\x8b",
        "\x55\xaa\xef\x00\x05\x00\x80\x85",
        "\x55\xaa\xef\x00\x05\x00\x41\x8b",
        "\x55\xaa\xef\x00\x05\x00\xa0\x85",
        "\x55\xaa\xef\x00\x05\x00\x81\x8b",
        "\x55\xaa\xef\x00\x05\x00\xc0\x85",
        "\x55\xaa\xef\x00\x05\x00\xc1\x8b",

        "\x55\xaa\xef\x00\x05\x00\xe0\x85"
        "\x55\xaa\xef\x00\x05\x00\x01\x8c"
        "\x55\xaa\xef\x00\x05\x00\x00\x86"
        "\x55\xaa\xef\x00\x05\x00\x41\x8c"
        "\x55\xaa\xef\x00\x05\x00\x20\x86"
        "\x55\xaa\xef\x00\x05\x00\x81\x8c"
        "\x55\xaa\xef\x00\x05\x00\x40\x86"
        "\x55\xaa\xef\x00\x05\x00\xc1\x8c"

        "\x55\xaa\xef\x00\x05\x00\x60\x86"
        "\x55\xaa\xef\x00\x05\x00\x01\x8d"
        "\x55\xaa\xef\x00\x05\x00\x80\x86"
        "\x55\xaa\xef\x00\x05\x00\x41\x8d"
        "\x55\xaa\xef\x00\x05\x00\xa0\x86"
        "\x55\xaa\xef\x00\x05\x00\x81\x8d"
        "\x55\xaa\xef\x00\x05\x00\xc0\x86"
        "\x55\xaa\xef\x00\x05\x00\xc1\x8d"

        "\x55\xaa\xef\x00\x05\x00\xe0\x86"
};

static const char *str_reset[] = {
	"55AAC000808080800000000001000000", // Chip reset
	NULL
};

static const char *str_init[] = {
	"55AAC000C0C0C0C00500000001000000",
	"55AAEF020000000000000000000000000000000000000000",
	"55AAEF3020000000",
	NULL
};

static const char *str_ltc_reset[] = {
	"55AA1F2816000000",
	"55AA1F2817000000",
	NULL
};


#ifdef WIN32
static void set_text_color(WORD color)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
#endif

/*---------------------------------------------------------------------------------------*/

static void _transfer(struct cgpu_info *gridseed, uint8_t request_type, uint8_t bRequest,
		uint16_t wValue, uint16_t wIndex, uint32_t *data, int siz, enum usb_cmds cmd)
{
	int err;

	err = usb_transfer_data(gridseed, request_type, bRequest, wValue, wIndex, data, siz, cmd);

	applog(LOG_DEBUG, "%s: cgid %d %s got err %d",
			gridseed->drv->name, gridseed->sgminer_id,
			usb_cmdname(cmd), err);
}

static int gc3355_write_data(struct cgpu_info *gridseed, unsigned char *data, int size)
{
	int err, wrote;

#if 1
	if (!opt_quiet && opt_debug) {
		int i;
#ifndef WIN32
		printf("[1;33m >>> %d : [0m", size);
#else
		set_text_color(FOREGROUND_RED|FOREGROUND_GREEN);
		printf(" >>> %d : ", size);
		set_text_color(FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE);
#endif
		for(i=0; i<size; i++) {
			printf("%02x", data[i]);
			if (i==3)
				printf(" ");
		}
		printf("\n");
	}
#endif
	err = usb_write(gridseed, data, size, &wrote, C_SENDWORK);
	if (err != LIBUSB_SUCCESS || wrote != size)
		return -1;
	return 0;
}

static int gc3355_get_data(struct cgpu_info *gridseed, unsigned char *buf, int size)
{
	unsigned char *p;
	int readcount;
	int err = 0, amount;

	readcount = size;
	p = buf;
	while(readcount > 0) {
		err = usb_read_once(gridseed, p, readcount, &amount, C_GETRESULTS);
		if (err) {
			if (readcount != size)
				applog(LOG_ERR, "Timed out after receiving partial data from %i",
						gridseed->sgminer_id);
			break;
		}
		readcount -= amount;
		p += amount;
	}
#if 1
	if (!opt_quiet && opt_debug && (size-readcount) > 0) {
		int i;
#ifndef WIN32
		printf("[1;31m <<< %d : [0m", size);
#else
		set_text_color(FOREGROUND_RED);
		printf(" <<< %d : ", (size-readcount));
		set_text_color(FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE);
#endif
		for(i=0; i<(size-readcount); i++) {
			printf("%02x", buf[i]);
			if ((i+1) % 4 == 0)
			printf(" ");
		}
		printf("\n");
	}
#endif
	return err;
}

static void gc3355_send_cmds(struct cgpu_info *gridseed, const char *cmds[])
{
	unsigned char	ob[512];
	int				i;

	for(i=0; ; i++) {
		if (cmds[i] == NULL)
			break;
		hex2bin(ob, cmds[i], sizeof(ob));
		gc3355_write_data(gridseed, ob, strlen(cmds[i])/2);
		cgsleep_ms(GRIDSEED_COMMAND_DELAY);
	}
}

static bool gc3355_read_register(struct cgpu_info *gridseed, uint32_t reg_addr,
				 uint32_t *reg_value) {
	GRIDSEED_INFO *info = (GRIDSEED_INFO*)(gridseed->device_data);
	char cmd[16] = "\x55\xaa\xc0\x01";
	uint32_t reg_len = 4;
	unsigned char buf[4];

	if (info->fw_version != 0x01140113) {
		applog(LOG_ERR, "Can't read registers; incompatible firmware %08X on %i",
			info->fw_version, gridseed->device_id);
		return false;
	}

	*(uint32_t *)(cmd + 4) = htole32(reg_addr);
	*(uint32_t *)(cmd + 8) = htole32(reg_len);
	*(uint32_t *)(cmd + 12) = htole32(reg_len);
	if (gc3355_write_data(gridseed, cmd, sizeof(cmd)) != 0) {
		applog(LOG_DEBUG, "Failed to write data to %i", gridseed->device_id);
		return false;
	}
	cgsleep_ms(GRIDSEED_COMMAND_DELAY);

	if (gc3355_get_data(gridseed, buf, 4)) {
		applog(LOG_DEBUG, "No response from %i", gridseed->device_id);
		return false;
	}
	*reg_value = le32toh(*(uint32_t *)buf);
	return true;
}

static bool gc3355_write_register(struct cgpu_info *gridseed, uint32_t reg_addr,
				  uint32_t reg_value) {
	GRIDSEED_INFO *info = (GRIDSEED_INFO*)(gridseed->device_data);
	char cmd[16] = "\x55\xaa\xc0\x02";
	uint32_t reg_len = 4;
	unsigned char buf[4];

	if (info->fw_version != 0x01140113) {
		applog(LOG_ERR, "Can't write registers; incompatible firmware %08X on %i",
			info->fw_version, gridseed->device_id);
		return false;
	}

	*(uint32_t *)(cmd + 4) = htole32(reg_addr);
	*(uint32_t *)(cmd + 8) = htole32(reg_value);
	*(uint32_t *)(cmd + 12) = htole32(reg_len);
	if (gc3355_write_data(gridseed, cmd, sizeof(cmd)) != 0) {
		applog(LOG_DEBUG, "Failed to write data to %i", gridseed->device_id);
		return false;
	}
	cgsleep_ms(GRIDSEED_COMMAND_DELAY);

	if (gc3355_get_data(gridseed, buf, 4)) {
		applog(LOG_DEBUG, "No response from %i", gridseed->device_id);
		return false;
	}
	return true;
}

static int gc3355_find_freq_index(int freq)
{
	int	i;
	for(i=0; opt_frequency[i] != -1; i++) {
		if (freq == opt_frequency[i])
			return i;
	}
	return 5;
}

static void gc3355_set_core_freq(struct cgpu_info *gridseed)
{
	GRIDSEED_INFO *info = (GRIDSEED_INFO*)(gridseed->device_data);
	gc3355_write_data(gridseed, info->freq_cmd, sizeof(info->freq_cmd));
	cgsleep_ms(GRIDSEED_COMMAND_DELAY);
	applog(LOG_NOTICE, "Set GC3355 core frequency to %d MHz", info->freq);
}

static void gc3355_increase_voltage(struct cgpu_info *gridseed) {
	uint32_t reg_value;

	// Put GPIOA pin 5 into general function, 50 MHz output.
	if (!gc3355_read_register(gridseed, GRIDSEED_GPIOA_BASE + GRIDSEED_CRL_OFFSET, &reg_value)) {
		applog(LOG_DEBUG, "Failed to read GPIOA CRL register from %i", gridseed->device_id);
		return;
	}
	reg_value = (reg_value & 0xff0fffff) | 0x00300000;
	if (!gc3355_write_register(gridseed, GRIDSEED_GPIOA_BASE + GRIDSEED_CRL_OFFSET, reg_value)) {
		applog(LOG_DEBUG, "Failed to write GPIOA CRL register from %i", gridseed->device_id);
		return;
	}

	// Set GPIOA pin 5 high.
	if (!gc3355_read_register(gridseed, GRIDSEED_GPIOA_BASE + GRIDSEED_ODR_OFFSET, &reg_value)) {
		applog(LOG_DEBUG, "Failed to read GPIOA ODR register from %i", gridseed->device_id);
		return;
	}
	reg_value |= 0x00000020;
	//reg_value &= 0xFFFFFFDF;
	if (!gc3355_write_register(gridseed, GRIDSEED_GPIOA_BASE + GRIDSEED_ODR_OFFSET, reg_value)) {
		applog(LOG_DEBUG, "Failed to write GPIOA ODR register from %i", gridseed->device_id);
		return;
	}
}

static void gc3355_init(struct cgpu_info *gridseed, GRIDSEED_INFO *info)
{
	unsigned char buf[512];
	int amount;

	applog(LOG_NOTICE, "System reseting");
	gc3355_send_cmds(gridseed, str_reset);
	cgsleep_ms(200);
	usb_buffer_clear(gridseed);
	usb_read_timeout(gridseed, buf, sizeof(buf), &amount, 10, C_GETRESULTS);
	gc3355_send_cmds(gridseed, str_init);
	gc3355_send_cmds(gridseed, str_ltc_reset);
	gc3355_set_core_freq(gridseed);
	if (info->voltage)
		gc3355_increase_voltage(gridseed);
}

static bool get_options(GRIDSEED_INFO *info, char *options)
{
	char *ss, *p, *end, *comma, *colon;
	int tmp, pll_r = 0, pll_f = 0, pll_od = 0;

	if (options == NULL)
		return false;

	applog(LOG_NOTICE, "GridSeed options: '%s'", options);
	ss = strdup(options);
	p  = ss;
	end = p + strlen(p);

another:
	comma = strchr(p, ',');
	if (comma != NULL)
		*comma = '\0';
	colon = strchr(p, '=');
	if (colon == NULL)
		goto next;
	*colon = '\0';

	tmp = atoi(colon+1);
	if (strcasecmp(p, "baud")==0) {
		info->baud = (tmp != 0) ? tmp : info->baud;
	}
	else if (strcasecmp(p, "freq")==0) {
		int i;
		for(i=0; opt_frequency[i] != -1; i++) {
			if (tmp == opt_frequency[i])
				info->freq = tmp;
		}
	}
	else if (strcasecmp(p, "pll_r")==0) {
		pll_r = (tmp != 0) ? tmp : pll_r;
		pll_r = MAX(0, MIN(31, pll_r));
	}
	else if (strcasecmp(p, "pll_f")==0) {
		pll_f = (tmp != 0) ? tmp : pll_f;
		pll_f = MAX(0, MIN(127, pll_f));
	}
	else if (strcasecmp(p, "pll_od")==0) {
		pll_od = (tmp != 0) ? tmp : pll_od;
		pll_od = MAX(0, MIN(4, pll_od));
	}
	else if (strcasecmp(p, "chips")==0) {
		info->chips = (tmp != 0) ? tmp : info->chips;
		info->chips = MAX(0, MIN(8, info->chips));
	}
	else if (strcasecmp(p, "voltage")==0) {
		info->voltage = (tmp != 0) ? tmp : info->voltage;
	}
	else if (strcasecmp(p, "per_chip_stats")==0) {
		info->per_chip_stats = (tmp != 0) ? tmp : info->per_chip_stats;
	}

next:
	if (comma != NULL) {
		p = comma + 1;
		if (p < end)
			goto another;
	}
	free(ss);

	if (pll_r != 0 || pll_f != 0 || pll_od != 0) {
		int f_ref = GRIDSEED_F_IN / (pll_r + 1);
		int f_vco = f_ref * (pll_f + 1);
		int f_out = f_vco / (1 << pll_od);
		int pll_bs = (f_out >= 500) ? 1 : 0;
		int cfg_pm = 1, pll_clk_gate = 1;
		uint32_t cmd = (cfg_pm << 0) | (pll_clk_gate << 2) | (pll_r << 16) |
			(pll_f << 21) | (pll_od << 28) | (pll_bs << 31);
		info->freq = f_out;
		memcpy(info->freq_cmd, "\x55\xaa\xef\x00", 4);
		*(uint32_t *)(info->freq_cmd + 4) = htole32(cmd);
	} else {
		int freq_idx = gc3355_find_freq_index(info->freq);
		info->freq = opt_frequency[freq_idx];
		memcpy(info->freq_cmd, bin_frequency[freq_idx], 8);
	}

	return true;
}

static bool get_freq(GRIDSEED_INFO *info, char *options)
{
	char *ss, *p, *end, *comma, *colon;
        int tmp;

        if (options == NULL)
                return false;

        applog(LOG_NOTICE, "GridSeed freq options: '%s'", options);
        ss = strdup(options);
        p  = ss;
        end = p + strlen(p);

another:
        comma = strchr(p, ',');
        if (comma != NULL)
                *comma = '\0';
        colon = strchr(p, '=');
        if (colon == NULL)
                goto next;
        *colon = '\0';

        tmp = atoi(colon+1);
        if (strcasecmp(p, info->serial)==0) {
                applog(LOG_NOTICE, "%s unique frequency: %i", p, tmp);
                int i;
                for(i=0; opt_frequency[i] != -1; i++) {
                        if (tmp == opt_frequency[i])
                                info->freq = tmp;
                }
        }

next:
        if (comma != NULL) {
                p = comma + 1;
                if (p < end)
                        goto another;
        }
        free(ss);

        int freq_idx = gc3355_find_freq_index(info->freq);
        info->freq = opt_frequency[freq_idx];
        memcpy(info->freq_cmd, bin_frequency[freq_idx], 8);

        return true;
}

static int gridseed_cp210x_init(struct cgpu_info *gridseed, int interface)
{
	// Enable the UART
	transfer(gridseed, CP210X_TYPE_OUT, CP210X_REQUEST_IFC_ENABLE, CP210X_VALUE_UART_ENABLE,
			interface, C_ENABLE_UART);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set data control
	transfer(gridseed, CP210X_TYPE_OUT, CP210X_REQUEST_DATA, CP210X_VALUE_DATA,
			interface, C_SETDATA);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set the baud
	uint32_t data = CP210X_DATA_BAUD;
	_transfer(gridseed, CP210X_TYPE_OUT, CP210X_REQUEST_BAUD, 0,
			interface, &data, sizeof(data), C_SETBAUD);

	return 0;
}

static int gridseed_ftdi_init(struct cgpu_info *gridseed, int interface)
{
	int err;

	// Reset
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_RESET,
				FTDI_VALUE_RESET, interface, C_RESET);

	applog(LOG_DEBUG, "%s%i: reset got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set latency
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_LATENCY,
			   GRIDSEED_LATENCY, interface, C_LATENCY);

	applog(LOG_DEBUG, "%s%i: latency got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set data
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_DATA,
				FTDI_VALUE_DATA_AVA, interface, C_SETDATA);

	applog(LOG_DEBUG, "%s%i: data got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set the baud
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_BAUD, FTDI_VALUE_BAUD_AVA,
				(FTDI_INDEX_BAUD_AVA & 0xff00) | interface,
				C_SETBAUD);

	applog(LOG_DEBUG, "%s%i: setbaud got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set Modem Control
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_MODEM,
				FTDI_VALUE_MODEM, interface, C_SETMODEM);

	applog(LOG_DEBUG, "%s%i: setmodemctrl got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set Flow Control
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_FLOW,
				FTDI_VALUE_FLOW, interface, C_SETFLOW);

	applog(LOG_DEBUG, "%s%i: setflowctrl got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	/* Avalon repeats the following */
	// Set Modem Control
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_MODEM,
				FTDI_VALUE_MODEM, interface, C_SETMODEM);

	applog(LOG_DEBUG, "%s%i: setmodemctrl 2 got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set Flow Control
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_FLOW,
				FTDI_VALUE_FLOW, interface, C_SETFLOW);

	applog(LOG_DEBUG, "%s%i: setflowctrl 2 got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	return 0;
}

static int gridseed_pl2303_init(struct cgpu_info *gridseed, int interface)
{
	// Set Data Control
	transfer(gridseed, PL2303_CTRL_OUT, PL2303_REQUEST_CTRL, PL2303_VALUE_CTRL,
			 interface, C_SETDATA);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set Line Control
	uint32_t ica_data[2] = { PL2303_VALUE_LINE0, PL2303_VALUE_LINE1 };
	_transfer(gridseed, PL2303_CTRL_OUT, PL2303_REQUEST_LINE, PL2303_VALUE_LINE,
			 interface, &ica_data[0], PL2303_VALUE_LINE_SIZE, C_SETLINE);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Vendor
	transfer(gridseed, PL2303_VENDOR_OUT, PL2303_REQUEST_VENDOR, PL2303_VALUE_VENDOR,
			 interface, C_VENDOR);

	return 0;
}

static void gridseed_initialise(struct cgpu_info *gridseed, GRIDSEED_INFO *info)
{
	int err, interface;
	enum sub_ident ident;

	if (gridseed->usbinfo.nodev)
		return;

	interface = usb_interface(gridseed);
	ident = usb_ident(gridseed);

	switch(ident) {
		case IDENT_GSD:
			err = 0;
			break;
		case IDENT_GSD1:
			err = gridseed_cp210x_init(gridseed, interface);
			break;
		case IDENT_GSD2:
			err = gridseed_ftdi_init(gridseed, interface);
			break;
		case IDENT_GSD3:
			err = gridseed_pl2303_init(gridseed, interface);
			break;
		default:
			quit(1, "gridseed_intialise() called with invalid %s cgid %i ident=%d",
				gridseed->drv->name, gridseed->sgminer_id, ident);
	}
	if (err)
		return;
}

static bool gridseed_detect_one(libusb_device *dev, struct usb_find_devices *found)
{
	struct cgpu_info *gridseed;
	GRIDSEED_INFO *info;
	int err, wrote, def_freq_inx;
	unsigned char rbuf[GRIDSEED_READ_SIZE];
#if 0
	const char detect_cmd[] =
		"55aa0f01"
		"4a548fe471fa3a9a1371144556c3f64d"
		"2500b4826008fe4bbf7698c94eba7946"
		"ce22a72f4f6726141a0b3287eeeeeeee";
	unsigned char detect_data[52];
#else
	const char detect_cmd[] = "55aac000909090900000000001000000";
	unsigned char detect_data[16];
#endif

	gridseed = usb_alloc_cgpu(&gridseed_drv, GRIDSEED_MINER_THREADS);
	if (!usb_init(gridseed, dev, found))
		goto shin;

	libusb_reset_device(gridseed->usbdev->handle);

	info = (GRIDSEED_INFO*)calloc(sizeof(GRIDSEED_INFO), 1);
	if (unlikely(!info))
		quit(1, "Failed to calloc gridseed_info data");
	gridseed->device_data = (void *)info;

	info->baud = GRIDSEED_DEFAULT_BAUD;
	info->freq = GRIDSEED_DEFAULT_FREQUENCY;
	def_freq_inx = gc3355_find_freq_index(GRIDSEED_DEFAULT_FREQUENCY);
	memcpy(info->freq_cmd, bin_frequency[def_freq_inx], 8);
	info->chips = GRIDSEED_DEFAULT_CHIPS;
	info->voltage = 0;
	info->per_chip_stats = 0;
	info->serial = strdup(gridseed->usbdev->serial_string);
	memset(info->nonce_count, 0, sizeof(info->nonce_count));
	memset(info->error_count, 0, sizeof(info->error_count));

	get_options(info, opt_gridseed_options);
	get_freq(info, opt_gridseed_freq);

	update_usb_stats(gridseed);

	gridseed->usbdev->usb_type = USB_TYPE_STD;
	gridseed_initialise(gridseed, info);

	/* get MCU firmware version */
	hex2bin(detect_data, detect_cmd, sizeof(detect_data));
	if (gc3355_write_data(gridseed, detect_data, sizeof(detect_data))) {
		applog(LOG_DEBUG, "Failed to write work data to %i, err %d",
			gridseed->device_id, err);
		goto unshin;
	}

	/* waiting for return */
	if (gc3355_get_data(gridseed, rbuf, GRIDSEED_READ_SIZE)) {
		applog(LOG_DEBUG, "No response from %i", gridseed->device_id);
		goto unshin;
	}

	if (memcmp(rbuf, "\x55\xaa\xc0\x00\x90\x90\x90\x90", GRIDSEED_READ_SIZE-4) != 0) {
		applog(LOG_DEBUG, "Bad response from %i",
			gridseed->device_id);
		goto unshin;
	}

	info->fw_version = le32toh(*(uint32_t *)(rbuf+8));
	applog(LOG_NOTICE, "Device found, firmware version %08X, driver version %s",
		info->fw_version, gridseed_version);

	gc3355_init(gridseed, info);

	if (!add_cgpu(gridseed))
		goto unshin;

	return true;

unshin:
	usb_uninit(gridseed);
	free(gridseed->device_data);
	gridseed->device_data = NULL;

shin:
	gridseed = usb_free_cgpu(gridseed);
	return false;
}

static bool gridseed_send_task(struct cgpu_info *gridseed, struct work *work)
{
	unsigned char cmd[156];
	memcpy(cmd, "\x55\xaa\x1f\x00", 4);
	memcpy(cmd+4, work->target, 32);
	memcpy(cmd+36, work->midstate, 32);
	memcpy(cmd+68, work->data, 80);
	memcpy(cmd+148, "\xff\xff\xff\xff", 4);  // nonce_max
	memcpy(cmd+152, "\x12\x34\x56\x78", 4);  // taskid
	return (gc3355_write_data(gridseed, cmd, sizeof(cmd)) == 0);
}

/*========== functions for struct device_drv ===========*/

static void gridseed_detect(bool __maybe_unused hotplug)
{
	if (opt_noasic)
		return;
	usb_detect(&gridseed_drv, gridseed_detect_one);
}

static void gridseed_get_statline(char *buf, size_t siz, struct cgpu_info *gridseed) {
	GRIDSEED_INFO *info = gridseed->device_data;
	if (info->per_chip_stats) {
		int i;
		tailsprintf(buf, siz, " N:");
		for (i = 0; i < info->chips; ++i) {
			tailsprintf(buf, siz, " %d", info->nonce_count[i]);
			if (info->error_count[i])
				tailsprintf(buf, siz, "[%d]", info->error_count[i]);
		}
	}
}

static void gridseed_get_statline_before(char *buf, size_t siz, struct cgpu_info *gridseed) {
	GRIDSEED_INFO *info = gridseed->device_data;
	tailsprintf(buf, siz, "%s %4d | ", gridseed->usbdev->serial_string, info->freq);
}

static bool gridseed_prepare_work(struct thr_info __maybe_unused *thr, struct work *work) {
	struct cgpu_info *gridseed = thr->cgpu;
	GRIDSEED_INFO *info = gridseed->device_data;

	cgtime(&info->scanhash_time);
	gc3355_send_cmds(gridseed, str_ltc_reset);
	usb_buffer_clear(gridseed);
	return gridseed_send_task(gridseed, work);
}

static int64_t gridseed_scanhash(struct thr_info *thr, struct work *work, int64_t __maybe_unused max_nonce)
{
	struct cgpu_info *gridseed = thr->cgpu;
	GRIDSEED_INFO *info = gridseed->device_data;
	unsigned char buf[GRIDSEED_READ_SIZE];
	int ret = 0;
	struct timeval old_scanhash_time = info->scanhash_time;
	int elapsed_ms;

	while (!thr->work_restart && (ret = gc3355_get_data(gridseed, buf, GRIDSEED_READ_SIZE)) == 0) {
		if (buf[0] == 0x55 || buf[1] == 0x20) {
			uint32_t nonce = le32toh(*(uint32_t *)(buf+4));
			uint32_t chip = nonce / ((uint32_t)0xffffffff / info->chips);
			info->nonce_count[chip]++;
			if (!submit_nonce(thr, work, nonce))
				info->error_count[chip]++;
		} else {
			applog(LOG_ERR, "Unrecognized response from %i", gridseed->device_id);
			return -1;
		}
	}
	if (ret != 0 && ret != LIBUSB_ERROR_TIMEOUT) {
		applog(LOG_ERR, "No response from %i", gridseed->device_id);
		return -1;
	}

	cgtime(&info->scanhash_time);
	elapsed_ms = ms_tdiff(&info->scanhash_time, &old_scanhash_time);
	return GRIDSEED_HASH_SPEED * (double)elapsed_ms * (double)(info->freq * info->chips);
}

/* driver functions */
struct device_drv gridseed_drv = {
	.drv_id = DRIVER_gridseed,
	.dname = "gridseed",
	.name = "GSD",
	.drv_detect = gridseed_detect,
	.get_statline = gridseed_get_statline,
	.get_statline_before = gridseed_get_statline_before,
	.prepare_work = gridseed_prepare_work,
	.scanhash = gridseed_scanhash,
};
