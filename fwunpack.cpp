/*
fwunpack

	Nintendo DS Firmware Unpacker
    Copyright (C) 2007  Michael Chisholm (Chishm)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/


#define _CRT_SECURE_NO_DEPRECATE 1
#define _CRT_NONSTDC_NO_DEPRECATE 1

#include <stdio.h>
#include <malloc.h>
#include <string.h>

#include "nds_types.h"
#include "encryption.h"
#include "get_data.h"
#include "get_encrypted_data.h"
#include "get_normal_data.h"
#include "lz77.h"
#include "part345_comp.h"

typedef struct {
	u16	part3_romaddr;
	u16	part4_romaddr;
	u16	part34_crc16;
	u16	part12_crc16;
	u8	fw_identifier[4];
	u16	part1_romaddr;
	u16	part1_ramaddr;
	u16	part2_romaddr;
	u16	part2_ramaddr;
	u16	shift_amounts;
	u16	part5_romaddr;

	u8	fw_timestamp[5];
	u8	console_type;
	u16	unused1;
	u16	user_settings_offset;
	u16	unknown1;
	u16	unknown2;
	u16	part5_crc16;
	u16	unused2;
} FW_HEADER;

#define FW_HEADER_SIZE 0x200

#define COMPRESSION_TYPE_LZ77 1

int decrypt_decompress (u8* src, u8* *dest) {
	GET_DATA get_data = get_encrypted_data;

	get_data.set_address (src);

	int compression_type = (get_data.get_u8() & 0xF0) >> 4;
	int decompressed_size = get_data.get_u8();
	decompressed_size |= get_data.get_u8() << 8;
	decompressed_size |= get_data.get_u8() << 16;

	*dest = (u8*) malloc (decompressed_size);

	switch (compression_type) {
		case COMPRESSION_TYPE_LZ77:
			Decompress_LZ77 (get_data, *dest, decompressed_size);
			break;
		default:
			printf ("CANNOT DECOMPRESS TYPE %d\n", compression_type);
			decompressed_size = 0;
			break;
	}

	return decompressed_size;
}

int decompress (u8* src, u8* *dest) {
	GET_DATA get_data = get_normal_data;

	get_data.set_address (src);

	int compression_type = (get_data.get_u8() & 0xF0) >> 4;
	int decompressed_size = get_data.get_u8();
	decompressed_size |= get_data.get_u8() << 8;
	decompressed_size |= get_data.get_u8() << 16;

	*dest = (u8*) malloc (decompressed_size);

	switch (compression_type) {
		case COMPRESSION_TYPE_LZ77:
			Decompress_LZ77 (get_data, *dest, decompressed_size);
			break;
		default:
			printf ("CANNOT DECOMPRESS TYPE %d\n", compression_type);
			decompressed_size = 0;
			break;
	}

	return decompressed_size;
}

#ifdef _WIN32
# define EXPORT extern "C" __declspec(dllexport)
#else
# define EXPORT extern "C"
#endif

EXPORT bool GetDecyptedFirmware(u8* fw, u32 sz, u8** decryptedFw, u32* decryptedSz) {
	printf ("Nintendo DS Firmware Unpacker by Michael Chisholm (Chishm)\n");

	if (sz != 0x20000 && sz != 0x40000 && sz != 0x80000) {
		return false; // bad size
	}

	const char* mac = "MAC";
	char fwmac[4];
	memcpy (fwmac, &fw[8], 3);
	fwmac[3] = 0;
	if (strcmp (fwmac, mac)) {
		return false; // not a valid id
	}

	// Read the firmware file	
	size_t fw_size = sz;
	u8* fw_data = fw;
	printf ("Firmware size 0x%08llX\n", fw_size);

	FW_HEADER* fw_header = (FW_HEADER*)fw_data;

	u32 arm9boot_romaddr = fw_header->part1_romaddr * (4 << ((fw_header->shift_amounts>>0) & 7));
	u32 arm9boot_ramaddr = 0x02800000 - fw_header->part1_ramaddr * (4 << ((fw_header->shift_amounts>>3) & 7));

	u32 arm7boot_romaddr = fw_header->part2_romaddr * (4 << ((fw_header->shift_amounts>>6) & 7));
	u32 arm7boot_ramaddr = (fw_header->shift_amounts & 0x1000 ? 0x02800000 : 0x03810000) - fw_header->part2_ramaddr * (4 << ((fw_header->shift_amounts>>9) & 7));

	u32 arm9gui_romaddr = fw_header->part3_romaddr * 8;
	u32 arm7gui_romaddr = fw_header->part4_romaddr * 8;

	u32 data_romaddr = fw_header->part5_romaddr * 8;
	
	printf ("ARM9 Boot: From 0x%08X to 0x%08X\n", arm9boot_romaddr, arm9boot_ramaddr);
	printf ("ARM7 Boot: From 0x%08X to 0x%08X\n", arm7boot_romaddr, arm7boot_ramaddr);
	
	printf ("GUI Data: From 0x%08X\n", data_romaddr);
	printf ("ARM9 GUI: From 0x%08X\n", arm9gui_romaddr);
	printf ("ARM7 GUI: From 0x%08X\n", arm7gui_romaddr);

	// Start unpacking
	init_keycode ( ((u32*)fw_data)[2] , 2, 0x0C); // idcode (usually "MACP"), level 2

	u8* decomp_data[5];
	int decomp_size[5];

	// ARM7 boot binary
	decomp_size[0]  = decrypt_decompress (fw_data + arm7boot_romaddr, &decomp_data[0]);

	// ARM9 boot binary
	decomp_size[1]  = decrypt_decompress (fw_data + arm9boot_romaddr, &decomp_data[1]);

	// ARM7 GUI binary
	decomp_size[2] = part345_decompress (NULL, fw_data + arm7gui_romaddr);
	printf ("ARM7 GUI size: 0x%08X\n", decomp_size[2]);
	decomp_data[2] = (u8*) malloc (decomp_size[2]);
	part345_decompress (decomp_data[2], fw_data + arm7gui_romaddr);

	// ARM9 GUI binary
	decomp_size[3] = part345_decompress (NULL, fw_data + arm9gui_romaddr);
	printf ("ARM9 GUI size: 0x%08X\n", decomp_size[3]);
	decomp_data[3] = (u8*) malloc (decomp_size[3]);
	part345_decompress (decomp_data[3], fw_data + arm9gui_romaddr);

	// GUI graphics binary
	decomp_size[4] = part345_decompress (NULL, fw_data + data_romaddr);
	printf ("GUI Data size: 0x%08X\n", decomp_size[4]);
	decomp_data[4] = (u8*) malloc (decomp_size[4]);
	part345_decompress (decomp_data[4], fw_data + data_romaddr);

	*decryptedSz = 0;
	for (int i = 0; i < 5; i++) {
		*decryptedSz += decomp_size[i];
	}

	*decryptedFw = (u8*) malloc (*decryptedSz);
	u8* dfw = *decryptedFw;

	for (int i = 0; i < 5; i++) {
		memcpy (dfw, decomp_data[i], decomp_size[i]);
		dfw += decomp_size[i];
		free (decomp_data[i]);
	}

	printf ("Done\n");

	return true;
}

EXPORT void FreeDecryptedFirmware(u8* fw) {
	free (fw);
}