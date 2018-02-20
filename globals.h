/* globals.h
 * Kalina Allen, kallen07
 * Phoebe Yang, yyang08
 * COMP 117, Internet-Scale Distributed Systems
 * FileCopy Assignment
 * 02/19/2018
 *
 * Purpose: to share global variables & datatypes
 *          between the client and server
 */

#ifndef GLOBALS_H
#define GLOBALS_H

#define MAX_FILENAME_BYTES 260
#define MAX_DATA_BYTES 400
#define MAX_SHA1_BYTES 40

struct __attribute__((__packed__)) file_copy_header {
	uint8_t type;
	char filename[FILENAME_LEN];
	uint64_t num_packets;
};

struct __attribute__((__packed__)) filedata {
	uint8_t type;
	uint32_t file_id;
	uint64_t packet_id;
	uint64_t start_byte;
	uint64_t data_len;
	char data[MAX_DATA_LEN];
};

struct __attribute__((__packed__)) filedata_ACK {
	uint8_t type;
	uint32_t file_id;
	uint64_t packet_id;
};

struct __attribute__((__packed__)) E2E_header {
	uint8_t type;
	char filename[FILENAME_LEN];
	char hash[MAX_SHA1_BYTES];
};


enum msg_types {SEND = 1, SEND_ACK, PACKET, PACKET_ACK, SEND_DONE, DONE_ACK, 
				E2E_REQ, E2E_HASH, E2E_SUCC, E2E_FAIL, E2E_DONE};

#endif