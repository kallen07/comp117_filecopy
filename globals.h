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

#define MAX_FILE_BYTES 1000000   /* 1 MB */
#define MAX_FILENAME_BYTES 260
#define MAX_DATA_BYTES 400
#define MAX_SHA1_BYTES 20
#define MSG_TYPE_BYTES 1

#define NUM_READ_BUFFER 10
#define PKT_WINDOW_SIZE 40
#define MAX_PKT_RETRY 8
#define MAX_MSG_RETRY 6

#define MAX_UDP_MSG_BYTES 512
#define MAX_FILE_RETRIES 3


struct __attribute__((__packed__)) file_copy_header {
	uint8_t type;
	char filename[MAX_FILENAME_BYTES];
	uint32_t file_id;
};

struct __attribute__((__packed__)) filedata {
	uint8_t type;
	uint32_t file_id;
	uint64_t start_byte;
	uint64_t data_len;
	char data[MAX_DATA_BYTES];
};

struct __attribute__((__packed__)) filedata_ack {
	uint8_t type;
	uint32_t file_id;
	uint64_t start_byte;
};

struct __attribute__((__packed__)) e2e_header {
	uint8_t type;
	char filename[MAX_FILENAME_BYTES];
	unsigned char hash[MAX_SHA1_BYTES];
};


enum msg_types {SEND = 1, SEND_ACK = 2, PACKET = 3, PACKET_ACK  = 4, 
				SEND_DONE = 5, DONE_ACK = 6, E2E_REQ = 7, E2E_HASH = 8, 
				E2E_SUCC = 9, E2E_FAIL = 10, E2E_DONE = 11};

#endif
