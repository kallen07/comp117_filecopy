/* fileserver.cpp
 * Kalina Allen, kallen07
 * Phoebe Yang, yyang08
 * COMP 117, Internet-Scale Distributed Systems
 * FileCopy Assignment
 * 02/20/2018
 *
 *          
 */
#include "c150nastydgmsocket.h"
#include "c150nastyfile.h"        // for c150nastyfile & framework
#include "c150grading.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>                // for errno string formatting
#include <cerrno>
#include <iostream>               // for cerr
#include <fstream>                // for input files
#include <string>
#include "c150dgmsocket.h"
#include <openssl/sha.h>
#include <cstdlib>
#include <sstream>
#include <stdio.h>
#include "fileutils.h"
#include "packets.h"
#include "globals.h"
#include "fileutils.h"

/* Always use namespace C150NETWORK with COMP 150 IDS framework! */
using namespace C150NETWORK;
using namespace std;

const int TARGET_ARG = 3;      // name of folder in which to copy files

////////////////////////////////////////////////////////////////////////////////
/*************************** FUNCTION DECLARATIONS ****************************/
////////////////////////////////////////////////////////////////////////////////

void parse_command_line_args(int argc, char *argv[], int &networknastiness,
							 int &filenastiness);
void handle_message_loop(C150DgmSocket *sock, string target_dir, int filenastiness);
size_t send_filecopy_init_ack(
	C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
	char curr_filename[MAX_FILENAME_BYTES], uint32_t *curr_fileid, 
	bool is_duplicate);
void receive_packet(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
			   uint32_t curr_fileid, char curr_file_buff[]);
bool is_send_done(
	C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
	char curr_filename[MAX_FILENAME_BYTES], uint32_t curr_fileid, string dest_dir,
  	char curr_file_buff[], size_t filesize, int filenastiness);
void send_e2e_hash(C150DgmSocket *sock, char incoming_msg[],
				   string target, int nastiness);
void send_e2e_done_ack(
	C150DgmSocket *sock, char incoming_msg[], string dir);


////////////////////////////////////////////////////////////////////////////////
/*********************************** MAIN *************************************/
////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
	GRADEME(argc, argv); 	// Ensure our submission is graded

	int networknastiness, filenastiness;
	DIR *TARGET;    // Unix descriptor for open directory

	parse_command_line_args(argc, argv, networknastiness, filenastiness);
	checkDirectory(argv[3]); 	// Check that the source directory exists
	TARGET = opendir(argv[3]); 	// Open the source directory
	if (TARGET == NULL) {
		fprintf(stderr,"Error opening source directory %s\n", argv[4]);     
		exit(1);
	}

	try {
		/* create socket to listen for message */
		C150DgmSocket *sock = new C150NastyDgmSocket(networknastiness);
		/* enter receive and handle message loop */
		handle_message_loop(sock, argv[TARGET_ARG], filenastiness);
	} catch (C150NetworkException e) {
		*GRADING << argv[0] << ": caught C150NetworkException: " 
			 << e.formattedExplanation() << endl;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
/**************************** VERIFY USER INPUT *******************************/
////////////////////////////////////////////////////////////////////////////////

/* purpose: parse and validate command line arguments
 *			update caller's networknastiness and filenastiness
 */
void parse_command_line_args(int argc, char *argv[], int &networknastiness,
							 int &filenastiness)
{
	/* Check command line and parse arguments */
	if (argc != 4) {
		fprintf(stderr,"Correct syntxt is: %s <networknastiness>"
					   "<filenastiness> <TARGET dir>\n", argv[0]);
		exit(1);
	}

	if ((strspn(argv[1], "0123456789") != strlen(argv[1])) ||
		(strspn(argv[2], "0123456789") != strlen(argv[2]))) 
	{
		fprintf(stderr,"Nastiness is not numeric\n");     
		exit(1);
	}

	networknastiness = atoi(argv[1]);
	filenastiness = atoi(argv[2]);

	if (networknastiness < 0 || networknastiness > 4) {
		fprintf(stderr,"Network nastiness %i is out of the range 0-4\n",
				networknastiness);   
		exit(1);  
	}
	if (filenastiness < 0 || filenastiness > 5) {
		fprintf(stderr,"File nastiness %i is out of the range 0-5\n",
			    filenastiness);
		exit(1);
	}
}

////////////////////////////////////////////////////////////////////////////////
/************************** HANDLE CLIENT REQUESTS ****************************/
////////////////////////////////////////////////////////////////////////////////

/* purpose: recieve and handle client requests
 * aruguments:
 * 		sock: socket on which to listen for requests
 */
void handle_message_loop(C150DgmSocket *sock, string target_dir, int filenastiness)
{
	// NEEDSWORK: curr_filename should be better switched to string
	ssize_t readlen;
	char buffer[MAX_UDP_MSG_BYTES];
	bool waiting_for_filedata = false;       // server state
	bool waiting_for_e2e_results = false;    // server state
	msg_types type;
	char curr_filename[MAX_FILENAME_BYTES];
	uint32_t curr_fileid;
	char *curr_file_buff; 	// buffer for storing packets
	bool buff_init = false;
	size_t filesize;

	while (1) {
		/* read a message */
		readlen = sock -> read(buffer, sizeof(buffer));
		if (readlen == 0) {
			/* client closed socket so reset state */
			waiting_for_filedata = false;
			waiting_for_e2e_results = false;
			continue;
		}

		/* determine message type and handle accordingly */
		type = static_cast<msg_types>((uint8_t)buffer[0]);
		//fprintf(stderr, "received a msg of type %i\n",  type);
		switch (type) {
			case SEND:
				if (!waiting_for_e2e_results) {
					filesize = send_filecopy_init_ack(sock, buffer, curr_filename, 
										   &curr_fileid, waiting_for_filedata);
					if (!buff_init){
						curr_file_buff = (char*)malloc(filesize);
						buff_init = true;
					}
					waiting_for_filedata = true;
				}
				break;
			case PACKET:
				if (waiting_for_filedata) {
					receive_packet(sock, buffer, curr_fileid, curr_file_buff);
				}
				break;
			case SEND_DONE:
				if (waiting_for_filedata) {
					if (is_send_done(sock, buffer, curr_filename, curr_fileid, 
									target_dir, curr_file_buff, filesize,
									filenastiness)) {
						waiting_for_filedata = false;
						free(curr_file_buff); // free buffer after writing to disk
						buff_init = false;
					}
				}
				break;
			case E2E_REQ:
				if (!waiting_for_filedata) {
					send_e2e_hash(sock, buffer, target_dir, filenastiness);
					waiting_for_e2e_results = true;
				}
				break;
			case E2E_SUCC:
				send_e2e_done_ack(sock, buffer, target_dir);
				waiting_for_e2e_results  = false;
				break;
			case E2E_FAIL:
				send_e2e_done_ack(sock, buffer, target_dir);
				waiting_for_e2e_results = false;
				break;
			default:
				fprintf(stderr, "No matching message type %i\n", type);
		}
	}
}


/* purpose: send filecopy acknowledgment to the client
 * aruguments:
 * 		sock: socket on which to listen for requests
 *		incoming_msg: income request from the client
 *		curr_filename: the name of the file to-be-copied
 *		curr_fileid: the id of the file to-be-copied
 *		is_duplicate: did we already recevie a filecopy initalization message?
 * returns: 
 *		the size of the file we are going to copy
 */

size_t send_filecopy_init_ack(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
							char curr_filename[MAX_FILENAME_BYTES], 
							uint32_t *curr_fileid, bool is_duplicate)
{
	bool is_valid_duplicate;
	struct file_copy_header request;

	memcpy(&request, incoming_msg, sizeof(request));
	is_valid_duplicate = is_duplicate && request.file_id == *curr_fileid &&
						 strcmp(request.filename, curr_filename) == 0;

	if (!is_duplicate || is_valid_duplicate)
	{
		/* construct response */
		struct file_copy_header response;
		response.type = SEND_ACK;
		memcpy(&response.filename, request.filename, MAX_FILENAME_BYTES);
		response.file_id = request.file_id;

		/* write response */
		sock -> write((char *)&response, sizeof(response));

		/* Update server state */
		memcpy(curr_filename, request.filename, MAX_FILENAME_BYTES);
		*curr_fileid = request.file_id;
	}

	/* print to grading log */
	*GRADING << "File: " << request.filename
			 << " starting to receive file" << endl;

	return request.file_size;
	
}

/* purpose: send packet ack to the client and store packet data into buffer
 * aruguments:
 * 		sock: socket on which to listen for requests
 *		incoming_msg: income request from the client
 *		curr_fileid: the id of the copying file
 *		curr_file_buff: buffer to hold the packet data before writing to disk
 */

void receive_packet(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
			   uint32_t curr_fileid, char curr_file_buff[])
{
	struct filedata packet;

	memcpy(&packet, incoming_msg, sizeof(packet));

	/* write the data in the packet to the buffer */
	if (packet.file_id == curr_fileid) {
		memcpy(&(curr_file_buff[packet.start_byte]), &(packet.data), packet.data_len);
	}

	/* send an ack */
	struct filedata_ack response;
	response.type = PACKET_ACK;
	response.file_id = curr_fileid;
	response.start_byte = packet.start_byte;

	/* write response */
	sock -> write((char *)&response, sizeof(response));
}

/* purpose: send filecopy done ack to the client and write the copied file to disk
 * aruguments:
 * 		sock: socket on which to listen for requests
 *		incoming_msg: income request from the client
 *		curr_filename: the name of the copied file 
 *		curr_fileid: the id of the copied file
 *		dest_dir: target directory
 *		curr_file_buff: buffer to hold the copied data
 *		filesize: size of the copied file
 *		filenastiness: nastiness level for disk write
 *
 * return: true if the file is written to the disk,
 *		   false if the done message dont match the current fileid
 */
bool is_send_done(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
		         char curr_filename[MAX_FILENAME_BYTES], 
  				 uint32_t curr_fileid, string dest_dir,
  				 char curr_file_buff[], size_t filesize,
  				 int filenastiness)
{
	struct file_copy_header request;
	memcpy(&request, incoming_msg, sizeof(request));

	if (request.file_id == curr_fileid) {

		/* write buffer to disk as TMP file */
		write_file_to_disk(dest_dir, curr_filename, filenastiness, 
						   curr_file_buff, filesize);

		/* construct response */
		struct file_copy_header response;
		response.type = DONE_ACK;
		memcpy(&response.filename, request.filename, MAX_FILENAME_BYTES);
		response.file_id = request.file_id;

		/* write response */
		sock -> write((char *)&response, sizeof(response));
		
		return true;
	}

	return false;
}


/* arguments:
 * 		sock: socket
 *		buffer: incoming message buffer
 *		target: target directory
 *		nastiness: file nastiness
 * purpose: compute the hash of the requested file and send the response back
 * 		to the client
 */
void send_e2e_hash(C150DgmSocket *sock, char incoming_msg[],
				   string target, int nastiness)
{
	struct e2e_header request;
	struct e2e_header response;

	memcpy((char *)&request, incoming_msg, sizeof(request));

	/* print to grading log */
	*GRADING << "File: " << request.filename
			 << " received, beginning end-to-end check" << endl;
	
	/* compute the hash*/
	unsigned char hash[MAX_SHA1_BYTES];
	string tmp_filename = string(request.filename) + ".TMP";
	compute_file_hash(tmp_filename, target, nastiness, hash);

	/* construct and send hash */
	response.type = E2E_HASH;
	strcpy(response.filename, request.filename);	
	memcpy(&response.hash, &hash, MAX_SHA1_BYTES);	
	sock->write((char *)&response, sizeof(struct e2e_header));

}

/* arguments:
 * 		sock: socket
 *		buffer: incoming message buffer
 *		dir: target directory
 * purpose: if the client indicates e2e success, rename the file;
 * 		if the client indicates e2e fails, removes the TMP file.
 */
void send_e2e_done_ack(C150DgmSocket *sock, char incoming_msg[], string dir)
{
	// bool is_valid_duplicate;
	struct e2e_header request;
	char fname[MAX_FILENAME_BYTES];

	memcpy(&request, incoming_msg, sizeof(request));
	memcpy(fname, request.filename, MAX_FILENAME_BYTES);

	/* rename file from .TMP to permanent if succ, remove otherwise */
	if ( request.type == E2E_SUCC )
		rename_tmp(fname, dir);
	else
		remove_tmp(fname, dir);

	/* construct response */
	struct e2e_header response;
	response.type = E2E_DONE;
	memcpy(&response.filename, fname, MAX_FILENAME_BYTES);
	bzero(&response.hash, sizeof(response.hash));

	/* write response */
	sock -> write((char *)&response, sizeof(response));

	/* print to grading log and console */
	if (request.type == E2E_SUCC) {
		*GRADING << "File: " << fname << " end-to-end check succeeded\n" << endl;
	} else {
		*GRADING << "File: " << fname << " end-to-end check failed\n" << endl;			
	}

}


