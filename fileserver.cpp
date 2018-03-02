/* fileserver.cpp
 * Kalina Allen, kallen07
 * Phoebe Yang, yyang08
 * COMP 117, Internet-Scale Distributed Systems
 * FileCopy Assignment
 * 02/20/2018
 *
 * Purpose: TODO
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
void send_filecopy_init_ack(
	C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
	char curr_filename[MAX_FILENAME_BYTES], uint32_t *curr_fileid, 
	bool is_duplicate);
void receive_packet(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
			   uint32_t curr_fileid, char curr_file_buff[MAX_FILE_BYTES],
			   uint64_t *curr_file_bytes);
bool is_send_done(
	C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
	char curr_filename[MAX_FILENAME_BYTES], uint32_t curr_fileid, string dest_dir,
  	char curr_file_buff[MAX_FILE_BYTES], uint64_t curr_file_bytes, 
  	int filenastiness);
void send_e2e_hash(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
				   char *curr_filename[MAX_FILENAME_BYTES], bool is_duplicate);
void send_e2e_done_ack(
	C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
	char *curr_filename[MAX_FILENAME_BYTES], bool is_duplicate);


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
		cerr << argv[0] << ": caught C150NetworkException: " 
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
 * NEEDSWORK: add support for multiple clients
 */
void handle_message_loop(C150DgmSocket *sock, string target_dir, int filenastiness)
{
	ssize_t readlen;
	char buffer[MAX_UDP_MSG_BYTES];
	bool waiting_for_filedata = false;       // server state
	bool waiting_for_e2e_results = false;    // server state
	msg_types type;
	char curr_filename[MAX_FILENAME_BYTES];
	uint32_t curr_fileid;
	// NEEDSWORK should not need to write into a buffer
	// before writing to disk?
	char curr_file_buff[MAX_FILE_BYTES];
	uint64_t curr_file_bytes;

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
					send_filecopy_init_ack(sock, buffer, curr_filename, 
										   &curr_fileid, waiting_for_filedata);
					waiting_for_filedata = true;
				}
				break;
			case PACKET:
				if (waiting_for_filedata) {
					receive_packet(sock, buffer, curr_fileid, 
								   curr_file_buff, &curr_file_bytes);
				}
				break;
			case SEND_DONE:
				if (waiting_for_filedata) {
					if (is_send_done(sock, buffer, curr_filename, curr_fileid, 
									target_dir, curr_file_buff, curr_file_bytes,
									filenastiness)) {
						waiting_for_filedata = false;
					}
				}
				break;
			case E2E_REQ:
				if (!waiting_for_filedata) {
					send_e2e_hash(sock, buffer, (char **)&curr_filename,
								  waiting_for_e2e_results);
					waiting_for_e2e_results = true;
				}
				break;
			case E2E_SUCC:
				if (waiting_for_e2e_results) {
					send_e2e_done_ack(sock, buffer, (char **)&curr_filename,
									  !waiting_for_e2e_results);
					waiting_for_e2e_results  = false;
				}
				break;
			case E2E_FAIL:
				if (waiting_for_e2e_results) {
					send_e2e_done_ack(sock, buffer, (char **)&curr_filename,
									  !waiting_for_e2e_results);
					waiting_for_e2e_results = false;
				}
				break;
			default:
				fprintf(stderr, "No matching message type %i\n", type);
		}
	}
}


void send_filecopy_init_ack(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
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
	cerr << "File: " << request.filename
			 << " starting to receive file" << endl;
	
}

void receive_packet(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
			   uint32_t curr_fileid, char curr_file_buff[MAX_FILE_BYTES],
			   uint64_t *curr_file_bytes)
{
	struct filedata packet;

	memcpy(&packet, incoming_msg, sizeof(packet));

	/* write the data in the packet */
	if (packet.file_id == curr_fileid) {
		memcpy(&(curr_file_buff[packet.start_byte]), &(packet.data), packet.data_len);
		*curr_file_bytes = packet.start_byte + packet.data_len;
	}

	/* send an ack */
	struct filedata_ack response;
	response.type = PACKET_ACK;
	response.file_id = curr_fileid;
	response.start_byte = packet.start_byte;

	/* write response */
	sock -> write((char *)&response, sizeof(response));
}

bool is_send_done(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
		         char curr_filename[MAX_FILENAME_BYTES], 
  				 uint32_t curr_fileid, string dest_dir,
  				 char curr_file_buff[MAX_FILE_BYTES], uint64_t curr_file_bytes,
  				 int filenastiness)
{
	struct file_copy_header request;
	memcpy(&request, incoming_msg, sizeof(request));

	if (request.file_id == curr_fileid) {

		/* write buffer to disk */
		write_file_to_disk(dest_dir, curr_filename, filenastiness, 
						   curr_file_buff, curr_file_bytes);

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
 * returns :
 * 		true: if the incoming message is processed and response is returned
 * 		false: otherwise
 */
// TODO update comments
void send_e2e_hash(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
				   char *curr_filename[MAX_FILENAME_BYTES], bool is_duplicate)
{
	struct e2e_header request;
	struct e2e_header response;

	memcpy((char *)&request, incoming_msg, sizeof(request));

	/* if we already sent a hash without recieving a success/fail 
	   confirmation from the server, then don't handle new request.
	   also, ignore stale requests */
	if (is_duplicate && strcmp(*curr_filename, request.filename) != 0)
	{
		return;
	}

	/* print to grading log */
	cerr << "File: " << request.filename
			 << " received, beginning end-to-end check" << endl;
	
	/* compute the hash*/
	// NEEDSWORK use filenastiness here
	ifstream *t;
	stringstream *buffer;
	unsigned char hash[MAX_SHA1_BYTES];
	t = new ifstream(request.filename);
	buffer = new stringstream;
	*buffer << t->rdbuf();
	SHA1((const unsigned char*)buffer->str().c_str(), 
		(buffer->str()).length(), hash);
	delete t;
	delete buffer;

	/* construct and send hash */
	response.type = E2E_HASH;
	strcpy(response.filename, request.filename);	
	memcpy(&response.hash, &hash, MAX_SHA1_BYTES);	
	sock->write((char *)&response, sizeof(struct e2e_header));

	/* update state */
	memcpy(curr_filename, request.filename, MAX_FILENAME_BYTES);
}

void send_e2e_done_ack(C150DgmSocket *sock, char incoming_msg[MAX_UDP_MSG_BYTES],
					   char *curr_filename[MAX_FILENAME_BYTES], bool is_duplicate)
{
	bool is_valid_duplicate;
	struct e2e_header request;
	char fname[MAX_FILENAME_BYTES];

	memcpy(&request, incoming_msg, sizeof(request));
	memcpy(fname, request.filename, MAX_FILENAME_BYTES);

	is_valid_duplicate = is_duplicate && strcmp(fname, *curr_filename) == 0;

	// NEEDSWORK: if the file check succeeded, change the name of the file

	if (!is_duplicate || is_valid_duplicate)
	{
		/* construct response */
		struct e2e_header response;
		response.type = E2E_DONE;
		memcpy(&response.filename, fname, MAX_FILENAME_BYTES);
		bzero(&response.hash, sizeof(response.hash));

		/* write response */
		sock -> write((char *)&response, sizeof(response));

		/* print to grading log and console */
		if (request.type == E2E_SUCC) {
			cerr << "File: " << fname << " end-to-end check succeeded\n" << endl;
		} else {
			cerr << "File: " << fname << " end-to-end check failed\n" << endl;			
		}
	}
}


