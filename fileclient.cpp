/* fileclient.cpp
 * Kalina Allen, kallen07
 * Phoebe Yang, yyang08
 * COMP 117, Internet-Scale Distributed Systems
 * FileCopy Assignment
 * 02/19/2018
 *
 * Purpose: Copies a directory of files to some server.
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
#include <iostream>               // for cout
#include <fstream>                // for input files
#include <string>
#include "c150dgmsocket.h"
#include <openssl/sha.h>
#include <cstdlib>
#include <sstream>
#include <stdio.h>

#include "fileutils.h"
#include "globals.h"
#include "packets.h"

/* Always use namespace C150NETWORK with COMP 150 IDS framework! */
using namespace C150NETWORK;
using namespace std;

const int SERVERARG = 1;
const int SRC_ARG = 4;       // name of source file
const int TIMEOUT = 1500;    // in milliseconds

////////////////////////////////////////////////////////////////////////////////
/*************************** FUNCTION DECLARATIONS ****************************/
////////////////////////////////////////////////////////////////////////////////

void check_dir(char *dirname);
bool is_file(string fname);
void parse_command_line_args(int argc, char *argv[], int &networknastiness,
							 int &filenastiness);
bool copy_file(C150DgmSocket *sockfd, string src_dir, string fname, 
			   uint32_t file_id, int filenastiness);
void init_filecopy(C150DgmSocket *sockfd, string fname, uint32_t file_id, size_t fsize);
void send_packets(C150DgmSocket *sockfd, string src_dir, string fname,
				  uint32_t file_id, int filenastiness);
void finish_filecopy(C150DgmSocket *sockfd, string fname, uint32_t file_id);


bool end_to_end_check(C150DgmSocket *sockfd, string fname, string src, int filenastiness);
void send_e2e_message(char *message_to_send, int res_type, char* filename,
					  struct e2e_header *response, C150DgmSocket *sockfd);
bool get_e2e_response(char *incoming_msg_buffer, int type, char * curr_file,
					  struct e2e_header *response);
bool compute_and_compare_hash(string filename, string src, int filenastiness, struct e2e_header *hash_msg);


void send_done_message(C150DgmSocket *sock, uint32_t f_id);
void send_filecopy_request(C150DgmSocket *sock, uint32_t f_id, char *fname, int num_pkts);
void send_file_message(C150DgmSocket *sock, char *request, int response_type, uint32_t file_id);


////////////////////////////////////////////////////////////////////////////////
/*********************************** MAIN *************************************/
////////////////////////////////////////////////////////////////////////////////


int main(int argc, char *argv[])
{

	GRADEME(argc, argv); // Ensure our submission is graded

	int networknastiness, filenastiness;
	struct dirent *sourceFile;  // Directory entry for source file
	DIR *SRC;            // Unix descriptor for open directory
	int num_files = 0;
	C150DgmSocket *sock;

	parse_command_line_args(argc, argv, networknastiness, filenastiness);

	checkDirectory(argv[SRC_ARG]); 	  // Check that the source directory exists
	SRC = opendir(argv[SRC_ARG]);     // Open the source directory
	if (SRC == NULL) {
		fprintf(stderr,"Error opening source directory %s\n", argv[4]);     
		exit(1);
	}

	try {
		/* Create socket to connect to the server */
		sock = new C150NastyDgmSocket(networknastiness);
		sock->setServerName(argv[SERVERARG]);
		sock->turnOnTimeouts(TIMEOUT);
	} catch (C150Exception e) {
		fprintf(stderr, "Unable to create new socket, name socket, or turn on timeouts");
		exit(1);
	}

	/* Copy each file, report error if unable */
	while ((sourceFile = readdir(SRC)) != NULL) {
		/* skip any non-regular files */
		if ((strcmp(sourceFile->d_name, ".") == 0) ||
			(strcmp(sourceFile->d_name, "..")  == 0) ||
			isFile(makeFileName(argv[SRC_ARG], sourceFile->d_name)) == false)
			continue;

		try {
			num_files += 1;
			bool success = copy_file(sock, argv[SRC_ARG], sourceFile->d_name, 
									 num_files, filenastiness);
			if (!success) {
				*GRADING << "Unable to copy file " << sourceFile->d_name 
						<<  " after " << MAX_FILE_RETRIES << " tries" << endl;
			}
  		} catch (C150Exception e) {
			fprintf(stderr, "%s\n", e.formattedExplanation().c_str());
			exit(1);
  		}
	}

	closedir(SRC);
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
	if (argc != 5) {
		fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness>"
					   "<filenastiness> <SRC dir>\n", argv[0]);
		exit(1);
	}

	if ((strspn(argv[2], "0123456789") != strlen(argv[2])) ||
		(strspn(argv[3], "0123456789") != strlen(argv[3]))) 
	{
		fprintf(stderr,"Nastiness is not numeric\n");     
		exit(1);
	}

	networknastiness = atoi(argv[2]);
	filenastiness = atoi(argv[3]);

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
/******************************** SEND FILE ***********************************/
////////////////////////////////////////////////////////////////////////////////


/* purpose: reliably copy a single file.
 * arguments:
 *		sockfd: socket file descriptor for the server
 * 		src_dir: directory from which the file originates
 * 		fname: name of the file to copy
 * 		file_id: id of file to copy
 * 		filenastiness: nastiness to use for disk read/write
 * returns:
 * 		true if the file copy succeeded
 * 		false if they filecopy failed after the globally determined 
 * 			number of retries
 */
bool copy_file(C150DgmSocket *sockfd, string src_dir, string fname, 
			   uint32_t file_id, int filenastiness)
{
	bool copy_success;

	for (int retries = 0; retries < MAX_FILE_RETRIES; retries++) {
		*GRADING << "File: " << fname 
				 << " beginnning transmission, attempt " << retries + 1 << endl;
		size_t file_size = get_source_size(src_dir, fname);
		init_filecopy(sockfd, fname, file_id, file_size);
		send_packets(sockfd, src_dir, fname, file_id, filenastiness);
		finish_filecopy(sockfd, fname, file_id);
		*GRADING << "File: " << fname << " transmission complete, waiting for "
				 << "end-to-end check, attempt " << retries + 1  << endl;
		copy_success = end_to_end_check(sockfd, fname, src_dir, filenastiness);

		if (copy_success) {
			*GRADING << "File: " << fname 
					 << " end-to-end check succeeded, attempt " 
					 << retries + 1  << endl << endl;
			return true;
		} else {
			*GRADING << "File: " << fname 
					 << " end-to-end check failed, attempt " 
					 << retries + 1  << endl << endl;
		}
	}

	return false;
}

/* purpose: notify the server that we are about to begin the filecopy process
 * 			and wait for an acknowledgement from the server
 * arguments:
 *		sockfd: socket file descriptor for the server
 * 		fname: name of the file to copy
 * 		file_id: id of file to copy
 */
void init_filecopy(C150DgmSocket *sockfd, string fname, uint32_t file_id, size_t fsize)
{	
	/* create file copy request msg */
	struct file_copy_header init_msg;
	init_msg.type = SEND;
	strcpy(init_msg.filename, fname.c_str());
	init_msg.file_id = file_id;
	init_msg.file_size = fsize;

	send_file_message(sockfd, (char *)&init_msg, SEND_ACK, file_id);
}


/* purpose: send a file to the server
 * arguments:
 *		sockfd: socket file descriptor for the server
 * 		src_dir: directory from which the file originates
 * 		fname: name of the file to copy
 * 		file_id: id of file to copy
 * 		filenastiness: nastiness to use for disk read/write
 */
void send_packets(C150DgmSocket *sockfd, string src_dir, string fname,
				  uint32_t file_id, int filenastiness)
{
	size_t file_size = get_source_size(src_dir, fname);
	char *buffer = (char *)malloc(file_size);
	read_file_from_disk(src_dir, fname, filenastiness, buffer);
	send_file_packets(sockfd, buffer, file_size, file_id);
	free(buffer);
}

void finish_filecopy(C150DgmSocket *sockfd, string fname, uint32_t file_id)
{
	/* create msg */
	struct file_copy_header done_msg;
	done_msg.type = SEND_DONE;
	strcpy(done_msg.filename, fname.c_str());
	done_msg.file_id = file_id;
	done_msg.file_size = -1;

	send_file_message(sockfd, (char *)&done_msg, DONE_ACK, file_id);
}


/* purpose: send a file copy initialization or done message and wait for a response
 *
 */
void send_file_message(C150DgmSocket *sock, char *request, int response_type, uint32_t file_id)
{
	ssize_t readlen;
	char incomingMessage[sizeof(struct file_copy_header)];
	int attempt = 0;
	bool is_valid = false;

	do {
		/* send message */
		sock->write(request, sizeof(struct file_copy_header));

		/* read response */
		readlen = sock->read(incomingMessage, sizeof(incomingMessage));
		
		if (readlen < 0)
			throw C150NetworkException("Error: server closed the socket.");

		is_valid = validate_server_response(incomingMessage, response_type, file_id);
		if (is_valid) return;

		/* keep reading server messages until timedout */
		while ( sock->timedout() == false) {
			readlen = sock->read(incomingMessage, sizeof(incomingMessage));

			if (readlen < 0)
				throw C150NetworkException("Error: server closed the socket.");

			is_valid = validate_server_response(incomingMessage, response_type, file_id);
			if (is_valid) return;
		}

		/* retry has failed */
		attempt++;

	} while ( attempt < MAX_MSG_RETRY);

	if (attempt == MAX_MSG_RETRY)
		throw C150NetworkException("Fail to send message after max retries.");

}


////////////////////////////////////////////////////////////////////////////////
/****************************** END-TO-END CHECK ******************************/
////////////////////////////////////////////////////////////////////////////////

/* arguments:
 *		sockfd: socket file descriptor for the server
 * 		fname: fname to check
 * returns:
 * 		true if the end to end check succeeded
 *		false otherwise
 */
bool end_to_end_check(C150DgmSocket *sockfd, string fname, string src, int filenastiness)
{
	/* create end to end check request msg */
	struct e2e_header e2e_req;
	e2e_req.type = E2E_REQ;
	strcpy(e2e_req.filename, fname.c_str());
	bzero(e2e_req.hash, MAX_SHA1_BYTES);

	/* send E2E_REQ msg and get E2E_HASH result */
	struct e2e_header hash_msg;
	send_e2e_message((char *)&e2e_req, E2E_HASH, e2e_req.filename, &hash_msg, sockfd);

	/* compare client and server hash result */
	bool hash_match = compute_and_compare_hash(e2e_req.filename, src, filenastiness, &hash_msg);

	/* create E2E_SUCC msg or E2E_FAIL msg */
	struct e2e_header hash_result_msg;
	strcpy(hash_result_msg.filename, fname.c_str());
	bzero(hash_result_msg.hash, MAX_SHA1_BYTES);

	if (hash_match) {
		hash_result_msg.type = E2E_SUCC;
	} else {
		hash_result_msg.type = E2E_FAIL;
	}

	/* send E2E_SUCC/E2E_FAIL msg, get E2E_DONE ack */
	struct e2e_header done_msg;
	send_e2e_message((char*)&hash_result_msg, E2E_DONE, 
					e2e_req.filename, &done_msg, sockfd);

	return hash_match;
}

/* arguments:
 *		sockfd: socket
 * 		message_to_send: message to send to the server, pointer to e2e_header struct
 * 		res_type: expected response type from the server
 *		filename: expected filename from teh server
 * 		response: response from the server, pointer to e2e_header struct
 * returns :
 * 		true: if the message is successful sent and the according response is
 *		received 
 * 		false: otherwise
 */
void send_e2e_message(char *message_to_send, int res_type, char* filename,
					  struct e2e_header *response, C150DgmSocket *sockfd)
{	
	ssize_t readlen;
	char incomingMessage[sizeof(struct e2e_header)];
	bool got_hash;
	int attempt = 0;
	
	do {
		/* send end to end check request msg */
		sockfd->write(message_to_send, sizeof(struct e2e_header));

		/* wait for response */
		readlen = sockfd->read(incomingMessage, sizeof(incomingMessage));

		if (readlen < 0) 
			fprintf(stderr, "ERROR: server closed the socket\n");

		got_hash = get_e2e_response(incomingMessage, res_type, filename, response);
		if (got_hash) break;

		/* keep reading messages until timedout */
		while (sockfd->timedout() == false) {
			readlen = sockfd->read(incomingMessage, sizeof(incomingMessage));

			if (readlen < 0) 
				fprintf(stderr, "ERROR: server closed the socket\n");
			
			got_hash = get_e2e_response(incomingMessage, res_type, 
										filename, response);
			if (got_hash) break;
		}

		if (got_hash) break;

		attempt++;

	} while ( attempt < MAX_MSG_RETRY );

	if ( attempt == MAX_MSG_RETRY )
		throw C150NetworkException("Fail to send message after max retries.\n");

}

/* arguments:
 * 		incoming_msg_buffer: buffer containing a message from the server
 * 		type: the desired message type
 * 		curr_file: name of the current file that we are checking
 * 		response: will put the message in incoming_msg_buffer here if
 *				 get_e2e_response returns true
 * returns :
 * 		true: if the incoming message has the correct type and is 
 * 			  related to curr_file
 * 		false: otherwise
 */
bool get_e2e_response(char *incoming_msg_buffer, int type, char * curr_file,
					  struct e2e_header *response)
{
	if ((uint8_t)incoming_msg_buffer[0] == type) {
		memcpy(response, incoming_msg_buffer, sizeof(*response));
		if (string(response->filename) == curr_file) {
			return true;
		}
	}

	bzero(response, sizeof(*response));
	return false;
}

/* arguments: 
 *		filename: the file to compute hash on
 *		hash_msg: E2E_HASH response received from the server
 * returns: 
 *		true: if the hashes match and the file copied successfully
 *		false: otherwise
 */
bool compute_and_compare_hash(string filename, string src, int filenastiness, 
							  struct e2e_header *hash_msg)
{
	/* compute the hash on the client side */
	unsigned char hash[MAX_SHA1_BYTES];
	bool hash_match = true;
	compute_file_hash(filename, src, filenastiness, hash);

	/* compare client and server hash */
	for (int i=0; i<MAX_SHA1_BYTES; i++)
		if (hash[i] != hash_msg->hash[i])
			return false;

	return hash_match;
}
