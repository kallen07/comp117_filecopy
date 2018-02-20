/* fileclient.cpp
 * Kalina Allen, kallen07
 * Phoebe Yang, yyang08
 * COMP 117, Internet-Scale Distributed Systems
 * FileCopy Assignment
 * 02/19/2018
 *
 * Purpose: 
 *          
 */

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


#include "globals.h"
//
// Always use namespace C150NETWORK with COMP 150 IDS framework!
//
using namespace C150NETWORK;
using namespace std;

const int SERVERARG = 1;
const int TIMEOUT = 2000;    // in milliseconds

void checkDirectory(char *dirname);
bool isFile(string fname);
bool end_to_end_check(C150DgmSocket *sockfd, string fname);
bool send_e2e_message(char *message_to_send, int res_type, char* filename,
					  struct E2E_header *response, C150DgmSocket *sockfd);
bool get_e2e_response(char *incoming_msg_buffer, int type, char * curr_file,
					  struct E2E_header *response);

////////////////////////////////////////////////////////////////////////////////
/*********************************** MAIN *************************************/
////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
  	/* Ensure our submission is graded */
	GRADEME(argc, argv);

	int networknastiness;
	int filenastiness;
	string server;
	DIR *SRC;                   // Unix descriptor for open directory
	struct dirent *sourceFile;  // Directory entry for source file

	
	/* Check command line and parse arguments */
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

	/* Check that the source directory exists */
	checkDirectory(argv[4]);

	/* Open the source directory */
	SRC = opendir(argv[4]);
	if (SRC == NULL) {
		fprintf(stderr,"Error opening source directory %s\n", argv[4]);     
		exit(1);
	}

	/* Create socket to connect to the server */
  	C150DgmSocket *sock = new C150DgmSocket();
  	sock->setServerName(argv[SERVERARG]);
  	sock->turnOnTimeouts(TIMEOUT);

	//
	//  Loop copying the files
	//
	//    copyfile takes name of target file
	//
	while ((sourceFile = readdir(SRC)) != NULL) {
		// skip the . and .. names
		if ((strcmp(sourceFile->d_name, ".") == 0) ||
			(strcmp(sourceFile->d_name, "..")  == 0 )) 
			continue;

		// do the copy -- this will check for and 
		// skip subdirectories
		if (isFile(sourceFile->d_name)) {
			end_to_end_check(sock, sourceFile->d_name);
		}
	}

	closedir(SRC);
	return 0;
}

// ------------------------------------------------------
//
//                   checkDirectory
//
//  Make sure directory exists
//     
// ------------------------------------------------------

void checkDirectory(char *dirname) {
	struct stat statbuf;  
	if (lstat(dirname, &statbuf) != 0) {
		fprintf(stderr,"Error: directory %s does not exist\n", dirname);
		exit(1);
	}

	if (!S_ISDIR(statbuf.st_mode)) {
		fprintf(stderr,"File %s exists but is not a directory\n", dirname);
		exit(1);
	}
}


// ------------------------------------------------------
//
//                   isFile
//
//  Make sure the supplied file is not a directory or
//  other non-regular file.
//     
// ------------------------------------------------------

bool isFile(string fname) {
	const char *filename = fname.c_str();
	struct stat statbuf;  
	if (lstat(filename, &statbuf) != 0) {
		fprintf(stderr,"isFile: Error stating supplied source file %s\n", filename);
		return false;
	}

	if (!S_ISREG(statbuf.st_mode)) {
		fprintf(stderr,"isFile: %s exists but is not a regular file\n", filename);
		return false;
	}
	return true;
}


/* arguments:
 *		sockfd: socket file descriptor for the server
 * 		fname: fname to check
 * returns:
 * 		true if the end to end check succeeded
 *		false otherwise
 */
bool end_to_end_check(C150DgmSocket *sockfd, string fname)
{
	/* create end to end check request msg */
	struct E2E_header e2e_req;
	e2e_req.type = E2E_REQ;
	strcpy(e2e_req.filename, fname.c_str());
	bzero(e2e_req.hash, MAX_SHA1_BYTES);

	/* get hash from server */
	struct E2E_header hash_msg;
	send_e2e_message((char *)&e2e_req, E2E_HASH, e2e_req.filename, &hash_msg, sockfd);

	// compare the hash
	ifstream *t;
	stringstream *buffer;
	unsigned char hash[20];

	t = new ifstream(e2e_req.filename);
	buffer = new stringstream;
	*buffer << t->rdbuf();
	SHA1((const unsigned char*)buffer->str().c_str(), 
		(buffer->str()).length(), hash);
	delete t;
	delete buffer;

	struct E2E_header hash_result_msg;
	strcpy(hash_result_msg.filename, fname.c_str());
	bzero(hash_result_msg.hash, MAX_SHA1_BYTES);

	if (hash == hash_msg.hash) {
		hash_result_msg.type = E2E_SUCC;
	} else {
		hash_result_msg.type = E2E_FAIL;
	}

	// send a sucess/fail message
	struct E2E_header done_msg;
	send_e2e_message((char*)&hash_result_msg, E2E_DONE, 
					e2e_req.filename, &done_msg, sockfd);

	return true; // to do fix this
}

bool send_e2e_message(char *message_to_send, int res_type, char* filename,
					  struct E2E_header *response, C150DgmSocket *sockfd)
{	

	ssize_t readlen;
	char incomingMessage[sizeof(struct E2E_header)];
	bool got_hash;
	
	do {
		/* send end to end check request msg */
		sockfd->write(message_to_send, sizeof(struct E2E_header));

		/* wait for response */
		readlen = sockfd->read(incomingMessage, sizeof(incomingMessage));
		got_hash = get_e2e_response(incomingMessage, res_type, filename, response);
		if (got_hash) break;

		/* keep reading messages until timedout */
		while (sockfd->timedout() == false) {
			readlen = sockfd->read(incomingMessage, sizeof(incomingMessage));

			if (readlen < 0) {
				fprintf(stderr, "ERROR: server closed the socket");
			}

			got_hash = get_e2e_response(incomingMessage, res_type, 
										filename, response);
			if (got_hash) break;
		}

	// NEEDSWORK should we limit the number of tries?
	} while (sockfd->timedout() == true);

	return true;
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
					  struct E2E_header *response)
{
	if ((uint8_t)incoming_msg_buffer[0] == type) {
		memcpy(response, incoming_msg_buffer, sizeof(*response));
		if (response->filename == curr_file) {
			return true;
		}
	}

	bzero(response, sizeof(*response));
	return false;
}
