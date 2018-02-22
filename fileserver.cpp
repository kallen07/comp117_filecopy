/* fileserver.cpp
 * Kalina Allen, kallen07
 * Phoebe Yang, yyang08
 * COMP 117, Internet-Scale Distributed Systems
 * FileCopy Assignment
 * 02/20/2018
 *
 * Purpose: 
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

#include "globals.h"
//
// Always use namespace C150NETWORK with COMP 150 IDS framework!
//
using namespace C150NETWORK;
using namespace std;

void checkDirectory(char *dirname);
bool isFile(string fname);
bool handle_e2e_request(C150DgmSocket *sock, char incomingMessage[], uint8_t type);

////////////////////////////////////////////////////////////////////////////////
/*********************************** MAIN *************************************/
////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
	/* Ensure our submission is graded */
	GRADEME(argc, argv);

	int networknastiness;
	int filenastiness;
	DIR *TARGET;                   // Unix descriptor for open directory

	ssize_t readlen;
	char incomingMessage[sizeof(struct E2E_header)];

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

	/* Check that the source directory exists */
	checkDirectory(argv[3]);

	/* Open the source directory */
	TARGET = opendir(argv[3]);
	if (TARGET == NULL) {
		fprintf(stderr,"Error opening source directory %s\n", argv[4]);     
		exit(1);
	}

	try {
		/* socket for listening messages */
<<<<<<< HEAD
		C150DgmSocket *sock = new C150NastyDgmSocket(networknastiness);

		/* infinite loop processing messages */
		while (1) {
			/* read a packet */
=======
	    C150DgmSocket *sock = new C150NastyDgmSocket(networknastiness);

	    /* infinite loop processing messages */
	    while (1) {
	    	/* read a packet */
>>>>>>> ba2130d7755c277f9ef37bcf2d69d029a87829e9
			readlen = sock -> read(incomingMessage, sizeof(incomingMessage));
			
			if (readlen == 0) 
				continue;

			/* cast the first byte to msg_type and handle accordingly */
			msg_types type = static_cast<msg_types>((uint8_t)incomingMessage[0]);

			switch ( type ) {
				case E2E_REQ:
				case E2E_SUCC:
				case E2E_FAIL:
					handle_e2e_request(sock, incomingMessage, type);
					break;
				case SEND:
				case SEND_DONE:
					break; // filecopy: to be implement
				case PACKET:
					break;
				default:
					fprintf(stderr, "No matching message type.\n");
			}

<<<<<<< HEAD
		}

	} catch (C150NetworkException e) {
		cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
=======
	    }

	} catch (C150NetworkException e) {
    	cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
>>>>>>> ba2130d7755c277f9ef37bcf2d69d029a87829e9
	}

	return 0;
}


/* arguments:
 * 		sock: socket
 *		incomingMessage: incoming message buffer
 *		type: type of the message received from the client
 * returns :
 * 		true: if the incoming message is processed and response is returned
 * 		false: otherwise
 */
bool handle_e2e_request(C150DgmSocket *sock, char incomingMessage[], uint8_t type)
{
	// NEEDSWORK: grading logs dont seem to be logging all msgs

	/* initalize request and response e2e_header */
	struct E2E_header request;
	struct E2E_header response;

	memcpy((char *)&request, incomingMessage, sizeof(request));
	char *fname = request.filename;

	if (type == E2E_REQ) {

		/* print to grading log */
		*GRADING << "File: " << fname << " received, beginning end-to-end check\n";
		
		/* compute the hash on the server side */
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

		/* construct response header */
		response.type = E2E_HASH;
		strcpy(response.filename, request.filename);		
		for (int i=0; i<MAX_SHA1_BYTES; i++)
			response.hash[i] = hash[i];

		/* send response */
		sock->write((char *)&response, sizeof(struct E2E_header));

		return true;

	} else if ( type == E2E_SUCC || type == E2E_FAIL ) {

		/* print to grading log and console */
		if (type == E2E_SUCC) {
			printf("File %s copied successfully\n", fname);
			*GRADING << "File: " << fname << " end-to-end check succeeded\n";
		} else {
			*GRADING << "File: " << fname << " end-to-end check failed\n";			
		}

		/* construct response header */
		response.type = E2E_DONE;
		strcpy(response.filename, request.filename);
		bzero(response.hash, MAX_SHA1_BYTES);

		/* send response */
		sock->write((char *)&response, sizeof(struct E2E_header));

		return true;
	}

	return false;
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