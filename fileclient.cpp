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

//
// Always use namespace C150NETWORK with COMP 150 IDS framework!
//
using namespace C150NETWORK;
using namespace std;


void checkDirectory(char *dirname);
bool isFile(string fname);

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
			// do End to End check
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
