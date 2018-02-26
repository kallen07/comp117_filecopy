#include "fileutils.h"
// ------------------------------------------------------
//
//                   compute_file_hash
//
// Compute SHA1 hash of the given file, make sure buffer
// reads the same
//
// ------------------------------------------------------

void compute_file_hash(char *filename, unsigned char *hash) {
	ifstream *t;
	stringstream *buffer = new stringstream;
	stringstream *buffer_copy = new stringstream;

	// read from buffer until the same 
	do {
		t = new ifstream(filename);
		*buffer << t->rdbuf();
		*buffer_copy << t->rdbuf();
	} while ( buffer->str() != buffer_copy->str() );


	SHA1((const unsigned char*)buffer->str().c_str(), 
		(buffer->str()).length(), hash);

	delete t;
	delete buffer;
	delete buffer_copy;
}

// ------------------------------------------------------
//
//                   copyFile
//
// Copy a single file from sourcdir to target dir
//
// ------------------------------------------------------

size_t get_source_size(string src, string filename) {
	struct stat statbuf;  
	size_t sourceSize;

	string src_name = makeFileName(src, filename);

	if (!isFile(src_name)) {
		fprintf(stderr, "%s is a directory or other non-regular file. Skippin\n", filename.c_str());
		exit(1);
	}

	if (lstat(src_name.c_str(), &statbuf) != 0) {
		fprintf(stderr,"copyFile: Error stating supplied source file %s\n", src_name.c_str());
		exit(1);
  	}

  	// Make an input buffer large enough for the whole file
	sourceSize = statbuf.st_size;

	return sourceSize;

}

// ------------------------------------------------------
//
//                   is_same_file
// 
// used for comparing file buffers
// returns true if two c strs have the same [file_len] chararcters
//
// ------------------------------------------------------

inline bool is_same_file(char * s1, char * s2, int len) {

	for (int i = 0; i<len; i++) {
		if (s1[i] != s2[i])
			return false;
	}

	return true;

}


// ------------------------------------------------------
//
//                   read_file_from_disk
//
// Args: source directory, filename, file nastiness score, 
//		 buffer to read to, size of the buffer
//
// read the file safely to the buffer without to offset
// the corruption of a nasty read
//
// ------------------------------------------------------


void read_file_from_disk(string src, string filename, int nastiness, char* buffer, size_t sourceSize){
	// vars?
	void *fopenretval;
	size_t len1, len2;
	char *buffer1; char *buffer2; char *buffer3;

	// make filenames with path
	string src_name = makeFileName(src, filename);

	printf("Copying file %s\n", filename.c_str());

	try {
  		// Make an input buffer large enough for the whole file
		buffer1 = (char *)malloc(sourceSize);
		buffer2 = (char *)malloc(sourceSize);
		buffer3 = (char *)malloc(sourceSize);

		NASTYFILE inputFile(nastiness);

		// open and read a file into the buffer
		fopenretval = inputFile.fopen(src_name.c_str(), "rb");

		if (fopenretval == NULL){
			fprintf(stderr, "Error opening file %s\n", filename.c_str());
		}

		// read to a second buffer and compare
		len1 = inputFile.fread(buffer1, 1, sourceSize);

		if (inputFile.fclose() == 0){
			inputFile.fopen(src_name.c_str(), "rb");
			len2 = inputFile.fread(buffer2, 1, sourceSize);
		} else {
			fprintf(stderr, "Error closing file %s\n", filename.c_str());
			exit(1);
		}

		if (len1 != sourceSize || len2 != sourceSize) {
			fprintf(stderr, "Error reading file %s\n", filename.c_str());
		}


		// loop until yields the same read result 
		while ( memcmp(buffer1, buffer2, len1) != 0 ) {
			// read from file again 
			printf("Re-reading file %s\n", filename.c_str());
			if (inputFile.fclose() == 0){
				inputFile.fopen(src_name.c_str(), "rb");
				inputFile.fread(buffer3, 1, sourceSize);
			} else {
				fprintf(stderr, "Error closing file %s\n", filename.c_str());
				exit(1);
			}

			// return the first matching buffer
			if ( memcmp(buffer1, buffer3, len1) == 0 ) {
				memcpy(buffer, buffer1, len1);
				break;
			}
			else if ( memcmp(buffer2, buffer3, len1) == 0 ) {
				memcpy(buffer, buffer2, len1);
				break;
			}
			else {
				if (inputFile.fclose() == 0){				
					inputFile.fopen(src_name.c_str(), "rb");
					inputFile.fread(buffer1, 1, sourceSize);
					memcpy(buffer2, buffer3, len1);
				} else {
					fprintf(stderr, "Error closing file %s\n", filename.c_str());
					exit(1);
				}
			}

		}

		memcpy(buffer, buffer1, len1);

		// free mem and close file
		free(buffer1);
		free(buffer2);
		free(buffer3);

		if (inputFile.fclose() != 0){
			fprintf(stderr, "Error closing file %s\n", filename.c_str());
			exit(1);
		}
	

	} catch (C150Exception e) {
		cerr << "nastyfiletest:copyfile(): Caught C150Exception: " << 
		e.formattedExplanation() << endl;
	}


}


// ------------------------------------------------------
//
//                   write_file_to_disk
//
// Args: target directory, filename, file nastiness score, 
//		 buffer to write, size of the buffer
//
// write the buffer safely to the file without to offset
// the corruption of a nasty write
//
// ------------------------------------------------------

void write_file_to_disk(string target, string filename, int nastiness, char* buffer, size_t sourceSize){

	printf("Writing file %s\n", filename.c_str());

	// vars
	size_t len;
	char *buffer_copy = (char *)malloc(sourceSize);

	// make copy file name
	string targetName = makeFileName(target, filename);

	NASTYFILE outputFile(nastiness);
	
	// loop until write result in sync with buffer
	do {
		// open and write to target
		outputFile.fopen(targetName.c_str(), "wb");
		len = outputFile.fwrite(buffer, 1, sourceSize);

		if (len != sourceSize) {
			fprintf(stderr, "Error writing file %s\n", targetName.c_str());
			exit(1);
		}

		// read from file again to check copied correctly
		if ( outputFile.fclose() == 0 ){
			outputFile.fopen(targetName.c_str(), "rb");
			outputFile.fread(buffer_copy, 1, sourceSize);
			outputFile.fclose();
		} else {
			fprintf(stderr, "Error closing file %s\n", filename.c_str());
			exit(1);
		}
	
	} while ( memcmp(buffer, buffer_copy, len) != 0 );
	
	cout << "Finished writing file " << targetName << endl;

	free(buffer_copy);

}

  
// ------------------------------------------------------
//
//                   makeFileName
//
// Put together a directory and a file name, making
// sure there's a / in between
//
// ------------------------------------------------------

string makeFileName(string dir, string name) {
  stringstream ss;

  ss << dir;
  // make sure dir name ends in /
  if (dir.substr(dir.length()-1,1) != "/")
    ss << '/';
  ss << name;     // append file name to dir
  return ss.str();  // return dir/name
  
}

// ------------------------------------------------------
//
//                   checkDirectory
//
//  Make sure directory exists
//     
// ------------------------------------------------------

void
checkDirectory(char *dirname) {
  struct stat statbuf;  
  if (lstat(dirname, &statbuf) != 0) {
    fprintf(stderr,"Error stating supplied source directory %s\n", dirname);
    exit(8);
  }

  if (!S_ISDIR(statbuf.st_mode)) {
    fprintf(stderr,"File %s exists but is not a directory\n", dirname);
    exit(8);
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

bool
isFile(string fname) {
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
