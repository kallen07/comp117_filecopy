#include "fileutils.h"

// ------------------------------------------------------
//
//                   compute_file_hash
//
// Compute SHA1 hash of the given nastyfile. To make sure buffer
// reads the same, it loops reading to buffers until two 
// buffers are consistent.
//
// ------------------------------------------------------

void compute_file_hash(char *filename, unsigned char *hash) {
	ifstream *t;
	stringstream *buffer = new stringstream;
	stringstream *buffer_copy = new stringstream;

	// read from buffer until the same 
	// NEEDSWORK use filenastiness here
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
//                   get_source_size
//
// Return the size of the file in number of bytes
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
//                   read_buffer_safe
//
// Read file from disk to NUM_READ_BUFFER number of buffers
// Compare copies and return the majority vote among buffers
//
// ------------------------------------------------------

void read_buffer_safe(string src_name, int nastiness, char* buffer, size_t sourceSize){

	char *buffers [NUM_READ_BUFFER];
	int vote[NUM_READ_BUFFER] = {0};
	void *fopenretval;
	size_t len;
	int max_index;

	// open as nasty file
	NASTYFILE inputFile(nastiness);


	// read to multiple buffers
	for (int i = 0; i<NUM_READ_BUFFER; i++){
		buffers[i] = (char*)malloc(sourceSize);
		fopenretval = inputFile.fopen(src_name.c_str(), "rb");

		if (fopenretval == NULL){
			fprintf(stderr, "Error opening file %s\n", src_name.c_str());
		}

		len = inputFile.fread(buffers[i], 1, sourceSize);

		if (len != sourceSize){
			fprintf(stderr, "Error reading file %s\n", src_name.c_str());
		}

		if ( inputFile.fclose() != 0) {
			fprintf(stderr, "Error closing file %s\n", src_name.c_str());
			exit(1);			
		}
	}


	// get the most common buffer
	for (int i = 0; i < NUM_READ_BUFFER; i++) {
		for (int j = i+1; j < NUM_READ_BUFFER; j++){
			if ( memcmp(buffers[i], buffers[j], sourceSize) == 0 ) {
				vote[i]++; vote[j]++;
			}
		}
	}

	// max element index
	max_index = distance(vote, max_element(vote, vote + sizeof(vote)/sizeof(vote[0])));

	// copy to the destination buffer
	memcpy(buffer, buffers[max_index], len);

	// free mem
	for (int i=0; i < NUM_READ_BUFFER; i++)
		free(buffers[i]);

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


void read_file_from_disk(string src, string filename, int nastiness, char* buffer){

	// make source name with src dir + filename
	string src_name = makeFileName(src, filename);
	size_t src_size = get_source_size(src, filename);

	printf("Copying file %s\n", filename.c_str());

	try {

		read_buffer_safe(src_name, nastiness, buffer, src_size);

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
// write the buffer safely to the nasty file, read from the
// file again to make sure it is the same as the buffer
//
// ------------------------------------------------------

void write_file_to_disk(string target, string filename, int nastiness, 
						char* buffer, size_t sourceSize)
{
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
	
	free(buffer_copy);

	cout << "Finished writing file " << targetName << endl;

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

void checkDirectory(char *dirname) {
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
