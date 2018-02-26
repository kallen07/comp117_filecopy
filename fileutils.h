
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
#include <cstdlib>
#include <sstream>
#include <stdio.h>
#include <openssl/sha.h>

//
// Always use namespace C150NETWORK with COMP 150 IDS framework!
//
using namespace C150NETWORK;

bool isFile(string fname);
void checkDirectory(char *dirname);
string makeFileName(string dir, string name);
void compute_file_hash(char *filename, unsigned char *hash);
void read_file_from_disk(string src, string filename, int nastiness, char* buffer, size_t sourceSize);
void write_file_to_disk(string target, string filename, int nastiness, char* buffer, size_t sourceSize);
size_t get_source_size(string src, string filename);
