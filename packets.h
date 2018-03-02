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
#include <set>
#include <cstdlib>
#include <sstream>
#include <stdio.h>
#include "c150dgmsocket.h"
#include <numeric>
#include "globals.h"

//
// Always use namespace C150NETWORK with COMP 150 IDS framework!
//
using namespace C150NETWORK;
using namespace std;

// Client functions for sending packets
void buffer_to_packets(char *buffer, size_t buffer_size, 
						struct filedata packets[], int f_id);
void send_file_packets(C150DgmSocket *sock, char *buffer, size_t buffer_size, int f_id);
void send_window_packets(C150DgmSocket *sock, struct filedata packets[], uint64_t start_packet, int total_pkts);
bool validate_server_response(char *incomingMessage, int type, uint32_t file_id);

// Server function for reassembling packets
struct filedata handle_packets(C150DgmSocket *sock, char* incomingMessage);
void packet_to_buffer(char *buffer, uint32_t file_id, struct filedata packet);


inline int index_to_byte(int index) {
	return index * MAX_DATA_BYTES;
}

inline int byte_to_index(int start_byte) {
	return start_byte / MAX_DATA_BYTES;
}