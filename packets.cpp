#include "packets.h"


/////////////////////////////////////////////////////////////////////////
/****************************Server functions***************************/
/////////////////////////////////////////////////////////////////////////


// ------------------------------------------------------
//
//                   handle_packets
//
// Event handler for incoming packets, unpack messages to packets,
// send acknowledgement to the client, and return the unpacked packet struct
//
// ------------------------------------------------------
struct filedata handle_packets(C150DgmSocket *sock, char* incomingMessage)
{
	struct filedata packet;
	struct filedata_ACK response;

	memcpy((char *)&packet, incomingMessage, sizeof(struct filedata));

	/* construct response header */
	response.type = PACKET_ACK;
	response.file_id = packet.file_id;
	response.packet_id = packet.packet_id;

	cout << "Received file: " << packet.file_id 
		 << " packet: " << packet.packet_id << endl;

	/* send packet ack */
	sock->write((char *)&response, sizeof(struct filedata_ACK));

	return packet;

}

// ------------------------------------------------------
//
//                   packet_to_buffer
//
// Given a valid packet that matches the expected file_id, 
// write packet data to its byte location in the buffer 
//
// ------------------------------------------------------

void packet_to_buffer(char *buffer, uint32_t file_id, struct filedata packet)
{
	if ( file_id == packet.file_id ) {
		memcpy(&buffer[packet.start_byte], packet.data, packet.data_len);
	}

}


/////////////////////////////////////////////////////////////////////////
/****************************Client functions***************************/
/////////////////////////////////////////////////////////////////////////


// ------------------------------------------------------
//
//                   send_file_packets
//
// Break down file buffer into packets and send to the 
// server in a window size of packets, listens for pkt_ack
// to make sure every packet arrives
//
// ------------------------------------------------------

void send_file_packets(C150DgmSocket *sock, char *buffer, size_t buffer_size, int f_id)
{
	int num_pkts = (buffer_size / MAX_DATA_BYTES) + 1; // total # pkts
	int num_windows = num_pkts / PKT_WINDOW_SIZE + 1; // total # windows of pkts
	struct filedata packets[num_pkts];	// packets to send

	/* break buffer into packets */
	buffer_to_packets(buffer, buffer_size, packets, f_id);

	cout << "NUM OF PKT: " << num_pkts << endl; // testing

	/* send packets to the server */
	for (int i=0; i<num_windows; i++) {
		// last window might have less packets
		if ( i == num_windows - 1)
			send_window_packets(sock, packets, i*PKT_WINDOW_SIZE, num_pkts % PKT_WINDOW_SIZE);
		else
			send_window_packets(sock, packets, i*PKT_WINDOW_SIZE, PKT_WINDOW_SIZE);
	}

}


// ------------------------------------------------------
//
//                   send_window_packets
//
// Send a single window size of packets to the server
// The window is specified by the start_packet index and 
// the total number of packets in the window
//
// ------------------------------------------------------

void send_window_packets(C150DgmSocket *sock, struct filedata packets[], 
					  int start_packet, int total_pkts)
{
	
	set<int> sent_packets; // stores p_id of acknowledged packets
	ssize_t readlen;
	char incomingMessage[sizeof(struct filedata_ACK)]; // read server msg
	uint32_t file_id = packets[0].file_id; // file_id of the packets
	struct filedata_ACK response; // cast response to struct
	bool is_valid;
	int attempt = 0; // total # of retries

	/* retry until max */
	do {
		/* send all packets in the window */
		for (int i=0; i<total_pkts; i++){
			cout << "Send file: "<< file_id << " packet: " << start_packet+i << endl;
			sock->write((char*)&packets[start_packet+i], sizeof(struct filedata));
		}

		/* read for response and check if response is packet_ack */
		readlen = sock->read(incomingMessage, sizeof(incomingMessage));
		
		is_valid = validate_server_response(incomingMessage, PACKET_ACK, file_id, &response);
		if (is_valid)
			sent_packets.insert(response.packet_id); // packet has been ack

		/* keep reading server messages until timedout */
		while ( sock->timedout() == false ) {
			readlen = sock->read(incomingMessage, sizeof(incomingMessage));

			if (readlen < 0)
				throw C150NetworkException("ERROR: server closed the socket");

			is_valid = validate_server_response(incomingMessage, PACKET_ACK, file_id, &response);
			
			if (is_valid)
				sent_packets.insert(response.packet_id);
		}

		/* all packets sent */
		if ( sent_packets.size() == (uint32_t)total_pkts )
			break;

		/* retry has failed */
		if ( sock->timedout() )
			attempt++;

	} while ( attempt < PKT_MAX_RETRY );

	if (attempt == PKT_MAX_RETRY)
		throw C150NetworkException("Fail to send packets after max retries.");

}

// ------------------------------------------------------
//
//                   validate_server_response
//
// Check if the message from the server is relevant
// the response has to match the message type and current file_id.
// Return true and unpack message if valid, return false otherwise
//
// ------------------------------------------------------

bool validate_server_response(char *incomingMessage, int type, uint32_t file_id, 
							  struct filedata_ACK *response)
{
	if ((uint8_t)incomingMessage[0] == type) {
		// cast to response if expected type
		memcpy(response, incomingMessage, sizeof(struct filedata_ACK)); 
		if (response->file_id == file_id) {
			return true;
		}
	}

	return false;
}

// ------------------------------------------------------
//
//                   buffer_to_packets
//
// Break down the given file buffer into packets ready for transmission
// to the server. Packets are stored in the array of packets.
//
// ------------------------------------------------------

void buffer_to_packets(char *buffer, size_t buffer_size, 
					   struct filedata packets[], int f_id)
{
	int num_pkts = (buffer_size / MAX_DATA_BYTES) + 1;
	size_t end_pkt_size = buffer_size % MAX_DATA_BYTES; // trailing pkt

	/* break down buffer into packets */
	for (int i=0; i<num_pkts; i++) {
		/* compute packet size */
		int pkt_size;
		if (i == num_pkts - 1) {
			pkt_size = end_pkt_size; // last packet might be smaller
		} else {
			pkt_size = MAX_DATA_BYTES;		
		}

		/* construct packet header to send */
		struct filedata pkt;
		pkt.type = PACKET;
		pkt.file_id = f_id;
		pkt.packet_id = i;
		pkt.start_byte = index_to_byte(i);
		pkt.data_len = pkt_size;
		memcpy(pkt.data, &buffer[index_to_byte(i)], pkt_size);

		packets[i] = pkt; // store in packets array
	}

}