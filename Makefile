# Makefile for COMP 117 Filecopy Assignment
#
#    Copyright 2012 - Noah Mendelsohn
#


# Do all C++ compies with g++
CPP = g++
CPPFLAGS = -g -Wall -Werror -I$(C150LIB)

# Where the COMP 150 shared utilities live, including c150ids.a and userports.csv
# Note that environment variable COMP117 must be set for this to work!

C150LIB = $(COMP117)/files/c150Utils/
C150AR = $(C150LIB)c150ids.a

LDFLAGS = 
INCLUDES = $(C150LIB)c150dgmsocket.h $(C150LIB)c150nastydgmsocket.h $(C150LIB)c150network.h $(C150LIB)c150exceptions.h $(C150LIB)c150debug.h $(C150LIB)c150utility.h

all: fileclient fileserver

#
# Build fileclient
# 
fileclient: fileclient.cpp fileutils.cpp $(C150AR) $(INCLUDES)
	$(CPP) -o fileclient $(CPPFLAGS) fileclient.cpp fileutils.cpp packets.cpp -lssl -lcrypto $(C150AR)

#
# Build fileserver
#
fileserver: fileserver.cpp fileutils.cpp $(C150AR) $(INCLUDES)
	$(CPP) -o fileserver $(CPPFLAGS) fileserver.cpp fileutils.cpp packets.cpp -lssl -lcrypto $(C150AR)

#
# To get any .o, compile the corresponding .cpp
#
%.o:%.cpp  $(INCLUDES)
	$(CPP) -c  $(CPPFLAGS) $< 


#
# Delete all compiled code in preparation
# for forcing complete rebuild#

clean:
	 rm -f fileclient fileserver *.o 


