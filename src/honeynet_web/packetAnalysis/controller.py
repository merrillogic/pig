"""
controller.py
"""
##TODO: change threatomata timeout mechanism (global time mechanism)
## updated time after a bunch of packets
#update the time before processing a chunk.
# TODO: Figure out multi-threading.

from connection import Connection

class Controller(object):
    def __init__(self):
        self.connections = {}
        self.packetBuffer = [] #Implement a linked list for this? Seems
                               #reasonable... we only need the start and end.
                               #FIFO, my friend, FIFO.

    def bufferPackets(self, packets):
        """
        Gets the next chunk of packets from the file reading packet reader and
        adds them to the packet buffer.
        """
        self.packetBuffer.extend(packets)

    def assignPackets(self):
        """
        Reads a chunk of packets from the packetbuffer and passes them on to
        their respective connections.
        """
        for packet in self.packetBuffer: #must be changed if using FIFO dll
            id = packet.source_ip + packet.destination_ip
            if id not in self.connections:
                self.connections[id] = Connection(packet.source_ip,
                                                  packet.destination_ip)
            connection = self.connections[id]
            connection.bufferPacket(packet)

    def processPackets(self):
        """
        Tells each connection to analyze their packet buffers. If the
        connection has all automata in safe states and has not received packets
        for a given period of time, it returns False and is deleted.
        """
        for connectionID in self.connections:
            connection = self.connections[connectionID]
            result = connection.analyzePackets()
            if result == False: # If the connection returns false, it will have
                                # already stored everything it needs to in the
                                # database, so it's safe to del.
                del self.connections[connectionID]
