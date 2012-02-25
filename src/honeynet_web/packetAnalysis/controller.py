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
        self.packetBuffer = []

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
        for packet in self.packetBuffer:
            id = packet.source_ip + packet.destination_ip
            if id not in self.connections.keys():
                self.connections[id] = Connection(packet.source_ip,
                                                  packet.destination_ip)
            connection = self.connections[id]
            connection.bufferPacket(packet)
        # empty out the controller's packet buffer, since we've assigned all
        # packets
        self.packetBuffer = []

    def pruneConnections(self):
        """
        Tells each connection to analyze their packet buffers. If the
        connection has all automata in safe states and has not received packets
        for a given period of time, it returns False and is deleted.
        """
        # init list of IDs of connections to delete after processing
        deadCons = []
        for connectionID in self.connections:
            connection = self.connections[connectionID]
            result = connection.isActive()
            if result == False: # If the connection returns false, it will have
                                # already stored everything it needs to in the
                                # database, so it's safe to mark for deletion.
                deadCons.append(connectionID)
        # and get rid of the connections that have timed out
        for deadConID in deadCons:
            del self.connections[deadConID]
