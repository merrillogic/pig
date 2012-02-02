"""
connection.py

Defines the Connection class, a wrapper for source/destination IP-paired sets
of AttackAnalyzers

Public methods:
- Connection(source IP address, destination IP address)
- bufferPacket(packet to add to the buffer)
- analyzePackets()

"""
# import the attack analyzers
from analyzers.all import *

class Connection(object):

    # Initialize values for the source IP and destination IP of the connection
    src = None
    dest = None

    # Initialize the pointers to the Threatomaton analyzers
    analyzers = []

    # Initialize the list used to buffer a set of packets to analyze
    packetBuffer = []
    # Initialize the minimum number of packets to have in the buffer before
    # processing them
    minBufferSize = 500

    # Init the flag marking if we should force analysis of buffered packets
    analysisFlag = False

    def __init__(self, src, dest):
        """ Create a Connection object; initializes all variables and creates
        instance-specific AttackAnalyzer instances

        @param src - An identifier for the connection's source host
        @param dest - An identifier for the connection's destination host
        """
        self.src = src
        self.dest = dest

        # Initialize all of our AttackAnalyzers

        sqlinj = SQLInjectionAnalyzer(src, dest)
        self.analyzers.append(sqlinj)

        dos = DOSAnalyzer(src, dest)
        self.analyzers.append(dos)

        passcrack = PassCrackAnalyzer(src, dest)
        self.analyzers.append(passcrack)

        mail = MailAnalyzer(src, dest)
        self.analyzers.append(mail)

        mitm = MitMAnalyzer(src, dest)
        self.analyzers.append(mitm)


    def bufferPacket(self, packet):
        """ Add a packet to this Connection's packet buffer
        @param packet - The Packet object to add to the buffer
        """
        self.packetBuffer.append(packet)


    def analyzePackets(self):
        """ Run attack analysis on all packets contained in this instance's
        packet buffer

        @return None if attacks were detected or no processing was done, False
                if this Connection instance has seen no activity and can be
                garbage-collected
        """
        # To avoid overhead, only actually analyze the packets if there is a
        # large enough packet set buffered, or if this has been called a couple
        # times in a row
        if len(self.packetBuffer < self.minBufferSize):
            if not self.analysisFlag:
                self.analysisFlag = True
                return

        # Run all the attack analyses
        # :TODO: These should really be multi-threaded for efficiency
        countAttacksFound = 0   # The number of analyzers that returned a
                                # positive result
        for analyzer in self.analyzers:
            if analyzer.processPackets(packets):
                countAttacksFound += 1

        # If all the attacks timed out, let the caller know that this
        # Connection is no longer necessary
        if not countAttacksFound:
            return False
