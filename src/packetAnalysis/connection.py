'''
connection.py
@author (primary) Denis Griffis

Defines the Connection class, a wrapper for source/destination IP-paired sets
of AttackAnalyzers

Public methods:
- Connection(source IP address, destination IP address)
- bufferPacket(packet to add to the buffer)
- analyzePackets()

'''
class Connection(object):

    # Initialize values for the source IP and destination IP of the connection
    src = None
    dest = None

    # Initialize the pointers to the Threatomaton analyzers
    sqlinj = None
    dos = None
    passcrack = None
    mail = None
    mitm = None

    # Initialize the list used to buffer a set of packets to analyze
    packetBuffer = []
    # Initialize the minimum number of packets to have in the buffer before
    # processing them
    minBufferSize = 500

    def __init__(self, src, dest):
        """ Create a Connection object; initializes all variables and creates
        instance-specific AttackAnalyzer instances

        @param src - An identifier for the connection's source host
        @param dest - An identifier for the connection's destination host
        """
        self.src = src
        self.dest = dest

        self.sqlinj = SQLInjectionAnalyzer(src, dest)
        self.dos = DOSAnalyzer(src, dest)
        self.passcrack = PassCrackAnalyzer(src, dest)
        self.mail = MailAnalyzer(src, dest)
        self.mitm = MitMAnalyzer(src, dest)

        self.analysisFlag = False


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
        sqlResult = self.sqlinj.processPackets(packets)
        dosResult = self.dos.processPackets(packets)
        passResult = self.passcrack.processPackets(packets)
        mailResult = self.mail.processPackets(packets)
        mitmResult = self.mitm.processPackets(packets)

        # If all the attacks timed out, let the caller know that this
        # Connection is no longer necessary
        if (not sqlResult
                and not dosResult
                and not passResult
                and not mailResult
                and not mitmResult):
            return False
