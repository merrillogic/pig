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
#import multiprocessing library
from multiprocessing import Process, Queue, Pipe, Value, Lock

class AttackProcess(object):
    def __init__(self, analyzer, src, dest):
        self.pipe, analyzerConnection = Pipe()
        self.queue = Queue()
        # status represents whether or not the analyzer has timed out. There's not a way to do a 
        # boolean, so it's just 0 or 1 in an unsigned char.
        self.status = Value('b', 1)
        self.lock = Lock()
        self.process = Process(target=analyzer.processPackets, 
                                    args=(self.queue, analyzerConnection, self.status,
                                            self.lock),
                                    name=(src + '->' + dest + ':' + analyzer.attackType))
        self.process.start()
        
    def queuePacket(self, packet):
        #Lock to prevent race condition with checking dead connection and adding packets.
        self.lock.acquire()
        self.status.value = 1
        try:
            self.queue.put(packet)
        except PicklingError, e:
            print "NOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO"
            exit()
        except Error, e:
            print "MAAAAAAYBE"
            exit()
        self.lock.release()
        
    def killConnection(self):
        self.pipe.send(True)
        self.process.join()
    
    def getMessage(self):
        if self.pipe.poll():
            return self.pipe.recv()
        else:
            return None
            
    def setAlive(self):
        self.status.value = 1
            
    def checkForAttacks(self):
        return self.status.value

class Connection(object):

    # Initialize values for the source IP and destination IP of the connection
    src = None
    dest = None

    # Initialize the pointers to the Threatomaton analyzers
    analyzers = None

    # Initialize the list used to buffer a set of packets to analyze
    packetBuffer = None
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
        
        # Initialize our unique analyzer list
        self.analyzers = []

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
        
        # Initialize our processes
        self.processes = []
        for analyzer in self.analyzers:
            self.processes.append(AttackProcess(analyzer, self.src, self.dest))

    def bufferPacket(self, packet):
        """ Add a packet to this Connection's packet buffer
        @param packet - The Packet object to add to the buffer
        """
        for process in self.processes:
            process.queuePacket(packet)

    def isActive(self):
        """ Run attack analysis on all packets contained in this instance's
        packet buffer

        @return None if attacks were detected or no processing was done, False
                if this Connection instance has seen no activity and can be
                garbage-collected
        """
        results = []
        for process in self.processes:
            results.append(process.checkForAttacks())
        print "Results of running threaded analyzers:", results

        # If all the attacks timed out, let the caller know that this
        # Connection is no longer necessary
        if sum(results) == 0:
            print "No attacks found"
            return False
        else:
            return None
            
    def killConnection(self):
        """
        Tells all the analyzers to finish processing what they have and then return.
        This cleans up those processes, joining them back into this one, making it safe to delete
        the connection without orphaning any processes.
        """
        for process in self.processes:
            process.killConnection()