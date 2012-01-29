'''
threatomaton.py
@author (primary) Denis Griffis

Defines the Threatomaton class (the base structural class for AttackAnalyzers)

Public methods:
- Threatomaton(source IP address, destination IP address)
- addPrelimNode()
- addThreatNode()
- addTransition(source node, destination node, transition score, list of
  transition conditions)
- processPackets(list of Packets to analyze)

Private methods:
- processPacket(single Packet to analyze)
- exportAttackData()
- reset()

'''
# :TODO: Make the timeout functionality use packet time, not system time
from time import time

from node import *
from transition import *

### GLOBALS #######
SAFE = 0
PRELIM = 1
THREAT = 2
###################

class Threatomaton(object):

    # Each Threatomaton has a type marking what it is used for (e.g. for a
    # SQLInjection AttackAnalyzer, it's 'sqlinjection'); here, initialize this
    # to a default value
    type = 'Default'

    # The instance-dependent number of seconds in packet time after which to
    # say an attack has timed out
    timeoutVal = -1

    # The list of node objects contained in the automaton
    nodes = []
    # The mapping of STATE (SAFE, PRELIM, or THREAT) to a list of indices in
    # self.nodes of nodes belonging to that state
    nodeMap = {}
    # Pointer to the node the machine is currently sitting at
    curNode = None
    # Mark the state the machine is in at all times for convenience
    curState = SAFE

    # Attack data
    lastAttackStart = 0
    attackDuration = 0
    attackScore = 0
    attackPackets = []
    attackSrc = None
    attackDest = None



    def __init__(self, src, dest):
        """ Create a Threatomaton object; initializes the automaton to contain
        one node (the SAFE node);

        @param src - Identifier for the parent Connection's source host
        @param dest - Identifier for the parent Connection's destination host
        """
        startNode = Node(SAFE)

        self.nodes.append(startNode)
        self.nodeMap[SAFE] = 0
        self.curNode = self.nodes[0]

        self.nodeMap[PRELIM] = []
        self.nodeMap[THREAT] = []

        self.attackSrc = src
        self.attackDest = dest


    def addPrelimNode(self):
        """ Add a node in the PRELIM grouping
        @return - The index in self.nodes of the new node
        """
        newNodeIndex = len(self.nodes)
        prelimNode = Node(PRELIM)
        self.nodes.append(prelimNode)
        self.nodeMap[PRELIM].append(newNodeIndex)
        return newNodeIndex


    def addThreatNode(self):
        """ Add a node in the THREAT grouping
        @return - The index in self.nodes of the new node
        """
        newNodeIndex = len(self.nodes)
        threatNode = Node(THREAT)
        self.nodes.append(threatNode)
        self.nodes[THREAT].append(threatNode)
        return newNodeIndex


    def addTransition(self, source, dest, score, triggers):
        """ Add a Transition object to a Node
        @param source - The index in self.nodes of the node to add the Transition to
        @param dest - The index in self.nodes to Transition to
        @param score - The score value assigned to this Transition
        @param triggers - List of boolean functions that act as Transition conditions
        """
        trans = Transition(dest, score, triggers)
        src = self.nodes[source]
        src.addTransition(trans)


    def processPackets(self, packets):
        """ Check if the automaton has timed out and then feed each packet into
        self.processPacket;

        @param packets - List of Packet objects to process
        @return - False if timed out, None otherwise
        """
        # timeout stuff
        curTime = time.time()
        if (curTime - self.lastAttackTime) > self.timeoutVal:
            self.reset()
            # let the caller know that this timed out and reset
            # :TODO: This is a problem; if times out, currently returns without
            # processing packets; but if store return value and return after
            # processing packets, Connection that saw start of an attack could
            # hypothetically get erased
            return False

        # actually process the packets
        for packet in packets:
            self.processPacket(packet)


    def processPacket(self, packet):
        """ Update the machine state and attack data based on the contents of
        the input packet

        @param packet - A Packet object to analyze
        """
        # pull state before processing packets for checking to see if attack
        # started
        prevState = self.curState

        # Get the results of checking this packet against the current Node's
        # available Transitions
        dest, score = self.curNode.processPacket(packet)

        # If there were no transitions available, ignore this packet and move
        # on
        if dest == False: return

        # Otherwise, add the transition's score in, move the current node, and
        # update the machine's state
        self.attackScore += score
        self.curNode = self.nodes[dest]
        self.curState = dest.threatLevel

        # If the transition moved to the SAFE node, that signals the end of an
        # attack, so write out attack data and reset the machine
        if dest.threatLevel == SAFE:
            self.reset()
        # Otherwise, store update attack data
        else:
            self.lastAttackTime = time.time()
            self.attackPackets.append(packet)
            # if moved from SAFE state, attack may have started, so flag it
            if prevState == SAFE and prevState != self.curState:
                self.lastAttackStart = time.time()


    def exportAttackData(self):
        """ Do something with self.attackPackets
        """
        pass


    def reset(self):
        """ Write out any attack data and set the machine back to a clean slate
        with no attack data recorded yet
        """
        # :TODO: This needs to be updated a bit when we decide on the database
        # structure
        self.attackDuration = self.lastAttackTime - self.lastAttackStart

        self.exportAttackData()

        self.lastAttackStart = 0
        self.lastAttackTime = 0
        # set the current Node to the initial (SAFE) node
        self.curNode = self.nodes[0]
        self.curState = SAFE



def _test():
    th = Threatomaton(None, None)
    print th.timeoutVal
if __name__=='__main__':_test()
