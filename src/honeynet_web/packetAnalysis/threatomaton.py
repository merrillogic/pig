"""
threatomaton.py

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
- markPacket(single Packet to mark)
- exportAttackData()
- reset()

"""
# :TODO: Make the timeout functionality use packet time, not system time
from datetime import datetime

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


    def addPrelimNode(self, timeout=-1):
        """ Add a node in the PRELIM grouping
        @return - The index in self.nodes of the new node
        """
        newNodeIndex = len(self.nodes)
        prelimNode = Node(PRELIM)
        self.nodes.append(prelimNode)
        self.nodeMap[PRELIM].append(newNodeIndex)
        return newNodeIndex


    def addThreatNode(self, timeout=-1):
        """ Add a node in the THREAT grouping
        @return - The index in self.nodes of the new node
        """
        newNodeIndex = len(self.nodes)
        threatNode = Node(THREAT)
        self.nodes.append(threatNode)
        self.nodes[THREAT].append(threatNode)
        return newNodeIndex


    def addTimeout(self, node, timeout):
        """ Add a timeout to the given node.
        @param node - The node to add the timeout to
        @param timeout - The length of the timeout, in milliseconds
        """
        node.setTimeout(timeout)

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
        timeoutFlag = False
        curTime = datetime.now()
        timeElapsed = curTime - self.lastAttackTime
        if (timeElapsed > self.curNode.timeout):
            self.reset()
            # flag that this timed out
            timeoutFlag = True

        # actually process the packets
        for packet in packets:
            self.processPacket(packet)

        # if we had flagged a timeout and the packets just processed did not
        # start an attack, then let the parent Connection know this is inactive
        if timeoutFlag and self.lastAttackStart == 0:
            return False


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
            self.lastAttackTime = datetime.now()
            self.attackPackets.append(packet)
            # if moved from SAFE state, attack may have started, so flag it
            if prevState == SAFE and prevState != self.curState:
                self.lastAttackStart = datetime.now()
            # if moved from PRELIM to THREAT, confirms that this is an
            # attack, so create an attack object and mark all stored packets
            # with its ID
            elif prevState == PRELIM and self.curState == THREAT:
                self.attack = None # TODO: what here?
                for pckt in self.attackPackets:
                    self.markPacket(pckt)
            # otherwise, if we're still in THREAT, the only packet that needs
            # to get marked is the one we just processed
            elif self.curState == THREAT:
                self.markPacket(packet)


    def markPacket(self, packet):
        """ Mark the packet in the DB with the current Attack object's ID
        """
        pass

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

        self.attack = None
        self.lastAttackStart = 0
        self.lastAttackTime = 0
        # set the current Node to the initial (SAFE) node
        self.curNode = self.nodes[0]
        self.curState = SAFE



def _test():
    th = Threatomaton(None, None)
    print th.timeoutVal
if __name__=='__main__':_test()
