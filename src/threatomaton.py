from time import time

from node import *
from transition import *

### GLOBALS #######
SAFE = 0
PRELIM = 1
THREAT = 2
###################

class Threatomaton:

    type = 'Default'
    
    timeoutVal = -1

    ## maps STATE to list of Nodes
    nodes = [] 
    nodeMap = {}
    curNode = None
    curState = SAFE

    lastAttackStart = 0
    attackDuration = 0
    attackScore = 0
    attackPackets = []



    def __init__(self):
        startnode = Node(SAFE)

        self.nodes.append(startNode)
        self.nodeMap[SAFE] = 0
        self.curNode = self.nodes[0]

        self.nodeMap[PRELIM] = []
        self.nodeMap[THREAT] = []


    def addPrelimNode(self):
        newNodeIndex = len(self.nodes)
        prelimNode = Node(PRELIM)
        self.nodes.append(prelimNode)
        self.nodeMap[PRELIM].append(newNodeIndex)


    def addThreatNode(self):
        newNodeIndex = len(self.nodes)
        threatNode = Node(THREAT)
        self.nodes.append(threatNode)
        self.nodes[THREAT].append(threatNode)


    def addTransition(self, source, dest, score, triggers):
        """ Add a Transition object to a Node
        Args:
        - source: the index in self.nodes of the node to add the Transition to
        - dest: the index in self.nodes to Transition to
        - score: the score value assigned to this Transition
        - triggers: list of Trigger objects that act as Transition conditions
        """
        trans = Transition(dest, score, triggers)
        src = self.nodes[source]
        src.addTransition(trans)

    
    def processPackets(self, packets):
        # timeout stuff
        curTime = time.time()
        if (curTime - self.lastAttackTime) > self.timeoutVal:
            self.reset()

        # actually process the packets
        for packet in packets:
            self.processPacket(packet)

    
    def processPacket(self, packet):
        # pull state before processing packets for checking to see if attack
        # started
        prevState = self.curState
        
        dest, score = self.curNode.processPacket(packet)

        if dest == False: return

        self.attackScore += score
        self.curNode = self.nodes[dest]
        self.curState = dest.threatLevel

        if dest.threatLevel == SAFE:
            self.reset()
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
        self.attackDuration = self.lastAttackTime - self.lastAttackStart

        self.exportAttackData()

        self.lastAttackStart = 0
        self.lastAttackTime = 0
        # set the current Node to the initial (SAFE) node
        self.curNode = self.nodes[0]
        self.curState = SAFE

    

def _test():
    th = Threatomaton()
    print th.timeoutVal
if __name__=='__main__':_test()
