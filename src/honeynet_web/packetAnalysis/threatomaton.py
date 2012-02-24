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
from django.db import transaction
from datetime import datetime, timedelta

from honeynet_web.honeywall.models import Attack

from django.core import serializers

from node import Node
from transition import Transition

class Threatomaton(object):

    # Each Threatomaton has a type marking what it is used for (e.g. for a
    # SQLInjection AttackAnalyzer, it's 'sqlinjection'); here, initialize this
    # to a default value
    attackType = 'Default'

    # Store the state values as readable variables
    SAFE = 0
    PRELIM = 1
    THREAT = 2

    # The list of node objects contained in the automaton
    nodes = None
    # The mapping of STATE (SAFE, PRELIM, or THREAT) to a list of indices in
    # self.nodes of nodes belonging to that state
    nodeMap = None
    # Pointer to the node the machine is currently sitting at
    curNode = None
    # Mark the state the machine is in at all times for convenience
    curState = -1

    # Attack data
    attack = None
    lastAttackStart = None
    lastAttackTime = None
    attackDuration = 0
    attackScore = 0
    attackPackets = None
    attackSrc = None
    attackDest = None

    # Special case timeout vars
    noPackets = False
    noPacketTime = None

    # Marker for when to stop processing and terminate the process. Should never be set to false
    # except here in initiation.
    stop = False
    
    # debug mode flag (prints attack data instead of saving to DB)
    DEBUG = False



    def __init__(self, src, dest):
        """ Create a Threatomaton object; initializes the automaton to contain
        one node (the self.SAFE node);

        @param src - Identifier for the parent Connection's source host
        @param dest - Identifier for the parent Connection's destination host
        """
        # Init the necessary unique lists/dicts/stuff
        self.nodes = []
        self.nodeMap = {}
        self.attackPackets = []

        self.curState = self.SAFE
        startNode = Node(self.SAFE)

        self.nodes.append(startNode)
        self.nodeMap[self.SAFE] = 0
        self.curNode = self.nodes[0]

        self.nodeMap[self.PRELIM] = []
        self.nodeMap[self.THREAT] = []

        self.attackSrc = src
        self.attackDest = dest


    def addPrelimNode(self, timeout=-1):
        """ Add a node in the self.PRELIM grouping
        @return - The index in self.nodes of the new node
        """
        newNodeIndex = len(self.nodes)
        prelimNode = Node(self.PRELIM, timeout)
        self.nodes.append(prelimNode)
        self.nodeMap[self.PRELIM].append(newNodeIndex)
        return newNodeIndex


    def addThreatNode(self, timeout=-1):
        """ Add a node in the self.THREAT grouping
        @return - The index in self.nodes of the new node
        """
        newNodeIndex = len(self.nodes)
        threatNode = Node(self.THREAT, timeout)
        self.nodes.append(threatNode)
        self.nodeMap[self.THREAT].append(threatNode)
        return newNodeIndex


    def addTimeout(self, node, timeout):
        """ Add a timeout to the given node.
        @param node - The node to add the timeout to
        @param timeout - The length of the timeout, in milliseconds
        """
        timeout = timedelta(milliseconds=timeout)
        node.setTimeout(timeout)


    def addTransition(self, source, dest, score, triggers):
        """ Add a Transition object to a Node
        @param source - The index in self.nodes of the node to add the
                        Transition to
        @param dest - The index in self.nodes to Transition to
        @param score - The score value assigned to this Transition
        @param triggers - List of boolean functions that act as Transition
                          conditions
        """
        trans = Transition(dest, score, triggers)
        src = self.nodes[source]
        src.addTransition(trans)

    def dequeuePacket(self, queue):
        """
        Pops a packet from the given queue, and deserializes it
        """
        return serializers.deserialize("json", queue.get()).next().object

    def checkStop(self, connection):
        """
        Checks the connection to see if True has been sent. If True has been sent, flags the
        process to stop.
        
        @param connection - Connection object to check
        """
        if connection.poll():
            val = connection.recv()
            if val == True:
                self.stop = True
                
    @transaction.commit_manually
    def processPackets(self, packetQueue, connection, status, lock):
        """ Continually check if the automaton has timed out and then feed each packet from
        the queue into self.processPacket; Exits if told to stop.
        """

        #MIGHT NEED TO RESTRUCTURE THIS. Worried about the method of sending true/false back.
        # Should I just send it back when there are no more input packets?
        # Maybe... If I keep this system, I need a way of not insta-timing out in connection,
        # probably
        #might need to check each packet for timeout, since it looks like that could be happening...
        
        #WARNING: Timeout need to be changed a bit. We need to be sure to never have status=0 if 
        # there are packets remaining to be processed. Maybe set it at the beginning OH NO A RACE
        # CONDITION. I THINK I NEED TO SOLVE IT IN CONNECTION. Like, set status to 1 as soon as I 
        # buffer any packets. Oh, before I buffer packets! Then if processor finishes quickly, it's 
        # okay.
        # SOLVED^ Just added a lock around necessary parts.
        print self.attackType, "is starting"
        while ((self.stop == False) or (not packetQueue.empty())):
            # flag a timeout if we have had an attack and the time since its last
            # packet seen is more than the timeout value
            timeoutFlag = False
            firstPacket = None
            if self.lastAttackTime:
                if not packetQueue.empty():
                    firstPacket = self.dequeuePacket(packetQueue)
                    timeElapsed = firstPacket.time - self.lastAttackTime
                    self.noPackets = False
                    self.noPacketTime = None
                elif not self.noPackets:
                    self.noPackets = True
                    self.noPacketTime = datetime.now() 
                    timeElapsed = timedelta()
                elif self.noPackets:
                    timeElapsed = datetime.now() - self.noPacketTime
                if (timeElapsed > self.curNode.timeout):
                    print "Timed out! AW SHIT YO"
                    self.reset(self.lastAttackTime)
                    # flag that this timed out
                    timeoutFlag = True
    
            # if it exists, process the first packet
            if firstPacket:
                self.processPacket(firstPacket)
            
            # actually process the packets
            while (not packetQueue.empty()):
                self.processPacket(self.dequeuePacket(packetQueue))
    
            # if we had flagged a timeout and the packets just processed did not
            # start an attack, then let the parent Connection know this is inactive
            lock.acquire()
            if timeoutFlag and not self.lastAttackStart and self.packetQueue.empty():
                status.value = 0
                print self.attackType, "is timing out or something"
            lock.release()
    
            # if we detected an attack, let the Connection know
            if self.attack:
                status.value = 1
            
            #transaction.commit()
            
            self.checkStop(connection)
        
    def processPacket(self, packet):
        """ Update the machine state and attack data based on the contents of
        the input packet

        @param packet - A Packet object to analyze
        """
        #print packet.id, packet.time
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
        self.curState = self.curNode.threatLevel

        # If the transition moved to the self.SAFE node, that signals the end
        # of an attack, so write out attack data and reset the machine
        if (self.curNode.threatLevel == self.SAFE
                and self.curState != prevState):
            self.reset(packet.time)
        # Otherwise, store update attack data
        else:
            self.lastAttackTime = packet.time
            self.attackPackets.append(packet)
            # if moved from self.SAFE state, attack may have started, so flag it
            if prevState == self.SAFE and prevState != self.curState:
                self.lastAttackStart = packet.time
            # if moved from self.PRELIM to self.THREAT, confirms that this is an
            # attack, so create an attack object and mark all stored packets
            # with its ID
            elif prevState != self.THREAT and self.curState == self.THREAT:
                # initialize the Attack object for this attack
                self.initializeAttack()
                # and mark the packets we've seen so far
                for pckt in self.attackPackets:
                    self.markPacket(pckt)
            # otherwise, if we're still in self.THREAT, the only packet that needs
            # to get marked is the one we just processed
            elif self.curState == self.THREAT:
                self.markPacket(packet)


    def initializeAttack(self):
        """ Initialize an Attack instance with the data we've recorded so far
        and record it in the database as a partial attack
        """
        print self.attackType, "attack found on", self.attackSrc, "->",\
              self.attackDest
        self.attack = Attack()
        self.attack.classification_time = datetime.now()
        self.attack.source_ip = self.attackSrc
        self.attack.destination_ip = self.attackDest
        self.attack.start_time = self.lastAttackStart
        self.attack.score = self.attackScore
        self.attack.attack_type = self.attackType
        # save it so we can mark the collected attackPackets
        if not self.DEBUG:
            self.attack.save()


    def markPacket(self, packet):
        """ Mark the packet in the DB with the current Attack object's ID
        """
        if self.DEBUG: return
        packet.attacks.add(self.attack)
        packet.save()


    def exportAttackData(self):
        """ Save the current attack object to the database (or print it if in
        debug mode); This is a separate function so it can be called
        externally, regardless of if an attack has been recorded or not
        """
        if not self.DEBUG:
            print "Attack completed!"
            print self.attack
            self.attack.save()
        else:
            print "Attack data currently recorded for this analysis:"
            print "-------------------------------------------------"
            print self.attack
            print


    def reset(self, resetTime=0):
        """ Write out any attack data and set the machine back to a clean slate
        with no attack data recorded yet
        """
        print "reset!"
        if self.attack:
            self.attack.end_time = resetTime
            self.attack.score = self.attackScore
            self.exportAttackData()

        self.attack = None
        self.lastAttackStart = None
        self.lastAttackTime = None
        # set the current Node to the initial (self.SAFE) node
        self.curNode = self.nodes[0]
        self.curState = self.SAFE



def _test():
    th = Threatomaton(None, None)
    print th.timeoutVal
if __name__=='__main__':_test()
