"""
analyzers.py

Basic file for defining the different attack profiles
Functions to use are:
- addPrelimNode() :: adds a Node at the PRELIM threat level
    @return - The integer index of the added node
- addThreatNode() :: adds a Node at the THREAT threat level
    @return - The integer index of the added node
- addTransition(src, dest, score, triggers) :: adds a scored transition between
  the src and dest nodes
    @param src - Integer index of the Node to transition from
    @param dest - Integer index of the Node to transition to
    @param score - Numerical attack score to be assigned to the transition
    @param triggers - List of boolean functions to be satisfied in order to
        make the transition

"""
from attackanalyzer import AttackAnalyzer

class MailAnalyzer(AttackAnalyzer):
    attackType = 'mail'

    def rxNewMail(self, packet):
        #checks if this packet is SMTP and begins with keywords 'mail from:'
        #which indicates a new piece of mail
        #sets a low limit and high limit for specific threat level

        #SMTP IS PORT 25            
        if packet.dest_port == 25 and \
           packet.payload.lower().startswith('mail from:'):
            return True
        else:
            return False

    def addAttackProfile(self):
        numPrelimNodes = 5
        prelimNodes = []
        threatNode = -1
        
        #add prelimNodex
        for i in range(numPrelimNodes):
            #1 second timeout
            prelimNodes.append(self.addPrelimNode(1000))

        #add threatNode
        threatNode = self.addThreatNode(1000)

        prevNode = self.SAFE

        for curNode in prelimNodes:
            #transition to next prelim node
            self.addTransition(prevNode,
                               curNode,
                               5,
                               [self.rxNewMail])
            prevNode = curNode

        self.addTransition(prevNode,
                           threatNode,
                           10,
                           [self.rxNewMail])
        self.addTransition(threatNode,
                           threatNode,
                           15,
                           [self.rxNewMail])
