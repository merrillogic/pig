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
    mailRxNum = 0

    def rxNewMail(self, packet):
        return self.rxMailTemp(packet, -1, 5)

    def rxMoreMail(self, packet):
        return self.rxMailTemp(packet, 4, 20)

    def rxHeavyMail(self, packet):
        return self.rxMailTemp(packet, 19, 50)

    def rxTooMuchMail(self, packet):
        return self.rxMailTemp(packet, 49, 1000) #upper limit of 1000, set by exim

    def rxMailTemp(self, packet, lowLimit, highLimit):
        #checks if this packet is SMTP and begins with keywords 'mail from:'
        #which indicates a new piece of mail
        #sets a low limit and high limit for specific threat level

        #SMTP
        if packet.dest_port == 25 and \
           packet.payload.lower().startswith('mail from:') and \
           mailRxNum > lowLimit and \
           mailRxNum < highLimit:
            mailRxNum += 1
            print True
            return True
        else:
            print False
            return False

    def addAttackProfile(self):
        prelimNodes = 5
        threatNodes = 3
        prelimNodeIndecise = []
        threatNodeIndecise = []
        transitionFunctions = [self.rxMoreMail,
                               self.rxHeavyMail,
                               self.rxTooMuchMail]
        
        #add prelimNodex
        for i in range(prelimNodes):
            #1 second timeout
            prelimNodeIndecise.append(self.addPrelimNode(1000))

        #add separate threat node for each threat level, store index in list
        for i in range(threatNodes):
            #1 second timeout
            threatNodeIndecise.append(self.addThreatNode(1000))

        prevNode = self.SAFE

        for curNode in prelimNodeIndecise:
            #transition to next prelim node
            self.addTransition(prevNode,
                               curNode,
                               1,
                               [self.rxNewMail])
            prevNode = curNode

        for i in range(len(threatNodeIndecise)):
            #transition to next node
            self.addTransition(prevNode,
                               threatNodeIndecise[i],
                               10 * (i + 1),
                               [transitionFunctions[i]])
            
            #transition to same node
            self.addTransition(threatNodeIndecise[i],
                               threatNodeIndecise[i],
                               10 * (i + 1),
                               [transitionFunctions[i]])
                               
            prevNode = threatNodeIndecise[i]
                               
        """
        #started receiving mail
        self.addTransition(self.SAFE,
                           prelimNodeIndex,
                           0,
                           [self.rxNewMail])
        #receive more mail, same connection
        self.addTransition(prelimNodeIndex, 
                           prelimNodeIndex, 
                           0,
                           [self.rxNewMail])
        #move to threatOne if # >= 50
        self.addTransition(prelimNodeIndex, 
                           threatNodeIndecise[0], 
                           1, 
                           [self.rxMoreMail])
        #receive 50 or more pieces of mail, same connection
        self.addTransition(threatNodeIndecise[0], 
                           threatNodeIndecise[0], 
                           1, 
                           [self.rxMoreMail])
        #move to threatTwo if # >= 100
        self.addTransition(threatNodeIndecise[0], 
                           threatNodeIndecise[1], 
                           2, 
                           [self.rxHeavyMail])
        #receive 100 or more pieces of mail, same connection
        self.addTransition(threatNodeIndecise[1], 
                           threatNodeIndecise[1], 
                           2, 
                           [self.rxHeavyMail])
        #move to threatThree if # >= 250
        self.addTransition(threatNodeIndecise[1], 
                           threatNodeIndecise[2], 
                           3, 
                           [self.rxTooMuchMail])
        """
