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

    type = 'mail'
    mailRxNum = 0

    def rxNewMail(packet):
        rxMailTemp(packet, -1, 50)

    def rxMoreMail(packet):
        rxMailTemp(packet, 49, 100)

    def rxHeavyMail(packet):
        rxMailTemp(packet, 99, 250)

    def rxTooMuchMail(packet):
        rxMailTemp(packet, 249, 1000) #upper limit of 1000, set by exim

    def rxMailTemp(packet, lowLimit, highLimit):
        if packet.protocol == SMTP and
           packet.payload.startswith('mail from:') and
           mailRxNum > lowLimit and
           mailRxNum < highLimit:
            mailRxNum += 1
            return True
        else:
            return False

    def addAttackProfile(self):
        safeNodeIndex = self.addPrelimNode(300000) #5 minute timeout, for mail 
        threatOneIndex = self.addThreatNode(300000) #5 minute timeout, for mail
        threatTwoIndex = self.addThreatNode(300000) #5 minute timeout, for mail
        threatThreeIndex = self.addThreatNode(300000) #5 minute timeout, for mail
        threatFourIndex = self.addThreatNode(300000) #5 minute timeout, for mail

        #started receiving mail
        self.addTransition(self.startNode, self.nodes[safeNodeIndex], 0, [rxNewMail])
        #receive more mail, same connection, move to threatOne if # >= 50
        self.addTransition(self.nodes[safeNodeIndex], self.nodes[safeNodeIndex], 0, [rxNewMail])
        self.addTransition(self.nodes[safeNodeIndex], self.nodes[threatOneIndex], 1, [rxMoreMail])
        #receive 50 or more pieces of mail, same connection, move to threatTwo if # >= 100
        self.addTransition(self.nodes[threatOneIndex], self.nodes[threatOneIndex], 1, [rxMoreMail])
        self.addTransition(self.nodes[threatOneIndex], self.nodes[threatTwoIndex], 2, [rxHeavyMail])
        #receive 100 or more pieces of mail, same connection, move to threatThree if # >= 250
        self.addTransition(self.nodes[threatTwoIndex], self.nodes[threatTwoIndex], 2, [rxHeavyMail])
        self.addTransition(self.nodes[threatTwoIndex], self.nodes[threatThreeIndex], 3, [rxTooMuchMail])

