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
        #checks if this packet is SMTP and begins with keywords 'mail from:'
        #which indicates a new piece of mail
        #sets a low limit and high limit for specific threat level

        #SMTP
        if packet.protocol == 25 and \
           packet.payload.startswith('mail from:') and \
           mailRxNum > lowLimit and \
           mailRxNum < highLimit:
            mailRxNum += 1
            return True
        else:
            return False

    def addAttackProfile(self):
        prelimNodeIndex = self.addPrelimNode(300000) #5 minute timeout, for mail
        threatNodeIndecise = []
        threatLevels = 3

        #add separate threat node for each threat level, store index in list
        for i in range(threatLevels):
            #5 minute timeout
            threatNodeIndecise.append(self.addThreatNode(300000))

        #started receiving mail
        self.addTransition(self.SAFE,
                           prelimNodeIndex,
                           0,
                           [rxNewMail])
        #receive more mail, same connection
        self.addTransition(prelimNodeIndex, 
                           prelimNodeIndex, 
                           0,
                           [rxNewMail])
        #move to threatOne if # >= 50
        self.addTransition(prelimNodeIndex, 
                           threatNodeIndecise[0], 
                           1, 
                           [rxMoreMail])
        #receive 50 or more pieces of mail, same connection
        self.addTransition(threatNodeIndecise[0], 
                           threatNodeIndecise[0], 
                           1, 
                           [rxMoreMail])
        #move to threatTwo if # >= 100
        self.addTransition(threatNodeIndecise[0], 
                           threatNodeIndecise[1], 
                           2, 
                           [rxHeavyMail])
        #receive 100 or more pieces of mail, same connection
        self.addTransition(threatNodeIndecise[1], 
                           threatNodeIndecise[1], 
                           2, 
                           [rxHeavyMail])
        #move to threatThree if # >= 250
        self.addTransition(threatNodeIndecise[1], 
                           threatNodeIndecise[2], 
                           3, 
                           [rxTooMuchMail])

