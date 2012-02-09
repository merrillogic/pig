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
    
    def addAttackProfile(self):
        safeNodeIndex = self.addPrelimNode(300000) #5 minute timeout, for mail 
        threatNodeIndex = self.addThreatNode(300000) #5 minute timeout, for mail
        
        self.addTransition(self.startNode, self.nodes[safeNodeIndex], 0, #condition) #started receiving mail
            #condition = SMTP mail FROM, keep track of how many times this comes up w/ same ip
        self.addTransition(self.nodes[safeNodeIndex], self.nodes[safeNodeIndex], 0, #condition)
            #condition = SMTP rcpt TO or SMTP data or SMTP QUIT or anything else from same ip, SMTP
        self.addTransition(self.nodes[safeNodeIndex], self.startNode, 0, #condition) #QUIT command received, moving back to start
        self.addTransition(self.nodes[safeNodeIndex], self.nodes[threatNodeIndex], #some score, #condition) #receiving a lot of mail in one connection
            #condition = SMTP mail FROM AND counter in self.nodes[safeNodeIndex] is huge
        pass
