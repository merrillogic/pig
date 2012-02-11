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

class SQLInjectionAnalyzer(AttackAnalyzer):

    type = 'sqlinjection'
    attackedAddress = ''

    def isQuery(packet):
        return True
    
    def isSameQuery(packet1):
        #check to match self.urls or something
        return True

    def addAttackProfile(self):
        numPrelims = 5
        for i in range(numPrelims):
            self.addPrelimNode(500)
            
        self.addTransition(0, 1, 0, [self.isQuery])
        for prelimIndex in range(1, numPrelims):
            #for the first numPrelims-1 nodes...
            self.addTransition(prelimIndex, prelimIndex + 1, prelimIndex+1, [self.isSameQuery])
            
        self.addThreatNode()
        self.addTransition(-2, -1, numPrelims, [self.isSameQuery])
        self.addTransition(-1, -1, numPrelims, [self.isSameQuery])
        
