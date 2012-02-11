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

def isQuery(packet):
    return True
    
def isSameQuery(packet1, packet2):
    return True

class SQLInjectionAnalyzer(AttackAnalyzer):

    type = 'sqlinjection'
    attackedAddress = ''

    def addAttackProfile(self):
        numPrelims = 5
        for i in range(numPrelims):
            self.addPrelimNode(500)
            
        self.addTransition(self.nodes[0], prelims[0], 0, [isQuery])
        for prelimIndex in range(1, numPrelims):
            #for the first numPrelims-1 nodes...
            self.addTransition(self.nodes[prelimIndex], self.nodes[prelimIndex
                                                                    + 1], prelimIndex+1, isSameQuery)
            
        self.addThreatNode()
        self.addTransition(self.nodes[-2], self.nodes[-1], numPrelims, isSameQuery)
        self.addTransition(self.nodes[-1], self.nodes[-1], numPrelims, isSameQuery)
        
