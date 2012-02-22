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

class DOSAnalyzer(AttackAnalyzer):

    attackType = 'dos'

    def addAttackProfile(self):
        for i in range(190):
            funct = lambda x: True
            self.addPrelimNode(5.1)
            self.addTransition(i, i+1, 1, [funct])
        threat = self.addThreatNode(5.1)
        self.addTransition(i+1, threat, 1, [funct])
        self.addTransition(threat, threat, 1, [funct])

        fraggle = lambda x: x.source_port == 19
        self.addTransition(0, threat, 1, [fraggle])

        land = lambda x: x.source_ip == x.destination_ip
        self.addTransition(0, threat, 1, [land]) 
