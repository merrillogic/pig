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
        for i in range(50):
            funct = lambda x: True
            self.addPrelimNode(21)
            self.addTransition(i, i+1, 1, [funct])
        threat = self.addThreatNode(21)
        self.addTransition(i+1, threat, 1, [funct])
        self.addTransition(threat, threat, 1, [funct])
