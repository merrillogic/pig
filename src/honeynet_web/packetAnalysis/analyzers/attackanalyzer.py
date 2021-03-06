'''
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

'''
from honeynet_web.packetAnalysis.threatomaton import Threatomaton

class AttackAnalyzer(Threatomaton):

    def __init__(self, src, dest):
        Threatomaton.__init__(self, src, dest)
        self.addAttackProfile()

    def addAttackProfile(self):
        pass


def _test():
    aa = AttackAnalyzer()
    print aa.type
if __name__=='__main__':_test()
