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
	'''A standard DoS attack shall be a connection that sends more than
             200 packets over one second.
	'''
        funct = lambda x: True
        for i in range(1000):
            self.addPrelimNode(1.1)
            self.addTransition(i, i+1, 1, [funct])
        threat = self.addThreatNode(5.1)
        self.addTransition(i+1, threat, 1, [funct])
        self.addTransition(threat, threat, 1, [funct])

	'''A fraggle attack utilizes the random character generation TCP port
	     and the Echo port to cause an endless loop.
	'''
	charGenPort = 19
        fraggle = lambda x: x.source_port == charGenPort or \
		            x.destination_port == charGenPort
        self.addTransition(0, threat, 100, [fraggle])

	'''A land attack spoofs the victim's IP as the source and dest, 
     	     causing the machine to try to open a connection with itself.
	'''
        land = lambda x: x.source_ip == x.destination_ip
        self.addTransition(0, threat, 150, [land]) 
