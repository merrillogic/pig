"""
node.py
"""
class Node(object):
    def __init__(self, threatLevel, timeout = -1):
        self.transitions = []
        self.threatLevel = threatLevel
        self.timeout = timeout


    def addTransition(self, transition):
        self.transitions.append(transition)

    def setTimeout(self, timeout):
        self.timeout = timeout

    def processPacket(self, packet):
        for transition in self.transitions:
            if transition.match(packet):
                # expecting the attack to add that packet to the list of
                # threatening packets related to it
                return (transition.dest, transition.score)
        return (False, 0) #that packet is not part of anything
