class Node:
    def __init__(self, threatLevel):
        self.transitions = []
        self.threatLevel = threatLevel


    def addTransition(self, transition):
        self.transitions.append(transition)

    def processPacket(self, packet):
        for transition in self.transitions:
            if transition.match(packet):
                return (transition.dest, transition.score) #expecting the attack to add that packet to the list of threatening packets related to it
        return (False, 0) #that packet is not part of anything