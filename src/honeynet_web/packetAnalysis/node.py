"""
node.py

The code for the node that's part of a threatomaton.

"""
from datetime import timedelta

class Node(object):
    def __init__(self, threatLevel, timeout=-1):
        self.transitions = []
        self.threatLevel = threatLevel
        self.setTimeout(timeout)

    def addTransition(self, transition):
        """
        Adds a transition to the node.
        @param transition - The transition to add.
        """
        self.transitions.append(transition)

    def setTimeout(self, timeout):
        """
        Sets the nodes timeout.
        @param timeout - The timeout length in milliseconds.
        """
        self.timeout = timedelta(milliseconds=timeout)

    def processPacket(self, packet):
        '''
        Checks the given packet against all the transitions to see if it matches any.
        
        @return - Returns the destination and score if a match is found, otherwise False and 0.
        @param packet - packet to investigate
        '''
        for transition in self.transitions:
            if transition.match(packet):
                # expecting the attack to add that packet to the list of
                # threatening packets related to it
                return (transition.dest, transition.score)
        return (False, 0) #that packet is not part of anything
