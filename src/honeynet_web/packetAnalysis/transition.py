"""
transition.py

Definition of Transition class; a data structure containing a set of boolean
conditions based on packet contents, a node in the containing machine to move
to, and the attack score of having met those transition conditions

Public methods:
- Transition(destination node, attack score, list of trigger conditions)
- match(Packet to compare against stored triggers)
"""
class Transition(object):

    # The index of the destination node to transition to
    dest = None
    # Integer score value assigned to this transition
    score = 0
    # List of boolean functions to match to make this transition
    triggers = []

    def __init__(self, dest, score, triggers):
        """ Create a Transition object
        @param dest - Integer index in the parent machine of the Node to move
                      to
        @param score - Attack score for taking this transition
        @param triggers - List of boolean functions to match in order to take
                          this Transition
        """
        self.dest = dest
        self.score = score
        self.triggers = triggers

    def match(self, packet):
        """ Checks if the input packet matches all this Transition's stored
        triggers

        @param packet - The Packet to compare to the triggers
        @return - The resulting Boolean value of comparison
        """
        for trigger in self.triggers:
            if not trigger(packet):
                return False
        return True

    def __str__(self):
        output = "Dest: "+str(self.dest)+'\n'+\
                 "Score: "+str(self.score)+'\n'+\
                 "Triggers: "

        return output
