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
class PassCrackAnalyzer(AttackAnalyzer):

    type = 'passwordcracking'

    def addAttackProfile(self):
        # set up the basic conditions to classify a packet as an SSH login
        sshConds = [lambda p: p.dest_port == 22,
                    lambda p: p.protocol == TCP]
        
        ### SSH ############
        # set up the first PRELIM node (triggered when we get a single SSH
        # packet)
        firstPrel = self.addPrelimNode()
        self.addTransition(SAFE, firstPrel, 0, sshConds)

        ##### SLOW SSH #####
        # PRELIM node for the slow attack profile
        slowPrel = self.addPrelimNode()
        slowConds = sshConds[:]
        slowConds.append(lambda p: p.time >= self.lastAttackStart + 5)
        self.addTransition(firstPrel, slowPrel, 1, slowConds)

        # repeating PRELIM nodes for slow attack
        prev = slowPrel
        for i in range(30):
            new = self.addPrelimNode()
            self.addTransition(prev, new, 1, sshConds)
            prev = new
        lastPrel = prev # just for clarity of coding

        # THREAT node
        threat = self.addThreatNode()
        self.addTransition(lastPrel, threat, 5, sshConds)
        # and the THREAT -> THREAT transition
        self.addTransition(threat, threat, 5, sshConds)

        ##### FAST SSH #####
        fastPrel = self.addPrelimNode()
        fastConds = sshConds[:]
        fastConds.append(lambda p: p.time < self.lastPotentialAttackTime + 5)
        self.addTransition(firstPrel, fastPrel, 1, fastConds)

        # repeating PRELIM nodes for fast attack
        # There are fewer of these, as it is presumable less likely to get a
        # legal large set of really fast login packets
        prev = fastPrel
        for i in range(10):
            new = self.addPrelimNode()
            self.addTransition(prev, new, 1, sshConds)
            prev = new
        lastPrel = prev

        # the THREAT node
        threat = self.addThreatNode()
        self.addTransition(lastPrel, threat, 5, sshConds)
        # and the THREAT -> THREAT transition
        self.addTransition(threat, threat, 5, sshConds)

        ### MYSQL ##########
        # DERP
        
        pass
