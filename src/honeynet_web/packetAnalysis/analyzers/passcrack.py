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
from datetime import timedelta
from honeywall.utils import protocol_lookup

class PassCrackAnalyzer(AttackAnalyzer):

    attackType = 'pass'

    def addAttackProfile(self):
        # set up the basic conditions to classify a packet as an SSH login
        sshConds = [lambda p: p.dest_port == 22,
                    lambda p: protocol_lookup(p.protocol) == 'TCP']
        sqlConds = [lambda p: p.dest_port == 3306,
                    lambda p: protocol_lookup(p.protocol) == 'TCP']


        ### SSH ############
        # set up the first PRELIM node (triggered when we get a single SSH
        # packet)
        firstPrel = self.addPrelimNode(10000)
        self.addTransition(self.SAFE, firstPrel, 0, sshConds)

        # Slow SSH
        slowConds = sshConds[:]
        slowConds.append(lambda p: p.time >= self.lastAttackStart
                                             + timedelta(seconds=5))
        self.addSingleProfile(firstPrel, sshConds, slowConds, 30, 5000)
        # Fast SSH
        fastConds = sshConds[:]
        fastConds.append(lambda p: p.time < self.lastAttackStart
                                            + timedelta(seconds=5))
        self.addSingleProfile(firstPrel, sshConds, fastConds, 10, 500)

        # Slow SQL
        slowConds = sqlConds[:]
        slowConds.append(lambda p: p.time >= self.lastAttackStart
                                             + timedelta(seconds=5))
        self.addSingleProfile(firstPrel, sqlConds, slowConds, 30, 5000)
        # Fast SQL
        fastConds = sqlConds[:]
        fastConds.append(lambda p: p.time < self.lastAttackStart
                                            + timedelta(seconds=5))
        self.addSingleProfile(firstPrel, sqlConds, fastConds, 10, 500)

        """
        ##### SLOW SSH #####
        # PRELIM node for the slow attack profile
        slowPrel = self.addPrelimNode()
        slowConds = sshConds[:]
        slowConds.append(lambda p: p.time >= self.lastAttackStart
                                             + timedelta(seconds=5))
        self.addTransition(firstPrel, slowPrel, 1, slowConds)
        self.addTimeout(slowPrel, 5000)

        # repeating PRELIM nodes for slow attack
        prev = slowPrel
        for i in range(30):
            new = self.addPrelimNode()
            self.addTransition(prev, new, 1, sshConds)
            self.addTimeout(new, 5000)
            prev = new
        lastPrel = prev # just for clarity of coding

        # THREAT node
        threat = self.addThreatNode()
        self.addTransition(lastPrel, threat, 5, sshConds)
        # and the THREAT -> THREAT transition
        self.addTransition(threat, threat, 5, sshConds)
        self.addTimeout(threat, 5000)

        ##### FAST SSH #####
        fastPrel = self.addPrelimNode()
        fastConds = sshConds[:]
        fastConds.append(lambda p: p.time < self.lastAttackStart
                                            + timedelta(seconds=5))
        self.addTransition(firstPrel, fastPrel, 1, fastConds)
        self.addTimeout(fastPrel, 500)

        # repeating PRELIM nodes for fast attack
        # There are fewer of these, as it is presumable less likely to get a
        # legal large set of really fast login packets
        prev = fastPrel
        for i in range(10):
            new = self.addPrelimNode()
            self.addTransition(prev, new, 1, sshConds)
            self.addTimeout(new, 500)
            prev = new
        lastPrel = prev

        # the THREAT node
        threat = self.addThreatNode()
        self.addTransition(lastPrel, threat, 5, sshConds)
        # and the THREAT -> THREAT transition
        self.addTransition(threat, threat, 5, sshConds)
        self.addTimeout(threat, 500)

        ### MYSQL ##########
        # DERP
        """


    def addSingleProfile(self, firstPrel, conds, extraConds, numRepNodes, 
                         timeout):
        prel = self.addPrelimNode(timeout)
        self.addTransition(firstPrel, prel, 1, extraConds)

        # repeating PRELIM nodes for slow attack
        prev = prel
        for i in range(numRepNodes):
            new = self.addPrelimNode(timeout)
            self.addTransition(prev, new, 1, conds)
            prev = new
        lastPrel = prev # just for clarity of coding

        # THREAT node
        threat = self.addThreatNode(timeout)
        self.addTransition(lastPrel, threat, 5, conds)
        # and the THREAT -> THREAT transition
        self.addTransition(threat, threat, 5, conds)
