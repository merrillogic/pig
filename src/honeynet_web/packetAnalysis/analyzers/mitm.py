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
from honeywall.models import ARPRecord

class MitMAnalyzer(AttackAnalyzer):

    type = 'maninthemiddle'
    __arp_tables = {'IP': {}, 'MAC': {}}

    @property
    def arp_tables(self):
        if not self.__arp_tables['IP'] or not self.__arp_tables['MAC']:
            records = ARPRecord.objects.all()
            for record in records:
                self.__arp_tables['IP'][record.ip] = record.mac
                self.__arp_tables['MAC'][record.mac] = record.ip

        return self.__arp_tables

    def isARPThreat(self, packet):
        if (packet.source_ip in self.arp_tables['IP'] and packet.source_mac != \
            self.arp_tables['IP'][packet.source_ip]) or \
            packet.source_mac in self.arp_tables['MAC'] and packet.source_ip != \
            self.arp_tables['MAC'][packet.source_mac]
        #### a) packet.source_ip in self.arp_tables['IP'] and
        ####    packet.source_mac != self.arp_tables['IP'][packet.source_ip]
        #### OR
        #### b) packet.source_mac in self.arp_tables['MAC'] and
        ####    packet.source_ip != self.arp_tables['MAC'][packet.source_mac]

    def addAttackProfile(self):
        self.addThreatNode(600000) #10 minute timeout

        self.addTransition(self.nodes[0], self.nodes[-1], 5, [isARPThreat])
        self.addTransition(self.nodes[-1], self.nodes[-1], 5, [isARPThreat])
        pass
