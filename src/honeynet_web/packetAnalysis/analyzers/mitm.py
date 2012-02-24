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

    attackType = 'mitm'
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
        def _outside_network(packet):
            # assuming the network is a /24 subnet
            record = self.arp_tables['IP'].keys()[0]
            record = record.split('.')
            p = packet.source_ip.split('.')

            return not p[:-1] == record[:-1]

        def _wrong_ip_mac(packet):
            if packet.source_ip in self.arp_tables['IP']:
                return packet.source_mac != self.arp_tables['IP'][packet.source_ip]
            return False

        def _wrong_mac_ip(packet):
            if packet.source_mac in self.arp_tables['MAC']:
                return packet.source_ip != self.arp_tables['MAC'][packet.source_mac]
            return False

        return (_wrong_ip_mac(packet) or _wrong_mac_ip(packet)) and not(_outside_network(packet))


    def addAttackProfile(self):
        i = self.addThreatNode(10000) #10 second timeout
        prelim = self.addPrelimNode(10000)

        self.addTransition(0, prelim, 5, [self.isARPThreat])
        self.addTransition(prelim, i, 5, [self.isARPThreat])
        self.addTransition(i, i, 5, [self.isARPThreat])
