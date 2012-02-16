from datetime import datetime
from scapy.all import *

'''
USAGE:
from Packeteer import *
packetList = PacketReader("pcapFile")
singlePacket = packetList[45]
singlePacket['payload']


Currently supported attributes:
<Attribute -> 'Dictionary key'>
Payload -> 'payload'
Source MAC -> 'source_mac'
Source IP -> 'source_ip'
Destination IP -> 'destination_ip'
Source Port -> 'source_port'
Destination Port -> 'dest_port'
Length -> 'len'
Options -> 'options'
ID# -> 'packet_id'
Flags -> 'flags'
Time -> 'time'
protocol -> 'protocol'


To avoid potential conflicts with scapy classes, no class variables or
    names will be 'packet.'
'''

#Currently: when the reader is initialized, we make every packet object
#           Should this instead be done in getPacketChunk?
#           Shorter initialization time vs. Packet chunk retrieval time

class PacketReader(object):
    def __init__(self,pcapFile):
        self.packetList = []
        self.chunkCounter = 0
        self.pcap = rdpcap(pcapFile)

        for packetCap in self.pcap:
            if not packetCap.haslayer(LLC):
                self.packetList.append(Packeteer(packetCap))

    def __iter__(self):
        return iter(self.packetList)

    def __getitem__(self, i):
        return self.packetList[i]

    def getPacketChunk(self, size):
        '''
        Breaks off a size number of packets and returns them in a list.
        '''
        returnList = []
        for item in range(size):
            if item+self.chunkCounter >= len(self.packetList):
                break

            returnList.append(self.packetList[item+self.chunkCounter])
            self.chunkCounter += 1
        return returnList

class Packeteer(object):
    def __init__(self, singlePacket):
        self.packet = singlePacket
        self.dict = self._populate_dict()

    def _populate_dict(self):
        d = {}
        IPLayer = self.packet.payload
        # required fields
        d['time'] = datetime.utcfromtimestamp(self.packet.time)
        d['source_mac'] = self.packet.src


        # optional fields
        try:
            d['packet_id'] = IPLayer.id
        except AttributeError:
            pass

        try:
            d['protocol'] = IPLayer.proto
        except AttributeError:
            pass
        try:
            if self.packet.haslayer(ARP):
                d['source_ip'] = IPLayer.psrc
            else:
                d['source_ip'] = self.packet.payload.src
        except AttributeError:
            pass
        try:
            if self.packet.haslayer(ARP):
                d['destination_ip'] = IPLayer.pdst
            else:
                d['destination_ip'] = IPLayer.dst
        except AttributeError:
            pass
        try:
            d['source_port'] = self.packet.sport
        except AttributeError:
            pass
        try:
            d['dest_port'] = self.packet.dport
        except AttributeError:
            pass
        try:
            d['destination_mac'] = self.packet.dst
        except AttributeError:
            pass
        try:
            if str(self.packet.lastlayer()):
                d['payload'] = str(self.packet.lastlayer())
            else:
                d['payload'] = ''

        except AttributeError:
            pass

        if not d.get('source_ip'):
            print 'HALP'
            self.packet.show()

        return d

    def keys(self):
        ## returns a list of all of the keys
        return self.dict.keys()

    def __getitem__(self, item):
        return self.dict[item]

    @property
    def id(self):
        if 'id' in self.dict:
            return self.dict['packet_id']
        else:
            return None

if __name__ == '__main__':
    import sys
    assert len(sys.argv) == 2, "Usage: python Packeteer.py pcapFile"
    a = PacketReader(sys.argv[1])
