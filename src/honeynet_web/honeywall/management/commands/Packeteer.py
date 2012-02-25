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
'''
from datetime import datetime
from scapy.all import *


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
	For debugging purposes.
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

        hasIPField = lambda x: x in IPLayer.fields
        # optional fields
	# here we'll have to check if each attribute exists before grabbing it
        if hasIPField('id'):
            d['packet_id'] = IPLayer.id

        if hasIPField('proto'):
            d['protocol'] = IPLayer.proto
            
        if self.packet.haslayer(ARP):
            if hasIPField('psrc'):
                d['source_ip'] = IPLayer.psrc
            if hasIPField('pdst'):
                d['destination_ip'] = IPLayer.pdst
        else:
            if hasIPField('src'):
                d['source_ip'] = IPLayer.src
            if hasIPField('dst'):
                d['destination_ip'] = IPLayer.dst
       
        if self.packet.haslayer(IP):
            if 'sport' in IPLayer.payload.fields:
                d['source_port'] = self.packet.sport
            if 'dport' in IPLayer.payload.fields:
                d['dest_port'] = self.packet.dport

        if 'dst' in self.packet.fields:
            d['destination_mac'] = self.packet.dst
           
        if str(self.packet.lastlayer()):
            d['payload'] = str(self.packet.lastlayer())
        else:
            d['payload'] = ''

        if not d.get('source_ip'):
            print "Unexpected error! Source IP not found!"
            self.packet.show()

        return d

    def keys(self):
        ## returns a list of all of the keys
        return self.dict.keys()

    def __getitem__(self, item):
        return self.dict[item]


if __name__ == '__main__':
    import sys
    assert len(sys.argv) == 2, "Usage: python Packeteer.py pcapFile"
    a = PacketReader(sys.argv[1])
