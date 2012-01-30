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
Source IP -> 'src'
Destination IP -> 'dst'
Length -> 'len'
Options -> 'options'
ID# -> 'id'
Flags -> 'flags'
Time -> 'time'
TCP/UDP -> 'layer'


To avoid potential conflicts with scapy classes, no class variables or
    names will be 'packet.'
'''

#Currently: when the reader is initialized, we make every packet object
#           Should this instead be done in getPacketChunk? 
#           Shorter initialization time vs. Packet chunk retrieval time

class PacketReader:
    def __init__(self,pcapFile):
        self.packetList = []
        self.chunkCounter = 0
        self.pcap = rdpcap(pcapFile)
        
        #Let's set the time!
        self.startTime = self.pcap[0].time
        
        for packetCap in self.pcap:
            self.packetList.append(Packeteer(packetCap, self.startTime))

    def __getitem__(self, i):
        return self.packetList[i]
    
    def getPacketChunk(size):
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
    
class Packeteer:
    def __init__(self, singlePacket, start):
        self.packet = singlePacket
        self.dict = {}
        self.time = self.packet.time - start
        self.detectLayer()

    def __getitem__(self, item):
        if item == 'payload':
            return str(self.getPayload())
        elif item == 'time':
            return self.time
        elif item == 'layer':
            return self.dict[item]
        else:
            return self.getIPField(item)
        
    def getIPField(self, field):
        if field in self.dict:
            return self.dict[field]
        else:
            try:
                fieldval = self.packet[IP].getfieldval(field)
            except IndexError:
                fieldval = None
            self.dict[field] = fieldval
            return fieldval
        
    def getEthField(self, field):
        return self.packet.getfieldval(field)
        
    def getPayload(self): 
        if "payload" in self.dict:
            return self.dict["payload"]
        else:
            try:
                fieldval = self.packet[TCP].payload
            
            except IndexError:
                fieldval = self.packet[UDP].payload
            self.dict["payload"] = fieldval
            return fieldval

    def detectLayer(self):
        if self.packet.haslayer(UDP):
            self.dict['layer'] = 'UDP'
        elif self.packet.hasLayer(TCP):
            self.dict['layer'] = 'TCP'
    
    
    def source(self):
        return self.getIPField("src")
        
    
    def destination(self):
        return self.getIPField("dst")
        
    
    def length(self):
        return self.getIPField("len")
    
        
    def options(self):
        return self.getIPField("options")
        
    
    def id(self):
        return self.getIPField("id")
        
    
    def flags(self):
        return self.getIPField("flags")
        
    
    def sourceMAC(self):
        return self.getEthField("src")
        
    
    def destinationMAC(self):
        return self.getEthField("dst")

if __name__ == '__main__':
    a = PacketReader("wiresharkCaptures/loic_dos")
    b = a[13]
    b[source]
