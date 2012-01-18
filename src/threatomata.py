class Node:
	def __init__(self):
		self.repeatCount = 10 #How many times this node can link back to itself
		self.currentRepeat = self.repeatCount
		self.timeout = -1 #timeout, in seconds
		
	def addLink(self, triggers, score, destination):
		#to set a repeat, have the destination be self
		if not duplicate:
			add(link)
			return True
		else:
			return False
		
	def setTimeout(self, time, score, destination):
		#very much like a link
		return
		
	def processPacket(self, packet):
		for trigger in self.triggers:
			if match(packet, trigger):
				return trigger[destination, score] #expecting the attack to add that packet to the list of threatening packets related to it
		return False #that packet is not part of anything
			
	def decrementRepeat(self):
		self.currentRepeat -= 1
		
#Intersting thought: How do we account for time delay between packets? Automata generally don't care. There are two things I can think of:
#1. The automata node has a timer, and on timeout will redirect to an alternate node. (I like this)
#2. When we read in packets, we include a calculation from the last packet from that source (by maintaining
#	a 'last packet at' dictionary with all the ips and their last time recieved.) (I don't like this)