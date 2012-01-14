class Node:
	def __init__(self):
		self.repeatCount = 10 #How many times this node can link back to itself
		self.timeout = 1 #timeout, in seconds
		
	def addLink(self, triggers, 
		
#Intersting thought: How do we account for time delay between packets? Automata generally don't care. There are two things I can think of:
#1. The automata node has a timer, and on timeout will redirect to an alternate node. (I like this)
#2. When we read in packets, we include a calculation from the last packet from that source (by maintaining
#	a 'last packet at' dictionary with all the ips and their last time recieved.) (I don't like this)