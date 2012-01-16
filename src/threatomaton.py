from time import time

SAFE = 0
POSSIBLE = 1
ATTACK = 2

class Threatomaton:
	
	timeoutVal = -1

	nodes = {}
	curNode = None
	curState = SAFE

	lastPotentialAttackTime = 0
	attackDuration = 0



	def __init__(self):
		pass
	
	def handlePackets(self, packets):
		prevState = self.curState
		for packet in packets:
			self.curNode = self.curNode.handlePacket(packet)
			## update curState somehow

			## if moving from safety into warm/hot zone, mark that an attack may have started
			if prevState == SAFE and self.curState != prevState:
				prevState = None
				self.lastPotentialAttackTime = time()

			## if moving from hot zone to safety, attack just finished, so mark its length and export to DB 
			elif prevState == ATTACK and self.curState == SAFE:
				self.attackDuration = time() - self.lastPotentialAttackTime
				self.exportAttackData()

		## if we've hit the end of the packet set and it's been a long time since we've seen a potential
		## attack packet, timeout to reset
		if time() - self.lastPotentialAttackTime >= self.timeoutVal:
			self.timeout()

	def exportAttackData(self):
		pass
	
	def timeout(self):
		self.lastPotentialAttackTime = 0
		self.curState = SAFE

	

def _test():
	th = Threatomaton()
	print th.timeoutVal
if __name__=='__main__':_test()
