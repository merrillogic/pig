from django.core.management.base import BaseCommand
from honeynet_web.honeywall.models import Packet
from honeynet_web.packetAnalysis.controller import Controller 
import time

class Command(BaseCommand):
    help = 'Starts the eternally-running packet analysis loop; '\
           'Terminate with Ctrl+D'

    def handle(self, *args, **options):
        controller = Controller()
        while True:
            # pull the next 10,000 unprocessed packets
            print "Pulling new packets..."
            newPackets = Packet.objects.filter(
                            classification_time__isnull=True)[:10000]
            controller.bufferPackets(newPackets)
            print "Assigning them to their Connections..."
            controller.assignPackets()
            print "Processing..."
            controller.processPackets()
            print "WATE 4 DUH PURKURTZZZ..."
            time.sleep(5)
