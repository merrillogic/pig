from django.core.management.base import BaseCommand
from django.db import transaction
from honeynet_web.honeywall.models import Packet
from honeynet_web.packetAnalysis.controller import Controller 
from datetime import datetime
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
                            classification_time__isnull=True).order_by(
                                                                'time')[:10000]
            # mark them as fed into the analyzers
            print "Marking them as seen..."
            timenow = datetime.now()
            self.mark_packets(newPackets, timenow)
            # hand them to the controller's packetBuffer
            controller.bufferPackets(newPackets)
            print "Assigning them to their Connections..."
            controller.assignPackets()
            print "Processing..."
            controller.processPackets()
            print "WATE 4 DUH PURKURTZZZ..."
            time.sleep(5)

    @transaction.commit_manually
    def mark_packets(self, newpackets, timenow):
        for p in newpackets:
            p.classification_time = timenow
            p.save()
        transaction.commit()
