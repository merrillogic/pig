from django.core.management.base import BaseCommand
from django.db import transaction
from honeynet_web.honeywall.models import Packet
from Packeteer import PacketReader

class Command(BaseCommand):
    args = '<pcap-file>'
    help = 'Parses a pcap file into the DB.'

    @transaction.commit_manually
    def handle(self, *args, **options):
        pcap_file = args[0]
        pcap = PacketReader(pcap_file)

        #### Get Chris to name fields same way as in model
        #### unpack dictionary into constructor
        for packet in pcap:
            p = Packet()
            # required fields
            p.source_ip = packet['src']
            p.time = packet['time']
            #p.protocol = packet['protocol']

            # optional fields

            #p.save()

        transaction.commit()
