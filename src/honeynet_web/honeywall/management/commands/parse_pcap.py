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

        for packet in pcap:
            p = Packet(**packet)
            p.save()

        transaction.commit()
