'''Debugging command that parses a directory of pcap files into the db.
'''
from cProfile import Profile
from optparse import make_option
from django.core.management.base import BaseCommand
from django.db import transaction
from honeynet_web.honeywall.models import Packet
from Packeteer import PacketReader
import os

class Command(BaseCommand):
    args = '<pcap-dir>'
    option_list = BaseCommand.option_list + (
    make_option('--profile',
        action='store_true',
        dest='profile',
        default=False,
        help='profiles the command'),
    )

    help = 'Parses a directory of pcap files into the DB.'

    @transaction.commit_manually
    def _handle(self, *args, **options):
        pcap_dir = args[0]
        pcaps = os.listdir(pcap_dir)
        for pcap_file in pcaps:
            print "current file: ", pcap_dir+ pcap_file
            pcap = PacketReader(pcap_dir+pcap_file)

            for packet in pcap:
                p = Packet(**packet)
                p.save()

        transaction.commit()

    def handle(self, *args, **options):
        if options['profile']:
            profiler = Profile()
            profiler.runcall(self._handle, *args, **options)
            profiler.print_stats()
        else:
            self._handle(*args, **options)

