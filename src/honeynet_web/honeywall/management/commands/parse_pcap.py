from cProfile import Profile
from optparse import make_option
import sys
from django.core.management.base import BaseCommand
from django.db import transaction, IntegrityError
from honeynet_web.honeywall.models import Packet
from Packeteer import PacketReader

class Command(BaseCommand):
    args = '<pcap-file>'
    option_list = BaseCommand.option_list + (
    make_option('--profile',
        action='store_true',
        dest='profile',
        default=False,
        help='profiles the command'),
    )

    help = 'Parses a pcap file into the DB.'

    @transaction.commit_manually
    def _handle(self, *args, **options):
        pcap_file = args[0]
        print 'Parsing %s' %pcap_file
        pcap = PacketReader(pcap_file)

        try:
            for packet in pcap:
                p = Packet(**packet)
                p.save()
            transaction.commit()
            print '%s parsed successfully.' %pcap_file
        except IntegrityError:
            transaction.rollback()
            sys.stderr.write('ERROR: %s was already parsed.\n' %pcap_file)


    def handle(self, *args, **options):
        if options['profile']:
            profiler = Profile()
            profiler.runcall(self._handle, *args, **options)
            profiler.print_stats()
        else:
            self._handle(*args, **options)

