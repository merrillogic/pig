from django.core.management.base import BaseCommand
from django.db import transaction
from honeynet_web.honeywall.models import ARPRecord
from honeynet_web.honeywall.utils import parse_arp_records

class Command(BaseCommand):
    args = '<arp-table file>'
    help = 'Parses a list of ARP records in BSD format into the DB.'

    def handle(self, *args, **options):
        arp_file = args[0]
        with open(arp_file) as f:
            parse_arp_records(f.readlines())

