from django.core.management.base import BaseCommand
from django.core.exceptions import FieldError
from honeynet_web.honeywall.models import Packet
from honeynet_web.packetAnalysis.analyzers.all import *
from optparse import make_option

class Command(BaseCommand):
    args = '<machine type> <packet filter 1> <filter 2> ...'

    # add the --list option, to list the keywords for each AttackAnalyzer type
    option_list = BaseCommand.option_list + (
                    make_option('-l',
                                '--list',
                                action='store_true',
                                dest='list_analyzers',
                                default=False,
                                help='List keywords for all AttackAnalyzer '\
                                     'types'),
                  )

    # informative help
    help = "Tests the results of running a single AttackAnalyzer on filtered "\
           "packets\n\n"\
           "For the packet filters, put in as many Django-style filters as "\
           "necessary; for example, to find all packets with a packet_id>4 "\
           "and source_ip of 137.22.73.135, enter the following:\n\n"\
           "python manage.py test_auto pass packet_id__gt=4 source_ip__exact"\
           "=\'137.22.73.135\'"

    # establish the dictionary keying keywords to Analyzer types
    analyzers = { 'sql' : 'SQLInjectionAnalyzer',
                  'pass' : 'PassCrackAnalyzer',
                  'mail' : 'MailAnalyzer',
                  'mitm' : 'MitMAnalyzer',
                  'dos' : 'DOSAnalyzer' }


    def handle(self, *args, **options):
        # if we need to list the available keywords, print them
        # human-readably
        if options['list_analyzers']:
            print "Keyword => Analyzer type\n",\
                  "------------------------"
            for key in self.analyzers:
                print key, ' => ', self.analyzers[key]
            return

        # if they didn't put in any filters, bail
        if len(args) < 2:
            print "No filters input! Run test_auto -h to see usage."
            return False

        # pull the type of AttackAnalyzer they want and parse the filters they
        # put in
        typ = args[0]
        unparsed_filters = args[1:]
        filters = {}
        for f in unparsed_filters:
            conds = f.split('=')
            filters[conds[0]] = conds[1]
        
        # initialize the AttackAnalyzer type
        try:
            analyzer = eval(self.analyzers[typ])('0.0.0.0', '0.0.0.0')
            pass
        except KeyError:
            print "Unsupported attack type"
            return False
            
        # pull the packets matching their filters
        try:
            packets = Packet.objects.filter(**filters)
            print "Number of packets: ",len(packets)
            return
        except FieldError as strerror:
            print "FieldError: ", strerror
            return False

        # run the analyzer in debug mode
        analyzer.DEBUG = True
        analyzer.processPackets(packets)
        analyzer.exportAttackData()
