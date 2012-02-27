from django.core.management.base import BaseCommand
from honeynet_web.honeywall.models import Packet, TrafficPoint
from django.db import transaction
from django.db.models import Max, Q
import datetime

@transaction.commit_manually
class Command(BaseCommand):
    def handle(self, *args, **options):
        while True:
            packets = Packet.objects.filter(Q(traffic_point=None)).order_by('time')

            if TrafficPoint.objects.all().count == 0 or (newest_traffic_point.time - packets[0].time) > datetime.timedelta(minutes = 30):
                newest_traffic_point = TrafficPoint(time = packets[0].time, 
                                                    num_all_packets = 0,
                                                    num_high_packets = 0,
                                                    num_medium_packets = 0,
                                                    num_low_packets = 0)
            else:
                newest_traffic_point = TrafficPoint.objects.all()[0]
            
            cur_packets = packets.filter(Q(time__gte = newest_traffic_point.time) & Q(time__lt = newest_traffic_point.time + datetime.timedelta(minutes = 30)))
            
            if cur_packets.count() > 0:
                print 'got packets'
                newest_traffic_point.num_all_packets = cur_packets.count()
                print 'all: ' + str(newest_traffic_point.num_all_packets)
                
                for packet in cur_packets:
                    packet.traffic_point = newest_traffic_point
                    packet.save()
                print 'done marking packets'
                #get rid of all packets that don't have an attack
                cur_packets = cur_packets.filter(~Q(attacks = None))
                
                cur_packets = cur_packets.annotate(num_attacks = Count('attacks'), max_score = Max('attacks__score'))
                
                no_false_positive_packets = cur_packets.filter(~Q(attacks__false_positive = True))
                
                newest_traffic_point.num_high_packets = no_false_positive_packets.filter(Q(max_score__gte = 100000)).count()
                print 'high: ' + str(newest_traffic_point.num_high_packets)
                
                newest_traffic_point.num_medium_packets = no_false_positive_packets.filter(Q(max_score__gte = 100000)).count()
                print 'medium: ' + str(newest_traffic_point.num_medium_packets)
                
                newest_traffic_point.num_low_packets = cur_packets.count() - newest_traffic_point.num_high_packet - newest_traffic_point.num_medium_packet
                print 'low: ' + str(newest_traffic_point.num_low_packets)
                
                for packet in cur_packets.filter(Q(attacks__false_positive = True) & Q(num_attacks__gt = 0)):
                    max_score = -1
                    
                    for attack in packet.attacks.all():
                        if not attack.false_positive:
                            max_score = max(max_score, attack.score)
                            
                    if max_score >= 100000:
                        newest_traffic_point.num_high_packets += 1
                    elif max_score >= 50000:
                        newest_traffic_point.num_medium_packets += 1
                    elif max_score >= 0:
                        newest_traffic_point.num_low_packets += 1
             
            newest_traffic_point.save()
            transaction.commit()
            print 'done, made traffic point',
            print newest_traffic_point
            raw_input()     
