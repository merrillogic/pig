from django.core.management.base import BaseCommand
from honeynet_web.honeywall.models import Packet, TrafficPoint
from django.db import transaction
from django.db.models import Max, Q
import datetime

@transaction.commit_manually
class Command(BaseCommand):
    def handle(self, *args, **options):
        packets = Packet.objects.filter(Q(traffic_point=None)).order_by('time')
        
        try:
            newest_traffic_point = TrafficPoint.objects.all()[0]
        except IndexError:
            newest_traffic_point = TrafficPoint(time = packets[0].time, 
                                                num_all_packets = 0,
                                                num_high_packets = 0,
                                                num_medium_packets = 0,
                                                num_low_packets = 0)
        
        for packet in packets:
            if (packet.time - newest_traffic_point.time) >= datetime.timedelta(minutes = 30):
                #save newest_traffic_point
                newest_traffic_point.save()
                transaction.commit()
                
                #create a new traffic point
                newest_traffic_point = TrafficPoint(time = newest_traffic_point.time + datetime.timedelta(minutes = 30),
                                                    num_all_packets = 0,
                                                    num_high_packets = 0,
                                                    num_medium_packets = 0,
                                                    num_low_packets = 0)            
            
            #add this packet to newest_traffic_point
            packet.traffic_point = newest_traffic_point
            packet.save()
            newest_traffic_point.num_all_packets += 1
            
            attacks = packet.attacks.filter(Q(false_positive = False))
            
            if attacks.count() > 0:
                score = attacks.aggregate(Max('score'))['score__max']
            
                if score >= 100000:
                    newest_traffic_point.num_high_packets += 1
                elif score >= 50000:
                    newest_traffic_point.num_medium_packets += 1
                else:
                    newest_traffic_point.num_low_packets += 1
                    
        newest_traffic_point.save()
        transaction.commit()
