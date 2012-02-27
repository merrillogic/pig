from django.core.management.base import BaseCommand
from honeynet_web.honeywall.models import Packet, TrafficPoint
from django.db import connection, transaction
from django.db.models import Count, Max, Q
import datetime, time

@transaction.commit_manually
class Command(BaseCommand):
    def handle(self, *args, **options):
        cursor = connection.cursor()
        time_span = datetime.timedelta(minutes = 30)
             
        while True:
            #grab all unclassified packets
            packets = Packet.objects.filter(Q(traffic_point = None)).order_by('time')
            print packets.count()
            
            if packets.count() > 0:
                try:
                    #get closest available traffic point
                    cur_traffic_point = TrafficPoint.objects.filter(Q(time__lte = packets[0].time))[0]
                    
                    
                    while (packets[0].time - cur_traffic_point.time) > time_span:
                        #the oldest packet does not fall within the 30 minutes 
                        #covered by this traffic point, create a new traffic point
                        print 'new traffic point!'
                        cur_traffic_point = TrafficPoint(cur_traffic_point.time + time_span, 
                                                         num_all_packets = 0,
                                                         num_high_packets = 0,
                                                         num_medium_packets = 0,
                                                         num_low_packets = 0)
                        
                except IndexError:
                    #no traffic points exists
                    #create one using the oldest packet time
                    print 'first traffic point!'
                    cur_traffic_point = TrafficPoint(time = packets[0].time, 
                                                     num_all_packets = 0,
                                                     num_high_packets = 0,
                                                     num_medium_packets = 0,
                                                     num_low_packets = 0)
                

                #get all unmarked packets that fall into this traffic point
                cur_packets = packets.filter(Q(time__gte = cur_traffic_point.time) & 
                                             Q(time__lt = cur_traffic_point.time + time_span))
                
                if cur_packets.count() > 0:
                    print 'got ' + str(cur_packets.count()) + ' packets'
                    for attack in cur_packets[0].attacks.all():
                        print attack.score, attack.false_positive
                    cur_traffic_point.num_all_packets += cur_packets.count()
                    print 'all: ' + str(cur_traffic_point.num_all_packets)
                    
                    print 'marking packets'
                    
                    #mark packets to show that it has been checked
                    cursor.execute("UPDATE honeywall_packet SET traffic_point_id = %s WHERE time >= %s AND time < %s", 
                                   [cur_traffic_point.id, cur_traffic_point.time, cur_traffic_point.time + time_span])

                    print 'done marking packets'
                    #get number of attacks and max score for each packet
                    cur_packets = cur_packets.annotate(num_attacks = Count('attacks'), max_score = Max('attacks__score'))
                    
                    #get rid of all packets that don't have an attack
                    cur_packets = cur_packets.filter(Q(num_attacks__gt = 0))
                    print 'packets with attacks: ' + str(cur_packets.count())
                    no_false_positive_packets = cur_packets.filter(~Q(attacks__false_positive = True)) #this line is wrong
                    print 'no false positive packets: ' + str(no_false_positive_packets.count())
                    cur_traffic_point.num_high_packets += no_false_positive_packets.filter(Q(max_score__gte = 100000)).count()
                    print 'high: ' + str(cur_traffic_point.num_high_packets)
                    
                    cur_traffic_point.num_medium_packets += no_false_positive_packets.filter(Q(max_score__gte = 50000) & Q(max_score__lt = 100000)).count()
                    print 'medium: ' + str(cur_traffic_point.num_medium_packets)
                    
                    cur_traffic_point.num_low_packets += no_false_positive_packets.filter(Q(max_score__lt = 50000)).count()
                    print 'low: ' + str(cur_traffic_point.num_low_packets)
                    
                    for packet in cur_packets.filter(Q(attacks__false_positive = True)):
                        print 'print checking'
                        max_score = -1
                        
                        for attack in packet.attacks.all():
                            if not attack.false_positive:
                                max_score = max(max_score, attack.score)
                                
                        if max_score >= 100000:
                            cur_traffic_point.num_high_packets += 1
                        elif max_score >= 50000:
                            cur_traffic_point.num_medium_packets += 1
                        elif max_score >= 0:
                            cur_traffic_point.num_low_packets += 1
                 
                cur_traffic_point.save()
                transaction.commit()
                print 'done iteration'
                raw_input()
            else:
                print 'sleep'
                time.sleep(60) #1 minute
