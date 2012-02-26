from django.http import HttpResponse
from django.template import RequestContext, loader
from django.db.models import Avg, Max, Count, Q
from annoying.decorators import ajax_request
from honeywall.models import Attack, Packet
import datetime

@ajax_request
def traffic_analysis(request):
    d = {}
    total_attack_count = Attack.objects.filter(false_positive=False).count()
    total_packet_count = Packet.objects.count()

    for attack_type, description in Attack.ATTACK_CHOICES:
        attacks = Attack.objects.filter(attack_type=attack_type, false_positive=False).order_by('-start_time')
        d[attack_type] = {}
        if attacks:
            most_recent = attacks[0]
            d[attack_type]['last_attack'] = most_recent.start_time.isoformat()
        else:
            d[attack_type]['last_attack'] = None

        d[attack_type]['high_score'] = attacks.aggregate(Max('score'))['score__max']
        d[attack_type]['average_score'] = attacks.aggregate(Avg('score'))['score__avg']

        if attacks.count() != 0:
            d[attack_type]['percent_attacks'] = attacks.count()*1.0 / total_attack_count
            d[attack_type]['percent_traffic'] = 1.0 / total_packet_count

            false_positives = Attack.objects.filter(attack_type=attack_type, false_positive=True).count()
            d[attack_type]['percent_false_positives'] = false_positives*1.0 / (attacks.count() + false_positives)
        else:
            d[attack_type]['percent_attacks'] = None
            d[attack_type]['percent_traffic'] = None
            d[attack_type]['percent_false_positives'] = None

    return d
    
def plot_data(request):
    d = {}
    newest_packet_time = Packet.objects.all().order_by('-time')[0].time
    packets = Packet.objects.filter(time__gte = newest_packet_time - datetime.timedelta(days = 1))
    
    print packets.count()
    #need a point every 30 min, twice an hour, thus 24 * 2
    for i in range(24 * 2, 0, -1):
        print 'started iteration #' + str(-1 * (i - 24 * 2))
        points = {}
        
        packets = Packet.objects.filter(Q(time__gt = newest_packet_time - datetime.timedelta(minutes = i * 30)) & Q(time__lte = newest_packet_time - datetime.timedelta(minutes = (i - 1) * 30)))
#            time__gt = newest_packet_time - datetime.timedelta(minutes = i * 30)).filter(
#                time__lte = newest_packet_time - datetime.timedelta(minutes = (i - 1) * 30))

        if packets.count() > 0:
            print '\tgot packets'
            points['all'] = packets.count()
            print '\tall: ' + str(points['all'])
            #get rid of all packets that don't have an attack associated with it
            packets = packets.filter(~Q(attacks=None))
            
            #get max attack score and number of attacks associated with each packet
            packets = packets.annotate(num_attacks = Count('attacks'), max_score = Max('attacks__score'))
            
            #get all packets that do not have an attack marked as false positive
            no_false_positive_packets = packets.filter(~Q(attacks__false_positive = True))
            
            points['high'] = no_false_positive_packets.filter(Q(max_score__gte=100000)).count()
            print '\thigh: ' + str(points['high'])
            points['medium'] = no_false_positive_packets.filter(Q(max_score__lt=100000) & Q(max_score__gte=50000)).count()
            print '\tmedium: ' + str(points['medium'])
            points['low'] = no_false_positive_packets.filter(Q(max_score__lt=50000)).count()
            print '\tlow:' + str(points['low'])
            
            #go through all packets that do have an attack marked as false positive
            for packet in packets.filter(Q(attacks__false_positive = True) & Q(num_attacks__gt = 0)):
                max_score = -1
                
                for attack in packet.attacks.all():
                    if not attack.false_positive:
                        max_score = max(max_score, attack.score)
                    
                if max_score >= 100000:
                    points['high'] += 1
                elif max_score >= 50000:
                    points['medium'] += 1
                elif max_score >= 0:
                    points['low'] += 1            

            #first iteration, when i = 48, is the first point, so x = 0
            d[-1 * (i - 24 * 2)] = points
            print points
        else:
            d[-1 * (i - 24 * 2)] = {'all': 0, 'high': 0, 'medium': 0, 'low': 0}
        print 'done with iteration #' + str(-1 * (i - 24 * 2))
        
    return d


def index(request):
    t = loader.get_template('index.html')
    c = RequestContext(request, None)

    return HttpResponse(t.render(c))

def attack(request, attack_id):
    t = loader.get_template('attack.html')
    c = RequestContext(request, {'attack_id': attack_id,})

    return HttpResponse(t.render(c))
