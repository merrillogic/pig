from django.http import HttpResponse
from django.template import RequestContext, loader
from django.db.models import Avg, Max, Count, Q
from annoying.decorators import ajax_request
from honeywall.models import Attack, Packet, RecordCount

@ajax_request
def traffic_analysis(request):
    d = {}
    total_attack_count = Attack.objects.filter(false_positive=False).count()
    total_packet_count, created = RecordCount.objects.get_or_create(record='packets')
    total_packet_count = total_packet_count.record_count

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

def index(request):
    t = loader.get_template('index.html')
    c = RequestContext(request, None)

    return HttpResponse(t.render(c))

def attack(request, attack_id):
    t = loader.get_template('attack.html')
    c = RequestContext(request, {'attack_id': attack_id,})

    return HttpResponse(t.render(c))
