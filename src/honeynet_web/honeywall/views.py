from datetime import datetime
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from annoying.decorators import ajax_request
from honeywall.models import Packet, Attack
from honeywall.utils import packet_to_dict, attack_to_dict, json_response

@ajax_request
def attack(request, attack_id):
    if not request.method == 'GET':
        return HttpResponse(status=405)

    a = get_object_or_404(Attack, pk=attack_id)
    return attack_to_dict(a)


@ajax_request
def attack_packets(request, attack_id):
    if not request.method == 'GET':
        return HttpResponse(status=405)

    a = get_object_or_404(Attack, pk=attack_id)
    packets = Packet.objects.filter(attack=a).order_by('time')

    return [packet_to_dict(p) for p in packets]

@ajax_request
def attacks(request):
    if not request.method == 'GET':
        return HttpResponse(status=405)

    since = request.GET.get('since')
    if since:
        try:
            since = int(since)
        except (ValueError, TypeError):
            since = None

    query = Attack.objects.all()
    if since:
        query = query.filter(start_time__gt=datetime.utcfromtimestamp(since))

    return [attack_to_dict(a) for a in attacks]
