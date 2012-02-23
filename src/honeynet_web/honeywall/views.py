from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.template import RequestContext, loader
from honeywall.models import Attack, Packet

def index(request):
    t = loader.get_template('index.html')
    c = RequestContext(request, None)

    return HttpResponse(t.render(c))

def attack(request, attack_id):
    selected_attack = get_object_or_404(Attack, id=attack_id)
    packet_list = Packet.objects.filter(attacks__in = [selected_attack])
    t = loader.get_template('attack.html')
    c = RequestContext(request, {'packet_list': packet_list, 'attack': selected_attack,})

    return HttpResponse(t.render(c))
