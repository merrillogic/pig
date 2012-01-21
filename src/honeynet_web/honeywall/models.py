from django.db import models

class Packet(models.Model):
    source_ip = models.IntegerField()
    destination_ip = models.IntegerField()
    # protocal can be 0-255
    protocal = models.IntegerField()

    # should attacks be a many-to-one relationship or many-to-many?
    # i.e. can a single packet be used in multiple attacks?
    attack = models.ForeignKey('Attack')
    # other fields:
    ## data
    ## length
    ## identification
    ## time
    ## options
    ## flags
    ## ???

class Attack(models.Model):
    # fields:
    ## packets
    ## classification
    ## source
    ## target
    ## time
    ## ???
    pass
