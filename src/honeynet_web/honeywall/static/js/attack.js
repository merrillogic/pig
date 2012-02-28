/*
 *attack.js
 *
 *for index.html, for handling row clicks on main table
 *
 *TODO: can't use django objects in javascript file
 */

var aid = $('#aid').text();

//fills in attack information table
function fillAttackInformation(){
    var jsonAttack = JSON.parse(getAttack());

    $('#type').text(jsonAttack.attack_type);
    $('#start').text(jsonAttack.start_time);
    $('#end').text(jsonAttack.end_time);
    $('#source').text(jsonAttack.source_ip);
    $('#destination').text(jsonAttack.destination_ip);
    $('#level').text(jsonAttack.score);
    document.getElementById("falsePositive").checked = jsonAttack.false_positive;
}

function getAttack(){
    var xmlHttp = null;

    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/attack/' + aid + '/?format=json', false);
    xmlHttp.send(null);

    return xmlHttp.responseText;
}

//handles updating false positive
function updateFalsePositive(checkbox){
    var xmlHttp = new XMLHttpRequest();

    xmlHttp.open("PUT", '/api/v1/classify/' + aid + '/?format=json', false);
    xmlHttp.setRequestHeader('Content-Type', 'application/json');
    xmlHttp.send('{"false_positive": ' + checkbox.checked + '}');
}

//Function that handles clicking of rows on attack table
$(document).ready(function() {
    $('#main_table td').click(function(event) {
        var pid = $(this).parent().children('#idCol').text();
        var jsonPacket = JSON.parse(getPacket(pid));

        $('#payload_info').text(base64Decode(jsonPacket._payload));
    });
});

function getPacket(pid){
    var xmlHttp = null;

    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/packet/' + pid + '/?format=json', false);
    xmlHttp.send(null);

    return xmlHttp.responseText;
}

/*
 *Knockout driven dynamic packet table entry
 */
function packet(packetEntry){
    var self = this;
    self.pid = ko.observable(packetEntry.id);
    self.time = ko.observable(packetEntry.time);
    self.srcIp = ko.observable(packetEntry.source_ip);
    self.srcMac = ko.observable(packetEntry.source_mac);
    self.srcPort = ko.observable(packetEntry.source_port);
    self.destIp = ko.observable(packetEntry.destination_ip);
    self.destMac = ko.observable(packetEntry.destination_mac);
    self.destPort = ko.observable(packetEntry.dest_port);
    self.protocol = ko.observable(packetEntry.protocol);
};

function updatePacketEntry(packetObj, packetEntry){
    packetObj.pid(packetEntry.id);
    packetObj.time(packetEntry.time);
    packetObj.srcIp(packetEntry.source_ip);
    packetObj.srcMac(packetEntry.source_mac);
    packetObj.srcPort(packetEntry.source_port);
    packetObj.destIp(packetEntry.destination_ip);
    packetObj.destMac(packetEntry.destination_mac);
    packetObj.destPort(packetEntry.dest_port);
    packetObj.protocol(packetEntry.protocol);
};

function packetsViewModel(){
    var self = this;
    var jsonPacketObj = getPackets();
    var packetList = jsonPacketObj.objects;
    self.packets = ko.observableArray([]);
    self.nextPage = ko.observable(jsonPacketObj.meta.next);
    self.previousPage = ko.observable(jsonPacketObj.meta.previous);

    for(var i = 0; i < packetList.length; i++){
        self.packets.push(new packet(packetList[i]));
    }
    
    self.get_previous = function(){
        self.packets_from_url(self.previousPage());
    }
    
    self.get_next = function(){
        self.packets_from_url(self.nextPage());
    }
    
    self.packets_from_url = function(url){
        var jsonFilteredPackets = getPacketsFromURL(url); //get filtered attacks
        self.nextPage(jsonFilteredPackets.meta.next);
        self.previousPage(jsonFilteredPackets.meta.previous);

        if(jsonFilteredPackets.objects.length <= self.packets().length){
            //there are more attacks currently in the table than needed
            for(var i = 0; i < self.packets().length; i++){
                //if at this index, an attack exists within the json object array
                if(i < jsonFilteredPackets.objects.length){
                    //change the entry to reflect the filtered attack that was retrieved
                    updatePacketEntry(self.packets()[i], jsonFilteredPackets.objects[i]);
                }else{
                    //done with filtered attacks, but entries are left in the array so remove them
                    self.attacks.remove(self.packets()[i]);
                    i--;
                }
            }
        }else{
            //there are more filtered attacks than we can currently fit in the table
            for(var i = 0; i < jsonFilteredAttacks.objects.length; i++){
                //if at this index, a table entry exists
                if(i < self.packets().length){
                    //change the entry to reflect the filtered attack that was retrieved
                    updatePacketEntry(self.packets()[i], jsonFilteredPackets.objects[i]);
                }else{
                    //no more room in the table, create new row
                    self.attacks.push(new packet(jsonFilteredPackets.objects[i]));
                }
            }
        }
    }
};

function getPackets(){
    var xmlHttp = null;

    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/packet/?format=json&attack=' + aid, false);
    xmlHttp.send(null);

    return JSON.parse(xmlHttp.responseText);
};

function getPacketsFromURL(url){
    //get list of attacks from url
    var xmlHttp = new XMLHttpRequest();

    xmlHttp.open("GET", url, false);
    xmlHttp.send(null);

    return JSON.parse(xmlHttp.responseText);
}

fillAttackInformation();
ko.applyBindings(new packetsViewModel());
