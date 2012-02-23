/*
 *index.js
 *
 *for index.html, for plotting chart in upper row and handling
 *row clicks on main table
 *
 */

//Function that handles clicking of rows on attack table
$(document).ready(function() {
    $('#main_table td').click(function(event) {
        var aid = $(this).parent().children('#aid').text();
        var jsonAttack = JSON.parse(getAttack(aid));

        $('#type').text(jsonAttack.attack_type);
        $('#start').text(jsonAttack.start_time);
        $('#end').text(jsonAttack.end_time);
        $('#source').text(jsonAttack.source_ip);
        $('#dest').text(jsonAttack.destination_ip);
        $('#score').text(jsonAttack.score);
        
        $('#attack_button').attr('href', 'attack/' + aid);
    });
});

function getAttack(aid){
    var xmlHttp = null;
    
    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/attack/' + aid + '/?format=json', false);
    xmlHttp.send(null);
    
    return xmlHttp.responseText;
}

/*
 *Flot driven dynamic plot
 */
$(function () {
    var all_packets = {
        color: '#000000',
        data: [[0, 53], [1, 48], [2, 55], [3, 44], [4, 58], [5, 54]],
        label: 'all'
    };
    var low_threat = {
        color: '#ffcc00',
        data: [[0, 20], [1, 21], [2, 23], [3, 19], [4, 33], [5, 28]],
        label: 'low threat'
    };
    var medium_threat = {
        color: '#ff6600',
        data: [[0, 5], [1, 7], [2, 6], [3, 10], [4, 9], [5, 4]],
        label: 'medium threat'
    };
    var high_threat = {
        color: '#ff1919',
        data: [[0, 0], [1, 0], [2, 2], [3, 15], [4, 16], [5, 22]],
        label: 'high threat'
    };

    var placeholder = $("#placeholder");
    var plot = $.plot(placeholder, [all_packets, low_threat, medium_threat, high_threat]);

    placeholder.resize(function () {
    });
});

/*
 *Knockout driven dynamic table entries
 */
function attack(attackEntry){
    var self = this;
    self.aid = ko.observable(attackEntry.id);
    self.attackType = ko.observable(attackEntry.attack_type);
    self.time = ko.observable(attackEntry.start_time);
    self.sourceIp = ko.observable(attackEntry.source_ip);
    self.threatLevel = ko.observable(attackEntry.score);
    
    if(attackEntry.false_positive){
        self.level = "none";
    }else if(attackEntry.score >= 100000){
        self.level = "high";    
    }else if(attackEntry.score >= 50000){
        self.level = "medium";
    }else{
        self.level = "low";
    }
};

function attacksViewModel(){
    var self = this;
    var jsonAttackObj = JSON.parse(getAttacks());
    var attackList = jsonAttackObj.objects;
    self.attacks = ko.observableArray([]);
    
    for(var i = 0; i < attackList.length; i++){
        self.attacks.push(new attack(attackList[i]));
    }
};

function getAttacks(){
    var xmlHttp = null;
    
    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/attack/?format=json', false);
    xmlHttp.send(null);
    
    return xmlHttp.responseText;
};

ko.applyBindings(new attacksViewModel());
