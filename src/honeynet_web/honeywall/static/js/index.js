/*
 *index.js
 *
 *for index.html, for plotting chart in upper row and handling
 *row clicks on main table
 *
 *TODO: can't use django objects in javascript file
 */

$(function () {
    var d1 = [];
    for (var i = 0; i < 14; i += 0.5)
        d1.push([i, Math.sin(i)]);

    var d2 = [[0, 3], [4, 8], [8, 5], [9, 13]];

    // a null signifies separate line segments
    var d3 = [[0, 12], [7, 12], null, [7, 2.5], [12, 2.5]];

    var placeholder = $("#placeholder");
    
    var plot = $.plot(placeholder, [d1, d2, d3]);

    placeholder.resize(function () {
    });
});

//Function that handles clicking of rows on attack table
$(document).ready(function() {
    $('#main_table td').click(function(event) {
        var aid = $(this).parent().children('#idCol').text();
        
        {% for attack in attack_list %}
            if(aid == {{ attack.id }}){
                $('#type').text('{{ attack.attack_type }}');
                $('#start').text('{{ attack.start_time }}');
                $('#end').text('{{ attack.end_time }}');
                $('#source').text('{{ attack.source_ip }}');
                $('#dest').text('{{ attack.destination_ip }}');
                $('#score').text('{{ attack.score }}');
            }
        {% endfor %}
        
        $('#attack_button').attr('href', 'attack/' + aid);
    });
});
