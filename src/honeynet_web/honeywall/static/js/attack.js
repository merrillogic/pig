/*
 *attack.js
 *
 *for index.html, for handling row clicks on main table
 *
 *TODO: can't use django objects in javascript file
 */

//Function that handles clicking of rows on attack table
$(document).ready(function() {
    $('#main_table td').click(function(event) {
        var pid = $(this).parent().children('#idCol').text();
        
        {% for packet in packet_list %}
            if(pid == {{ packet.id }}){
                $('#payload_info').text('{{ packet.payload }}');
            }
        {% endfor %}
    });
});
