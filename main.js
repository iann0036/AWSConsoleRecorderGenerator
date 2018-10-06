var only_one_select = false;

function stringToColour(str) {
    var hash = 0;
    for (var i = 0; i < str.length; i++) {
      hash = str.charCodeAt(i) + ((hash << 5) - hash);
    }
    var colour = '#';
    for (var i = 0; i < 3; i++) {
      var value = (hash >> (i * 8)) & 0xFF;
      colour += ('00' + value.toString(16)).substr(-2);
    }
    return colour;
}

chrome.runtime.sendMessage(null, {
    "action": "getCombined"
}, null, function(combined){
    var combined_select = '';
    for (var service in combined) {
        for (var operation in combined[service]['operations']) {
            var operation_name = combined[service]['operations'][operation]['name'];
            combined_select += `<option>${service}.${operation_name}</option>`;
        }
    }

    chrome.runtime.sendMessage(null, {
        "action": "getRequests"
    }, null, function(response){
        for (var i=0; i<response.length; i++) {
            console.log(response[i]);
            var potentials_length = response[i]['potentials'].length;
            var first_row = true;
            var url = response[i]['url'];
            var request_body = response[i]['requestBody'];
            var url_color = stringToColour(response[i]['service']);
            
            if (potentials_length > 0) {
                for (var j=0; j<response[i]['potentials'].length; j++) {
                    var potential = response[i]['potentials'][j]['service'] + "." + response[i]['potentials'][j]['opname'];
                    var potential_color = stringToColour(response[i]['potentials'][j]['service']);
                    var foundinuri = response[i]['potentials'][j]['foundinuri'];

                    document.getElementById('main').innerHTML += `
                    <tr>
                    ${first_row ? `<td rowspan="${potentials_length}" style="background-color: ${url_color};"><b>${url}</b><br />${request_body}</td>` : ''}
                    <td style="background-color: ${potential_color};">${potential}${foundinuri ? "" : " <sup><i>respBody</i></sup>"}</td> 
                    <td><button>Accept</button></td>
                    </tr>`;
                    first_row = false;
                }
            } else {
                if (!only_one_select) {
                    document.getElementById('main').innerHTML += `
                    <tr>
                    <td style="background-color: ${url_color};"><b>${url}</b><br />${request_body}</td>
                    <td><select>${combined_select}</select></td> 
                    <td><button>Accept</button></td>
                    </tr>`;
                    only_one_select = true;
                } else {
                    document.getElementById('main').innerHTML += `
                    <tr>
                    <td style="background-color: ${url_color};"><b>${url}</b><br />${request_body}</td>
                    <td>(no potentials)</td> 
                    <td>&nbsp;</td>
                    </tr>`;
                }
            }
        }
    });
});