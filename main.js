var only_one_select = false;
var selectables;
var response;
var final_output = '';

function addSelectable() {
    selectables.push({
        'prop': this.getAttribute('data-prop'),
        'val': this.getAttribute('data-val')
    });
    this.innerHTML += " (selected)";
}

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

function convertApiToBoto3(str) {
    var i = 1;
    var character = '';
    var next_char = '';
    var prev_char = '';
    var outputstr = str.substring(0,1).toLowerCase();
    
    while (i <= str.length) {
        character = str.charAt(i);
        next_char = str.charAt(i+1);
        prev_char = str.charAt(i-1);
        if (character == character.toUpperCase() && character != "" && (next_char != next_char.toUpperCase() || prev_char != prev_char.toUpperCase())) {
            outputstr += "_";
        }
        outputstr += character.toLowerCase();
        i++;
    }

    return outputstr;
}

function convertApiToCli(str) {
    var i = 1;
    var character = '';
    var next_char = '';
    var prev_char = '';
    var outputstr = str.substring(0,1).toLowerCase();
    
    while (i <= str.length) {
        character = str.charAt(i);
        next_char = str.charAt(i+1);
        prev_char = str.charAt(i-1);
        if (character == character.toUpperCase() && character != "" && (next_char != next_char.toUpperCase() || prev_char != prev_char.toUpperCase())) {
            outputstr += "-";
        }
        outputstr += character.toLowerCase();
        i++;
    }

    return outputstr;
}

function doAccept() {
    var i = this.getAttribute('data-response-index');
    var j = this.getAttribute('data-potential-index');

    var service = response[i]['service'];
    var method = response[i]['method'];
    var regexval = document.getElementById(`regexinput${i}`).value;
    var apiservice ='';
    var apimethod = '';

    if (!j || j == "") {
        var cs = document.getElementById("combinedSelect");
        var selected_option = cs.options[cs.selectedIndex];
        apimethod = selected_option.getAttribute('data-opname');
        apiservice = selected_option.getAttribute('data-service');

        cs.outerHTML = apimethod + "." + apiservice;
    } else {
        apimethod = response[i]['potentials'][j]['opname'];
        apiservice = response[i]['potentials'][j]['service'];
    }

    var selectables_string = '';
    if (selectables.length > 0) {
        selectables.forEach(selectable => {
            selectables_string += ` && jsonRequestBody.${selectable.prop} == "${selectable.val}"`;
        });
    }

    var boto3method = convertApiToBoto3(apimethod);
    var climethod = convertApiToCli(apimethod);

    document.getElementById('final_output').innerHTML += `
    // ${service}
    if (details.method == "${method}" && details.url.match(/${regexval}/g)${selectables_string}) {
        outputs.push({
            'region': region,
            'service': '${apiservice}',
            'method': {
                'api': '${apimethod}',
                'boto3': '${boto3method}',
                'cli': '${climethod}'
            },
            'options': reqParams
        });
        
        return true;
    }
`;
    document.getElementById('final_output').setAttribute('style', 'width: 100%; height: 0;');
    var scrollHeight = document.getElementById('final_output').scrollHeight;
    document.getElementById('final_output').setAttribute('style', 'width: 100%; height: ' + scrollHeight + 'px;');

    this.outerHTML = "<i>accepted</i>";
    selectables = [];
}

chrome.runtime.sendMessage(null, {
    "action": "getCombined"
}, null, function(combined){
    var combined_select = '<select id="combinedSelect">';
    var combined_select_options = [];
    for (var service in combined) {
        for (var operation in combined[service]['operations']) {
            var operation_name = combined[service]['operations'][operation]['name'];
            combined_select_options.push(`<option data-service="${service}" data-opname="${operation_name}">${service}.${operation_name}</option>`);
        }
    }
    combined_select_options.sort();
    combined_select += combined_select_options.join('');
    combined_select += '</select>';

    chrome.runtime.sendMessage(null, {
        "action": "getRequests"
    }, null, function(xresponse){
        response = xresponse;
        for (var i=0; i<response.length; i++) {
            var potentials_length = response[i]['potentials'].length;
            var first_row = true;
            var url = response[i]['url'];
            var method = response[i]['method'];
            var request_body = response[i]['requestBody'];
            var url_color = stringToColour(response[i]['service']);
            var regex = response[i]['regex'];
            var selectable_json = '';
            selectables = [];

            try {
                jsonRequestBody = JSON.parse(request_body);
                for (var prop in jsonRequestBody) {
                    var val = JSON.stringify(jsonRequestBody[prop]);
                    selectable_json += `<a id="${i}-${prop}" data-prop="${prop}" data-val=${val} href="#">${prop}</a>: ${val}<br />`;
                    setTimeout(function(i, prop){
                        document.getElementById(`${i}-${prop}`).onclick = addSelectable;
                    }, 1, i, prop);
                }
            } catch(e) {;}
            
            if (potentials_length > 0) {
                for (var j=0; j<response[i]['potentials'].length; j++) {
                    var potential = response[i]['potentials'][j]['service'] + "." + response[i]['potentials'][j]['opname'];
                    var potential_color = stringToColour(response[i]['potentials'][j]['service']);
                    var foundinuri = response[i]['potentials'][j]['foundinuri'];

                    document.getElementById('main').innerHTML += `
                    <tr>
                    ${first_row ? `<td rowspan="${(potentials_length+1)}" style="background-color: ${url_color};"><b>${url}</b> <i>${method}</i><br />${selectable_json}/<input id="regexinput${i}" style="width: 90%;" value="${regex}" />/g</td>` : ''}
                    <td style="background-color: ${potential_color};">${potential}${foundinuri ? "" : " <sup><i>respBody</i></sup>"}</td> 
                    <td><button data-response-index="${i}" data-potential-index="${j}" id="acceptPotential-${i}-${j}">Accept</button></td>
                    </tr>`;
                    first_row = false;

                    setTimeout(function(i, j){
                        document.getElementById(`acceptPotential-${i}-${j}`).onclick = doAccept;
                    }, 1, i, j);
                }
            } else {
                document.getElementById('main').innerHTML += `
                <tr>
                <td rowspan="2" style="background-color: ${url_color};"><b>${url}</b> <i>${method}</i><br />${selectable_json}/<input id="regexinput${i}" style="width: 90%;" value="${regex}" />/g</td>
                <td>(no potentials)</td> 
                <td>&nbsp;</td>
                </tr>`;
            }
            document.getElementById('main').innerHTML += `
            <tr>
            <td id="pickArea${i}"><button id="pickButton${i}">Pick</button></td> 
            <td><button data-response-index="${i}" id="pickAcceptButton${i}">Accept</button></td>
            </tr>`;
            setTimeout(function(i, combined_select){
                document.getElementById(`pickButton${i}`).onclick = function() {
                    document.getElementById(`pickArea${i}`).innerHTML = combined_select;
                };
                document.getElementById(`pickAcceptButton${i}`).onclick = doAccept;
            }, 1, i, combined_select);
        }
    });
});