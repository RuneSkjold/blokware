'use strict';

if (window.tinymce) tinymce.init({selector: "textarea.formatting", entity_encoding : "raw", forced_root_block: false, valid_elements: "-br,-em,-strong,-span[!style],-sub,-sup", menubar: false, toolbar: "bold italic underline subscript superscript | undo redo | removeformat", statusbar: false, content_style: "body {font: inherit ! important;}"});

setTimeout('document.body.className="loaded"', 1); //used for css transitions
setTimeout('if(document.getElementById("usernav")){if(!fetch_news.position_info)fetch_news.position_info="";fetch_news(2048);}', 4000);

function fetch_news(time) {
    var r = new XMLHttpRequest();
    r.addEventListener("load", function(){parse_news(this.responseText, time)});
    r.open("GET", "/_news/" + (fetch_news.position_info));
    r.send();
}

function parse_news(response, time) {
    var bits = response.trim().split('\n');
    if (bits[0] != 'n~') {
        document.querySelector('nav').appendChild(document.createElement('details')).innerHTML = "<summary>*** An error occured and this page is no longer receiving updates from the server automatically. Reload if you wish. ***</summary><pre></pre>";
        document.querySelector('nav > details > pre').innerText = response;
        return;
    }
    
    set_msg_count(bits[1]);
    
    if (bits[2] != '~n') {
        fetch_news.position_info = bits[3];

        var newelement = document.createElement('div');
        newelement.innerHTML = bits[2];
        newelement.className = 'dynamic_highlight';
        var color_pos = bits[2].indexOf('color: #');
        if (color_pos) newelement.style.outlineColor = bits[2].slice(color_pos+7, color_pos+14);

        document.body.insertBefore(newelement, document.getElementById('news_insert_marker'));
        setTimeout('document.querySelector(".dynamic_highlight").className="dynamic_highlight_toggled";', 15);
        if (time=='android_special') return; //android app needs ability to call fetch_news in response to out-of-band notifications without starting a timer avalanche.
        time = 2048; //when data received, set the time between polls to low again
    }

    setTimeout("fetch_news(" + (time*2) + ")", time);
}

function set_msg_count(count) {
    var newmsgselm = document.getElementById("newmsgs");

    if (count == '0') {
        newmsgselm.innerHTML = '';
        if (newmsgselm.dataset.flash_interval) {
            clearInterval(newmsgselm.dataset.flash_interval);
            document.title = flash_new_msgs.origtitle;
            document.querySelector('link[rel=icon]').href = flash_new_msgs.origicon;
        }
    } else {
        if (count == '1') {
            newmsgselm.innerHTML = '✉ ';
        } else {
            newmsgselm.innerHTML = '✉' + count + ' ';
        }
        flash_new_msgs.count = count;
        flash_new_msgs.countimg = draw(count);
        if (!newmsgselm.dataset.flash_interval) {
            newmsgselm.dataset.flash_interval = setInterval('flash_new_msgs();', '1400');
            flash_new_msgs();
        }
    }
}

function flash_new_msgs() {
    var icon = document.querySelector('link[rel=icon]');

    if (!flash_new_msgs.origtitle) {
        flash_new_msgs.origtitle = document.title;
        flash_new_msgs.origicon = icon.href;
        flash_new_msgs.envelopeimg = draw('✉');
        flash_new_msgs.phase = 1;
    }

    switch (flash_new_msgs.phase) {
        case 1:
            icon.href = flash_new_msgs.envelopeimg;
            document.title = flash_new_msgs.count + '\xa0\u200a\xa0\xa0' + flash_new_msgs.origtitle;
            break;
        case 2:
            icon.href = flash_new_msgs.countimg;
            document.title = '✉\xa0\xa0\xa0' + flash_new_msgs.origtitle;
            flash_new_msgs.phase = 0;
    }
    flash_new_msgs.phase++;
}

function draw(string) {
    var dims = 32;
    
    var canvas = document.createElement('canvas');
    canvas.width = dims;
    canvas.height = dims;
    var context = canvas.getContext('2d')

    context.font = '27px arial sans-serif';
    context.textAlign = 'center';
    context.fillText(string, dims/2, 25, dims);

    return canvas.toDataURL()
}

function indicate(elm) {
    if(typeof elm.dataset.foocount == "undefined"){elm.dataset.foocount=0;elm.dataset.toggle='color'};elm.dataset.foocount++;var ri=function(){return Math.floor(Math.random()*254);}; if(elm.dataset.foocount>12) elm.dataset.toggle = (elm.dataset.toggle == "color" ? "backgroundColor" : "color"); (elm.dataset.foocount<26 ? elm : document.body).style[elm.dataset.toggle]="rgb(" + ri() + "," + ri() + "," + ri() + ")"; if (elm.dataset.foocount==42) document.getElementsByTagName("head")[0].appendChild(document.createElement("script")).src="/blokware/bonuslevel.js";
}

