/*
datetime-local input fallback code copyright 2016 Jonas Helguson

This work is free. You can redistribute it and/or modify it under
the following license terms:

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
*/

function datetimepickerfoo(elm, idx, lst) {
    if (elm.type != 'text') return;
    if (elm.value != '') elm.value = elm.value.substr(0, 16).replace('T', ' ');
    elm.setAttribute('maxlength', '16');
    elm.title = "YYYY-MM-DD HH:MM (for example 2018-09-26 16:20)";
    elm.setAttribute('pattern', '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9][ |T][0-2][0-9]:[0-6][0-9](:[0-6][0-9])?');
    elm.setAttribute('onfocus', 'this.getAttribute("data-datetimepickerstate") == "open" ? datetimepickerclose(this) : datetimepickershow(this)');
    elm.setAttribute('ondblclick', 'datetimepickershow(this)');
    elm.setAttribute('onblur', 'datetimepickerclose(this)');
}

function datetimepickershow(elm) {
    if (elm.getAttribute('data-datetimepickerstate') == 'open') return;

    box = elm.parentNode.appendChild(document.createElement('div'));
    box.setAttribute('onclick', 'return false;');
    box.innerHTML = '<div style="float:left;padding-bottom:1.5em;padding-left:2px;padding-right:0.5em;"><select style="border:none;border-left:1px solid #bbb;font-size:smaller;" onchange="datetimepickersetmonth(this.nextSibling.nextSibling.value, this.value, this.parentNode.nextSibling)" size=12><option>01<option>02<option>03<option>04<option>05<option>06<option>07<option>08<option>09<option>10<option>11<option>12</select><br><select style="position:absolute;font-size:smaller;" onchange="datetimepickersetmonth(this.value, this.previousSibling.previousSibling.value, this.parentNode.nextSibling)"><option>2016<option>2017<option>2018<option>2019</select></div><div></div><br style="clear:both">';
    if (elm.value.substr(10) == '') {
        startdate = new Date();
    } else {
        startdate = new Date(elm.value);
        if (isNaN(startdate.getFullYear())) startdate = new Date();
    }
    box.firstChild.firstChild.value = (startdate.getMonth() > 8 ? (startdate.getMonth() + 1) : '0' + (startdate.getMonth() + 1));
    box.firstChild.firstChild.nextSibling.nextSibling.value = startdate.getFullYear();
    datetimepickersetmonth(startdate.getFullYear(), box.firstChild.firstChild.value, box.firstChild.nextSibling)
    box.firstChild.firstChild.focus();

    elm.setAttribute('data-datetimepickerstate', 'open');
}

function datetimepickersetmonth(year, month, target) {
    limit = 32;
    switch (month) {
      case '02':
        limit--;
        limit--;
        //fuck leap years (hoping firefox and safari support datetime-local before february 2020)
      case '04':
      case '06':
      case '09':
      case '11':
        limit--;
    }
    day = 1;
    pos = new Date(year + '-' + month + '-01').getDay() - 1;
    if (pos == -1) pos = 6;
    r = '';
    for (i=0;i<pos;i++) {
      r += '<td></td>';
    }
    currentdate = new Date().toISOString().substr(0,10)
    while (day < limit) {
      fullday = day;
      if (day < 10) fullday = '0' + day;
      style = '';
      if (year+'-'+month+'-'+fullday == currentdate) {
        style = 'background-color: white; color: black;'
      }
      r += '<td style="cursor: pointer;' + style + '" onclick="datetimepickerputdate(this.parentNode.parentNode.parentNode.parentNode.parentNode.previousSibling, \'' + year+'-'+month+'-'+fullday + '\')">' + day + '</td>';
      day++;
      pos++;
      if (pos == 7) {
        r += '</tr><tr>';
        pos = 0;
      }
    }

    target.innerHTML = '<table cellspacing=7 style="text-align:right; color:#444;font-family:monospace;font-size:125%;"><tbody><tr style="color:#777"><td>M</td><td>T</td><td>W</td><td>T</td><td>F</td><td>S</td><td>S</td></tr><tr>' + r + '</tr></tbody></table>';
}

function datetimepickerputdate(elm, date) {
    time = elm.value.substr(10);
    if (time == '') time = ' 12:00';
    elm.value = date + time;
    elm.focus();
    elm.setSelectionRange(11,16)
    if (elm.onchange) elm.onchange();
    datetimepickerclose(elm);
}

function datetimepickerclose(elm) {
    if (elm.getAttribute('data-datetimepickerstate') != 'open') return;

    elm.parentNode.removeChild(elm.nextSibling);
    elm.setAttribute('data-datetimepickerstate', 'closed');
}

setTimeout("Array.prototype.forEach.call(document.querySelectorAll('input[type=datetime-local]'), datetimepickerfoo);", 1)

