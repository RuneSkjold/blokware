var fooid=0;
function panda(starttop, startleft) {
    fooid++;
    var foo = document.getElementsByTagName("body")[0].appendChild(document.createElement("div"));
    foo.id='foo' + fooid;
    foo.style.position="fixed";
    foo.setAttribute("top", starttop);
    foo.setAttribute("left", startleft);
    foo.setAttribute("dir", (Math.random()*12)-6);
    foo.setAttribute("topdir", 1);
    foo.style.top=foo.getAttribute("top") + "%";
    foo.style.left=foo.getAttribute("left") + "%";
    foo.style.fontSize=Math.floor(70+(Math.random()*100)) + "%";
    foo.style.color="rgb(" + Math.floor(Math.random() * 253) + "," + Math.floor(Math.random() * 253) + "," + Math.floor(Math.random() * 253) + ")";
    switch(Math.floor(Math.random()*10)) {
        case 0:
            foo.innerHTML = "&#x2665;";
            break;
        case 1:
            foo.innerHTML = "&#x266a;";
            break;
        case 2:
            foo.innerHTML = "&#x262d;";
            break;
        case 3:
            foo.innerHTML = "&#x262e;";
            break;
        case 4:
            foo.innerHTML = "&#x262f;";
            break;
        case 5:
            foo.innerHTML = "&#x950;";
            break;
        case 6:
            foo.innerHTML = "&#x263b;";
            break;
        case 7:
            foo.innerHTML = "&#x26a4;";
            break;
        case 8:
            foo.innerHTML = "&#x2625;";
            break;
        case 9:
            foo.innerHTML = "&#x0fd8;";
            break;
    }
    panda2(document.getElementById('foo' + fooid));
    setTimeout("panda(" + starttop + "," + startleft + ")", 70);
}
function panda2(elm) {
    if (Number(elm.getAttribute("top"))==70) elm.setAttribute("dir", Number(elm.getAttribute("dir"))*(randomDir()));
    elm.setAttribute("top",Number(elm.getAttribute("top")-(1*elm.getAttribute("topdir"))));
    elm.setAttribute("left",Number(elm.getAttribute("left")-(Number(elm.getAttribute("dir")/(Number(elm.getAttribute("top")))))));
    if(Number(elm.getAttribute("top"))<2) {
        elm.setAttribute("topdir", "-1");
    }
    elm.style.top=elm.getAttribute("top") + "%";
    elm.style.left=elm.getAttribute("left") + "%";
    if (Number(elm.getAttribute("top"))<105) {
        setTimeout("panda2(document.getElementById('" + elm.id + "'))", (35+Math.floor(Math.random()*15)));
    } else {
        elm.parentNode.removeChild(elm);
    }
}
function randomDir() {
    if (Math.floor(Math.random()*2) == 1) {
        return 1;
    } else {
        return -1;
    }
}

document.body.style.overflow='hidden';
panda(100, 50.3);

