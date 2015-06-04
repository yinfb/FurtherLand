//
//   Copyright 2015 Futur Solo
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

window.loading = false;

function datetimeToUnix(datetime){
    var tmp_datetime = datetime.replace(/:/g,"-");
    tmp_datetime = tmp_datetime.replace(/ /g,"-");
    var arr = tmp_datetime.split("-");
    var now = new Date(Date.UTC(arr[0], arr[1]-1, arr[2], arr[3]-8, arr[4], arr[5]));
    return parseInt(now.getTime()/1000);
}

function unixToDatetime(unix){
    Date.prototype.format = function(format) {
       var date = {
              "M+": this.getMonth() + 1,
              "d+": this.getDate(),
              "h+": this.getHours(),
              "m+": this.getMinutes(),
              "s+": this.getSeconds(),
              "q+": Math.floor((this.getMonth() + 3) / 3),
              "S+": this.getMilliseconds()
       };
       if (/(y+)/i.test(format)) {
              format = format.replace(RegExp.$1, (this.getFullYear() + "").substr(4 - RegExp.$1.length));
       }
       for (var k in date) {
              if (new RegExp("(" + k + ")").test(format)) {
                     format = format.replace(RegExp.$1, RegExp.$1.length == 1 ? date[k] : ("00" + date[k]).substr(("" + date[k]).length));
              }
       }
       return format;
   };
    var now = new Date(parseInt(unix) * 1000);
    return now.format("yyyy-MM-dd hh:mm:ss");
}

function collectionHas(a, b) {
    for(var i = 0, len = a.length; i < len; i ++) {
        if(a[i] == b) return true;
    }
    return false;
}
function findParentBySelector(elm, selector) {
    var all = document.querySelectorAll(selector);
    var cur = elm.parentNode;
    while(cur && !collectionHas(all, cur)) {
        cur = cur.parentNode;
    }
    return cur;
}

document.querySelector("#menu-button").addEventListener("click", function (e) {
    document.querySelector("aside").classList.toggle("visible");
});
document.querySelector("#reload").addEventListener("click", function (e) {
    if (!window.loading){
        loadLayout(function (callback) {
            setTimeout(callback, 1500);
        });
    }
});


Array.prototype.forEach.call(document.querySelectorAll(".aside-item"), function (element) {
    element.addEventListener("click", function (e) {
        document.querySelector("aside").classList.remove("visible");
    });
});

function loadLayout(callback) {
    window.loading = true;
    document.querySelector(".load-layout").style.height = "100%";
    document.querySelector(".load-layout").style.width = "100%";
    document.querySelector(".load-layout").classList.add("visible");
    function hideLoadLayout() {
        document.querySelector(".load-layout").classList.remove("visible");
        setTimeout(function () {
        document.querySelector(".load-layout").style.height = "0";
        document.querySelector(".load-layout").style.width = "0";
            window.loading = false;
        }, 300);
    }
    setTimeout(callback, 300, hideLoadLayout);
}

function toggle(event) {
    var spinners = event.target.parentElement.querySelectorAll('paper-spinner');
    Array.prototype.forEach.call(spinners, function (spinner) {
        spinner.active = !spinner.active;
    });
}

document.querySelector("#switch-to-lobby").addEventListener("click", function () {
    loadLayout(function (callback) {
        document.querySelector(".main-part.current").classList.remove("current");
        document.querySelector(".main-part.lobby").classList.add("current");
        callback();
    });
});
document.querySelector("#switch-to-working").addEventListener("click", function () {
    loadLayout(function (callback) {
        document.querySelector(".main-part.current").classList.remove("current");
        document.querySelector(".main-part.working").classList.add("current");
        callback();
    });
});
function previewText(event) {
    document.querySelector("#working-preview-area").innerHTML = marked(document.querySelector("#editor-textarea").value);
    syncHeight();
}

function syncHeight() {
    editor = document.querySelector("#editor-textarea");
    preview = document.querySelector("#working-preview-area");
    percentage = editor.scrollTop / (editor.scrollHeight - editor.offsetHeight);
    preview.scrollTop = (preview.scrollHeight - preview.offsetHeight) * percentage;
}

document.querySelector("#editor-textarea").addEventListener("change", previewText);
document.querySelector("#editor-textarea").addEventListener("keypress", previewText);
document.querySelector("#editor-textarea").addEventListener("keydown", previewText);
document.querySelector("#editor-textarea").addEventListener("keyup", previewText);
document.querySelector("#editor-textarea").addEventListener("blur", previewText);
document.querySelector("#editor-textarea").addEventListener("scroll", syncHeight);

document.querySelector("#show-working-info-buttton").addEventListener("click", function () {
    document.querySelector(".working .working-info").classList.add("visible");
});
document.querySelector("#working-info-close-button").addEventListener("click", function () {
    document.querySelector(".working .working-info").classList.remove("visible");
});

function previewSlug() {
    if (!document.querySelector("#working-info-slug-input paper-input-container").invalid && document.querySelector("#working-info-slug-input").value !== "") {
        document.querySelector("#working-info-slug-preview").innerHTML = window.location.host;
        document.querySelector("#working-info-slug-preview").innerHTML += "/writings/";
        document.querySelector("#working-info-slug-preview").innerHTML += document.querySelector("#working-info-slug-input").value;
        document.querySelector("#working-info-slug-preview").innerHTML += ".htm";
        return;
    }
     document.querySelector("#working-info-slug-preview").innerHTML = "";
}

document.querySelector("#working-info-slug-input").addEventListener("change", previewSlug);
document.querySelector("#working-info-slug-input").addEventListener("keypress", previewSlug);
document.querySelector("#working-info-slug-input").addEventListener("keydown", previewSlug);
document.querySelector("#working-info-slug-input").addEventListener("keyup", previewSlug);
document.querySelector("#working-info-slug-input").addEventListener("blur", previewSlug);

function loadTime() {
    if (document.querySelector("#working-time-is-when-published").checked){
        document.querySelector("#working-time-input").disabled = true;
        document.querySelector("#working-time-input").value = unixToDatetime(Math.round((new Date()).getTime() / 1000));
    }else{
        document.querySelector("#working-time-input").disabled = false;
    }
    setTimeout(loadTime, 1000);
}

window.addEventListener("load", function () {
    var arr = document.querySelector("#working-time-input").value.split(" ");
    var dateReg = /^(?:(?!0000)[0-9]{4}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1[0-9]|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[0-9]{2}(?:0[48]|[2468][048]|[13579][26])|(?:0[48]|[2468][048]|[13579][26])00)-02-29)$/;
    var timeReg = /^2[0-3]|[0-1]?\d:[0-5][0-9]:[0-5][0-9]$/;
    try{
        if (!(dateReg.test(arr[0]) && timeReg.test((arr[1] + "")))){
            document.querySelector("#working-time-input").value = unixToDatetime(Math.round(document.querySelector("#working-time-input").value)).replace(/\//g,"-");
        }
    }catch (e){
        try{
            document.querySelector("#working-time-input").value = unixToDatetime(Math.round(document.querySelector("#working-time-input").value)).replace(/\//g,"-");
        }catch (e2){
            document.querySelector("#working-time-input").value = unixToDatetime(Math.round((new Date()).getTime() / 1000));
        }
    }
    setTimeout(loadTime, 1);
});

document.querySelector("#working-time-input input").addEventListener("blur", function () {
    after = unixToDatetime(datetimeToUnix(document.querySelector("#working-time-input").value));
    if (after != document.querySelector("#working-time-input").value) {
        document.querySelector("#working-time-input").value = unixToDatetime(Math.round((new Date()).getTime() / 1000)).replace(/\//g,"-");
    }
});
window.addEventListener("load", function () {
    Array.prototype.forEach.call(document.querySelectorAll("paper-radio-button"), function (element) {
        element.addEventListener("click", function (e) {
        var element = e.srcElement || e.target;
        if (findParentBySelector(element, "paper-radio-button") !== null) {
            element = findParentBySelector(element, "paper-radio-button");
        }
        element.checked = true;
        });
    });
});
