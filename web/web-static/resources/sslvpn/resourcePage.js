var oldTime = new Date().getTime();
var newTime = new Date().getTime();
var outTime = 3 * 60 * 1000;
var flag = true;
var cateLiw = 0;
var catew = $('.groupName-container').width() - 150;

// var jsonData = '{"my_resource":[{"name":"OAaaaaaaaaaaaaaaaaaaaaaaabbbbbb","url_rewrite_enable":"on","url":"http:\/\/192.168.137.100:80\/index.htmldfgdg","replaced_url":"https:\/\/192.168.1.1:1194\/sslvpn\/http\/192.168.137.100\/80\/index.html","child_link_enable":"on"}],"default":[{"name":"baidu","url_rewrite_enable":"on","url":"http:\/\/www.baidu.com\/","replaced_url":"https:\/\/192.168.1.1:1194\/sslvpn\/http\/www.baidu.com\/80\/","child_link_enable":"on"},{"name":"sina","url_rewrite_enable":"on","url":"http:\/\/www.sina.com\/","replaced_url":"https:\/\/192.168.1.1:1194\/sslvpn\/http\/www.sina.com\/80\/","child_link_enable":"on"}],"f":[{"name":"233","url_rewrite_enable":"on","url":"http:\/\/192.168.137.100\/","replaced_url":"https:\/\/192.168.1.1:1194\/sslvpn\/http\/192.168.137.100\/80\/","child_link_enable":"off"}]}'
// var resourceGroupTable = JSON.parse(jsonData);

$(function () {
    //鼠标移动事件，更新上次操作时间
    $(document).mousemove(function () {
        oldTime = new Date().getTime();
    })

    //选项卡切换
    $(document).on('click', '.groupName-container ul li', function () {
        indexC = $(this).index();
        $(this).addClass('active').siblings().removeClass('active');
        $('.resourceList-container').eq(indexC).addClass('active').siblings().removeClass('active');
    })

    $('.next').click(function () {
        var marginLeft = $('.groupName-container ul').css("marginLeft");
        var numMarginLeft = Number(marginLeft.substr(0, marginLeft.length-2));
        var newMarginLeft = numMarginLeft - catew;

        if (newMarginLeft > 0 - cateLiw - 60 )
        {
            $('.groupName-container ul').animate({
                "margin-left": (newMarginLeft) + 'px'
            }, 500)
        }
    })

    $('.prev').click(function () {
        var marginLeft = $('.groupName-container ul').css("marginLeft");
        var numMarginLeft = Number(marginLeft.substr(0, marginLeft.length-2));
        var newMarginLeft = numMarginLeft + catew;

        if (newMarginLeft > 0) {
            newMarginLeft = 0;
        }

        $('.groupName-container ul').animate({
            "margin-left": (newMarginLeft) + 'px'
        }, 500)
    })
})

$(document).ready(function () {
    var username = "admin";
    var resourceGroupTable = {};
    var resTable;

    $.ajax({
        url: '/user_info.json',
        type: 'get',
        async: false,
        dataType: 'json',
        cache: false,

        success: function (json_data) {
            var stdjson = JSON.stringify(json_data);
            resTable = JSON.parse(stdjson);
            username = resTable["username"];
            resourceGroupTable = resTable["group"];
            // outTime = resTable["idle_time"];
        }
    });

    $("#top_username").text(username);
    $("#welcome_username").text("你好，" + username);

    generateResourceGroupTabFromJson(resourceGroupTable);
    $('.groupName-container ul li').each(function () {
        cateLiw += $(this).outerWidth();
    })
    window.setInterval(timeOut, 5000);
})

function createResourceGroupTab(groupName, groupId, selected) {
    if (selected) {
        // $(".groupName-container ul").append('<li class="active">' + groupName + "</li>");
        // $(".resourceGroup-tab-inner").append('<div class="resourceList-container active"><ul id="' + groupId + '"></ul></div>');
        $("#group_insert").append('<li class="active">' + groupName + "</li>");
        $("#resource_insert").append('<div class="resourceList-container active"><ul id="' + groupId + '"></ul></div>');
    } else {
        // $(".groupName-container ul").append("<li>" + groupName + "</li>");
        // $(".resourceGroup-tab-inner").append('<div class="resourceList-container"><ul id="' + groupId + '"></ul></div>');
        $("#group_insert").append("<li>" + groupName + "</li>");
        $("#resource_insert").append('<div class="resourceList-container"><ul id="' + groupId + '"></ul></div>');
    }
}

function generateResourceHtml(resourceName, originUrl, rewriteUrl) {
    var res = '<li><a href="' + rewriteUrl + '" target="_blank"><div class="web_resource"><h3 class="resourceName">' + resourceName + '</h3><p class="resourceUrl">' + originUrl + '</p></div></a></li>'
    return res;
}

function addResourceHtmlToList(resourceHtml, groupId) {
    var resourceListId = "#" + groupId;
    $(resourceListId).append(resourceHtml);
}

function addResourceToGroup(resourceName, originUrl, rewriteUrl, groupId) {
    var innerHtml = generateResourceHtml(resourceName, originUrl, rewriteUrl);
    addResourceHtmlToList(innerHtml, groupId);
}

function generateResourceGroupTabFromJson(resourceGroupTable) {
    $("#group_insert").empty();
    $("#resource_insert").empty();

    var groupIndex = 0;
    var groupId = "group" + groupIndex.toString();

    createResourceGroupTab("全部资源", groupId, true);
    var flagTable = {};

    for (var j = 0; j < resourceGroupTable.length; j++) {
        groupIndex++;
        groupId = "group" + groupIndex.toString();

        var tmpGroupName = resourceGroupTable[j].name;
        var tmpResourceArray = resourceGroupTable[j].resource_list;
        createResourceGroupTab(tmpGroupName, groupId, false);

        for (var i = 0; i < tmpResourceArray.length; i++) {
            var resourceName = tmpResourceArray[i]["name"];
            var originUrl = tmpResourceArray[i]["url"];
            var rewriteUrl = tmpResourceArray[i]["replaced_url"];

            addResourceToGroup(resourceName, originUrl, rewriteUrl, groupId);

            if (!flagTable[resourceName]) {
                flagTable[resourceName] = true;
                addResourceToGroup(resourceName, originUrl, rewriteUrl, "group0");
            }
        }
    }
}

function timeOut() {
    newTime = new Date().getTime(); //更新未进行操作的当前时间
    if (newTime - oldTime > outTime) { //判断是否超时不操作
        if(flag)
        {
            flag = false;
            alert("长时间未操作，请重新登录。");
            window.location.href = "login.html";
        }
    }
}