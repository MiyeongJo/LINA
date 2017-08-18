var BASE64 = {

	// private property
	_keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

	// public method for encoding
	encode : function (input) {
		var output = "";
		var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
		var i = 0;

		while (i < input.length) {

		  chr1 = input.charCodeAt(i++);
		  chr2 = input.charCodeAt(i++);
		  chr3 = input.charCodeAt(i++);

		  enc1 = chr1 >> 2;
		  enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
		  enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
		  enc4 = chr3 & 63;

		  if (isNaN(chr2)) {
			  enc3 = enc4 = 64;
		  } else if (isNaN(chr3)) {
			  enc4 = 64;
		  }

		  output = output +
			  this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
			  this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);

		}

		return output;
	},

	// public method for decoding
	decode : function (input)
	{
	    var output = "";
	    var chr1, chr2, chr3;
	    var enc1, enc2, enc3, enc4;
	    var i = 0;

	    input = input.replace(/[^A-Za-z0-9+/=]/g, "");

	    while (i < input.length)
	    {
	        enc1 = this._keyStr.indexOf(input.charAt(i++));
	        enc2 = this._keyStr.indexOf(input.charAt(i++));
	        enc3 = this._keyStr.indexOf(input.charAt(i++));
	        enc4 = this._keyStr.indexOf(input.charAt(i++));

	        chr1 = (enc1 << 2) | (enc2 >> 4);
	        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
	        chr3 = ((enc3 & 3) << 6) | enc4;

	        output = output + String.fromCharCode(chr1);

	        if (enc3 != 64) {
	            output = output + String.fromCharCode(chr2);
	        }
	        if (enc4 != 64) {
	            output = output + String.fromCharCode(chr3);
	        }
	    }

	    return output;
	}
}

function SHA256(s){
	 
	var chrsz   = 8;
	var hexcase = 0;
 
	function safe_add (x, y) {
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
	}
 
	function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
	function R (X, n) { return ( X >>> n ); }
	function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
	function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
	function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
	function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
	function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
	function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }
 
	function core_sha256 (m, l) {
		var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
		var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		var W = new Array(64);
		var a, b, c, d, e, f, g, h, i, j;
		var T1, T2;
 
		m[l >> 5] |= 0x80 << (24 - l % 32);
		m[((l + 64 >> 9) << 4) + 15] = l;
 
		for ( var i = 0; i<m.length; i+=16 ) {
			a = HASH[0];
			b = HASH[1];
			c = HASH[2];
			d = HASH[3];
			e = HASH[4];
			f = HASH[5];
			g = HASH[6];
			h = HASH[7];
 
			for ( var j = 0; j<64; j++) {
				if (j < 16) W[j] = m[j + i];
				else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
 
				T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
				T2 = safe_add(Sigma0256(a), Maj(a, b, c));
 
				h = g;
				g = f;
				f = e;
				e = safe_add(d, T1);
				d = c;
				c = b;
				b = a;
				a = safe_add(T1, T2);
			}
 
			HASH[0] = safe_add(a, HASH[0]);
			HASH[1] = safe_add(b, HASH[1]);
			HASH[2] = safe_add(c, HASH[2]);
			HASH[3] = safe_add(d, HASH[3]);
			HASH[4] = safe_add(e, HASH[4]);
			HASH[5] = safe_add(f, HASH[5]);
			HASH[6] = safe_add(g, HASH[6]);
			HASH[7] = safe_add(h, HASH[7]);
		}
		return HASH;
	}
 
	function str2binb (str) {
		var bin = Array();
		var mask = (1 << chrsz) - 1;
		for(var i = 0; i < str.length * chrsz; i += chrsz) {
			bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
		}
		return bin;
	}
 
	function Utf8Encode(string) {
		string = string.replace(/\r\n/g,"\n");
		var utftext = "";
 
		for (var n = 0; n < string.length; n++) {
 
			var c = string.charCodeAt(n);
 
			if (c < 128) {
				utftext += String.fromCharCode(c);
			}
			else if((c > 127) && (c < 2048)) {
				utftext += String.fromCharCode((c >> 6) | 192);
				utftext += String.fromCharCode((c & 63) | 128);
			}
			else {
				utftext += String.fromCharCode((c >> 12) | 224);
				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
				utftext += String.fromCharCode((c & 63) | 128);
			}
 
		}
 
		return utftext;
	}
 
	function binb2hex (binarray) {
		var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
		var str = "";
		for(var i = 0; i < binarray.length * 4; i++) {
			str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
			hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
		}
		return str;
	}
 
	s = Utf8Encode(s);
	return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
 
}

function setCookie( name, value, expiredays ) {
    var todayDate = new Date();
    todayDate.setDate( todayDate.getDate() + expiredays );
    document.cookie = name + '=' + escape( value ) + '; path=/; expires=' + todayDate.toGMTString() + ';';
}

function setCookieDomain( name, value, expiredays, domain ) {
	var domainName = (domain ? ' domain='+domain : '');
    var todayDate = new Date();
    todayDate.setDate( todayDate.getDate() + expiredays );
    document.cookie = name + '=' + escape( value ) + '; path=/; expires=' + todayDate.toGMTString() + ';' + domainName;
}

function getCookie( name ) {
	if ( document.domain != 'cjone.com' ) setCookieDomain( name, '', -1, '.cjone.com' );
    var nameOfCookie = name + "=";
    var x = 0;
    while ( x <= document.cookie.length ) {
        var y = (x+nameOfCookie.length);
        if ( document.cookie.substring( x, y ) == nameOfCookie ) {
            if ( (endOfCookie=document.cookie.indexOf( ";", y )) == -1 )
                endOfCookie = document.cookie.length;
            return unescape( document.cookie.substring( y, endOfCookie ) );
        }
        x = document.cookie.indexOf( " ", x ) + 1;
        if ( x == 0 ) break;
    }
    return "";
}

function alertMsg2(objId, ErrMsg){
	$("#"+objId).text(ErrMsg);
	$("#"+objId).show();
}

// 간편로그인
function loginSimple() {
	if(loginCheck() == false){
            //cjone.openModal('/cjmweb/login/login-simple.do');
		$(location).attr('href', '/cjmweb/login.do?return_url='+escape($(location).attr('href')));
		return false; 
	}
	return true;
}


function loginCheck(){
	resultLogin = false;
	$.ajax({
		//url : loginURL
		url : '/cjmweb/layer/login/login-check.do'
		, type : 'POST'
		, async : false
		, success : function(data) {
			if(data.code == '001'){
				resultLogin = true;
			}else{
				resultLogin = false;
			}
		}
		, error : function(data) {
			resultLogin = false;
		}
	});
	return resultLogin;
}

function captchaCheck(){
	captchaLogin = false;
	$.ajax({
		url : '/cjmweb/layer/login/captcha-check.do'
		, type : 'POST'
		, async : false
		, success : function(data) {
			console.log(data);
			if(data.code == '001'){
				captchaLogin = true;
			}else{
				captchaLogin = false;
			}
		}
		, error : function(data) {
			captchaLogin = false;
		}
	});
	return captchaLogin;
}

function limitTodayView(bnr_name)
{
	if($("#"+bnr_name).hasClass("on") == true) {
		setCookie(bnr_name, "done" , 1);
	}
}

function enterKey(idName,fucntionName){
	$('#'+idName).keydown(function(e) {
	    if (e.keyCode == 13){
	    	eval(fucntionName+";");
	    }
	});
}

function simpleLoginCallBack(func_nm){
	simpleLoginAction('', '&func_name=' + func_nm);
}

function simpleLoginAction(simple_return_url,url_param){
	if(loginCheck() == false){
		if(captchaCheck() == true){
			curent_url =  (simple_return_url ? simple_return_url+url_param : document.location.href);
			location.href = "/cjmweb/login.do?return_url="+escape(curent_url);
		}else{
			cjone.openModal('/cjmweb/login/login-simple.do?return_url='+escape(simple_return_url+url_param));
		}
	}else if(simple_return_url != undefined && simple_return_url != null && simple_return_url != ""){
		location.href = simple_return_url+url_param;
	}
}

//메뉴 클래스 설정
function menuClassOn(){
	var cp = '';
	if(typeof(contextPath) != 'undefined' && contextPath != undefined) {
		cp = contextPath;
	} else {
		cp = '/cjmweb';
	}
	var origin = location.href;
	origin = origin.replace(/(\?).+/,'');
	var re = new RegExp('^.+'+cp);
	origin = origin.replace(re, '');
	var result = origin.match(/\/[^\s^.\/]+/g);
	origin = result[0];
	if( result.length > 1 ) {
		origin += result[1];
	}
	
	if( origin.indexOf('/shopping') == 0 ) {
		origin = '/shopping/list';
	}
	
	var $gnbli = $('li','#gnb');
	var $gnblia = $('a[href*="'+ origin +'"]', $gnbli);
	$gnbli.removeClass('on');

	if(origin == '/point-card/brand') {
		$($gnblia.get(0)).parent('li').addClass('on');
		$($gnblia.get(0)).parent('li').parent('ul.gnb_2depth').parent('li.depth1').addClass('on');
	} else {
		$gnblia.parent('li').addClass('on');
		$gnblia.parent('li').parent('ul.gnb_2depth').parent('li.depth1').addClass('on');
	}

}

// 윈도우 팝업 객체
var win = null;
function openAddressWindow(gubun) {
	//window.open('/cjmweb/vip/address.do?gubun=' + gubun, "", "width=720, height=520,  scrollbars=no");
	windPopupCenter('/cjmweb/layer-ssl/vip/address.do?gubun=' + gubun, '', '700', '700', 'yes');
}

function windPopupCenter(url, winName, pwidth, pheight, scrollYN, resizeYN){
	var winL = (screen.width - pwidth)/2;
	var winT = (screen.height - pheight)/2;
	var spec = 'toolbar=no,';//도구메뉴
	spec += 'status=no,';//상태바
	spec += 'location=yes,'; // 주소관련메뉴
	spec += 'height='+pheight+','; // 높이
	spec += 'width='+pwidth+','; // 너비
	spec += 'top='+winT+','; // 세로위치
	spec += 'left='+winL+','; // 가로위치
	spec += 'scrollbars='+(scrollYN == undefined ? "no":scrollYN)+',';//스크롤바 여부(기본)
	spec += 'resizable='+(resizeYN == undefined ? "no":resizeYN)+','//창크기조정 여부
	
	if(win == null) {
		win = window.open(url, winName, spec);
    } else {
        if (win.closed == false) {        	
    		win.focus();
        } else {
        	win = window.open(url, winName, spec);
        }
    }
}

function closeWinPopup() {
	if(win != null) win.close();
}

$(function () {
	menuClassOn();
});

window.onbeforeunload = function(){
	setCookie("previousUrl", window.location.pathname , 1);
}

// 중복 호출 방지 변수 (common에서 사용하다 보니 사용하지 않을만한 변수로 길게 만듬)
var commBlockDupliCallValue = true;
// 중복 호출 방지 (8초간)
function commBlockDupliCall(callbackFunc){
	
	
	// 중복 호출 방지
	if(commBlockDupliCallValue){
		commBlockDupliCallValue = false;
		
		// 1초후 중복 호출 방지 해제
		setTimeout(function(){
			commBlockDupliCallValue = true;
		}, 8000);
		
		callbackFunc();
	}
	
}

// 서비스 로그에 구분값을 위한 화면 카테고리 저장
function commSetCertificationserviceLogCate(cate, type){
	$.ajax({
		url : '/cjmweb/common/setSertificationServiceLogCate.do'
		,dataType:'json'
		,async: true
		,type: 'POST'
		, data : {
			cate : cate
			, type : type
		},
		success:function(data)
		{
		}
	});  
}
