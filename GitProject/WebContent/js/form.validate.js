var showMsg='';

//space 가 있으면 true, 없으면 false
function checkSpace( str )
{
     if(str.search(/\s/) != -1){
     	return true;
     } else {
        return false;
     }
}

function chkForm(f)
{ 
       var i,currEl;
		//
       for(i = 0; i < f.elements.length; i++){ 
              currEl = f.elements[i]; 

              //필수 항목을 체크한다.  
              if (currEl.getAttribute("required") != null)
              { 
                     if(currEl.type.toUpperCase() == "TEXT" || currEl.tagName.toUpperCase() == "SELECT" || currEl.tagName.toUpperCase() == "TEXTAREA" ||currEl.type.toUpperCase() == "PASSWORD")
                     { 
                            if(!chkText(currEl,currEl.msg)) return false; 

                     } else if(currEl.type.toUpperCase() == "CHECKBOX"){ 
                            if(!chkCheckbox(f, currEl,currEl.msg)) return false; 

                     } else if(currEl.type.toUpperCase() == "RADIO"){ 
                            if(!chkRadio(f, currEl,currEl.msg)) return false; 

                     }
              }
              // 입력 페턴을 체크한다.
              if(currEl.getAttribute("validator") != null && currEl.value.length > 0){ 
                     if(!chkPatten(currEl,currEl.validator,currEl.msg)) return false; 
              } 
              // 길이제한을 체크한다.
              if(currEl.getAttribute("lengthchk") != null && currEl.value.length > 0){ 
                     if(!chkLength(currEl,currEl.lengthchk,currEl.msg)) return false; 
              } 
       }
	   return true;
} 


function chkPatten(field,patten,name)
{ 
       var regNum =/^[0-9]+$/; 
       var regPhone =/^[0-9]{2,3}-[0-9]{3,4}-[0-9]{4}$/; 
       var regMail =/^[_a-zA-Z0-9-]+@[._a-zA-Z0-9-]+.[a-zA-Z]+$/; 
       var regDomain =/^[.a-zA-Z0-9-]+.[a-zA-Z]+$/; 
       var regAlpha =/^[a-zA-Z]+$/; 
       var regHost =/^[a-zA-Z-]+$/; 
       var regHangul =/[가-�]/; 
       var regHangulEng =/[가-�a-zA-Z]/; 
       var regHangulNum = /[가-�0-9]/; 
	   var regEngNum	= /[a-zA-Z0-9]/;
       var regHangulOnly =/^[가-�]*$/; 
       var regId = /^[a-zA-Z]{1}[a-zA-Z0-9_-]{6,12}$/; 
       var regDate =/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/; 
	   var regIp = /([1]\d\d|[2]([0-4][0-9]|5[0-5])|[1-9][0-9]|[0-9]){1}(\.([1]\d\d|[2]([0-4][0-9]|5[0-5])|[1-9][0-9]|[0-9])){3}/gi;
       var regMac = /^[0-9a-fA-F]{2}$/;
	   //setMessage(patten);
	   
		switch (patten) {
			case "regNum":				showMsg     = "숫자만 입력하십시오.";					
				break
			case "regPhone":			showMsg     = "전화번호가 유효하지 않습니다.";					
				break
			case "regMail":				showMsg     = "이메일 주소가 유효하지 않습니다.";					
				break
			case "regDomain":			showMsg     = "도메인이 유효하지 않습니다.";					
				break
			case "regAlpha":			showMsg     = "영문자만 입력하십시오.";					
				break
			case "regHost":				showMsg     = "host명이 유효하지 않습니다.";					
				break
			case "regHangul":			showMsg     = "한글만 입력하십시오";					
				break	
			case "regHangulEng":		showMsg     = "영문자 또는 한글만 입력하십시오.";				
				break
			case "regHangulNum":		showMsg     = "한글 또는 숫자만 입력하십시오.";				
				break
			case "regEngNum":		showMsg			= "영문자 또는 숫자만 입력하십시오.";				
				break
			case "regHangulOnly":		showMsg     = "한글만 입력하십시오";					
				break
			case "regId":				showMsg     = "아이디가 형식에 맞지 않습니다.";				
				break
			case "regDate":				showMsg     = "등록일이 형식에 맞지 않습니다.";					
				break
			case "regIp":				showMsg     = "아이피가 형식에 맞지 않습니다.";					
				break
			case "regMac":				showMsg     = "MAC ADDRESS가 형식에 맞지 않습니다.(숫자 0~9, 영문자 a~f)";	
				break		
		}


	   patten = eval(patten); 

	   
       if(patten == regIp) {
		    
			if(field.value.match(regIp) != field.value) {
				alert(showMsg); 
				field.focus(); 
				return false;
			}
			if(field.value.length >= 2) {
				if('12' != field.value.substring(0,2)) {
					alert('IP는 12. 으로 시작해야 합니다.');
					field.focus(); 
					return false;
				}
			}
	   }
	   else if(!patten.test(field.value)){ 
              alert(showMsg); 
              field.focus(); 
              return false; 
       }
	   
       return true; 
}

// 패턴만 체크 
function testPatten(str, patten)
{ 
       var regNum =/^[0-9]+$/; 
       var regPhone =/^[0-9]{2,3}-[0-9]{3,4}-[0-9]{4}$/; 
       var regMail =/^[_a-zA-Z0-9-]+@[._a-zA-Z0-9-]+.[a-zA-Z]+$/; 
       var regDomain =/^[.a-zA-Z0-9-]+.[a-zA-Z]+$/; 
       var regAlpha =/^[a-zA-Z]+$/; 
       var regHost =/^[a-zA-Z-]+$/; 
       var regHangul =/[가-�]/; 
       var regHangulEng =/[가-�a-zA-Z]/; 
       var regHangulNum = /[가-�0-9]/; 
	   var regEngNum	= /[a-zA-Z0-9]/;
       var regHangulOnly =/^[가-�]*$/; 
       var regId = /^[a-zA-Z]{1}[a-zA-Z0-9_-]{6,12}$/; 
       var regDate =/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/; 
	   var regIp = /([1]\d\d|[2]([0-4][0-9]|5[0-5])|[1-9][0-9]|[0-9]){1}(\.([1]\d\d|[2]([0-4][0-9]|5[0-5])|[1-9][0-9]|[0-9])){3}/gi;
       var regMac = /^[0-9a-fA-F]{2}$/;
	   //setMessage(patten);
	   
		switch (patten) {
			case "regNum":				showMsg     = "숫자만 입력하십시오.";					
				break
			case "regPhone":			showMsg     = "전화번호가 유효하지 않습니다.";					
				break
			case "regMail":				showMsg     = "이메일 주소가 유효하지 않습니다.";					
				break
			case "regDomain":			showMsg     = "도메인이 유효하지 않습니다.";					
				break
			case "regAlpha":			showMsg     = "영문자만 입력하십시오.";					
				break
			case "regHost":				showMsg     = "host명이 유효하지 않습니다.";					
				break
			case "regHangul":			showMsg     = "한글만 입력하십시오";					
				break	
			case "regHangulEng":		showMsg     = "영문자 또는 한글만 입력하십시오.";				
				break
			case "regHangulNum":		showMsg     = "한글 또는 숫자만 입력하십시오.";				
				break
			case "regEngNum":		showMsg			= "영문자 또는 숫자만 입력하십시오.";				
				break
			case "regHangulOnly":		showMsg     = "한글만 입력하십시오";					
				break
			case "regId":				showMsg     = "아이디가 형식에 맞지 않습니다.";				
				break
			case "regDate":				showMsg     = "등록일이 형식에 맞지 않습니다.";					
				break
			case "regIp":				showMsg     = "아이피가 형식에 맞지 않습니다.";					
				break
			case "regMac":				showMsg     = "MAC ADDRESS가 형식에 맞지 않습니다.(숫자 0~9, 영문자 a~f)";	
				break		
		}


	   patten = eval(patten); 

	   
       if(patten == regIp) {
		    
			if(str.match(regIp) != str) {
				alert(showMsg); 
				field.focus(); 
				return false;
			}
			if(fstr >= 2) {
				if('12' != str.substring(0,2)) {
					alert('IP는 12. 으로 시작해야 합니다.');
					return false;
				}
			}
	   }
	   else if(!patten.test(str)){ 
              alert(showMsg); 
              field.focus(); 
              return false; 
       }
	   
       return true; 
}

//-- 문자열 길이 검사
function getLength(str) {
       return (str.length + (escape(str) + "/%u").match(/%u/g).length-1);
}
function chkLength(field,length,name)
{
       if(getLength(field.value) > length){        			
              alert(name + "  영문,숫자 "+length+"자 , 한글 "+(length/2)+"자 이하 입력제한 입니다."); 
              //field.focus(); 
              return false; 
       } 
       return true; 
}

function chkText(field, name)
{ 
		
       if(field.value.length < 1){ 
              alert(name + '입력하세요'); 
              field.focus(); 
              return false; 
       } 
       return true; 
}

function chkCheckbox(form, field, name)
{
       fieldname = eval(form.name+'.'+field.name);
       if (!fieldname.checked){
              alert(name); 
              field.focus(); 
              return false; 
       }
       return true; 
}

function chkRadio(form, field, name)
{
       fieldname = eval(form.name+'.'+field.name);
       for (i=0;i<fieldname.length;i++) {
              if (fieldname[i].checked)
                     return true; 
       }
       alert(name); 
       field.focus(); 
       return false; 
} 

function setMessage(vType) {
	
	switch (vType) {
		case "regNum":				showMsg     = "숫자만 입력하십시오.";					
			break
		case "regPhone":			showMsg     = "전화번호가 유효하지 않습니다.";					
			break
		case "regMail":				showMsg     = "이메일 주소가 유효하지 않습니다.";					
			break
		case "regDomain":			showMsg     = "도메인이 유효하지 않습니다.";					
			break
		case "regAlpha":			showMsg     = "영문자만 입력하십시오.";					
			break
		case "regHost":				showMsg     = "host명이 유효하지 않습니다.";					
			break
		case "regHangul":			showMsg     = "한글만 입력하십시오";					
			break	
		case "regHangulEng":		showMsg     = "영문자 또는 한글만 입력하십시오.";				
			break
		case "regHangulOnly":		showMsg     = "한글만 입력하십시오";					
			break
		case "regId":				showMsg     = "아이디가 형식에 맞지 않습니다.";				
			break
		case "regDate":				showMsg     = "등록일이 형식에 맞지 않습니다.";					
			break
		case "regMac":				showMsg     = "아이피가 형식에 맞지 않습니다.";					
			break	
	}
}


function EmailCheck (emailStr) {
	var knownDomsPat=/^(com|net|org|edu|int|mil|gov|arpa|biz|aero|name|coop|info|pro|museum)$/;
	var emailPat=/^(.+)@(.+)$/;
	var specialChars="\\(\\)><@,;:\\\\\\\"\\.\\[\\]";
	var validChars="\[^\\s" + specialChars + "\]";
	var quotedUser="(\"[^\"]*\")";
	var ipDomainPat=/^\[(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\]$/;
	var atom=validChars + '+';
	var word="(" + atom + "|" + quotedUser + ")";
	var userPat=new RegExp("^" + word + "(\\." + word + ")*$");
	var domainPat=new RegExp("^" + atom + "(\\." + atom +")*$");
	var matchArray=emailStr.match(emailPat);

	if (matchArray == null) {
		alert("Email 주소의 형식이 명확하지 않습니다.");
		return false;
	}

	var user   = matchArray[1];
	var domain = matchArray[2];

	if (user.length < 2) {
		alert("이용자 ID는 최소 2문자 이상입니다.");
		return false;
	}

	if (domain.length < 4) {
		alert("Domain 이름은 최소 4문자 이상입니다.");
		return false;
	}

	for (i=0; i<user.length; i++) {

		if (user.charCodeAt(i) > 127) {
			alert("이용자 ID에 유효하지 않은 문자가 있습니다.");
			return false;
	   }
	}

	for (i=0; i<domain.length; i++) {
		if (domain.charCodeAt(i) > 127) {
			alert("Domain 이름에 유효하지 않은 문자가 있습니다.");
			return false;
	   }
	}

	if (user.match(userPat) == null) {
		alert("Email 주소의 형식이 명확하지 않습니다.");
		return false;
	}

	var IPArray = domain.match(ipDomainPat);

	if (IPArray != null) {

		for (var i=1;i<=4;i++) {
			if (IPArray[i] > 255) {
				alert("Domain의 IP가 명확하지 않습니다.");
				return false;
	   		}
		}
		return true;
	}

	var atomPat = new RegExp("^" + atom + "$");
	var domArr  = domain.split(".");
	var len     = domArr.length;

	for (i=0;i<len;i++) {
		if (domArr[i].search(atomPat) == -1) {
			alert("Domain 이름이 정확하지 않습니다.");
			return false;
	   }
	}

	if (domArr[domArr.length-1].length != 2 &&
		domArr[domArr.length-1].search(knownDomsPat) == -1) {
		alert("Email 주소는 알려진 Domain 이름이나, 2문자 이상의 국가Domain(kr,jp,cn..) 이름으로 끝나야 합니다.");
		return false;
	}

	if (len < 2) {
		alert("Domain 형식이 명확하지 않습니다.");
		return false;
	}

	return true;
}

/**
 * form element의 Array 가져옴
 * @param nm
 * @return
 */
function getElementArrayByName(form_index, nm){
	var obj = document.forms[form_index][nm];
	return (obj==null) ? new Array() : (obj.length!=null) ? obj : new Array(obj);
}

function enableObject(nm, able){
	getElementByName(nm).disabled = !able;
}
function getElementByName(form_index, nm){
	return document.forms[form_index][nm];
}
function getObjectById(id){
	return document.getElementById(id);
}
function getRadioValue(nm){
	var i, es = getElementArrayByName(nm);
	for(i=0;i<es.length;i++){
		if(es[i].checked) return es[i].value;
	}
	return '';
}
function setRadioValue(nm, va){
	var i, es = getElementArrayByName(nm);
	for(i=0;i<es.length;i++){
		if(es[i].value==va){
			es[i].checked = true;
			break;
		}
	}
}

// Dealing with : Event
function checkOnlyNoEnter(withPoint){
	if(event.keyCode==13){
		return true;
	} else if(event.keyCode==45) {// 음수 -
		return false;
	} else if(event.keyCode<48||event.keyCode>57){
		if(withPoint==true && event.keyCode==46) event.returnValue=true;
		else event.returnValue=false;
	}
	return false;
}

// 아이디 유효성 체크 
function isValid_id(str){ 
    var patten = new Array();
    var msg = new Array();
    var p;
    var ret_msg = new Array();
    
    //patten["not_eng_num"] =/[a-zA-Z0-9_-]$/;  //a-z와 0-9 _ - 이외의 문자가 있는지 확인
    //msg["not_eng_num"] = "영문, 숫자 ,특수기호(_)만 사용가능합니다.";
    //patten["not_eng_num"] =/^[a-zA-Z0-9]+$/g;  //a-z와 0-9 _ - 이외의 문자가 있는지 확인    
    //msg["not_eng_num"] = "영문 대/소문자/숫자만 사용가능합니다.";
    patten["not_eng_num"] =/^[a-z0-9]+$/g;  //a-z와 0-9 이외의 문자가 있는지 확인    
    msg["not_eng_num"] = "영문 소문자/숫자만 사용가능합니다.";
    //patten["len"] = /^\w{6,12}$/;	// 문자열 길이
    patten["len"] = /^\w{6,12}$/;	// 문자열 길이
    msg["len"] = "6~12자리로 사용가능합니다.";
    patten["only_num"] = /[a-zA-Z]/;// 숫자만
    msg["only_num"] = "영문 소문자/숫자의 혼용으로 사용가능합니다(숫자만으로는 사용불가).";
    //patten["only_alpha"] = /[0-9]/; // 영문만
    //msg["only_alpha"] = "영문 대/소문자/숫자의 혼용으로 사용가능합니다(영문 대/소문자만으로 사용불가).";



  
	 var retVal = checkSpace( str );
	 if( retVal ) {
		 alert("아이디는 빈 공간 없이 연속된 영문 소문자와 숫자만 사용할 수 있습니다.");
		 return false;
	 }

	/*
	if( str.charAt(0) == '_') {
		alert("아이디의 첫문자는 '_-'로 시작할수 없습니다.");
		return false;
	}
	*/

	// 패턴 체크 
	var i=0;
	for (x in patten)
	{
		p = eval(patten[x]);
		if(!p.test(str))
		{
			ret_msg[i] = msg[x];
			i++;
		} 
	}

	if(i>0) {
		//alert(ret_msg.join('\n'));
		alert("6~12자리의 영문 소문자,숫자 혼용으로 사용가능합니다.");
		return false;
	}
	else return true;
}


// 비밀번호 유효성 체크
/*
function isValid_passwd(str){ 
    var patten = new Array();
    var msg = new Array();
    var p;
    var ret_msg = new Array();
    
    //patten["not_eng_num"] =/[a-zA-Z0-9\_\-]$/;  //a-z와 0-9 _ - 이외의 문자가 있는지 확인
    patten["not_eng_num"] =/[a-zA-Z0-9]$/;  //a-z와 0-9이외의 문자가 있는지 확인
    msg["not_eng_num"] = "영문, 숫자 ,특수기호(_, -)만 사용가능합니다.";
    patten["len"] = /^\w{6,12}$/;	// 문자열 길이
    msg["len"] = "6~12자리로 사용가능합니다.";
    patten["only_num"] = /[a-zA-Z]/;// 숫자만
    msg["only_num"] = "영문 대/소문자/숫자의 혼용으로 사용가능합니다(숫자만으로는 사용불가).";
    patten["only_alpha"] = /[0-9]/; // 영문만
    msg["only_alpha"] = "영문 대/소문자/숫자의 혼용으로 사용가능합니다(영문 대/소문자만으로 사용불가).";
//    patten["same_4"] = /.{4,}/; // 반복문자 4개는 안됨
//    msg["same_4"] = "반복된 문자 4개 이상은 사용불가 합니다.";
    
	 var retVal = checkSpace( str );
	 if( retVal ) {
		 alert("아이디는 빈 공간 없이 연속된 영문 소문자와 숫자만 사용할 수 있습니다.");
		 return false;
	 }
	 
	 if(!contCheck(str, 4)) return;
	 
	// 패턴 체크 
	var i=0;
	for (x in patten)
	{
		p = eval(patten[x]);
		if(!p.test(str))
		{
			alert(x);
			ret_msg[i] = msg[x];
			i++;
		} 
	}

	if(i>0) {
		//alert(ret_msg.join('\n'));		
		alert("6~12자리의 영문 대/소문자,숫자 혼용으로 사용가능합니다.");
		return false;
	}
	else return true;
}
*/


// 비밀번호 유효성 체크
// 동일ID 체크 포함함 
function isValid_passwd_with_id( str, chk_id )
{

	var patten = new Array();
    var msg = new Array();
    var p;
    var ret_msg = new Array();    
    
    // \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\＼\]\^\_\`\{\|\}\~
    // "',./:;<=>?[＼]`{})

    //patten["not_eng_num"] =/[a-zA-Z0-9_-]$/;  //a-z와 0-9 _ - 이외의 문자가 있는지 확인
    //msg["not_eng_num"] = "영문, 숫자 ,특수기호(_)만 사용가능합니다.";
    //patten["not_eng_num"] =/[a-zA-Z0-9]$/;  //a-z와 0-9 _ - 이외의 문자가 있는지 확인
    patten["not_eng_num"] =/^[a-zA-Z0-9\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\＼\]\^\_\`\{\|\}\~]{8,12}$/;
    msg["not_eng_num"] = "영문자, 숫자, 특수문자의 8~12자리로 사용가능합니다.";

    patten["only_num"] = /[a-zA-Z\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\＼\]\^\_\`\{\|\}\~]/;// 숫자만
    msg["only_num"] = "영문자, 숫자, 특수문자의 혼용으로 사용가능합니다(숫자만으로는 사용불가).";
    patten["only_alpha"] = /[0-9\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\＼\]\^\_\`\{\|\}\~]/; // 영문만
    msg["only_alpha"] = "영문자, 숫자, 특수문자의 혼용으로 사용가능합니다(영문/대소문자만으로 사용불가).";
    patten["only_spec_char"]  = /[a-zA-Z0-9]/; 
    msg["only_spec_char"] = "영문자, 숫자, 특수문자의 혼용으로 사용가능합니다(특수문자만으로 사용불가).";
    
    
    patten["not_num"] = /[0-9]/;
    msg["not_num"] ="영문자,숫자, 특수문자의 혼용으로 사용 가능합니다.(숫자 추가 필요)";
    patten["not_alpha"] = /[a-zA-Z]/;
    msg["not_alpha"] = "영문자,숫자, 특수문자의 혼용으로 사용 가능합니다.(영문자 추가 필요)";
    patten["not_spec_char"] = /[\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\＼\]\^\_\`\{\|\}\~]/;
    msg["not_spec_char"] = "영문자,숫자, 특수문자의 혼용으로 사용 가능합니다.(특수문자 추가 필요)";
    
 
   
	 var retVal = checkSpace( str );
	 if( retVal ) {
		 alert("아이디는 빈 공간 없이 연속된 영문자와 숫자만 사용할 수 있습니다.");
		 return false;
	 }
	 
	 if(!contCheck(str, 4)) return;

	 // ID랑 4개 이상 같으면 오류 
	if(chk_id.length >= 4) {

		for(var i=3;i<chk_id.length;i++) {
			 if(str.indexOf(chk_id.substring(i-3,i+1)) != -1){
		     	alert('ID와 4자리수 이상 동일한 비밀번호를 사용할수 없습니다');
		     	return false;
		     }
		}
	}
	 
	// 패턴 체크 
	var i=0;
	for (x in patten)
	{
		p = eval(patten[x]);
		if(!p.test(str))
		{
			ret_msg[i] = msg[x];
			i++;
		} 
	}

	if(i>0) {
		alert(ret_msg[0]);
		return false;
	}
	else return true;
		
}

function isValid_passwd_with_id2( str, chk_id, msg_id )
{
    var patten = new Array();
    var msg = new Array();
    var p;
    var ret_msg = new Array();
        
    patten["not_eng_num"] =/^[a-zA-Z0-9\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\＼\]\^\_\`\{\|\}\~]{8,12}$/;
    msg["not_eng_num"] = "영문자, 숫자, 특수문자의 8~12자리로 사용가능합니다.";

    patten["only_num"] = /[a-zA-Z\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\＼\]\^\_\`\{\|\}\~]/;// 숫자만
    msg["only_num"] = "영문자, 숫자, 특수문자의 혼용으로 사용가능합니다(숫자만으로는 사용불가).";
    patten["only_alpha"] = /[0-9\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\＼\]\^\_\`\{\|\}\~]/; // 영문만
    msg["only_alpha"] = "영문자, 숫자, 특수문자의 혼용으로 사용가능합니다(영문/대소문자만으로 사용불가).";
    patten["only_spec_char"]  = /[a-zA-Z0-9]/; 
    msg["only_spec_char"] = "영문자, 숫자, 특수문자의 혼용으로 사용가능합니다(특수문자만으로 사용불가).";
    
    
    patten["not_num"] = /[0-9]/;
    msg["not_num"] ="영문자,숫자, 특수문자의 혼용으로 사용 가능합니다.(숫자 추가 필요)";
    patten["not_alpha"] = /[a-zA-Z]/;
    msg["not_alpha"] = "영문자,숫자, 특수문자의 혼용으로 사용 가능합니다.(영문자 추가 필요)";
    patten["not_spec_char"] = /[\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\＼\]\^\_\`\{\|\}\~]/;
    msg["not_spec_char"] = "영문자,숫자, 특수문자의 혼용으로 사용 가능합니다.(특수문자 추가 필요)";
    
	 var retVal = checkSpace( str );
	 if( retVal ) {
		 //alert("아이디는 빈 공간 없이 연속된 영문 소문자와 숫자만 사용할 수 있습니다.");
		 alertMsg( msg_id, "아이디는 빈 공간 없이 연속된 영문자와 숫자만 사용할 수 있습니다.");
		 return false;
	 }
	 
	 if(!contCheckMsg(str, 4, msg_id)) return;

	 // ID랑 4개 이상 같으면 오류 
	if(chk_id.length >= 4) {

		for(var i=3;i<chk_id.length;i++) {
			 if(str.indexOf(chk_id.substring(i-3,i+1)) != -1){
		     	//alert('ID와 동일한 4자리수 이상 동일한 비밀번호를 사용할수 없습니다');
		     	alertMsg( msg_id, "아이디와 4자리수 이상 동일한 비밀번호를 사용할수 없습니다.");
		     	return false;
		     }
		}
	}
	
	// 패턴 체크 
	var i=0;
	for (x in patten)
	{
		p = eval(patten[x]);
		if(!p.test(str))
		{
			//alert(msg[x]);
			alertMsg( msg_id, msg[0]);
			return false;
		}
		i++;
	}

	return true;
	
}


function checkSpace( str )
{
	 if(str.search(/\s/) != -1){
		return true;
	 } else {
		return false;
	 }
}

// cabs lock 켜져있는지 체크하는 함수 
function checkCapsLock() {
    
    var myKeyCode=0;
    var myShiftKey=false;
	var e = window.event;
	
    // Internet Explorer 4+
    if ( document.all ) {
        myKeyCode=e.keyCode;
        myShiftKey=e.shiftKey;
    // Netscape 4
    } else if ( document.layers ) {
        myKeyCode=e.which;
        myShiftKey=( myKeyCode == 16 ) ? true : false;
    // Netscape 6
    } else if ( document.getElementById ) {
        myKeyCode=e.which;
        myShiftKey=( myKeyCode == 16 ) ? true : false;
    }
    

    // Upper case letters are seen without depressing the Shift key, therefore Caps Lock is on
    if ( ( myKeyCode >= 65 && myKeyCode <= 90 ) && !myShiftKey ) {    	
    	return true;
    // Lower case letters are seen while depressing the Shift key, therefore Caps Lock is on
    } else if ( ( myKeyCode >= 97 && myKeyCode <= 122 ) && myShiftKey ) {
    	return true;
    }
    else {
        return false;
    }
}

//주민번호, validation 체크 함수
function isValid_socno(socno)
{
	var socnoStr = socno;
     a = socnoStr.substring(0, 1);
     b = socnoStr.substring(1, 2);
     c = socnoStr.substring(2, 3);
     d = socnoStr.substring(3, 4);
     e = socnoStr.substring(4, 5);
     f = socnoStr.substring(5, 6);
     g = socnoStr.substring(6, 7);
     h = socnoStr.substring(7, 8);
     i = socnoStr.substring(8, 9);
     j = socnoStr.substring(9, 10);
     k = socnoStr.substring(10, 11);
     l = socnoStr.substring(11, 12);
     m = socnoStr.substring(12, 13);
	 month = socnoStr.substring(2,4);
	 day = socnoStr.substring(4,6);
	 socnoStr1 = socnoStr.substring(0, 7);
	 socnoStr2 = socnoStr.substring(7, 13);

	 // 월,일 Validation Check
	 if(month <= 0 || month > 12) { return false; }
	 if(day <= 0 || day > 31) { return false; }

	 // 주민등록번호에 공백이 들어가도 가입이 되는 경우가 발생하지 않도록 한다.
	 if (isNull(socnoStr1) || isNull(socnoStr2))  { return false; }

     temp=a*2+b*3+c*4+d*5+e*6+f*7+g*8+h*9+i*2+j*3+k*4+l*5;
     temp=temp%11;
     temp=11-temp;
     temp=temp%10;

     if(temp == m) {
        return true;
     } else {
        return false;
     }
}

// 외국인 등록번호의   유효성 체크
function isValid_fgnno(socno)
{
	var total =0;
	var parity = 0;

	var fgnNo = new Array(13);

	for(i=0;i < 13;i++) fgnNo[i] = parseInt(socno.charAt(i));

	if(fgnNo[11] < 6) return false;

	if((parity = fgnNo[7]*10 + fgnNo[8])&1) return false;


	var weight = 2;

	for(i=0,total=0;i < 12;i++)
	{
		var sum = fgnNo[i] * weight;
		total += sum;

		if(++weight > 9) weight=2;
	}

	if((total = 11 - (total%11)) >= 10) total -= 10;
	if((total += 2) >= 10) total -= 10;
	if(total != fgnNo[12]) return false;

	return true;
}

// 동일문자가 이어지면 체크

function contCheck(str, num) {
	var i;
	var cnt = 0;
	for( i=1; i < str.length; i++) {
		if(str.substring(i-1,i) == str.substring(i,i+1)) {
			cnt++;
		}
		else {
			cnt = 0;
		}
		if(cnt >= num-1) {
			alert('동일한 문자를 '+num+'번이상 사용불가능 합니다.')
			return false;
		}
	}
	return true;
}

function contCheckMsg(str, num, msg_id) {
	var i;
	var cnt = 0;
	for( i=1; i < str.length; i++) {
		if(str.substring(i-1,i) == str.substring(i,i+1)) {
			cnt++;
		}
		else {
			cnt = 0;
		}
		if(cnt >= num-1) {
			//alert('동일한 문자를 '+num+'번이상 사용불가능 합니다.')
			alertMsg( msg_id, '동일한 문자를 '+num+'번이상 사용불가능 합니다.');
			return false;
		}
	}
	return true;
}



// 인증번호 생성
function genAuthNum(gen_num) {
	try {
		var charSetNum = new Array ('0','1','2','3','4','5','6','7','8','9');
		var retNum = new Array();
		var idx;
		// 숫자 6개 
		var row = 0;
		for(var i=0; i<gen_num; i++)
		{
			idx = parseInt(Math.random() * 10);
			retNum[row] = charSetNum[idx];
			row++;
		}
	}
	catch (error) {
		alert('인증번호 생성 오류:'+error.description);
	}
	return retNum.join('');
}


//이메일 체크 
function CheckMailFormat(strMail) { 
   /** 체크사항 
     - @가 2개이상일 경우 
     - .이 붙어서 나오는 경우 
     -  @.나  .@이 존재하는 경우 
     - 맨처음이.인 경우 
     - @이전에 하나이상의 문자가 있어야 함 
     - @가 하나있어야 함 
     - Domain명에 .이 하나 이상 있어야 함 
     - Domain명의 마지막 문자는 영문자 2~4개이어야 함 **/ 

    var check1 = /(@.*@)|(\.\.)|(@\.)|(\.@)|(^\.)/;  

    var check2 = /^[a-zA-Z0-9\-\.\_]+\@[a-zA-Z0-9\-\.]+\.([a-zA-Z]{2,4})$/; 
     
    if ( !check1.test(strMail) && check2.test(strMail) ) { 
        return true; 
    } else { 
        return false; 
    } 
}

function onlyNumber(){
	if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;
}

function chkOnlyNumber(pattern) {
	var regNum =/^[0-9]+$/;
	if(!regNum.test(pattern)){
		return false; 
	} else {
		return true;
	}
}


