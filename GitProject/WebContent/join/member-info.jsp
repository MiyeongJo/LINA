<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<!DOCTYPE html>
<html lang="euc-kr">

<!-- Mirrored from www.cjone.com/cjmweb/join/member-info.do by HTTrack Website Copier/3.x [XR&CO'2014], Thu, 27 Jul 2017 14:59:41 GMT -->
<!-- Added by HTTrack -->
<meta http-equiv="content-type" content="text/html;charset=UTF-8" /><!-- /Added by HTTrack -->
<head>
    <meta charset="utf-8"/>
    <title>회원정보 입력 | CJ ONE</title>
	<meta name="Description" content="CJ ONE 서비스를 이용하실 회원님의 정보를 입력해주세요. 다양한 혜택과 서비스를 받으실 수 있습니다." />
    <meta http-equiv="X-UA-Compatible" content="IE=edge ,chrome=1" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
	<meta name="format-detection" content="telephone=no" />
	<meta http-equiv="Cache-Control" content="no-cache" />
	<meta http-equiv="Pragma" content="no-cache" />
	
	<link rel="shortcut icon" href="https://www.cjone.com/cjmweb/images/ico/favicon.ico" type="images/x-ico" />
	<link rel="alternate" href="https://m.cjone.com:8443/cjmmobile/member/meberjoinstep2.do" />
	<script type="text/javascript">
		var contextPath = '/cjmweb';
	</script>
	<script src="../js/jquery-1.11.3.min.js"></script>
	<script src="../js/common.js"></script>
	<script src="../js/form.validate.js"></script>

	<script type="text/javascript" src="http://cdnjs.cloudflare.com/ajax/libs/jquery/1.9.0/jquery.js"></script>
	 
	<link rel="stylesheet" href="../css/base.css" >
	<link rel='stylesheet' href='../css/member.css' > 

		
			<script>
			  (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
			  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
			  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
			  })(window,document,'script','../../../www.google-analytics.com/analytics.js','ga');
			  ga('create', 'UA-17703059-2', 'auto');
			  ga('send', 'pageview');
			</script>
		
		
	
	  <script type="text/javascript">
		
		var digitalData={
				page:{
					pageInfo:{
						pageName:"[P]회원가입^회원정보입력",
						siteType:"P",
						LayerPageName:""
								}
						},
				user:{
					loginStatus:"logged out",
					custID:"",
					level:""
					},
				shop:{
					location:"",
					brand:"",
					name:""
					},
				consult:{
					type:""
					},
				myshop:{
					name:"",
					brand:""
					},
				click:{
					track:""
				}
			};
		
	
	  </script>
	  <script src="../../../assets.adobedtm.com/81654681a53723e7e24e9d28bcbbae479c047b65/satelliteLib-e1b7fc64ff48523381d135a16bae0d60c92eebf0.js"></script>
	  
</head>


<body>
<!--skip navigation-->
<div class="skipNavi">
	<a href="#contentsWrap">본문으로 바로가기</a>
</div>
<!--//skip navigation-->
<div id="bodyWrap">
	
	<!--header-->
	






<script type="text/javascript">

function search(){
	var search_keyword = $("#search_keyword").val();
   	if($(".tSearch").hasClass("on")) {
   		
   		if(search_keyword.trim().length == 0) {
   			alert("검색어를 입력해주세요.");
			$("#search_keyword").focus();
			return false;   			
   		}
   		
   		if(search_keyword.trim().length > 20) {
			alert("검색어는 최대 20자까지 검색 가능합니다.");
			$("#search_keyword").focus();
			return false;
		}

   		ga('send', 'event', 'Header 영역', '통합검색', '통합검색');
   		digitalData.click.track= "Header^통합검색";
   		_satellite.track('clicks');
		//$("#h_search_keyword").val(encodeURIComponent(search_keyword));
		//$("#headerFrm").attr("action", "http://www.cjone.com/cjmweb/search.do?h_search_keyword=" + encodeURIComponent(search_keyword));
		$("#h_search_keyword").val(search_keyword);
		$("#headerFrm").attr("action", "http://www.cjone.com/cjmweb/search.do?h_search_keyword=" + search_keyword);
		$("#headerFrm").submit();
    }	
};

function goStore() {
	cjone.openModal('/cjmweb/layer/store/search.do');
}


//DashBoard 관련 function 
var isFirstDashOpen = false;
$(function () {
   /**
    * 대시보드 열기/ 닫기:
    **/
    $('[data-control="personalInfo"]').on({
        'click': function (e) {
            e.preventDefault();
            personalInfoAction();
        }
    });
    
	// ie8에서 trim()함수 오류로 인한 정의
    if(typeof String.prototype.trim !== 'function') {
    	String.prototype.trim = function() {
    	    return this.replace(/^\s+|\s+$/g, ''); 
    	};
    }
    
});


//DashBoard html 불러오기
function personalInfoAction() {
	if(loginCheck() == true){
		if(isFirstDashOpen == false){
			var $appendArea = $('#personalInfo');
			var t = new Date().getTime();
			$.ajax({
				url: '/cjmweb/common/layer/dash-board-action.do?t='+t
	        }).done(function (html) {
	            var $html = $(html).find('div:eq(0)').parent();
	            $appendArea.html($html).show();
	            isFirstDashOpen = true;
	    		var $this = $('[data-control="personalInfo"]');
	    	    $this.triggerHandler('toggle');
	    	    // Google Analytics
	    		ga('send', 'event', 'Header 영역', 'NOW', 'NOW');
	    	    // Adobe Analytics
	       		digitalData.click.track= "Header^NOW";
	       		_satellite.track('clicks');
	    	    $("#noticeList_box").scroll( function() {
	   	    	  	var elem = $("#noticeList_box");
	   	    	  	if ( elem[0].scrollHeight - elem.scrollTop() == elem.outerHeight()){
	   	    		  notifyMessageAction();
	   	    	  	}
	    	    });
	    	    $('[data-control="randomNum"]').charMotion('runUp');
	    	    $('[data-control="tooltip"]').tooltip();
	    	    $('[data-control="scrollView"]').scrollview();	    	    
	    	    
	        });
		}else{
			var $this = $('[data-control="personalInfo"]');
		    $this.triggerHandler('toggle');
		 // Google Analytics
			ga('send', 'event', 'Header 영역', 'NOW', 'NOW');
			// Adobe Analytics
       		digitalData.click.track= "Header^NOW";
       		_satellite.track('clicks');
		}    
	}else{
		linkLogin();
	}
}


//알림정보 추가 조회
var noti_page_num = 1 ;
var readProcessResult = false;
function notifyMessageAction(page_num){
	if(noti_page_num == 99) return; //더이상 조회할건 없음.
	
	noti_page_num = noti_page_num + 1;
	
	$.ajax({
        url : '/cjmweb/layer/notify/notify-list.do',
        dataType : 'json',
        data : 'page_num='+noti_page_num,
        async : true,
        type : 'POST',
        error : function(err) { 
        },
        success : function(response, statusText) {
        	if (response.notifylist != undefined && response.notifylist != null && response.notifylist.length > 0) {
        		makeList(response.notifylist);
        		if(response.notifylist < 10){
        			noti_page_num = 99; //추가조회 없음
        		}
        	}else{
        		noti_page_num = 99; //추가조회 없음
        	}
        }
	});
}

//알림 리스트 생성
function makeList (jsonList) {
	if (jsonList != undefined && jsonList != null && jsonList.length > 0){ 
		$(jsonList).each(function(index,data) {				
			 html ="";
			 html += '<li>';
			 if(data.read_yn == "Y"){
				 html +='<a class="visited" href="javascript:goNotifyAction('+ data.notify_seq +','+ data.notify_link_url +')">';
			 }else{
				 html +='<a href="javascript:goNotifyAction('+ data.notify_seq +','+ data.notify_link_url +')">';
			 }
			 
			 if(data.notify_section_name != "" && data.notify_section_name != undefined ) {
				 html += '	<p>['+ data.notify_section_name +'] '+ data.notify_msg +'</p>';	 
			 } else {
				 html += '	<p>'+ data.notify_msg +'</p>';
			 }
			 
			 html += '	<span class="date">' + data.aprv_fr_dy +' ' + data.reg_time + '</span>';
			 html += '</a>';
			 html += '</li>';

			 $("#noticeList").append(html);
		});
	}
}

//알림 상세로 이동
function goNotifyAction(notify_seq,link_url){
	if(readNotifyAction(notify_seq) == true ){
		ga('send', 'event', 'MY Dash Board 영역', '알림메세지', '알림메세지');		
		$(location).attr("href",link_url);
	}
}

//알림 읽음처리
function readNotifyAction(notify_seq){
	$.ajax({
        url : '/cjmweb/layer/notify/notify-read.do',
        dataType : 'json',
        data : 'notify_seq='+notify_seq,
        async : false,
        type : 'POST',
        error : function(err) { 
        	readProcessResult = false;
        },
        success : function(response, statusText) {
        	if(statusText == 'success'){
        		readProcessResult = true;
        	}else{
        		readProcessResult = false;
        	}
        }
	});
	return readProcessResult;
}
	
function linkLogin() {
	var current = location.href;
	var rtn = '';
	if(current.indexOf('/cjmweb/main.do')> -1) {
		rtn = 'http://www.cjone.com/cjmweb/main.do?s=m';
		rtn = '?return_url='+encodeURI(rtn);
	}
	location.href = 'https://www.cjone.com/cjmweb/login.do'+rtn;
}

function linkCardMng() {
	if( !loginCheck() ) {
		if(confirm('카드 등록을 위해 로그인이 필요합니다.\n계속 진행하시겠습니까?')) {
			//location.href='https://www.cjone.com/cjmweb/my-one/card.do';
			$(location).attr('href', '/cjmweb/login.do?return_url='+escape('https://www.cjone.com/cjmweb/my-one/card.do'));
			return false;
		}
	} else {
		location.href='https://www.cjone.com/cjmweb/my-one/card.do';
		return false;
	}
	return false;
}

</script>
<form id="headerFrm" method="get">
	<input type="hidden" name="h_search_keyword" id="h_search_keyword">
</form>
	<!-- 참여사 관련 판단 로직 변경 2016-06-20 pjh0416 -->
    
	<div id="headerWrap">
	<!-- on시 height:313px 로 해주세요. css 에 넣어서 important 를 넣을 경우 animation 이 안일어납니다.-->
		<!--header inner-->
		<div class="header_wrap">
			<h1>
				
				
				
					
					
						
					
				
				
				<a href="http://www.cjone.com/cjmweb/main.do" onclick="ga('send', 'event', 'BI', 'SUB BI', 'SUB BI');">
					<img src="../images/common/logo_cjone.png" alt="CJ ONE" />
				</a>
			</h1>
			<!-- 20160315 -->
			<div class="bg_dim">
			<!-- //20160315 -->
				<div id="navi" class="hide">
					<!-- 20160315 -->
					<h2 class="mobile">메뉴 전체보기</h2>
					<!-- //20160315 -->
					<!-- 20160315 -->
					<div class="menu_scroll">
					<!-- //20160315 -->						
						<dl class="util">
							<dt class="haze">유틸메뉴</dt>
							
							<dd class="logIn"><a href="javascript:;" onclick="ga('send', 'event', 'Header 영역', '로그인', '로그인');linkLogin();" data-track="Header^로그인"><span>로그인</span></a></dd>
							<dd class="join"><a href="https://www.cjone.com/cjmweb/join.do"  onclick="ga('send', 'event', 'Header 영역', '회원가입', '회원가입');" data-track="Header^회원가입"><span>회원가입</span></a></dd>
							
							
							<dd class="mobile"><a href="http://www.cjone.com/cjmweb/vip.do"  onclick="ga('send', 'event', 'Header 영역', 'VIP라운지', 'VIP라운지');" data-track="Header^VIP라운지"><span>VIP라운지</span></a></dd>
							<dd class="store"><a href="http://www.cjone.com/cjmweb/find-store.do"  onclick="ga('send', 'event', 'Header 영역', '매장찾기', '매장찾기');" data-track="Header^매장찾기"><span>매장찾기</span></a></dd>
							<dd class="go_cscenter mobile"><a href="#go_cscenter" data-control="toggleGnb" title="고객센터 열기" class="link" data-open-text="고객센터 닫기" data-close-text="고객센터 열기"><span>고객센터</span></a>
								<ul id="go_cscenter" class="hide">
									<li><a href="http://www.cjone.com/cjmweb/customer/faq.do" onclick="ga('send', 'event', 'Header 영역', '고객센터', '자주 찾는 질문');" data-track="Header^고객센터|자주 찾는 질문"><span>자주 찾는 질문</span></a></li>
									<li><a href="https://www.cjone.com/cjmweb/customer/counseling/apply.do" onclick="ga('send', 'event', 'Header 영역', '고객센터', '1:1상담');" data-track="Header^고객센터|1:1상담"><span>1:1상담</span></a></li>
									<li><a href="http://www.cjone.com/cjmweb/customer/news-notice.do" onclick="ga('send', 'event', 'Header 영역', '고객센터', '뉴스&공지');" data-track="Header^고객센터|뉴스&공지"><span>뉴스&amp;공지</span></a></li>
								</ul>
							</dd>
							<dd class="card">
								<a href="javascript:;" onclick="ga('send', 'event', 'Header 영역', '카드등록', '카드등록');linkCardMng();"><span>카드등록</span></a>
							</dd>
						</dl>
		                
						
						<div id="gnb">
							<ul class="gnb_1depth" data-control="accordionGnb">
								<li class="depth1"><a href="http://www.cjone.com/cjmweb/about-cjone.do" onclick="ga('send', 'event', 'GNB 영역', 'CJ ONE소개', 'CJ ONE소개');" class="link_1depth" data-track="GNB^CJ ONE소개" >CJ ONE 소개</a></li>
								<li class="depth1"><a href="http://www.cjone.com/cjmweb/point-card/guide.do" onclick="ga('send', 'event', 'GNB 영역', '포인트/카드', '포인트/카드');" class="link_1depth" data-track="GNB^포인트/카드|포인트/카드">포인트/카드</a>
									<ul class="gnb_2depth" data-event="gnb">
										<li><a href="http://www.cjone.com/cjmweb/point-card/guide.do" onclick="ga('send', 'event', 'GNB 영역', '포인트/카드', '포인트 적립/사용');" class="link_2depth"><span>포인트 적립/사용</span></a></li>
										<li><a href="http://www.cjone.com/cjmweb/point-card/brand.do" onclick="ga('send', 'event', 'GNB 영역', '포인트/카드', '제휴 브랜드');" class="link_2depth"><span>제휴 브랜드</span></a></li>
										<li><a href="http://www.cjone.com/cjmweb/point-card/bonus-point.do" onclick="ga('send', 'event', 'GNB 영역', '포인트/카드', '보너스포인트');" class="link_2depth"><span>보너스포인트</span></a></li>
										<li><a href="http://www.cjone.com/cjmweb/point-card/point-donation.do" onclick="ga('send', 'event', 'GNB 영역', '포인트/카드', '포인트 기부');" class="link_2depth"><span>포인트 기부</span></a></li>
										
											<li><a href="http://www.cjone.com/cjmweb/point-card/point-gift.do" onclick="ga('send', 'event', 'GNB 영역', '포인트/카드', '포인트 선물');" class="link_2depth" data-track="GNB^포인트/카드|포인트 선물"><span>포인트 선물</span></a></li>
										
										<li><a href="http://www.cjone.com/cjmweb/point-card/point-conversion.do" onclick="ga('send', 'event', 'GNB 영역', '포인트/카드', '포인트 전환');" class="link_2depth" data-track="GNB^포인트/카드|포인트 전환"><span>포인트 전환</span></a></li>
										<li><a href="http://www.cjone.com/cjmweb/point-card/gift-point.do" onclick="ga('send', 'event', 'GNB 영역', '포인트/카드', '기프트포인트 등록');" class="link_2depth" data-track="GNB^포인트/카드|기프트포인트 등록"><span>기프트포인트 등록</span></a></li>
										<li><a href="http://www.cjone.com/cjmweb/point-card/branded-card.do" onclick="ga('send', 'event', 'GNB 영역', '포인트/카드', '제휴 신용카드 안내');" class="link_2depth" data-track="GNB^포인트/카드|제휴 신용카드 안내"><span>제휴 신용카드 안내</span></a></li>
									</ul>
								</li>
								<li class="depth1"><a href="http://www.cjone.com/cjmweb/event-coupon/event.do" onclick="ga('send', 'event', 'GNB 영역', '이벤트/쿠폰', '이벤트/쿠폰');" class="link_1depth" data-track="GNB^이벤트/쿠폰|이벤트/쿠폰">이벤트/쿠폰</a>
									<ul class="gnb_2depth" data-event="gnb">
										<li><a href="http://www.cjone.com/cjmweb/event-coupon/event.do" onclick="ga('send', 'event', 'GNB 영역', '이벤트/쿠폰', '이벤트');" class="link_2depth" data-track="GNB^이벤트/쿠폰|이벤트"><span>이벤트</span></a></li>
										<li><a href="http://www.cjone.com/cjmweb/event-coupon/coupon.do" onclick="ga('send', 'event', 'GNB 영역', '이벤트/쿠폰', '쿠폰');" class="link_2depth" data-track="GNB^이벤트/쿠폰|쿠폰"><span>쿠폰</span></a></li>
										<li><a href="http://www.cjone.com/cjmweb/event-coupon/stamp/list.do" onclick="ga('send', 'event', 'GNB 영역', '이벤트/쿠폰', '득템프');" class="link_2depth" data-track="GNB^이벤트/쿠폰|득템프"><span>득템프</span></a></li>
									</ul>
								</li>
								<li class="depth1"><a href="http://www.cjone.com/cjmweb/shopping/list.do"  onclick="ga('send', 'event', 'GNB 영역', 'ONE콘', 'ONE콘');" class="link_1depth" data-track="GNB^ONE콘">ONE콘</a></li>
								<!--  기프트카드 메뉴  -->
								<li class="depth1"><a href="http://www.cjone.com/cjmweb/cash/cashmain.do" onclick="ga('send', 'event', 'GNB 영역', '기프트카드', '기프트카드');" class="link_1depth"  data-track="GNB^기프트카드|기프트카드">기프트카드</a>
									<ul class="gnb_2depth" data-event="gnb">
										<li><a href="http://www.cjone.com/cjmweb/cash/cashmain.do" onclick="ga('send', 'event', 'GNB 영역', '기프트카드', '나의 기프트카드');" class="link_2depth" data-track="GNB^기프트카드|나의 기프트카드"><span>나의 기프트카드</span></a></li>
										<li><a href="http://www.cjone.com/cjmweb/cash/cashinfo.do" onclick="ga('send', 'event', 'GNB 영역', '기프트카드', '기프트카드 안내');" class="link_2depth" data-track="GNB^기프트카드|기프트카드 안내"><span>기프트카드 안내</span></a></li>
										<li><a href="http://www.cjone.com/cjmweb/cash/cashreg.do"  onclick="ga('send', 'event', 'GNB 영역', '기프트카드', '등록');" class="link_2depth" data-track="GNB^기프트카드|등록"><span>등록</span></a></li>
										<li><a href="https://www.cjone.com/cjmweb/cash/cashPurcList.do"  onclick="ga('send', 'event', 'GNB 영역', '기프트카드', '구매/선물');" class="link_2depth" data-track="GNB^기프트카드|구매/선물"><span>구매 / 선물</span></a></li>							
										<li><a href="http://www.cjone.com/cjmweb/cash/cashSendPrsntList.do" onclick="ga('send', 'event', 'GNB 영역', '기프트카드', '선물함');" class="link_2depth" data-track="GNB^기프트카드|선물함"><span>선물함</span></a></li>										 
									</ul>
								</li>						
								<li class="depth1 last"><a href="https://www.cjone.com/cjmweb/my-one/recommend.do"  onclick="ga('send', 'event', 'GNB 영역', '나의 ONE', '나의 ONE');" class="link_1depth" data-track="GNB^나의 ONE|나의 ONE">나의 ONE</a>
									<ul class="gnb_2depth" data-event="gnb">
										<li><a href="https://www.cjone.com/cjmweb/my-one/recommend.do"  onclick="ga('send', 'event', 'GNB 영역', '나의 ONE', '나의 ONE');" class="link_2depth" data-track="GNB^나의 ONE|나의 ONE"><span>나의 ONE</span></a></li>
										<li><a href="https://www.cjone.com/cjmweb/my-one/point.do" onclick="ga('send', 'event', 'GNB 영역', '나의 ONE', '나의 포인트');" class="link_2depth" data-track="GNB^나의 ONE|나의 포인트"><span>나의 포인트</span></a></li>
										<li><a href="javascript:;" onclick="ga('send', 'event', 'GNB 영역', '나의 ONE', '카드 관리/변경');linkCardMng();return false;" class="link_2depth" data-track="GNB^나의 ONE|카드 관리/변경"><span>카드 관리/변경</span></a></li>
										<li><a href="https://www.cjone.com/cjmweb/my-one/coupon.do" onclick="ga('send', 'event', 'GNB 영역', '나의 ONE', '나의 쿠폰');" class="link_2depth" data-track="GNB^나의 ONE|나의 쿠폰"><span>나의 쿠폰</span></a></li>
										<li><a href="https://www.cjone.com/cjmweb/my-one/event.do" onclick="ga('send', 'event', 'GNB 영역', '나의 ONE', '응모한 이벤트');" class="link_2depth" data-track="GNB^나의 ONE|응모한 이벤트"><span>응모한 이벤트</span></a></li>
										<li><a href="https://www.cjone.com/cjmweb/my-one/shopping.do" onclick="ga('send', 'event', 'GNB 영역', '나의 ONE', 'ONE콘 구매내역');" class="link_2depth" data-track="GNB^나의 ONE|ONE콘 구매내역"><span>ONE콘 구매내역</span></a></li>
										<li><a href="https://www.cjone.com/cjmweb/my-one/counseling.do" onclick="ga('send', 'event', 'GNB 영역', '나의 ONE', '나의 상담내역');" class="link_2depth" data-track="GNB^나의 ONE|나의 상담내역"><span>나의 상담내역</span></a></li>
									</ul>
								</li>
							</ul>
							<!--<button type="button" class="close" data-event="gnb_close">전체메뉴닫기</button>-->
							<button type="button" class="close" data-control="gnbClose">전체메뉴닫기</button>
						</div>
						
					<!-- 20160315 -->
					</div>
					<!-- //20160315 -->				
				</div>
			<!-- 20160315 -->
			</div>
			<!-- //20160315 -->
			<dl class="myInfo">
				<dt class="haze">개인화 컨텐츠</dt>
				<dd class="viewNavi"><a href="#navi" data-control="smallGnbButton"><img src="../images/common/btn_gnb_open.png" alt="메뉴보기" data-handler="toggleText"></a></dd>
				<dd class="tSearch" data-handler="searchTag"><!-- 클릭 시, 클래스 on 추가 -->
					<span class="btn_open"><a href="#global_search" class="open" data-control="toggleSearch" data-submit-text="검색입력서식 보내기" data-close-text="검색입력서식 열기" data-open-text="검색입력서식 닫기" title="검색입력서식 열기">검색입력서식 열기</a></span>
				</dd>
				<dd class="onester">
					<span class="btn_open">
						<a href="#personalInfo" data-control="personalInfo" data-close-text="나의정보 열기" data-open-text="나의정보 닫기">
                            <!-- 최초 진입 시 -->
                            <span class="img_wrap nowload" data-file-url="/cjmweb/images/common/onester/appear_[number].png" data-start-num="00000" data-end-num="00056">
                                <img src="../images/common/onester/appear_00056.png" alt=""><!-- appear_00000 ~ appear_00056 -->
                            </span>
                            <!-- 평상 시 -->
                            <span class="img_wrap normal hide" data-file-url="/cjmweb/images/common/onester/loop_[number].png" data-start-num="00000" data-end-num="00081">
                                <img src="../images/common/onester/loop_00000.png" alt=""><!-- loop_00000 ~ loop_00081 -->
                            </span>
                            <!-- 대시보드 오픈 시 -->
                            <span class="img_wrap dash_open hide" data-file-url="/cjmweb/images/common/onester/myIn_[number].png" data-start-num="00000" data-end-num="00016">
                                <img src="../images/common/onester/myIn_00000.png" alt=""><!-- myIn_00000 ~ myIn_00016 -->
                            </span>
                            <!-- 대시보드 닫기 시 -->
                            <span class="img_wrap dash_close hide" data-file-url="/cjmweb/images/common/onester/myOut_[number].png" data-start-num="00000" data-end-num="00015">
                                <img src="../images/common/onester/myOut_00000.png" alt=""><!-- myOut_00000 ~ myOut_00015 -->
                            </span>
							<span class="haze">나의정보 열기</span>
						</a>
					</span>
				</dd>
			</dl>
		</div>
		<!--//header inner-->
		<!-- global search -->
		<div id="global_search" class="global_search"><!-- 활성화 시, 클래스 on 추가 -->
			<div class="search_sec">
				<div class="search_box">
					<span class="input_txt"><input type="text" id="search_keyword" maxlength="200" class="text" value="" name="search_keyword" title="검색어 입력란" placeholder="검색어를 입력해주세요." onkeypress="if(event.keyCode==13){ search(); return false; };"></span>
					<button type="button" class="btn btn_search" onclick="search();"><span>검색</span></button>
				</div>
			</div>
		</div>		
		<!-- //global search -->
		
		<!-- personal + alarm notice -->
		<div id="personalInfo" name="personalInfo" class="personalInfo" >
			<h2 class="haze">나의 정보</h2>
		</div>
		<!-- //personal + alarm notice -->
		
	</div>


	<!--//header-->

	<!--contents-->
	<div id="contentsWrap">
		<div id="contents">
			<!--title-->
			
			<div class="location_wrap">
				<div class="location"><a href="http://www.cjone.com/cjmweb/main.do" class="home"><span class="haze">홈</span></a><a href="https://www.cjone.com/cjmweb/join.do" class="now"><span>회원가입</span></a></div>
			</div>
			
			<div class="cont_header">
				<h1 class="h1_tit">회원가입</h1>
				<p class="h_desc">라이프스타일 멤버십 CJ ONE! 외식, 쇼핑, 엔터테인먼트 서비스를 한 장의 카드로 즐기세요~</p>
			</div>
			<!--title-->
			<div class="cont_area">
				<div class="member_join">
					<!--step-->
					<div class="step_join">
						
							
							
								<ul class="col4">
								<!--
									<li class="step1">본인인증 <span class="haze">진행 완료</span><span class="line"></span></li>
									<li class="step2">약관동의 <span class="haze">진행 완료</span><span class="line"></span></li>
								-->
									<li class="step3 on">회원정보 입력 <span class="haze">진행 중</span></li>
								<!--	<li class="step4">가입완료 <span class="haze">진행 전</span></li>
								-->
								</ul>
							
						
					</div>
					<!--//step-->
					<div class="member_data">
						<h2 class="haze">회원정보 입력</h2>
						<!-- <p class="msg_emph">
							CJ ONE 회원가입을 위해 <em>회원정보를 입력</em>해주세요.
						</p> -->

						<div class="member_info">
							<form id="form1" method="post" action="#">
							    <input type="hidden" id="coopco_cd"     name="coopco_cd"     value="">
							    <input type="hidden" id="brnd_cd"       name="brnd_cd"       value="">
							    <input type="hidden" id="mcht_no"       name="mcht_no"       value="">
							    <input type="hidden" name="coop_return_url" id="coop_return_url" value="">
							    <input type="hidden" id="sub_type"      name="sub_type"      value="">
							    <input type="hidden" id="ipin_use_yn"   name="ipin_use_yn"   value="">
							    <input type="hidden" id="hg_nm"         name="hg_nm"         value="">
							    <input type="hidden" id="vno"           name="vno"           value="">
							    <!-- ####주민번호미보유#### 주민번호삭제 -->
							    <input type="hidden" id="ipin_ci"       name="ipin_ci"       value="">
							    <input type="hidden" id="ssn1"          name="ssn1"                 value="">
    							<input type="hidden" id="ssn2"          name="ssn2"                 value="">
							    <input type="hidden" id="ipin_di"       name="ipin_di"       value="">
							    <input type="hidden" id="gender"        name="gender"        value="">
							    <input type="hidden" id="legl_birth_dy" name="legl_birth_dy" value="">
							    <input type="hidden" id="frgnr_yn"      name="frgnr_yn"      value="">
							    <input type="hidden" id="under_14"      name="under_14"      value="">
							    <input type='hidden' id="id_validate"   name="id_validate"   value="">
							    <input type="hidden" id="agr_dy"        name="agr_dy"        value="">
							    <input type="hidden" id="agr_tm"        name="agr_tm"        value="">
							    <input type="hidden" id="agr_yn"        name="agr_yn"        value="">
							    <input type="hidden" name="svcuse_agr_typ_cd" value="">
							    <input type="hidden" name="agr_sub_yn99" id="agr_sub_yn99" value=""> <!-- 3자 동의파라메터   -->
							    <input type="hidden" id="mbr_no"        name="mbr_no"           value="">
							    <input type="hidden" id="mbr_typ_cd"    name="mbr_typ_cd"       value="">
							    <input type="hidden" id="legl_rep_nm" name="legl_rep_nm" value="">
							    <input type="hidden" id="legl_birth_day" name="legl_birth_day" value="">
							    <input type="hidden" id="legl_ipin_ci" name="legl_ipin_ci" value="">
							    <input type="hidden" id="legl_cert" name="legl_cert" value="">
							    <input type="hidden" id="legl_typ_cd" name="legl_typ_cd" value="">
							    <input type="hidden" id="legl_rep_agr_yn" name="legl_rep_agr_yn" value="">
							    <input type="hidden" id="join_coopco_list"     name="join_coopco_list"     value="">
							    <input type="hidden" id="rejoin_yn"            name="rejoin_yn"            value="">
							    <input type="hidden" id="actionUrl"            name="actionUrl"            value="">
							    <input type="hidden" id="nm_cnfm_yn"           name="nm_cnfm_yn"           value="">
							    <input type="hidden" id="coopco_hg_nm"         name="coopco_hg_nm"         value=""/>
							    <input type="hidden" name=agr_typ_onln value="">
							    <input type="hidden" id="card_chk"              name="card_chk"             value="N" >
							    <input type="hidden" name="evt_typ" id="evt_typ" value="">
							    <input type="hidden" id="clndr_typ_cd" name="clndr_typ_cd" value="S"/>
							    <input type="hidden" id="upd_coopco_id"         name="upd_coopco_id"        value="">
							    <!-- 2010.12.21 가입출처 제휴사 정보 추가.(오쇼핑,온마트의 다음온, 링크프라이스를 통한 회원가입시 가입출처 정보) -->
							    
								    
							
								<div class="table_header">
									<h3 class="h3_tit">기본정보</h3>
									<div class="info"><p class="msg_mandatory"><span class="haze">"필수"</span> 표시는 필수 입력 항목입니다.</p></div>
								</div>
								<div class="table_col">
									<table>
										<caption>회원기본정보 입력 표로 회원정보 이름, 아이디, 비밀번호, 비밀번호 확인, 생년월일, 휴대전화, 이메일을 나타냅니다.</caption>
										<colgroup>
											<col class='title'>
											<col class='body'>
										</colgroup>
										<tbody>
											<tr class="input">
												<th scope="row" class="mandatory">
													<label for="input_member_name"><span class="haze">"필수"</span> 이름</label>
												</th>
												<td>
													<span class="input_txt"><input type="text" placeholder="이름을 입력해주세요." value="" class="text" id="input_member_name"></span><!-- 에러시 .error 클래스 추가 -->
												</td>
											</tr>
											<tr class="input">
												<th scope="row" class="mandatory">
													<label for="mbr_id"><span class="haze">"필수"</span> 아이디</label>
												</th>
												<td>
													<div class="input_group">
														<span class="input_txt w250"><input type="text" class="text" title="사용 할 영문 아이디 명 입력" placeholder="아이디를 입력해주세요." name="mbr_id" id="mbr_id" maxlength="12" value=""><!-- 에러시 .error 클래스 추가 --></span>
														
															<button type="button" class="btn btn_search" onclick="javascript:idCheck();">중복확인</button>
														
														<a class="btn btn_sm" onclick="cjone.openModal('/cjmweb/join/cjPotalIdInfo.do')" href="javascript://;"><span class="arr">CJ ONE 통합 아이디 안내</span></a>
														<p class="msg_info em hide" id="alert_mbr_id"></p>
													</div>
													<p class="msg_desc">CGV,CJmall, Mnet 등 기존의 CJ ONE  제휴 브랜드 회원님의 경우는 기존에 사용하고 계신 아이디가 새롭게 생성하신 <br>통합 아이디로 변경됩니다.</p>
												</td>
											</tr>
											<tr class="input">
												<th scope="row" class="mandatory">
													<label for="pwd"><span class="haze">"필수"</span> 비밀번호</label>
												</th>
												<td>
													<div class="input_group">
														<span class="input_txt w250"><input type="password" class="text" placeholder="비밀번호를 입력해주세요." name="pwd" id="pwd" maxlength="12"></span>
														<span class="pwd_lv" id="alert_pwd_strength"></span>
														<p class="msg_info em hide" id="msg_pwd" >비밀번호는 영문자, 숫자, 특수문자 모두 최소 1가지 이상 조합한 8~12자리이어야 합니다.</p>
													</div>
													<p class="msg_desc">영문자, 숫자,특수문자 조합하여 8~12자리, 아이디와 4자리이상 동일,반복 문자숫자 불가<br>사용 가능 특수 문자 : !"#$%&amp;'()*+,-./:;&lt;=&gt;?@[]^_'{|}~</p>
												</td>
											</tr>
											<tr class="input">
												<th scope="row" class="mandatory">
													<label for="pwd_check"><span class="haze">"필수"</span> 비밀번호 확인</label>
												</th>
												<td>
													<div class="input_group">
														<span class="input_txt"><input type="password" class="text" placeholder="비밀번호를 재입력해주세요." name="pwd_check"  id="pwd_check" maxlength="12"></span>
														<p class="msg_info em hide" id="msg_pwd_check">비밀번호와 비밀번호 확인이 일치하지 않습니다.</p>
													</div>
												</td>
											</tr>
											<tr class="input">
												<th scope="row" class="mandatory">
													<label for="birth_yy">
													<span class="haze">"필수"</span> 생년월일</label>
												</th>
												<td>
													<div class="birthday_select">
														<span class="select w120" data-skin="form">
															<select title="생년월일 중 년 선택" id="birth_yy" name="birth_yy">
																<option value="" >선택</option>
													<%
												        for(int i = 1930; i<2018; i++){
												       %>
												      <option value ="<%=i%>"> <%=i%></option>
												      <%
												        }
													 %>
															</select>
														</span>
														<span class="symbol">년</span>
														<span class="select w70" data-skin="form">
															<select title="생년월일 중 월 선택" class="narrow" id="birth_mm" name="birth_mm">
																<option value="" selected="selected">선택</option>
													<%
												        for(int i = 1; i<13; i++){
												       %>
												      <option value ="<%=i%>"> <%=i%></option>
												      <%
												        }
													 %>
															</select>
														</span>
														<span class="symbol">월</span>
														<span class="select w70" data-skin="form">
															<select title="생년월일 중 일 선택" class="narrow" id="birth_dd" name="birth_dd">
																<option value="" selected="selected">선택</option>
													<%
												        for(int i = 1; i<32; i++){
												       %>
												      <option value ="<%=i%>"> <%=i%></option>
												      <%
												        }
													 %>
															</select>
														</span>
														<span class="symbol">일</span>
														
														<span class="select w70" data-skin="form">
															<select title="성별 선택" class="narrow" id="gender" name="gender">
																<option value="여자" selected="selected">여자</option>
																<option value="남자">남자</option>
															</select>
														</span>
													</div>
													<p class="msg_desc">설정하신 생일을 기준으로 <em>15일 전</em> 생일쿠폰이 발행됩니다.</p>
												</td>
											</tr>
											<tr class="input">
												<th scope="row" class="mandatory">
													<label for="mob_no_1"><span class="haze">"필수"</span> 휴대전화</label>
												</th>
												<td>
													<div class="phon_write">
														<span class="select w100" data-skin="form">
															<select title="휴대전화 앞자리 선택" id="mob_no_1" name="mob_no_1">
																<option value="" selected="selected">선택</option>
																<option value="010" >010</option>
																<option value="011" >011</option>
																<option value="017" >016</option>
																<option value="017" >017</option>
																<option value="017" >019</option>
															</select>
														</span>
														<span class="symbol">-</span>
														<span class="input_txt w100">
															<input type="text" class="text narrow" title="휴대전화 중간자리 입력" data-format="num" id="mob_no_2" name="mob_no_2" maxlength="4" value="">
														</span>
														<span class="symbol">-</span>
														<span class="input_txt w100">
															<input type="text" class="text narrow" title="휴대전화 끝자리 입력" data-format="num" id="mob_no_3" name="mob_no_3" maxlength="4" value="">
														</span>
														<p class="msg_info em hide" id="alert_mob_no"></p>
													</div>
													<p class="msg_desc">주문 및 배송, 쿠폰, 이벤트 정보 등을 제공 받으실 수 있습니다.</p>
												</td>
											</tr>
											<tr class="input">
												<th scope="row" class="mandatory">
													<label for="email_addr1"><span class="haze">"필수"</span> 이메일</label>
												</th>
												<td>
													<div class="email_write">
														<span class="input_txt w110" data-skin="form">
															<input type="text" class="text small" title="이메일 아이디 입력" name="email_addr1" id="email_addr1" value="" placeholder="이메일 아이디" data-format="email">
														</span>
														<span class="symbol">@</span>
														<span class="input_txt w110">
															<input type="text" class="text small" title="이메일 도메인 입력" name="email_addr2" id="email_addr2" value="" placeholder="이메일 도메인" data-format="email">
														</span>
														<span class="select w100" data-skin="form">
														<select title="이메일 도메인 선택" name="email_addr_opt" id="email_addr_opt" data-control="emailSelector">
															  <option value="" selected="selected">직접입력</option>
															  <option value="gmail.com" >구글</option>
															  <option value="naver.com" >네이버</option>
															  <option value="nate.com" >네이트</option>
															  <option value="hanmail.net" >다음</option>
															  <option value="yahoo.com" >야후</option>
														</select>
														</span>
														<p class="msg_info em hide" id="alert_email_addr">이메일 주소를 다시 확인해주세요.</p>
													</div>
													<p class="msg_desc">이메일 주소 입력 시 사용 가능 특수 문자 : - . _</p>
												</td>
											</tr>
										</tbody>
									</table>
								</div>
								<div class="table_header choice">
									<h3 class="h3_tit">선택정보</h3>
								</div>
								<div class="table_col">
									<input type='hidden' name='rcvr_coopco' value='|' />
									<table>
										<caption>회원선택정보 입력 표로 CJ ONE 마케팅 정보 수신 동의, 제휴 브랜드 마케팅 정보수신 동의, 추천인 입력 내용의 입력을 나타냅니다.</caption>
										<colgroup>
											<col class='title'>
											<col class='body'>
										</colgroup>
										<tbody>
											<tr id="cj_agree">
												<th scope="row">CJ ONE 마케팅<br>정보 수신 동의</th>
												
												<!--// 160217 수정 -->
												<td data-handler="checkAll">
													<strong class="msg_desc">포인트/이벤트/문화공연/상품 소식을 전해드립니다. (공지목적의 발송되는 메일은 제외)</strong>
													<div class="chk_group">
														<span class="checkbox" data-skin="form" data-checked-text="선택됨" data-unchecked-text="미선택됨">
															<a href="#">
																<span class="haze">전체 동의<span>미선택됨</span></span>
															</a>
															<input type="checkbox" id="mkt_rcv_all" enabled="enabled">
															<label class="label_check" for="mkt_rcv_all"><span class="ico"></span>전체 동의</label>
														</span>
														<span class="checkbox" data-skin="form" data-checked-text="선택됨" data-unchecked-text="미선택됨">
															<a href="#">
																<span class="haze">이메일<span>미선택됨</span></span>
															</a>
															<input type="checkbox" id="email_rcv_" name="chk">
															<label class="label_check" for="email_rcv_"><span class="ico"></span>이메일</label>
														</span>
														<span class="checkbox" data-skin="form" data-checked-text="선택됨" data-unchecked-text="미선택됨">
															<a href="#">
																<span class="haze">SMS<span>미선택됨</span></span>
															</a>
															<input type="checkbox"id="sms_rcv_"  name="chk">
															<label class="label_check" for="sms_rcv_"><span class="ico"></span>SMS</label>
														</span>
														<span class="checkbox" data-skin="form" data-checked-text="선택됨" data-unchecked-text="미선택됨">
															<a href="#">
																<span class="haze">휴대전화<span>미선택됨</span></span>
															</a>
															<input type="checkbox" id="tm_rcv_" name="chk">
															<label class="label_check" for="tm_rcv_"><span class="ico"></span>휴대전화</label>
														</span>
													</div>
												</td>
											</tr>
	
											<!--160217 add-->
											
											<!--160616 리스트 empty 여부 확인해서 전체 노출여부 판단 추가-->
											
											<!--//160217 add-->
											
											<tr class="input hide" id="recommender_tr">
												<th scope="row">
													<label for="rcm_id">추천인</label>
												</th>
												<td>
													<span class="input_txt w250"><input type="text" class="text" name="rcm_id" id="rcm_id" placeholder="추천인 ID" title="추천인 ID"></span>
													<input type="hidden" id="rcm_conf_seq" name="rcm_conf_seq" value="">
													<button type="button" class="btn" onclick="javascript:checkRcmId();">ID 확인</button>
													<p id="alert_rcm_id" class="msg_info em hide">추천인 ID가 확인되었습니다. 이름, ID (ex. 홍*동, abcd123)</p>
												</td>
											</tr>
											<!-- //160204 수정 --> 
										</tbody>
									</table>
								</div>
								<!-- cjone 카드 등록 -->
									<div id="crdHead" class="table_header choice">
										<h3 class="h3_tit">CJ ONE 카드등록</h3>
									</div>
									<div id="crdBody" class="table_col">
										<table>
											<caption>CJ ONE 카드등록을 위한 정보 입력 테이블입니다. 카드번호 입력,
												카드번호 재입력, 카드 비밀번호, 카드 비밀번호 확인 순으로 나열됩니다.</caption>
											<colgroup>
												<col class='title'>
												<col class='body'>
											</colgroup>
											<tbody>
												<tr class="input">
													<th scope="row" ><label
														for="card_num">
															카드번호 입력
													</label></th>
													<td>
														<div class="card_number">
															<span class="input_txt w80"> <input type="text"
																style="width: 38px" name="crdNo01" id="crdNo01"
																maxlength="4" value=""
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																style="ime-mode:inactive;" class="w80">
															</span> <span class="symbol">-</span> <span
																class="input_txt w80"> <input type="text"
																style="width: 38px" name="crdNo02" id="crdNo02"
																maxlength="4" value=""
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																style="ime-mode:inactive;" class="w80">
															</span> <span class="symbol">-</span> <span
																class="input_txt w80"> <input type="password"
																style="width: 38px" name="crdNo03" id="crdNo03"
																maxlength="4" value=""
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																style="ime-mode:inactive;" class="w80">
															</span> <span class="symbol">-</span> <span
																class="input_txt w80"> <input type="password"
																style="width: 38px" name="crdNo04" id="crdNo04"
																maxlength="4" value=""
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																style="ime-mode:inactive;" class="w80">
															</span>

														</div>
													</td>
												</tr>
												<tr class="input">
													<th scope="row" ><label
														for="card_num_again">
															카드번호 재입력
													</label></th>
													<td>
														<div class="card_number">
															<span class="input_txt w80"> <input type="text"
																style="width: 38px" name="re_crdNo05" id="re_crdNo05"
																maxlength="4" value=""
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																style="ime-mode:inactive;" class="w80" readonly>
															</span> <span class="symbol">-</span> <span
																class="input_txt w80"> <input type="text"
																style="width: 38px" name="re_crdNo06" id="re_crdNo06"
																maxlength="4" value=""
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																style="ime-mode:inactive;" class="w80" readonly>
															</span> <span class="symbol">-</span> <span
																class="input_txt w80"> <input type="text"
																style="width: 38px" name="re_crdNo07" id="re_crdNo07"
																maxlength="4" value=""
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																style="ime-mode:inactive;" class="w80">
															</span> <span class="symbol">-</span> <span
																class="input_txt w80"> <input type="text"
																style="width: 38px" name="re_crdNo08" id="re_crdNo08"
																maxlength="4" value=""
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																style="ime-mode:inactive;" class="w80">
															</span>

														</div>
														<p id="labelCardNo" class="noticePp"
															style="padding: 2px 0 1px 15px; margin-left: 5px;"></p>
													</td>
												</tr>
												<tr class="input">
													<th scope="row" ><label
														for="card_pwd"> 카드 비밀번호
													</label></th>
													<td>
														<div class="input_group">
															<span class="input_txt"><input type="password"
																name="crd_pwd" class="w80"
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																id="crd_pwd" value="" maxlength="4"></span>

														</div> <span id="labelPW1" class="msg_desc"
														style="padding: 2px 0 1px 15px; margin-left: 2px;">4자리의
															숫자만 입력해주세요.</span>
													</td>
												</tr>
												<tr class="input">
													<th scope="row" ><label
														for="card_pwd_again">
															카드 비밀번호 확인
													</label></th>
													<td>
														<div class="input_group">
															<span class="input_txt"><input type="password"
																name="re_crd_pwd" class="w80"
																onkeypress="if(event.keyCode<48 || event.keyCode>57) event.returnValue=false;"
																id="re_crd_pwd" value="" maxlength="4"></span>

														</div> <span id="labelPW2" class="msg_desc"
														style="padding: 2px 0 1px 15px; margin-left: 2px;">4자리의
															숫자만 입력해주세요.</span>
													</td>
												</tr>
											</tbody>
										</table>
									</div>

									<div class="btn_sec">
									<button type="button" class="btn" onclick="javascript:goCancel();">취소</button>
									<button type="button" class="btn btn_em" onclick="javascript:goSubmit();">등록</button>
								</div>
								<div class="box_gray box_btm">
									<dl class="box_info">
										<dt>이용안내</dt>
										<dd>
											<ul class="bul_list">
												<li class="dot_arr">CJ ONE 회원가입 후에도 각 제휴 브랜드 웹사이트에서 통합 아이디를 사용하여 로그인 하시려면, 각 브랜드 웹사이트의 이용약관에 대한 동의를 거친 후에 이용 가능합니다.</li>
												<li class="dot_arr">개인정보 수집 및 활용 동의 (선택)에 거부한 회원님은 마케팅 정보 수신을 받으실 수 없습니다.</li>
											</ul>
										</dd>
									</dl>
								</div>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
	<!--//contents-->

	<!-- footer -->
	<div id="footer">
    	



<script type="text/javascript">if(typeof _satellite !== "undefined" && _satellite) {_satellite.pageBottom();}</script>
<script type="text/javascript">
// footer 이벤트 선택 함수(1=이용약관,2=이전이용약관, 3=ARS 본인인증,4=법적고지, 5=이메일무단수집거부, 6=사이트맵, 그이외 개인정보취급)
function goFooterMenu(type){
	var pageUrl="";
	if("1"==type){
		pageUrl="http://www.cjone.com/cjmweb/terms.do?type="+type;
		location.href=pageUrl;
	}
	else if("2"==type){
		pageUrl="http://www.cjone.com/cjmweb/previous-terms.do?type="+type;
		location.href=pageUrl;
	}
	else if("3"==type){
		pageUrl="/cjmweb/layer/verify-account.do?type="+type;	
		cjone.openModal(pageUrl);
	}
	else if("4"==type){
		pageUrl="/cjmweb/layer/legal-notices.do?type="+type;	
		cjone.openModal(pageUrl);
	}
	else if("5"==type){
		pageUrl="/cjmweb/layer/email-security.do?type="+type;	
		cjone.openModal(pageUrl);
	}
	else if("6"==type){
		pageUrl="http://www.cjone.com/cjmweb/sitemap.do?type="+type;
		location.href=pageUrl;
	}
	// 등록일 format(yyyymmdd)
	else{
		if(""==type){
			pageUrl="http://www.cjone.com/cjmweb/privacy.do?privacyDate="+type+"&recent_yn=Y";

			location.href=pageUrl;
		}
		else{
			pageUrl="http://www.cjone.com/cjmweb/privacy.do?privacyDate="+type+"&recent_yn=N";
			location.href=pageUrl;
		}
	}
}
</script>

<div class="footer_wrap">			
	
	<div class="util_menu">
		<ul>
			<li><a href='javascript:goFooterMenu("1")' onclick="ga('send', 'event', 'Footer 영역', '이용약관', '이용약관');" data-track="Footer^이용약관">이용약관</a></li>
			<li><a href='javascript:goFooterMenu("")' onclick="ga('send', 'event', 'Footer 영역', '개인정보취급방침', '개인정보처리방침');" data-track="Footer^개인정보취급방침"><em>개인정보처리방침</em></a></li>
			<li><a href='javascript:goFooterMenu("3")' onclick="ga('send', 'event', 'Footer 영역', 'ARS 본인인증', 'ARS 본인인증');" data-track="Footer^ARS 본인인증">ARS 본인인증</a></li>
			<li><a href='javascript:goFooterMenu("4")' onclick="ga('send', 'event', 'Footer 영역', '법적고지', '법적고지');" data-track="Footer^법적고지">법적고지</a></li>
			<li><a href='javascript:goFooterMenu("5")' onclick="ga('send', 'event', 'Footer 영역', '이메일무단수집거부', '이메일무단수집거부');" data-track="Footer^이메일무단수집거부">이메일무단수집거부</a></li>
		</ul>
	</div>
	<div class="go_link">
			<a href="http://www.cjone.com/cjmweb/about-cjone.do" onclick="ga('send', 'event', 'Footer 영역', 'CJ ONE소개', 'CJ ONE소개');" class="cjone_info" data-track="Footer^CJ ONE소개"><span>CJ ONE소개</span></a>
			<a href="http://www.cjone.com/cjmweb/about-cjone.do#app_guide" onclick="ga('send', 'event', 'Footer 영역', 'APP 소개', 'APP 소개');" class="app_info" data-track="Footer^APP 소개"><span>APP 소개</span></a>
			<a href='javascript:goFooterMenu("6")' onclick="ga('send', 'event', 'Footer 영역', '사이트맵', '사이트맵');" class="ars_certify" data-track="Footer^사이트맵"><span>사이트맵</span></a>
			<a href="http://www.cjolivenetworks.co.kr/" target="_blank" onclick="ga('send', 'event', 'Footer 영역', '회사소개', '회사소개');" class="company_info" data-track="Footer^회사소개"><span>회사소개</span></a>
		<div class="familySite">
			<a href="#familySite" data-control="toggleGnb" data-open-text="열기" data-close-text="닫기" title="열기" class="btn_open">CJ그룹 계열사 바로가기</a>
			<ul id="familySite" class="site_list hide">
				<li><p class="title">CJ그룹</p>
					<ul class="list_2depth">
						<li><a target="_blank" href="http://www.cj.net/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ주식회사');" data-track="Footer^CJ그룹 계열사 바로가기|CJ주식회사">CJ주식회사</a></li>
					</ul>
				</li>
				<li><p class="title">엔터테인먼트 &amp; 미디어</p>
					<ul class="list_2depth">
						<li><a target="_blank" href="http://www.cjenm.com/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ E&amp;M');" data-track="Footer^CJ그룹 계열사 바로가기|CJ E&M">CJ E&amp;M</a></li>
						<li><a target="_blank" href="http://www.cgv.co.kr/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ CGV');" data-track="Footer^CJ그룹 계열사 바로가기|CJ CGV">CJ CGV</a></li>
						<li><a target="_blank" href="http://www.cjhellovision.com/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ헬로비전');" data-track="Footer^CJ그룹 계열사 바로가기|CJ헬로비전">CJ헬로비전</a></li>
						<li><a target="_blank" href="http://www.cjpowercast.com/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ파워캐스트');" data-track="Footer^CJ그룹 계열사 바로가기|CJ파워캐스트">CJ파워캐스트</a></li>
					</ul>
				</li>
				<li><p class="title">식품 &amp; 식품서비스</p>
					<ul class="list_2depth">
						<li><a target="_blank" href="http://www.cj.co.kr/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ제일제당');" data-track="Footer^CJ그룹 계열사 바로가기|CJ제일제당">CJ제일제당</a></li>
						<li><a target="_blank" href="http://www.cjfreshway.com/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ프레시웨이');" data-track="Footer^CJ그룹 계열사 바로가기|CJ프레시웨이">CJ프레시웨이</a></li>
						<li><a target="_blank" href="http://www.cjfoodville.co.kr/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ푸드빌');" data-track="Footer^CJ그룹 계열사 바로가기|CJ푸드빌">CJ푸드빌</a></li>
						<li><a target="_blank" href="http://www.md1.co.kr/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ엠디원');" data-track="Footer^CJ그룹 계열사 바로가기|CJ엠디원">CJ엠디원</a></li>
					</ul>
				</li>
				<li><p class="title">생명공학</p>
					<ul class="list_2depth">
						<li><a target="_blank" href="http://www.cj.co.kr/cj-kr/businesses/4/main" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ제일제당');" data-track="Footer^CJ그룹 계열사 바로가기|CJ제일제당">CJ제일제당</a></li>
						<li><a target="_blank" href="http://www.cjp.co.kr/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ헬스케어');" data-track="Footer^CJ그룹 계열사 바로가기|CJ헬스케어">CJ헬스케어</a></li>
					</ul>
				</li>
				<li><p class="title">신유통</p>
					<ul class="list_2depth">
						<li><a target="_blank" href="http://www.cjoshopping.com/index.asp" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ오쇼핑');" data-track="Footer^CJ그룹 계열사 바로가기|CJ오쇼핑">CJ오쇼핑</a></li>
						<li><a target="_blank" href="http://www.cjkoreaexpress.co.kr/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ대한통운');" data-track="Footer^CJ그룹 계열사 바로가기|CJ대한통운">CJ대한통운</a></li>
						<li><a target="_blank" href="http://www.cjtelenix.com/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ텔레닉스');" data-track="Footer^CJ그룹 계열사 바로가기|CJ텔레닉스">CJ텔레닉스</a></li>
						<li><a target="_blank" href="http://www.cjolivenetworks.co.kr/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ올리브네트웍스');" data-track="Footer^CJ그룹 계열사 바로가기|CJ올리브네트웍스">CJ올리브네트웍스</a></li>
						<li><a target="_blank" href="http://www.myctstudio.com/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', '㈜루비콘컴퍼니');" data-track="Footer^CJ그룹 계열사 바로가기|㈜루비콘컴퍼니">㈜루비콘컴퍼니</a></li>
					</ul>
				</li>
				<li><p class="title">인프라</p>
					<ul class="list_2depth">
						<li><a target="_blank" href="http://www.cjenc.co.kr/" onclick="ga('send', 'event', 'Footer 영역', 'CJ그룹 계열사 바로가기', 'CJ건설');" data-track="Footer^CJ그룹 계열사 바로가기|CJ건설">CJ건설</a></li>
					</ul>
				</li>
			</ul>
		</div>
	</div>
	
	<div class="site_info">
		<span class="ceo_info">대표이사 이경배</span>
		<address>주소 04320 서울시 용산구 한강대로 336 트윈시티 10~14층 (갈월동, 71-13)</address>
		<span class="customer_info">CJ ONE 고객센터 1577-8888</span>
		<span class="license_num">사업자 등록번호 104-81-36565</span>
		<span class="privacy_info">개인정보보호책임자 박재광</span>
	</div>
	<p class="copyright">
		<span class="img"><img src="../images/common/logo_cjolivenetworks_footer.png" alt="CJ 올리브넥트웍스"></span>
		Copyright (c)2016 CJ OLIVENETWORKS. All Rights Reserved
	</p>
	
	<div class="fixedTop" data-control="goTop" ><a href="#headerWrap" title="페이지 처음으로 이동"><span class="haze">TOP</span></a></div>
	
</div>

    </div>
	<!-- //footer -->
</div>

<!--script 영역-->
    <script src="../js/modules/cjoneCore.js"></script>
    <script src="../js/modules/commonUi.js"></script>
    <script src="../js/frontUi.js"></script>
    <script src="../js/modules/jquery.bxslider.js"></script>
<!-- 160203 수정 --> 
<script type="text/javascript" src="../js/crypto-js/crypto-js.js"></script>

<script type="text/javascript" src="../js/password_ck.js"></script>
<script type="text/javascript">
    $(document).ready(function(){	
		
		if ($('#upd_coopco_id').val() == ''){
			 $("#crdHead").hide();
			 $("#crdBody").hide();
			
		}else{
			 $("#crdHead").show();
			 $("#crdBody").show();
		}
		
	    setUserInfo();  // 오프라인 회원의 경우 값 셋팅
	    
	    $("#crdNo01").keyup(goNext);        // 카드번호이동       
        $("#crdNo02").keyup(goNext);        // 카드번호이동       
        $("#crdNo03").keyup(goNext);        // 카드번호이동
        $("#crdNo04").keyup(goNext);        // 카드번호이동       
        $("#re_crdNo07").keyup(goNext);     // 카드번호이동
        $("#crdNo04").blur(reInput);
        
        $("#crd_pwd").blur(checkPwd3);
        $("#re_crd_pwd").blur(checkPwd4);
        
	 	var coopco_cd = "";
	 	var brnd_cd = "";

	 	if(coopco_cd == "7000" && brnd_cd == "0000"){
	 		//추천인 이벤트 여부 확인
		 	setRcmEvt();
	 	}
	    
       	$('#rcm_id').change(function(){
       		if($('#rcm_id').val().length > 0){
       			rcmCheck = false;	
       		}else{
       			rcmCheck = true;
       		}
   	 		
   	 	});
	    
        function setRcmEvt(){
       	 
       	 $.ajax({
       			url : "/cjmweb/join/getRcmSeq.do"
       			,dataType:"json"
       			,async: false
       			,type: "POST"
       			, success:function(data)
       			{				
       				if(data.rcm_conf_seq != ""){
       					$('#recommender_tr').removeClass("hide");
       					$('#rcm_conf_seq').val(data.rcm_conf_seq);
       				}
       				
       			}
       			, error:function(data){
       				alert(data.msg);
       			}
       		});
        }
       	
	    $('#mbr_id').change(function() { 
	    	$('#id_validate').val('N');
	    	//showErrorMsg("mbr_id", "mbr_id_dupcheck");
	    	alertMsg("alert_mbr_id", "아이디 중복확인을 해주세요.");
	    }); // 아이디(ID)중복확인

//	    $("#email_addr_opt").val("").change();
	    $('#pwd').keyup(checkPassword);      // 강도  체크(비밀번호)
	
	    $('#email_addr_opt').change(setEmail);  // 이메일 직접 입력등 선택
	    $('#email_addr_opt').change(chkEmail);  // 이메일 직접입력
	    $('#email_addr2').blur(chkEmailDomain); // 직접입력 이메일 도메인 유효성 체크
	    
	    $('#crdNo01').keypress(onlyNumber);
        $('#crdNo02').keypress(onlyNumber);
        $('#crdNo03').keypress(onlyNumber);
        $('#crdNo04').keypress(onlyNumber);


	//$('#mkt_rcv_all').click(radioAll);              // 마케팅 수신동의

		$("#mkt_rcv_all").click(function(){
			if($("#mkt_rcv_all").prop("checked")) { //해당화면에 전체 checkbox들을 체크해준다
				$("input[name='chk']").prop("checked",true); // 전체선택 체크박스가 해제된 경우
			}
			else { //해당화면에 모든 checkbox들의 체크를해제시킨다.
				$("input[name='chk']").prop("checked",false);
			} 
		});
		
		$("input[name='chk']").click(function () {
			if($("input[name='chk']").filter(":checked")==1){
				if($(":checkbox:checked").length==$(":checkbox:gt(0)").length){						
					$("#mkt_rcv_all").get(0).checked="checked";						
				}
			}
			else{					
				$("#mkt_rcv_all").val([""]);
			}
		});


	$('#mkt_rcv_all2').click(radioAll2);              // 푸드빌 마케팅 수신동의
	    

	    
	    $("#birth_yy").change(function(){
	    	date_change();
	    });
	    $("#birth_mm").change(function(){
	    	date_change();
	    });
	    
	    var cj_marketing_agree = "";
	    if(cj_marketing_agree != "Y"){
    		$('#cj_agree input').attr("disabled", true).trigger('change');
	    }
	    
	    var coop_marketing_agree = "";
	    if(coop_marketing_agree != "Y"){
	    	$('#coop_agree input').attr("disabled", true).trigger('change');
	    } 	    

   });
      
    
    // 오프라인 회원정보
    function setUserInfo() {
        // 기본정보 hidden
        if('' != '') {$('#legl_rep_nm').val('')};
        if('' != '') {$('#legl_rep_ssn1').val('')};
        if('' != '') {$('#legl_rep_ssn2').val('')};
        if('' != '') {$('#legl_rep_mob_no1').val('')};
        if('' != '') {$('#legl_rep_mob_no2').val('')};
        if('' != '') {$('#legl_rep_mob_no3').val('')};
        if('' != '') {$('#legl_rep_email_addr1').val('')};
        if('' != '') {$('#legl_rep_email_addr2').val('')};
        if('' != '') {$('#legl_rep_rel_cnts').val('')};
        if('' != '') {$('#legl_rep_agr_dy').val('')};
        if('' != '') {$('#legl_rep_agr_yn').val('')};

        if('' != '') {$('#email_addr1').val('')};
        if('' != '') {$('#email_addr_opt').val('')};
        if('' != '') {$('#email_addr2').val('')};

        // 이메일 직접입력일때
        if($('#email_addr2').val() != '' && ($('#email_addr_opt').val() != $('#email_addr2').val())) {
            $('#email_addr_opt').val('0');
        }

        // 휴대폰
        if('' != '') {$('#mob_no_1').val('')};
        if('' != '') {$('#mob_no_2').val('')};
        if('' != '') {$('#mob_no_3').val('')};

        // 생일
        if('' != '') {
            $('#birth_yy').val('');
            $('#birth_mm').val('');
            $('#birth_dd').val('');
        }

    }
    
    // 이메일 셋팅
    function setEmail(){
        // 직접입력일때
        if($('#email_addr_opt').val() == '0') {
            $('#email_addr2').attr('readonly', false);
        } else if ($('#email_addr_opt').val() != '') {
            $('#email_addr2').attr('readonly', true);
            $('#email_addr2').val($('#email_addr_opt').val());
        } else {
            $('#email_addr2').attr('readonly', true);
        }
    }
    
    // 이메일 직접입력일때 추가필드 초기화
    function chkEmail(){
        // 직접입력일때
        if($('#email_addr_opt').val() == '0') {
            $('#email_addr2').val('');
        }
    }
    
    // cabs lock 체크
    var msgStr  = "";
    function cabsCheck() {
        var id = this.id;
        if(checkCapsLock()) {
            msgStr = "Cabs lock가 켜져 있습니다.";
        } else {
            $("#msg_"+id).hide();
            msgStr  = "";
        }
    }
    
    // 패스워드 강도 체크  2012.1.5
    var pwStrength = false;
    function checkPassword() {
        pwStrength = false;
        var special_chars1 = "~!@#$%&*";

        var pw = new Password(document.getElementById('pwd').value, special_chars1);
        var verdict = pw.getStrength();

        var hint = msgStr;
        if (pw.lcase_count  == 0)   hint += "";
        if (pw.ucase_count  == 0)   hint += "";
        if (pw.num_count    == 0)   hint += "";
        if (pw.schar_count  == 0)   hint += "";
        if (pw.run_score    <= 1)   hint += "";

        alertMsg("alert_pwd_strength", "<em>"+verdict+" "+hint+"</em>");

        if(pw.strength >= 38){ pwStrength=true;}
    }
    
	function checkPasswordRule() {
        if($('#pwd').val() == ""){
            alert("msg_pwd", "비밀번호를 입력해 주세요.");
            alert("비밀번호를 입력해 주세요.");
            return false;
        } else {
        	
        	var parameter = {};
        	parameter.p = BASE64.encode($('#pwd').val());
        	if($('#mbr_id').val()!= undefined){
    			parameter.m = BASE64.encode($('#mbr_id').val());  
    		}
        	
			$.ajax({
		        url     : '/cjmweb/common/check-pwd-rule.do',
		        dataType  : 'json',
		        data	: 'mbr_id='+parameter.m+'&pwd=' + parameter.p,
		        async   : false,
		        type    : 'POST',
		        error   : function(err) { alert(err); },
		        success   : function(response, statusText) {
		        	if (response.resultCode != "0000") {
		        		alertMsg("alert_pwd_strength","<em>"+response.result_msg+"</em>");
			        	return false;
		        	} else {
		        		return true;
		        	}
		        }
			});
		    
        }
	}
	
    function checkPwd2(){
	        if( $("#pwd").val() != $("#pwd_check").val() ){
	        	alertMsg('msg_pwd_check',"입력하신 비밀번호가 일치하지 않습니다. 다시 확인해 주세요.")
        } else{
            $("#msg_pwd_check").hide();
        }
    }
    
	function chkEmailDomain() {
        if($('#email_addr_opt').val() == '0' && $('#email_addr2').val()) {
			$.ajax({
		        url     : '/cjmweb/common/check-email-available.do',
		        dataType  : 'json',
		        data	: 'domain=' + $('#email_addr2').val(),
		        async   : false,
		        type    : 'POST',
		        error   : function(err) { alert(err); },
		        success   : function(response, statusText) {
		        	if (response.result_code != '00000') {
			        	alertMsg('alert_email_addr', "메일 도메인주소를 정확하게 입력하셨나요? 다시 한 번 확인해 주세요.");
		        	} else $('#alert_email_addr').hide();
		        }
			});
        }
	}
	
    function showCupoon() {
        alert("생일쿠폰 보기!!");
    }
    
    function showMemory() {
        alert("기념일서비스보기 보기!!");
    }

    
    // 취소
    function goCancel() {
        if(!confirm('회원가입을 취소하시겠습니까?')) return;
       
        if (''==''){
        	 location.href='http://www.cjone.com/cjmweb/main.do';
	    }else{
	    	 location.href='https://www.cjone.com/cjmweb/join.do?coopco_cd=&amp;brnd_cd=&amp;mcht_no=&amp;upd_coopco_id=';
	    }
    }
    
    // 회원가입 완료
    function goSubmit() {
		
        if( beforeSubmit() )
        {
        	var actionUrl = $('#form2').attr('action');
        	
        	if(actionUrl.indexOf('/join.do') > -1){
        		location.href = actionUrl;
        	}else{
        		$('#form2').submit();
        	}
        }
    }
    
    function beforeSubmit() {
        // 이메일 셋팅
        if($('#email_addr_opt').val() != "0"){
            $('#email_addr2').val($('#email_addr_opt').val());
        }

        if(!checkInput()) return false;
	
        if(!confirm('소중한 고객님의 정보는 CJ ONE 제휴 브랜드와 함께 변경 적용됩니다.\n이대로 입력하시겠습니까?')) {
            return false;
        } else {	

        	ajaxRegister();
            return true;
        }
    }
    
    //매장가입pc
    function submitOk() {
        // 이메일 셋팅
        if($('#email_addr_opt').val() != "0"){
            $('#email_addr2').val($('#email_addr_opt').val());
        }

        ajaxRegister();
        
        var actionUrl = $('#form2').attr('action');
    	
    	if(actionUrl.indexOf('/join.do') > -1){
    		location.href = actionUrl;
    	}else{
    		$('#form2').submit();
    	}   
    }
    
    function ajaxRegister(){
    	
		$("#pwd").val(SHA256($("#pwd").val()));
		$("#pwd_check").val('');
		var params = $("#form1").serialize();
		
		$.ajax({
			url : '/cjmweb/join/member-register.do'
			,dataType:'json'
			,async: false
			,type: 'POST'
			, data : params,
			success:function(data)
			{
				$("#pwd").val('');
				
				if(data.reqBox.str_msg !='' && data.reqBox.str_msg != null &&  data.reqBox.str_msg != 'undefined'){
					var str_msg ="" + data.reqBox.str_msg;
 					str_msg = str_msg.replace(/\\n/g, '\n');
 					alert(str_msg);
				}
				
	 			if(data.reqBox.coopco_cd != "undefined" && data.reqBox.coopco_cd != null && data.reqBox.coopco_cd != '' )$("#form2 #coopco_cd").val(data.reqBox.coopco_cd);		    					
	 			if(data.reqBox.brnd_cd != "undefined" && data.reqBox.brnd_cd != null && data.reqBox.brnd_cd != '' )$("#form2 #brnd_cd").val(data.reqBox.brnd_cd);	
	 			if(data.reqBox.mcht_no != "undefined" && data.reqBox.mcht_no != null && data.reqBox.mcht_no != '' )$("#form2 #mcht_no").val(data.reqBox.mcht_no);
	 			if(data.reqBox.upd_coopco_id != "undefined" && data.reqBox.upd_coopco_id != null && data.reqBox.upd_coopco_id != '' )$("#form2 #upd_coopco_id").val(data.reqBox.upd_coopco_id);
	 			if(data.reqBox.coop_return_url != "undefined" && data.reqBox.coop_return_url != null && data.reqBox.coop_return_url != '' )$("#form2 #coop_return_url").val(data.reqBox.coop_return_url);	
	 			if(data.reqBox.return_func != "undefined" && data.reqBox.return_func != null && data.reqBox.return_func != '' )$("#form2 #return_func").val(data.reqBox.return_func);	
	 			if(data.reqBox.mbr_id != "undefined" && data.reqBox.mbr_id != null && data.reqBox.mbr_id != '' )$("#form2 #mbr_id").val(data.reqBox.mbr_id);	
	 			if(data.reqBox.sub_type != "undefined" && data.reqBox.sub_type != null && data.reqBox.sub_type != '' )$("#form2 #sub_type").val(data.reqBox.sub_type);	
	 			if(data.reqBox.ipin_use_yn != "undefined" && data.reqBox.ipin_use_yn != null && data.reqBox.ipin_use_yn != '' )$("#form2 #ipin_use_yn").val(data.reqBox.ipin_use_yn);	
	 			if(data.reqBox.hg_nm != "undefined" && data.reqBox.hg_nm != null && data.reqBox.hg_nm != '' )$("#form2 #hg_nm").val(data.reqBox.hg_nm);	
	 			if(data.reqBox.vno != "undefined" && data.reqBox.vno != null && data.reqBox.vno != '' )$("#form2 #vno").val(data.reqBox.vno);	
	 			if(data.reqBox.ssn1 != "undefined" && data.reqBox.ssn1 != null && data.reqBox.ssn1 != '' )$("#form2 #ssn1").val(data.reqBox.ssn1);	
	 			if(data.reqBox.ssn2 != "undefined" && data.reqBox.ssn2 != null && data.reqBox.ssn2 != '' )$("#form2 #ssn2").val(data.reqBox.ssn2);	
	 			if(data.reqBox.ipin_ci != "undefined" && data.reqBox.ipin_ci != null && data.reqBox.ipin_ci != '' )$("#form2 #ipin_ci").val(data.reqBox.ipin_ci);	
	 			if(data.reqBox.ipin_di != "undefined" && data.reqBox.ipin_di != null && data.reqBox.ipin_di != '' )$("#form2 #ipin_di").val(data.reqBox.ipin_di);	
	 			if(data.reqBox.gender != "undefined" && data.reqBox.gender != null && data.reqBox.gender != '' )$("#form2 #gender").val(data.reqBox.gender);	
	 			if(data.reqBox.frgnr_yn != "undefined" && data.reqBox.frgnr_yn != null && data.reqBox.frgnr_yn != '' )$("#form2 #frgnr_yn").val(data.reqBox.frgnr_yn);	
	 			if(data.reqBox.under_14 != "undefined" && data.reqBox.under_14 != null && data.reqBox.under_14 != '' )$("#form2 #under_14").val(data.reqBox.under_14);	
	 			if(data.reqBox.id_validate != "undefined" && data.reqBox.id_validate != null && data.reqBox.id_validate != '' )$("#form2 #id_validate").val(data.reqBox.id_validate);	
	 			if(data.reqBox.agr_dy != "undefined" && data.reqBox.agr_dy != null && data.reqBox.agr_dy != '' )$("#form2 #agr_dy").val(data.reqBox.agr_dy);	
	 			if(data.reqBox.agr_tm != "undefined" && data.reqBox.agr_tm != null && data.reqBox.agr_tm != '' )$("#form2 #agr_tm").val(data.reqBox.agr_tm);	
	 			if(data.reqBox.agr_yn != "undefined" && data.reqBox.agr_yn != null && data.reqBox.agr_yn != '' )$("#form2 #agr_yn").val(data.reqBox.agr_yn);	
	 			if(data.reqBox.agr_sub_yn99 != "undefined" && data.reqBox.agr_sub_yn99 != null && data.reqBox.agr_sub_yn99 != '' )$("#form2 #agr_sub_yn99").val(data.reqBox.agr_sub_yn99);	
	 			if(data.reqBox.mbr_no != "undefined" && data.reqBox.mbr_no != null && data.reqBox.mbr_no != '' )$("#form2 #mbr_no").val(data.reqBox.mbr_no);	
	 			if(data.reqBox.mbr_typ_cd != "undefined" && data.reqBox.mbr_typ_cd != null && data.reqBox.mbr_typ_cd != '' )$("#form2 #mbr_typ_cd").val(data.reqBox.mbr_typ_cd);	
	 			if(data.reqBox.legl_rep_nm != "undefined" && data.reqBox.legl_rep_nm != null && data.reqBox.legl_rep_nm != '' )$("#form2 #legl_rep_nm").val(data.reqBox.legl_rep_nm);	
	 			if(data.reqBox.legl_birth_day != "undefined" && data.reqBox.legl_birth_day != null && data.reqBox.legl_birth_day != '' )$("#form2 #legl_birth_day").val(data.reqBox.legl_birth_day);	
	 			if(data.reqBox.legl_ipin_ci != "undefined" && data.reqBox.legl_ipin_ci != null && data.reqBox.legl_ipin_ci != '' )$("#form2 #legl_ipin_ci").val(data.reqBox.legl_ipin_ci);	
	 			if(data.reqBox.legl_cert != "undefined" && data.reqBox.legl_cert != null && data.reqBox.legl_cert != '' )$("#form2 #legl_cert").val(data.reqBox.legl_cert);	
	 			if(data.reqBox.legl_typ_cd != "undefined" && data.reqBox.legl_typ_cd != null && data.reqBox.legl_typ_cd != '' )$("#form2 #legl_typ_cd").val(data.reqBox.legl_typ_cd);	
	 			if(data.reqBox.legl_rep_agr_yn != "undefined" && data.reqBox.legl_rep_agr_yn != null && data.reqBox.legl_rep_agr_yn != '' )$("#form2 #legl_rep_agr_yn").val(data.reqBox.legl_rep_agr_yn);	
	 			if(data.reqBox.join_coopco_list != "undefined" && data.reqBox.join_coopco_list != null && data.reqBox.join_coopco_list != '' )$("#form2 #join_coopco_list").val(data.reqBox.join_coopco_list);	
	 			if(data.reqBox.rejoin_yn != "undefined" && data.reqBox.rejoin_yn != null && data.reqBox.rejoin_yn != '' )$("#form2 #rejoin_yn").val(data.reqBox.rejoin_yn);	
	 			if(data.reqBox.action_url != "undefined" && data.reqBox.action_url != null && data.reqBox.action_url != '' )$("#form2 #action_url").val(data.reqBox.action_url);	
	 			if(data.reqBox.evt_typ != "undefined" && data.reqBox.evt_typ != null && data.reqBox.evt_typ != '' )$("#form2 #evt_typ").val(data.reqBox.evt_typ);	
	 			if(data.reqBox.strEvtCode != "undefined" && data.reqBox.strEvtCode != null && data.reqBox.strEvtCode != '' )$("#form2 #strEvtCode").val(data.reqBox.strEvtCode);	
	 			if(data.reqBox.evt_coopco_cd != "undefined" && data.reqBox.evt_coopco_cd != null && data.reqBox.evt_coopco_cd != '' )$("#form2 #evt_coopco_cd").val(data.reqBox.evt_coopco_cd);	
	 			if(data.reqBox.evt_brnd_cd != "undefined" && data.reqBox.evt_brnd_cd != null && data.reqBox.evt_brnd_cd != '' )$("#form2 #evt_brnd_cd").val(data.reqBox.evt_brnd_cd);	
	 			if(data.reqBox.evt_mcht_no != "undefined" && data.reqBox.evt_mcht_no != null && data.reqBox.evt_mcht_no != '' )$("#form2 #evt_mcht_no").val(data.reqBox.evt_mcht_no);	
	 			if(data.reqBox.evt_mbr_no != "undefined" && data.reqBox.evt_mbr_no != null && data.reqBox.evt_mbr_no != '' )$("#form2 #evt_mbr_no").val(data.reqBox.evt_mbr_no);	
	 			if(data.reqBox.card_register_error != "undefined" && data.reqBox.card_register_error != null && data.reqBox.card_register_error != '' )$("#form2 #card_register_error").val(data.reqBox.card_register_error);
	 			
				var html = ""
				
				if(data.reqBox.svcuse_agr_typ != "undefined" && data.reqBox.svcuse_agr_typ != null && data.reqBox.svcuse_agr_typ != '' ){
					var obj01 = data.reqBox.svcuse_agr_typ;
					$.each(obj01, function(index,item){
						html += "<input type='hidden' name='svcuse_agr_typ_cd' id='svcuse_agr_typ_cd' value='"+item+"' />";
					});
				}
				
				if(data.reqBox.agr_onln != "undefined" && data.reqBox.agr_onln != null && data.reqBox.agr_onln != '' ){
					var obj02 = data.reqBox.agr_onln;
					$.each(obj02, function(index,item){
						html += "<input type='hidden' name='agr_typ_onln' id='agr_typ_onln' value='"+item+"' />";
					});
				}
				
				if(data.reqBox.etc_map != "undefined" && data.reqBox.etc_map != null && data.reqBox.etc_map != '' ){				
					var obj03 = data.etc_map;
					$.each(obj03, function(index,item){
						html += "<input type='hidden' name='etc"+index+"' id='etc"+index+"' value='"+item+"' />";
					});
				}		
				$("#form2").append(html);	
				
				$('#form2').attr('action', '/cjmweb'+data.reqBox.action_url);
			}
			, error:function(data){
				var str_msg ="test" + data.reqBox.str_msg;
					str_msg = str_msg.replace(/\\n/g, '\n');
					alert(str_msg);			
			}
		});     	
    }
    
	function alertMsg(objId, ErrMsg){
		$("#"+objId).html(ErrMsg);
		$("#"+objId).show();
	}
    
	function showErrorMsg(occur_loc, occur_msg){
		$("#msg_pwd").addClass("hide");
		$("#msg_pwd_chedk").addClass("hide");
		$("#alert_mob_no").addClass("hide");
		$("#alert_email_addr").addClass("hide");
		$("#alert_rcm_id").addClass("hide");
		
		$("#mbr_id").removeClass("error");
		$("#pwd").removeClass("error");
		$("#pwd_chedk").removeClass("error");
		$("#mob_no_1").removeClass("error");
		$("#email_addr1").removeClass("error");
		$("#rcm_id").removeClass("error");
		
		$("#" + occur_loc).addClass("error");
		if(occur_msg.length < 1){
			$("#msg_" + occur_loc).removeClass("hide");
		} else {
			$("#msg_" + occur_msg)
			$("#msg_" + occur_msg).removeClass("hide");
		}
	}
    
	var flag = "invalid";
    function checkPasswordValid() {
    	flag ="invalid";
    	$('#pwd').val($('#pwd_check').val());
    	
    	var parameter = {};
    	function transHEX(a){
    		var result = "";
    		for(var i = 0; i < a.length; ++i){
    			var code = a.charCodeAt(i).toString(16);
    			result += ''+code;
    		}
    		return result;
    	}
    	/*
		var ki = {
			k : CryptoJS.enc.Hex.parse(transHEX('qawsedrftgyhujik')),
			//i : CryptoJS.enc.Hex.parse(transHEX('azsxdcfvgbhnjmk,'))
			i : CryptoJS.enc.Hex.parse(transHEX('azsxdcfvgbhnjmkm'))
		};
		parameter.p = CryptoJS.AES.encrypt($('#pwd').val(), ki.k, {iv: ki.i});
		parameter.m = CryptoJS.AES.encrypt($('#mbr_id').val(), ki.k, {iv: ki.i});
    	*/
    	parameter.p = BASE64.encode($('#pwd').val());
    	
    	if($('#mbr_id').val()!= undefined){
			parameter.m = BASE64.encode($('#mbr_id').val());  
		}
    	
    	$.ajax({
	        url     : '/cjmweb/common/check-pwd-rule.do',
	        dataType  : 'json',
	        data :  'mbr_id='+parameter.m+'&pwd=' + parameter.p,
	        async   : false,
	        type    : 'POST',
	        error   : function(err) {
	        	alertMsg("msg_pwd","<em>"+err+"</em>");
	        },
	        success   : function(response, statusText) {
	        	if (response.result_code != "0000") {
	        		alertMsg("msg_pwd","<em>"+response.result_msg+"</em>");
	        		alert(response.result_msg);
	        		$('#pwd').focus();
	        		flag = "invalid";
	        	} else {
	        		flag = "valid";
	        	}
	        }
		}); 
    }		
    
    // 회원가입 체크
    function checkInput() {
        if( $('#mbr_id').val().length < 6 ) {
        	alertMsg("alert_mbr_id", "6~12자리의 영문 소문자 또는 영문 소문자+숫자 아이디를 입력해 주세요.");
        	alert("6~12자리의 영문 소문자 또는 영문 소문자+숫자 아이디를 입력해 주세요.");
            $('#mbr_id').focus();
            return false;
        }
        
        if($('#id_validate').val() != "Y"){
        	alertMsg("alert_mbr_id", "아이디 중복확인을 해주세요.");
        	alert("아이디 중복확인을 해주세요.");
            $('#mbr_id').focus();
            return false;
        }

        if($('#pwd').val().length < 6){
        	showErrorMsg("pwd", "");
        	alert("비밀번호를 입력해 주세요.");
            $('#pwd').focus();
            return false;
        }
		$("#msg_pwd").hide();
		
        if($('#pwd_check').val() == ""){
        	showErrorMsg("pwd_check", "");
        	alert("입력하신 비밀번호가 일치하지 않습니다. 다시 확인해 주세요.");
            $('#pwd_check').focus();
            return false;
        }

        if( $("#pwd").val() != $("#pwd_check").val() ){
        	alertMsg('msg_pwd_check',"입력하신 비밀번호가 일치하지 않습니다. 다시 확인해 주세요.")
        	alert("입력하신 비밀번호가 일치하지 않습니다. 다시 확인해 주세요.");
            $('#pwd_check').focus();
            return false;
	    } else{
	        $("#msg_pwd_check").hide();
	    }
        
        checkPasswordValid();
		if ( flag == "invalid") {
			return false;
		} 	
		

		if (!$('#birth_yy').val()) {
            alert("생년월일을 선택하세요.");
            $('#birth_yy').focus();
            return false;
		} else if (!$('#birth_mm').val()) {
            alert("생년월일을 선택하세요.");
            $('#birth_mm').focus();
            return false;
		} else if (!$('#birth_dd').val()) {
            alert("생년월일을 선택하세요.");
            $('#birth_dd').focus();
            return false;
		}
        
        if(!setFocusMobileTel("1")||!setFocusMobileTel("2")||!setFocusMobileTel("3")) return false;
        $('#alert_mob_no').hide();
        
        if($('#email_addr1').val() == ""){
            alertMsg("alert_email_addr", "이메일 주소를 다시 확인해주세요.");
            alert("이메일 주소를 다시 확인해주세요.");
            $('#email_addr1').focus();
            return false;
        }

        if($('#email_addr_opt').val() == ""){
            alertMsg("alert_email_addr", "이메일 도메인을 선택 하세요.");
            alert("이메일 도메인을 선택 하세요.");
            $('#email_addr_opt').focus();
            return false;
        }

        if($('#email_addr_opt').val() == "0" && $('#email_addr2').val() == ""){
            alertMsg('alert_email_addr', "이메일 도메인 직접입력시 이메일 도메인을 입력하셔야 합니다.");
            alert("이메일 도메인 직접입력시 이메일 도메인을 입력하셔야 합니다.");
            $('#email_addr2').focus();
            return false;
        }

        // 이메일 유효성 체크
        if(!CheckMailFormat($('#email_addr1').val()+'@'+$('#email_addr2').val())) {
            alertMsg('alert_email_addr', "유효하지 않는 이메일 주소 입니다.");
            alert("유효하지 않는 이메일 주소 입니다.");
            $('#email_addr2').focus();
            return false;
        }
        $('#alert_email_addr').hide();
        
        if($('#upd_coopco_id').val() != ""){
      
			//카드번호 체크
	        if($('#crdNo01').val() == "" && 
	                $('#crdNo02').val() == "" && 
	                $('#crdNo03').val() == "" && 
	                $('#crdNo04').val() == "" &&
	                $('#crd_pwd').val() == "" && 
	                $('#re_crd_pwd').val() == "") {
	         /*   if (checkValidate()){
	            	if($('#upd_coopco_id').val()!=""){
	           		 $('#card_chk').val("Y");
	           		} 
	            	 return false;
	            }else{
	            	if($('#upd_coopco_id').val()!=""){
	           		 $('#card_chk').val("N");
	           	} 	           	
	            	 return true;
	            }*/
	        	 checkValidate();
	             return false;
	        } else {
	            if($('#crdNo01').val() == "") {
	                alertMsg("labelCardNo", "카드번호를 입력하세요.");
	                $('#crdNo01').focus();
	                return false;
	            }
	            
	            if($('#crdNo02').val() == "") {
	                alertMsg("labelCardNo", "카드번호를 입력하세요.");    
	                $('#crdNo02').focus();
	                return false;
	            }
	            
	            if($('#crdNo03').val() == "") {
	                alertMsg("labelCardNo", "카드번호를 입력하세요.");    
	                $('#crdNo03').focus();
	                return false;
	            }
	            
	            if($('#crdNo04').val() == "") {
	                alertMsg("labelCardNo", "카드번호를 입력하세요.");
	                $('#crdNo04').focus();
	                return false;
	            }
	
	            if($('#re_crdNo05').val() == "") {
	                alertMsg("labelCardNo", "카드번호를 입력하세요.");
	                $('#re_crdNo05').focus();
	                return false;
	            }
	
	            if($('#re_crdNo06').val() == "") {
	                alertMsg("labelCardNo", "카드번호를 입력하세요.");
	                $('#re_crdNo06').focus();
	                return false;
	            }
	
	            if($('#re_crdNo07').val() == "") {
	                alertMsg("labelCardNo", "카드번호를 입력하세요.");
	                $('#re_crdNo07').focus();
	                return false;
	            }
	
	            if($('#re_crdNo08').val() == "") {
	                alertMsg("labelCardNo", "카드번호를 입력하세요.");
	                $('#re_crdNo08').focus();
	                return false;
	            }
	            
	            if($('#crdNo01').val().substring(0,2) != "77") {
	                alertMsg("labelCardNo", "유효하지 않은 카드 번호입니다. 확인 후 다시 입력해주세요.");       
	                $('#crdNo01').focus();
	                return false;
	            }
	
	            if($('#crdNo01').val().length + $('#crdNo02').val().length +
	               $('#crdNo03').val().length + $('#crdNo04').val().length != 16) {
	                alertMsg("labelCardNo", "카드번호 16자리를 정확하게 입력해주세요.");             
	                return false;
	            }
	            
	            if($("#crdNo01").val() != $("#re_crdNo05").val()) {
	                alertMsg("labelCardNo", "카드번호가 서로 다릅니다.");
	                $("#re_crdNo05").focus();
	                return;
	            }
	            
	            if($("#crdNo02").val() != $("#re_crdNo06").val()) {
	                alertMsg("labelCardNo", "카드번호가 서로 다릅니다.");
	                $("#re_crdNo06").focus();
	                return;
	            }
	            
	            if($("#crdNo03").val() != $("#re_crdNo07").val()) {
	                alertMsg("labelCardNo", "카드번호가 서로 다릅니다.");
	                $("#re_crdNo07").focus();
	                return;
	            }
	            
	            if($("#crdNo04").val() != $("#re_crdNo08").val()) {
	                alertMsg("labelCardNo", "카드번호가 서로 다릅니다.");
	                $("#re_crdNo08").focus();
	                return;
	            }
	
	            if($('#crd_pwd').val().length != 4) {
	                alertMsg("labelPW1", "4자리의 숫자만 입력해주세요.");
	                $('#crd_pwd').focus();
	                return false;
	            } 
	            else{
	                $("#labelPW1").hide();
	            }
	            
	            if($('#re_crd_pwd').val().length != 4) {
	                alertMsg("labelPW2", "4자리의 숫자만 입력해주세요.");
	                $('#re_crd_pwd').focus();
	                return false;
	            }
	            
	            if($('#crd_pwd').val() != $('#re_crd_pwd').val()) {
	                alertMsg("labelPW2", "카드 비밀번호가 서로 다릅니다.");
	                $('#re_crd_pwd').focus();
	                return false;
	            }
	            else{
	                $("#labelPW2").hide();
	            }

	           $('#card_chk').val("Y");

	        }
        }
		return true;
    }
    
    // 카드번호 재입력 창으로 커서 이동시
    function reInput() {
        if($("#crdNo03").val().length == 4 && $("#crdNo04").val().length == 4) {
            var crdNo05 = $("#crdNo01").val();
            var crdNo06 = $("#crdNo02").val();
            $("#re_crdNo05").val(crdNo05);
            $("#re_crdNo06").val(crdNo06);
        } else return false;
    }
    
 // 다음창으로 이동
    function goNext(){
        if($('#'+this.id).val().length == 4){
            switch(this.id) {
                case "crdNo01": //카드번호1
                    if($("#crdNo01").val().length == 4){
                        $("#crdNo02").focus();
                    }
                    break;
                case "crdNo02": //카드번호2
                    if($("#crdNo02").val().length == 4){
                        $("#crdNo03").focus();
                    }
                    break;
                case "crdNo03": //카드번호3
                    if($("#crdNo03").val().length == 4){
                        $("#crdNo04").focus();
                    }
                case "crdNo04": //카드번호4
                    if($("#crdNo04").val().length == 4){
                        $("#re_crdNo07").focus();
                    }
                case "re_crdNo07": //카드번호7
                    if($("#re_crdNo07").val().length == 4){
                        $("#re_crdNo08").focus();
                    }
                    break;
            }
        }
    }
 
    // 카드유효성 체크 팝업창
    function checkValidate(){	
    	cjone.openModal('/cjmweb/join/regCardPop.do');
    }

    function checkPwd3(){
        // 비밀번호 유효성 체크 
        if($('#crd_pwd').val() == ""){
            alertMsg("labelPW1", "비밀번호를 입력해 주세요.");
        }
        else{
            $("#labelPW1").hide();
        }
    }
    function checkPwd4(){
        if($('#re_crd_pwd').val() == ""){
            alertMsg("labelPW2", "비밀번호를 입력해 주세요.");
        }
        else if( $('#crd_pwd').val() != $('#re_crd_pwd').val() ){
            alertMsg("labelPW2", "입력하신 비밀번호가 일치하지 않습니다. 다시 확인해 주세요.");
        }
        else{
            $("#labelPW2").hide();
        }
    }

    function checkCardNo(){
        alertMsg("labelCardNo", "카드번호를 입력하세요.");
    }
    /* 2012.02.01 휴대전화번호가 양식에 틀리면 focus를 준다. */
    function setFocusMobileTel(id) {
        /* 휴대전화 검사 */
        var objMp   = $('#mob_no_'+id);
        var chkVal  = "";

        if(objMp.val() == "")   chkVal  = "*";

        if(objMp.val() != "" && ((id == "2" && objMp.val().length < 3) || (id == "3" && objMp.val().length < 4)))   chkVal  = "*";

        if(chkVal != "") {
            alertMsg("alert_mob_no", "휴대 전화번호를  정확히 입력해 주세요.");
            alert("휴대 전화번호를  정확히 입력해 주세요.");
            objMp.focus();

            return false;
        }
        else return true;

    }
    
    function isValid_mbrId(str) {
        var patten = new Array();
        var msg = new Array();
        var p;
        var ret_msg = new Array();
        patten["not_eng_num"] =/^[a-z0-9]+$/g;  //a-z와 0-9 이외의 문자가 있는지 확인    
        msg["not_eng_num"] = "영문 소문자/숫자만 사용가능합니다.";
        patten["len"] = /^\w{6,12}$/;	// 문자열 길이
        msg["len"] = "6~12자리로 사용가능합니다.";
        patten["only_num"] = /[a-zA-Z]/;// 숫자만
        msg["only_num"] = "영문 소문자/숫자의 혼용으로 사용가능합니다(숫자만으로는 사용불가).";
    	 var retVal = checkSpace( str );
    	 if( retVal ) {
    		 alertMsg('msg_id', "아이디는 빈 공간 없이 연속된 영문 소문자와 숫자만 사용할 수 있습니다.");
    		 alert("아이디는 빈 공간 없이 연속된 영문 소문자와 숫자만 사용할 수 있습니다.");
    		 return false;
    	 }
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
    		alertMsg("alert_mbr_id", "6~12자리의 영문 소문자 또는 영문 소문자+숫자 아이디를 입력해 주세요.");
    		alert("6~12자리의 영문 소문자 또는 영문 소문자+숫자 아이디를 입력해 주세요.");
    		return false;
    	}
    	else return true;
    }
    
    // 아이디 체크 팝업창
    // 탈퇴회원 재가입은 안띄움
    function idCheck()  {
        if ( $('#id_validate').val() != 'Y' ) {
        	$('#mbr_id').val($('#mbr_id').val().replace(' ',''));
        	if ( isValid_mbrId($('#mbr_id').val()) ) {
                if ( $('#mbr_id').val().length > 5 ) {
    				$.ajax({
    			        url     : '/cjmweb/join/check-iddup.do',
    			        dataType  : 'json',
    			        data	: 'mbr_id='+$('#mbr_id').val()+'&ipin_ci='+encodeURIComponent($('#ipin_ci').val())+'&coopco_cd='+$('#coopco_cd').val()+'&brnd_cd='+$('#brnd_cd').val(),
    			        async   : false,
    					cache   : false,
    			        type    : 'POST',
    			        error   : function(err) { alert(err); },
    			        success   : function(resp) {
    			        	if (resp.resultCode == '00') $('#id_validate').val('Y');
    			        	else {
    			        		$('#id_validate').val('N');
    			        		$('#mbr_id').focus();
    			        	}
    			        	alertMsg("alert_mbr_id", resp.resultMessage);
    			        	alert(resp.resultMessage);
    			        }
    				});
                } else {
                	alertMsg("alert_mbr_id", "6~12자리의 영문 소문자 또는 영문 소문자+숫자 아이디를 입력해 주세요.");
                	alert("6~12자리의 영문 소문자 또는 영문 소문자+숫자 아이디를 입력해 주세요.");
                    $('#mbr_id').focus();
                }
        	} else {
        		$('#mbr_id').focus();
        	}
        }
    }
    
    function checkRcmId(){
   	 if($('#rcm_id').val() == ""){
   		 alertMsg("alert_rcm_id", "추천인 아이디를 입력해주세요");
   		$('#rcm_id').focus();
   		 return false;
   	 }else{
   		 $.ajax({
   				url : "/cjmweb/join/chkRcmId.do"
   				, dataType:"json"
   				, async: false
   				, type: "POST"
   				, data : {rcm_id : $('#rcm_id').val()}
   				, success:function(data)
   				{				
   					var html = '';
   					if(data.result == "0"){
   						alertMsg("alert_rcm_id", "추천인 ID가 확인되었습니다.");
   						rcmCheck = true;
   					}else{
   						alertMsg("alert_rcm_id", "입력하신 회원 정보를 찾을 수 없습니다.<br>확인 후 다시 입력 해 주세요.");
   						rcmCheck = false;
   						$('#rcm_id').focus();
   					}
   				}
   				, error:function(data){
   					alert(data.msg);
   				}
   			});
   	 }
   	 
    }
    
	function date_change(){
		$('#birth_dd').empty();
		var dt = new Date($('#birth_yy').val(), $('#birth_mm').val(), 0);
	    $('#birth_dd').append($('<option value="일">일</option>'));
		for(var i=1; i<=dt.getDate(); i++){
			if(i<10){
				if(i == 1){
					$('#birth_dd').append($('<option value="0'+i+'" selected="selected" >0' + i + '</option>'));
				}else{
					$('#birth_dd').append($('<option value="0'+i+'">0' + i + '</option>'));
				}
			}else{
				$('#birth_dd').append($('<option value="'+i+'">' + i + '</option>'));
			}
		}
		$('[data-skin="form"] select#birth_dd').formSkin('addSkin');
	}

</script>   
    <script>
        $(function () {
            $('[data-check-all]').checkboxAllChecker();             //CJONE마케팅 전체동의
            
            //input type 설정
            cjone.importJs(['/cjmweb/js/modules/formatter'], function () {
                $('[data-format]').formatter();
            });
            
            if('' == '') {
	            $("#email_addr_opt").val("").change();
            }
        });
    </script>
<!-- //160203 수정 -->    
<!--//script 영역-->
	<form method="post" name="form2" id="form2">
	<input type="hidden" id="coopco_cd" name="coopco_cd" value="" />
	<input type="hidden" id="brnd_cd" name="brnd_cd" value="" />
	<input type="hidden" id="mcht_no" name="mcht_no" value="" />
	<input type="hidden" name="coop_return_url" id="coop_return_url" value="">
	<input type="hidden" id="return_func" name="return_func" value="" />
	<input type="hidden" id="mbr_id" name="mbr_id" value="" />
	<input type="hidden" id="sub_type" name="sub_type" value="" />
	<input type="hidden" id="ipin_use_yn" name="ipin_use_yn" value="" />
	<input type="hidden" id="hg_nm" name="hg_nm" value="" />
	<input type="hidden" id="vno" name="vno" value="" />
	<input type="hidden" id="ssn1" name="ssn1" value="" />
	<input type="hidden" id="ssn2" name="ssn2" value="" />
	<input type="hidden" id="ipin_ci" name="ipin_ci" value="" />
	<input type="hidden" id="ipin_di" name="ipin_di" value="" />
	<input type="hidden" id="gender" name="gender" value="" />
	<input type="hidden" id="frgnr_yn" name="frgnr_yn" value="" />
	<input type="hidden" id="under_14" name="under_14" value="" />
	<input type='hidden' id="id_validate" name="id_validate" value="" />
	<input type="hidden" id="agr_dy" name="agr_dy" value="" />
	<input type="hidden" id="agr_tm" name="agr_tm" value="" />
	<input type="hidden" id="agr_yn" name="agr_yn" value="" />
	
	<input type="hidden" name="agr_sub_yn99" id="agr_sub_yn99" value="" /><!-- 3자 동의파라메터   -->
	<input type="hidden" id="mbr_no" name="mbr_no" value=""  />
	<input type="hidden" id="mbr_typ_cd" name="mbr_typ_cd" value=""  />
	<input type="hidden" id="legl_rep_nm" name="legl_rep_nm" value=""  />
	<input type="hidden" id="legl_birth_day" name="legl_birth_day" value="">
	<input type="hidden" id="legl_ipin_ci" name="legl_ipin_ci" value="">
	<input type="hidden" id="legl_cert" name="legl_cert" value="">
	<input type="hidden" id="legl_typ_cd" name="legl_typ_cd" value="">
	<input type="hidden" id="legl_rep_agr_yn" name="legl_rep_agr_yn" value="" />
	<input type="hidden" id="join_coopco_list" name="join_coopco_list" value="" />
	
	<input type="hidden" id="rejoin_yn" name="rejoin_yn" value="" />
	<input type="hidden" id="action_url" name="action_url" value="" />
	
	<input type="hidden" name="evt_typ" id="evt_typ" value="" />
	<input type="hidden" name="strEvtCode" id="strEvtCode" value="" />
	<input type="hidden" name="evt_coopco_cd" id="evt_coopco_cd" value="" />
	<input type="hidden" name="evt_brnd_cd" id="evt_brnd_cd" value="" />
	<input type="hidden" name="evt_mcht_no" id="evt_mcht_no" value="" />
	<input type="hidden" name="evt_mbr_no" id="evt_mbr_no" value="" />
	<input type="hidden" name="card_register_error" id="card_register_error" value="" />
	<input type="hidden" name="upd_coopco_id"  id="upd_coopco_id"  value="">
	<input type="hidden" name="card_chk"  id="card_chk"  value="">
	</form>
</body>

<!-- Mirrored from www.cjone.com/cjmweb/join/member-info.do by HTTrack Website Copier/3.x [XR&CO'2014], Thu, 27 Jul 2017 14:59:49 GMT -->
</html>
