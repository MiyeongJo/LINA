<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<!doctype html>
<html lang="euc-kr">
<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge ,chrome=1">
	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
	<meta name="format-detection" content="telephone=no">
	<meta http-equiv="Cache-Control" content="no-cache">
	<meta http-equiv="Pragma" content="no-cache">
	<title>4xx 에러, CJ ONE</title>
	<meta name="description" content="">
	<meta name="keywords" content="">
	<link rel="shortcut icon" href="/cjmweb/images/ico/favicon.ico" type="images/x-ico" />

	<link rel="stylesheet" type="text/css" href="/cjmweb/css/base.css">
	<script type="text/javascript" src="/cjmweb/js/jquery-1.11.3.min.js"></script>
</head>

<body>

<div id="bodyWrap">
	<div class="error_wrap">
		<span class="img"></span>
		<h1 class="h2_tit">비정상적인 경로로 접근하셨습니다.</h1>
		<p class="h_desc">비정상적인 접근으로 페이지 로딩에 실패하였습니다.<br>정상적인 경로를 이용해 주세요.</p>
		<div class="btn_center">
			<a href="/cjmweb/main.do" class="btn btn_em"><span>CJ ONE 메인</span></a>
			<a href="#" onclick="javascript:history.back(-1);return false;" class="btn btn_em"><span>이전페이지</span></a>
		</div>
		<div class="box_gray">
			<p>관련 문의사항은 고객센터 (1577-8888)로 문의 주시기 바랍니다. </p>
		</div>
	</div>
</div>

<!--script 영역-->
	<script type="text/javascript" src="/cjmweb/js/modules/cjoneCore.js"></script>
	<script type="text/javascript" src="/cjmweb/js/modules/commonUi.js"></script>
	<script type="text/javascript" src="/cjmweb/js/frontUi.js"></script>
	<script type="text/javascript" src="/cjmweb/js/modules/jquery.bxslider.js"></script>
<!--//script 영역-->

</body>
</html>