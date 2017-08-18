(function ($, core, undefined) {
	/**
     * @description GNB 관련 클래스
     * @class
     * @name cjone.ui.HeaderUI
     * @extends cjone.ui.View
     */	
	var $doc = $(document),
          $win = $(window);
	var headerUI = core.ui('HeaderUI', /**@lends cjone.ui.HeaderUI */{
		/** jquery 플러그인명  */
		bindjQuery: 'headerUI',
		/**	기본 옵션값 선언부	*/
		defaults: {
		},
		/**	selector 선언부		*/
        selectors: {
            gnb: '#gnb',
            gnbDisplay: '[data-event="gnb"]',
            gnbClose: '[data-control="gnbClose"]',
            
            //navi영역
            navi: '#navi',
            headerWrap: '#headerWrap',

            footer: '#footer',
            contentsWrap: '#contentsWrap',
            contents: '.contents',
            bannerFlag: '.bannerFlag',
            bodyWrap: '#bodyWrap',
            dimWrap: '.bg_dim',
            
            toggleGNB: '[data-control="toggleGnb"]',
            accordionGNB: '[data-control="accordionGnb"]',
            smallGnbButton: '[data-control="smallGnbButton"]',
            
            lang: '#lang',
            notice: '#notice',
            personalInfo: '#personalInfo',
            csCenter: '#go_cscenter',
            goTop: '[data-control="goTop"]',
            
            
            search: '[data-control="toggleSearch"]',
            searchParent: '[data-handler="searchTag"]',
            searchArea: '#global_search',
            
			gnbSeq: '[data-control="personalInfo"] .img_wrap'
        },
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         */
		initialize: function (el, options) {
			var me = this;
			if (me.supr(el, options) === false) { return; }
			
            //me.$bodyWrap = me.$el;
            me.$bodyWrap = $('#bodyWrap');
            me.initGnb();
            me._setGNBSequenceImage();
			me._bindEvents();
		},
		/**
		 * GNB 시퀀스 이미지 관련 이벤트
		 * @private
		 * @description
		 		이미지 로드후 시퀀스 이미지 처리
		 * @param {requestCallback} sequence:end - 시퀀스 이미지가 종료되었을때 callack
		 *  */
		_setGNBSequenceImage: function () {
			var me = this,
				  playManager = {
				  	isPlaying: false,
				  	$el: null
				  };
			var setMotion = function (uid) {
				var uid = uid||'.normal';
			  	me.$gnbSeq.addClass('hide');    
				return me.$gnbSeq.filter(uid).removeClass('hide').sequenceMotion('start');
			};
			me.$gnbSeq.sequenceMotion({seqManager: $('#headerWrap')});
			setMotion('.nowload');
			
			me.$gnbSeq.parent().on({
				'open close': function (e, dataSet) {
					if(dataSet) return;
					var uid = null;
					switch(e.type){
						case 'open':
							uid = '.dash_open';
						break;
						case 'close':
							uid = '.dash_close';
						break;
					}
					me.$gnbSeq.filter(uid).children().first().removeClass('hide').siblings().last().addClass('hide');
					if(me.$headerWrap.find('.dash_open').hasClass('hide') == true &&  e.type == 'close') return;
					setMotion(uid);
				}
			});

			/**	시퀀스 이미지가 종료 되었을때 callback 되는 부분 	*/
			me.$gnbSeq.on({
				'sequence:end': function (e) {
					var $this = $(e.target);
					if($this.hasClass('nowload') == true || $this.hasClass('dash_close')){
						setMotion('.normal');
					}else if($this.hasClass('normal')){
						setMotion('.normal');
					}
					playManager = {						isPlaying: false,					  	$el: $this					};					
				},
				'sequence:start': function () {
					playManager = {						isPlaying: true,					  	$el: $(this)					};
				}
			});
		},
		/**
		 * GNB 열기 설정
		 * @private
		 * @param {String} selectorString - 호출된 jquery.selector
		 *  */
		_controlGNB: function (selectorString) {
			var triggerData = {
				el: selectorString || '#headerWrap'
			};
			
			switch(selectorString){
				case '#search':
					$('[data-control="personalInfo"]').triggerHandler('close', triggerData);
					$('[href="#go_cscenter"]').triggerHandler('close');
					if(cjone.getScreenStatus() != 'small')					$('#headerWrap').triggerHandler('hide:gnb');
				break;
				case '#personalInfo':
					$('[data-control="toggleSearch"]').triggerHandler('close', triggerData);
					$('[href="#go_cscenter"]').triggerHandler('close');
					if(cjone.getScreenStatus() != 'small')					$('#headerWrap').triggerHandler('hide:gnb');
				break;
				case '#go_cscenter':
					$('[data-control="personalInfo"]').triggerHandler('close', triggerData);
					$('[data-control="toggleSearch"]').triggerHandler('close', triggerData);
					if(cjone.getScreenStatus() != 'small')					$('#headerWrap').triggerHandler('hide:gnb');
				break;
				default:
					$('[href="#go_cscenter"]').triggerHandler('close', triggerData);
					$('[data-control="personalInfo"]').triggerHandler('close', triggerData);
					$('[data-control="toggleSearch"]').triggerHandler('close', triggerData);
				break;
			}
		},
		
        /**
        * GNB 설정 ( 768해상도에서 accordion 처리 ) 및 리사이즈 이벤트 처리
        * @private
        */
        initGnb: function () {
            var me = this,
            	 headerWrapIsOpen = me.$headerWrap.hasClass('on');
			me.$accordionGNB.accordion({toggleSelector: '>a', type: 'gnb'});
			cjone.$win.on({
				'resize': function () {
					var $accordionLi = me.$accordionGNB.find('>li'),
						  selectedIndex = $accordionLi.index($accordionLi.filter('.on'));
					if(selectedIndex > -1) $accordionLi.removeClass('on').eq(selectedIndex).children('a').trigger('click');
				}
			});
			
            /**	768사이즈의 GNB열기 버튼 */			
			me.$smallGnbButton.on({
				'click': function (e) {
					e.preventDefault();
					me.$headerWrap.addClass('on');
					me.$navi.animate({
						left: '0%'
					});
					me.$gnbClose.show();
					me._controlGNB();

					cjone.$htmlBody.addClass('ovh');
					var _height = cjone.util.getWinHeight()-(me.$navi.find('h2').outerHeight());
					me.$navi.find('.menu_scroll').height((cjone.browser.isDevice == true ? _height: ''));
				}
			});
			
		{	//gnb열기/ 닫기
			//GNB닫기
			 me.$gnbClose.on({
				'click': function () {
					cjone.$htmlBody.removeClass('ovh');
					me.$headerWrap.removeClass('on');
					switch(cjone.getScreenStatus()){
						case 'small': 	//small 사이즈 일때
							me.$navi.animate({
								left: '-100%'
							});
						break;
						default:			//small 사이즈를 제외
							var isNotHeaderWrap = (me.$searchParent.hasClass('on') || me.$el.find('[href="'+(me.selectors.notice)+'"]').hasClass('on') || me.$el.find('[href="'+(me.selectors.personalInfo)+'"]').hasClass('on'));		//검색, 알림, 개인화영역이 열려있을경우							
							if(isNotHeaderWrap == true) return;
							me._controlGNB();
							me.$headerWrap.stop().animate({
								'height': me.$headerWrap.attr('data-min-height')
							}, function () {
								if(cjone.getScreenStatus() != 'small'){	
									me.$gnbDisplay.hide();
									me.$gnbClose.hide();
								}
							});
						break;
					}
				}
			});
						
			//big gnb열리는 모션
			me.$accordionGNB.on({
				'mouseenter': function () {
					if(cjone.browser.isDevice == false)		me.$headerWrap.triggerHandler('show:gnb');
				},
				'click.gnb': function (e) {
					if(cjone.browser.isDevice == true && cjone.getScreenStatus() == 'medium' && me.$headerWrap.hasClass('on') == false){
						e.preventDefault();	
					}
					if(cjone.getScreenStatus() == 'small') return;
					var isOpen = me.$headerWrap.hasClass('on');
					me.$headerWrap.triggerHandler((isOpen == false ? 'show:gnb' : 'hide:gnb'));
				},
				'mouseleave': function () {
					if(cjone.browser.isDevice == false){
						me.$headerWrap.triggerHandler('hide:gnb');
						me._controlGNB();
					}
				},
				'focusin': function () {
					clearTimeout(me.timer);
					me.timer = '';
					me.timer = null;
				},
				'focusout': function () {
					if(cjone.browser.isDevice == false){
						me.timer = setTimeout(function () {
							me.$headerWrap.triggerHandler('hide:gnb');
							me._controlGNB();
						}, 200);
					}
				}
			});
			 
			me.$headerWrap.on({
				'show:gnb': function () {
					var isOpen = me.$headerWrap.hasClass('on');
		  			if(cjone.getScreenStatus() == 'small' || isOpen == true) return;
		  			
		  			//gnbClose
		  			if(cjone.getScreenStatus() == 'medium' && cjone.browser.isDevice == true){
		  				me.$gnbClose.show();
		  			}

					me.$gnbDisplay.show();
					me._controlGNB();
					
					me.$headerWrap.stop().addClass('on').height(me.$headerWrap.attr('data-min-height')).stop().animate({
						'height': me.$headerWrap.attr('data-max-height')
					});
				},
				'hide:gnb': function () {
					me.$gnbClose.triggerHandler('click');
				}
			});
		}			
		
		{
            //검색 영역
            me.$search.toggle().on({
            	'open close': function (e) {
            		var $this = $(this),
            			  $parent = me.$searchParent,
            			  $input = me.$searchArea.find('[placeholder]'),
            			  parentIsClose = $parent.hasClass('on'),
            			  isClose = ($.trim($input.val()).length == 0? true: false),
            			  classStatus = (e.type == 'open'? 'addClass': 'removeClass');
            			  
					switch(e.type){
						case 'open':
		            		{
		            			me.$searchArea.hide().slideDown(500, function () {
		            				me.$searchArea.removeAttr('style');
		            			});
		            		}
						break;
						case 'close':
							if(me.$searchArea.children().height() > 0){
								me.$searchArea.show().slideUp(500, function () {
		            				me.$searchArea.removeAttr('style');
		            			});
		            		}
						break;
					}
					me.$searchArea[classStatus]('on');
            		$parent[classStatus]('on');
            		$this[classStatus]('on');
            		$this.text($this.attr('data-'+(e.type)+'-text'));
            		$this.attr('title', $this.attr('data-'+(e.type)+'-text'));
            	},
            	'toggle:end': function (e, datas) {
            		var $this = $(this),
            			  isOpen = $this.hasClass('on');
            		$this.triggerHandler((isOpen == true? 'open': 'close'));
            		me._controlGNB('#search');
            	}
            });
		}
		
		{	//개인화 영역의 부하로 인한 함수로 처리
            $('[data-control="personalInfo"]').on({
            	'open close': function (e) {
            		var $this = $(this),
            			 data = {$handlerTarget: $('#personalInfo')},
            			 isOpen = (e.type == 'open'? true: false);
            		$this.find('.haze').text($this.attr('data-'+(e.type)+'-text'));
            		
                    if(isOpen == true){
                    	var maxHeight = me.$personalInfo.height();
	            		me.$personalInfo.show().children().each(function () {
	            			var $$this = $(this);
	            			maxHeight = ($$this.outerHeight(true) > maxHeight ? $$this.outerHeight(true): maxHeight);
	            		});
            		
                        data.$handlerTarget.hide().stop(true, true).slideDown(500, function () {});
                        data.$handlerTarget.find('button.close').off('click.'+'href').one('click.'+'href', function (e) {
                            e.preventDefault();
                            $this.triggerHandler('close');
                        });
                        $('[data-control="randomNum"]').charMotion('runUp');
                        $('[data-control="scrollView"]').scrollview();
                        $this.addClass('on');
                    }else{
						data.$handlerTarget.stop(true, true).slideUp(500, function () {});
						$this.removeClass('on');
                    }
            	},
            	'toggle': function (e) {
            		var $this = $(this).toggleClass('on'),
            			  isOpen = $this.hasClass('on');
					$this.triggerHandler((isOpen == true? 'open': 'close'));
					me._controlGNB('#personalInfo');
            	}
            });
		}
            
           /**
			  * gnb모션에 속해있는 
              * 768이하의 gnb모션, 알림메시지, footer의 제휴브랜드
              * @example
            		me.$toggleGNB.toggle({skipText:['#notice']});
            		me.$accordionGNB.accordion({toggleSelector: '>a', type: 'gnb'});
            */
			me.$toggleGNB.toggle().on({
            	'toggle:end': function (e, datas, isOpen) {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    var data = datas.data,
                          href = data.$el.attr('href'),
                          $el = data.$el,
                          isOpen = datas.isOpen;
                          
					me._controlGNB(href);
                    switch(href){
                    	//case '#lang':
                    	case '#go_cscenter':
                    		$el.triggerHandler((isOpen == true? 'open': 'close'));
                    	break;
                    	case '#familySite':
                    		$el.attr('title', (isOpen == true? $el.attr('data-close-text'): $el.attr('data-open-text')));
                    	break;
                        default:
                        break;
                	}
            	}
			});
			
			//고객센터 탭
			$('[href="'+(me.selectors.csCenter)+'"]').on({
				'open close': function (e) {
					var $this = $(this);
					$this.attr('title', $this.attr('data-'+(e.type)+'-text'));
					
					$this[(e.type == 'open' ? 'addClass': 'removeClass')]('on');
					me.$csCenter[(e.type == 'open' ? 'removeClass': 'addClass')]('hide');
				}
			});
			
            $('[data-control="tooltip"]').tooltip();
        },
        
        /**
        * 리사이즈및 레이아웃 재정의 함수
        * @private
        * @description
        	재 호출시 resize이벤트가 중복해서 걸림
        */
        setLayout: function () {
            var me = this;
            me.$footer = $(me.selectors.footer);
            var footerOffset = me.$footer.offset(),
                  resizeTimer = null;
            //서브 레이아웃 bx슬라이더 처리 부분
            
            cjone.$win.on({
            	'resizestart': function () {
            	},
            	'resize': function () {
            		me.$headerWrap.removeClass('on');
            		me.$headerWrap.triggerHandler('hide:gnb');
            		cjone.$htmlBody.removeClass('ovh');
            		cjone.$htmlBody.height(((cjone.getScreenStatus() == 'small') ? cjone.util.getWinHeight() : ''));
            	}
            }).triggerHandler('resize');
        },
        
        /**
         * 키보드 접근성 항목
         * @private
         * @description
         		GNB및 푸터의 키보드 접근 처리를 위한 함수
         *  */
        _accessableKeyboard: function () {
        	var me = this;
        	if(cjone.browser.isDevice == true) return;
        	/**
             * 언어설정항목
             *  */
            $.fn.testKey = function (options) {
            	var $el = this,
            		  options = $.extend({focus: $($el.selector), handler: $el.attr('href'), selector: 'a, button, input', callback: function () {}}, options);
            	options.handler = $(options.handler);
            	
            	$el.on({
            		'keydown keyup': function (e) {
            			if(e.keyCode != 9) return;
            			var $this = $(this);
            			clearTimeout($this.data('keyevents'));
            			$this.data('keyevents', setTimeout(function () {
            				if(e.shiftKey == true && $this.hasClass('on')) $this.triggerHandler('click');
            				$el.triggerHandler('callback', {$el: $this, evt: e, options: options});
            			}, 0));
            		}
            	});
            	
            	options.handler.on({
					'keydown': function (e) {
						if(e.keyCode != 9) return;
            			var $this = $(e.target);
            			clearTimeout($this.data('keyevents'));
            			$this.data('keyevents', setTimeout(function () {
            				var $obj = options.handler.find(options.selector);
            				if(e.shiftKey == false && $obj.size()-($obj.index($this)+1) == 0){
            					$el.triggerHandler('click');
            					$el.triggerHandler('callback', {$el: $this, evt: e, options: options});	
            				}
            			}, 0));
					}            		
            	});
            	return this;
            };

            $('[href="#go_cscenter"]').testKey();
            $('[href="#global_search"]').testKey().on({				//상단 검색창의 input 영역이 열렸을때
            	'callback': function (e, dataSet) {
            		var $el = dataSet.$el,
            			  e = dataSet.evt,
            			  options = dataSet.options;
            		
            		if($el.hasClass('on') == true && e.keyCode == 9){
            			var $searchInput = options.handler.find(options.selector).first().focus().off('keydown.tab').on({			//backtab시
            				'keydown.tab': function (_e) {
            					if(_e.shiftKey == true && _e.keyCode == 9){
            						var $globalSearchBtn = $('[href="'+(me.$searchArea.selector)+'"]');
            						setTimeout(function () {            							$globalSearchBtn.focus();            						}, 0);
            					}
            				}
            			});
            			
            			options.handler.find(options.selector).last().off('keydown.tab').on({												//tab시
            				'keydown.tab': function (_e) {
            					if(_e.keyCode != 9 || _e.shiftKey == true) return;
            					setTimeout(function () {            						$('[href="#personalInfo"]').focus();            					}, 0);
            				}
            			});
            		}
            	}
            });
            $('[href="#personalInfo"]').testKey();
            $('[href="#familySite"]').testKey();
            
            var $gnbEl = me.$accordionGNB.find('a.link_1depth'); 
            $gnbEl.on({
            	'keydown focus': function (e) {
            		if(e.type == 'focus')            		me.$headerWrap.triggerHandler('show:gnb');
            		if(e.type == 'keydown' && (e.keyCode==9 && e.shiftKey == true))		me.$headerWrap.triggerHandler('hide:gnb');
            	}
            });
            
            $('#footer').on({
            	'keyup': function (e) {
            		var $this = $(this),
            			  $target = $(e.target);
            		if($('[href="#familySite"]').hasClass('on') == true &&  $target.closest('.familySite').size() == 0)	$('[href="#familySite"]').triggerHandler('click');
					if($('[href="#familySite"]').hasClass('on') == true && $target.attr('target') == '_blank' && e.keyCode == 13) $('[href="#familySite"]').triggerHandler('click');			//엔터키로 링크를 열 경우
            	}
            });
        },
        /**
         * 마우스 이벤트 처리
         * @private
         * @description
         		푸터 > 패밀리 사이트가 열린후 문서를 클릭및 해당 링크를 클릭시 닫히는 처리
         *  */
        _accessableMouse: function () {
        	var me = this;
        	cjone.$doc.on({
        		'click': function (e) {
        			var $target = $(e.target);
        			if($('#familySite').hasClass('hide') == false)		$('[href="#familySite"]').triggerHandler('click');
        		}
        	});
        },
        
        /**
         * Top 버튼 처리
         * @private
         * @description
         		최 상단으로 스크롤 이동
         *  */
        _goTop: function () {
        	var me = this,
        		 margin = (cjone.browser.isDevice == true ? 0 : 50);
        	
        	if(me.$footer.size() == 0) return;
        		
			cjone.$win.on({
	        	'scroll': function () {
	            	me.$goTop.removeClass('hide');
	                    
	                if(cjone.$win.scrollTop() <= $('#headerWrap').height()){
	                	me.$goTop.addClass('hide');
					}
	                    
	                if(cjone.$win.scrollTop()+cjone.util.getWinHeight() > me.$footer.offset().top){
	                	var bottom = (cjone.$win.scrollTop()+cjone.util.getWinHeight()) - me.$footer.offset().top;
						me.$goTop.css({
							'bottom': bottom+me.$goTop.height()
						});
	                }else{
						me.$goTop.css({ 
							'bottom': '50px'
						});
					}
				}
			});
			
			me.$goTop.on({
                'click': function (e) {
                    e.preventDefault();

					if($.fn.smoothWheel){
	                    var flag = (cjone.browser.isChrome == true || cjone.browser.isSafari == true);
						$((flag == true ? 'body': 'html')).triggerHandler('setScrollTop');
					}
                    
                    cjone.util.scrollToElement(me.$headerWrap, {complete: function () {
                    	setTimeout(function () {
                    		$('html, body').focus();
                    	}, 0);
                    }});
                }
            }).addClass('hide');
        },
		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
		_bindEvents: function () {
			var me = this;
            
            //레이아웃 관련 스크립트 위치 입니다.
            me.setLayout();
            me._accessableKeyboard();
            me._accessableMouse();
            me._goTop();
            
            //오늘 하루 더 안보기
			$('#headerWrap .closeChk .ondaychk, .spotBanner .todayChk .today').click(function () {
            	$(this).toggleClass('on');    
        	});
        	
        	/** input 영역에 focus시 해당 영역의 text를 선택처리	*/
        	$('[data-format]').on({
        		'focus': function () {
        			$(this).select();
        		}
        	});
        }
	});

    if (typeof define === "function" && define.amd) {
		define([], function() {
			return HeaderUI;
		});
	}
})(jQuery, window[LIB_NAME]);


/**
 * 레이어 팝업 포커스 및 키보드 컨트롤 시작
 * @global
 * @description
		1. 마지막 선택한 링크 및 버튼을 배열로 담아 컨트롤
		2. 키보드 접근성 ( 닫힐때 마직막으로 선택한 항목으로 포커스가 가야함 )
 *  */
var g_layer = {
    layerButtonStack: [],           //docuemnt의 버튼과 a링크를 담고 있는 객체
    layerStack: []                      //실제 레이어의 객체
};

$(function () {
	/**		문서를 클릭했을때 마다 해당 요소를 배열로 담아 컨트롤		*/
    cjone.$doc.on({
        'click': function (e) {
        	var $this = $(this);
        	if($this.attr('data-control') != 'modal')			g_layer.layerButtonStack.push(this);
        }
    }, 'a, button');
    
    /**
     * 레이어 팝업이 열린후 클릭한 요소들을 컨트롤
     * @description
     		키보드 접근성 ( 레이어를 닫을때 마지막으로 선택된 항목에 포커스를 처리해야 함 )
     *  */
    cjone.$doc.on({
    	/**	레이어 팝업이 열렸을때 	*/
        'modal:show': function () {
            g_layer.layerStack.push(g_layer.layerButtonStack[g_layer.layerButtonStack.length-1]);
            g_layer.layerButtonStack = [];
        },
        /**	레이어 팝업이 닫혔을때 	*/
        'modal:hidden': function () {
        	var focusEl = g_layer.layerStack.pop();
        	try{
        		if(focusEl) focusEl.focus();
        	}catch(e){}
            g_layer.layerButtonStack = [];
        }
    });
});
//레이어 팝업 포커스 컨트롤 끝

$(function () {
	/**
	 * GNB 및 푸터 관련 문서가 로드가 끝난후 이벤트 바인딩 및 실행 부분
	 *  */
	var $doc = $(document),
		 $win = $(window),
		 $body = $('body');
		 
    $body.headerUI();										/**	GNB 이벤트 바인딩 및 실행 	*/
    $('[data-control="tooltip"]').tooltip();			/**	툴팁 관련 이벤트 처리		*/
    
    /**	페이지내 선언되지 못한 외부 함수들을 동적 load 함 */
    $doc.ready(function(){
    	/**	로컬 PC 와 DEV 서버의 파일 경로 sync용	 */
		var asFront = (cjone.uri.parseUrl(location.href).directory.indexOf('/cjmweb/front') > -1 || cjone.uri.parseUrl(location.href).directory.indexOf('/script') > -1 ? 'front/': '' );
		cjone.importJs(['/cjmweb/'+(asFront)+'js/modules/placeholder'], function () {
			$('input, textarea').placeholder();
		});
		
		if(typeof $.fn.formatter == 'undefined'){
			var asFront = (cjone.uri.parseUrl(location.href).directory.indexOf('/cjmweb/front') > -1 || cjone.uri.parseUrl(location.href).directory.indexOf('/script') > -1? 'front/': '' );
			cjone.importJs(['/cjmweb/'+(asFront)+'js/modules/formatter'], function () {
				$('[data-format]').formatter();
			});
		}
    });
    
    /**	checkbox, radio, select 용 커스텀 스킨 실행 부분 	*/
    $('[data-skin="form"] input').formSkin('addSkin');
	$('[data-skin="form"] select').formSkin('addSkin');

	/**	
	 *	모바일서 hover, focus css 를 컨트롤 하기 위한 이벤트 바인딩
	 * @callback {Object} focus:on - 포커스가 되었을때
	 * @callback {Object} hover:on - hover가 되었을때
	 * @callback {Object} hover:off - hover에서 풀렸ㅇ르때
	 * @callback {Object} focus:off - 포커스가 풀렸을때
	 * @description
	 		css > select:focus, select:hover 속성 사용시 태블릿 기기에서는 링크로 넘어가기 위해 두번 클릭해야 
	 * */
	$doc.on({
		'click': function (e) {
			if(cjone.browser.isDevice == false)	return;
			var $this = $(this).toggleClass('hover'),
				  href = cjone.getHref($this.context.hash);
				  
			if(cjone.browser.isDevice == true && (!href) && $this.hasClass('hover') == true){
				//e.preventDefault();
			}
			
			$this.triggerHandler('hover:on');
		},
		'focus': function (e) {
			var $this = $(this);
			if(cjone.browser.isDevice == true){
				$this.removeClass('hover');
				return;
			};
			$(this).addClass('focus').triggerHandler('focus:on');
		},
        'hover mouseenter': function (e) {
        	var $this = $(this);
			if(cjone.browser.isDevice == true) {
				$this.addClass('hover');
				return;
			}
			$(this).addClass('hover').triggerHandler('hover:on');
        },
        'mouseleave': function (e) {
        	var $this = $(this);
			if(cjone.browser.isDevice == true) {
				$this.removeClass('hover');
				return;	
			}
            $(this).removeClass('hover').triggerHandler('hover:off');
        },
        'blur': function (e) {
        	var $this = $(this);
			if(cjone.browser.isDevice == true) {
				$this.removeClass('hover');
				return;
			}
			
            $(this).removeClass('focus').triggerHandler('focus:off');
        }
	}, 'a:not("[disabled]"), button:not("[disabled]"), input, select, radio, checkbox, textarea, [data-handler="motion"]');
    
	/**	인쇄를 할 경우 미디어 쿼리 실행	*/    
    $doc.on({
    	//레이어 팝업이 열렸을경우 callback
        'modal:show': function () {
            $('<style media="print">  body{-webkit-print-color-adjust:exact; print-color-adjust:exact;} #bodyWrap {display:none;} .ui_modal_overlay {background-image:none;}</style>').appendTo('head');
        },
        //레이어 팝업이 닫혔을때 callback
        'modal:hide': function () {
            $('[media="print"]').remove();
        }
    });
    
    /**
     * IE7, 8 브라우저 일경우 다른 속성을 적용하기 위한 body에 클래스 선언
     *  */
    switch(cjone.browser.version){
    	case 7:    	case 8:
    		cjone.$htmlBody.filter('body').addClass('ie'+(cjone.browser.version));
    	break;
    }
    
    //키보드 접근성 확인용 로컬 테스트용 소스
	var inlineHTML = '';
   	inlineHTML+= '<style type="text/css">:focus, .focus, button.focus, button.em.focus{ border: 2px solid red !important; }</style>';
	if(cjone.uri.parseUrl(location.href).host === 'cj.local.com'){
   		$(document.body).append(inlineHTML);
   	}

	//alert 로직 수정
	/*window.alert = function (al, $) {
		return function (msg) {
			al(msg);
			$('html, body').focus();
		};
	}(window.alert, window.jQuery);*/
});