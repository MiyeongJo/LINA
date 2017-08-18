(function ($, core, undefined) {
    "use strict";
	/**
	 * @description 휠 스크롤 컨트롤
	 * @class
	 * @name cjone.ui.ScrollAction
	 * @extends cjone.ui.View
     * @example
			http://dev.cjone.com:8001/cjmweb/front/main/MA_010_01.html
	 * @modify 
	 		@160902 비활성화 상태의 체크 항목이 추가됨
	 */
    core.ui('ScrollAction', /**	@lends cjone.ui.ScrollAction */{
    	/** jquery 플러그인명  */
        bindjQuery: 'scrollAction',
        /**	기본 옵션값 선언부	*/
        defaults: {
        	type: '',		/** @member {String} type - 타입설정 */
        	margin: 0	/** @member {String} margin - 스크롤 margin */
        },
        /**	selector 선언부		*/
        selectors: {
           item: '[data-scroll-callback]' 
        },
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {String}  options.type - 타입
         * @param {Integer}  options.margin - 스크롤 margin
         */
        initialize: function (el, options) {
            var me = this;
            if (me.supr(el, options) === false) {
                return;
            }
            me._bindEvents();
        },
        
        /**
         * 스크롤의 위치값을 캐치후 해당 이벤트 호출
         * @private
         * @param  {boolean} isInner - 스크롤의 위치값 안에 들어있는 요소인지 판별
         *  */
        _checkScroll: function (isInner) {
            var me = this;
            me.$item = me.$el.find(me.selectors.item);
            
            me.$item.each(function (idx) {
				var $this = $(this),
					  hasBottomLine = cjone.$win.scrollTop()+cjone.util.getWinHeight() <= me.$el.offset().top+me.$el.outerHeight(true)+me.options.margin,
					  hasTopLine = (cjone.$win.scrollTop()+cjone.util.getWinHeight() > me.$el.offset().top),
					  isInner = (hasTopLine && hasBottomLine),
					  scrollStatus = {
						hasTopLine: hasTopLine,
						hasBottomLine: hasBottomLine,
						isInner: (hasTopLine && hasBottomLine)
					  };
				$this.triggerHandler($this.attr('data-scroll-callback'), {data:me, $el: $this, isInner: isInner, scrollStatus: scrollStatus});
            });
        },
        
        /**
         * 스크롤 이벤트에 바인딩 되어 있는 이벤트를 release
         *  */
        release: function () {
        	var me = this;
        	cjone.$win.off('scroll.scrollaction');
        	me.release();
        },
        
		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
        _bindEvents: function () {
            var me = this;
            
            cjone.$win.on({
                'scroll.scrollaction': function () {
                    var isInner = (cjone.$win.scrollTop()+cjone.util.getWinHeight() >= me.$el.offset().top) && (cjone.$win.scrollTop()+cjone.util.getWinHeight() <= me.$el.offset().top+me.$el.outerHeight(true)+me.options.margin);
                    if(isInner == true){
                        //me._checkScroll();
                    };
                    me._checkScroll(isInner);
                }
            });
        }
    });

    if (typeof define === 'function' && define.amd) {
        define('modules/scrollAction', [], function (){
            return ScrollAction;
        });
    }
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
	/**
	 * @description 순차적인 레이아웃에 대해 재정렬
	 * @class
	 * @name cjone.ui.RePositionOrder
	 * @extends cjone.ui.View
	 * @sample
	 		http://dev.cjone.com:8001/cjmweb/front/event/EV_010_010.html
	 * @example
			- default
	 			$(window).load(function () {
	 				$('[data-control="repositionList"]').rePositionOrder('reposition');	
	 			});
			- append
				$('[data-control="repositionList"]').append(HTML).rePositionOrder('reposition');
	 *
	 */    
    core.ui('RePositionOrder', /**	@lends cjone.ui.RePositionOrder*/{
    	/** jquery 플러그인명  */
        bindjQuery:'rePositionOrder',
        $statics: {
            ON_CLICK: 'click'
        },
        /**	기본 옵션값 선언부	*/
        defaults: {
            marginTop: 0,		/** @member {Integer} marginTop - 요소위치 재정의시 추가시킬 위쪽 높이 */
            marginLeft: 0,		/** @member {Integer} marginLeft - 요소위치 재정의시 추가시킬 좌측 위치 */
            type: 'default'			/** @member {String} type - type 설정 */
        },
		/**	selector 선언부		*/
        selectors: {
            slide: '[data-handler="item"]'
        },
        positionArray: [],

		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Integer}  options.marginTop - 요소위치 재정의시 추가시킬 위쪽 높이
         * @param {Integer}  options.marginLeft - 요소위치 재정의시 추가시킬 좌측 위치
         * @param {String}  options.type - type 설정
         */
        initialize: function (el, options) {
            var me = this;
            if(me.supr(el, options) === false) { return; }
            
            me._bindEvent();
        },
        
        /**
         * Object들의 위치값들을 재 수정
         * @private
         *  */
        _rePositionCell: function (e, data) {
            var me = this;
            var x = 0,                  //다시 지정해줄 position.x
                 y = 0,                 //다시 지정해중 position.y
                 cellCountX = 0,        //x축 좌표에 최대 넣을수 있는 갯수
                 $tempCell = null,
                 _resizeHeight = 0, //me.$el의 최대 높이값
                marginTop = me.options.marginTop,       //윗쪽으로 붙일 maring값
                marginLeft = me.options.marginLeft,     //좌측으로 붙일 maring값
                width = 0,
                loadCount = 0;;
            
            me.positionArray = [];

            me.$slide.removeAttr('style').each(function (idx, cell) {
                var $this = $(this),
                     $tempCell = me.$slide.eq(idx-1);
                     
                cellCountX = Math.round(me.$el.width()/(me.$slide.last().width()+marginLeft));
                
                if(cellCountX == 1){
                    marginLeft = 0;
                    marginTop = 0;
                }
                
                if(x >= me.$el.width()){
                    x = 0;
                    y = $tempCell.position().top+$tempCell.height()+marginTop;
                }
                if((idx-cellCountX)>-1){
                    $tempCell = me.$slide.eq(idx-cellCountX);
                    y = $tempCell.position().top+$tempCell.height()+marginTop;
                }
                
                $this.setPosition({posX: x, posY: y, usingCSS3: false});
                
                x += $this.width()+marginLeft;
                cellCountX = idx;
                ++loadCount;
            });
            
            if(me.$slide.size() < cellCountX){
                _resizeHeight = me.$slide.height();
            }else{
                for(var x=me.$slide.size()-1 ; x>-1 ; x--){
                    if(me.$slide.eq(x).css('display').toLowerCase() != 'none'){
                        var temp = me.$slide.eq(x).position().top+me.$slide.eq(x).height();
                        if(temp > _resizeHeight)    _resizeHeight = temp;
                    }                   
                }
            }
            //최대 높이값 설정
            me.$el.height(_resizeHeight);
            me.$el.trigger('reposition:end');
            if(loadCount == me.$slide.size()) me.$el.removeClass('invisible, js_vhidden');
            
            if(loadCount == me.$slide.size()){
            }
        },
        /**
         * object를 재정의 위한 함수
         * @public
         * @param {Object} options
         * @param {Integer} options.marginTop - 요소위치 재정의시 추가시킬 위쪽 높이
         * @param {Integer} options.marginLeft - 요소위치 재정의시 추가시킬 좌측 위치
         * @param {String} options.type - type 설정
         *  */
        reposition: function (options) {
        	var me = this;
        	me.$el.addClass('js_vhidden');
        	me.options = $.extend(me.options, options);
        	me.updateSelectors();
        	me._rePositionCell();
        },
        
        
		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
        _bindEvent: function () {
            var me = this,
                 resizeTimer = null,
                 screenSize = cjone.util.getWinWidth();
                 
			cjone.$win.on({
				'resize': function (e, data) {
					me._rePositionCell(e, data);
					cjone.$win.scrollTop(cjone.$win.scrollTop());
				}
			}).triggerHandler('resize');
        }
    });
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
	var $win = $(window);
	/**
	 * @description BxSlider 확장
	 * @class
	 * @name cjone.ui.Slider
	 * @extends cjone.ui.View
	 * @sample http://dev.cjone.com:8001/cjmweb/front/mypage/MP_010_010.html
	 */
	core.ui('Slider', /** @lends cjone.ui.Slider */{
		/** jquery 플러그인명  */
		bindjQuery:'slider',
		$statics: {
		},
		/**	기본 옵션값 선언부	*/
		defaults: {
			changeWidth: true,		/** @member {Boolean} changeWidth - 너비값 가변 여부	*/
			hidePager: true,			/** @member {Boolean} hidePager - bxSlider의 기본 페이져 숨김처리 */
			bindResizeEvent: true	/** @member {Boolean} bindResizeEvent - 리사이즈 이벤트 허용 여부 */
		},
		/**	selector 선언부		*/
		selectors: {
			banner: '[data-handler="banner"]',
			btnNext: '.btn_next',
			btnPrev: '.btn_prev',
			control: '.indicator_wrap',
			indicator: null
		},
		indicatorCount: 0,
		sliderOptions: {			/** @description bxslider의 options */
            maxSlides: 100,
            slideMargin: 0,
            startSlide: 0,
            checkIndicator: function (currentIndex) {
            },
            onSlideBefore: function ($el, oldIndex, currentIndex) {
            },
            onSlideAfter: function ($el, oldIndex, currentIndex) {
            },
            onSlideNext: function ($el, oldIndex, currentIndex) {
            },
            onSlidePrev: function ($el, oldIndex, currentIndex) {
            },
            onSliderLoad: function (currentIndex, b, c) {
            },
			infiniteLoop: false,            
            auto: false,
            autoControls: false,
            pager: true,
            controls: true
		},

		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Boolean}  options.chageWidth - 너비값 가변 여부
         * @param {Boolean}  options.hidePager - bxSlider의 기본 페이져 숨김처리
         * @param {Boolean}  options.bindResizeEvent - 리사이즈 이벤트 허용 여부
         */
		initialize: function (el, options) {
			var me = this;
			if(me.supr(el, options) === false) { return; }
			
			me.sliderOptions = $.extend(me.sliderOptions, options.sliderOptions);
			
			me._setBanner('init');
			me._bindEvent();
		},
		/**
		 * 배너의 custom indicator 정의
		 * @private
		 *  */		
		_setBanner: function (type) {
			var me = this;
			switch(type){
				case 'reload':
					me.sliderOptions.startSlide = me.$banner.getCurrentSlide();
					me.$banner.reloadSlider(me.sliderOptions);
				break;
				default:
					me.$banner = me.$banner.bxSlider(me.sliderOptions);
				break;
			}
			me.$indicator = me.$control.children().first().clone(true).removeClass('on');
			me.indicatorCount = me.$el.find('.bx-pager >').size();
			me.$el.find('.bx-controls')[(me.options.hidePager == true || me.indicatorCount <= 1? 'hide': 'show')]();
			
			me.$btnPrev = (me.$btnPrev.size() == 0 ? me.$banner.getSlider().controls.prev : me.$btnPrev);
			me.$btnNext = (me.$btnNext.size() == 0 ? me.$banner.getSlider().controls.next : me.$btnNext);
			me.$control.empty();
			
			for(var x=0 ; x<me.indicatorCount ; x++){
				var $clone = me.$indicator.clone();
				$clone.find('.haze').text(x+1);
				if(x==0) $clone.addClass('on');
				me.$control.append($clone);
			}
		},
        
		 /**
		 * 이벤트 바인딩 함수
		 * @private
		 */
		_bindEvent: function () {
			var me = this;
			
			me.$el.on({
				'click'	: function (e) {
					var $this = $(this),
						  $target = $(e.target),
						  indicatorCount = ((me.$banner.getSlideCount()-me.sliderOptions.minSlides)+1);
					
					me.$banner[($target.is(me.$btnNext) == true ? 'goToNextSlide': 'goToPrevSlide')]();				
					me.$control.children().removeClass('on').eq(me.$banner.getCurrentSlide()).addClass('on');
				}
			}, me.selectors.btnNext+', '+me.selectors.btnPrev);
			
			me.$el.on({
				'click': function (e) {
					e.preventDefault();
					var $this = $(this),
						  $buttons = me.$el.find('.indicator_wrap button'),
						  currentIndex = $buttons.index($buttons.filter('.on')),
						  selectedIndex = $buttons.index($(e.target));
						  
					me.$banner.goToSlide(selectedIndex);
					me.$control.children().removeClass('on').eq(selectedIndex).addClass('on');
				}
			}, '.indicator_wrap button');
			
			cjone.$win.on({
				'resize': function () {
					me._setBanner('reload');
				}
			});
		}
	});
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
    "use strict";
	/**
	 * @description <br/>form 요소중 radio button, checkbox, select box에 커스텀 스킨을 적용<br/>
	  		radio, checkbox 항목은 한개의 항목에 대해 이벤트 처리
	  		select 항목은 append 되는 항목에 대해 이벤트 재부여
	 * @class
	 * @name cjone.ui.formSkin
	 * @extends cjone.ui.View
     * @example
			http://dev.cjone.com:8001/cjmweb/front/main/MA_010_01.html
	 */

    core.ui('FormSkin', /**@lends cjone.ui.formSkin*/{
    	/** jquery 플러그인명  */
        bindjQuery: 'formSkin',
        /**	기본 옵션값 선언부	*/
        defaults: {
        	openText: ' 목록 닫기',						/** @member {String} openText - select 항목이 열렸을때의 대체 텍스트 */
            closeText: ' 목록 열기',						/** @member {String} closeText - select 항목이 닫혔을때의 대체 텍스트 */
            checkedText: '선택됨',						/** @member {String} checkedText - check, radio 항목이 선택되었을때의 대체 텍스트 */
            uncheckedText: '미선택됨'				/** @member {String} uncheckedText - check, radio 항목이 선택되지 않았을때의 대체 텍스트 */
        },
        /**	selector 선언부		*/
        selectors: {
            checkbox: 'input[type="checkbox"]',
            radio: 'input[type="radio"]',
            input: 'input',
            skinWrap: '.select_wrap'
        },
        
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {String}  openText - select 항목이 열렸을때의 대체 텍스트
         * @param {String}  closeText - select 항목이 닫혔을때의 대체 텍스트
         * @param {String}  checkedText - check, radio 항목이 선택되었을때의 대체 텍스트 
         * @param {String}  uncheckedText - check, radio 항목이 선택되지 않았을때의 대체 텍스트
         */
        initialize: function (el, options) {
            var me = this;
            if (me.supr(el, options) === false) {
                return;
            }
            
            me._bindEvents();
        },

		/**
		 * 스킨을 적용하는 함수
		 * @public
		 * @example
		 		$('[data-skin="form"] input').formSkin('addSkin'); 
		 		$('[data-skin="form"] select').formSkin('addSkin');
		 *  */
		addSkin: function () {
			var me = this;

			switch(me.$el.context.type){
				case 'radio':
				case 'checkbox':
					me.$skin = me.$el.closest('[data-skin]');
					if(me.$el.size() > 0)					me._addCheckboxRadioSkin();
				break;
				case 'select-one':
					me.$skin = me.$el.closest('[data-skin]');
					if(me.$el.size() > 0)					me._addSelectBox();
				break;
			}
		},
		/**
		 * select 항목의 custom skin을 붙이는 항목
		 * @private
		 *  */
		_getSelectSkin: function () {
			var me = this;
			var HTML = '';
				HTML += '<div class="select_wrap">';
				HTML += '	<div class="item_seleced"><a href="#" title="휴대전화 앞자리 선택">선택<span class="haze">선택됨</span></a></div>';
				HTML += '	<div class="item_list_wrap ">';
				HTML += '		<div class="item_list ui_scrollarea">';
				HTML += '			<ul class="ui_content">';
				HTML += '				<li class="on"><a href="#"><span>선택 - 1</span></a></li>';
				HTML += '				<li class="on"><a href="#"><span>선택 - 2</span></a></li>';
				HTML += '				<li class="on"><a href="#"><span>선택 - 3</span></a></li>';
				HTML += '				<li class="on"><a href="#"><span>선택 - 4</span></a></li>';
				HTML += '				<li class="on"><a href="#"><span>선택 - 5</span></a></li>';
				HTML += '			</ul>';
				HTML += '		</div>';
				HTML += '		<div class="scroll ui_scrollbar">';
				HTML += '			<span class="bg_top"></span>';
				HTML += '			<span class="bg bg_mid"></span>';
				HTML += '			<span class="bg_btm"></span>';
				HTML += '		</div>';
				HTML += '	</div>';
				HTML += '</div>';
			return HTML;
		}, 
		
		/**
		 * select 항목에 스킨이 입혀졌을때 default select box를 display: none 처리함
		 * @private
		 *  */
		_setSkinCSS: function () {
			var me = this;
			me.$skin.addClass('hide');
		},
		
		/**
		 * system select 항목의 option값과 스킨의 구성요소를 동적 동기화
		 * @private
		 *  */
		_addSelectBox: function () {
			var me = this,
				  html = '',
				  $appendTag = null;
				  
			if(me.$skin.next('div.select_wrap').size() == 0){
				me.$skin.after(me._getSelectSkin());
			}
			$appendTag = me.$skin.next().find('ul').empty();
			
			//system select.option의 구조와 동일하게 ul.li의 구조를 만들어줌			
			me.$el.children().each(function () {
				var tag = this.outerHTML,
					 $this = $(tag),
					 text = $this.text(),
					 value = $this.attr('value') || '',
					 selected = ($this.attr('selected') ? ' data-selected="true"' : '');

				html += '<li><a href="#'+(value)+'"'+(selected)+'><span>'+(text)+'</span></a></li>';
			 });

			$appendTag.append(html);

			//동적 select 항목이 생성이 될경우 스크롤 처리를 위한 클래스를 붙여줌
			if(!me.$skin.next().data('ui_scrollview')){
				me.$skin.next().scrollview().addClass(me.$skin.attr('class')).removeClass('select');
				me._bindSelectEvent();
				me._setSkinCSS();
			}
			
			//options.selected="selected" 항목을 지원
			$appendTag.find('[data-selected="true"]').trigger('click');
		},
		
		/**
		 * alert 후 focus 처리용
		 * @private
		 * @description
		 		default elements의 focus 함수 호출시 화면에 표시되지 않아 확장 개발
		 		IE7, 8 브라우저에는 지원 하는 기능이 없슴 
		 *  */
		_supportFocus: function ($el, $a) {
			try{//IE7, 8 브라우저 지원하지 않음
	            var oldHTMLFocus = HTMLElement.prototype.focus;
	            HTMLElement.prototype.focus = function () {
	                var _this = this;
	                switch(this.type){
	                    case 'checkbox':
	                    case 'radio':
	                        _this = this.parentNode.children[0];
	                    break;
	                    case 'select-one':
	                	    var $parent = $(this).parent();
							if($parent.attr('data-skin')){
	                        	_this = $parent.next().find('a').first()[0];
	                       }
	                    break;
	                }
	                oldHTMLFocus.apply(_this, arguments);
	            };
	        }catch(e){}
		},
		
		/**
		 * system select box의 이벤트 캐치후 스킨에 이벤트 적용
		 * @private
		 *  */
		_bindSelectEvent: function () {
			var me = this;
			var $skinTag = me.$skin.next();
			var $scrollArea = $skinTag.find('.ui_scrollarea');
			var $a = $skinTag.find('.item_seleced a').attr('data-title', me.$el.attr('title'));
			$a.attr('title', $a.attr('data-title')+me.options.closeText);
			
			me._supportFocus(me.$el, $a);
			
			cjone.$doc.on({
				'click': function (e) {
					var $this = $(this),
						  $id = $('#'+$this.attr('for'));
					if($id[0].type == 'select-one'){
						e.preventDefault();
						$id.focus();
					}
				}
			}, '[for]');

			//custom skin에 dom 요소를 붙여 넣는 함수
			var acceptSkin = function ($obj) {
				var $this = $obj,
					  selectedIndex = $scrollArea.find('a').removeAttr('data-selected').index($this), 
					  val = $this.attr('href'),
					  text = $this.text(),
					  haze = $a.children()[0].outerHTML,
					  html = text+haze;
				$this.attr('data-selected', 'true');
				$a.empty().html(html).attr('href',val);
				$skinTag.removeClass('on');	  
				return me.$el.children().eq(selectedIndex).prop('selected', true);
			};

			//system select box의 구성요소가 바뀌었을때 skin도 동일하게 적용			
			me.$el.on({
				'change': function (e) {
					var $this = $(this),
						  $options = $this.children(),
						  selectedIndex = $options.index($options.filter(':selected'));
					
					acceptSkin($scrollArea.find('a').eq(selectedIndex));
					$a.triggerHandler('closeText');
				}
			});
			
			//스킨의 리스트 열기 / 닫기
			$a.on({
				'click': function (e) {
					e.preventDefault();
					e.stopPropagation();
					
					if(me.$el.prop('disabled')) return;
					var $this = $(this),
						  isOpen = $skinTag.toggleClass('on').hasClass('on');
					
					$a.attr('title', $a.attr('data-title')+(isOpen == true ? me.options.openText: me.options.closeText));
					$('.select_wrap').not($a.closest('.select_wrap')).removeClass('on');
				},
				'openText': function () {
					
					$a.attr('title', $a.attr('data-title')+me.options.openText);
				},
				'closeText': function () {
					$a.attr('title', $a.attr('data-title')+me.options.closeText);
				}
			});
			
			//리스트의 항목 선택시 해당 내용으로 치환우 default select form의 selected Index를 넘겨줌
			$scrollArea.on({
				'click': function (e) {
					e.preventDefault();
					e.stopPropagation();
					acceptSkin($(this)).trigger('change');
					if(!e.isTrigger) $a.focus();
				}
			}, 'a');

			//키보드 접근성 테스트용			
			me.$skin.next().on({
				'keydown': function (e) {
					var $this = $(this),
						  $target = $(e.target);
					if(e.keyCode != 9) return;
					clearTimeout($this.data('timer'));
					$this.data('timer', setTimeout(function () {
						var $listContents = $this.find('.ui_content a'),
							  isClose = {
									backward: ($this.find('.item_seleced a').is(':focus') || $target.closest('.item_seleced').size()>0 && e.shiftKey == true) || false,
	                   				forward: ($listContents.size()-1 == $listContents.index($target)) || false
							  };
	                   
						if(isClose.backward || isClose.forward){
							$this.removeClass('on');
						}
					}, 50));
				}
			});
			
			//select skin이 열린 상태에서 다른 항목을 눌렀을때 닫음 처리
			cjone.$doc.on({
				'click': function (e) {
					var $target = $(e.target);
					me.$skin.next().removeClass('on');
					
					$a.triggerHandler('closeText');
				}
			});
		},
	
		//radio, checkbox의 스킨 이벤트 적용
        _addCheckboxRadioSkin: function () {
            var me = this,
				 $radioCheckbox = me.$skin.filter('[class^="check"], [class^="radio"]');

			if($radioCheckbox.size() == 0) return;
			var $a = $radioCheckbox.find('>a');
			var $haze = $a.find('.haze');
			var $label = me.$el.siblings('label');
			var labelText = $label.text();
			
			me._supportFocus(me.$el, $a);
			
			$a.on({
				'keydown keypress': function (e) {
					if(e.keyCode == 32 || e.keyCode == 13) {
						e.preventDefault();
						$(this).triggerHandler('click');
					}
				},
				'click': function (e) {
					e.preventDefault();
					var $this = $(this);
					$this.siblings('input').trigger('click');
					
					if(cjone.browser.isIE == true && cjone.browser.version<9){
						$this.siblings('input').triggerHandler('change');
					}
				}
			});

			//
			if(cjone.browser.isIE == true && cjone.browser.version<9){			
				$label.on({
					'click': function (e) {
						var $this = $(this);
						$this.prev().trigger('click').trigger('change');
					}
				});
			}
			
			//radio, checkbox 대체 텍스트 정리
			var changeText = function ($obj) {
				$obj.each(function () {
					if($(this).siblings('a').size() == 0) return;
					var $this = $(this),
						  $_haze = $this.siblings('a').find('.haze'),
						  labelText = $this.siblings('label').text(),
						  replaceHTML = $_haze.get(0).innerHTML,
						  text = ($this.prop('checked') == true? me.$skin.attr('data-checked-text'): me.$skin.attr('data-unchecked-text'));
									
					replaceHTML = $(replaceHTML.substring(replaceHTML.indexOf('<'))).text(text).get(0).outerHTML;
					$_haze.empty().html(labelText+replaceHTML);
				});
			};


			var disabledHTML = '<span class="hide"><span class="haze">'+(me.$el.next('label').text())+'<span>선택불가</span></span></span>';
			me.$el.siblings('a').after(disabledHTML);

			$radioCheckbox.find('input[type="checkbox"], input[type="radio"]').on({
                'change': function () {
                    var $this = $(this),
                          type = $this.attr('type'),
                          isChecked = $this.prop('checked'),
                          isDisabled = $this.prop('disabled'),
                          $a = $this.siblings('a'),
                          $span = $this.siblings('span'),
                          $closest = $this.closest('[data-skin]').attr('data-skin', 'accept').removeClass('check');
                          
					$a[(isDisabled == true ? 'addClass': 'removeClass')]('hide');
					$span[(isDisabled == true ? 'removeClass': 'addClass')]('hide');
					$this.parent()[(isDisabled == true ? 'addClass': 'removeClass')]('dis');
					
					if(isDisabled == true && isChecked == true) $closest.addClass('check');
					
                    if(type == 'radio'){
                        if(isChecked == true){
                        	var $radioGroup = $('[name="'+($this.attr('name'))+'"]').not($this);
                        	$radioGroup.parent().removeClass('on');
                        	changeText($radioGroup);
                        }   
                    }
                    $this.parent()[(isChecked ? 'addClass': 'removeClass')]('on');
                    changeText($this);
                }
			}).trigger('change');
        },
        _bindEvents: function () {
            var me = this;
        }
    });

    if (typeof define === 'function' && define.amd) {
        define('modules/formSkin', [], function (){
            return FormSkin;
        });
    }
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
    "use strict";
    /**
	 * @description 이미지들의 시퀀스 처리
	 * @class
	 * @name cjone.ui.SequenceMotion
	 * @extends cjone.ui.View
	 * @example
	 		$('[data-control="onesterMotions"] .hi').sequenceMotion('start);
	 * @sample
	 		http://dev.cjone.com:8001/cjmweb/front/main/MA_010.html
	 */
	core.ui('SequenceMotion', /** @lends cjone.ui.SequenceMotion */{
		/** jquery 플러그인명  */
        bindjQuery: 'sequenceMotion',
        defaults: {
        	motionDelayTime: 1000/24,		/** @member {Double} motionDealyTime - 프레임 기준, 시퀀스 인터벌 설정 ( 기준: 24fps ) */
        	seqManager: null						/** @member {Object} seqManager - 시퀀스를 관리하는 메니져 */
        },
        
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Double}  options.motionDealyTime - 프레임 기준, 시퀀스 인터벌 설정
         * @param {Object}  options.seqManager - 시퀀스를 관리하는 메니져
         */
        initialize: function (el, options) {
            var me = this;
            if (me.supr(el, options) === false) {
                return;
            }
            
            me.options.seqManager = me.options.seqManager || me.$el;
            me.setImages();
            me._bindEvents();
        },
        
		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
        _bindEvents: function () {
            var me = this;
        },
        
        /**
         * 해당 되는 이미지들 로딩
         * @private
         * @returns {Object} Object 이미지 로드가 끝난 객체
         * @description
         		이미지 로딩이 끝났을경우 태그속성: data-motion-status의 값이 sequenceReady로 변경됨
         *  */
        setImages: function () {
        	var me = this;
        	var $el = me.$el;
        	
			var fileUrl = $el.attr('data-file-url'),
                  start = $el.attr('data-start-num'),
                  end = $el.attr('data-end-num'),
                  $cloneTemp = $el.children().first().clone(true),
                  padLengths = end.length;
                  
            $el.empty().attr('data-motion-status', 'imageLoaded');
            for(var x=parseFloat(start); x<parseFloat(end)+1 ; x++){
                var result = cjone.number.pad(x, padLengths, '0'),
                      imgSrc = fileUrl.replace('[number]', result),
                      $cloneEl = $cloneTemp.clone(true);
                $cloneEl.attr('src', imgSrc).addClass('hide');
                $el.append($cloneEl);
            }
            $el.children().on({
                'load': function () {
                    $el.attr('data-motion-status', 'sequenceReady');
                }
            }).first().removeClass('hide');
            return $el;
        },
        /**
         * 시퀀스 이미지 시작
         * @private
         * @callback {Object} sequence:start - 시퀀스가 시작되었을때 callback
         * @callback {Object} sequence:end -  시퀀스가 종료되었을때 callback
         * @example
         		$('[data-control="onesterMotions"] .hi').sequenceMotion('start);
         		$('[data-control="onesterMotions"] .hi').sequenceMotion('start', {endSeq:-1});
         *  */
        start: function (options) {
        	var me = this,
        		  $el = me.$el;
        		  
			me.$el.attr('data-motion-status', 'sequenceReady');		//이미지들 load가 완료 되었는지 판별
			
            var motionStartTimer = null,
                  start = function () {
					var $children = $el.children(),
                    	  childrenLength = $children.size(),
                          startSeq = (options && options.startSeq ? options.startSeq : 0),
                          endSeq = (options && options.endSeq ? options.endSeq : childrenLength-1),
                          isReverse = true,
                          motionDelayTime = (options && options.motionDelayTime ? options.motionDelayTime: me.options.motionDelayTime);

					endSeq = (endSeq < 0? childrenLength+endSeq: endSeq);
					isReverse = (endSeq < startSeq ? true: false);
					
					$el.removeAttr('data-motion-status', 'sequencePlaying');
					clearTimeout(me.options.seqManager.data('sequenceTimer'));
					
					$el.triggerHandler('sequence:start');
					me.options.seqManager.data('sequenceTimer', setInterval(function () {
                   		if((isReverse == false ? startSeq >= endSeq : startSeq <= endSeq)){
                            clearTimeout(me.options.seqManager.data('sequenceTimer'));
                            $el.attr('data-motion-status', 'sequenceReady');
                            $el.triggerHandler('sequence:end');
                        }                         
                        $children.not($children.eq(startSeq).removeClass('hide')).addClass('hide');
                    	startSeq = (isReverse == false ? ++startSeq : --startSeq);
					}, motionDelayTime));
                },
                end = function () {
                };

            motionStartTimer = setInterval(function () {
                if($el.attr('data-motion-status') == 'sequenceReady'){
                    start();
                    clearTimeout(motionStartTimer);
                }
            }, 50);
            return $el;
        },
        
        /**
         * 시퀀스 확장형 function
         * @private
         * @deprecated
         *  */
        end: function (options) {
        	var me = this;
        	var $el = me.$el;
        	var $parent = $el.parent();
        	clearTimeout($parent.data('depth2Timer'));
        	$el.addClass('hide').children().addClass('hide');
        	$parent.removeAttr('data-motion-start');
        },
        
        /**
         * 연속으로 이어지는 모션
         * @private
         * @deprecated
         *  */
        groupMotion: function (motionArray) {
        	var me = this;
        	var $parent = me.$el; 
            var $el = null,
                  motionIndex = 0,
                  groupInterval = setInterval(function () {
                    if(!$parent.attr('data-motion-start')){
                        motionArray[motionIndex].sequenceMotion('start');
                        ++motionIndex;
                    }
                    if(motionIndex == motionArray.length) clearTimeout(groupInterval);
                  }, 0);
            return motionArray;
        }
    });

    if (typeof define === 'function' && define.amd) {
        define('modules/sequenceMotion', [], function (){
            return SequenceMotion;
        });
    }
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
    "use strict";
    /**
	 * @description 시스템 숫자 카운트 모션
	 * @class
	 * @name cjone.ui.charMotion
	 * @extends cjone.ui.View
	 * @sample
	 		http://dev.cjone.com:8001/cjmweb/front/mypage/MP_010_010.html
	 * @example
	 		$('[data-control="onesterMotions"] .hi').sequenceMotion('start);
	 */
    core.ui('CharMotion', /** @lends cjone.ui.charMotion*/{
    	/** jquery 플러그인명  */
        bindjQuery: 'charMotion',
        /**	기본 옵션값 선언부	*/
        defaults: {
        },
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         */
        initialize: function (el, options) {
            var me = this;
            if (me.supr(el, options) === false) {
                return;
            }
            me._bindEvents();
        },
        
        /**
         * 실제 카운트모션을 실행시키는 함수
         * @private
         * @param {Object} $obj - 대상 object
         * @param {Integer} val - 정지시킬 value값
         *  */
        _setNum: function ($obj, val) {
        	var ran = -1,
        		  rollCount = 0,			/** @member {Integer} rollCont - loop count 변수 */
        		  maxRollCount = 2;	/** @member {Integer} maxRollCount - max loop 카운트 */
	        var timer = setInterval(function () {
	            ran = (++ran%10);
	        	$obj.text(ran);
				if(ran == val){
	        		++rollCount;
	        	}
	        	if(rollCount == maxRollCount)	clearTimeout(timer);
	        }, 50);
	        return $obj;
	    },
    	/**
    	 * 숫자들을 태그로 감싸주는 함수
    	 * @private
    	 * @example
    	 		<span data-control="rundomNum">12,43,P,32</span>의 태그가
				<span>1</span><span>2</span>,<span>4</span><span>3</span>,P,<span>3</span><span>2</span>형식으로 만들어짐
		 * @important
		 		숫자의 간격으로 레이아웃이 움직이는 경우가 발생 ( 1, 0 등등 )
    	 *  */
        runUp: function () {
			var me = this,
	  			 val = me.$el.attr('data-val') || me.$el.text(),
		         str = '',
		         $target = '',
		         target = null;
		         
			if(!me.$el.attr('data-val')) me.$el.attr('data-val', me.$el.text());
		         
		    for(var x=0 ; x<val.length ; x++){
		       	if(/[0-9]/.test(val.charAt(x))){
		            str = str.concat('<span class="d-digit" data-val="'+(val.charAt(x))+'">0</span>');
		        }else{
		            str = str.concat('<span class="d-char">'+(val.charAt(x))+'</span>');
		        }
		    }
		    me.$el.empty().append(str);
		    $target = me.$el.find('.d-digit');
		    
		    $target.each(function (idx, cell) {
		        var $this = $(this),
		              num = ($target.size()-idx)-1,
		              $tag = $target.eq(num);
		              
		        $this.delay(300*idx).queue(function () {
		            me._setNum($tag, $tag.attr('data-val'));
		        });
		    });
        },
        _bindEvents: function () {
            var me = this;
        }
    });

    if (typeof define === 'function' && define.amd) {
        define('modules/charMotion', [], function (){
            return CharMotion;
        });
    }
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
	var $win = $(window);
	/**
	 * @description cell 영역에 마우스 포인터 위치 체크후 좌표값이동
	 * @class
	 * @name cjone.ui.MoveToElements
	 * @extends cjone.ui.View
	 */
	core.ui('MoveToElements', /** @lends cjone.ui.MoveToElements */{
		/** jquery 플러그인명  */
		bindjQuery:'moveToElements',
		$statics: {
		},
		/**	기본 옵션값 선언부	*/
		defaults: {
		},
		/**	selector 선언부		*/
		selectors: {
			list: ' li',
			parentObj: null
		},

		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         */
		initialize: function (el, options) {
			var me = this;
			if(me.supr(el, options) === false) { return; }
			
			me.$parentObj = $(me.selectors.parentObj);
			
			if(!me.$list.attr('style')){
				me.$list.each(function () {
					var $this = $(this);
					$this.css({
						'top': $this.css('top'),
						'left': $this.css('left')
					});
				});
			}

            me._setPosition();
            
            if(me.$parentObj.size() > 0){
            	me._pullMe();
            }else{
            	me._pushOther();
            }
            me._bindEvent();
		},
        
        /**
        * cell들의 포지션을 재정리
        * @private
        */
        _setPosition: function () {
            var me = this,
            	 timer = null,
				 before = {};
            
			me.$list.each(function () {
				var $this = $(this),
					 attr = $this.attr('style').split(';'),
					 css = {};
					 
				for(var key in attr){
					if(attr[key]){
						var _attr = attr[key].split(':');
						$this.attr('data-'+$.trim(_attr[0]), $.trim(_attr[1]));
					};
				}
			});
        },
        
        /**
         * cell들의 포지션 정리후 처리 확장 함수
         * @private
         * @deprecated
         *  */
        _pullMe: function () {
        	var me = this,
        		 before = {},
    			 timer = null;

        	me.$el = me.$parentObj;

			me.$el.off('mouseenter mousemove mouseleave').on({
				'mouseenter': function (e) {
					before.x = e.offsetX; 
					before.y = e.offsetY; 
			  	},
				'mousemove': function (e) {
					me._setMotion(false);

					clearTimeout(timer);
			    	timer = setTimeout(function () {
			      		before.x = e.offsetX;
			      		before.y = e.offsetY;
			    	}, 50);
			
			    	var dir = {
			      		left: (before.x < e.offsetX ? -1: +1),
			      		top: (before.y < e.offsetY ? -1: +1)
			    	};

			    	me.$list.stop().each(function (idx) {
			      		var $this = $(this),
			           		  pos = $this.position(),
			          		  left = pos.left+(0.2*dir.left),
							  top = pos.top+(0.2*dir.top);
			      
			      		$this.css({
							left: left,
			        		top: top
			      		});      
			    	});
				},
				'mouseleave': function () {
					setTimeout(function () {
						me.$list.each(function () {
				      		var $this = $(this);
				      		$this.stop().animate({
				        		top: $this.attr('data-top'),
				        		left: $this.attr('data-left')
				      		});
				    	});
				    	me._setMotion(true);
				  }, 50);
			  	}
			});
        },
        /**
         * 움직이는 모션 처리 함수
         * @private
         * @deprecated
         *  */
        _setMotion: function (isRun) {
        	var me = this,
        	 	 className = 'zoomMotion';
        	
        	me.$list.each(function () {
        		if(isRun == true){
        			$(this).randomMotion(className);
        		}else{
        			$(this).removeClass(className);
        		}
        	});
        },
        
        /**
         * 선택된 항목 제외 나머지 것들을 이동
         * @private
         *  */
        _pushOther: function () {
        	var me = this,
				 $el = null,
				 timer = null,
				 before = {};
				 
			me.$list.on('click', 'a', function () {
				var $this = $(this);
				me.$list.css('z-index', '').triggerHandler('mouseleave');
			});
				 
			me.$list.off('mouseenter mousemove mouseleave').on({
				'mouseenter': function (e) {    
					$el = $(this);  
					before.x = e.offsetX; 
					before.y = e.offsetY; 
					//$el.css('z-index', 9999);
					
					$el.removeClass('zoomMotion').addClass('tada');
				},
				'mousemove': function (e) {
					me._setMotion(false);    
					clearTimeout(timer);
       
					timer = setTimeout(function () {
    					before.x = e.offsetX;
    					before.y = e.offsetY;
					}, 50);
    
					var dir = {
						left: (before.x < e.offsetX ? -1: +1),
						top: (before.y < e.offsetY ? -1: +1)
					};

					me.$list.stop().not($el).each(function (idx) {
						var $this = $(this),
							  pos = $this.position(),
							  left = pos.left+(0.2*dir.left),
							  top = pos.top+(0.2*dir.top);
					      	  
					  	$this.css({
					    	left: left,
					    	top: top
					  	});
					});
  				},
				'mouseleave': function () {
					if(!$el) return;
					$el.removeClass('tada');
					setTimeout(function () {
      					me.$list.not($el).each(function () {
        					var $this = $(this);
        					$this.stop().animate({
          						top: $this.attr('data-top'),
          						left: $this.attr('data-left')
        					});      
      					});
      					$el.css('z-index', '');
      					
      					me._setMotion(true);
					}, 50);
				}
			});
        },
		
		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
		_bindEvent: function () {			
		}
	});
	
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
	/**
	 * @description 스크롤 이벤트 캐치후 특정 태그를 상단에 고정시키는 클래스
	 * @class
	 * @name cjone.ui.Stamp
	 * @extends cjone.ui.View
	 * @sample
			http://dev.cjone.com:8001/cjmweb/front/stamp/ST_010_030.html 		
	 * @example
	 		$('selector').stamp('openStamp', $object);
	 */
	var $win = $(window);
	core.ui('Stamp', /** @lends cjone.ui.Stamp */{
		/** jquery 플러그인명  */
		bindjQuery:'stamp',
		$statics: {
		},
		/**	기본 옵션값 선언부	*/
		defaults: {
            openText: '닫기',		/** @member {String} openText - 열려있을때의 대체 텍스트 */
            closeText: '열기'		/** @member {String} closeText - 닫혀있을때의 대체 텍스트 */
		},
		/**	selector 선언부		*/
		selectors: {
            toggleStamp: '[data-control="toggleStamp"]',
            stampItem: '[data-handler="stampItem"]',
            stampDetail: '[data-handler="stampDetail"]',
            stampClose: '[data-control="closeStamp"]'
		},

		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         */
		initialize: function (el, options) {
			var me = this;
			if(me.supr(el, options) === false) { return; }
            
            me._bindEvent();
		},
		
		/**
		 * 스탬프가 열릴때 실 컨텐츠의 높이가 가변인 부분이 있어 외부 함수로 지원
		 * @public
		 *  */
		reposition: function (dataSet) {
			var me = this,
				  isOpen = dataSet.isOpen,
				  $this = dataSet.$this,
				  selectedIndex = me.$toggleStamp.index($this);

			var $stampItem = $this.closest(me.$stampItem).toggleClass('on'),
				  $parentClosest = $stampItem.parent();
		},
		
		/**
		 * 스탬프를 여는 함수
		 * @public
		 *  */
		openStamp: function ($el) {
			var me = this,
				  $this = $el,
				  $stampItem = $this.closest(me.$stampItem).toggleClass('on'),
				  isOpen = $stampItem.hasClass('on'),
				  $parentClosest = $stampItem.parent();
				  
			me.$stampItem.not($stampItem).removeClass('on');
			me.$stampItem.parent().removeAttr('style').removeClass('open');
			//me.$toggleStamp.find('.haze').text(me.options.closeText);
			$this.closest(me.$stampItem).find('.haze').text(me.options.closeText);
					
			if(isOpen == true){
				$parentClosest.addClass('open');
				$this.closest(me.$stampItem).find('.haze').text(me.options.openText);
				
				var height = $stampItem.find(me.$stampDetail).outerHeight(true)+$stampItem.outerHeight(true);
				$parentClosest.height(height);
				
				$stampItem.find(me.$stampClose).off('click.close').one({
					'click.close': function () {
						me.closeStamp($this);	
					}
				});
			}
		},
		
		/**
		 * 스탬프를 닫는 함수
		 * @public
		 *  */
        closeStamp: function ($el) {
        	var me = this,
        		  $this = $el;
        	me.openStamp($this);
        },
        
		/**
		 * DOM에 이벤트설정
		 * @memberOf Stamp
		 * @name _bindEvent
		 * @private
		 *
		 * @example
		 * Stamp._bindEvent();
		 */
		_bindEvent: function () {
			var me = this;
			me.$stampItem.filter(':odd').addClass('even');		//짝수일때 화살표 방향때문에 even클래스 추가
		}
	});
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
	var $win = $(window);
	/**
	 * @description 스크롤 이벤트 캐치후 특정 태그를 상단에 고정시키는 클래스
	 * @class
	 * @deprecated
	 * @name cjone.ui.FixedScroll
	 * @extends cjone.ui.View
	 * @example
	 		$('[data-control="fixedScroll"]').fixedScroll();
	 */
	core.ui('FixedScroll', /** @lends cjone.ui.FixedScroll */{
		/** jquery 플러그인명  */
		bindjQuery:'fixedScroll',
		$statics: {
		},
		/**	기본 옵션값 선언부	*/
		defaults: {
			margin: -10		/** @member {Integer} margin - 기준점으로 부터 추가/ 감소값  */
		},
		/**	selector 선언부		*/
		selectors: {
            indicatorClickable: 'a',
            target: $('[data-handler="scrollHandler"]')
		},

		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Integer}  options.margin - 기준점으로 부터 추가/ 감소값
         */
		initialize: function (el, options) {
			var me = this;
			if(me.supr(el, options) === false) { return; }
			
            me._horizoneScroll();
            me._bindEvent();
		},
        
		/**
		 * 가로 메뉴의 fixed 클래스 추가
		 * @private
		 * @example
		 		FixedScroll._horizoneScroll();
		 */
		_horizoneScroll: function () {
			var me = this,
                  checkScroll = function () {
                      me.$el.removeClass('fixed');
                      if($win.scrollTop() > me.$el.offset().top){
                          me.$el.addClass('fixed');
                      }
                  };
            
            $win.on({
               'scroll': function () {
					checkScroll();
               }
            });
		},
		
		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
		_bindEvent: function () {
			var me = this,
                  setClass = function (selectedIndex) {
                      me.$indicatorClickable.parent().not(me.$indicatorClickable.eq(selectedIndex).parent().addClass('on')).removeClass('on');
                      me.$indicatorClickable.parent().setHaze(me.$el);
                  };
            
            //키보드 접근에 따라 상단 fixed의 클래스 처리		@IE7 확인해야 함
            core.util.supportFocus($('[data-control="fixedScroll"]'), {callback: function (datas) {
                var $el = datas.$obj,
                      selectedIndex = 0;
                
				setTimeout(function () {
					selectedIndex = 0;
					me.$target.each(function () {
						var $_this = $(this);
						selectedIndex = me.$target.index($el.closest('[data-handler="scrollHandler"]'));
		                setClass(selectedIndex);
						return false;
					});
				}, 300);
            }});
            
            me.$el.on({
                'focusin': function () {
                    me.$el.removeAttr('data-action');
                }
            });
            
            //상단 fixed의 항목을 클릭했을때
            me.$indicatorClickable.on({
                'click': function (e) {
                    e.preventDefault();
                    var $this = $(this),
                          $target  = $(cjone.getHref($this.attr('href'))),
                          margin = me.options.margin || parseFloat($target.attr('data-margin')) || 0,
                          offset = me.$el.outerHeight(true)+margin;
                    
                    me.$el.attr('data-action', 'click');
                    cjone.util.scrollToElement($target, {offset: offset, duration: 500, complete: function () {
                        offset = me.$el.outerHeight(true)+margin;
                        cjone.util.scrollToElement($target, {offset: offset, duration: 500, complete: function () {
                            var selectedIndex = me.$indicatorClickable.parent().index($this.parent());
                            setClass(selectedIndex);
                        }});
                    }});
                    
                },
                'keydown': function (e) {
                   if(e.shiftKey == false && e.keyCode == 9){
                       if(!me.$el.attr('data-action')){
                           return;
                       }
                        var selectedIndex = me.$indicatorClickable.parent().index(me.$indicatorClickable.parent().filter('.on'));
                        me.$target.each(function (idx) {
                            if(idx<selectedIndex) return;
                            
                            var $_this = $(this), 
                                  $first = me.$target.eq(idx).find('a, button').first();
                            if($first.size()>0){
                                setTimeout(function () {
                                    $first.focus();
                                }, 50);
                                return false;
                            }
                        });
                    }
                }
            });
            
            //윈도우 스크롤시 indicator floating
			$win.on({
				'scrollend': function (e) {
                    var selectedIndex = 0;
                    
                    me.$target.each(function (idx, cell) {
                        var $_this = $(this);
                        if($win.scrollTop()+(me.$el.outerHeight(true)+10) > $_this.offset().top){
                            selectedIndex = me.$target.index($_this);
                        }
                    });
                    setClass(selectedIndex);
                    me.$indicatorClickable.parent().not(me.$indicatorClickable.eq(selectedIndex).parent().addClass('on')).removeClass('on').children('a').removeClass('focus');
				}
			});
		},
		/**
		 * selector 재설정
		 * @private
		 *  */
		updateSelector: function () {
			var me = this;
			me.$target = $('[data-handler="scrollHandler"]');
			me.$indicatorClickable = me.$el.find(me.selectors.indicatorClickable);
		}
	});
})(jQuery, window[LIB_NAME]);


(function ($, core) {
   "use strict";
    /**
     * @description 리스트내의 유동적인 요소들의 높이값을 짧은쪽 기준으로 재정렬
     * @class
     * @name cjone.ui.RePosition
     * @extends cjone.ui.View
     * @example
     		http://dev.cjone.com:8001/cjmweb/front/search/SE_010_020.html
     		$('selector').reposition();
	 * @sample
	 		$('selector').reposition('updateLayout');		//ajax 형태의 더보기후 재정렬 지원 함수
			'reposition:end'		//더보기 재정렬후 callback 호출 되는 함수

			$('selector').on({
				'reposition:end': function () {
					alert('callback end');
				}
			});
     */
    core.ui('RePosition', /** @lends cjone.ui.RePosition */{
    	/** jquery 플러그인명  */
        bindjQuery:'rePosition',
        $statics: {
            ON_CLICK: 'click'
        },
        /**	기본 옵션값 선언부	*/
        defaults: {
            marginTop: 0,	/** @member {Double} marginTop - 추가적인 높이 설정값 */
            marginLeft: 0		/** @member {Double} marginLeft - 추가적인 좌측 설정값 */
        },
        /**	selector 선언부		*/
        selectors: {
            slide: '[data-handler="item"]'
        },

		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Doubler}  options.marginTop - 추가적인 높이 설정값
         * @param {Double}  options.marginLeft - 추가적인 좌측 설정값
         */
        initialize: function (el, options) {
            var me = this;
            if(me.supr(el, options) === false) { return; }

            core.$win = $(window);			

            me._bindEvent();

            setTimeout(function () {
                me._rePositionCell();
            }, 0);			
        },
        
        /**
         * 추가적인 ajax 로드나 리사이즈 이벤트 발생시 레이아웃 재설정
         * @public
         *  */
        updateLayout: function () {
           var me = this;

            me.$slide = me.$el.find(me.selectors.slide);
            me.$slide.removeAttr('style');
            me._rePositionCell();
        },
        
        /**
         * 일정 해상도 이하로 내려갔을 때 Object들의 높이값을 재 수정
         * @private
         *  */
        _rePositionCell: function (e, data) {
            var me = this;

            var maxHeight = 0,
                  marginTop = me.options.marginTop,		//윗쪽으로 붙일 maring값
                  marginLeft = me.options.marginLeft;		//좌측으로 붙일 maring값

            var rowCount = Math.floor(me.$el.width()/(me.$slide.last().width())),		//가로열 카운트
                  colCount = 0,																							//세로열 카운트
                  width = me.$slide.last().outerWidth(true);

            function getTop($el){
                return $el.position().top+$el.outerHeight(true);
            }
            function getLeft($el){
                return $el.position().left;
            }

            var posArray = [],
                  height = 0;

            me.$slide.each(function (idx, cell) {
                var $this = $(this), 
                      posX = 0, 
                      posY = 0;

                if(colCount == 0){				//첫번째 열
                    var $before = $this.prev();					$before = ($before.size() == 0 ? $this: $before);
                    posX = (idx == 0 ? 0 : $before.position().left+$before.outerWidth(true));
                }else{								// 두번째 열부터
                    if(idx == rowCount){
                        for(var x=0 ; x<rowCount ; x++){
                            posArray.push([getLeft(me.$slide.eq(x)), getTop(me.$slide.eq(x)), me.$slide.eq(x)]);
                        }
                    }

                    var tempY = posArray[0][1];
                    for(var x=0 ; x<posArray.length ; x++){
                        if(posArray[x][1] <= tempY){
                            tempY = posArray[x][1];
                        }
                    }

                    //if(idx>6) return;

                    for(var x=0 ; x<posArray.length ; x++){
                        if(tempY == posArray[x][1]){
                            posX = posArray[x][0];
                            posY = posArray[x][1];

                            posArray[x] = [posX, posY+getTop(me.$slide.eq(idx)), me.$slide.eq(idx)];
                            break;
                        }
                    }
                }
                $this.setPosition({posX: posX, posY: posY, usingCSS3: false});

                if(idx%rowCount == rowCount-1) ++colCount;

                var tempHeight = $this.position().top+$this.outerHeight(true);
                if(tempHeight > height) height = tempHeight;

            });
            me.$el.height(height);
            me.$el.trigger('reposition:end');
        },

		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
        _bindEvent: function () {
            var me = this;

            $(window).on({
                'resizeend': function (e) {
                    me.updateLayout();
                }
            });
        }
    });
    ///////////////////////////////////////////////////////////////////////////////////////

    if (typeof define === "function" && define.amd) {
        define(['lib/jquery'], function() {
            return RePosition;
        });
    }
})(jQuery, window[LIB_NAME]);

(function ($, core, undefined) {
	/**
	 * @description 토글 지원
	 * @class
	 * @name cjone.ui.Toggle
	 * @extends cjone.ui.View
	 * @sample
	 		http://dev.cjone.com:8001/cjmweb/front/mypage/MP_010_010.html
	 */
    var toggle = core.ui('Toggle', /** @lends cjone.ui.Toggle */{
    	/** jquery 플러그인명  */
        bindjQuery: 'toggle',
        /**	기본 옵션값 선언부	*/
        defaults: {
            onClass: 'on',
            handlerTarget: 'href',					/** @member {String} handlerTarget - 컨트롤 시키는 tag( click 요소 ) */
            handler: '[data-handler]',				/** @member {String } handler - 컨트롤 되는 대상의 tag */
            openText: '닫기',							/** @member {String} openText - 열려 있는 상태의 대체 text */
            closeText: '열기',							/** @member {string} closeText - 닫혀 있는 상태의 대체 text */
            delayTime: 0,								/** @member {Integer} delayTime - 애니메이션 효과가 있을경우의 시간설정 */
            type: null, 									/** @member {Object} type - type 설정 */
            skipText: [] 								/** @member {Array} skipText - 스킵할 text 설정 */
        },
        /**	selector 선언부		*/
        selectors: {
            handler: null,
            handlerTarget: null
        },
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {String}  options.handlerTarget - 컨트롤 시키는 tag( click 요소 )
         * @param {String}  options.handler - 컨트롤 되는 대상의 tag
         * @param {String}  options.openText - 열려 있는 상태의 대체 text
         * @param {String}  options.closeText - 닫혀 있는 상태의 대체 text
         * @param {Integer}  options.delayTime - 애니메이션 효과가 있을경우의 시간설정 
         * @param {Object}  options.type - type 설정 
         * @param {Array}  options.skipText - 스킵할 text 설정
         */
        initialize: function (el, options) {
			var me = this;
			if (me.supr(el, options) === false) { return; }
			
            me.$handler = me.$el.find(me.options.handler);
            me.$handlerTarget = me.$el.closest('body').find(cjone.getHref(me.$el.attr(me.options.handlerTarget)));
            
            if(me.options.handler == 'me'){
            	me.$handler = me.$handler.andSelf();
            }
            if(me.$el.context.tagName.toUpperCase() === 'A' && me.options.handlerTarget && me.$el.attr('href').indexOf('#') == 1){
            	me.$handlerTarget = me.$el.closest('body').find(me.options.handlerTarget);
            }
			me._bindEvents();
		},
        /**
		 * 이벤트 바인딩
		 * @param {callback} toggle:end - 토글이 완료 된후 callback
		 * @private
		 */
        _bindEvents: function () {
            var me = this,
                  defer = $.Deferred();
            
            defer.resolve();
            
            me.$el.on({
                'click': function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    var $this = $(this),
                          isOpen = me.$el.toggleClass(me.options.onClass).hasClass(me.options.onClass);
                    
                    me.$handlerTarget.toggleClass('hide');
                    
                    switch(me.options.type){
                        case 'gnb':
                        break;
                        
                        default:
                            me.$handlerTarget[(isOpen == true ? 'hide': 'show')]()[(isOpen == true ? 'slideDown': 'slideUp')](me.options.delayTime, function () {
                                me.$handlerTarget.removeAttr('style');
                                if(me.$el.attr('href') != me.options.skipText[0]){
                                	me.$handler.text((isOpen == true? me.options.openText : me.options.closeText));
                                }
                            });
                        break;
                    }
                    defer.done(function () {
                        me.$el.trigger('toggle:'+(isOpen == true? 'open' : 'close'), {data: me});
                        me.$el.trigger('toggle:end', {data:me, isOpen: isOpen});
                    });
                }
            });
        }
    });
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
	/**
	 * @class
	 * @name cjone.ui.HoverUI
	 * @extends cjone.ui.View
	 */
    var hoverUI = core.ui('HoverUI', /** @lends cjone.ui.HoverUI */{
    	/** jquery 플러그인명  */
        bindjQuery: 'hover',
        /**	기본 옵션값 선언부	*/
        defaults: {
            handler: 'test',			/** @deprecated */
            onClass: 'on',				/** @member {String} onClass - on 되었을때 설정되는 클래스 명 */
            handlerTarget: '>li',	/** @member {String} handlerTarget  - */
            handler: 'li>a'			/** @member {String} handler - */
        },
        /**	selector 선언부		*/
        selectors: {
            handler: null,
            handlerTarget: null
        },
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Boolean}  options.onClass - on 되었을때 설정되는 클래스 명
         * @param {Boolean}  options.handlerTarget - 
         * @param {Boolean}  options.handler - 
         */
        initialize: function (el, options) {
			var me = this;
			if (me.supr(el, options) === false) { return; }
            
            me.$handler = me.$el.find(me.options.handler);
            me.$handlerTarget = me.$el.find(me.options.handlerTarget);
            
			me._bindEvents();
		},
        /**
		 * 이벤트 바인딩
		 * @private
		 */
        _bindEvents: function () {
            var me = this;

            me.$handler.on({
                'mouseenter focus': function (e) {
                    var selectedIndex = me.$handler.index(this);
                    me.$handlerTarget.not(me.$handlerTarget.eq(selectedIndex).addClass(me.options.onClass)).removeClass(me.options.onClass);
                },
                'blur mouseleave': function (e) {
                    var selectedIndex = me.$handler.index(this);
                    me.$handlerTarget.eq(selectedIndex).removeClass(me.options.onClass);
                }
            });
        }
    });
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
    "use strict";
    /*
	 * @description 기타 확장 함수
	 */
    if (core.ui.Accordion) { return; }

    var context = window,
        ui  = core.ui,
        disabledAccordion = $('body').hasClass('ui_disabled_accordion');			//ui_disabled_accordion 클래스 제외 열리는 항목으로 설정 

    core.extend(core, /** @lends cjone.ui.View*/{
        screenSize: {
            small: 768,
            big: 1024
        },
        /**
         * IE7, 8에서 href의 값이 fullURL로 떨어지는 현상 방지용
         * @public
         *  */
        getHref: function (str) {
        	if(!str || str === '#') return;
            return '#'+str.split('#')[1];
        },
        /**
        * 스크린 사이즈별 status 값 리턴
        * @public
        * @returns {String} ['small' | 'medium' | 'big']
        */
        getScreenStatus: function () {
            if(cjone.util.getWinWidth() <= this.screenSize['small']){
                return (Object.keys(this.screenSize)[0]);
            }else if(cjone.util.getWinWidth() > this.screenSize['big']){
                return (Object.keys(this.screenSize)[1]);
            }else{
                return 'medium';
            }
        }
    });
    
    /**
     * @description 아코디언
     * @class
     * @name cjone.ui.Accordion
     * @extends cjone.ui.View
     * @sample http://dev.cjone.com:8001/cjmweb/front/member/EX_100_120.html
     */
    var Accordion = ui('Accordion', /**@lends cjone.ui.Accordion */{
    	/** jquery 플러그인명  */
        bindjQuery: 'accordion',
        /**	기본 옵션값 선언부	*/
        defaults: {
            singleOpen: true,               										/** @member {Boolean} singleOpen - 단일열림 / 다중열림 여부 */ 
            toggleButtonType: '',												/** @member {String} toggleButtonType - 토글버튼 유형.(현재 미사용)*/ 
            duration: 0,                   											/** @member {Double} duration - 펼쳐지거나 닫혀지거나 할 때 애니메이션 속도 */ 
            activeClass: "",        												/** @member {String} activeClass - 활성화됐을 때 추가할 css 클래스명 */ 
            selectedClass: 'on',        											/** @member {String} selectedClass - 버튼이 토글될 때 추가할 css 클래스명 */ 
            itemClosest: 'li',
            itemSelector: '>li',
            toggleSelector: " button",  										/** @member {String} toggleSelector - 토글버튼 */ 
            contentSelector: ">:eq(1)",       								/** @member {String} contentSelector - 컨텐츠 */ 
            toggleTextFileld: " [data-handler='toggleText']",        /** @member {String} toggleTextField - 버튼에 따른 텍스트 내용이 바뀔 부분 */
            openText: '닫기',
            closeText: '열기',
            type: null
        },

		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Boolean}  options.singleOpen - 단일열림 / 다중열림 여부
         * @param {String}  options.toggleButtonType - 토글버튼 유형.(현재 미사용)
         * @param {Double}  options.duration - 펼쳐지거나 닫혀지거나 할 때 애니메이션 속도
         * @param {String}  options.activeClass - 활성화됐을 때 추가할 css 클래스명
         * @param {String}  options.selectedClass - 버튼이 토글될 때 추가할 css 클래스명
         * @param {String}  options.toggleSelector - 토글버튼
         * @param {String}  options.contentSelector - 컨텐츠
         * @param {String}  options.toggleTextField - 버튼에 따른 텍스트 내용이 바뀔 부분
         */
        initialize: function (el, options) {
            var me = this;
            
            if (me.supr(el, options) === false || disabledAccordion) {
                return;
            }
            
            me._bindEvent();
            
            // option에 기본적으로 오픈시킬 인덱스 값이 있으면 오픈시킨다.
            var openIndex = me.$el.data('openIndex');
            if (openIndex !== undefined) {
                if(openIndex === 'all') {
                    // 전체 오픈
                    me.expandAll();
                } else {
                    // openIndex에 해당하는 컨텐츠를 오픈
                    me.expand(openIndex, false);
                }
            }
        },

		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
        _bindEvent: function () {
            var me = this,
                o;
            
            // 토글버튼 클릭됐을 때
            me.on("click dblclick", me.options.itemSelector + me.options.toggleSelector, function (e) {
                me.updateSelectors();
                
                var $this = $(this),
                    $item = $this.closest(me.options.itemClosest),
                    index = me.$items.index($item);
                    
				if(cjone.util.getWinWidth() <= 768 && (me.options.type == 'gnb' && $this.siblings().size() > 0)) e.preventDefault();

                // 열려있으면 닫고
                if ($item.hasClass(me.options.selectedClass)) {
                    me.collapse(index, true, function(){
                        $item.addClass(me.options.activeClass);
                    });
                } else {
                    // 아니면 열고
                    me.expand(index, true);
                }
            });

            if (o = me.options.accordGroup) {
                // 아코디언 요소가 따로 떨어져 있는 것을 data-accord-group속성을 묶고,
                // 하나가 열리면 그룹으로 묶여진 다른 아코디언에 열려진게 있으면 닫아준다.
                me.on('accordionbeforeexpand', function (e) {
                    $('.ui_accordion[data-accord-group=' + o + '], .ui_accordion_list[data-accord-group=' + o + ']')
                        .not(me.$el).scAccordion('collapse').find(me.options.itemSelector).removeClass(me.options.selectedClass);
                });
            }
        },

        /**
         * 이벤트 및 selector의 요소들을 재정의
         * @public
         *  */
        updateSelectors: function() {
            var me = this;

            if (me.$items && me.$items.size() > 0) {
                me.$items = me.$items.add(me.$items.last().nextAll());
            } else {
                me.$items = me.options.itemSelector ? me.$(me.options.itemSelector) : me.$el;
            }
        },

        /**
         * slide effect collapse handler
         * @private
         * @param { }
         */
        collapse: function (index, isAni, cb) {
            var me = this,
                opts = me.options,
                data = {};           // 애니메이션 시간
            
            if (arguments.length === 0 || index === null) {
                // index가 안넘어보면 현재 활성화된 패널의 index를 갖고 온다.
                index = me.$items.filter('.' + opts.selectedClass).index();
            }

            if (index < 0) { return; }

            data.index = index;
            data.header = me.$items.eq(index);
            data.content = data.header.find(opts.contentSelector);

            // 열리기 전에 이벤트 발생
            if (me.triggerHandler('accordionbeforecollapse', data) === false){ return; }
            if(isAni !== false) {
                // 애니메이션 모드
                //if(this.isAnimate) { return; }
                data.header.removeClass(opts.selectedClass);
                data.content.slideUp(opts.duration, function () {
                    // 열려진 후에 이벤트 발생
                    me.trigger('accordioncollapse', data);
                    me.trigger('accordion:close', data);
                    me._updateButton(index, false);
                    cb && cb();
                });
            } else {
                // 일반 모드
                data.header.removeClass(opts.selectedClass);
                data.content.hide();
                // 열려진 후에 이벤트 발생
                me.trigger('accordioncollapse', data);
                me.trigger('accordion:close', data);
                me._updateButton(index, false);
                cb && cb();
            }
        },


        /**
         * slide effect expand handler
         * @param { }
         */
        expand: function (index, isAni, cb) {
            var me = this,
                opts = me.options,
                oldItem, oldIndex, newItem, data;

            if (arguments.length === 0) {
                return;
            }

            newItem = me.$items.eq(index);
            oldItem = me.$items.filter('.'+opts.selectedClass);
            oldIndex = oldItem.index();
            data = {
                index: index,
                header: newItem,
                oldIndex: oldIndex,
                oldHeader: oldIndex < 0 ? null : oldItem
            };

            if (data.index === data.oldIndex) { return; }

            data.content = newItem.find(opts.contentSelector);
            data.oldContent = oldIndex < 0 ? null : oldItem.find(opts.contentSelector);

            if (me.triggerHandler('accordionbeforeexpand', data) === false) { return; }
            
            if(isAni !== false) {
				// 애니메이션 사용
                me.isAnimate = true;
                if (opts.singleOpen && data.oldHeader) {
					// 하나만 열리는 모드
                    data.oldHeader.removeClass(opts.selectedClass);
                    data.oldContent.slideUp(opts.duration, function () {
                        me._updateButton(data.oldIndex, false);
                        cb && cb();
                    });
                }
                data.header.addClass(opts.selectedClass);
                data.content.slideDown(opts.duration, function () {
                    me.isAnimate = false;
                    me.trigger('accordionexpand', data);
                    me.trigger('accordion:open', data);
                    me._updateButton(index, true);
                    cb && cb();
                });
            } else {
				// 에니메이션 미사용
                if (opts.singleOpen) {
					// 하나만 열리는 모드
                    data.oldHeader.removeClass(opts.selectedClass);
                    data.oldContent.hide();
                }
                data.header.addClass(opts.selectedClass);
                data.content.show();
                me.trigger('accordionexpand', data);
                me.trigger('accordion:open', data);
                me._updateButton(index, true);
                cb && cb();
            }
        },

        getActivate: function () {
            var me = this,
                opts = me.options,
                item = me.$items.filter('.'+opts.selectedClass);

            if (item.length === 0) {
                return {
                    index: -1,
                    header: null,
                    content: null
                };
            } else {
                return {
                    index: item.index(),
                    header: item,
                    content: item.find(opts.contentSelector)
                };
            }
        },

        _updateButton: function(index, toggle) {
            var me = this,
                sc = me.options.activeClass,
                tc = me.options.toggleButtonClass,
                $btn = me.$items.eq(index).find(me.options.toggleTextFileld);
            
            if ($btn.is('a')) {
                if(toggle) {
                    $btn.parent().parent().removeClass(sc).addClass(tc);
                    $btn.find('span.ui_accord_text').html(function () {
                        return $btn.attr('data-close-text');
                    }).parent().parent().replaceClass('btn_open', 'btn_close');
                } else {
                    $btn.parent().parent().removeClass(tc);
                    $btn.find('span.ui_accord_text').html(function () {
                        return $btn.attr('data-open-text');
                    }).parent().parent().replaceClass('btn_close', 'btn_open');
                }
            } else {
                if(toggle) {
                    $btn.html(function () {
                        return me.options.openText;
                    });
                } else {
                    $btn.html(function () {
                        return me.options.closeText;
                    });
                }
            }
        },

        collapseAll: function() {
            var me = this,
                count = me.$items.size();

            me.collapseMode = 'all';
            for(var i = 0; i < count; i++) {
                me.collapse(i, false);
            }
            me.collapseMode = null;
        },

        expandAll: function() {
            if(this.options.singleOpen){ return; }
            var me = this,
                count = me.$items.size();

            me.expandMode = 'all';
            for(var i = 0; i < count; i++) {
                me.expand(i, false);
            }
            me.expandMode = null;
        }
    });


    if (typeof define === "function" && define.amd) {
        define('modules/accordion', [], function ($) {
            return Accordion;
        });
    }

})(jQuery, window[LIB_NAME]);

(function ($, core, undefined) {
    "use strict";
	/**
     * @description 가상의 스크롤을 생성 ( formSkin- select의 리스트박스에서 사용됨 ) 
	 * @class 
	 * @name cjone.ui.Scrollview
	 * @extends cjone.ui.View
	 */
    if (core.ui.Scrollview) { return; }

    $.easing.smooth = function (x, t, b, c, d) {
        var ts = (t /= d) * t, tc = ts * t;
        return b + c * (-1 * ts * ts + 4 * tc + -6 * ts + 4 * t);
    };

    var cssTransform = core.css3.prefix('transform');

    var Scrollview = core.ui('Scrollview', /** @lends cjone.ui.Scrollview*/{
    	/** jquery 플러그인명  */
        bindjQuery: 'scrollview',
       /**	selector 선언부		*/
        selectors: {
            wrapper: '.ui_scrollarea',
            scroller: '.ui_scrollarea>.ui_content',
            //vscrollbar: '.ui_scrollbar'
            vscrollbar: '.bg_mid'
        },
		/**	기본 옵션값 선언부	*/        
        defaults: {
            duration: 600,
            speedLimit: 1.2,
            moveThreshold: 100,
            offsetThreshold: 30,
            startThreshold: 5,
            acceleration: 0.1,
            accelerationT: 250,
            watch: true,
            watchInterval: 400,
            preventScroll: true
        },
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         */
        initialize: function (el, options) {
            var me = this;

            if (me.supr(el, options) === false) {
                return;
            }
            
            me.maxScrollY = 0;
            me.scrollHeight = 0;
            me.wrapperHeight = 0;
            me.visibleScroll = false;

            if (me.$vscrollbar.length > 0) {
                me.scrollbarStyle = me.$vscrollbar[0].style;
                me.scrollbarStyle.display = 'none';
                var $inner = me.$vscrollbar.find('span.bg_mid');
                if ($inner.length) {
                    me.scrollbarInnerStyle = $inner[0].style;
                    me.scrollbarInnerStyle.paddingBottom = 0;
                }
            }
            me._bindEvents();
        },

		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
        _bindEvents: function () {
            var me = this;
            if (me.$vscrollbar.size()){
                me.$wrapper.on('scroll', function () {
                    me._moveScrollbar((me.$wrapper[0].scrollTop*me.scrollRate));
                });
                if (me.options.watch === true) {
					// 사이즈 변화 감시
                    var totalTime = 0, dur = me.options.watchInterval;
                    me.updateTimer = setInterval(function () {
						// 40초에 한번씩 dom에서 제거 됐건지 체크해서 타이머를 멈춘다.
                        if (totalTime > 40000) {
                            totalTime = 0;
                            if (!$.contains(document, me.$el[0])) {
                                clearInterval(me.updateTimer);
                                me.updateTimer = null;
                                return;
                            }
                        } else {
                            totalTime += dur;
                        }
                        me.update();
                    }, dur);
                }
            }
            if (core.browser.isDevice) {
                me._bindContentScroll();
            } else {
                me._bindScrollbar();
                me._bindKeys();
                me._bindWheel();
            }
        },

		/**
		 * @deprecated
		 *  */
        _watchStart: function () {
            var me = this;

        },
        /**
         * 터치기반 디바이스에서 터치로 컨텐츠를 스크롤할 수 있도록 바인딩
         * @private
         */
        _bindContentScroll: function () {
            var me = this,
                times = {}, multiplier = 1,
                isMove, startY, scrollableY, distance, acc, touchTime, maxOffset, elemH, offset, maxScrollY,
                scrollTop, duration;

            me.$el.on('touchstart touchmove touchend touchcancel', function (e) {
                times[e.type] = e.timeStamp;

                switch (e.type) {
                    case 'touchstart':
                        e.stopPropagation();

                        elemH = me.wrapperHeight;
                        scrollableY = me.$wrapper[0].scrollHeight/*.scrollHeight*/ > elemH;
                        maxScrollY = me.$wrapper[0].scrollHeight/*.scrollHeight*/ - elemH;
                        startY = e.originalEvent.touches[0].pageY;
                        multiplier = 1;

                        if (me.$wrapper.is(":animated")
                            && (times['touchstart'] - times['touchend'] < me.options.accelerationT)) {
                            multiplier += me.options.acceleration;
                        } else {
                            multiplier = 1;
                        }

                        me.$wrapper
                            .stop(true, false)
                            .data('scrollTop', me.$wrapper.scrollTop());

                        break;
                    case 'touchmove':
                        e.preventDefault();
                    case 'touchend':
                    case 'touchcancel':
                        if (!scrollableY) { return; }

                        isMove = (Math.abs(startY - e.originalEvent.pageY) > me.options.startThreshold);
                        if (isMove) {
                            if (e.type === 'touchmove') {
                                distance = startY - e.originalEvent.touches[0].pageY;
                                acc = Math.abs(distance / (times['touchmove'] - times['touchstart']));

                                scrollTop = me.$wrapper.data('scrollTop') + distance;
                                duration = 0;
                            } else {
                                elemH = me.wrapperHeight;

                                touchTime = times['touchend'] - times['touchmove'];
                                maxOffset = elemH * me.options.speedLimit;
                                offset = Math.pow(acc, 2) * elemH;
                                offset = offset > maxOffset ? maxOffset : multiplier * offset;
                                offset = (multiplier * offset) * ((distance < 0) ? -1 : 1);

                                if ((touchTime < me.options.moveThreshold) && offset != 0 && Math.abs(offset) > me.options.offsetThreshold) {
                                    scrollTop = me.$wrapper.data('scrollTop') + distance + offset;
                                    duration = me.options.duration;
                                }
                            }

                            if (scrollableY) {
                                if (scrollTop < 0) { scrollTop = 0; }
                                else if (scrollTop > maxScrollY) { scrollTop = maxScrollY; }

                                if (duration > 0) {
                                    me.$wrapper.stop(true, false).animate({
                                        scrollTop: scrollTop
                                    }, {
                                        duration: duration,
                                        easing: 'smooth',
                                        complete: function () {
                                            multiplier = 1;
                                        }
                                    });
                                } else {
                                    me.$wrapper.stop(true, false).scrollTop(scrollTop);
                                    e.stopPropagation();
                                    multiplier = 1;

                                    if (e.type === 'touchmove') {
                                        e.preventDefault();
                                        e.stopPropagation();
                                    }
                                }
                            }
                        }
                        break;
                }
            });

        },

        /**
         * pc에서 상하키로 스크롤할 수 있도록 바인딩
         * @private
         */
        _bindKeys: function () {
            var me = this;

            me.$el.on('keydown', function (e) {
                var keyCode = e.keyCode || e.which,
                    wrapperHeight = me.$wrapper.innerHeight(),
                    scrollTop = me.$wrapper.prop('scrollTop'),
                    maxScrollY = me.$wrapper.prop('scrollHeight') - wrapperHeight,
                    newY;

                switch (keyCode) {
                    case 38: // up
                        e.preventDefault();
                        if (scrollTop <= 0) {
                            return;
                        }
                        newY = scrollTop - wrapperHeight;
                        break;
                    case 40: // down
                        e.preventDefault();
                        if (scrollTop >= maxScrollY) {
                            return;
                        }
                        newY = scrollTop + wrapperHeight;
                        break;
                    default:
                        return;
                }
                if (newY) {
                    me.$wrapper.stop(true, false)
                        .animate({
                            scrollTop: newY
                        }, {
                            duration: me.options.duration,
                            easing: 'smooth'
                        });
                }
            });
        },

        /**
         * pc에서 스크롤바로 컨텐츠를 스크롤할 수 있도록 바인딩
         * @private
         */
        _bindScrollbar: function () {
            var me = this,
                $doc = $(document),
                isTouch = core.browser.isTouch,
                currY, downY, moveY;

            function getY(e){
                if (isTouch && e.originalEvent.touches) {
                    e = e.originalEvent.touches[0];
                }
                return e.pageY;
            }

            me.$vscrollbar.on('mousedown touchstart', function (e) {
                e.preventDefault();
                if (isTouch) {
                    e.stopPropagation();
                }

                me.isMouseDown = true;
                currY = me.getPosition().y;
                downY = getY(e);

                $doc.on('mouseup.' + me.cid + ' mousecancel.' + me.cid +
                    ' touchend.' + me.cid + ' mousemove.' + me.cid +
                    ' touchmove.' + me.cid + ' touchcancel.' + me.cid, function (e) {
                    if (!me.isMouseDown) {
                        $doc.off('.' + me.cid);
                        return;
                    }

                    switch (e.type) {
                        case 'mouseup':
                        case 'touchend':
                        case 'mousecancel':
                        case 'touchcancel':
                            me.isMouseDown = false;
                            moveY = 0;
                            $doc.off('.' + me.cid);
                            break;
                        case 'mousemove':
                        case 'touchmove':
                            moveY = getY(e);

                            var top = currY - (downY - moveY),
                                scrollHeight = me.wrapperHeight - me.scrollbarHeight,
                                y;

                            me.scrollbarStyle.top = (top = Math.max(0, Math.min(top, scrollHeight)));
                            y = (me.scrollHeight - me.wrapperHeight) * (top / scrollHeight);
                            me.$wrapper.scrollTop(y);
                            e.preventDefault();
                            break;
                    }
                });
                return false;
            });
        },

        /**
         * pc에서 마우스로 스크롤할 수 있도록 바인딩
         * @private
         */
        _bindWheel: function () {
            var me = this;
            me.$wrapper.on('mousewheel DOMMouseScroll wheel', function (ev) {
                var e = ev.originalEvent;
                var delta     = core.util.getDeltaY(e) * 100,
                    scrollTop = me.$wrapper[0].scrollTop;

                me.$wrapper.scrollTop(scrollTop - delta); // -: down +: up
                if (me.options.preventScroll) {
                    ev.preventDefault();
                    ev.stopPropagation();
                } else {
                    if (me.$wrapper[0].scrollTop != scrollTop) {
                        ev.preventDefault();
                        ev.stopPropagation();
                    }
                }
            });
        },

        /**
         * 스크롤바의 위치를 반환
         * @returns {{x: *, y: *}}
         */
        getPosition: function () {
            var matrix = this.scrollbarStyle,
                x, y;

            if ( core.css3.support ) {
                matrix = matrix[cssTransform].match(/-?[0-9]+/g);
                x = +(matrix[0]);
                y = +(matrix[1]);
            } else {
                x = +matrix.left.replace(/[^-\d.]/g, '');
                y = +matrix.top.replace(/[^-\d.]/g, '');
            }

            return { x: x, y: y };
        },

        /**
         * 스크롤바를 움직여주는 함수
         * @param top
         * @param height
         * @private
         */
        _moveScrollbar: function (top, height) {
            var me = this;

            if (!me.visibleScroll) { return; }
            if (height !== undefined && me.scrollbarHeight != height) {
                height = Math.max(height, 8);
                if (me.scrollbarInnerStyle){
                    var roundSize = me.$vscrollbar.children().eq(0).height();
                    me.scrollbarInnerStyle.top = roundSize + 'px';
                    me.scrollbarInnerStyle.bottom = roundSize + 'px';
                }
                me.scrollbarStyle.height = height+'px';
                me.scrollbarHeight = height;
            } else {
                height = me.scrollbarHeight;
            }
            if (me.wrapperHeight < height + top) {
                top = me.wrapperHeight - height;
            }
            if (core.css3.support) {
                me.scrollbarStyle[cssTransform] = 'translate(0px, ' + top + 'px)';
            } else {
                me.scrollbarStyle.top = top + 'px';
            }
        },

        /**
         * 사이즈 변화에 따른 UI 갱신
         */
        update: function (){
            var me = this,
                wrapperHeight, scrollHeight, visibleScroll, scrollbarHeight;

            wrapperHeight = me.$wrapper[0].offsetHeight;
            if (wrapperHeight === 0){
                me.wrapperHeight = 0;
                return;
            }

            scrollHeight = me.$wrapper[0].scrollHeight;
            visibleScroll = wrapperHeight < scrollHeight;
            if (visibleScroll !== me.visibleScroll) {
                me.visibleScroll = visibleScroll;
                me.scrollbarStyle.display = visibleScroll ? '' : 'none';
                me.$el.toggleClass('strack', visibleScroll);
            }
            me.$vscrollbar.parent()[visibleScroll == true? 'show': 'hide']();
            
            if (visibleScroll && (scrollHeight !== me.scrollHeight || wrapperHeight !== me.wrapperHeight)) {
                me.wrapperHeight = wrapperHeight;
                me.scrollHeight = scrollHeight;
                me.scrollRate = wrapperHeight / scrollHeight;
                me._moveScrollbar(me.$wrapper[0].scrollTop * me.scrollRate, scrollbarHeight = wrapperHeight * me.scrollRate);
            }
        },

        /**
         * scrollTop 설정
         * @param top
         * @returns {*}
         */
        scrollTop: function (top) {
            var me = this;
            if (arguments.length > 0) {
                me.$wrapper.scrollTop(top);
                me.update();
            } else {
                return me.$wrapper.scrollTop();
            }
        },

        release: function () {
            var me = this;

            me.updateTimer && (clearInterval(me.updateTimer), me.updateTimer = null);
            me.supr();
        }
    });

    if (typeof define === 'function' && define.amd) {
        define('mobules/scrollview', [], function (){
            return Scrollview;
        });
    }

})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
	"use strict";
    /*
	 * @description 레이어 팝업 들을 관리
	 * @class
	 * @name cjone.ui.Modal
	 * @extends cjone.ui.View
	 * @sample http://dev.cjone.com:8001/cjmweb/script/wsg/layerPop/script_popup.html
	 */
	var $doc = $(document),
        $win = $(window),
        browser = core.browser,
        ui = core.ui,
        isTouch = browser.isTouch,
        _zIndex = 9000;

	/**
	 * modal 팝업을 관리하는 메니저
	 *  */
    var ModalManager = {
        init: function(options) {
            var me = this;

            me.options = $.extend({}, options);
            me.stack = [];			//레이어 팝업을 array로 관리
            me.active = null;

            me._bind();
            $doc.data('modal-stack', me.stack);
        },
        
		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
        _bind: function() {
            var me = this;

            $win.on('resizeend.modalmanager', function() {
                for(var i = -1, modal; modal = me.stack[++i];){
                    modal.isShown && modal.center();
                }
            });

            $doc.on('modal:show.modalmanager', '.ui_modal_container', function(e) {
                var $modal = $(e.currentTarget),
                    modal = $modal.modal('instance'),
                    zIndex = me.nextZIndex();

                modal.$overlay && modal.$overlay.css('zIndex', zIndex++);
                modal.$el && modal.$el.css('zIndex', zIndex++);

                me.active = modal;
                me.add(modal);

            }).on('modal:hidden', '.ui_modal_container', function(e) {
                var $modal = $(e.currentTarget),
                    modal = $modal.modal('instance');

                me.revertZIndex();
                me.remove(modal);

                if(me.stack.length){
                    me.active = me.stack[me.stack.length - 1];
                } else {
                    me.active = null;
                }
            }).on('focusin.modalmanager', function(e) {
                if (!me.active){ return; }
                if (me.active.$el[0] !== e.target && !$.contains(me.active.$el[0], e.target)) {
                    me.active.$el.find(':focusable').first().focus();
                    e.stopPropagation();
                }
            }).on('click.modalmanager', '[data-control=modal]', function(e) {
                e.preventDefault();

                var $el = $(this),
                    target = $el.attr('href') || $el.attr('data-target'),
                    //data = $.parseJSON($el.attr('data-params')) || {},
                    data = ($el.attr('data-params') ? $.parseJSON($el.attr('data-params')) : {}) || {},
                    $modal;

                if (target) {
                    // ajax형 모달인 경우
                    if (!/^#/.test(target)) {
                        $.ajax({
                            url: target,
                            data: data
                        }).done(function(html) {
							//var origin = html.replace(/(.|(\n|\r))*(<body.*>)/, '');
							/*var origin = html.substr(html.indexOf('<body>')+6);
							var result = origin.match(/<.*\/.*div.*>/);
							if(result.length > 0) {
								var comp = result[result.length-1];
							 	origin = origin.substr(0, origin.lastIndexOf(comp)+comp.length);
							}*/
							/** @description ajax로 불러들인 html 소스를 substring */
							var btr = html.match(/<body>/);
       						var idx = (btr != null && btr.length > 0)? (html.indexOf('<body>')+6): 0;
       						var origin = html.substr(idx);
       						var result = origin.match(/<.*\/.*div.*>/);
       						if(result != null && result.length > 0) {
        						var comp = result[result.length-1];
         						origin = origin.substr(0, origin.lastIndexOf(comp)+comp.length);
       						}
							html = origin;
                        	
                            var html = $(html).find('div:eq(0)').parent().wrap('<div>').parent();
                            $modal = $('<div class="ui_modal ui_modal_ajax" style="display:none" data-url="'+(target)+'"></div>').html(html).appendTo('body');
                            $modal.modal($.extend({
                                removeOnClose: true,
                                eventBorn: $el
                            }, $el.data())).on('modal:hidden', function(e){
								$el.focus();
                                $modal.off('modal:hidden');
                            });
                        });
                    } else {
                        $(target).modal($el.data()).on('modal:hidden', function(e){
							$el.focus();
                            $(this).off('modal:hidden');
                        });
                    }
                }
            }).on('modalCloseAll', function () {
                $('.ui_modal_container').each(function () {
                    var $this = $(this);
                    $this.data('ui_modal').close();
                });
                $doc.triggerHandler('modal:closeAll');
            });
        },
        add: function(modal) {
            modal.$el.attr('data-modal-id', core.getUniqId());        //modal에 유니크한 string을 할당함
            if(this.stack.length > 0){
            var $beforeModal = this.stack[this.stack.length-1];
                $beforeModal.$el.hide();              //기존에 열려있는 레이어팝업을 display: none시킴
                $beforeModal.$overlay.hide();
            }         
            this.stack.push(modal);
        },
        remove: function(modal) {
            this.stack = core.array.remove(this.stack, modal);
            if(this.stack.length > 0){
            var $beforeModal = this.stack[this.stack.length-1];
                $beforeModal.$el.show();              //기존에 열려있는 레이어팝업을 display: show시킴
                $beforeModal.$overlay.show();
            }
        },
        nextZIndex: function() {
            var zi = _zIndex;
            _zIndex += 2;
            return zi;
        },
        revertZIndex: function() {
            _zIndex -= 2;
        }
    };
    ModalManager.init();


	/**
     * @description 모달 클래스
     * options.overlay:true 오버레이를 깔것인가<br />
     * options.clone: true  복제해서 띄울 것인가<br />
     * options.closeByEscape: true  // esc키를 눌렀을 때 닫히게 할 것인가<br />
     * options.removeOnClose: false // 닫을 때 dom를 삭제할것인가<br />
     * options.draggable: true              // 드래그를 적용할 것인가<br />
     * options.dragHandle: 'h1.title'       // 드래그대상 요소<br />
     * options.show: true                   // 호출할 때 바로 표시할 것인가...
     *
     * @class
     * @name cjone.ui.Modal
     * @extends cjone.ui.View
     */
    var Modal = ui('Modal', /** @lends cjone.ui.Modal */ {
    	/** jquery 플러그인명  */
        bindjQuery: 'modal',
        defaults: {
            overlay: true,
            clone: true,
            closeByEscape: true,
            removeOnClose: false,
            draggable: true,
            dragHandle: 'header h1',
            show: true,
            effect: 'fade', // slide | fade
			displayTime: 'fast',
            clickToCloseModal: false,           //dim 클릭시 modal을 닫을지 여부
            cssTitle: '.ui_modal_title',
            eventBorn: null
        },

        events: {
            'click button[data-role]': function(e) {
                var me = this,
                    $btn = $(e.currentTarget),
                    role = ($btn.attr('data-role') || ''),
                    ev;

                if (role) {
                    me.triggerHandler(ev = $.Event('modal:'+role), [me]);
                    if (ev.isDefaultPrevented()) {
                        return;
                    }
                }

                this.hide();
            },
            'click [data-control="modalClose"]': function(e) {
                e.preventDefault();
                e.stopPropagation();

                this.hide();
            }
        },
        /**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Boolean}  options.overlay:true 오버레이를 깔것인가
         * @param {Boolean}  options.clone: true    복제해서 띄울 것인가
         * @param {Boolean}  options.closeByEscape: true    // esc키를 눌렀을 때 닫히게 할 것인가
         * @param {Boolean}  options.removeOnClose: false   // 닫을 때 dom를 삭제할것인가
         * @param {Boolean}  options.draggable: true                // 드래그를 적용할 것인가
         * @param {Boolean}  options.dragHandle: 'h1.title'     // 드래그대상 요소
         * @param {Boolean}  options.show: true                 // 호출할 때 바로 표시할 것인가...
         */
        initialize: function(el, options) {
            var me = this;
            if (me.supr(el, options) === false) {
                return;
            }

            // 열릴때 body로 옮겼다가, 닫힐 때 다시 원복하기 위해 임시요소를 넣어놓는다.
            me._createHolder();
            if (me.options.overlay !== false) {
                me._overlay();    // 오버레이 생성
            }
            me.$el.addClass('ui_modal_container');

            me.isShown = false;
            me._originalDisplay = me.$el.css('display');

            me.options.show && core.util.waitImageLoad(me.$('img')).done(function() {
                me.show();
            });
        },
        
        getURL: function () {
            return this.$el.attr('data-url');
        },

        _bindAria: function() {
            var me = this;
            // TODO
            me.$el.attr({
                'role': 'dialog',
                'aria-hidden': 'false',
                'aria-describedby': me.$('section').attr('id') || me.$('section').attr('id', me.cid + '_content').attr('id'),
                'aria-labelledby': me.$('h1').attr('id') || me.$('h1').attr('id', me.cid + '_title').attr('id')
            });
        },
        /**
         * zindex때문에 모달을 body바로 위로 옮긴 후에 띄우는데, 닫을 때 원래 위치로 복구시켜야 하므로,
         * 원래 위치에 임시 홀더를 만들어 놓는다.
         * @private
         */
        _createHolder: function() {
            var me = this;

            if (me.$el.parent().is('body')) {
                return;
            }

            me.$holder = $('<span class="ui_modal_holder" style="display:none;"></span>').insertAfter(me.$el);
            me.$el.appendTo('body');
        },
        /**
         * 원래 위치로 복구시키고 홀더는 제거
         * @private
         */
        _replaceHolder: function() {
            var me = this;

            if (me.$holder) {
                me.$el.insertBefore(me.$holder);
                me.$holder.remove();
            }
        },

        /**
         * 토글
         */
        toggle: function() {
            var me = this;

            me[me.isShown ? 'hide' : 'show']();
        },

        /**
         * 표시
         */
        show: function() {
            if (this.isShown) {
                return;
            }

            var me = this,
                opts = me.options,
                e = $.Event('modal:show');

            if (me.isShown || e.isDefaultPrevented()) {
                return;
            }
            me.isShown = true;

            if (opts.title) {
                me.$(opts.cssTitle).html(opts.title || '알림');
            }

            me.layout();
            me.layout();
            
            var defer = $.Deferred();
            if(opts.effect === 'fade') {
                me.$el.hide().fadeIn(me.options.displayTime, function () {
                    defer.resolve();
                });
            } else if(opts.effect === 'slide') {
                me.$el.css('top', -me.$el.height()).animate({top: '50%'}, function () {
                    defer.resolve();
                });
            } else {
                defer.resolve();
            }
            

            defer.done(function () {
				/** 모바일 장비 support 시작 */
				//if(cjone.browser.isDevice == true && $(document).data('modalStack').length == 1){
				if($(document).data('modalStack').length == 1){
					var $htmlBody = $('html, body');
					$htmlBody.height(cjone.util.getWinHeight());
					$htmlBody.data('scrollTop', cjone.$win.scrollTop());
				}
				/** 모바일 장비 support 종료 */
               
				$('html, body').addClass('ovh');
				
                me._bindAria(); // aria 셋팅
                me._draggabled();    // 드래그 기능 빌드
                me._escape();    // esc키이벤트 바인딩
				me._enforceFocus();

                me.on('mousewheel', function(e) {
                    e.stopPropagation();
                });

                var $focusEl = me.$el.find('[data-autofocus=true]');

                // 레이어내에 data-autofocus를 가진 엘리먼트에 포커스를 준다.
                if ($focusEl.size() > 0) {
                    $focusEl.eq(0).focus();
                } else {
                    // 레이어에 포커싱
                    me.$el.attr('tabindex', 0).focus();
                    //me.$el.find('[tabindex]').removeAttr('tabindex');
                }

                var $focusEl = me.$('[data-autofocus=true]');
                if ($focusEl.size() > 0) {
                    $focusEl.eq(0).focus();
                } else {
                    me.$el.attr('tabindex', 0).focus();
                }
              
				me.trigger('modal:shown', {
                    module: me
                });
                
               if(typeof $.fn.formatter == 'undefined'){
					var asFront = (cjone.uri.parseUrl(location.href).directory.indexOf('/cjmweb/front') > -1 ? 'front/': '' );
					cjone.importJs(['/cjmweb/'+(asFront)+'js/modules/formatter'], function () {
						me.$el.find('[data-format]').formatter();
					});
               }else{
					me.$el.find('[data-format]').formatter();
               }
               
               if(typeof $.fn.placeholder== 'undefined'){
               		var asFront = (cjone.uri.parseUrl(location.href).directory.indexOf('/cjmweb/front') > -1 ? 'front/': '' );
               		cjone.importJs(['/cjmweb/'+(asFront)+'js/modules/placeholder'], function () {
						$('input, textarea').placeholder();
					});
               }else{
               		me.$el.find('input, textarea').placeholder();
               }
               
                me.$el.find('[data-skin="form"] input').formSkin('addSkin');
				me.$el.find('[data-skin="form"] select').formSkin('addSkin');
				
                me.$el.on('click', '[data-control="modalCloseAll"]', function (e) {        //전체레이어 닫기 버튼을 누를때 실행됨
                    e.preventDefault();
                    $(document).triggerHandler('modalCloseAll');
                });
            });
			me.trigger(e, {module: me});
        },

        /**
         * 숨김
         */
        hide: function(e) {
            if (e) {
                e.preventDefault();
            }
            var me = this;
            e = $.Event('modal:hide');
            me.trigger(e, {module: me});
            if (!me.isShown || e.isDefaultPrevented()) {
                return;
            }

            var defer = $.Deferred();
            me.isShown = false;
            if(me.options.effect === 'fade') {
                me.$el.fadeOut(me.options.displayTime, function () {
                    defer.resolve();
                });
            } else if(me.options.effect === 'slide') {
                me.$el.animate({
                    top: -me.$el.outerHeight()
                }, function() {
                   defer.resolve();
                });
            } else {
                defer.resolve();
            }

            defer.done(function() {
                me.trigger('modal:hidden', {module: me});
				
				/** 모바일 장비 support 시작 */
				//if(cjone.browser.isDevice == true){
				if($(document).data('modalStack').length == 0){
					var $htmlBody = $('html, body'),
						  _scrollTop = $htmlBody.data('scrollTop');
						  
					$htmlBody.css({						'height': ''					});
					//$htmlBody.scrollTop(_scrollTop).data('scrollTop', null);
					//$htmlBody.animate({						'scrollTop': _scrollTop					});
					setTimeout(function () {
						$htmlBody.scrollTop(_scrollTop);
					}, 10);
				}
				/** 모바일 장비 support 종료 */

                me.$el.removeClass('ui_modal_container');    // dom에 추가된 것들 제거
                me._escape();    // esc 키이벤트 제거
                me._replaceHolder();    // body밑으로 뺀 el를 다시 원래 위치로 되돌린다.

                if (me.options.removeOnClose) {
                    me.$el.remove();    // 닫힐 때 dom에서 삭제하도록 옵션이 지정돼있으면, dom에서 삭제한다.
                }
                if (me.$overlay) {
                    me.$overlay.remove(), me.$overlay = null;    // 오버레이를 제거
                }
                me.release();
                
                if($(document).data('modalStack').length == 0) $('html, body').removeClass('ovh');
                if(me.options.eventBorn)		me.options.eventBorn.focus();				//포커스 이벤트 유지
            });
        },

        /**
         * 도큐먼트의 가운데에 위치하도록 지정
         */
        layout: function() {
            var me = this,
                width, height, attr, isOver,
                winHeight = core.util.getWinHeight();

            if (!me.isShown) {
                me.$el.css({
                    'display': 'inline'
                });
            }
            if(cjone.browser.isDevice == true){
				if(cjone.$htmlBody.data('scrollTop'))		cjone.$htmlBody.height(cjone.util.getWinHeight());
			}                        
            var $layerPop = me.$el.find('div:eq(0)');
            width = Math.max(me.$el.outerWidth(), $layerPop.children().outerWidth(true));
            height = Math.max(me.$el.outerHeight(), $layerPop.children().outerHeight(true));
            isOver = height > winHeight;

            attr = {
                display: '',
                position: 'absolute',
                backgroundColor: '#ffffff',
                outline: 'none',
                backgroundClip: 'padding-box',
                top: isOver ? 0 : '50%',
                left: '50%',
                marginLeft: Math.ceil(width / 2) * -1,
                marginTop: isOver ? '' : Math.ceil(height / 2) * -1
            };

			//레이어팝업을 감싸고 있는 태그가 없을 경우
            if(me.$el.parent('.ui_modal_overlay').size() == 0){
            	//attr.top = (cjone.browser.isDevice == true ? 0 : cjone.$win.scrollTop())+((cjone.util.getWinHeight()-height)/2);
            	//attr.left = (cjone.browser.isDevice == true ? 0 : cjone.$win.scrollLeft())+((cjone.util.getWinWidth()-width)/2);
            	attr.top = (cjone.util.getWinHeight()-height)/2;
            	attr.left = (cjone.util.getWinWidth()-width)/2;
            	attr.marginLeft = 0;
            	attr.marginTop = 0;
            }
			me.$el.stop(true, true).css(attr);
            me.$el.width(width).height(height);
        },

        /**
         * 타이틀 영역을 드래그기능 빌드
         * @private
         */
        _draggabled: function() {
            var me = this,
                options = me.options;

            if (!options.draggable || me.bindedDraggable) {
                return;
            }
            me.bindedDraggable = true;

            if (options.dragHandle) {
                me.$el.css('position', 'absolute');
                core.css3.prefix('user-select') && me.$(options.dragHandle).css(core.css3.prefix('user-select'), 'none');
                me.on('mousedown touchstart', options.dragHandle, function(e) {
                    e.preventDefault();

                    var isMouseDown = true,
                        pos = me.$el.position(),
                        oriPos = {
                            left: e.pageX - pos.left,
                            top: e.pageY - pos.top
                        }, handler;

                    $doc.on(me.getEN('mousemove mouseup touchmove touchend touchcancel'), handler = function(e) {
                        switch (e.type) {
                            case 'mousemove':
                            case 'touchmove':
                                if (!isMouseDown) {
                                    return;
                                }
                                me.$el.css({
                                    left: e.pageX - oriPos.left,
                                    top: e.pageY - oriPos.top
                                });
                                break;
                            case 'mouseup':
                            case 'touchend':
                            case 'touccancel':
                                isMouseDown = false;
                                $doc.off(me.getEN(), handler);
                                break;
                        }
                    });
                });

                me.$(options.dragHandle).css('cursor', 'move');
            }
        },

        /**
         * 모달이 띄워진 상태에서 탭키를 누를 때, 모달안에서만 포커스가 움직이게
         * @private
         */
        _enforceFocus: function() {
            var me = this;
            me.$el.on({
                'keydown': function (e) {
                    var $this = $(e.target);
                    if((e.shiftKey == false && e.keyCode==9) && (me.$el.find('button').last().index($this)) == 0){
                        e.preventDefault();
                        me.$el.focus();
                    }
                    if((e.shiftKey == true && e.keyCode==9) && (me.$el.index($this)) == 0) {
                        e.preventDefault();
                        me.$el.find('button').last().focus();
                    }
                }
            });
        },
        /**
         * esc키를 누를 때 닫히도록
         * @private
         */
        _escape: function() {
            var me = this;

            if (me.isShown && me.options.closeByEscape) {
                me.off('keyup').on('keyup', me.proxy(function(e) {
                    //e.which === 27 && me.hide();
                }));
            } else {
                me.off('keyup');
            }
        },

        /**
         * 오버레이 생성
         * @private
         */
        _overlay: function() {
            var me = this;
            if (!me.options.overlay || me.$overlay) {
                return false;
            } //140123_추가

            me.$overlay = $('<div class="ui_modal_overlay" />');
            me.$overlay.css({
                //'backgroundColor': '#000',
                //'opacity': 0.6,
                'position': 'fixed',
                'top': 0,
                'left': 0,
                'right': 0,
                'bottom': 0
            }).appendTo('body');

            if(me.options.clickToCloseModal == true){
                me.$overlay.off('click.modal').on('click.modal', function(e) {
                    if (e.target != e.currentTarget) {
                        return;
                    }
                    me.$overlay.off('click.modal');
                    me.hide();
                });
            }
        },

        /**
         * 모달의 사이즈가 변경되었을 때 가운데위치를 재조절
         * @example
         * $('...').modal(); // 모달을 띄운다.
         * $('...').find('.content').html( '...');  // 모달내부의 컨텐츠를 변경
         * $('...').modal('center');    // 컨텐츠의 변경으로 인해 사이즈가 변경되었으로, 사이즈에 따라 화면가운데로 강제 이동
         */
        center: function() {
            this.layout();
        },

        /**
         * 열기
         */
        open: function() {
            this.show();
        },

        /**
         * 닫기
         */
        close: function() {
            this.hide();
        },

        /**
         *
         */
        release: function() {
            var me = this;

			me.$el.find('[data-control="modalAccept"]').each(function () {
				$('[data-control="modalAccept"]').releaseEvent('click');
			});
			me.$el.find('[data-control="modalCancel"]').each(function () {
				$('[data-control="modalCancel"]').releaseEvent('click');
			});
			$doc.releaseEvent('modal:shown');			
			
            me.supr();
            $doc.off(me.getEN());
            $win.off(me.getEN());
            
            //$doc.off('modal:show modal:shown');
        }
    });


    /**
     * 열려 있는 레이어팝업을 가운데에 위치시키는 글로벌이벤트
     * @example
     * cjone.PubSub.trigger('resize:modal')
     */
    /*core.PubSub.on('resize:modal', function() {
        if(Modal.active){
            Modal.active.center();
        }
    });*/

    //윈도우가 리사이징 될때 가운데에 자동으로 위치시킴
    /*$(window).on('resize.modal', function() {
        if(Modal.active){
            Modal.active.center();
        }
    });*/

    core.modal = function(el, options){
        $(el).modal(options);
    };

    /**
     * @function
     * @name cjone.ui.AjaxModal
     * @description ajax로 불러들인 컨텐츠를 모달로 띄워주는 함수
     * @extends cjone.ui.View
     */
    core.ui.ajaxModal = function () {
        return function(url, options) {
            // TODO
            setTimeout(function() {
                var $modal = $('<div class="ui_modal" style="display: none;">').appendTo('body');
                $modal.load(url, function () {
                    $modal.modal($.extend(options, {removeOnClose: true}));
                });
            }, 1000);
        };
    }();

	/**
     * @function
     * @name cjone.ui.AjaxModal
     * @description 메시지 alert형
     * @extends cjone.ui.View
     */
    core.ui.alert = function () {
        /**
         * 얼럿레이어
         * @class
         * @name cjone.ui.alert
         * @function
         * @param {string} msg 얼럿 메세지
         * @param {Object} options 모달 옵션
         * @example
         		cjone.ui.alert('안녕하세요');
         */
        return function (msg, options) {
            if(typeof msg !== 'string' && arguments.length === 0) {
                options = msg;
                msg = '';
            };
            var el = $(core.ui.alert.tmpl).appendTo('body').find('div.ui_modal_content').html(msg).end();
            var modal = new Modal(el, core.extend({removeOnClose: true}, options));
            modal.getElement().buildUIControls();
            modal.on('modalhidden', function(){
                el = null;
                modal = null;
            });
            return modal;
        };
    }();
    core.ui.alert.tmpl = ['<div class="layer_popup small ui_alert" role="alert" style="display:none">',
        '<h1 class="title ui_modal_title">알림창</h1>',
        '<div class="cntt">',
        '<div class="ui_modal_content">&nbsp;</div>',
        '<div class="wrap_btn_c">',
        '<button type="button" class="btn_emphs_small" data-role="ok"><span><span>확인</span></span></button>',
        '</div>',
        '</div>',
        '<button type="button" data-control="modalClose"><span>닫기</span></button>',
        '<span class="shadow"></span>',
        '</div>'].join('');
    ///////////////////////////////////////////////////////////////////////////////////////

    if (typeof define === "function" && define.amd) {
        define([], function() {
            return Modal;
        });
    }

})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
    "use strict";
	/**
     * @description 툴팁 클래스 
	 * @class 
	 * @name cjone.ui.Tooltip
	 * @extends cjone.ui.View
	 */
    if (core.ui.Tooltip) { return; }

    var $doc    = $(document),
        $win    = $(window),
        isTouch = core.browser.isTouch;

    var Tooltip = core.ui('Tooltip', /** @lends cjone.ui.Tooltip */{
    	/** jquery 플러그인명  */
        bindjQuery: 'tooltip',
        /**	기본 옵션값 선언부	*/
        defaults: {
            interval: 300 /** @member {Double} interval - 툴팁이 뜨는데 최소 제한 시간 */
        },

		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Double} options.interval - 툴팁이 뜨는데 최소 제한 시간
         */
        initialize: function (el, options) {
            var me = this;

            if (me.supr(el, options) === false) {
                return;
            }

            me.$tooltip = (me.$el.attr('data-handler-target') ? $(me.$el.attr('data-handler-target')) : me.$el.next('div'));
            me.$tooltip = (me.$tooltip.size() == 0 ? $(me.$el.attr('data-handler-target')) : me.$tooltip);
            
            me.isShown = false;
            me.timer = null;

            me.on('click.tooltip', function (e) {
                e.preventDefault();
                e.stopPropagation();

                if (me.isShown) {
                    me.close();
                } else {
                    me.open();
                }
            });

            me.on('mouseenter', me.open.bind(me)).on('mouseleave', me.close.bind(me));
            me.$tooltip.on('focusin.tooltip mouseenter.tooltip', function () {
                if (me.$tooltip.data('timer')) {
                    clearTimeout(me.$tooltip.data('timer')), me.$tooltip.removeData('timer');
                }
            }).on('mouseleave.tooltip', function () {
                me.isShown && me.$tooltip.data('timer', setTimeout(function () {
                    me.isShown = false, me.$tooltip.addClass('hide'), me.triggerHandler('tooltip:hidden', {data: me});;
                    if (me.$tooltip.data('timer')) {
                        clearTimeout(me.$tooltip.data('timer')), me.$tooltip.removeData('timer');
                    }
                }, me.options.interval));
            }).on('click', function (){
                clearTimeout(me.$tooltip.data('timer')), me.$tooltip.removeData('timer');
            }).on('click.tooltip focusout.tooltip', '.ui_tooltip_close, .btn_close, [data-handler="closeTooltip"], .close_tooltip', function (e) {
                e.preventDefault();
                setTimeout(function () {
                	me.close();
                }, 0);
                if (e.type === 'click') me.$el.focus();
            });
            
            me.$el.on('focus', me.open.bind(me));
            if(me.$tooltip.find('.close_tooltip').size() == 0){		//툴팁 레이어에 닫기 버튼이 없을경우
            	me.$el.on('blur', me.close.bind(me));
            }
            //me.open();
        },
        /**
         * 표시
         */
        open: function () {
            var me     = this,
                offset = me.$el.offset();
            
            me.triggerHandler('tooltip:show', {data: me});

            offset.top += me.$el.height();
            me.timer = setTimeout(function () {
                //me.$tooltip/*.css(offset)*/.fadeIn('fast');
                me.$tooltip.removeClass('hide');
                me.isShown = true;
                me.triggerHandler('tooltip:shown', {data: me});
            }, me.options.interval);
        },
        /**
         * 숨김
         */
        close: function () {
            var me = this;

            clearTimeout(me.timer), me.timer = null;
            if (me.isShown) {
                me.$tooltip.data('timer', setTimeout(function () {
                    me.isShown = false;
                    //me.$tooltip.hide();
                    me.$tooltip.addClass('hide');
                    me.triggerHandler('tooltip:hidden', {data: me});
                }, me.options.interval));
            }
        },
        /**
         * 소멸자
         */
        destroy: function () {
            var me = this;

            me.supr();
            me.$tooltip.off('.tooltip').removeData('timer');
        }
    });

    $doc.on('mouseenter.tooltip focusin.tooltip click.tooltip', '[data-control=tooltip]', function () {
        var $btn = $(this);
//if ($btn.data('ui_tooltip')){ return; }

        //$btn.scTooltip();
    });

    if (typeof define === "function" && define.amd) {
        define('modules/tooltip', [], function () {
            return Tooltip;
        });
    }
})(jQuery, window[LIB_NAME]);


(function ($, core) {
    "use strict";
	/**
	 * @description 탭 확장 클래스
	 * @class 
	 * @name cjone.ui.Tab
	 * @extends cjone.ui.View
	 */
    if(core.ui.Tab){ return; }

    var BaseTab = core.ui.View.extend({
        name: 'BaseTab',
        defaults: {
            tabSelector: '>li',
            btnSelector: '>a:not([data-disable="link"])',
            haze: true,
            isPreventDefault: true
        },
        initialize: function (el, options) {
            var me = this, index;
            if (me.supr(el, options) === false) { return; }

            me._findControls();
            me._bindEvents();
            me._initTab();
        },
        _initTab: function (){
            var me = this, index;
            if ((index = me.$tabs.filter('.on').index()) >= 0) {
                me.selectTab(index);
            }
        },
        _findControls: function () {
            var me = this,
                selectors = [],
                contents = [];

            me.$tabs = me.$(me.options.tabSelector);
            me.$tabs.each(function () {
                var $el = me.options.btnSelector ? $(this).find(me.options.btnSelector) : $(this),
                    cont = $el.attr('href') || $el.attr('data-href');
                    if(typeof cont != 'undefined' && cont.indexOf('javascript') > -1){
                    	cont = $el;
                    	me.options.isPreventDefault = false;
                    }
                if (cont && cont.length > 1) {
                    selectors.push(cjone.getHref(cont));
                } else {
				// '#' 만 있으면 inner content
                    contents.push($el.next().length > 0 ? $el.next() : {});
                }
            });
            
            if (selectors.length > 0) {
                me.$contents = $(selectors.join(', '));
            } else {
                me.$contents = $(contents);
            }
        },
        _bindEvents: function () {
            var me = this;
            
            me.$el.on('click', me.options.tabSelector + me.options.btnSelector, function (e) {
            	if(me.options.isPreventDefault == true)	e.preventDefault();
                if (me.getState('disabled') || me.getState('readonly')) { return; }
                var index = me.$tabs.index(me.$tabs.has(this));
                me.selectTab(index);
            }).on('statechange', function (e, data) {
                switch(data.name) {
                    case 'disabled':
                    case 'readonly':
                        if (data.value) {
                            me.$tabs.find(':focusable').attr('tabindex', -1);
                        } else {
                            me.$tabs.find(':focusable').removeAttr('tabindex');
                        }
                        break;
                }
            });
        },

		// 별도의 처리가 필요한거는 오버라이드
        _selectTab: function (index) {
        	var me = this;
        	me.$tabs.removeClass('on').eq(index).addClass('on');
			me.$contents.addClass('hide').eq(index).removeClass('hide');
        },
        _toggleText: function (index) {},
        _getEventTarget: function (index) {
            var me = this;
            return me.options.btnSelector ? me.$tabs.eq(index).find(me.options.btnSelector) : me.$tabs.eq(index);
        },
        /**
         * index에 해당하는 탭을 활성화
         * @param {number} index 탭버튼 인덱스
         */
        selectTab: function(index) {
            var me = this, e, param;
            if (me.getState('disabled') || me.getState('readonly')) { return; }
            if(index < 0 || (me.$tabs.length && index >= me.$tabs.length)) {
                index = me.options.selectedIndex;
            }

            param = {
                selectedIndex: index,
                tab: me.$tabs.get(index),
                content: me.$contents.get(index),
                sender: me._getEventTarget(index)
            };

            me.trigger(e = $.Event('tab:change'), param);
            if(e.isDefaultPrevented()) { return false; }
            
            me.selectedIndex = index;
            me._selectTab(index);
            me._toggleText(index);
            
            me.trigger('tab:changed', param);
        }
    });

    /**
     * 다음 네항목 중에서 type에 따라 필요한걸 구현해주면 된다.
     * defaults: 기본 옵션값
     * _toggleText: 탭이 선택여부에 따른 숨김문구 변경하는 함수
     * _selectTab: 선택될 때 호출되는 함수
     * _initTab: 초기화 함수
     */
    var TabTypes = {
        //'type01': BaseTab,
        'type02': BaseTab.extend({ // 바로 하위에 버튼이 있는 경우
            defaults: {
                tabSelector: '>a, >button',
                btnSelector: false
            },
            _toggleText: function (index) {
                var me = this;
                me.$tabs.find('span.hide').html(' ');
                me.$tabs.eq(index).find('span.hide').html('현재 선택됨');
            }
        }),
        'type01': BaseTab.extend({
        	_initTab: function () {
        		var me = this;
        		switch(me.$el.find('.haze').size()){
        			case 0:
        				//alert('haze클래스를 설정해야 합니다.');
        			break;
        			case 1:
        			break;
        			default:
        				//alert('haze 클래스의 갯수가 2개 이상입니다.');
        			break;
        		}
        		
				setTimeout(function () {
                	me.$tabs.filter('.on').find(me.options.btnSelector).trigger('click');
                });
        	},
        	_toggleText: function (index) {
                var me = this,
                	  $selectedEl = me.$tabs.eq(me.selectedIndex).setHaze(me.$el);
            }
        }),
        'localMap': BaseTab.extend({
        	defaults: {
        		tabSelector: '.town_item',
        		btnSelector: ' .summary_info>a:not([data-disable="link"])',
        		hazeText: ''
        	},
        	selectors: {
        		townList: '.town_list',
        		detailInfo: '.detail_info',
        		btns: '.summary_info>a',
        		haze: '.summary_info>a span.haze'
        	},
        	_initTab: function () {
        		var me = this;
        		me.options.hazeText = me.$haze.first().text();
        	},
        	_selectTab: function (index) {
        		var me = this;
				me.$townList.removeClass('open').removeAttr('style');
				me.$haze.text(me.options.hazeText);
				
    			var $selectedTab = me.$tabs.eq(index),
    				  $sender = me._getEventTarget(index),
    				  $detailInfo = $selectedTab.find(cjone.getHref($sender.attr('href'))),
					  resizeHeight = $detailInfo.height(),
					  resizeHeight = (resizeHeight ? resizeHeight+($sender.height()*2) : 0),
                	  $resizeHeightTarget = $selectedTab.closest(me.$townList);
                	  
				$resizeHeightTarget.height(resizeHeight).addClass('open');        		
	        	me.$tabs.not($selectedTab.addClass('on')).removeClass('on');
	        	me.$haze.eq(index).text(me.options.hazeText+' '+(me.$el.attr('data-haze-text')));
	        }
        })
    };

    var Tab = core.ui('Tab', {
    	/** jquery 플러그인명  */
        bindjQuery: 'tab',
        defaults: {
            selectedIndex: 0
        },
        initialize: function (el, options) {
            var me = this,
                tabType, TabClass;

            tabType = $(el).data('tabType') || 'type01'; //'scrollTab';
            if (TabClass = TabTypes[tabType]) {
                var tab = new TabClass(el, $.extend({}, options, me.defaults));
                $.extend(me, tab);
                
            } else {
                throw new Error('탭가이드에 없는 형식입니다.');
            }
        }
    });

    if (typeof define === "function" && define.amd) {
        define('modules/tab', ['lib/jquery'], function() {
            return Tab;
        });
    }

})(jQuery, window[LIB_NAME]);


(function($, core, undefined) {
    "use strict";
	/**
     * @description 제스쳐 지원 클래스
     * @class
	 * @name cjone.ui.Gesture
	 * @extends cjone.ui.View
	 */
    if (core.ui.Gesture) { return; }

    var util = core.util;
    var Gesture = core.ui('Gesture', /** @lends cjone.ui.Gesture */{
    	/**	기본 옵션값 선언부	*/
        defaults: {
            threshold: 50,				/** @member {Double} threshold - 최소시간 */
            direction: 'horizontal'		/** @member {String} direction - 허용시킬 방향 */
        },
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Boolean}  options.threshold - 최소시간
         * @param {Boolean}  options.direction -  허용시킬 방향
         */
        initialize: function(el, options) {
            var me = this;
            if (me.supr(el, options) === false) {
                return;
            }

            me.isHoriz = me.options.direction === 'horizontal' || me.options.direction === 'both';
            me.isVerti = me.options.direction === 'vertical' || me.options.direction === 'both';
            me._bindGestureEvents();
        },
        /**
         * 이벤트 바인딩
         * @private
         *  */
        _bindGestureEvents: function() {
            var me = this,
                touchStart,
                downPos,
                isSwipe = false,
                isScroll = false,
                $doc = $(document);

            me.$el[0].onselectstart = function (){ return false; };
            me.$el.attr('unselectable', 'on');
            me.$el.on('mousedown.gesture, touchstart.gesture', function(downEvent) {
                if (downEvent.type === 'mousedown') {
                    downEvent.preventDefault();
                }
                downPos = touchStart = util.getEventPoint(downEvent);
                isSwipe = isScroll = false;


                $doc.on('mousemove.gesture'+me.cid+' touchmove.gesture'+me.cid, function (moveEvent) {
                    var touch = util.getEventPoint(moveEvent),
                        diff, slope, swipeY, swipeX;
                    if (!touchStart || isScroll) {
                        return;
                    }

                    diff = util.getDiff(touch, touchStart);
                    if (!isSwipe) {
                        swipeX = Math.abs(diff.y) / Math.abs(diff.x || 1);
                        swipeY = Math.abs(diff.x) / Math.abs(diff.y || 1);
                        if ((swipeX < 1 && me.isHoriz) || (swipeY < 1 && me.isVerti)) {
                            isSwipe = true;
                            touch.event = moveEvent;
                            me.triggerHandler('gesturestart', touch);
                        } else {
                            if ((me.isHoriz && swipeX > 1) || (me.isVerti && swipeY > 1)) {
                                isScroll = true;
                            }
                        }
                    }

                    if (isSwipe) {
                        moveEvent.stopPropagation();
                        moveEvent.preventDefault();

                        touch.diff = diff;
                        touch.direction = util.getDirection(touchStart, touch,  me.options.direction); 
                        touch.event = moveEvent;
                        me.triggerHandler('gesturemove', touch);
                    }
                }).on('mouseup.gesture'+me.cid+' mousecancel.gesture'+me.cid+' touchend.gesture'+me.cid+' touchcancel.gesture'+me.cid, function (upEvent) {
                    if (isSwipe && touchStart) {
                        var touch = util.getEventPoint(upEvent, 'end');
                        touch.diff = util.getDiff(touch, touchStart);

                        touch.direction = util.getDirection(touchStart, touch, me.options.direction);
                        touch.event = upEvent;
                        if(Math.abs(touch.diff.x) > me.options.threshold
                            || Math.abs(touch.diff.y) > me.options.threshold) {
                            me.triggerHandler('gestureend', touch);
                        } else {
                            me.triggerHandler('gesturecancel', touch);
                        }
                        switch(touch.direction) {
                            case 'left':
                            case 'right':
                                if(Math.abs(touch.diff.x) > me.options.threshold && me.isHoriz){
                                    me.triggerHandler('gesture'+touch.direction);
                                }
                                break;
                            case 'up':
                            case 'down':
                                if(Math.abs(touch.diff.y) > me.options.threshold && me.isVerti){
                                    me.triggerHandler('gesture'+touch.direction);
                                }
                                break;
                        }
                    }
                    touchStart = null;
                    isScroll = false;

                    $doc.off('.gesture'+me.cid);
                });
            }).on('click', 'a, button', function(e) {
                if(!downPos){ return; }
                var pos = util.getEventPoint(e);
                if(downPos.x != pos.x || downPos.y != pos.y) {
                    e.preventDefault();
                }
            });
        },

		/**
		 * 이벤트 release
		 *  */
        release: function(){
            this.off('.gesture'+this.cid);
            this.supr();
        }
    });

    core.ui.bindjQuery(Gesture, 'gesture');
    if (typeof define === 'function' && define.amd) {
        define('modules/gesture', [], function (){
            return Gesture;
        });
    }
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
    "use strict";
	/**
	 * @description 전체체크 기능지원
	 * @class 
	 * @name cjone.ui.checkboxAllChecker
	 * @extends cjone.ui.View
	 */
    if (core.ui.checkboxAllChecker) {
        return;
    }

    var CheckboxAllChecker = core.ui('CheckboxAllChecker', /** @lends cjone.ui.checkboxAllChecker */{
    	/** jquery 플러그인명  */
        bindjQuery: 'checkboxAllChecker',
        /**	기본 옵션값 선언부	*/
        defaults: {
            handler: null
        },
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         * @param {Object}  options.handler - 
         */
        initialize: function (el, options) {
            var me = this;

            if (me.supr(el, options) === false) {
                return;
            }
			me.$wrapper = me.$el.closest(me.$el.attr('data-check-all')).find('input:not(:disabled)').not(me.$el);            
			if (me.$wrapper.size() === 0) { return; }            
            me._bindEvents();
        },
        
		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
        _bindEvents: function () {
            var me = this,
                selector = ':checkbox:enabled:not(.ui_checkall_ignore)';

            me.$el.on('change', function (e) {
            	var $this = $(this);
                me.$wrapper.prop('checked', $this.is(':checked')).trigger('change');
            });
            
            me.$wrapper.on('change', function (e) {
            	var $this = $(this),
            		  trigger = $this.attr('data-trigger'),
            		  handler = $this.attr('data-handler');
                
                //같은 항목의 선택을 눌렀을때
                me.$wrapper.filter('[data-handler="'+(trigger)+'"]').prop('checked', me.$wrapper.filter('[data-trigger="'+(trigger)+'"]').is(':checked')).trigger('change');
                
                if(me.$el.context.type == 'checkbox'){
	                var $checkboxs = me.$el.closest(me.$el.attr('data-check-all')).find('input[type="'+(me.$el.context.type)+'"]:not(:disabled)').not(me.$el),
	                	  checkboxSize = $checkboxs.size(),
	                	  checkedCount = 0;
	
	                $checkboxs.each(function () {
	                	checkedCount += ($(this).prop('checked') == true ? 1 : 0);
	                });
	                
	                me.$el.prop('checked', (checkedCount == checkboxSize ? true: false));
	                me.$el.parent()[(me.$el.prop('checked') == true ? 'addClass': 'removeClass')]('on');
                }
            });
        }
    });

    if (typeof define === 'function' && define.amd) {
        define('modules/checkbox-all-checker', [], function (){
            return CheckboxAllChecker;
        });
    }

})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
    "use strict";
	/**
	 * @description Dropdown 클래스
	 * @class 
	 * @name cjone.ui.Dropdown
	 * @extends cjone.ui.View
	 * @deprecated
	 */
    if (core.ui.Dropdown) {
        return;
    }

    var $doc = $(document),
        $win = $(window),
        isTouch = core.browser.isTouch;

    var contains = function (parentEl, el) {
        if (!parentEl || !el) { return false; }
        if (parentEl === el || $.contains(parentEl, el)) { return true; }
        return false;
    };

    var Dropdown = core.ui('Dropdown', /** @lends cjone.ui.Dropdown */{
    	/** jquery 플러그인명  */
        bindjQuery: 'dropdown',
        /**	selector 선언부		*/
        defaults: {
            wrapper: 'parent', //
            dropdown: '.ui_dropdown_box',
            activeClass: 'on'
        },
		/**
         * 생성자
         * @constructors
         * @param {String|Element|jQuery} el
         * @param {Object} options
         */
        initialize: function (el, options) {
            var me = this;
            if(me.supr(el, options) === false) { return false; }

            me._findControls();
            me._bindEvents();
        },
        
		/**
		 * 이벤트 바인딩
		 * @private
		 *  */
        _bindEvents: function () {
            var me = this, $target;

            me.$el.on('click', function(e) {
                e.preventDefault();

                if (me.$wrapper.hasClass(me.options.activeClass)) {
                    me.hide();
                } else {
                    me.show();
                }
            });
        },
        
        /**
         * 컨트롤 요소를 찾음
         * @private
         *  */
        _findControls: function() {
            var me = this;
            switch(true) {
                case me.$el.attr('data-target'):
                    me.$wrapper = me.$el;
                    break;
                case me.options.wrapper === 'parent':
                    me.$wrapper = me.$el.parent();
                    break;
                case me.options.wrapper.indexOf('closest') === 0:
                    me.$wrapper = me.$el.closest(me.options.wrapper.split('=')[1]);
                    break;
                default:
                    me.$wrapper = $(me.options.wrapper);
                    break;
            }
            return $();
        },
        show: function () {
            var me = this;

            $doc.on('touchstart.' + me.cid + ' click.' + me.cid, function(e) {
                if (!contains(me.$wrapper[0], e.target)) {
                    me.hide();
                }
            });
            var focusTimer;
            me._toggle(true);
            me.$wrapper.on('focusin focusout', function(e) {
                clearTimeout(focusTimer);

                switch (e.type) {
                    case 'focusout':
                        focusTimer = setTimeout(function() {
                            me.hide();
                        }, 300);
                        break;
                }
            });
            me.options.show && me.options.show();
        },
        hide: function () {
            var me = this;

            me._toggle(false);
            $doc.off('click.' + me.cid);
            me.options.hide && me.options.hide();
        },
        _toggle: function (flag) {
            var me = this;
            me.$wrapper.toggleClass(me.options.activeClass, flag);
        }
    });

    if (typeof define === 'function' && define.amd) {
        define('modules/dropdown', [], function (){
            return Dropdown;
        });
    }
})(jQuery, window[LIB_NAME]);


(function ($, core, undefined) {
    "use strict";
    /*
     * @description 기능키 할당
     * @function
     * @name cjone.ui 
	 */
    if (core.ui.isNumberKeys) { return; }

    core.ui.isNumberKeys = function (keyCode) {
        return (keyCode >= 48 && keyCode <= 57)
            || (keyCode >= 96 && keyCode <= 105) // 오른쪽 숫자키
            || (keyCode === 37) // left
            || (keyCode === 39)  // right
            || (keyCode === 9)// left
            || (keyCode === 46) // delete
            || (keyCode === 35) // end
            || (keyCode === 36) // home
            || (keyCode === 144) // num lock
            || (keyCode === 109) // -
            || (keyCode === 189) // .
            || (keyCode === 8); // backspace
    };

	/**
	 * @deprecated
	 *  */
    core.ui.setBodyOverflow = function (flag) {
        var $html = $('html'),
            cnt   = $html.data('overflowCount') === undefined ? 0 : $html.data('overflowCount');

        if (flag) {
            cnt += 1;
            if (cnt === 1) {
                $html.css('overflow', 'hidden');
            }
        } else {
            cnt = Math.max(cnt - 1, 0);
            if (cnt === 0) {
                $html.css('overflow', '');
            }
        }

        $html.data('overflowCount', cnt);
    };
    
    /**
    * @description 상단 fixed 밑에 포커스가 가려질 경우 스크롤 이동
    */
    core.util.supportFocus = function ($el, opts) {
        opts || (opts = {});
        
        var $headerWrap = $el,
              $win = $(window),
              $doc = $(document),
              callback = opts.callback || null,
              status = 0;
        
		$doc.on({
            'keyup.document': function (e) {
                if(e.keyCode !== 9) return;
                var $this = $(e.target);
				if($this.closest($el).size() > 0) return;

                if($this.offset().top < $win.scrollTop()+$headerWrap.height()){
                    status = -1;
                    cjone.util.scrollToElement($this, {offset: $el.outerHeight(true)+1});
                }
                if(callback) callback({$obj: $this, staus: status});
            }
        });

    };

	/**
	 * @description 특정태그 위치로 스크롤 이동
	 * @function 
	 *  */
    core.util.scrollToElement = function($el, opts) {
        opts || (opts = {});
        var top,
            duration = opts.duration || 'fast',
            easing = opts.easing || 'easeOutQuad',
            step = opts.step || "",
            complete = opts.complete || null,
            scroller;

        if (opts.scroller) {
            scroller = $(opts.scroller).children();
            top = ($el.offset().top - scroller.offset().top) + scroller.scrollTop();
        } else {
            scroller = $('html, body');
            top = $el.offset().top;
        }

        scroller.stop().animate({
            scrollTop: top - (opts.offset|0)
        }, {
            duration: duration,
            easing: easing,
            complete: complete
        });
    };

})(jQuery, window[LIB_NAME]);

/* ============================================================
 * jQuery Easing v1.3 - http://gsgd.co.uk/sandbox/jquery/easing/
 *
 * Open source under the BSD License.
 *
 * Copyright © 2008 George McGinley Smith
 * All rights reserved.
 * https://raw.github.com/danro/jquery-easing/master/LICENSE
 * ======================================================== */
jQuery.easing.jswing=jQuery.easing.swing,jQuery.extend(jQuery.easing,{def:"easeOutQuad",swing:function(a,b,c,d,e){return jQuery.easing[jQuery.easing.def](a,b,c,d,e);},easeInQuad:function(a,b,c,d,e){return d*(b/=e)*b+c;},easeOutQuad:function(a,b,c,d,e){return -d*(b/=e)*(b-2)+c;},easeInOutQuad:function(a,b,c,d,e){return (b/=e/2)<1?d/2*b*b+c:-d/2*(--b*(b-2)-1)+c;},easeInCubic:function(a,b,c,d,e){return d*(b/=e)*b*b+c;},easeOutCubic:function(a,b,c,d,e){return d*((b=b/e-1)*b*b+1)+c;},easeInOutCubic:function(a,b,c,d,e){return (b/=e/2)<1?d/2*b*b*b+c:d/2*((b-=2)*b*b+2)+c;},easeInQuart:function(a,b,c,d,e){return d*(b/=e)*b*b*b+c;},easeOutQuart:function(a,b,c,d,e){return -d*((b=b/e-1)*b*b*b-1)+c;},easeInOutQuart:function(a,b,c,d,e){return(b/=e/2)<1?d/2*b*b*b*b+c:-d/2*((b-=2)*b*b*b-2)+c;},easeInQuint:function(a,b,c,d,e){return d*(b/=e)*b*b*b*b+c;},easeOutQuint:function(a,b,c,d,e){return d*((b=b/e-1)*b*b*b*b+1)+c;},easeInOutQuint:function(a,b,c,d,e){return (b/=e/2)<1?d/2*b*b*b*b*b+c:d/2*((b-=2)*b*b*b*b+2)+c;},easeInSine:function(a,b,c,d,e){return -d*Math.cos(b/e*(Math.PI/2))+d+c;},easeOutSine:function(a,b,c,d,e){return d*Math.sin(b/e*(Math.PI/2))+c;},easeInOutSine:function(a,b,c,d,e){return -d/2*(Math.cos(Math.PI*b/e)-1)+c;},easeInExpo:function(a,b,c,d,e){return b==0?c:d*Math.pow(2,10*(b/e-1))+c;},easeOutExpo:function(a,b,c,d,e){return b==e?c+d:d*(-Math.pow(2,-10*b/e)+1)+c;},easeInOutExpo:function(a,b,c,d,e){return b==0?c:b==e?c+d:(b/=e/2)<1?d/2*Math.pow(2,10*(b-1))+c:d/2*(-Math.pow(2,-10*--b)+2)+c;},easeInCirc:function(a,b,c,d,e){return -d*(Math.sqrt(1-(b/=e)*b)-1)+c;},easeOutCirc:function(a,b,c,d,e){return d*Math.sqrt(1-(b=b/e-1)*b)+c;},easeInOutCirc:function(a,b,c,d,e){return (b/=e/2)<1?-d/2*(Math.sqrt(1-b*b)-1)+c:d/2*(Math.sqrt(1-(b-=2)*b)+1)+c;},easeInElastic:function(a,b,c,d,e){var f=1.70158,g=0,h=d;if(b==0)return c;if((b/=e)==1)return c+d;g||(g=e*.3);if(h<Math.abs(d)){h=d;var f=g/4;}else var f=g/(2*Math.PI)*Math.asin(d/h);return -(h*Math.pow(2,10*(b-=1))*Math.sin((b*e-f)*2*Math.PI/g))+c;},easeOutElastic:function(a,b,c,d,e){var f=1.70158,g=0,h=d;if(b==0)return c;if((b/=e)==1)return c+d;g||(g=e*.3);if(h<Math.abs(d)){h=d;var f=g/4;}else var f=g/(2*Math.PI)*Math.asin(d/h);return h*Math.pow(2,-10*b)*Math.sin((b*e-f)*2*Math.PI/g)+d+c;},easeInOutElastic:function(a,b,c,d,e){var f=1.70158,g=0,h=d;if(b==0)return c;if((b/=e/2)==2)return c+d;g||(g=e*.3*1.5);if(h<Math.abs(d)){h=d;var f=g/4;}else var f=g/(2*Math.PI)*Math.asin(d/h);return b<1?-0.5*h*Math.pow(2,10*(b-=1))*Math.sin((b*e-f)*2*Math.PI/g)+c:h*Math.pow(2,-10*(b-=1))*Math.sin((b*e-f)*2*Math.PI/g)*.5+d+c;},easeInBack:function(a,b,c,d,e,f){return f==undefined&&(f=1.70158),d*(b/=e)*b*((f+1)*b-f)+c;},easeOutBack:function(a,b,c,d,e,f){return f==undefined&&(f=1.70158),d*((b=b/e-1)*b*((f+1)*b+f)+1)+c;},easeInOutBack:function(a,b,c,d,e,f){return f==undefined&&(f=1.70158),(b/=e/2)<1?d/2*b*b*(((f*=1.525)+1)*b-f)+c:d/2*((b-=2)*b*(((f*=1.525)+1)*b+f)+2)+c;},easeInBounce:function(a,b,c,d,e){return d-jQuery.easing.easeOutBounce(a,e-b,0,d,e)+c;},easeOutBounce:function(a,b,c,d,e){return (b/=e)<1/2.75?d*7.5625*b*b+c:b<2/2.75?d*(7.5625*(b-=1.5/2.75)*b+.75)+c:b<2.5/2.75?d*(7.5625*(b-=2.25/2.75)*b+.9375)+c:d*(7.5625*(b-=2.625/2.75)*b+.984375)+c;},easeInOutBounce:function(a,b,c,d,e){return b<e/2?jQuery.easing.easeInBounce(a,b*2,0,d,e)*.5+c:jQuery.easing.easeOutBounce(a,b*2-e,0,d,e)*.5+d*.5+c;}});

if (!Object.keys) {
  Object.keys = function(obj) {
    var keys = [];

    for (var i in obj) {
      if (obj.hasOwnProperty(i)) {
        keys.push(i);
      }
    }

    return keys;
  };
}


(function ($, core) {
    "use strict";
    var $doc = $(document),
        $win = $(window);

	/**
	 * 레이어팝업 열기 확장형 함수
	 * @function
	 *  */
    core.openModal = function (href, options) {
        var def = $.Deferred();
        var params = '';
        for(var key in options){
            if(typeof options[key] == 'object')            params += ' data-'+key+'=\''+JSON.stringify(options[key])+'\'';
            if(typeof options[key] == 'string')             params += ' data-'+key+'="'+options[key]+'"';
        }
        
        //캐싱 처리용
        var t = new Date().getTime();
		if(href.indexOf('?')>-1){
		 	href += '&t='+t; 
		}else{
		 	href += '?t='+t;
		}
        var $a = $('<a href="'+(href)+'" class="hide" data-control="modal" '+(params)+'>createModal</a>');
        $(document.body).append($a);
        def.resolve();
        
        $a.trigger('click');
        def.done(function () {
          $a.remove();
        });
        
        if($('.main_wrap').size() > 0){
        	$('body').height('auto');
        }
        
        cjone.$doc.on({
        	'modal:hidden': function () {
        		if(!options || !options.el) return;
        		options.el.focus();
        	}
        });
    };
    
    /**
     * @description 레이어 팝업 닫기 함수
     * @function
     *  */
    core.closeModal = function (obj) {
    	if(obj){
    		$(obj).closest('.ui_modal').data('ui_modal').close();
    	}else{
    		$('.ui_modal').last().data('ui_modal').close();
    	}
    };
    
    /**
     * html 페이지가 ajax형태가 아닌 페이지 내에서 열리는 경우
     * @deprecated
     *  */
    core.innerModal = function (selector, closeSelector) {
    	var def = $.Deferred();
    	if(typeof selector == 'object') selector = '#'+selector.attr('id');
    	var $a = $('<a href="'+(selector)+'" class="hide" data-control="modal">createModal</a>');
        $(document.body).append($a);
        def.resolve();
        
        $a.trigger('click');
        def.done(function () {
          $a.remove();
        });
        
        if(!g_layer.layerStack[g_layer.layerStack.length-1]) g_layer.layerStack[g_layer.layerStack.length-1] = $(closeSelector);
    };
    
    /**
     * html 페이지가 ajax형태가 아닌 페이지 내에서 열리는 경우에 대한 닫기 함수
     * @deprecated
     *  */
    core.closeInnerModal = function (selector, closeSelector) {
    	$(selector).data('ui_modal').close();
    };
    
    /**
     * @description 등록된 이벤트 제거<br/>사용시 주의해야 함
     * @example
     		$('...').deleteEvent();
     *  */
	$.fn.deleteEvent = function () {
  		var detail = $._data(this[0]);
  		for(var key in detail){
    		delete detail[key];
  		}
	};
    
	/**
     *	@description 위치값 이동
     * @member Of plugin
     * @name setPosition
     * @function
     * @param {number} options.posX x축 좌표
     * @param {number} options.posY y축좌표
     * @param {number} options.posZ Z축좌표
     * @param {number} options.time 애니메이션 시간
     * @param {Boolean} options.usingCSS3 CSS3기능 사용여부
     * 
     * @param {String} options.transform css3.transform 속성
     * @param {String} options.transition css3.transition 속성
     * 
     * @example
			$('body').setPosition({
			  	posX: '50%',
			  	time: 10000,
			  	transition: 'transform 500ms',
				usingCSS3: true  
			});
     *  */
    $.fn.setPosition = function (options) {
		var me = this,
			 defaults = {
	    		 posX:  0,
	    		 posY:  0,
	    		 posZ: 0,
	    		 time: 0,
	    		 usingCSS3: true,
	    		 transform: 'translate3d(_posX_, _posY_, 1px)',
	    		 transition: 'transform 750ms cubic-bezier(0.86, 0, 0.07, 1) 0ms'
			 },
			 options = $.extend(defaults, options);
			 
		var cssPrefix = '',
			 isSupport = (core.browser.isIE && core.browser.version<10 ? false: true),
			 isSupport = (options.usingCSS3 == true && isSupport == true ? true: false),
			 posX = (typeof options.posX === 'number'? options.posX+'px' : options.posX),
			 posY = (typeof options.posY === 'number'? options.posY+'px' : options.posX),
			 posZ = (typeof options.posZ === 'number'? options.posZ+'px' : options.posZ);
			 
		switch(isSupport){
			case true:
				if(core.browser.isWebKit)	            	cssPrefix = '-webkit-';
				if(core.browser.isIE)							cssPrefix = '-ms-';
	
				me.get(0).style[cssPrefix+'transform'] = options.transform.replace('_posX_', posX).replace('_posY_', posY).replace('_posZ_', posZ);
				me.get(0).style[cssPrefix+'transition'] = cssPrefix+options.transition;
			break;
			default:
				this.animate({
					'left': posX,
					'top': posY
				}, options.time);
			break;			
		}
		return this;
	};        

    
    /**
     * @description 대체 텍스트 설정용 확장 클래스
     * @example
     		tooltip, toggle등
     *  */
	$.fn.setHaze = function ($parent, $group) {
		if($parent.data('haze')==null){
        	var haze = ($parent.find('.haze').size() > 0 ? '.haze' : '[data-handler="haze"]');
        	$parent.data('haze', $parent.find(haze).clone(true)).find(haze).remove();
    	}
    	var $on = this.closest($parent).find('.on');
    	var $addTag = ($on.find('a').size() > 0? $on.find('a'): $on);
    	$addTag.append($parent.data('haze'));
    	return this;
	};
	
	/**
	 * @description formSkin 적용
	 * @deprecated
	 * @sample http://dev.cjone.com:8001/cjmweb/script/wsg/script_form.html
	 * @example $('input[type="radio"],input[type="checkbox"]').formSkin();
	 *  */
	$.fn._formSkin = function (options) {
		var self = this,
			 options = $.extend({}, options);
			 
		self.on({
			'change': function () {
		    	var $this = $(this),
		        	  type = $this.attr('type'),
		        	  isChecked = $this.prop('checked');
		        	  
				$this.attr('data-skin', 'accept');
		        	  
				if(type == 'radio'){
		        	if(isChecked == true)	$('[name="'+($this.attr('name'))+'"]').not($this).parent().removeClass('on');
				}				
				$this.parent()[(isChecked ? 'addClass': 'removeClass')]('on');
			}
		}).trigger('change');
	};
	
	/**
	 * @description input box의 스킨 처리를 위한 이벤트
	 * @deprecated
	 *  */
	$.fn.labelSkin = function (options) {
		var self = this,
			  options = $.extend({nodes:null, tag: null, type: 'radio'}, options),
			  $target = self[options.nodes](options.tag);
			  
		self.on({
			'focus': function () {
				var $this = $(this);
				$this.prop('checked', true).triggerHandler('change');
			},
			'change': function (e) {
				var $this = $(this),
					  isChecked = $this.prop('checked');
				
				if($this.attr('type') == 'radio') $target.removeClass('on');
				var $parents = $this[options.nodes](options.tag)[(isChecked == true? 'addClass': 'removeClass')]('on').parent();
				$parents.addClass('cursor').siblings().removeClass('cursor');
				$this.triggerHandler('checked:end', {data: {$el: $this, options: options} });
			} 
		});
  		return this;
	};
	/**
     * @description 키보드 접근성 tab키를 위한 jquery function
     * @example
        $('#msg_write').accessableTab({first: 'input[type="radio"]', focus: '[href="#msg_write"]', last: 'button.close'});
        
        $('#event').accessableTab({first: '.bx-prev', last: 'button.close', focus: '.circle a', callback: function () {
            this.closest('.brand').removeClass('on');    
        }});
        
        @param {string} first 키보드 탭시 처음 위치하는 항목
        @param {string} last 키보드 탭시 마지막에 위치하는 항목
        @param {string} focus 마지막항목이나 처음 항목에 대한 포커스 초과시 포커스가 이동해야 할 항목
     *  */
    $.fn.accessableTab = function (options) {
        var $el = this;
        var options = $.extend({className: 'on', focus: $($el.selector), delayTime: 0, callback: function () {}}, options);
        
        if(typeof options.focus == 'string'){
        	$(options.focus).one({
        		'click.keyTab': function () {
        			options.focus = $(this);	
        		}
        	});
        }
        
        $el.off('keydown.accessable, keyup.accessable').on({
            'keydown.accessable': function (e) {
                if(e.keyCode !=9 ) return;
                
                clearTimeout($el.data('keydown.timer'));
                $el.data('keydown.timer', setTimeout(function () {
                    var $target = $(e.target),
                    	  isClose = {
	                        forward: ($target.filter(options.last).size() && e.shiftKey == false) || false,
	                        backward: (($target.filter(options.first).size()>0 && e.shiftKey == true)) || false
	                    },
	                    callback= {
	                    	type: 'close', 
	                    	data: {
	                    		$el: $el,
	                    		$target: $target,
	                    		forward: isClose.forward,
	                    		backward: isClose.backward,
	                    		isBackTab: e.shiftKey
	                    	}
	                    };
		
                    if(isClose.forward || isClose.backward){
                        $el.removeClass(options.className);
                        options.focus.focus();
                        options.callback.call($el);
                        $el.triggerHandler('key:after', callback);
                        
                        if(isClose.forward == true){
                        	//setTimeout(function () {
                    			options.focus.focus();
                        	//}, 50);
                        }
                    }else{
                    	callback.type = 'key';
                        $el.triggerHandler('key:after', callback);
                    }
                }, options.delayTime));
            }
        });
        return this;
    };
    
    /**
	 * @description object에 타이머 설정
	 * @example
			cjone.$win.setTimeoutCallback(function () {
				alert(1);
			}, {delayTime: 0});
	 *  */
	$.fn.setTimeoutCallback = function (callback, options) {
		var options = $.extend({delayTime: 35});
		
		clearTimeout(this.data('time'));
		this.data('time', setTimeout(function () {
			callback();	
		}, options.delayTime));
		return this;
	};
            
	cjone.$doc = $(document);
	cjone.$win = $(window);
	cjone.$htmlBody = $('html, body');
	cjone.util.arrayInIndex = function (arrays, value) {
		var index = -1;
	  	for(var key in arrays){
	    	if(arrays[key] == value){
	      		return parseFloat(key);
	    	}
	  	}
		return index;
	};

if (!Array.prototype.lastIndexOf){
	/**
	 * @description IE7, 8 지원용 함수
	 * @function
	 *  */
	Array.prototype.lastIndexOf = function(searchElement /*, fromIndex*/)	{
		"use strict";

    	if (this == null)      throw new TypeError();

    	var t = Object(this);
    	var len = t.length >>> 0;
    	if (len === 0)      return -1;

    	var n = len;
    	if (arguments.length > 1)    {
      		n = Number(arguments[1]);
      		if (n != n)        n = 0;
      		else if (n != 0 && n != (1 / 0) && n != -(1 / 0))
        	n = (n > 0 || -1) * Math.floor(Math.abs(n));
		}

    	var k = n >= 0 ? Math.min(n, len - 1) : len - Math.abs(n);

		for (; k >= 0; k--)    {
			if (k in t && t[k] === searchElement)        return k;
    	}
    	return -1;
	};
}

})(jQuery, window[LIB_NAME]);
