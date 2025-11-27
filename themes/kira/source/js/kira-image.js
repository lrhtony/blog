/**
 * Kira Hexo Theme - 图片预览功能
 * @description 点击文章图片放大预览，支持切换和缩放
 */

window.addEventListener('load', () => {
	// ============================================
	// 常量定义
	// ============================================
	
	/** 图片切换动画时长（毫秒） */
	const SWITCH_ANIMATION_DURATION = 200;
	
	/** 图片放大倍数 */
	const ZOOM_SCALE = 2;
	
	/** 匹配 transform translate 值的正则表达式 */
	const TRANSLATE_REGEX = /translate\((-?\d+(?:\.\d+)?)px,\s*(-?\d+(?:\.\d+)?)px\)/;

	// ============================================
	// 工具函数
	// ============================================

	/**
	 * 阻止默认事件
	 * @param {Event} ev - 事件对象
	 */
	const preventDefault = (ev) => {
		ev.preventDefault();
	};

	// ============================================
	// DOM 元素获取
	// ============================================

	/** 获取文章中需要预览的图片 */
	const articleImageDoms = Array.from(
		document.querySelectorAll(
			'div.kira-content > div.kira-main-content article img:not(.disabled-kira-image)'
		)
	);

	const modal = document.querySelector('.kira-image > .kira-image-modal');
	const nowImage = modal.querySelector('.kira-image-now > img');
	const prevImage = modal.querySelector('.kira-image-prev > img');
	const nextImage = modal.querySelector('.kira-image-next > img');
	const zoomButton = modal.querySelector(
		'.kira-image-header > .kira-image-operation > #kira-image-operation-button-zoom'
	);

	// ============================================
	// 缩放功能
	// ============================================

	/**
	 * 放大图片
	 */
	const zoomIn = () => {
		nowImage.classList.add('zoom');
		zoomButton.querySelector('i').classList.remove('icon-zoom-in');
		zoomButton.querySelector('i').classList.add('icon-zoom-out');
	};

	/**
	 * 缩小图片并重置位置
	 */
	const zoomOut = () => {
		nowImage.style.transform = 'translate(0px, 0px)';
		nowImage.classList.remove('zoom');
		zoomButton.querySelector('i').classList.remove('icon-zoom-out');
		zoomButton.querySelector('i').classList.add('icon-zoom-in');
	};

	zoomButton.addEventListener('click', () => {
		if (zoomButton.querySelector('i').classList.contains('icon-zoom-in')) {
			zoomIn();
		} else {
			zoomOut();
		}
	});

	// ============================================
	// 图片拖动功能
	// ============================================

	/**
	 * 处理放大后图片的拖动
	 * @param {MouseEvent} evt - 鼠标按下事件
	 */
	const onDragStart = (evt) => {
		if (!nowImage.classList.contains('zoom')) return;
		if (evt.button !== 0) return; // 仅匹配鼠标左键

		const startTransform = nowImage.style.transform;
		const matchResult = TRANSLATE_REGEX.exec(startTransform) || [0, 0, 0];
		const initialX = Number(matchResult[1]) * ZOOM_SCALE;
		const initialY = Number(matchResult[2]) * ZOOM_SCALE;

		// 鼠标按下的坐标
		const startX = evt.clientX;
		const startY = evt.clientY;

		/**
		 * 拖动过程中更新图片位置
		 * @param {MouseEvent} evt - 鼠标移动事件
		 */
		const onDragging = (evt) => {
			const finalX = initialX + (evt.clientX - startX);
			const finalY = initialY + (evt.clientY - startY);
			// 因为放大了倍数，所以移动时需要除以相应的倍数
			nowImage.style.transform = `translate(${finalX / ZOOM_SCALE}px, ${finalY / ZOOM_SCALE}px)`;
		};

		/**
		 * 拖动结束清理事件监听
		 */
		const onDragEnd = () => {
			nowImage.removeEventListener('mousemove', onDragging);
			nowImage.removeEventListener('mouseup', onDragEnd);
		};

		nowImage.addEventListener('mouseup', onDragEnd);
		nowImage.addEventListener('mousemove', onDragging);
	};

	nowImage.addEventListener('mousedown', onDragStart);
	nowImage.addEventListener('click', zoomIn);

	// ============================================
	// 图片数据管理
	// ============================================

	/** 当前显示的图片索引 */
	let nowImageIndex = undefined;

	/** 所有图片的属性缓存 */
	const imgProps = [];

	/**
	 * 根据当前索引设置图片属性
	 */
	const setImageProp = () => {
		const index = nowImageIndex;
		const { src: prevSrc } = index === 0 ? imgProps[imgProps.length - 1] : imgProps[index - 1];
		const { src: nowSrc, alt: nowAlt } = imgProps[index];
		const { src: nextSrc } = index === imgProps.length - 1 ? imgProps[0] : imgProps[index + 1];

		prevImage.setAttribute('src', prevSrc);
		nowImage.setAttribute('src', nowSrc);
		nextImage.setAttribute('src', nextSrc);

		modal.querySelector('.kira-image-header > .kira-image-counter').innerText = 
			`${index + 1} / ${imgProps.length}`;
		modal.querySelector('.kira-image-header > .kira-image-title').innerText = nowAlt || '';
	};

	// ============================================
	// 模态框控制
	// ============================================

	/**
	 * 处理模态框点击（点击背景关闭）
	 * @param {MouseEvent} evt - 点击事件
	 */
	const onVisibleModalClick = (evt) => {
		if (evt.target !== modal) return;
		onClose();
	};

	/**
	 * 关闭模态框
	 */
	const onClose = () => {
		modal.classList.remove('visible');
		// 恢复页面滚动
		modal.removeEventListener('mousewheel', preventDefault);
		modal.removeEventListener('touchmove', preventDefault);
		modal.removeEventListener('click', onVisibleModalClick);
	};

	modal
		.querySelector('.kira-image-header > .kira-image-operation > #kira-image-operation-button-close')
		.addEventListener('click', onClose);

	/**
	 * 打开模态框显示指定图片
	 * @param {number} index - 图片索引
	 */
	const onKiraImagesClick = (index) => {
		nowImageIndex = index;
		zoomOut();
		setImageProp();
		modal.classList.add('visible');
		modal.addEventListener('click', onVisibleModalClick);
		// 阻止页面滚动
		modal.addEventListener('mousewheel', preventDefault, { passive: false });
		// 阻止移动端页面滚动
		modal.addEventListener('touchmove', preventDefault, { passive: false });
	};

	// ============================================
	// 图片切换功能
	// ============================================

	/** 是否正在切换图片 */
	let switchingImage = false;

	/**
	 * 切换到上一张或下一张图片
	 * @param {'prev' | 'next'} direction - 切换方向
	 */
	const switchImage = (direction) => {
		if (switchingImage) return;
		switchingImage = true;

		const imgListDom = document.querySelector('.kira-image .kira-image-modal .kira-image-list');
		zoomOut();

		setTimeout(() => {
			imgListDom.style.animationName = '';
			if (direction === 'prev') {
				nowImageIndex = nowImageIndex === 0 ? imgProps.length - 1 : nowImageIndex - 1;
			} else {
				nowImageIndex = nowImageIndex === imgProps.length - 1 ? 0 : nowImageIndex + 1;
			}
			setImageProp();
			switchingImage = false;
		}, SWITCH_ANIMATION_DURATION);

		imgListDom.style.animationName = `kira-image-to-${direction}`;
	};

	// 绑定切换按钮
	const prevButton = document.querySelector(
		'.kira-main-content > .kira-image div.kira-image-container > div.kira-image-prev-button-panel > div'
	);
	const nextButton = document.querySelector(
		'.kira-main-content > .kira-image div.kira-image-container > div.kira-image-next-button-panel > div'
	);

	prevButton.addEventListener('click', () => switchImage('prev'));
	nextButton.addEventListener('click', () => switchImage('next'));

	// ============================================
	// 初始化图片数据
	// ============================================

	articleImageDoms.forEach((articleImageDom, index) => {
		imgProps.push({
			src: articleImageDom.getAttribute('data-src') || articleImageDom.getAttribute('src'),
			alt: articleImageDom.getAttribute('alt'),
		});
		articleImageDom.addEventListener('click', () => {
			onKiraImagesClick(index);
		});
	});
});
