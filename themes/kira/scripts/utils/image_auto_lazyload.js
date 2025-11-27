/**
 * Kira Hexo Theme - 图片懒加载辅助函数
 * @description 自动为文章中的图片添加懒加载属性
 */

'use strict';

/**
 * 将普通 img 标签转换为懒加载格式
 * @param {string} content - 文章 HTML 内容
 * @returns {string} 处理后的 HTML 内容
 */
function imageAutoLazyloadHelper(content) {
	// 匹配 <img src="..." alt="..."> 格式的标签
	// 转换为带有 data-src 和 lazyload class 的格式
	const imgPattern = /<img.*?src="(.*?)".*?alt="(.*?)".*?\/?>/gi;
	
	return content.replace(
		imgPattern,
		'<img data-fancybox="gallery" data-sizes="auto" data-src="$1" alt="$2" class="lazyload">'
	);
}

hexo.extend.helper.register('image_auto_lazyload', imageAutoLazyloadHelper);
