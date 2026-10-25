/**
 * Kira Hexo Theme - 图片懒加载辅助函数
 * @description 为文章中的图片注入原生懒加载属性，保留原有全部属性
 */

'use strict';

/**
 * 为所有 img 标签添加原生 loading/decoding 属性
 * 不重建标签，因此 style/class/width 等原有属性全部保留
 * @param {string} content - 文章 HTML 内容
 * @returns {string} 处理后的 HTML 内容
 */
function imageAutoLazyloadHelper(content) {
	return content.replace(/<img\b/gi, '<img loading="lazy" decoding="async" ');
}

hexo.extend.helper.register('image_auto_lazyload', imageAutoLazyloadHelper);
