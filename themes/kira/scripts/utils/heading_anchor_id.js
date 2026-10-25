/**
 * Kira Hexo Theme - 标题锚点 id 修正
 * @description hexo-toc 会把锚点 id 放进标题内层的 <span>，而 Hexo 内核的
 * toc() helper 只解析 <hN> 标签自身的 id，导致目录链接没有 href。
 * 此处把 id 提升到标题标签上，使目录链接在服务端原生可用。
 */

'use strict';

hexo.extend.filter.register('after_post_render', function (data) {
	if (!data.content) return data;

	data.content = data.content.replace(
		/(<h[1-6])([^>]*?)>\s*<span id="([^"]+)">([\s\S]*?)<\/span>\s*<\/h[1-6]>/gi,
		function (match, openTag, attrs, id, inner) {
			// 标题上已有 id 则保持原样，避免重复 id
			if (/\sid=/.test(attrs)) return match;
			return openTag + attrs + ' id="' + id + '">' + inner + '</' + openTag.slice(1) + '>';
		}
	);

	return data;
});
