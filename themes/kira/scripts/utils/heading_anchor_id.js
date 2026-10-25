/**
 * Kira Hexo Theme - 标题锚点 id 修正
 * @description hexo-toc 会把锚点 id 放进标题内层的 <span>，而 Hexo 内核的
 * toc() helper 只解析 <hN> 标签自身的 id，导致目录链接没有 href。
 * 此处把 id 提升到标题标签上，使目录链接在服务端原生可用；
 * 并对同名标题的 id 去重（hexo-toc 的 slugify 不去重，重复 id 会让
 * 目录与锚点跳到第一个同名标题）。
 */

'use strict';

hexo.extend.filter.register('after_post_render', function (data) {
	if (!data.content) return data;

	const seenIds = new Set();

	data.content = data.content.replace(
		/(<h[1-6])([^>]*?)>\s*<span id="([^"]+)">([\s\S]*?)<\/span>\s*<\/h[1-6]>/gi,
		function (match, openTag, attrs, id, inner) {
			// 标题上已有 id 则保持原样，避免重复 id
			if (/\sid=/.test(attrs)) return match;

			// 同名标题追加序号后缀
			let finalId = id;
			let n = 1;
			while (seenIds.has(finalId)) {
				finalId = id + '-' + n++;
			}
			seenIds.add(finalId);

			return openTag + attrs + ' id="' + finalId + '">' + inner + '</' + openTag.slice(1) + '>';
		}
	);

	return data;
}, 20);
