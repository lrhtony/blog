/**
 * Kira Hexo Theme - 标题锚点 id 拼音化
 * @description 渲染器（hexo-renderer-markdown-it 的 anchors 规则）给标题打的
 * id 是原文（中文标题即中文 id）。这里统一改写为拼音 slug，与历史锚点
 * URL 保持一致（原由 hexo-toc 提供，因其依赖链存在安全漏洞而移除），
 * 并对同名标题的 id 去重，避免目录与锚点跳到第一个同名标题。
 * 相关：根 package.json 的 overrides（linkify-it ^5、transliteration 内
 * yargs ^17）同样为清除依赖安全告警所设，理由见依赖变更的提交说明。
 */

'use strict';

const { slugify } = require('transliteration');

hexo.extend.filter.register('after_post_render', function (data) {
	if (!data.content) return data;

	const seenIds = new Set();

	data.content = data.content.replace(
		/(<h[1-6])([^>]*?)\sid="([^"]*)"([^>]*)>([\s\S]*?)<\/h[1-6]>/gi,
		function (match, openTag, preAttrs, oldId, postAttrs, inner) {
			// 标题纯文本：仅去内联标签。刻意不做 HTML 实体解码——历史上
			// hexo-toc（cheerio decodeEntities:false）就是拿未解码文本做的
			// slugify（如 "&amp;" 产生 "amp" 段），解码会改变既有锚点 URL
			const text = inner
				.replace(/<[^>]+>/g, '')
				.trim();

			let id = slugify(text, { lowercase: true, separator: '-' });
			if (!id) id = oldId; // 纯符号标题等无法音译时保留原 id
			if (!id) return match;

			// 同名标题追加序号后缀（延续历史行为：-1、-2…）
			let finalId = id;
			let n = 1;
			while (seenIds.has(finalId)) {
				finalId = id + '-' + n++;
			}
			seenIds.add(finalId);

			return (
				openTag + preAttrs + ' id="' + finalId + '"' + postAttrs + '>' +
				inner + '</' + openTag.slice(1) + '>'
			);
		}
	);

	return data;
}, 20);
