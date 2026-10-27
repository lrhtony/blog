/**
 * Kira Hexo Theme - 本地搜索
 * @description 基于 hexo-generator-search 生成的 search.xml 实现侧边栏文章搜索。
 * 索引懒加载：首次聚焦输入框时才请求，避免为不搜索的访客浪费带宽。
 */

// ============================================
// 常量定义
// ============================================

/** 输入防抖延迟（毫秒） */
const SEARCH_INPUT_DEBOUNCE = 150;

/** 结果超过该数量时列表需要滚动，在末尾显示统计行 */
const SEARCH_COUNT_THRESHOLD = 5;

/** 摘要截取长度（字符） */
const SEARCH_SNIPPET_LENGTH = 100;

/** 摘要中首个命中词前保留的上下文长度（字符） */
const SEARCH_SNIPPET_CONTEXT = 24;

/** 搜索评分：标题命中基础分（保证高于任何正文命中） */
const SEARCH_TITLE_WEIGHT = 1000;

/** 搜索评分：正文命中基础分（命中位置越靠前得分越高） */
const SEARCH_CONTENT_WEIGHT = 100;

// ============================================
// 模块状态
// ============================================

/** 搜索索引：null 表示尚未加载 */
let kiraSearchIndex = null;

/** 索引加载 Promise，避免重复请求 */
let kiraSearchIndexPromise = null;

/** 防抖定时器句柄 */
let kiraSearchDebounceTimer = null;

/** 是否处于 IME 组合输入中（拼音/日文等，中间态不触发搜索） */
let kiraSearchComposing = false;

/** DOM 引用 */
let kiraSearchInput = null;
let kiraSearchClearBtn = null;
let kiraSearchResults = null;
/** 组件根节点（.kira-search），用于判断点击是否在组件外 */
let kiraSearchWidget = null;
/** 供屏幕阅读器实时播报结果的视觉隐藏区域 */
let kiraSearchLive = null;

/** 文案（由模板以 data 属性注入，跟随站点语言） */
const kiraSearchMessages = {
	loading: '',
	noResult: '',
	error: '',
	count: ''
};

// ============================================
// 工具函数
// ============================================

/**
 * 转义正则表达式特殊字符
 * @param {string} str - 原始字符串
 * @returns {string} 可安全拼入正则的字符串
 */
function kiraEscapeRegExp(str) {
	return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * 转义 HTML 实体，防止文章标题/内容注入
 * @param {string} str - 原始字符串
 * @returns {string} 转义后的字符串
 */
function kiraEscapeHtml(str) {
	return str
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

/**
 * 由关键词列表构建全局高亮正则（不区分大小写）
 * @param {string[]} keywords - 关键词数组
 * @returns {RegExp} 高亮正则
 */
function kiraBuildKeywordRegex(keywords) {
	const source = keywords.map(kiraEscapeRegExp).join('|');
	return new RegExp(source, 'gi');
}

/**
 * 将纯文本转为带高亮标记的安全 HTML。
 * 逐段转义，仅关键词部分包裹 <mark>，杜绝注入。
 * @param {string} text - 纯文本
 * @param {RegExp} regex - kiraBuildKeywordRegex 构建的正则
 * @returns {string} 安全的 HTML 片段
 */
function kiraHighlightText(text, regex) {
	if (!text) return '';
	regex.lastIndex = 0;
	let result = '';
	let last = 0;
	let match;
	while ((match = regex.exec(text)) !== null) {
		if (match[0].length === 0) {
			// 空匹配保护（理论上关键词已过滤空串）
			regex.lastIndex++;
			continue;
		}
		result += kiraEscapeHtml(text.slice(last, match.index));
		result += '<mark class="kira-search-key">' + kiraEscapeHtml(match[0]) + '</mark>';
		last = match.index + match[0].length;
	}
	result += kiraEscapeHtml(text.slice(last));
	return result;
}

/**
 * 去除 HTML 标签得到纯文本。
 * 使用 <template> 承载内容：解析但惰性，不会触发图片等资源请求。
 * @param {string} html - 文章 HTML 内容
 * @returns {string} 纯文本
 */
function kiraStripHtml(html) {
	if (!html) return '';
	const template = document.createElement('template');
	template.innerHTML = html;
	return (template.content.textContent || '').replace(/\s+/g, ' ').trim();
}

/**
 * 解析 search.xml 为索引数组
 * @param {string} xmlText - XML 文本
 * @returns {Array<{title: string, url: string, content: string, titleLower: string, contentLower: string}>} 索引数组
 */
function kiraParseSearchXml(xmlText) {
	const doc = new DOMParser().parseFromString(xmlText, 'text/xml');
	if (doc.querySelector('parsererror')) {
		// DOMParser 解析失败不抛异常而是产出 parsererror 文档，
		// 不识别会被当成"无结果"误报，这里转为错误走失败提示与重试路径
		throw new Error('search index parse error');
	}
	const entries = doc.querySelectorAll('entry');
	const index = [];
	entries.forEach((entry) => {
		const titleNode = entry.querySelector('title');
		const urlNode = entry.querySelector('url');
		const contentNode = entry.querySelector('content');
		const title = titleNode ? titleNode.textContent.trim() : '';
		const content = contentNode ? kiraStripHtml(contentNode.textContent) : '';
		index.push({
			title: title,
			url: urlNode ? urlNode.textContent.trim() : '',
			content: content,
			// 预计算小写形式，避免每次按键对全量文章重复 toLowerCase
			titleLower: title.toLowerCase(),
			contentLower: content.toLowerCase()
		});
	});
	return index;
}

/**
 * 懒加载搜索索引（带缓存与失败重试）
 * @returns {Promise<Array>} 索引数组
 */
function kiraLoadSearchIndex() {
	if (kiraSearchIndex) {
		return Promise.resolve(kiraSearchIndex);
	}
	if (!kiraSearchIndexPromise) {
		kiraSearchIndexPromise = fetch(kiraSearchInput.dataset.src)
			.then((response) => {
				if (!response.ok) {
					throw new Error('HTTP ' + response.status);
				}
				return response.text();
			})
			.then((xmlText) => {
				kiraSearchIndex = kiraParseSearchXml(xmlText);
				return kiraSearchIndex;
			})
			.catch((err) => {
				// 失败后重置，允许下次输入时重试
				kiraSearchIndexPromise = null;
				throw err;
			});
	}
	return kiraSearchIndexPromise;
}

/**
 * 截取首个命中位置附近的摘要文本
 * @param {string} content - 纯文本内容
 * @param {RegExp} regex - 高亮正则
 * @returns {string} 摘要纯文本
 */
function kiraBuildSnippet(content, regex) {
	if (!content) return '';
	regex.lastIndex = 0;
	const match = regex.exec(content);
	let start = 0;
	if (match) {
		start = Math.max(0, match.index - SEARCH_SNIPPET_CONTEXT);
	}
	const end = Math.min(content.length, start + SEARCH_SNIPPET_LENGTH);
	const prefix = start > 0 ? '…' : '';
	const suffix = end < content.length ? '…' : '';
	return prefix + content.slice(start, end) + suffix;
}

/**
 * 执行搜索：多关键词 AND 匹配，标题命中权重高于正文命中
 * @param {string} query - 用户输入
 * @returns {Array<{entry: object, snippet: string, keywords: string[]}>} 排序后的结果
 */
function kiraExecuteSearch(query) {
	const keywords = query
		.toLowerCase()
		.split(/\s+/)
		.filter(Boolean);
	if (!keywords.length || !kiraSearchIndex) return [];

	const results = [];
	kiraSearchIndex.forEach((entry) => {
		const title = entry.titleLower;
		const content = entry.contentLower;
		let score = 0;
		for (const keyword of keywords) {
			const titleIndex = title.indexOf(keyword);
			const contentIndex = content.indexOf(keyword);
			if (titleIndex === -1 && contentIndex === -1) {
				// AND 语义：任一关键词未命中即排除
				return;
			}
			if (titleIndex !== -1) {
				score += SEARCH_TITLE_WEIGHT - titleIndex;
			} else {
				// 长文深处命中的分数钳到 0，避免出现负分（仅影响展示，不影响排序）
				score += Math.max(0, SEARCH_CONTENT_WEIGHT - Math.floor(contentIndex / 100));
			}
		}
		results.push({ entry: entry, score: score });
	});

	results.sort((a, b) => b.score - a.score);

	const regex = kiraBuildKeywordRegex(keywords);
	return results.map((item) => ({
		entry: item.entry,
		snippet: kiraBuildSnippet(item.entry.content, regex),
		keywords: keywords
	}));
}

// ============================================
// 渲染
// ============================================

/**
 * 面板悬浮于可滚动的侧边栏内：展开时滚动侧边栏，让面板底部尽量进入视野
 */
function kiraRevealPanel() {
	const sidebar = kiraSearchWidget ? kiraSearchWidget.closest('.kira-sidebar') : null;
	if (!sidebar) return;
	const overflow =
		kiraSearchResults.getBoundingClientRect().bottom -
		sidebar.getBoundingClientRect().bottom;
	if (overflow > 0) {
		sidebar.scrollTop += overflow + 8;
	}
}

/**
 * 在结果面板中显示一条状态文案（加载中/无结果/出错）
 * @param {string} message - 文案
 */
function kiraShowStatus(message) {
	kiraSearchResults.innerHTML =
		'<div class="kira-search-status">' + kiraEscapeHtml(message) + '</div>';
	kiraSearchResults.hidden = false;
	kiraSearchInput.setAttribute('aria-expanded', 'true');
	if (kiraSearchLive) {
		kiraSearchLive.textContent = message;
	}
	kiraRevealPanel();
}

/**
 * 渲染搜索结果列表（全部结果都渲染，面板内部滚动）
 * @param {Array} results - kiraExecuteSearch 的返回值
 */
function kiraRenderResults(results) {
	const regex = kiraBuildKeywordRegex(results[0].keywords);
	const items = results.map((item) => {
		const titleHtml = kiraHighlightText(item.entry.title || item.entry.url, regex);
		const snippetHtml = kiraHighlightText(item.snippet, regex);
		return (
			'<a class="kira-search-item" href="' + kiraEscapeHtml(item.entry.url) + '">' +
			'<div class="kira-search-item-title">' + titleHtml + '</div>' +
			(snippetHtml
				? '<div class="kira-search-item-snippet">' + snippetHtml + '</div>'
				: '') +
			'</a>'
		);
	});

	// 统计行放在列表末尾，超过一屏（需要滚动）时才显示
	let html = items.join('');
	if (results.length > SEARCH_COUNT_THRESHOLD) {
		html +=
			'<div class="kira-search-count">' +
			kiraEscapeHtml(kiraSearchMessages.count.replace('{n}', results.length)) +
			'</div>';
	}
	kiraSearchResults.innerHTML = html;
	kiraSearchResults.hidden = false;
	kiraSearchInput.setAttribute('aria-expanded', 'true');
	if (kiraSearchLive) {
		kiraSearchLive.textContent = kiraSearchMessages.count.replace('{n}', results.length);
	}
	kiraRevealPanel();
}

/**
 * 隐藏结果面板
 */
function kiraHideResults() {
	// 取消尚未触发的防抖搜索，防止收起后又被定时器重新弹开
	clearTimeout(kiraSearchDebounceTimer);
	kiraSearchResults.hidden = true;
	kiraSearchResults.innerHTML = '';
	kiraSearchInput.setAttribute('aria-expanded', 'false');
	if (kiraSearchLive) {
		kiraSearchLive.textContent = '';
	}
}

/**
 * 搜索是否仍处于活跃状态（输入框或结果项持有焦点）。
 * 用户点击外部收起面板后，仍在途的索引加载不应再把面板弹开
 * @returns {boolean}
 */
function kiraSearchStillActive() {
	return (
		document.activeElement === kiraSearchInput ||
		kiraSearchResults.contains(document.activeElement)
	);
}

/**
 * 处理输入事件（防抖后执行搜索）
 */
function kiraHandleInput() {
	const query = kiraSearchInput.value.trim();
	kiraSearchClearBtn.hidden = query === '';
	if (query === '') {
		kiraHideResults();
		return;
	}

	kiraShowStatus(kiraSearchMessages.loading);
	kiraLoadSearchIndex()
		.then(() => {
			// 加载期间输入可能已被清空，或面板已被点击外部收起
			if (kiraSearchInput.value.trim() === '' || !kiraSearchStillActive()) {
				return;
			}
			const results = kiraExecuteSearch(kiraSearchInput.value.trim());
			if (results.length === 0) {
				kiraShowStatus(kiraSearchMessages.noResult);
			} else {
				kiraRenderResults(results);
			}
		})
		.catch(() => {
			if (kiraSearchInput.value.trim() !== '' && kiraSearchStillActive()) {
				kiraShowStatus(kiraSearchMessages.error);
			}
		});
}

// ============================================
// 事件绑定
// ============================================

/**
 * 绑定键盘交互：
 * - Enter：跳转第一条结果
 * - Escape：清空并收起
 * - 方向键：在输入框与结果之间移动焦点
 * @param {KeyboardEvent} e - 键盘事件
 */
function kiraHandleKeydown(e) {
	// IME 组合输入期间（拼音候选、日文变换等）不拦截按键：
	// 此时 Enter 是确认候选词而非跳转，方向键/Escape 属于候选窗操作
	if (e.isComposing || e.keyCode === 229) {
		return;
	}

	if (e.key === 'Escape') {
		kiraSearchInput.value = '';
		kiraSearchClearBtn.hidden = true;
		kiraHideResults();
		kiraSearchInput.blur();
		return;
	}

	if (kiraSearchResults.hidden) return;
	const items = Array.prototype.slice.call(
		kiraSearchResults.querySelectorAll('.kira-search-item')
	);
	if (!items.length) return;

	const currentIndex = items.indexOf(document.activeElement);

	if (e.key === 'ArrowDown') {
		e.preventDefault();
		items[Math.min(currentIndex + 1, items.length - 1)].focus();
	} else if (e.key === 'ArrowUp') {
		e.preventDefault();
		if (currentIndex <= 0) {
			kiraSearchInput.focus();
		} else {
			items[currentIndex - 1].focus();
		}
	} else if (e.key === 'Enter' && document.activeElement === kiraSearchInput) {
		// 输入框内回车：跳转第一条结果
		e.preventDefault();
		items[0].click();
	}
}

/**
 * 初始化搜索组件（组件不存在时静默退出）
 */
function initKiraSearch() {
	kiraSearchInput = document.getElementById('kira-search-input');
	kiraSearchClearBtn = document.getElementById('kira-search-clear');
	kiraSearchResults = document.getElementById('kira-search-results');
	if (!kiraSearchInput || !kiraSearchResults || !kiraSearchClearBtn) return;
	kiraSearchWidget = kiraSearchInput.closest('.kira-search');
	kiraSearchLive = document.getElementById('kira-search-live');

	kiraSearchMessages.loading = kiraSearchResults.dataset.msgLoading || 'Loading…';
	kiraSearchMessages.noResult = kiraSearchResults.dataset.msgNoResult || 'No results';
	kiraSearchMessages.error = kiraSearchResults.dataset.msgError || 'Failed to load';
	kiraSearchMessages.count = kiraSearchResults.dataset.msgCount || '';

	// 首次聚焦即预取索引，让第一次敲键就有结果
	kiraSearchInput.addEventListener('focus', () => {
		kiraLoadSearchIndex().catch(() => {});
	});

	// IME 组合期间跳过中间态（拼音字母），提交候选词后再搜索。
	// 统一走防抖：Chrome 的 compositionend 后还会跟一次原生 input 事件，
	// 直接执行会双重搜索（第二次 innerHTML 重建还会打断方向键焦点）；
	// 走防抖后两处定时器互相合并，Chrome/Firefox 两种事件顺序都只执行一次
	kiraSearchInput.addEventListener('compositionstart', () => {
		kiraSearchComposing = true;
	});
	kiraSearchInput.addEventListener('compositionend', () => {
		kiraSearchComposing = false;
		clearTimeout(kiraSearchDebounceTimer);
		kiraSearchDebounceTimer = setTimeout(kiraHandleInput, SEARCH_INPUT_DEBOUNCE);
	});

	kiraSearchInput.addEventListener('input', () => {
		if (kiraSearchComposing) return;
		clearTimeout(kiraSearchDebounceTimer);
		kiraSearchDebounceTimer = setTimeout(kiraHandleInput, SEARCH_INPUT_DEBOUNCE);
	});

	kiraSearchInput.addEventListener('keydown', kiraHandleKeydown);
	kiraSearchResults.addEventListener('keydown', kiraHandleKeydown);

	// 点击搜索框空白区域（图标/内边距）时聚焦输入框
	const box = kiraSearchInput.closest('.kira-search-box');
	if (box) {
		box.addEventListener('click', (e) => {
			if (!e.target.closest('.kira-search-clear')) {
				kiraSearchInput.focus();
			}
		});
	}

	// 点击组件外部时收起悬浮结果面板
	document.addEventListener('pointerdown', (e) => {
		if (kiraSearchWidget && !kiraSearchWidget.contains(e.target)) {
			kiraHideResults();
		}
	});

	kiraSearchClearBtn.addEventListener('click', () => {
		kiraSearchInput.value = '';
		kiraSearchClearBtn.hidden = true;
		kiraHideResults();
		kiraSearchInput.focus();
	});
}

document.addEventListener('DOMContentLoaded', initKiraSearch);
