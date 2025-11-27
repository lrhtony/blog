/**
 * Kira Hexo Theme - 代码复制功能
 * @description 为代码块添加一键复制按钮
 */

/** 复制成功提示显示时长（毫秒） */
const COPIED_FEEDBACK_DURATION = 1500;

window.addEventListener('load', () => {
	const codeBlocks = document.querySelectorAll('figure.highlight');
	if (!codeBlocks.length) return;

	// 动态加载样式
	const style = document.createElement('link');
	style.rel = 'stylesheet';
	style.href = '/css/kira-code-copy.css';
	document.head.appendChild(style);

	/**
	 * 为代码块添加复制按钮
	 * @param {HTMLElement} codeBlock - 代码块元素
	 */
	const addCopyButton = function (codeBlock) {
		const copyWrapper = document.createElement('div');
		copyWrapper.setAttribute('class', 'kira-codeblock-copy-wrapper');

		let copiedTimeout = null;

		copyWrapper.addEventListener('click', (ev) => {
			const highlightDom = ev.target.parentElement;
			const code = highlightDom.querySelector('code');

			let copiedCode = '';

			/**
			 * 递归遍历子节点提取文本内容
			 * @param {Node} node - DOM 节点
			 */
			(function traverseChildNodes(node) {
				const childNodes = node.childNodes;
				childNodes.forEach((child) => {
					switch (child.nodeName) {
						case '#text':
							copiedCode += child.nodeValue;
							break;
						case 'BR':
							copiedCode += '\n';
							break;
						default:
							traverseChildNodes(child);
					}
				});
			})(code);

			// 去掉最后的换行符并复制到剪贴板
			navigator.clipboard
				.writeText(copiedCode.slice(0, -1))
				.then(() => {
					// 清除之前的定时器
					if (copiedTimeout) {
						clearTimeout(copiedTimeout);
					}

					// 显示复制成功状态
					copyWrapper.classList.add('kira-codeblock-copy-wrapper-copied');
					copiedTimeout = setTimeout(() => {
						copyWrapper.classList.remove('kira-codeblock-copy-wrapper-copied');
						copiedTimeout = null;
					}, COPIED_FEEDBACK_DURATION);
				})
				.catch((err) => {
					console.error('代码复制失败:', err);
				});
		});

		codeBlock.appendChild(copyWrapper);
	};

	codeBlocks.forEach(addCopyButton);
});
