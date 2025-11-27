/**
 * Kira Hexo Theme - Main JavaScript
 * @description 主题核心脚本，包含头部滚动、侧边栏控制和 TOC 目录功能
 */

// ============================================
// 常量定义
// ============================================

/** 头部栏高度（像素） */
const HEADER_HEIGHT = 60;

/** TOC 点击滚动的偏移量（像素） */
const TOC_SCROLL_OFFSET = 80;

/** 标题高亮检测的偏移量（像素） */
const ACTIVE_HEADING_OFFSET = 100;

/** 头部栏背景色 - 透明 */
const HEADER_BG_TRANSPARENT = 'transparent';

/** 头部栏背景色 - 不透明 */
const HEADER_BG_OPAQUE = 'rgba(255, 255, 255, 0.8)';

// ============================================
// 侧边栏控制
// ============================================

/**
 * 显示侧边栏
 */
function showSidebar() {
    const modal = document.querySelector('.kira-sidebar-modal');
    const sidebar = document.querySelector('.kira-sidebar#sidebar');
    if (modal) modal.classList.add('show');
    if (sidebar) sidebar.classList.add('show');
}

/**
 * 隐藏侧边栏
 */
function hideSidebar() {
    const modal = document.querySelector('.kira-sidebar-modal');
    const sidebar = document.querySelector('.kira-sidebar#sidebar');
    if (modal) modal.classList.remove('show');
    if (sidebar) sidebar.classList.remove('show');
}

// ============================================
// 头部滚动控制
// ============================================

let lastScrollTop = 0;

/**
 * 处理页面滚动事件
 * - 根据滚动方向显示/隐藏头部栏
 * - 根据滚动位置切换头部栏背景色
 */
function handleScroll() {
    const st = window.pageYOffset || document.documentElement.scrollTop;
    const kiraHeader = document.querySelector('.kira-header');
    
    if (!kiraHeader) return;

    if (st > lastScrollTop) {
        // 下滑 - 隐藏标题栏
        kiraHeader.style.height = '0';
    } else {
        // 上滑 - 显示标题栏
        kiraHeader.style.height = HEADER_HEIGHT + 'px';
    }
    
    if (st === 0) {
        // 滚动到顶部 - 透明背景
        kiraHeader.style.height = HEADER_HEIGHT + 'px';
        kiraHeader.style.backgroundColor = HEADER_BG_TRANSPARENT;
    } else {
        // 滚动到非顶部 - 不透明背景
        kiraHeader.style.backgroundColor = HEADER_BG_OPAQUE;
    }
    
    lastScrollTop = st;

    // 更新 TOC 高亮
    updateTocHighlight();
}

window.addEventListener('scroll', handleScroll);

// ============================================
// DOM 初始化
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    // 初始化侧边栏控制
    initSidebarControls();
    // 初始化 TOC 功能
    initToc();
});

/**
 * 初始化侧边栏控制事件
 */
function initSidebarControls() {
    // 侧边栏打开按钮
    const sidebarToggle = document.getElementById('sidebar-toggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', showSidebar);
    }
    
    // 侧边栏遮罩层点击关闭
    const sidebarModal = document.getElementById('sidebar-modal');
    if (sidebarModal) {
        sidebarModal.addEventListener('click', hideSidebar);
    }
}

// ============================================
// TOC 目录功能
// ============================================

/**
 * 修复 TOC 链接
 * Hexo toc() 生成的链接可能没有正确的 href，此函数补全链接
 */
function fixTocLinks() {
    const tocContainer = document.querySelector('.kira-toc');
    if (!tocContainer) return;

    const tocLinks = tocContainer.querySelectorAll('.toc-link');
    const headings = document.querySelectorAll('article h1, article h2, article h3, article h4, article h5, article h6');
    
    // 建立标题文本到元素的映射
    const headingMap = new Map();
    headings.forEach(heading => {
        // 获取标题文本（去除锚点符号）
        let text = heading.textContent.replace(/^#\s*/, '').trim();
        // 也尝试从 span 中获取
        const span = heading.querySelector('span[id]');
        if (span) {
            text = span.textContent.trim();
        }
        if (text) {
            headingMap.set(text, heading);
        }
    });

    // 为每个 TOC 链接补全 href
    tocLinks.forEach(link => {
        const textSpan = link.querySelector('.toc-text');
        const text = textSpan ? textSpan.textContent.trim() : link.textContent.trim();
        const heading = headingMap.get(text);
        
        if (heading) {
            // 查找标题中的锚点
            const span = heading.querySelector('span[id]');
            const anchor = heading.querySelector('a.header-anchor');
            
            if (span && span.id) {
                link.setAttribute('href', '#' + span.id);
            } else if (anchor && anchor.getAttribute('href')) {
                link.setAttribute('href', anchor.getAttribute('href'));
            } else if (heading.id) {
                link.setAttribute('href', '#' + heading.id);
            }
            
            // 存储对应的标题元素引用
            link._targetHeading = heading;
        }
    });
}

/**
 * 根据 TOC 链接查找目标标题元素
 * @param {HTMLElement} link - TOC 链接元素
 * @returns {HTMLElement|null} 目标标题元素，未找到返回 null
 */
function findTargetElement(link) {
    // 优先使用缓存的引用
    if (link._targetHeading) {
        return link._targetHeading;
    }
    
    const href = link.getAttribute('href');
    if (!href || !href.startsWith('#')) return null;
    
    const targetId = href.substring(1);
    const decodedId = decodeURIComponent(targetId);
    
    // 方法 1: 直接通过 ID 查找
    let element = document.getElementById(targetId);
    if (element) return element.closest('h1, h2, h3, h4, h5, h6') || element;
    
    // 方法 2: 尝试解码后的 ID
    element = document.getElementById(decodedId);
    if (element) return element.closest('h1, h2, h3, h4, h5, h6') || element;
    
    // 方法 3: 查找带有 header-anchor 类的链接
    const anchor = document.querySelector(`a.header-anchor[href="${CSS.escape(href)}"]`);
    if (anchor && anchor.parentElement) {
        return anchor.parentElement;
    }
    
    return null;
}

/**
 * 初始化 TOC 目录功能
 * - 修复 TOC 链接
 * - 添加平滑滚动
 * - 更新高亮状态
 */
function initToc() {
    const tocContainer = document.querySelector('.kira-toc');
    if (!tocContainer) return;

    // 首先修复 TOC 链接
    fixTocLinks();

    const tocLinks = tocContainer.querySelectorAll('.toc-link');
    if (!tocLinks.length) return;

    // 为 TOC 链接添加点击事件，实现平滑滚动
    tocLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            const targetElement = findTargetElement(link);
            
            if (targetElement) {
                // 计算偏移量（考虑固定头部）
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - TOC_SCROLL_OFFSET;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });

                // 更新 URL hash
                const href = link.getAttribute('href');
                if (href) {
                    history.pushState(null, null, href);
                }
            } else {
                console.warn('TOC: 未找到目标元素', link.textContent);
            }
        });
    });

    // 初始化时更新一次高亮
    updateTocHighlight();
}

/**
 * 更新 TOC 目录的高亮状态
 * 根据当前滚动位置高亮对应的目录项
 */
function updateTocHighlight() {
    const tocContainer = document.querySelector('.kira-toc');
    if (!tocContainer) return;

    const tocLinks = tocContainer.querySelectorAll('.toc-link');
    if (!tocLinks.length) return;

    // 获取所有标题元素
    const headings = [];
    tocLinks.forEach(link => {
        const heading = findTargetElement(link);
        if (heading) {
            headings.push({ element: heading, link: link });
        }
    });

    if (!headings.length) return;

    // 找到当前可见的标题
    const scrollTop = window.pageYOffset;
    let activeHeading = headings[0];

    for (let i = 0; i < headings.length; i++) {
        const heading = headings[i];
        const headingTop = heading.element.getBoundingClientRect().top + scrollTop - ACTIVE_HEADING_OFFSET;
        
        if (scrollTop >= headingTop) {
            activeHeading = heading;
        } else {
            break;
        }
    }

    // 更新高亮状态
    tocLinks.forEach(link => link.classList.remove('active'));
    if (activeHeading) {
        activeHeading.link.classList.add('active');

        // 将激活的链接滚动到可视区域
        const tocRect = tocContainer.getBoundingClientRect();
        const linkRect = activeHeading.link.getBoundingClientRect();
        
        if (linkRect.top < tocRect.top || linkRect.bottom > tocRect.bottom) {
            activeHeading.link.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }
    }
}