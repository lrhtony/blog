// 这里放自己增加的代码

let lastScrollTop = 0;
window.addEventListener("scroll", () => {
    const st = window.pageYOffset || document.documentElement.scrollTop;
    const kira_header = document.getElementsByClassName("kira-header")[0];

    if (st > lastScrollTop) {
        // 下滑
        kira_header.style.height = "0"; // 隐藏标题栏
    } else {
        // 上滑
        kira_header.style.height = "60px"; // 显示标题栏
    }
    if (st === 0) {
        // 滚动到顶部
        kira_header.style.height = "60px"; // 显示标题栏
        kira_header.style.backgroundColor = "transparent"; // 透明标题栏
    }
    else {
        // 滚动到非顶部
        kira_header.style.backgroundColor = "rgba(255, 255, 255, 0.8)"; // 不透明标题栏
    }
    lastScrollTop = st;

    // TOC 高亮当前章节
    updateTocHighlight();
});

// TOC 功能初始化
document.addEventListener("DOMContentLoaded", () => {
    initToc();
});

// 修复 TOC 链接（Hexo toc() 生成的链接可能没有 href）
function fixTocLinks() {
    const tocContainer = document.querySelector(".kira-toc");
    if (!tocContainer) return;

    const tocLinks = tocContainer.querySelectorAll(".toc-link");
    const headings = document.querySelectorAll("article h1, article h2, article h3, article h4, article h5, article h6");
    
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

// 根据 TOC 链接查找目标元素
function findTargetElement(link) {
    // 优先使用缓存的引用
    if (link._targetHeading) {
        return link._targetHeading;
    }
    
    const href = link.getAttribute("href");
    if (!href || !href.startsWith("#")) return null;
    
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

function initToc() {
    const tocContainer = document.querySelector(".kira-toc");
    if (!tocContainer) return;

    // 首先修复 TOC 链接
    fixTocLinks();

    const tocLinks = tocContainer.querySelectorAll(".toc-link");
    if (!tocLinks.length) return;

    // 为 TOC 链接添加点击事件，实现平滑滚动
    tocLinks.forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            const targetElement = findTargetElement(link);
            
            if (targetElement) {
                // 计算偏移量（考虑固定头部）
                const headerOffset = 80;
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: "smooth"
                });

                // 更新 URL hash
                const href = link.getAttribute("href");
                if (href) {
                    history.pushState(null, null, href);
                }
            } else {
                console.warn("TOC: 未找到目标元素", link.textContent);
            }
        });
    });

    // 初始化时更新一次高亮
    updateTocHighlight();
}

function updateTocHighlight() {
    const tocContainer = document.querySelector(".kira-toc");
    if (!tocContainer) return;

    const tocLinks = tocContainer.querySelectorAll(".toc-link");
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
    const headerOffset = 100;
    let activeHeading = headings[0];

    for (let i = 0; i < headings.length; i++) {
        const heading = headings[i];
        const headingTop = heading.element.getBoundingClientRect().top + scrollTop - headerOffset;
        
        if (scrollTop >= headingTop) {
            activeHeading = heading;
        } else {
            break;
        }
    }

    // 更新高亮状态
    tocLinks.forEach(link => link.classList.remove("active"));
    if (activeHeading) {
        activeHeading.link.classList.add("active");

        // 将激活的链接滚动到可视区域
        const tocRect = tocContainer.getBoundingClientRect();
        const linkRect = activeHeading.link.getBoundingClientRect();
        
        if (linkRect.top < tocRect.top || linkRect.bottom > tocRect.bottom) {
            activeHeading.link.scrollIntoView({ block: "center", behavior: "smooth" });
        }
    }
}