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
});