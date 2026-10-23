'use strict';
document.querySelectorAll('table tbody').forEach(body => {
  if (!body.children.length) {
    const cell = body.insertRow().insertCell();
    cell.colSpan = body.closest('table').querySelectorAll('thead th').length || 4;
    cell.className = 'empty-state';
    cell.textContent = '暂无记录，完成相关业务操作后将在这里显示。';
  }
});
document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', () => {
    if (form.checkValidity()) form.querySelectorAll('button[type="submit"], button:not([type])').forEach(button => {
      button.setAttribute('aria-busy', 'true');
      button.textContent = '正在处理…';
    });
  });
});
window.addEventListener('pageshow', event => { if(event.persisted) location.reload(); });
const navigation = document.querySelector('nav');
const currentLink = navigation?.querySelector('.active');
if (navigation && currentLink && navigation.scrollWidth > navigation.clientWidth) {
  navigation.scrollLeft = Math.max(0, currentLink.offsetLeft - navigation.clientWidth / 2 + currentLink.clientWidth / 2);
}
