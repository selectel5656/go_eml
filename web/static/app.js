document.addEventListener('DOMContentLoaded', () => {
  const path = window.location.pathname;
  document.querySelectorAll('nav a').forEach(a => {
    if (a.getAttribute('href') === path) a.classList.add('active');
  });
  document.querySelectorAll('a.delete-link').forEach(a => {
    a.addEventListener('click', e => {
      if (!confirm('Удалить?')) e.preventDefault();
    });
  });
});
