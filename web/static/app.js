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
  const typeSel = document.getElementById('att-type');
  if (typeSel) {
    const imgOpts = document.getElementById('image-opts');
    const docxOpts = document.getElementById('docx-opts');
    const toggle = () => {
      const v = typeSel.value;
      imgOpts.style.display = v === 'image' ? 'block' : 'none';
      docxOpts.style.display = v === 'docx' ? 'block' : 'none';
    };
    typeSel.addEventListener('change', toggle);
    toggle();
  }
});
