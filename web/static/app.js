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

  const macroType = document.getElementById('macro-type');
  if (macroType) {
    const counter = document.getElementById('counter-fields');
    const random = document.getElementById('random-fields');
    const list = document.getElementById('list-fields');
    const multi = document.getElementById('multi-fields');
    const toggle = () => {
      const v = macroType.value;
      counter.style.display = v === 'counter' ? 'block' : 'none';
      random.style.display = v === 'random' ? 'block' : 'none';
      list.style.display = v === 'list' ? 'block' : 'none';
      multi.style.display = v === 'multi' ? 'block' : 'none';
    };
    macroType.addEventListener('change', toggle);
    toggle();
  }

  const prog = document.getElementById('send-progress');
  if (prog) {
    setInterval(() => {
      fetch('/progress').then(r => r.json()).then(d => {
        prog.max = d.total;
        prog.value = d.sent;
        document.getElementById('progress-text').textContent = `${d.sent}/${d.total} (${d.processing} в очереди)`;
        const ec = document.getElementById('error-count');
        ec.textContent = d.errors;
        document.getElementById('error-download').style.display = d.errors > 0 ? 'inline' : 'none';
      });
    }, 1000);
  }
});
