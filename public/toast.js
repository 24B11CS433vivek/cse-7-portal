fetch('notice.txt')
  .then(res => res.text())
  .then(text => {
    const message = text.trim();
    if (!message) return;

    // Avoid repeat spam (same notice)
    const lastNotice = localStorage.getItem('lastNotice');
    if (lastNotice === message) return;

    localStorage.setItem('lastNotice', message);

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
      <span class="toast-close">&times;</span>
      🔔 <strong>New Announcement</strong><br>${message}
    `;

    document.body.appendChild(toast);

    // Show animation
    setTimeout(() => toast.classList.add('show'), 300);

    // Auto hide
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 400);
    }, 7000);

    // Close button
    toast.querySelector('.toast-close').onclick = () => {
      toast.remove();
    };
  })
  .catch(() => {});
