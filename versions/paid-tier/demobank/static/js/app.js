document.addEventListener('DOMContentLoaded', () => {
  const menu = document.querySelector('.menu-toggle');
  const nav = document.querySelector('#nav-links');
  if (menu && nav) menu.addEventListener('click', () => {
    const expanded = menu.getAttribute('aria-expanded') === 'true';
    menu.setAttribute('aria-expanded', String(!expanded)); nav.classList.toggle('open', !expanded);
  });
  document.querySelectorAll('.dismiss').forEach(btn => btn.addEventListener('click', () => btn.closest('.flash').remove()));
  document.querySelectorAll('[data-copy]').forEach(btn => btn.addEventListener('click', async () => {
    const text = document.getElementById(btn.dataset.copy)?.textContent;
    if (!text) return;
    try { await navigator.clipboard.writeText(text); btn.textContent = 'Copied!'; }
    catch { btn.textContent = 'Copy unavailable'; }
  }));
  const transfer = document.querySelector('form[data-confirm-transfer]');
  if (transfer) transfer.addEventListener('submit', event => {
    const data = new FormData(transfer);
    if (!window.confirm(`Send ${data.get('amount')} virtual credits to ${data.get('recipient')}?`)) event.preventDefault();
    else { const btn = transfer.querySelector('button[type=submit],button:not([type])'); if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; } }
  });
});
