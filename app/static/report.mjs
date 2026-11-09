// Security Assessment Report Interactive Printing & PDF Export
function initReport() {
  // Wire up print buttons
  const printBtns = document.querySelectorAll('.js-print-btn');
  printBtns.forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      window.print();
    });
  });

  // Wire up close banner button
  const closeBtns = document.querySelectorAll('.js-close-btn');
  closeBtns.forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const banner = document.querySelector('.print-banner');
      if (banner) banner.style.display = 'none';
    });
  });

  // Wire up back button: close tab if opened in separate window/tab
  const backBtns = document.querySelectorAll('.js-back-btn');
  backBtns.forEach((btn) => {
    btn.addEventListener('click', (e) => {
      if (window.opener && window.opener !== window) {
        e.preventDefault();
        window.close();
      }
    });
  });

  // Automatically launch print dialog once styles and DOM are fully ready
  window.addEventListener('load', () => {
    setTimeout(() => {
      try {
        window.print();
      } catch {}
    }, 500);
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initReport);
} else {
  initReport();
}

