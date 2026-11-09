// Security Assessment Report Interactive Printing & PDF Export
document.addEventListener('DOMContentLoaded', () => {
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
      window.close();
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

  // Automatically launch the browser's native Save as PDF / Print dialog
  setTimeout(() => {
    window.print();
  }, 400);
});

