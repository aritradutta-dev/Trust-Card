document.querySelectorAll('.report-row button').forEach((button) => {
  button.addEventListener('click', async () => {
    const row = button.closest('.report-row');
    button.disabled = true;
    const response = await fetch(`/api/v1/admin/reports/${row.dataset.reportId}/review`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision: button.dataset.decision }),
    });
    if (response.ok) row.remove();
    else button.disabled = false;
  });
});
