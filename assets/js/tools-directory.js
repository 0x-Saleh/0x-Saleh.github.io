(() => {
  const filters = document.getElementById('tool-filters');
  const search = document.getElementById('tool-search');
  const status = document.getElementById('tool-results');
  const cards = Array.from(document.querySelectorAll('#tool-directory .tool-card'), (card) => ({
    card,
    text: Array.from(card.querySelectorAll('h2, p'), (node) => node.textContent).join(' ').toLowerCase()
  }));

  function update() {
    const query = search.value.trim().toLowerCase();
    const source = filters.querySelector('input[name="source"]:checked').value;
    let count = 0;
    for (const { card, text } of cards) {
      const matches = (source === 'all' || source === card.dataset.source) && text.includes(query);
      card.hidden = !matches;
      if (matches) count++;
    }
    const message = count ? `${count} ${count === 1 ? 'tool' : 'tools'} found.` : 'No tools found.';
    status.toggleAttribute('data-empty', count === 0);
    if (status.textContent !== message) status.textContent = message;
  }

  search.addEventListener('input', update);
  filters.addEventListener('change', update);
  window.addEventListener('pageshow', update);
  update();
  filters.hidden = false;
})();
