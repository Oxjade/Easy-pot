// EasyPot landing page: one load sequence for the intercept log, a nav border on scroll,
// and the copy button. The page reads fine without any of it.
document.documentElement.classList.add('js');

const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const lines = [...document.querySelectorAll('.log li')];
if (reduce) {
  lines.forEach(li => li.classList.add('in'));
} else {
  // Requests arrive one by one; the agent's self-report and the block land together at the end.
  const delays = [500, 850, 1200, 1750, 2150, 2350, 2950];
  lines.forEach((li, i) => setTimeout(() => li.classList.add('in'), delays[i] ?? 500 + i * 350));
}

const nav = document.querySelector('.nav');
const onScroll = () => nav.classList.toggle('scrolled', window.scrollY > 8);
window.addEventListener('scroll', onScroll, { passive: true });
onScroll();

document.querySelectorAll('[data-copy]').forEach(btn => {
  btn.addEventListener('click', async () => {
    const label = btn.lastChild;
    try {
      await navigator.clipboard.writeText(btn.dataset.copy);
      label.textContent = 'Copied';
    } catch {
      label.textContent = 'Select to copy';
    }
    setTimeout(() => { label.textContent = 'Copy'; }, 1800);
  });
});
