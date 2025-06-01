export function templateSwitcher(templateSelector, itemSelector, activeClass = 'active') {
  const templateLinks = document.querySelectorAll(`${templateSelector} a`);
  const contentItems = document.querySelectorAll(itemSelector);

  function switchTo(targetId) {
    // Hide all content items
    contentItems.forEach(item => item.classList.remove(activeClass));

    // Deactivate all buttons
    templateLinks.forEach(link => link.classList.remove('active-tab'));

    // Show the target item
    const targetItem = document.getElementById(targetId);
    if (targetItem) {
      targetItem.classList.add(activeClass);
    }

    // Activate the corresponding tab button
    const activeTemplate = [...templateLinks].find(lnk => lnk.getAttribute('data-target') === targetId);
    if (activeTemplate) {
      activeTemplate.classList.add('active-tab');
    }
  }

  templateLinks.forEach(link => {
    link.addEventListener('click', () => {
      const targetId = link.getAttribute('data-target');
      switchTo(targetId);
    });
  });

  // Activate the first by default
  if (contentItems.length > 0 && templateLinks.length > 0) {
    const firstId = templateLinks[0].getAttribute('data-target');
    switchTo(firstId);
  }
}
