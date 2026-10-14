// Adds a toolbar with the language name and a copy button to each code block in a blog post.
(function () {
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand('copy') ? resolve() : reject();
      } catch (e) {
        reject(e);
      } finally {
        document.body.removeChild(area);
      }
    });
  }

  // Code blocks without a language come out as a bare <pre>; give them the same wrapper as highlighted ones
  document.querySelectorAll('.blog-content pre').forEach(function (pre) {
    if (pre.closest('.highlighter-rouge')) return;
    var outer = document.createElement('div');
    outer.className = 'highlighter-rouge';
    var inner = document.createElement('div');
    inner.className = 'highlight';
    pre.classList.add('highlight');
    pre.parentNode.insertBefore(outer, pre);
    inner.appendChild(pre);
    outer.appendChild(inner);
  });

  document.querySelectorAll('.blog-content div.highlighter-rouge').forEach(function (block) {
    var code = block.querySelector('pre code') || block.querySelector('pre');
    if (!code) return;

    var match = block.className.match(/language-(\S+)/);
    var lang = match && match[1] !== 'plaintext' ? match[1] : 'text';

    var toolbar = document.createElement('div');
    toolbar.className = 'code-toolbar';

    var label = document.createElement('span');
    label.textContent = lang;

    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'code-copy';
    button.textContent = 'Copy';
    button.setAttribute('aria-label', 'Copy code to clipboard');

    var timer;
    button.addEventListener('click', function () {
      copyText(code.innerText.replace(/\n$/, '')).then(function () {
        button.textContent = 'Copied';
        button.classList.add('copied');
      }, function () {
        button.textContent = 'Failed';
      });
      clearTimeout(timer);
      timer = setTimeout(function () {
        button.textContent = 'Copy';
        button.classList.remove('copied');
      }, 2000);
    });

    toolbar.appendChild(label);
    toolbar.appendChild(button);
    block.insertBefore(toolbar, block.firstChild);
  });
})();
