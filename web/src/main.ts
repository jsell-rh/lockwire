(function () {
  "use strict";

  const codeInput = document.getElementById("code") as HTMLInputElement;
  const watchBtn = document.getElementById("watch") as HTMLButtonElement;
  const statusEl = document.getElementById("status") as HTMLElement;

  const fragment = window.location.hash.substring(1);
  if (fragment) {
    codeInput.value = decodeURIComponent(fragment);
  }

  watchBtn.addEventListener("click", () => {
    const code = codeInput.value.trim();
    if (!code) {
      statusEl.textContent = "enter a code to connect";
      statusEl.className = "error";
      return;
    }
    watchBtn.disabled = true;
    codeInput.disabled = true;
    statusEl.textContent = "connecting…";
    statusEl.className = "";
  });
})();
