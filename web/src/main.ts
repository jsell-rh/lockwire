import { Terminal } from "@xterm/xterm";
import { LockwireClient, type ConnectionState } from "./client.js";

(function () {
  "use strict";

  const codeInput = document.getElementById("code") as HTMLInputElement;
  const watchBtn = document.getElementById("watch") as HTMLButtonElement;
  const statusEl = document.getElementById("status") as HTMLElement;
  const preJoin = document.getElementById("pre-join") as HTMLElement;
  const termContainer = document.getElementById(
    "terminal-container",
  ) as HTMLElement;
  const overlay = document.getElementById("overlay") as HTMLElement;
  const overlayMsg = document.getElementById("overlay-msg") as HTMLElement;
  const sizeBanner = document.getElementById("size-banner") as HTMLElement;

  const fragment = window.location.hash.substring(1);
  if (fragment) {
    codeInput.value = decodeURIComponent(fragment);
  }

  let term: Terminal | null = null;
  let client: LockwireClient | null = null;

  function showOverlay(msg: string): void {
    overlayMsg.textContent = msg;
    overlay.classList.add("visible");
  }

  function hideOverlay(): void {
    overlay.classList.remove("visible");
  }

  function showTerminal(): void {
    preJoin.style.display = "none";
    termContainer.classList.add("visible");
  }

  function updateSizeBanner(
    sharerCols: number,
    sharerRows: number,
  ): void {
    if (!term) return;
    if (sharerCols > term.cols || sharerRows > term.rows) {
      sizeBanner.textContent =
        `Terminal size mismatch: sharer ${sharerCols}x${sharerRows}, ` +
        `viewer ${term.cols}x${term.rows}`;
      sizeBanner.classList.add("visible");
    } else {
      sizeBanner.classList.remove("visible");
    }
  }

  function handleStateChange(state: ConnectionState, message?: string): void {
    switch (state) {
      case "connecting":
        statusEl.textContent = "connecting…";
        statusEl.className = "";
        break;
      case "active":
        hideOverlay();
        showTerminal();
        if (term) {
          term.focus();
        }
        break;
      case "ended":
        showOverlay(message ?? "session ended by sharer");
        break;
      case "lost":
        showOverlay(message ?? "session lost (connection dropped)");
        break;
      case "revoked":
        showOverlay(message ?? "access revoked");
        break;
      case "error":
        statusEl.textContent = message ?? "connection error";
        statusEl.className = "error";
        watchBtn.disabled = false;
        codeInput.disabled = false;
        break;
    }
  }

  function initTerminal(): Terminal {
    const t = new Terminal({
      cursorBlink: false,
      disableStdin: true,
      convertEol: false,
      scrollback: 1000,
      theme: {
        background: "#1a1a2e",
        foreground: "#e0e0e0",
        cursor: "#e94560",
      },
    });

    t.open(termContainer);

    const fitToWindow = (): void => {
      const charWidth = 9;
      const charHeight = 17;
      const cols = Math.floor(window.innerWidth / charWidth);
      const rows = Math.floor(window.innerHeight / charHeight);
      if (cols > 0 && rows > 0) {
        t.resize(cols, rows);
      }
    };

    fitToWindow();
    window.addEventListener("resize", fitToWindow);

    return t;
  }

  async function startSession(): Promise<void> {
    const code = codeInput.value.trim();
    if (!code) {
      statusEl.textContent = "enter a code to connect";
      statusEl.className = "error";
      return;
    }

    watchBtn.disabled = true;
    codeInput.disabled = true;

    term = initTerminal();

    client = new LockwireClient({
      onStateChange: handleStateChange,
      onTerminalData(data: Uint8Array): void {
        if (term) {
          term.write(data);
        }
      },
      onTerminalResize(cols: number, rows: number): void {
        if (term) {
          term.resize(cols, rows);
          updateSizeBanner(cols, rows);
        }
      },
    });

    try {
      await client.connect(code);
    } catch {
      // error state already set by client callbacks
    }
  }

  watchBtn.addEventListener("click", () => {
    startSession();
  });

  codeInput.addEventListener("keydown", (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      startSession();
    }
  });
})();
