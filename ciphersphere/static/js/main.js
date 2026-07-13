(() => {
  "use strict";

  const root = document.documentElement;
  root.classList.add("js");
  const status = document.querySelector("#ui-status");
  const announce = (message) => {
    if (!status) return;
    status.textContent = "";
    window.setTimeout(() => { status.textContent = message; }, 20);
  };

  const appearanceButtons = Array.from(document.querySelectorAll("[data-appearance-choice]"));
  const appearanceLabels = document.querySelectorAll("[data-appearance-current]");
  const appearanceValues = new Set(
    appearanceButtons
      .map((button) => button.dataset.appearanceChoice?.trim())
      .filter(Boolean)
  );
  const defaultAppearance = "cipher-noir";
  const storedAppearance = () => {
    try {
      const value = window.localStorage.getItem("ciphersphere-design-theme");
      return value && appearanceValues.has(value) ? value : null;
    } catch (_) { return null; }
  };
  const appearanceName = (value) => {
    const choice = appearanceButtons.find(
      (button) => button.dataset.appearanceChoice?.trim() === value
    );
    return choice?.dataset.appearanceName?.trim()
      || value.replace(/[-_]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  };
  const commitAppearance = (value, { persist = false, notify = false } = {}) => {
    const next = appearanceValues.has(value) ? value : defaultAppearance;
    root.dataset.appearance = next;
    appearanceButtons.forEach((button) => {
      const selected = button.dataset.appearanceChoice?.trim() === next;
      button.setAttribute("aria-pressed", String(selected));
    });
    const name = appearanceName(next);
    appearanceLabels.forEach((label) => { label.textContent = name; });
    if (persist) {
      try { window.localStorage.setItem("ciphersphere-design-theme", next); } catch (_) { /* Appearance still applies for this page. */ }
    }
    if (notify) announce(`${name} appearance enabled`);
  };
  const applyAppearance = (value, { persist = false, notify = false, animate = false, source = null } = {}) => {
    const next = appearanceValues.has(value) ? value : defaultAppearance;
    const commit = () => commitAppearance(next, { persist, notify });
    const canAnimate = animate
      && root.dataset.appearance !== next
      && !reducedMotion?.matches
      && !root.classList.contains("effects-paused");

    if (canAnimate && typeof document.startViewTransition === "function") {
      document.startViewTransition(commit);
    } else if (canAnimate) {
      root.classList.add("theme-transitioning");
      commit();
      window.setTimeout(() => root.classList.remove("theme-transitioning"), 520);
    } else {
      commit();
    }

    const picker = source?.closest("details");
    if (picker) {
      const summary = picker.querySelector("summary");
      picker.removeAttribute("open");
      window.requestAnimationFrame(() => summary?.focus());
    }
  };
  applyAppearance(storedAppearance() || defaultAppearance);
  appearanceButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const choice = button.dataset.appearanceChoice?.trim();
      if (choice) applyAppearance(choice, { persist: true, notify: true, animate: true, source: button });
    });
  });

  const navButton = document.querySelector(".nav-toggle");
  const navigation = document.querySelector("#primary-navigation");
  const syncNavigation = () => {
    if (!navButton || !navigation) return;
    if (window.innerWidth <= 1180) {
      const open = navButton.getAttribute("aria-expanded") === "true";
      const shouldHide = !open;
      if (shouldHide && navigation.contains(document.activeElement)) navButton.focus();
      navigation.hidden = shouldHide;
    } else {
      navigation.hidden = false;
      navButton.setAttribute("aria-expanded", "false");
    }
  };
  navButton?.addEventListener("click", () => {
    const open = navButton.getAttribute("aria-expanded") === "true";
    navButton.setAttribute("aria-expanded", String(!open));
    if (navigation) navigation.hidden = open;
  });
  window.addEventListener("resize", syncNavigation, { passive: true });
  syncNavigation();

  const syncScrolledHeader = () => root.classList.toggle("is-scrolled", window.scrollY > 16);
  window.addEventListener("scroll", syncScrolledHeader, { passive: true });
  syncScrolledHeader();

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const effectsButtons = Array.from(document.querySelectorAll("[data-effects-toggle]"));
  const effectsLabels = document.querySelectorAll("[data-effects-label]");
  const storedEffects = () => {
    try {
      const value = window.localStorage.getItem("ciphersphere-effects");
      return value === "paused" || value === "running" ? value : null;
    } catch (_) { return null; }
  };
  let effectsPreference = storedEffects() || (reducedMotion.matches ? "paused" : "running");
  const syncEffects = ({ persist = false, notify = false, reason = "preference" } = {}) => {
    const running = effectsPreference === "running" && !reducedMotion.matches && !document.hidden;
    root.classList.toggle("effects-paused", !running);
    effectsButtons.forEach((button) => {
      button.setAttribute("aria-pressed", String(!running));
    });
    const label = reducedMotion.matches && effectsPreference === "running"
      ? "Effects paused by system"
      : running ? "Pause effects" : "Resume effects";
    effectsLabels.forEach((element) => { element.textContent = label; });
    if (persist) {
      try { window.localStorage.setItem("ciphersphere-effects", effectsPreference); } catch (_) { /* The current-page preference still applies. */ }
    }
    window.dispatchEvent(new CustomEvent("ciphersphere:effects", {
      detail: { running, preference: effectsPreference, reason }
    }));
    if (notify) {
      announce(
        reducedMotion.matches && effectsPreference === "running"
          ? "Effects remain paused because reduced motion is enabled"
          : running ? "Page effects resumed" : "Page effects paused"
      );
    }
  };
  effectsButtons.forEach((button) => {
    button.addEventListener("click", () => {
      effectsPreference = effectsPreference === "running" ? "paused" : "running";
      syncEffects({ persist: true, notify: true, reason: "user" });
    });
  });
  document.addEventListener("visibilitychange", () => {
    syncEffects({ reason: document.hidden ? "hidden" : "visible" });
  });
  reducedMotion.addEventListener?.("change", () => syncEffects({ reason: "system" }));
  syncEffects({ reason: "initial" });

  const precisePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
  const coarsePointer = window.matchMedia("(pointer: coarse)");
  const revealElements = Array.from(document.querySelectorAll(".motion-reveal"));
  const reveal = (element, observer) => {
    element.classList.add("is-visible");
    observer?.unobserve(element);
  };
  if (reducedMotion.matches || !("IntersectionObserver" in window)) {
    revealElements.forEach((element) => reveal(element));
  } else {
    root.classList.add("motion-observer");
    const revealObserver = new IntersectionObserver((entries, observer) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) reveal(entry.target, observer);
      });
    }, { rootMargin: "0px 0px -6%", threshold: 0.08 });
    revealElements.forEach((element) => {
      element.addEventListener("focusin", () => reveal(element, revealObserver), { once: true });
      revealObserver.observe(element);
    });
    reducedMotion.addEventListener?.("change", (event) => {
      if (event.matches) revealElements.forEach((element) => reveal(element, revealObserver));
    });
  }

  let removeTiltListeners = [];
  const clearTilt = (surface) => {
    surface.classList.remove("is-tilting");
    ["--tilt-x", "--tilt-y", "--pointer-x", "--pointer-y"].forEach((property) => {
      surface.style.removeProperty(property);
    });
  };
  const syncPointerTilt = () => {
    removeTiltListeners.forEach((remove) => remove());
    removeTiltListeners = [];
    const surfaces = document.querySelectorAll("[data-cyber-tilt]");
    if (
      root.classList.contains("effects-paused")
      || reducedMotion.matches
      || coarsePointer.matches
      || !precisePointer.matches
    ) {
      surfaces.forEach(clearTilt);
      return;
    }
    surfaces.forEach((surface) => {
      let frame = 0;
      let pointerEvent = null;
      const onMove = (event) => {
        pointerEvent = event;
        if (frame) return;
        frame = window.requestAnimationFrame(() => {
          const bounds = surface.getBoundingClientRect();
          if (!pointerEvent || bounds.width === 0 || bounds.height === 0) {
            frame = 0;
            return;
          }
          const x = Math.min(1, Math.max(0, (pointerEvent.clientX - bounds.left) / bounds.width));
          const y = Math.min(1, Math.max(0, (pointerEvent.clientY - bounds.top) / bounds.height));
          surface.style.setProperty("--tilt-x", `${((0.5 - y) * 4).toFixed(2)}deg`);
          surface.style.setProperty("--tilt-y", `${((x - 0.5) * 4).toFixed(2)}deg`);
          surface.style.setProperty("--pointer-x", `${(x * 100).toFixed(1)}%`);
          surface.style.setProperty("--pointer-y", `${(y * 100).toFixed(1)}%`);
          surface.classList.add("is-tilting");
          frame = 0;
        });
      };
      const onLeave = () => {
        pointerEvent = null;
        if (frame) window.cancelAnimationFrame(frame);
        frame = 0;
        clearTilt(surface);
      };
      surface.addEventListener("pointermove", onMove, { passive: true });
      surface.addEventListener("pointerleave", onLeave, { passive: true });
      removeTiltListeners.push(() => {
        surface.removeEventListener("pointermove", onMove);
        surface.removeEventListener("pointerleave", onLeave);
        onLeave();
      });
    });
  };
  window.addEventListener("ciphersphere:effects", syncPointerTilt);
  coarsePointer.addEventListener?.("change", syncPointerTilt);
  precisePointer.addEventListener?.("change", syncPointerTilt);
  syncPointerTilt();

  const firstInvalid = Array.from(document.querySelectorAll("[aria-invalid='true']"))
    .find((element) => !element.hidden && !element.closest("[hidden]"));
  const pageAlert = Array.from(document.querySelectorAll(".flash[role='alert']"))
    .find((element) => !element.hidden && !element.closest("[hidden]"));
  if (firstInvalid) {
    firstInvalid.focus();
  } else if (pageAlert) {
    pageAlert.setAttribute("tabindex", "-1");
    pageAlert.focus();
  }

  document.querySelectorAll("[data-password-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.passwordToggle);
      if (!input) return;
      const reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      button.textContent = reveal ? "Hide password" : "Show password";
      button.setAttribute("aria-pressed", String(reveal));
    });
  });

  const recoveryForm = document.querySelector(".js-recovery-form");
  if (recoveryForm) {
    const recoveryStatus = document.querySelector("#recovery-status");
    const submit = recoveryForm.querySelector("[data-recovery-submit]");
    const accessInput = recoveryForm.querySelector("#recovery-access-token");
    const refreshInput = recoveryForm.querySelector("#recovery-refresh-token");
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const accessToken = fragment.get("access_token") || accessInput?.value;
    const refreshToken = fragment.get("refresh_token") || refreshInput?.value;
    const recoveryError = fragment.get("error_description");
    if (accessToken && refreshToken) {
      accessInput.value = accessToken;
      refreshInput.value = refreshToken;
      if (submit) submit.disabled = false;
      if (recoveryStatus) recoveryStatus.textContent = "Recovery link verified. Choose a new password.";
      if (window.location.hash) window.history.replaceState(null, "", window.location.pathname + window.location.search);
    } else if (recoveryStatus) {
      recoveryStatus.textContent = recoveryError || "Open the latest password-reset link from your email.";
      recoveryStatus.classList.add("callout--warning");
    }
  }

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const source = document.getElementById(button.dataset.copyTarget);
      if (!source) return;
      const value = "value" in source ? source.value : source.textContent;
      try {
        await navigator.clipboard.writeText(value || "");
        announce("Copied to clipboard");
        const original = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(() => { button.textContent = original; }, 1400);
      } catch (_) {
        announce("Copy failed. Select the value and copy it manually.");
      }
    });
  });

  const showRequestError = (message) => {
    const alert = document.querySelector("#ui-error");
    if (!alert) return;
    alert.textContent = "";
    alert.hidden = false;
    window.setTimeout(() => { alert.textContent = message; }, 20);
  };

  try {
    const pending = window.sessionStorage.getItem("ciphersphere-status");
    if (pending) {
      window.sessionStorage.removeItem("ciphersphere-status");
      const notice = document.querySelector("#ui-notice");
      if (notice) {
        notice.hidden = false;
        notice.textContent = pending;
      } else {
        announce(pending);
      }
    }
  } catch (_) { /* Session storage is optional. */ }

  document.querySelectorAll("form[data-json-form]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) return;
      const submit = form.querySelector("button[type='submit']");
      const data = Object.fromEntries(new FormData(form).entries());
      const token = data.csrf_token || "";
      if (submit) submit.disabled = true;
      try {
        const response = await fetch(form.action, {
          method: form.method || "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRFToken": token },
          body: JSON.stringify(data)
        });
        const isJson = (response.headers.get("content-type") || "").includes("application/json");
        const result = isJson ? await response.json() : {};
        if (!response.ok || result.success === false) throw new Error(result.message || result.error || "The request could not be completed.");
        const message = result.message || form.dataset.success || "Request completed";
        try { window.sessionStorage.setItem("ciphersphere-status", message); } catch (_) { /* Reload still completes. */ }
        window.location.reload();
      } catch (error) {
        showRequestError(error.message || "The request could not be completed.");
        if (submit) submit.disabled = false;
      }
    });
  });
  document.querySelectorAll("button[data-confirm]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (!window.confirm(button.dataset.confirm || "Continue?")) event.preventDefault();
    });
  });
})();
