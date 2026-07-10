(() => {
  const DUR = 18000;
  window.__duration = DUR;

  const $ = (selector) => document.querySelector(selector);
  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
  const seg = (time, start, end) => clamp((time - start) / (end - start), 0, 1);
  const easeOut = (p) => 1 - Math.pow(1 - p, 3);
  const easeInOut = (p) =>
    p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2;
  const lerp = (a, b, p) => a + (b - a) * p;

  const SCENES = [
    {
      key: "privacy",
      start: 0,
      end: 2500,
      kicker: "NO COOKIES · NO ANALYTICS · NO ADS",
      headline: "Private by<br><em>default.</em>",
    },
    {
      key: "no-account",
      start: 2500,
      end: 5500,
      kicker: "NO ACCOUNT REQUIRED",
      headline: "No profile.<br><em>No personal data.</em>",
    },
    {
      key: "links",
      start: 5500,
      end: 8800,
      kicker: "ADD WHAT MATTERS",
      headline: "Your links.<br><em>One address.</em>",
    },
    {
      key: "share",
      start: 8800,
      end: 11800,
      kicker: "ONE LINK + A QR",
      headline: "Ready to<br><em>share.</em>",
    },
    {
      key: "no-banner",
      start: 11800,
      end: 14900,
      kicker: "NO COOKIE BANNER",
      headline: "Nothing to<br><em>consent to.</em>",
    },
  ];

  const URL_TEXT = "ada";
  const NAME_TEXT = "Ada Lovelace";
  const HEADING_TEXT = "Mathematician · first computer programmer";

  function setTypedText(element, value, count, showCaret) {
    element.textContent = value.slice(0, count);
    if (showCaret) {
      const caret = document.createElement("span");
      caret.className = "text-caret";
      element.append(caret);
    }
  }

  function setCopy(time) {
    const scene = SCENES.find((item) => time >= item.start && time < item.end);
    if (!scene) {
      $("#message").style.opacity = "0";
      return;
    }

    const message = $("#message");
    if (message.dataset.scene !== scene.key) {
      message.dataset.scene = scene.key;
      $("#kicker").textContent = scene.kicker;
      $("#headline").innerHTML = scene.headline;
    }

    const enter =
      scene.start === 0
        ? 1
        : easeOut(seg(time, scene.start, scene.start + 280));
    message.style.opacity = "1";
    message.style.transform =
      "translateY(" +
      lerp(16, 0, enter).toFixed(2) +
      "px) scale(" +
      lerp(0.985, 1, enter).toFixed(4) +
      ")";
  }

  function renderAt(time) {
    time = clamp(time, 0, DUR);

    setCopy(time);

    // The product is already complete on frame one. Each later beat isolates
    // one action without ever leaving the viewer with an empty phone.
    const phoneEnter = 1;
    const phoneFloat = Math.sin(time / 850) * 3;
    const publishIn = easeOut(seg(time, 11900, 12600));
    $("#phone").style.opacity = phoneEnter.toFixed(3);
    $("#phone").style.transform =
      "translateX(-50%) translateY(" +
      (phoneFloat + publishIn * 10).toFixed(2) +
      "px) rotate(" +
      lerp(-0.8, 0.35, seg(time, 0, 8800)).toFixed(3) +
      "deg) scale(" +
      (1 - publishIn * 0.035).toFixed(4) +
      ")";

    // Keep the claimed address in place and type the two fields that make the
    // page personal. The second field begins as soon as the name is complete.
    $("#url").innerHTML = '<span class="host">found.as/</span>' + URL_TEXT;
    if (time >= 2500 && time < 5500) {
      const nameCount = Math.floor(seg(time, 2650, 3200) * NAME_TEXT.length);
      const headingCount = Math.floor(
        seg(time, 3300, 4300) * HEADING_TEXT.length,
      );
      setTypedText($("#name"), NAME_TEXT, nameCount, time < 3300);
      setTypedText(
        $("#bio"),
        HEADING_TEXT,
        headingCount,
        time >= 3300 && time < 4550,
      );
    } else {
      setTypedText($("#name"), NAME_TEXT, NAME_TEXT.length, false);
      setTypedText($("#bio"), HEADING_TEXT, HEADING_TEXT.length, false);
    }
    for (const selector of ["#avatar", "#name", "#bio"]) {
      $(selector).style.opacity = "1";
      $(selector).style.transform = "translateY(0)";
    }

    document.querySelectorAll(".btn").forEach((button) => {
      const index = Number(button.dataset.i);
      let visibility = 1;
      if (time >= 2500 && time < 5500) visibility = 0.13;
      if (time >= 5500 && time < 8800) {
        visibility = easeOut(seg(time, 5600 + index * 520, 6100 + index * 520));
      }
      button.style.opacity = visibility.toFixed(3);
      button.style.transform =
        "translateX(" +
        lerp(22, 0, visibility).toFixed(2) +
        "px) scale(" +
        lerp(0.97, 1, visibility).toFixed(4) +
        ")";
    });

    const euIn = easeOut(seg(time, 5700, 6200));
    const euVisibility = euIn * (1 - easeInOut(seg(time, 8400, 8800)));
    const euChip = $(".eu-chip");
    euChip.style.opacity = euVisibility.toFixed(3);
    euChip.style.transform =
      "translateX(" + lerp(-34, 0, euIn).toFixed(2) + "px) rotate(-4deg)";

    const energyIn = easeOut(seg(time, 8950, 9450));
    const energyVisibility =
      energyIn * (1 - easeInOut(seg(time, 11400, 11800)));
    const energyChip = $(".energy-chip");
    energyChip.style.opacity = energyVisibility.toFixed(3);
    energyChip.style.transform =
      "translateX(" + lerp(34, 0, energyIn).toFixed(2) + "px) rotate(4deg)";

    const qrVisibility = publishIn;
    $("#qr").style.opacity = qrVisibility.toFixed(3);
    $("#qr").style.transform =
      "translateX(-50%) translateY(" +
      lerp(80, 0, publishIn).toFixed(2) +
      "px) scale(" +
      lerp(0.94, 1, publishIn).toFixed(4) +
      ")";
    $("#screen").style.filter =
      "brightness(" + (1 - publishIn * 0.2).toFixed(3) + ")";

    $("#mast").style.opacity = "1";
    $("#backdrop").style.transform =
      "translateX(" + (Math.sin(time / 1500) * 6).toFixed(2) + "px)";
    $("#progress span").style.transform =
      "scaleX(" + (time / DUR).toFixed(5) + ")";
    $("#progress").style.opacity = "1";

    const end = $("#end");
    end.style.opacity = time >= 14800 ? "1" : "0";
    const endIn = easeInOut(seg(time, 14800, 15400));
    end.style.transform =
      "translateY(" + lerp(1920, 0, endIn).toFixed(2) + "px)";
    const endRise = easeOut(seg(time, 14850, 15350));
    $("#end .wm").style.opacity = endRise.toFixed(3);
    $("#end .wm").style.transform =
      "translateY(" + lerp(28, 0, endRise).toFixed(2) + "px)";
    $("#end .wave").style.transform =
      "rotate(" +
      (Math.sin(seg(time, 15300, 17400) * Math.PI * 5) * 10).toFixed(2) +
      "deg)";
    const endCopy = easeOut(seg(time, 15100, 15600));
    $("#end .end-headline").style.opacity = endCopy.toFixed(3);
    $("#end .end-headline").style.transform =
      "translateY(" + lerp(34, 0, endCopy).toFixed(2) + "px)";
    const ctaIn = easeOut(seg(time, 15400, 15900));
    $("#end .cta").style.opacity = ctaIn.toFixed(3);
    $("#end .cta").style.transform =
      "translateY(" + lerp(26, 0, ctaIn).toFixed(2) + "px)";
    $("#end .trust").style.opacity = easeOut(seg(time, 15700, 16200)).toFixed(
      3,
    );
  }

  window.__renderAt = renderAt;
  const match = location.hash.match(/t=(\d+)/);
  renderAt(match ? Number(match[1]) : 0);
})();
