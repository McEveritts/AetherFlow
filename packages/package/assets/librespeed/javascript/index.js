/**
 * LibreSpeed Obsidian V2 — Speedtest.net Stage & 120Hz Telemetry Engine
 * Grounded in AetherFlow v3.2 & Ookla Speedtest Choreography
 */

const INITIALIZING = 0;
const READY = 1;
const RUNNING = 2;
const FINISHED = 3;

const SCALE_1G = [
  { value: 0, label: "0" },
  { value: 5, label: "5" },
  { value: 10, label: "10" },
  { value: 50, label: "50" },
  { value: 100, label: "100" },
  { value: 250, label: "250" },
  { value: 500, label: "500" },
  { value: 750, label: "750" },
  { value: 1000, label: "1000" },
];

const SCALE_10G = [
  { value: 0, label: "0" },
  { value: 10, label: "10" },
  { value: 50, label: "50" },
  { value: 100, label: "100" },
  { value: 250, label: "250" },
  { value: 500, label: "500" },
  { value: 1000, label: "1G" },
  { value: 5000, label: "5G" },
  { value: 10000, label: "10G" },
];

const testState = {
  state: INITIALIZING,
  speedtest: null,
  servers: [],
  selectedServerDirty: false,
  testData: null,
  testDataDirty: false,
  telemetryEnabled: false,
  dlHistory: [],
  ulHistory: [],
  lastRecordedDlProgress: -1,
  lastRecordedUlProgress: -1,
  activeScale: SCALE_1G,
  currentMbps: 0,
  targetMbps: 0,
  currentFraction: 0,
  targetFraction: 0,
  currentProgress: 0,
  targetProgress: 0,
  tickElements: [],
  majorLabelElements: [],
};

function getBaseServerURL() {
  const path = window.location.pathname.replace(/\/[^/]*$/, "/");
  return window.location.origin + path;
}

function getDefaultLocalServer() {
  return {
    name: "AetherFlow Nexus · Falkenstein, DE",
    server: getBaseServerURL(),
    dlURL: "backend/garbage.php",
    ulURL: "backend/empty.php",
    pingURL: "backend/empty.php",
    getIpURL: "backend/getIP.php",
    sponsorName: "AetherFlow Obsidian V2",
    sponsorURL: window.location.origin,
  };
}

function normalizeServerEntry(s) {
  const copy = Object.assign({}, s);
  if (!copy.server || copy.server === "" || copy.server === "/") {
    copy.server = getBaseServerURL();
  }
  return copy;
}

window.addEventListener("DOMContentLoaded", async () => {
  buildSpeedometerTicks();
  initSparklines();
  createSpeedtest();
  hookUpButtons();
  startRenderingLoop();
  await applySettingsJSON();
  await applyServerListJSON();
});

/**
 * Populate the 270° radial scale ticks and labels around center (220, 190)
 */
function buildSpeedometerTicks() {
  const group = document.querySelector("#st-gauge-ticks");
  if (!group) return;
  group.innerHTML = "";
  testState.tickElements = [];
  testState.majorLabelElements = [];

  const cx = 220;
  const cy = 190;
  const rOuter = 126;
  const rMajorInner = 114;
  const rMinorInner = 120;
  const rLabel = 96;

  const stops = testState.activeScale;
  const segments = stops.length - 1;
  const minorPerSegment = 5;
  const totalSteps = segments * minorPerSegment;

  for (let step = 0; step <= totalSteps; step++) {
    const frac = step / totalSteps;
    const isMajor = step % minorPerSegment === 0;
    const degFromTop = -135 + frac * 270;
    const rad = ((degFromTop - 90) * Math.PI) / 180;
    const cos = Math.cos(rad);
    const sin = Math.sin(rad);

    const x1 = cx + rOuter * cos;
    const y1 = cy + rOuter * sin;
    const rIn = isMajor ? rMajorInner : rMinorInner;
    const x2 = cx + rIn * cos;
    const y2 = cy + rIn * sin;

    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", x1.toFixed(2));
    line.setAttribute("y1", y1.toFixed(2));
    line.setAttribute("x2", x2.toFixed(2));
    line.setAttribute("y2", y2.toFixed(2));
    line.setAttribute(
      "class",
      isMajor ? "st-tick-line" : "st-tick-line is-minor"
    );
    group.appendChild(line);

    let labelEl = null;
    if (isMajor) {
      const stopIdx = step / minorPerSegment;
      const stop = stops[stopIdx];
      const lx = cx + rLabel * cos;
      const ly = cy + rLabel * sin;
      labelEl = document.createElementNS("http://www.w3.org/2000/svg", "text");
      labelEl.setAttribute("x", lx.toFixed(2));
      labelEl.setAttribute("y", ly.toFixed(2));
      labelEl.setAttribute("class", "st-tick-label");
      labelEl.textContent = stop.label;
      group.appendChild(labelEl);
      testState.majorLabelElements.push(labelEl);
    }

    testState.tickElements.push({
      frac,
      line,
      labelEl,
    });
  }
}

function setGaugeScale(newScale) {
  if (testState.activeScale === newScale) return;
  testState.activeScale = newScale;
  for (let i = 0; i < testState.majorLabelElements.length; i++) {
    if (newScale[i]) {
      testState.majorLabelElements[i].textContent = newScale[i].label;
    }
  }
}

/**
 * Exact piecewise linear speed -> [0..1] gauge fraction matching activeScale stops (zero synthetic wiggle)
 */
function speedToFraction(mbps) {
  const s = Number(mbps);
  if (!s || s <= 0 || isNaN(s)) return 0;

  const stops = testState.activeScale;
  const maxVal = stops[stops.length - 1].value;
  if (s >= maxVal) return 1;

  for (let i = 0; i < stops.length - 1; i++) {
    const a = stops[i].value;
    const b = stops[i + 1].value;
    if (s >= a && s <= b) {
      const localT = (s - a) / (b - a);
      return Math.max(0, Math.min(1, (i + localT) / (stops.length - 1)));
    }
  }
  return 0;
}

/**
 * Draw a glowing area waveform sparkline on a canvas
 */
function drawWaveform(canvas, samples, strokeColor, fillTop, fillBottom) {
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || canvas.width;
  const h = canvas.clientHeight || canvas.height;
  const pw = Math.round(w * dpr);
  const ph = Math.round(h * dpr);
  if (canvas.width !== pw || canvas.height !== ph) {
    canvas.width = pw;
    canvas.height = ph;
  }

  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, pw, ph);

  // Subtle baseline
  ctx.beginPath();
  ctx.strokeStyle = "rgba(148, 163, 184, 0.16)";
  ctx.lineWidth = 1 * dpr;
  ctx.moveTo(0, ph - 2 * dpr);
  ctx.lineTo(pw, ph - 2 * dpr);
  ctx.stroke();

  if (!samples || samples.length < 2) return;

  const maxVal = Math.max(...samples, 10) * 1.12;
  const padTop = 4 * dpr;
  const padBot = 3 * dpr;
  const usableH = ph - padTop - padBot;

  const pts = samples.map((v, idx) => {
    const x = (idx / (samples.length - 1)) * pw;
    const y = padTop + usableH * (1 - Math.min(1, Math.max(0, v / maxVal)));
    return { x, y };
  });

  // Area fill under curve
  const grad = ctx.createLinearGradient(0, 0, 0, ph);
  grad.addColorStop(0, fillTop);
  grad.addColorStop(1, fillBottom);

  ctx.beginPath();
  ctx.moveTo(pts[0].x, ph - padBot);
  ctx.lineTo(pts[0].x, pts[0].y);
  for (let i = 1; i < pts.length; i++) {
    const xc = (pts[i - 1].x + pts[i].x) / 2;
    const yc = (pts[i - 1].y + pts[i].y) / 2;
    ctx.quadraticCurveTo(pts[i - 1].x, pts[i - 1].y, xc, yc);
  }
  const last = pts[pts.length - 1];
  ctx.lineTo(last.x, last.y);
  ctx.lineTo(last.x, ph - padBot);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Glowing top stroke
  ctx.beginPath();
  ctx.moveTo(pts[0].x, pts[0].y);
  for (let i = 1; i < pts.length; i++) {
    const xc = (pts[i - 1].x + pts[i].x) / 2;
    const yc = (pts[i - 1].y + pts[i].y) / 2;
    ctx.quadraticCurveTo(pts[i - 1].x, pts[i - 1].y, xc, yc);
  }
  ctx.lineTo(last.x, last.y);
  ctx.strokeStyle = strokeColor;
  ctx.lineWidth = 2.2 * dpr;
  ctx.lineCap = "round";
  ctx.stroke();
}

function initSparklines() {
  drawWaveform(
    document.querySelector("#dl-sparkline"),
    [],
    "#d946ef",
    "rgba(217, 70, 239, 0.35)",
    "rgba(217, 70, 239, 0.0)"
  );
  drawWaveform(
    document.querySelector("#ul-sparkline"),
    [],
    "#38bdf8",
    "rgba(56, 189, 248, 0.35)",
    "rgba(56, 189, 248, 0.0)"
  );
  drawWaveform(
    document.querySelector("#st-gauge-wave"),
    [],
    "#a855f7",
    "rgba(168, 85, 247, 0.30)",
    "rgba(168, 85, 247, 0.0)"
  );
}

function createSpeedtest() {
  testState.speedtest = new Speedtest();
  testState.speedtest.onupdate = (data) => {
    testState.testData = data;
    testState.testDataDirty = true;

    const dl = Number(data.dlStatus);
    if (
      data.testState === 1 &&
      dl > 0 &&
      data.dlProgress !== testState.lastRecordedDlProgress
    ) {
      testState.lastRecordedDlProgress = data.dlProgress;
      testState.dlHistory.push(dl);
    }

    const ul = Number(data.ulStatus);
    if (
      data.testState === 3 &&
      ul > 0 &&
      data.ulProgress !== testState.lastRecordedUlProgress
    ) {
      testState.lastRecordedUlProgress = data.ulProgress;
      testState.ulHistory.push(ul);
    }
  };
  testState.speedtest.onend = (aborted) => {
    testState.state = aborted ? READY : FINISHED;
    testState.testDataDirty = true;
  };
}

function beginBenchmark() {
  if (testState.state !== READY && testState.state !== FINISHED) return;
  testState.dlHistory = [];
  testState.ulHistory = [];
  testState.lastRecordedDlProgress = -1;
  testState.lastRecordedUlProgress = -1;
  setGaugeScale(SCALE_1G);
  testState.currentMbps = 0;
  testState.targetMbps = 0;
  testState.currentFraction = 0;
  testState.targetFraction = 0;
  testState.currentProgress = 0;
  testState.targetProgress = 0;
  initSparklines();
  testState.speedtest.start();
  testState.state = RUNNING;
}

function abortBenchmark() {
  if (testState.state === RUNNING) {
    testState.speedtest.abort();
    testState.state = READY;
    testState.targetMbps = 0;
    testState.currentMbps = 0;
    testState.targetFraction = 0;
    testState.targetProgress = 0;
  }
}

function hookUpButtons() {
  document
    .querySelector("#start-button")
    .addEventListener("click", () => {
      if (testState.state === RUNNING) {
        abortBenchmark();
      } else {
        beginBenchmark();
      }
    });

  const abortBtn = document.querySelector("#abort-button");
  if (abortBtn) {
    abortBtn.addEventListener("click", abortBenchmark);
  }

  const restartBtn = document.querySelector("#restart-button");
  if (restartBtn) {
    restartBtn.addEventListener("click", beginBenchmark);
  }

  document
    .querySelector("#choose-privacy")
    .addEventListener("click", (e) => {
      e.preventDefault();
      document.querySelector("#privacy").showModal();
    });

  document
    .querySelector("#share-results")
    .addEventListener("click", () =>
      document.querySelector("#share").showModal()
    );

  document
    .querySelector("#copy-link")
    .addEventListener("click", copyLinkButtonClickHandler);

  document
    .querySelectorAll(".close-dialog, #close-privacy")
    .forEach((element) => {
      element.addEventListener("click", () =>
        document.querySelectorAll("dialog").forEach((modal) => modal.close())
      );
    });
}

async function copyLinkButtonClickHandler() {
  const link = document.querySelector("img#results").src;
  await navigator.clipboard.writeText(link);
  const button = document.querySelector("#copy-link");
  button.classList.add("active");
  button.textContent = "Copied!";
  setTimeout(() => {
    button.classList.remove("active");
    button.textContent = "Copy link";
  }, 3000);
}

async function applySettingsJSON() {
  try {
    const response = await fetch("settings.json");
    if (!response.ok) throw new Error("settings.json not found");
    const settings = await response.json();
    if (!settings || typeof settings !== "object") return;
    for (let setting in settings) {
      testState.speedtest.setParameter(setting, settings[setting]);
      if (
        setting == "telemetry_level" &&
        settings[setting] &&
        settings[setting] != "off" &&
        settings[setting] != "disabled" &&
        settings[setting] != "false"
      ) {
        testState.telemetryEnabled = true;
      }
    }
  } catch (error) {
    testState.speedtest.setParameter("telemetry_level", "basic");
    testState.telemetryEnabled = true;
  }
}

async function applyServerListJSON() {
  let servers = [];
  try {
    const serverSource =
      typeof globalThis.SPEEDTEST_SERVERS !== "undefined"
        ? globalThis.SPEEDTEST_SERVERS
        : "server-list.json";
    const rawServers = Array.isArray(serverSource)
      ? serverSource
      : await fetch(serverSource).then((response) => {
          if (!response.ok) throw new Error("server-list.json not found");
          return response.json();
        });
    if (Array.isArray(rawServers) && rawServers.length > 0) {
      servers = rawServers.map(normalizeServerEntry);
    }
  } catch (error) {
    servers = [getDefaultLocalServer()];
  }

  if (servers.length === 0) {
    servers = [getDefaultLocalServer()];
  }

  testState.servers = servers;

  if (servers.length === 1) {
    populateDropdown(servers);
    return;
  }

  testState.speedtest.addTestPoints(servers);
  testState.speedtest.selectServer((bestServer) => {
    const aliveServers = testState.servers.filter((s) => {
      if (s.pingT !== -1) return true;
      return typeof s.server === "string" && s.server.startsWith("//");
    });

    if (aliveServers.length > 0) {
      testState.servers = aliveServers;
    }
    populateDropdown(testState.servers);

    if (bestServer) {
      selectServer(bestServer);
    } else {
      selectServer(testState.servers[0]);
    }
  });
}

function populateDropdown(servers) {
  const serverSelector = document.querySelector("div.server-selector");
  const serverList = serverSelector.querySelector("ul.servers");

  serverSelector.classList.remove("single-server");
  serverSelector.classList.remove("active");
  serverList.classList.remove("active");
  serverList.innerHTML = "";

  if (servers.length === 1) {
    serverSelector.classList.add("single-server");
    selectServer(servers[0]);
    return;
  }
  serverSelector.classList.add("active");

  if (serverSelector.dataset.hooked !== "1") {
    serverSelector.dataset.hooked = "1";

    serverSelector.addEventListener("click", () => {
      serverList.classList.toggle("active");
    });
    document.addEventListener("click", (e) => {
      if (e.target.closest("div.server-selector") !== serverSelector)
        serverList.classList.remove("active");
    });
  }

  servers.forEach((server) => {
    const item = document.createElement("li");
    const link = document.createElement("a");
    link.href = "#";
    link.innerHTML = `${server.name}${
      server.sponsorName ? ` <span>(${server.sponsorName})</span>` : ""
    }`;
    link.addEventListener("click", (e) => {
      e.preventDefault();
      selectServer(server);
    });
    item.appendChild(link);
    serverList.appendChild(item);
  });
}

function selectServer(server) {
  testState.speedtest.setSelectedServer(server);
  testState.selectedServerDirty = true;
  testState.state = READY;
}

function startRenderingLoop() {
  const mainEl = document.querySelector("main.st-main");
  const serverSelector = document.querySelector("div.server-selector");
  const selectedServer = document.querySelector("#selected-server");
  const sponsor = document.querySelector("#sponsor");
  const startButton = document.querySelector("#start-button");
  const startButtonSub = document.querySelector("#start-button-sub");
  const abortButton = document.querySelector("#abort-button");
  const restartButton = document.querySelector("#restart-button");
  const shareResults = document.querySelector("#share-results");
  const resultsImage = document.querySelector("img#results");

  const cardPing = document.querySelector("#card-ping");
  const cardJitter = document.querySelector("#card-jitter");
  const cardDownload = document.querySelector("#card-download");
  const cardUpload = document.querySelector("#card-upload");

  const pingText = document.querySelector("#ping");
  const jitterText = document.querySelector("#jitter");
  const downloadText = document.querySelector("#download-speed");
  const uploadText = document.querySelector("#upload-speed");

  const dlSparkCanvas = document.querySelector("#dl-sparkline");
  const ulSparkCanvas = document.querySelector("#ul-sparkline");
  const gaugeWaveCanvas = document.querySelector("#st-gauge-wave");

  const arcActive = document.querySelector("#st-arc-active");
  const arcProgress = document.querySelector("#st-arc-progress");
  const needleGroup = document.querySelector("#st-needle-group");
  const masterValue = document.querySelector("#st-master-value");
  const masterUnit = document.querySelector("#st-master-unit");
  const phaseText = document.querySelector("#st-phase-text");

  const clientIpText = document.querySelector("#client-ip-text");
  const privacyWarning = document.querySelector("#privacy-warning");
  const fiberBridge = document.querySelector("#fiber-bridge");
  const fiberStatusLabel = document.querySelector("#fiber-status-label");

  function renderUI() {
    // 1. Stage state (idle vs running vs finished)
    const stageStr =
      testState.state === RUNNING
        ? "running"
        : testState.state === FINISHED
        ? "finished"
        : "idle";
    if (mainEl.dataset.stage !== stageStr) {
      mainEl.dataset.stage = stageStr;
    }

    startButton.classList.toggle("disabled", testState.state === INITIALIZING);
    startButton.classList.toggle("active", testState.state === RUNNING);
    if (startButtonSub) {
      startButtonSub.textContent =
        testState.state === INITIALIZING ? "Initializing..." : "Start Benchmark";
    }

    serverSelector.classList.toggle("disabled", testState.state === RUNNING);

    if (abortButton) {
      abortButton.classList.toggle("hidden", testState.state !== RUNNING);
    }
    if (restartButton) {
      restartButton.classList.toggle("hidden", testState.state !== FINISHED);
    }
    if (shareResults) {
      shareResults.classList.toggle(
        "hidden",
        !(
          testState.state === FINISHED &&
          testState.telemetryEnabled &&
          testState.testData &&
          testState.testData.testId
        )
      );
    }

    // 2. Selected Server
    if (testState.selectedServerDirty) {
      const server = testState.speedtest.getSelectedServer();
      selectedServer.textContent = server.name;
      if (server.sponsorName) {
        if (server.sponsorURL) {
          sponsor.innerHTML = `Operator: <a href="${server.sponsorURL}" target="_blank" rel="noopener noreferrer">${server.sponsorName}</a>`;
        } else {
          sponsor.textContent = `Operator: ${server.sponsorName}`;
        }
      } else {
        sponsor.innerHTML = "&nbsp;";
      }
      testState.selectedServerDirty = false;
    }

    // 3. Process live telemetry update
    const d = testState.testData;
    const workerState = d ? d.testState : -1;

    let phase = "idle";
    if (testState.state === RUNNING) {
      if (workerState === 1) phase = "download";
      else if (workerState === 3) phase = "upload";
      else phase = "ping";
    } else if (testState.state === FINISHED) {
      phase = "finished";
    }
    if (mainEl.dataset.phase !== phase) {
      mainEl.dataset.phase = phase;
    }

    // Highlight active scoreboard card
    cardPing.classList.toggle("is-active-phase", phase === "ping");
    cardJitter.classList.toggle("is-active-phase", phase === "ping");
    cardDownload.classList.toggle("is-active-phase", phase === "download");
    cardUpload.classList.toggle("is-active-phase", phase === "upload");

    // Fiber bridge stream direction
    if (fiberBridge) {
      const streamMode =
        phase === "download"
          ? "download"
          : phase === "upload"
          ? "upload"
          : phase === "ping"
          ? "ping"
          : "idle";
      if (fiberBridge.dataset.stream !== streamMode) {
        fiberBridge.dataset.stream = streamMode;
      }
    }
    if (fiberStatusLabel) {
      fiberStatusLabel.textContent =
        phase === "download"
          ? "Downlink Stream Active"
          : phase === "upload"
          ? "Uplink Stream Active"
          : phase === "ping"
          ? "Measuring RTT Latency"
          : phase === "finished"
          ? "Benchmark Complete"
          : "10GbE Direct Link";
    }

    // Phase badge & master target speed (Ping NEVER moves the throughput gauge)
    if (phase === "ping") {
      phaseText.textContent = "Testing Ping & Jitter";
      masterUnit.textContent = "Mbps";
      testState.targetMbps = 0;
      testState.currentMbps = 0;
      testState.targetProgress = Number(d?.pingProgress || 0);
    } else if (phase === "download") {
      const dlProg = Number(d?.dlProgress || 0);
      const dlVal = d && d.dlStatus ? Number(d.dlStatus) : 0;
      if (dlVal > 950 && testState.activeScale !== SCALE_10G) {
        setGaugeScale(SCALE_10G);
      }
      if (dlProg >= 1) {
        // Inter-phase settle between Download and Upload: return needle toward 0
        phaseText.textContent = "Preparing Upload Test";
        masterUnit.textContent = "Mbps";
        testState.targetMbps = 0;
        testState.targetProgress = 0;
      } else {
        phaseText.textContent = "Testing Download Throughput";
        masterUnit.textContent = "Mbps Downlink";
        testState.targetMbps = dlVal > 0 ? dlVal : 0;
        testState.targetProgress = dlProg;
      }
    } else if (phase === "upload") {
      const ulProg = Number(d?.ulProgress || 0);
      const ulVal = d && d.ulStatus ? Number(d.ulStatus) : 0;
      if (ulVal > 950 && testState.activeScale !== SCALE_10G) {
        setGaugeScale(SCALE_10G);
      }
      if (ulProg >= 1) {
        testState.targetMbps = 0;
        testState.targetProgress = 1;
      } else {
        phaseText.textContent = "Testing Upload Throughput";
        masterUnit.textContent = "Mbps Uplink";
        testState.targetMbps = ulVal > 0 ? ulVal : 0;
        testState.targetProgress = ulProg;
      }
    } else if (phase === "finished" && d) {
      phaseText.textContent = "Benchmark Complete";
      masterUnit.textContent = "Mbps";
      testState.targetMbps = 0;
      testState.targetProgress = 1;
    } else {
      testState.targetMbps = 0;
      testState.currentMbps = 0;
      testState.targetProgress = 0;
    }

    if (testState.testDataDirty && d) {
      if (d.pingStatus) pingText.textContent = numberToText(d.pingStatus);
      if (d.jitterStatus) jitterText.textContent = numberToText(d.jitterStatus);
      if (d.dlStatus) downloadText.textContent = numberToText(d.dlStatus);
      if (d.ulStatus) uploadText.textContent = numberToText(d.ulStatus);

      // Update sparklines
      drawWaveform(
        dlSparkCanvas,
        testState.dlHistory,
        "#d946ef",
        "rgba(217, 70, 239, 0.38)",
        "rgba(217, 70, 239, 0.0)"
      );
      drawWaveform(
        ulSparkCanvas,
        testState.ulHistory,
        "#38bdf8",
        "rgba(56, 189, 248, 0.38)",
        "rgba(56, 189, 248, 0.0)"
      );

      if (phase === "upload") {
        drawWaveform(
          gaugeWaveCanvas,
          testState.ulHistory,
          "#38bdf8",
          "rgba(56, 189, 248, 0.35)",
          "rgba(56, 189, 248, 0.0)"
        );
      } else {
        drawWaveform(
          gaugeWaveCanvas,
          testState.dlHistory,
          "#d946ef",
          "rgba(217, 70, 239, 0.35)",
          "rgba(217, 70, 239, 0.0)"
        );
      }

      if (d.clientIp) {
        const parts = d.clientIp.split(" - ");
        clientIpText.textContent = parts[0] || d.clientIp;
        privacyWarning.textContent = parts[1] || "Direct Telemetry Session";
      }

      if (d.testId) {
        resultsImage.src =
          window.location.href.substring(
            0,
            window.location.href.lastIndexOf("/")
          ) +
          "/results/?id=" +
          d.testId;
      }

      testState.testDataDirty = false;
    }

    // 4. Synchronized 60/120fps interpolation: digital readout, needle angle, arc, and ticks all derive from currentMbps
    const diff = testState.targetMbps - testState.currentMbps;
    if (Math.abs(diff) < 0.05) {
      testState.currentMbps = testState.targetMbps;
    } else {
      testState.currentMbps += diff * 0.28;
    }

    masterValue.textContent = numberToText(testState.currentMbps);

    const frac = speedToFraction(testState.currentMbps);
    testState.currentFraction = frac;

    testState.currentProgress +=
      (testState.targetProgress - testState.currentProgress) * 0.25;
    const prog = Math.max(0, Math.min(1, testState.currentProgress));

    if (arcActive) {
      arcActive.style.strokeDashoffset = (1000 - frac * 1000).toFixed(2);
      arcActive.style.opacity = frac > 0.001 ? "1" : "0";
    }
    if (arcProgress) {
      arcProgress.style.strokeDashoffset = (1000 - prog * 1000).toFixed(2);
    }
    if (needleGroup) {
      const deg = -135 + frac * 270;
      needleGroup.setAttribute(
        "transform",
        `rotate(${deg.toFixed(2)} 220 190)`
      );
    }

    // Illuminate scale ticks up to current needle fraction
    for (let i = 0; i < testState.tickElements.length; i++) {
      const t = testState.tickElements[i];
      const lit = frac > 0.002 && t.frac <= frac + 0.001;
      t.line.classList.toggle("is-lit", lit);
      if (t.labelEl) {
        t.labelEl.classList.toggle("is-lit", lit);
      }
    }

    requestAnimationFrame(renderUI);
  }

  renderUI();
}

function numberToText(value) {
  if (!value && value !== 0) return "--";
  value = Number(value);
  if (isNaN(value) || value <= 0) return "0.00";
  if (value < 10) return value.toFixed(2);
  if (value < 100) return value.toFixed(1);
  return value.toFixed(0);
}
