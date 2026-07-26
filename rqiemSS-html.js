// rqiemSS — Módulo de UI/reporte
// buildHTML() arma el HTML del resultado. buildLangScript() vive en rqiemSS-i18n.js (única fuente).

function buildHTML(findings, netEntries, cheatAppFindings, knownCheatFindings, ipsFindings, ipsMeta, _unused, ghostAppFindings, proxyLoginFindings, filename) {
  let allDomains = new Set(netEntries.map(e => e.domain || ""))

  let allTimestamps = netEntries.map(e => e.timeStamp).filter(Boolean).sort()
  let firstTs = allTimestamps.length ? new Date(allTimestamps[0]) : null
  let lastTs  = allTimestamps.length ? new Date(allTimestamps[allTimestamps.length - 1]) : null

  function fmtDt(d) {
    if (!d) return "?"
    return d.toLocaleString("pt-BR", {
      day:"2-digit", month:"2-digit", year:"numeric",
      hour:"2-digit", minute:"2-digit"
    })
  }

  let uptimeStr = "?"
  let uptimeWarning = false
  if (firstTs && lastTs) {
    let diffMs  = lastTs - firstTs
    let diffMin = Math.floor(diffMs / 60000)
    let diffH   = Math.floor(diffMin / 60)
    let diffD   = Math.floor(diffH / 24)
    let remH    = diffH % 24
    let remMin  = diffMin % 60
    if (diffD > 0)      uptimeStr = `${diffD}d ${remH}h ${remMin}min`
    else if (diffH > 0) uptimeStr = `${diffH}h ${remMin}min`
    else                uptimeStr = `${diffMin} minutos`
    if (diffMin < 20)   uptimeWarning = true
  }

  let startStr = fmtDt(firstTs)
  let endStr   = fmtDt(lastTs)

  let staleWarning = false
  let staleMinutes = 0
  let staleStr = ""
  if (lastTs) {
    let now = new Date()
    let diffFromNow = Math.floor((now - lastTs) / 60000)
    staleMinutes = diffFromNow
    if (diffFromNow > 15) {
      staleWarning = true
      if (diffFromNow >= 1440) {
        let d = Math.floor(diffFromNow / 1440)
        let h = Math.floor((diffFromNow % 1440) / 60)
        staleStr = `${d}d ${h}h atrás`
      } else if (diffFromNow >= 60) {
        let h = Math.floor(diffFromNow / 60)
        let m = diffFromNow % 60
        staleStr = `${h}h ${m}min atrás`
      } else {
        staleStr = `${diffFromNow} minutos atrás`
      }
    }
  }

  let appStoreEntries = netEntries
    .filter(e => e.bundleID === "com.apple.AppStore" && e.timeStamp)
    .sort((a, b) => b.timeStamp.localeCompare(a.timeStamp))
  let appStoreLastTs = appStoreEntries.length ? new Date(appStoreEntries[0].timeStamp) : null
  let appStoreStr = appStoreLastTs ? fmtDt(appStoreLastTs) : null

  const FF_BUNDLES = ["com.dts.freefiremax", "com.dts.freefireth"]

  const FF_FB_LOGIN_DOMAIN = "m.facebook.com"

  const FF_SECONDARY_DOMAINS = {
    "twitter.com":           "Login Twitter/X",
    "api.twitter.com":       "Login Twitter/X",
    "oauth2.googleapis.com": "Login Gmail",
    "accounts.google.com":   "Login Gmail",
    "apis.google.com":       "Login Gmail",
    "api.vk.com":            "Login VK",
    "login.vk.com":          "Login VK",
  }

  let ffAll = netEntries
    .filter(e => FF_BUNDLES.includes(e.bundleID) && e.timeStamp)
    .sort((a, b) => a.timeStamp.localeCompare(b.timeStamp))

  let ffSessionGroups = []
  let _cur = []
  for (let e of ffAll) {
    if (_cur.length === 0) { _cur.push(e); continue }
    let gap = new Date(e.timeStamp) - new Date(_cur[_cur.length-1].timeStamp)
    if (gap > 2 * 60 * 1000) { ffSessionGroups.push(_cur); _cur = [e] }
    else _cur.push(e)
  }
  if (_cur.length > 0) ffSessionGroups.push(_cur)

  function resolveSession(group) {
    let domains = new Set(group.map(e => e.domain))
    let anchor  = group[group.length - 1]

    if (domains.has(FF_FB_LOGIN_DOMAIN)) {
      return { ts: anchor.timeStamp, loginType: "Login Facebook", bundleID: anchor.bundleID }
    }

    for (let d of domains) {
      if (FF_SECONDARY_DOMAINS[d]) {
        return { ts: anchor.timeStamp, loginType: FF_SECONDARY_DOMAINS[d], bundleID: anchor.bundleID }
      }
    }

    return null
  }

  let ffSessions = ffSessionGroups
    .map(resolveSession)
    .filter(Boolean)
    .sort((a, b) => b.ts.localeCompare(a.ts))
    .slice(0, 3)
    .map(s => ({ ...s, ts: fmtDt(new Date(s.ts)) }))

  let ffStr     = ffSessions.length > 0 ? ffSessions[0].ts : null
  let ffEntries = ffAll
  let ffVersion = ffAll.length > 0
    ? (ffAll[0].bundleID === "com.dts.freefiremax" ? "Free Fire MAX" : "Free Fire")
    : null

  let highCount = findings.filter(f => f.severity === "HIGH").length
  let medCount  = findings.filter(f => f.severity === "MEDIUM").length
  proxyLoginFindings = proxyLoginFindings || []
  let criticalCount = cheatAppFindings.length + knownCheatFindings.length + proxyLoginFindings.length

  let criticalCards = ""

  for (let p of proxyLoginFindings) {
    let bundleList = p.bundles.map(b => `<span class="bundle" style="color:#ff4400">${b}</span>`).join(" ")
    criticalCards += `
    <div class="card critical" style="border-left-color:#ff4400;background:#140800;border-color:#3a1500;">
      <div class="card-header">
        <span class="badge critical" style="background:#1a0800;color:#ff4400;border-color:#ff440055;">&#128274; PROXY BYPASS LOGIN — CRÍTICO</span>
        <span class="conns">${p.hits} conexões</span>
      </div>
      <div class="card-domain">${p.domain}</div>
      <div class="grid">
        <div class="row"><span class="label">Detecção</span><span class="val reason" style="color:#ff6600;font-weight:bold">Domínio exclusivo do Free Fire chamado por app não autorizado — padrão de proxy interceptando login</span></div>
        <div class="row"><span class="label">App interceptor</span><span class="val">${bundleList}</span></div>
        <div class="row"><span class="label">Esperado de</span><span class="val"><span class="bundle" style="color:#44ff88">com.dts.freefireth</span> <span class="bundle" style="color:#44ff88">com.dts.freefiremax</span></span></div>
      </div>
    </div>`
  }



  let ghostSection = ""
  if (ghostAppFindings && ghostAppFindings.length > 0) {
    let ghostRows = ghostAppFindings.map(g => {
      let domList = g.domains.slice(0,5).map(d => `<span class="ghost-domain">${d}</span>`).join("")
      let more = g.domains.length > 5 ? `<span class="ghost-more">+${g.domains.length - 5} mais</span>` : ""
      return `
      <div class="ghost-row">
        <div class="ghost-row-left">
          <span class="ghost-bundle">${g.bundleID}</span>
          <div class="ghost-domains">${domList}${more}</div>
        </div>
        <div class="ghost-row-right">
          <span class="ghost-hits">${g.hits} hits</span>
          <span class="ghost-label" data-i18n="ghostNotInUsage">⚠ Ausente no app_usage</span>
        </div>
      </div>`
    }).join("")
    ghostSection = `
  <div class="ghost-banner">
    <div class="ghost-header">
      <span class="ghost-icon">👻</span>
      <div class="ghost-title-block">
        <div class="ghost-title" data-i18n="ghostTitle">Apps com domínios suspeitos — ausentes no app_usage</div>
        <div class="ghost-sub" data-i18n="ghostSub">Presente no relatório de rede mas não encontrado nos dados de análise</div>
      </div>
      <span class="ghost-count">${ghostAppFindings.length}</span>
    </div>
    <div class="ghost-rows">${ghostRows}</div>
    <div class="ghost-hint" data-i18n="ghostHint">⚠ App pode ter sido instalado via sideload ou o arquivo app_usage não cobre o período</div>
  </div>`
  }

  for (let k of knownCheatFindings) {
    let bundleList = k.bundles.map(b => `<span class="bundle">${b}</span>`).join(" ")
    let indicatorKind = (k.indicator.includes(".") && !k.indicator.match(/^\d+\.\d+/)) ? "domain" : "ip"
    let indicatorText = indicatorKind === "domain" ? "Domínio" : "IP"
    criticalCards += `
    <div class="card critical">
      <div class="card-header">
        <span class="badge critical" data-badge-type="known-cheat">&#9888; CRÍTICO — CHEAT CONFIRMADO</span>
        <span class="conns">${k.hits} conexões</span>
      </div>
      <div class="card-domain">${k.indicator}</div>
      <div class="grid">
        <div class="row"><span class="label" data-i18n="labelCheat">Cheat</span><span class="val reason" style="color:#ff4444;font-weight:bold">${k.desc}</span></div>
        <div class="row"><span class="label" data-i18n="labelIndicator">Indicador</span><span class="val" data-i18n-indicator="${indicatorKind}">${indicatorText} detectado no relatório de rede</span></div>
        ${bundleList ? `<div class="row"><span class="label">Usado por</span><span class="val">${bundleList}</span></div>` : ""}
      </div>
    </div>`
  }

  for (let f of cheatAppFindings) {
    let suspectDomainSet = new Set(findings.map(f2 => f2.domain))
    let suspectDomains = f.domains.filter(d => suspectDomainSet.has(d))
    let suspectRows = suspectDomains.map(d => {
      let match = findings.find(f2 => f2.domain === d)
      let info = match ? ` &mdash; ${match.isp} (${match.country})` : ""
      return `<div class="domain-row"><span class="domain-badge ${match ? match.severity.toLowerCase() : ""}" data-sev="${match ? match.severity : ""}">${match ? (match.severity === "HIGH" ? "SUSPEITO" : "POSSÍVEL") : ""}</span> ${d}${info}</div>`
    }).join("")
    criticalCards += `
    <div class="card critical">
      <div class="card-header">
        <span class="badge critical">&#9888; CRÍTICO — APP PROXY/CHEAT</span>
        <span class="conns">${f.hits} conexões</span>
      </div>
      <div class="card-domain">${f.bundleID}</div>
      <div class="grid">
        <div class="row"><span class="label">App</span><span class="val reason">${f.desc}</span></div>
        <div class="row">
          <span class="label">IPs suspeitos<br><span class="sub">${suspectDomains.length} de ${f.domains.length} domínios</span></span>
          <span class="val">${suspectRows || '<span class="none">Nenhum IP suspeito detectado</span>'}</span>
        </div>
      </div>
    </div>`
  }

  let displayFindings = findings

  let cards = ""
  if (displayFindings.length === 0) {
    cards = `<div class="ok">&#10003; Nenhum IP VPS / Hosting / Proxy detectado.</div>`
  } else {
    for (let f of displayFindings) {
      let tag = f.tldSuspect ? "DOMÍNIO SUSPEITO" : f.hosting ? "VPS/HOSTING" : f.proxy ? "PROXY/VPN" : "NUVEM"
      let cls = f.tldSuspect ? "tld-flag" : f.severity === "HIGH" ? "high" : "medium"
      let sev = f.tldSuspect ? "&#9888; DOMÍNIO SUSPEITO" : f.severity === "HIGH" ? "SUSPEITO" : "POSSÍVEL"
      let bundleList = f.bundles.map(b => `<span class="bundle">${b}</span>`).join(" ")
      cards += `
      <div class="card ${cls}">
        <div class="card-header">
          <span class="badge ${cls}">${sev}</span>
          <span class="conns">${f.hits} conexões</span>
        </div>
        <div class="card-domain">${f.domain}</div>
        <div class="grid">
          <div class="row"><span class="label">IP</span><span class="val">${f.ip}</span></div>
          <div class="row"><span class="label" data-i18n="labelCountry">País</span><span class="val">${f.country} / ${f.city}</span></div>
          <div class="row"><span class="label" data-i18n="labelProvider">Provedor</span><span class="val isp">${f.isp}</span></div>
          <div class="row"><span class="label">Org</span><span class="val">${f.org}</span></div>
          ${f.reverse ? `<div class="row"><span class="label">rDNS</span><span class="val rdns">${f.reverse}</span></div>` : ""}
          ${f.probe ? `<div class="row"><span class="label">HTTP</span><span class="val">
            ${f.probe.online
              ? `<span class="http-on">&#9679; Online</span>${f.probe.status ? ` &mdash; HTTP ${f.probe.status}` : ""}${f.probe.banner ? ` &mdash; <span class="http-banner">${f.probe.banner}</span>` : ""}`
              : `<span class="http-off">&#9679; Offline / Sem resposta</span>`
            }
          </span></div>` : ""}
          <div class="row"><span class="label" data-i18n="labelReason">Motivo</span><span class="val reason" data-reasons='${JSON.stringify(f.reasons)}'>${f.reasons.join("<br>")}</span></div>
          <div class="row"><span class="label" data-i18n="labelUsedBy">Usado por</span><span class="val">${bundleList}</span></div>
        </div>
      </div>`
    }
  }

  let uptimeBg    = uptimeWarning ? "background:linear-gradient(90deg,#2a1000,#1a0800)" : "background:#0d1b2a"
  let uptimeDotCl = uptimeWarning ? "background:#ff8800;box-shadow:0 0 6px #ff8800" : "background:#4caf50;box-shadow:0 0 6px #4caf50"
  let uptimeWarnBadge = uptimeWarning
    ? `<span style="margin-left:8px;background:#3a1800;color:#ff8800;border:1px solid #ff8800;font-size:9px;padding:2px 7px;border-radius:10px;font-weight:bold" data-i18n="uptimeLess20">&#9888; MENOS DE 20MIN — Relatório pode não cobrir a partida inteira!</span>`
    : ""

  let rootsWarn = ""
  if (ipsMeta && ipsMeta.rootsInstalled > 0) {
    rootsWarn = `
  <div class="roots-banner">
    <div class="roots-icon">🔐</div>
    <div>
      <div class="roots-label" data-i18n="rootsLabel">Certificado Raiz Suspeito</div>
      <div class="roots-detail" data-roots-count="${ipsMeta.rootsInstalled}">${ipsMeta.rootsInstalled} certificado${ipsMeta.rootsInstalled > 1 ? "s" : ""} raiz instalado${ipsMeta.rootsInstalled > 1 ? "s" : ""} (roots_installed: ${ipsMeta.rootsInstalled})</div>
      <div class="roots-hint" data-i18n="rootsHint">Certificados raiz permitem interceptar tráfego HTTPS — padrão de proxy cheat tipo mitmproxy</div>
    </div>
  </div>`
  }

  let ipsSection = ""
  if (ipsFindings && ipsFindings.length > 0) {
    let ipsRows = ipsFindings.map(f => `
      <div class="ips-row ips-row-${f.category || 'warning'}">
        <div class="ips-row-left">
          <div class="ips-row-top">
            <span class="ips-cat-badge ips-cat-${f.category || 'warning'}">${f.category === 'critical' ? '🚨 CRÍTICO' : f.category === 'vpn' ? '🔒 VPN/PROXY' : f.category === 'developer' ? '🛠 DEVELOPER' : '⚠ SUSPEITO'}</span>
          </div>
          <span class="ips-bundle">${f.bundleId}</span>
          <span class="ips-reason" data-reason-key="${encodeURIComponent(f.bundleId)}">${f.reason}</span>
        </div>
        <div class="ips-row-right">
          <span class="ips-version">v${f.version}</span>
          <span class="ips-badge ${f.eventType === 'launches' ? 'launched' : 'installed'}" data-i18n="${f.eventType === 'launches' ? 'ipsLaunched' : 'ipsInstalled'}">${f.eventType === 'launches' ? '▶ Aberto' : '⬇ Instalado'}</span>
        </div>
      </div>`).join("")

    ipsSection = `
  <div class="ips-banner">
    <div class="ips-header">
      <span class="ips-icon">📲</span>
      <div class="ips-header-text">
        <div class="ips-title" data-i18n="ipsTitle">Apps Suspeitos Instalados</div>
        <div class="ips-sub" data-i18n="ipsSub">Detectados no histórico de uso do dispositivo</div>
      </div>
      <span class="ips-count">${ipsFindings.length}</span>
    </div>
    <div class="ips-rows">${ipsRows}</div>
    <div class="ips-hint" data-i18n="ipsHint">⚠ Apps encontrados nos dados de análise do iPhone — indicam presença de ferramentas de cheat/jailbreak/proxy</div>
  </div>`
  }

  let staleBanner = staleWarning ? `
  <div class="stale-banner">
    <div class="stale-left">&#128337;</div>
    <div>
      <div class="stale-label">Arquivo possivelmente antigo</div>
      <div class="stale-time">Último registro: <strong>${staleStr}</strong></div>
      <div class="stale-hint">Suspeita: arquivo gerado fora do período da partida para esconder atividade.</div>
    </div>
  </div>` : ""

  function loginColor(type) {
    if (type.includes("Facebook"))  return "#1877f2"
    if (type.includes("Twitter") || type.includes("X")) return "#1da1f2"
    if (type.includes("Gmail"))     return "#ea4335"
    if (type.includes("VK"))        return "#4a76a8"
    return "#556"
  }

  let ffSessionRows = ffSessions.map((s, i) => {
    let col = loginColor(s.loginType)
    let label = i === 0 ? "Última abertura" : i === 1 ? "2ª abertura" : "3ª abertura"
    return `
      <div class="ff-session-row">
        <div class="ff-session-left">
          <span class="ff-session-num">${label}</span>
          <span class="ff-session-ts">${s.ts}</span>
        </div>
        <span class="ff-login-badge" style="background:${col}22;color:${col};border:1px solid ${col}44">${s.loginType}</span>
      </div>`
  }).join("")

  let ffBanner = ffStr ? `
  <div class="ff-banner">
    <div class="ff-left">&#128293;</div>
    <div class="ff-info">
      <div class="ff-label">${ffVersion || "Free Fire"} — Sessões no período</div>
      ${ffSessionRows}
      <div class="ff-sessions">${ffEntries.length} inicializações registradas no período</div>
      <div class="ff-hint">Se a última abertura foi após a partida &rarr; aplique o W.O!</div>
    </div>
  </div>` : ""

  let appStoreBanner = appStoreStr ? `
  <div class="appstore-banner">
    <div class="appstore-left">&#128722;</div>
    <div>
      <div class="appstore-label">App Store aberta</div>
      <div class="appstore-time">${appStoreStr}</div>
      <div class="appstore-hint">Se foi após a partida &rarr; aplique o W.O!</div>
    </div>
  </div>` : ""

  let rawHtml = `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta charset="utf-8">
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:#0a0a0f; color:#e0e0e0; font-family:-apple-system,ui-monospace,monospace; font-size:13px; }

  /* HERO */
  .hero {
    background: linear-gradient(160deg, #0d1b2a 0%, #0a0a12 70%);
    border-bottom: 1px solid #1a2a3a;
    padding: 28px 16px 20px;
    position: relative; overflow: hidden;
    text-align: center;
  }
  .hero::after {
    content:""; position:absolute; top:-60px; left:50%; transform:translateX(-50%);
    width:220px; height:220px;
    background:radial-gradient(circle, #00e5ff0d 0%, transparent 70%);
    border-radius:50%; pointer-events:none;
  }
  .hero-eyebrow {
    font-size:9px; letter-spacing:3px; color:#00e5ff55;
    text-transform:uppercase; margin-bottom:8px;
  }
  .hero-name {
    font-size:30px; font-weight:700; color:#fff;
    letter-spacing:-0.5px; margin-bottom:5px;
  }
  .hero-credits {
    font-size:11px; color:#3a5a72; letter-spacing:2.5px;
    margin-bottom:18px; font-weight:500;
  }
  .hero-credits .credit-name {
    color:#557a94;
    transition: color 0.2s;
  }
  .hero-name span { color:#00e5ff; }
  .hero-file {
    font-size:10px; color:#556; word-break:break-all;
    padding:7px 10px; background:#0d1520;
    border-radius:7px; border-left:3px solid #00e5ff33;
    margin-bottom:14px; line-height:1.5;
    text-align:left;
  }
  .hero-file strong { color:#00e5ff99; }
  .hero-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
  .hg-card {
    background:#0d1520; border-radius:8px;
    padding:9px 12px; border:1px solid #1a2a3a;
  }
  .hg-label { font-size:9px; color:#446; letter-spacing:1px; text-transform:uppercase; margin-bottom:3px; }
  .hg-val        { font-size:12px; color:#ccd; }
  .hg-val.cyan   { color:#00e5ff; font-weight:bold; font-size:14px; }
  .hg-val.warn   { color:#ff8800; font-weight:bold; font-size:13px; }
  .hg-card-warn  { background:#1a0a00 !important; border-color:#ff880055 !important; }
  .hg-card-full  { grid-column: 1 / -1; }

  /* LANGUAGE SELECTOR */
  .lang-bar {
    display:flex; justify-content:center; gap:6px; margin-bottom:14px;
  }
  .lang-btn {
    background:#0d1520; border:1px solid #1a2a3a; border-radius:20px;
    color:#556; font-size:10px; letter-spacing:1px; padding:4px 10px;
    cursor:pointer; font-family:inherit; transition:all 0.2s;
    text-transform:uppercase; font-weight:600;
  }
  .lang-btn:hover { border-color:#00e5ff55; color:#00e5ffaa; }
  .lang-btn.active { background:#001a22; border-color:#00e5ff; color:#00e5ff; }

  /* UPTIME BAR */
  .uptime-bar {
    border-bottom:1px solid #1a2a3a;
    padding:10px 16px;
    display:flex; align-items:center; gap:8px; flex-wrap:wrap;
  }
  .uptime-dot {
    width:8px; height:8px; border-radius:50%; flex-shrink:0;
    animation:pulse 2s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
  .uptime-text { font-size:11px; color:#889; }
  .uptime-text strong { color:#fff; }

  /* CONTENT */
  .content { padding:16px; }

  /* APP STORE BANNER */
  .appstore-banner {
    display:flex; align-items:center; gap:14px;
    background:linear-gradient(135deg,#1c1800,#241f00);
    border:1px solid #6a5a00; border-radius:12px;
    padding:14px 16px; margin-bottom:18px;
  }
  .appstore-left { font-size:32px; flex-shrink:0; }
  .appstore-label { font-size:9px; color:#aa9900; letter-spacing:2px; text-transform:uppercase; font-weight:bold; }
  .appstore-time  { font-size:18px; font-weight:bold; color:#ffe500; margin:3px 0; }
  .appstore-hint  { font-size:10px; color:#8a7700; }

  /* SUMMARY */
  .summary { display:flex; gap:8px; margin-bottom:20px; }
  .stat {
    flex:1; background:#0d1520; border-radius:10px;
    padding:12px 6px; text-align:center; border:1px solid #1a2a3a;
  }
  .stat .num { font-size:28px; font-weight:bold; line-height:1; }
  .stat .lbl { font-size:9px; color:#446; margin-top:4px; letter-spacing:1px; text-transform:uppercase; }

  /* SECTION HEADERS */
  .section-header {
    display:flex; align-items:center; gap:10px;
    margin-bottom:14px; margin-top:6px;
  }
  .section-header .sh-icon {
    width:32px; height:32px; border-radius:8px;
    display:flex; align-items:center; justify-content:center;
    font-size:16px; flex-shrink:0;
  }
  .section-header .sh-text { flex:1; }
  .section-header .sh-title {
    font-size:12px; font-weight:bold; letter-spacing:0.5px; text-transform:uppercase;
  }
  .section-header .sh-sub { font-size:10px; color:#446; margin-top:1px; }
  .section-header .sh-count {
    font-size:11px; font-weight:bold;
    padding:3px 10px; border-radius:20px;
  }
  .sh-critical .sh-icon { background:#2a0035; }
  .sh-critical .sh-title { color:#ff00cc; }
  .sh-critical .sh-count { background:#2a0035; color:#ff00cc; border:1px solid #ff00cc44; }
  .sh-high .sh-icon { background:#2a0808; }
  .sh-high .sh-title { color:#ff5555; }
  .sh-high .sh-count { background:#2a0808; color:#ff5555; border:1px solid #ff444444; }
  .sh-medium .sh-icon { background:#2a2000; }
  .sh-medium .sh-title { color:#ffbb00; }
  .sh-medium .sh-count { background:#2a2000; color:#ffbb00; border:1px solid #ffbb0044; }
  .divider { height:1px; background:#1a2a3a; margin:20px 0; }

  /* CARDS */
  .card {
    background:#0d1520; border-radius:12px;
    margin-bottom:12px; overflow:hidden;
    border:1px solid #1a2a3a; border-left:4px solid #333;
  }
  .card.critical { border-left-color:#ff00cc; background:#110016; border-color:#2a0035; }
  .card.tld-flag { border-left-color:#ff6600; background:#120a00; border-color:#3a1a00; }
  .badge.tld-flag{ background:#2a1000; color:#ff6600; border:1px solid #ff660055; }
  .card.high     { border-left-color:#ff4444; border-color:#2a0808; }
  .card.medium   { border-left-color:#ffbb00; border-color:#2a2000; }
  .card-header {
    display:flex; justify-content:space-between; align-items:center;
    padding:10px 14px 6px;
  }
  .badge {
    font-size:9px; font-weight:bold;
    padding:3px 9px; border-radius:20px; letter-spacing:0.5px;
  }
  .badge.critical { background:#2a0035; color:#ff00cc; border:1px solid #ff00cc55; }
  .badge.high     { background:#2a0808; color:#ff5555; border:1px solid #ff444455; }
  .badge.medium   { background:#2a2000; color:#ffbb00; border:1px solid #ffbb0055; }
  .conns { font-size:10px; color:#446; }
  .card-domain {
    font-size:13px; font-weight:bold; color:#fff;
    padding:0 14px 10px; word-break:break-all;
  }
  .grid { padding:0 14px 12px; }
  .row {
    display:flex; gap:8px; padding:5px 0;
    border-top:1px solid #1a2a3a; align-items:flex-start;
  }
  .label { color:#446; min-width:65px; font-size:10px; padding-top:1px; flex-shrink:0; line-height:1.4; }
  .sub   { color:#334; font-size:9px; }
  .val   { color:#bbc; word-break:break-all; flex:1; font-size:11px; line-height:1.5; }
  .isp    { color:#ffbb00; }
  .reason { color:#ff8a80; }
  .rdns        { color:#ce93d8; font-style:italic; }

  .ghost-banner {
    background:linear-gradient(135deg,#0a0a1a,#080814);
    border:1px solid #3344aa55; border-radius:12px;
    padding:14px; margin-bottom:12px;
  }
  .ghost-header { display:flex; align-items:flex-start; gap:10px; margin-bottom:12px; }
  .ghost-icon   { font-size:20px; flex-shrink:0; }
  .ghost-title-block { flex:1; }
  .ghost-title  { font-size:12px; font-weight:bold; color:#8899ff; letter-spacing:0.5px; }
  .ghost-sub    { font-size:10px; color:#334466; margin-top:2px; }
  .ghost-count  { background:#0a0a2a; color:#6677ee; font-size:11px; font-weight:bold; padding:2px 8px; border-radius:10px; border:1px solid #3344aa55; align-self:flex-start; }
  .ghost-rows   { display:flex; flex-direction:column; gap:8px; margin-bottom:10px; }
  .ghost-row    { display:flex; justify-content:space-between; align-items:flex-start; gap:8px; background:#0a0a20; border:1px solid #222244; border-radius:8px; padding:10px; }
  .ghost-row-left  { flex:1; min-width:0; display:flex; flex-direction:column; gap:4px; }
  .ghost-row-right { display:flex; flex-direction:column; align-items:flex-end; gap:4px; flex-shrink:0; }
  .ghost-bundle { font-size:11px; font-weight:bold; color:#aabbff; word-break:break-all; }
  .ghost-domains { display:flex; flex-wrap:wrap; gap:4px; }
  .ghost-domain { font-size:9px; background:#0d0d30; color:#6677cc; border:1px solid #223; padding:1px 6px; border-radius:8px; }
  .ghost-more   { font-size:9px; color:#445; }
  .ghost-hits   { font-size:11px; font-weight:bold; color:#6677ee; }
  .ghost-label  { font-size:9px; color:#334; background:#0a0a1a; padding:2px 6px; border-radius:6px; border:1px solid #223; }
  .ghost-hint   { font-size:9px; color:#334466; border-top:1px solid #1a1a33; padding-top:8px; }

  .roots-banner {
    display:flex; align-items:flex-start; gap:12px;
    background:linear-gradient(135deg,#1a0a00,#120800);
    border:1px solid #ff880066; border-radius:12px;
    padding:14px; margin-bottom:12px;
  }
  .roots-icon   { font-size:22px; flex-shrink:0; }
  .roots-label  { font-size:12px; font-weight:bold; color:#ff8800; letter-spacing:0.5px; margin-bottom:3px; }
  .roots-detail { font-size:13px; color:#ffaa44; font-weight:bold; margin-bottom:4px; }
  .roots-hint   { font-size:10px; color:#885500; line-height:1.4; }

  .ips-banner {
    background:linear-gradient(135deg,#1a0a1a,#120010);
    border:1px solid #440044; border-radius:12px;
    padding:14px; margin-bottom:12px;
  }
  .ips-header {
    display:flex; align-items:center; gap:10px; margin-bottom:12px;
  }
  .ips-icon { font-size:22px; flex-shrink:0; }
  .ips-header-text { flex:1; }
  .ips-title { font-size:12px; font-weight:bold; color:#dd44ff; letter-spacing:0.5px; }
  .ips-sub   { font-size:10px; color:#664466; margin-top:1px; }
  .ips-count {
    background:#2a0035; color:#dd44ff; border:1px solid #dd44ff55;
    font-size:14px; font-weight:bold; padding:4px 10px; border-radius:20px;
  }
  .ips-rows  { display:flex; flex-direction:column; gap:8px; margin-bottom:10px; }
  .ips-row { }
  .ips-row-critical { background:#1a0010 !important; border-color:#ff004455 !important; }
  .ips-row-vpn      { background:#0a0a1a !important; border-color:#4455ff44 !important; }
  .ips-row-developer{ background:#0a1a0a !important; border-color:#44aa4444 !important; }
  .ips-row-warning  { background:#1a0a00 !important; border-color:#ff880033 !important; }
  .ips-row-top { margin-bottom:4px; }
  .ips-cat-badge {
    display:inline-block; font-size:9px; font-weight:bold;
    padding:2px 8px; border-radius:10px; letter-spacing:0.5px;
  }
  .ips-cat-critical  { background:#2a0015; color:#ff3388; border:1px solid #ff338855; }
  .ips-cat-vpn       { background:#0a0a2a; color:#6699ff; border:1px solid #6699ff55; }
  .ips-cat-developer { background:#0a2a0a; color:#44cc44; border:1px solid #44cc4455; }
  .ips-cat-warning   { background:#2a1000; color:#ff8800; border:1px solid #ff880055; }
  .ips-row {
    display:flex; justify-content:space-between; align-items:flex-start; gap:8px;
    background:#1a001a; border:1px solid #330033; border-radius:8px; padding:8px 10px;
  }
  .ips-row-left  { display:flex; flex-direction:column; gap:2px; flex:1; min-width:0; }
  .ips-row-right { display:flex; flex-direction:column; align-items:flex-end; gap:4px; flex-shrink:0; }
  .ips-bundle { font-size:11px; font-weight:bold; color:#cc88ff; word-break:break-all; }
  .ips-reason { font-size:10px; color:#886688; line-height:1.4; }
  .ips-version { font-size:9px; color:#554455; }
  .ips-badge {
    font-size:9px; font-weight:bold; padding:2px 7px; border-radius:10px;
  }
  .ips-badge.launched  { background:#1a0035; color:#aa44ff; border:1px solid #aa44ff55; }
  .ips-badge.installed { background:#002200; color:#44aa44; border:1px solid #44aa4455; }
  .ips-hint { font-size:9px; color:#553355; line-height:1.4; }

  .stale-banner {
    display:flex; align-items:flex-start; gap:12px;
    background:linear-gradient(135deg,#1a1200,#221800);
    border:1px solid #8a6000; border-radius:12px;
    padding:12px 16px; margin-bottom:14px;
  }
  .stale-left  { font-size:26px; flex-shrink:0; margin-top:2px; }
  .stale-label { font-size:9px; color:#aa7700; letter-spacing:2px; text-transform:uppercase; font-weight:bold; }
  .stale-time  { font-size:14px; color:#ffaa00; margin:3px 0; }
  .stale-time strong { color:#ffd000; }
  .stale-hint  { font-size:10px; color:#7a5500; line-height:1.4; }
  .ff-banner {
    display:flex; align-items:flex-start; gap:14px;
    background:linear-gradient(135deg,#0a1a00,#0f2200);
    border:1px solid #2a5500; border-radius:12px;
    padding:14px 16px; margin-bottom:14px;
  }
  .ff-left  { font-size:30px; flex-shrink:0; margin-top:2px; }
  .ff-info  { flex:1; }
  .ff-label { font-size:9px; color:#5a9900; letter-spacing:2px; text-transform:uppercase; font-weight:bold; margin-bottom:6px; }
  .ff-row   { display:flex; align-items:baseline; gap:8px; margin-bottom:2px; }
  .ff-tag   { font-size:9px; color:#446; min-width:100px; text-transform:uppercase; letter-spacing:0.5px; }
  .ff-time  { font-size:16px; font-weight:bold; color:#88ff00; }
  .ff-time-sub { font-size:13px; color:#5a9900; }
  .ff-sessions { font-size:10px; color:#3a6600; margin-top:6px; }
  .ff-session-row {
    display:flex; align-items:center; justify-content:space-between;
    gap:8px; padding:5px 0; border-top:1px solid #1a2a10;
  }
  .ff-session-row:first-of-type { border-top:none; }
  .ff-session-left { display:flex; flex-direction:column; gap:1px; }
  .ff-session-num  { font-size:9px; color:#446; text-transform:uppercase; letter-spacing:0.5px; }
  .ff-session-ts   { font-size:13px; font-weight:bold; color:#88ff00; }
  .ff-login-badge  {
    font-size:9px; font-weight:bold; padding:3px 8px;
    border-radius:10px; white-space:nowrap; flex-shrink:0;
  }
  .ff-hint  { font-size:10px; color:#4a7700; margin-top:3px; }

  /* PRE-LOGIN BANNER */
  .prelim-banner {
    background:linear-gradient(135deg,#1a0000,#240808);
    border:1px solid #8a0000; border-radius:12px;
    padding:14px 16px; margin-bottom:14px;
  }
  .prelim-header {
    display:flex; align-items:center; gap:10px; margin-bottom:12px;
  }
  .prelim-icon  { font-size:22px; flex-shrink:0; }
  .prelim-title { font-size:12px; font-weight:bold; color:#ff4444; letter-spacing:0.3px; }
  .prelim-sub   { font-size:10px; color:#884444; margin-top:2px; }
  .prelim-count {
    margin-left:auto; background:#3a0000; color:#ff4444;
    border:1px solid #ff444444; font-size:14px; font-weight:bold;
    padding:4px 12px; border-radius:20px; flex-shrink:0;
  }
  .prelim-rows  { display:flex; flex-direction:column; gap:6px; margin-bottom:10px; }
  .pre-row {
    background:#0d0505; border-radius:8px;
    padding:8px 10px; border-left:3px solid #8a0000;
  }
  .pre-row-top    { display:flex; align-items:center; gap:6px; margin-bottom:3px; flex-wrap:wrap; }
  .pre-domain     { font-size:12px; color:#ddc; word-break:break-all; flex:1; }
  .pre-hits       { font-size:10px; color:#664444; flex-shrink:0; }
  .pre-row-detail { font-size:10px; color:#664444; line-height:1.4; }
  .prelim-hint {
    font-size:10px; color:#884444; padding-top:10px;
    border-top:1px solid #2a0808; line-height:1.5;
  }
  .http-on     { color:#4caf50; font-weight:bold; }
  .http-off    { color:#555; font-weight:bold; }
  .http-banner { color:#ff00cc; font-weight:bold; text-transform:uppercase; font-size:10px; }
  .none   { color:#334; }
  .bundle {
    display:inline-block; background:#0d1520; border-radius:5px;
    padding:2px 6px; font-size:9px; color:#556; margin:1px;
    word-break:break-all; border:1px solid #1a2a3a;
  }
  .domain-row { padding:3px 0; font-size:11px; color:#bbc; word-break:break-all; }
  .domain-badge {
    display:inline-block; font-size:9px; font-weight:bold;
    padding:1px 5px; border-radius:4px; margin-right:4px; vertical-align:middle;
  }
  .domain-badge.high   { background:#2a0808; color:#ff5555; }
  .domain-badge.medium { background:#2a2000; color:#ffbb00; }
  .ok {
    background:#0a1a10; border:1px solid #1a3020; color:#4caf50;
    padding:20px; border-radius:12px; text-align:center; font-size:14px;
  }
</style>
</head>
<body>

<div class="hero">
  <div class="hero-eyebrow">Scanner iOS</div>
  <div class="hero-name">rqiem<span>SS</span></div>
  <div class="hero-credits">por <span class="credit-name">rqiem</span></div>
  <div class="lang-bar">
    <button class="lang-btn active" id="btn-pt">PT-BR</button>
    <button class="lang-btn" id="btn-en">EN</button>
    <button class="lang-btn" id="btn-es">ES</button>
  </div>
  <div class="hero-file"><strong>Arquivo:</strong> ${filename}</div>
  <div class="hero-grid">
    <div class="hg-card">
      <div class="hg-label">Início</div>
      <div class="hg-val">${startStr}</div>
    </div>
    <div class="hg-card">
      <div class="hg-label">Último registro</div>
      <div class="hg-val">${endStr}</div>
    </div>
    <div class="hg-card">
      <div class="hg-label">Domínios únicos</div>
      <div class="hg-val cyan">${allDomains.size}</div>
    </div>
    <div class="hg-card">
      <div class="hg-label">Total conexões</div>
      <div class="hg-val">${netEntries.length}</div>
    </div>
    ${ipsMeta && ipsMeta.iosVersion ? `<div class="hg-card${ipsMeta.rootsInstalled > 0 ? "" : " hg-card-full"}">
      <div class="hg-label" data-i18n="iosVersionLabel">Versão iOS</div>
      <div class="hg-val cyan">${ipsMeta.iosVersion}</div>
    </div>` : ""}
    ${ipsMeta && ipsMeta.rootsInstalled > 0 ? `<div class="hg-card hg-card-warn">
      <div class="hg-label" data-i18n="rootsCardLabel">⚠ Certificados raiz</div>
      <div class="hg-val warn">${ipsMeta.rootsInstalled} instalado${ipsMeta.rootsInstalled > 1 ? "s" : ""}</div>
    </div>` : ""}
  </div>
</div>

<div class="uptime-bar" style="${uptimeBg}">
  <div class="uptime-dot" style="${uptimeDotCl}"></div>
  <div class="uptime-text">Monitorado há <strong>${uptimeStr}</strong></div>
  ${uptimeWarnBadge}
</div>

<div class="content">

  ${staleBanner}
  ${ffBanner}
  ${appStoreBanner}

  <div class="summary">
    <div class="stat">
      <div class="num" style="color:#ff00cc">${criticalCount}</div>
      <div class="lbl">Crítico</div>
    </div>
    <div class="stat">
      <div class="num" style="color:#ff5555">${highCount}</div>
      <div class="lbl">Suspeito</div>
    </div>
    <div class="stat">
      <div class="num" style="color:#ffbb00">${medCount}</div>
      <div class="lbl">Possível</div>
    </div>
  </div>

  ${criticalCount > 0 ? `
  <div class="section-header sh-critical">
    <div class="sh-icon">&#9888;</div>
    <div class="sh-text">
      <div class="sh-title">Apps Proxy / Cheat Detectados</div>
      <div class="sh-sub">Aplicativos e infraestrutura conhecida de cheats</div>
    </div>
    <div class="sh-count">${criticalCount}</div>
  </div>
  ${criticalCards}
  <div class="divider"></div>` : ""}

  ${highCount > 0 ? `
  ${rootsWarn}
  ${ipsSection}
  ${ghostSection}
  <div class="section-header sh-high">
    <div class="sh-icon">&#128683;</div>
    <div class="sh-text">
      <div class="sh-title">IPs Suspeitos</div>
      <div class="sh-sub">VPS / Hosting / Proxy confirmados</div>
    </div>
    <div class="sh-count">${highCount}</div>
  </div>` : ""}

  ${medCount > 0 && highCount > 0 ? "" : highCount === 0 ? `
  <div class="section-header sh-medium">
    <div class="sh-icon">&#128308;</div>
    <div class="sh-text">
      <div class="sh-title">IPs Possíveis</div>
      <div class="sh-sub">Infraestrutura cloud / datacenter</div>
    </div>
    <div class="sh-count">${medCount}</div>
  </div>` : ""}

  ${cards}

  ${findings.length > 0 && highCount > 0 && medCount > 0 ? `
  <div class="divider"></div>
  <div class="section-header sh-medium">
    <div class="sh-icon">&#9888;</div>
    <div class="sh-text">
      <div class="sh-title">IPs Possíveis</div>
      <div class="sh-sub">Infraestrutura cloud / datacenter</div>
    </div>
    <div class="sh-count">${medCount}</div>
  </div>` : ""}

</div>
</body>
</html>`
  return rawHtml
}


module.exports = { buildHTML }
