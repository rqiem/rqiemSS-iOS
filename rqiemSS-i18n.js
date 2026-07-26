// rqiemSS — Módulo de idioma
// Única fuente de verdad para SPEECH (Siri) y TRANSLATIONS (WebView).
// buildLangScriptBody() = el JS crudo (traducciones + setLang + binder de botones).
// buildLangScript() = esa misma base envuelta en <script> para el HTML inicial.
// showResult() usa buildLangScriptBody() directo con evaluateJavaScript — antes tenía una copia pegada aparte.

const DEVICE_LANG = (Device.language() || "pt").toLowerCase().substring(0, 9)
const SPEECH = {
  pt: {
    start:    "Analisando, aguarde o rqiemSS terminar",
    half:     "Scanner em cinquenta por cento. Aguarde mais um pouco.",
    probe:    "Scanner em noventa por cento. Aguarde mais um pouco.",
    done:     "rqiemSS finalizado. Analise os resultados com cuidado.",
  },
  en: {
    start:    "Analyzing, please wait for rqiemSS to finish.",
    half:     "Scanner at fifty percent. Please wait a little longer.",
    probe:    "Scanner at ninety percent. Almost done.",
    done:     "rqiemSS finished. Analyze the results carefully.",
  },
  es: {
    start:    "Analizando, espera que reqienSS termine.",
    half:     "Escáner al cincuenta por ciento. Espera un poco más.",
    probe:    "Escáner al noventa por ciento. Ya casi termina.",
    done:     "rqiemSS finalizado. Analiza los resultados con cuidado.",
  },
}
const S = SPEECH[DEVICE_LANG] || SPEECH["pt"]

function buildLangScriptBody() {
  return `
var TRANSLATIONS = {
  pt: {
    eyebrow: "Scanner iOS",
    credits: "por Rqiem ·",
    fileLabel: "Arquivo:",
    start: "Início",
    lastRecord: "Último registro",
    uniqueDomains: "Domínios únicos",
    totalConns: "Total conexões",
    monitoredFor: "Monitorado há",
    criticalLabel: "Crítico",
    suspectLabel: "Suspeito",
    possibleLabel: "Possível",
    appProxyTitle: "Apps Proxy / Cheat Detectados",
    appProxySub: "Aplicativos conhecidos de interceptação de tráfego",
    suspectIPsTitle: "IPs Suspeitos",
    suspectIPsSub: "VPS / Hosting / Proxy confirmados",
    possibleIPsTitle: "IPs Possíveis",
    possibleIPsSub: "Infraestrutura cloud / datacenter",
    labelIP: "IP",
    labelCountry: "País",
    labelProvider: "Provedor",
    labelOrg: "Org",
    labelRDNS: "rDNS",
    labelHTTP: "HTTP",
    labelReason: "Motivo",
    labelUsedBy: "Usado por",
    labelApp: "App",
    labelSuspectIPs: "IPs suspeitos",
    noneDetected: "Nenhum IP suspeito detectado",
    noVPS: "✓ Nenhum IP VPS / Hosting / Proxy detectado.",
    staleLabel: "Arquivo possivelmente antigo",
    staleHint: "Suspeita: arquivo gerado fora do período da partida para esconder atividade.",
    ffLabel: "Sessões no período",
    ffLastOpen: "Última abertura",
    ffFirstOpen: "Primeira abertura",
    ffSessions: "inicializações registradas no período",
    ffHint: "Se a última abertura foi após a partida → aplique o W.O!",
    appStoreLabel: "App Store aberta",
    appStoreHint: "Se foi após a partida → aplique o W.O!",
    uptimeLess20: "MENOS DE 20MIN — Relatório pode não cobrir a partida inteira!",
    badgeCritical: "⚠ CRÍTICO — APP PROXY/CHEAT",
    badgeSuspect: "SUSPEITO",
    badgePossible: "POSSÍVEL",
    badgeDomainSuspect: "⚠ DOMÍNIO SUSPEITO",
    of: "de",
    online: "● Online",
    offline: "● Offline / Sem resposta",
    lastRecord2: "Último registro:",
    conns: "conexões",
    domains: "domínios",
    labelCheat: "Cheat",
    labelIndicator: "Indicador",
    indicatorDomain: "Domínio detectado no relatório de rede",
    indicatorIP: "IP detectado no relatório de rede",
    iosVersionLabel: "Versão iOS",
    rootsCardLabel: "⚠ Certificados raiz",
    rootsLabel: "Certificado Raiz Suspeito",
    rootsDetail1: "certificado raiz instalado",
    rootsDetailN: "certificados raiz instalados",
    rootsHint: "Certificados raiz permitem interceptar tráfego HTTPS — padrão de proxy cheat tipo mitmproxy",
    ipsTitle: "Apps Suspeitos Instalados",
    ipsSub: "Detectados no histórico de uso do dispositivo",
    ipsHint: "⚠ Apps encontrados nos dados de análise do iPhone — indicam presença de ferramentas de cheat/jailbreak/proxy",
    ipsLaunched: "▶ Aberto",
    ipsInstalled: "⬇ Instalado",
    badgeKnownCheat: "⚠ CRÍTICO — CHEAT CONFIRMADO",
    reasonTLD: function(tld){ return "TLD suspeito detectado: \"" + tld + "\" — padrão comum em cheats/proxies"; },
    reasonWord: function(word){ return "Palavra suspeita no domínio: \"" + word + "\""; },
    reasonVPS: function(isp){ return "VPS/HOSTING — ISP: " + isp; },
    reasonProxy: "PROXY / VPN detectado",
    reasonCF: function(asn){ return "Cloudflare acessado via IP direto — padrão de proxy cheat (" + asn + ")"; },
    reasonASN: function(asn,desc){ return "ASN de cheat proxy conhecido: " + asn + " — " + desc; },
    reasonRDNS: function(rdns){ return "rDNS de servidor: " + rdns; },
    reasonHostinger: function(rdns){ return "Hostinger VPS (padrao cheat proxy BR): " + rdns; },
    reasonNoRDNS: "Sem rDNS (PTR) — tipico de VPS usado como proxy",
    reasonOrg: function(kw){ return "Org/ISP associado a hospedagem/cheat proxy: " + kw; },
  },
  en: {
    eyebrow: "iOS Scanner",
    credits: "by Rqiem ·",
    fileLabel: "File:",
    start: "Start",
    lastRecord: "Last record",
    uniqueDomains: "Unique domains",
    totalConns: "Total connections",
    monitoredFor: "Monitored for",
    criticalLabel: "Critical",
    suspectLabel: "Suspicious",
    possibleLabel: "Possible",
    appProxyTitle: "Proxy / Cheat Apps Detected",
    appProxySub: "Known traffic interception applications",
    suspectIPsTitle: "Suspicious IPs",
    suspectIPsSub: "VPS / Hosting / Confirmed Proxy",
    possibleIPsTitle: "Possible IPs",
    possibleIPsSub: "Cloud / datacenter infrastructure",
    labelIP: "IP",
    labelCountry: "Country",
    labelProvider: "Provider",
    labelOrg: "Org",
    labelRDNS: "rDNS",
    labelHTTP: "HTTP",
    labelReason: "Reason",
    labelUsedBy: "Used by",
    labelApp: "App",
    labelSuspectIPs: "Suspicious IPs",
    noneDetected: "No suspicious IPs detected",
    noVPS: "✓ No VPS / Hosting / Proxy IPs detected.",
    staleLabel: "File possibly outdated",
    staleHint: "Suspicion: file generated outside the match period to hide activity.",
    ffLabel: "Sessions in period",
    ffLastOpen: "Last opened",
    ffFirstOpen: "First opened",
    ffSessions: "startups recorded in the period",
    ffHint: "If last opened after the match → apply W.O!",
    appStoreLabel: "App Store opened",
    appStoreHint: "If it was after the match → apply W.O!",
    uptimeLess20: "LESS THAN 20MIN — Report may not cover the entire match!",
    badgeCritical: "⚠ CRITICAL — PROXY/CHEAT APP",
    badgeSuspect: "SUSPICIOUS",
    badgePossible: "POSSIBLE",
    badgeDomainSuspect: "⚠ SUSPICIOUS DOMAIN",
    of: "of",
    online: "● Online",
    offline: "● Offline / No response",
    lastRecord2: "Last record:",
    conns: "connections",
    domains: "domains",
    labelCheat: "Cheat",
    labelIndicator: "Indicator",
    indicatorDomain: "Domain detected in network report",
    indicatorIP: "IP detected in network report",
    iosVersionLabel: "iOS Version",
    rootsCardLabel: "⚠ Root certificates",
    rootsLabel: "Suspicious Root Certificate",
    rootsDetail1: "root certificate installed",
    rootsDetailN: "root certificates installed",
    rootsHint: "Root certificates allow HTTPS traffic interception — common pattern in mitmproxy-type cheat tools",
    ipsTitle: "Suspicious Apps Installed",
    ipsSub: "Detected in device usage history",
    ipsHint: "⚠ Apps found in iPhone analytics data — indicate presence of cheat/jailbreak/proxy tools",
    ipsLaunched: "▶ Opened",
    ipsInstalled: "⬇ Installed",
    badgeKnownCheat: "⚠ CRITICAL — CONFIRMED CHEAT",
    reasonTLD: function(tld){ return "Suspicious TLD detected: \"" + tld + "\" — common pattern in cheats/proxies"; },
    reasonWord: function(word){ return "Suspicious word in domain: \"" + word + "\""; },
    reasonVPS: function(isp){ return "VPS/HOSTING — ISP: " + isp; },
    reasonProxy: "PROXY / VPN detected",
    reasonCF: function(asn){ return "Cloudflare accessed via direct IP — cheat proxy pattern (" + asn + ")"; },
    reasonASN: function(asn,desc){ return "Known cheat proxy ASN: " + asn + " — " + desc; },
    reasonRDNS: function(rdns){ return "Server rDNS: " + rdns; },
    reasonHostinger: function(rdns){ return "Hostinger VPS (known BR cheat proxy pattern): " + rdns; },
    reasonNoRDNS: "No rDNS (PTR) — typical of VPS used as proxy",
    reasonOrg: function(kw){ return "Org/ISP associated with hosting/cheat proxy: " + kw; },
  },
  es: {
    eyebrow: "Scanner iOS",
    credits: "por Rqiem ·",
    fileLabel: "Archivo:",
    start: "Inicio",
    lastRecord: "Último registro",
    uniqueDomains: "Dominios únicos",
    totalConns: "Total conexiones",
    monitoredFor: "Monitoreado hace",
    criticalLabel: "Crítico",
    suspectLabel: "Sospechoso",
    possibleLabel: "Posible",
    appProxyTitle: "Apps Proxy / Cheat Detectadas",
    appProxySub: "Aplicaciones conocidas de interceptación de tráfico",
    suspectIPsTitle: "IPs Sospechosas",
    suspectIPsSub: "VPS / Hosting / Proxy confirmados",
    possibleIPsTitle: "IPs Posibles",
    possibleIPsSub: "Infraestructura cloud / datacenter",
    labelIP: "IP",
    labelCountry: "País",
    labelProvider: "Proveedor",
    labelOrg: "Org",
    labelRDNS: "rDNS",
    labelHTTP: "HTTP",
    labelReason: "Motivo",
    labelUsedBy: "Usado por",
    labelApp: "App",
    labelSuspectIPs: "IPs sospechosas",
    noneDetected: "Ninguna IP sospechosa detectada",
    noVPS: "✓ Ninguna IP VPS / Hosting / Proxy detectada.",
    staleLabel: "Archivo posiblemente antiguo",
    staleHint: "Sospecha: archivo generado fuera del período del partido para ocultar actividad.",
    ffLabel: "Sesiones en el período",
    ffLastOpen: "Última apertura",
    ffFirstOpen: "Primera apertura",
    ffSessions: "inicializaciones registradas en el período",
    ffHint: "Si la última apertura fue después del partido → ¡aplica el W.O!",
    appStoreLabel: "App Store abierta",
    appStoreHint: "Si fue después del partido → ¡aplica el W.O!",
    uptimeLess20: "MENOS DE 20MIN — ¡El informe puede no cubrir toda la partida!",
    badgeCritical: "⚠ CRÍTICO — APP PROXY/CHEAT",
    badgeSuspect: "SOSPECHOSO",
    badgePossible: "POSIBLE",
    badgeDomainSuspect: "⚠ DOMINIO SOSPECHOSO",
    of: "de",
    online: "● En línea",
    offline: "● Sin conexión / Sin respuesta",
    lastRecord2: "Último registro:",
    conns: "conexiones",
    domains: "dominios",
    labelCheat: "Cheat",
    labelIndicator: "Indicador",
    indicatorDomain: "Dominio detectado en el informe de red",
    indicatorIP: "IP detectada en el informe de red",
    iosVersionLabel: "Versión iOS",
    rootsCardLabel: "⚠ Certificados raíz",
    rootsLabel: "Certificado Raíz Sospechoso",
    rootsDetail1: "certificado raíz instalado",
    rootsDetailN: "certificados raíz instalados",
    rootsHint: "Los certificados raíz permiten interceptar tráfico HTTPS — patrón común en cheats tipo mitmproxy",
    ipsTitle: "Apps Sospechosas Instaladas",
    ipsSub: "Detectadas en el historial de uso del dispositivo",
    ipsHint: "⚠ Apps encontradas en los datos de análisis del iPhone — indican presencia de herramientas de cheat/jailbreak/proxy",
    ipsLaunched: "▶ Abierta",
    ipsInstalled: "⬇ Instalada",
    badgeKnownCheat: "⚠ CRÍTICO — CHEAT CONFIRMADO",
    reasonTLD: function(tld){ return "TLD sospechoso detectado: \"" + tld + "\" — patrón común en cheats/proxies"; },
    reasonWord: function(word){ return "Palabra sospechosa en el dominio: \"" + word + "\""; },
    reasonVPS: function(isp){ return "VPS/HOSTING — ISP: " + isp; },
    reasonProxy: "PROXY / VPN detectado",
    reasonCF: function(asn){ return "Cloudflare accedido vía IP directa — patrón de proxy cheat (" + asn + ")"; },
    reasonASN: function(asn,desc){ return "ASN de proxy cheat conocido: " + asn + " — " + desc; },
    reasonRDNS: function(rdns){ return "rDNS de servidor: " + rdns; },
    reasonHostinger: function(rdns){ return "Hostinger VPS (patrón proxy cheat BR conocido): " + rdns; },
    reasonNoRDNS: "Sin rDNS (PTR) — típico de VPS usado como proxy",
    reasonOrg: function(kw){ return "Org/ISP asociado a hosting/proxy cheat: " + kw; },
  }
};

function setLang(lang) {
  const t = TRANSLATIONS[lang];
  if (!t) return;

  ['pt','en','es'].forEach(function(l) {
    var btn = document.getElementById('btn-' + l);
    if (btn) btn.classList.toggle('active', l === lang);
  });

  function q(sel) { return Array.from(document.querySelectorAll(sel)); }

  q('.hero-eyebrow').forEach(function(el){ el.textContent = t.eyebrow; });
  q('.hero-credits').forEach(function(el){ el.textContent = t.credits; });
  q('.hero-file strong').forEach(function(el){ el.textContent = t.fileLabel; });

  var hgLabels = q('.hg-label');
  ['start','lastRecord','uniqueDomains','totalConns'].forEach(function(k,i){
    if (hgLabels[i]) hgLabels[i].textContent = t[k];
  });

  // data-i18n generic handler
  q('[data-i18n]').forEach(function(el){
    var key = el.getAttribute('data-i18n');
    if (t[key] && typeof t[key] === 'string') el.textContent = t[key];
  });

  // indicator value (domain vs IP)
  q('[data-i18n-indicator]').forEach(function(el){
    var kind = el.getAttribute('data-i18n-indicator');
    el.textContent = kind === 'domain' ? t.indicatorDomain : t.indicatorIP;
  });

  // roots-detail with count
  q('[data-roots-count]').forEach(function(el){
    var n = parseInt(el.getAttribute('data-roots-count'), 10);
    var label = n > 1 ? t.rootsDetailN : t.rootsDetail1;
    el.textContent = n + ' ' + label + ' (roots_installed: ' + n + ')';
  });

  // domain-badge inline SUSPEITO/POSSÍVEL
  q('[data-sev]').forEach(function(el){
    var sev = el.getAttribute('data-sev');
    if (sev === 'HIGH') el.textContent = t.badgeSuspect;
    else if (sev === 'MEDIUM') el.textContent = t.badgePossible;
  });

  // reasons translation via data-reasons
  q('[data-reasons]').forEach(function(el){
    try {
      var reasons = JSON.parse(el.getAttribute('data-reasons'));
      var translated = reasons.map(function(r) {
        // match each reason pattern and translate
        var m;
        if ((m = r.match(/TLD suspeito detectado: "([^"]+)"/)) || (m = r.match(/Suspicious TLD detected: "([^"]+)"/)) || (m = r.match(/TLD sospechoso detectado: "([^"]+)"/))) return t.reasonTLD(m[1]);
        if ((m = r.match(/Palavra suspeita no domínio: "([^"]+)"/)) || (m = r.match(/Suspicious word in domain: "([^"]+)"/)) || (m = r.match(/Palabra sospechosa en el dominio: "([^"]+)"/))) return t.reasonWord(m[1]);
        if ((m = r.match(/VPS\/HOSTING — ISP: (.+)/))) return t.reasonVPS(m[1]);
        if (r.match(/PROXY \/ VPN/)) return t.reasonProxy;
        if ((m = r.match(/Cloudflare[^(]+\((\w+)\)/))) return t.reasonCF(m[1]);
        if ((m = r.match(/ASN[^:]+: (\w+) — (.+)/))) return t.reasonASN(m[1], m[2]);
        if ((m = r.match(/Hostinger VPS[^:]+: (.+)/))) return t.reasonHostinger(m[1]);
        if ((m = r.match(/rDNS de servidor: (.+)/) || r.match(/Server rDNS: (.+)/))) return t.reasonRDNS(m[1]);
        if (r.match(/Sem rDNS|No rDNS|Sin rDNS/)) return t.reasonNoRDNS;
        if ((m = r.match(/Org\/ISP[^:]+: (.+)/) || r.match(/Org\/ISP[^:]+: (.+)/))) return t.reasonOrg(m[1]);
        return r; // fallback: keep original
      });
      el.innerHTML = translated.join('<br>');
    } catch(e) {}
  });

  q('.uptime-text').forEach(function(el){
    var strong = el.querySelector('strong');
    if (strong) {
      var val = strong.textContent;
      while (el.firstChild) el.removeChild(el.firstChild);
      el.appendChild(document.createTextNode(t.monitoredFor + ' '));
      var ns = document.createElement('strong');
      ns.textContent = val;
      el.appendChild(ns);
    }
  });

  q('.uptime-bar span').forEach(function(el){
    if (el.style && el.style.marginLeft) el.innerHTML = '&#9888; ' + t.uptimeLess20;
  });

  var statLabels = q('.stat .lbl');
  ['criticalLabel','suspectLabel','possibleLabel'].forEach(function(k,i){
    if (statLabels[i]) statLabels[i].textContent = t[k];
  });

  q('.section-header').forEach(function(sh){
    var title = sh.querySelector('.sh-title');
    var sub   = sh.querySelector('.sh-sub');
    if (!title) return;
    if (sh.classList.contains('sh-critical')) {
      title.textContent = t.appProxyTitle;
      if (sub) sub.textContent = t.appProxySub;
    } else if (sh.classList.contains('sh-high')) {
      title.textContent = t.suspectIPsTitle;
      if (sub) sub.textContent = t.suspectIPsSub;
    } else if (sh.classList.contains('sh-medium')) {
      title.textContent = t.possibleIPsTitle;
      if (sub) sub.textContent = t.possibleIPsSub;
    }
  });

  q('.stale-label').forEach(function(el){ el.textContent = t.staleLabel; });
  q('.stale-hint').forEach(function(el){ el.textContent = t.staleHint; });
  q('.stale-time').forEach(function(el){
    var strong = el.querySelector('strong');
    if (strong) {
      var tv = strong.textContent;
      while (el.firstChild) el.removeChild(el.firstChild);
      el.appendChild(document.createTextNode(t.lastRecord2 + ' '));
      var ns2 = document.createElement('strong');
      ns2.textContent = tv;
      el.appendChild(ns2);
    }
  });

  q('.ff-label').forEach(function(el){
    var version = el.textContent.indexOf('MAX') !== -1 ? 'Free Fire MAX' : 'Free Fire';
    el.textContent = version + ' — ' + t.ffLabel;
  });
  var ffTags = q('.ff-tag');
  [t.ffLastOpen, t.ffFirstOpen].forEach(function(v,i){
    if (ffTags[i]) ffTags[i].textContent = v;
  });
  q('.ff-sessions').forEach(function(el){
    var num = el.textContent.match(/\d+/);
    if (num) el.textContent = num[0] + ' ' + t.ffSessions;
  });
  q('.ff-hint').forEach(function(el){ el.textContent = t.ffHint; });

  q('.appstore-label').forEach(function(el){ el.textContent = t.appStoreLabel; });
  q('.appstore-hint').forEach(function(el){ el.textContent = t.appStoreHint; });

  q('.ok').forEach(function(el){ el.textContent = t.noVPS; });

  var labelMap = {
    'IP': 'labelIP',
    'País': 'labelCountry', 'Country': 'labelCountry', 'País': 'labelCountry',
    'Provedor': 'labelProvider', 'Provider': 'labelProvider', 'Proveedor': 'labelProvider',
    'Org': 'labelOrg',
    'rDNS': 'labelRDNS',
    'HTTP': 'labelHTTP',
    'Motivo': 'labelReason', 'Reason': 'labelReason', 'Motivo': 'labelReason',
    'Usado por': 'labelUsedBy', 'Used by': 'labelUsedBy', 'Usado por': 'labelUsedBy',
    'App': 'labelApp',
    'Cheat': 'labelCheat',
    'Indicador': 'labelIndicator', 'Indicator': 'labelIndicator',
  };

  q('.card').forEach(function(card){
    var badge = card.querySelector('.badge');
    var connsEl = card.querySelector('.conns');
    if (connsEl) {
      var num = connsEl.textContent.match(/\d+/);
      if (num) connsEl.textContent = num[0] + ' ' + t.conns;
    }
    if (badge) {
      if (badge.classList.contains('critical')) {
        badge.innerHTML = badge.getAttribute('data-badge-type') === 'known-cheat' ? t.badgeKnownCheat : t.badgeCritical;
      }
      else if (badge.classList.contains('tld-flag')) badge.innerHTML = t.badgeDomainSuspect;
      else if (badge.classList.contains('high')) badge.textContent = t.badgeSuspect;
      else if (badge.classList.contains('medium')) badge.textContent = t.badgePossible;
    }
    card.querySelectorAll('.label').forEach(function(lbl){
      var sub = lbl.querySelector('.sub');
      if (sub) {
        var fn = lbl.childNodes[0];
        if (fn && fn.nodeType === 3) fn.textContent = t.labelSuspectIPs + ' ';
        var nums = sub.textContent.match(/\d+/g);
        if (nums && nums.length >= 2) sub.textContent = nums[0] + ' ' + t.of + ' ' + nums[1] + ' ' + t.domains;
        return;
      }
      var txt = lbl.textContent.trim();
      var key = labelMap[txt];
      if (key && t[key]) lbl.textContent = t[key];
    });
    card.querySelectorAll('.none').forEach(function(el){ el.textContent = t.noneDetected; });
    card.querySelectorAll('.val').forEach(function(el){
      if (el.textContent.indexOf('Online') !== -1 || el.textContent.indexOf('Offline') !== -1 || el.textContent.indexOf('línea') !== -1 || el.textContent.indexOf('conexión') !== -1) {
        el.innerHTML = el.innerHTML
          .replace(/●\s*(En línea|Online)/g, t.online)
          .replace(/●\s*(Sin conexión[^<]*|Offline[^<]*)/g, t.offline);
      }
    });
  });
}
window.setLang = setLang;

(function() {
  function bindLangButtons() {
    var langs = ['pt', 'en', 'es'];
    langs.forEach(function(l) {
      var btn = document.getElementById('btn-' + l);
      if (btn) {
        btn.addEventListener('click', function(e) {
          e.preventDefault();
          setLang(l);
        });
      }
    });
  }

  function tryBind(attempts) {
    var btn = document.getElementById('btn-pt');
    if (btn) {
      bindLangButtons();
    } else if (attempts > 0) {
      setTimeout(function() { tryBind(attempts - 1); }, 100);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { tryBind(10); });
  } else {
    tryBind(10);
  }
})();
`
}

function buildLangScript() {
  return `<script>` + buildLangScriptBody() + `<\/script>`
}

module.exports = { DEVICE_LANG, SPEECH, S, buildLangScript, buildLangScriptBody }
