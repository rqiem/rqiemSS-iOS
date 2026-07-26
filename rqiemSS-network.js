// rqiemSS — Módulo de red
// Requiere rqiemSS-config.js (cfg.FIELDS, listas de hosting/ASN) — se inyecta por parámetro, ver main.

const cfg = importModule("rqiemSS-config")

async function lookupBatch(targets) {
  try {
    let req = new Request(`http://ip-api.com/batch?fields=${cfg.FIELDS}`)
    req.method = "POST"
    req.body = Data.fromString(JSON.stringify(targets))
    req.headers = { "Content-Type": "application/json" }
    req.timeoutInterval = 15
    let results = await req.loadJSON()
    if (!Array.isArray(results)) return []
    return results
  } catch(e) {
    return []
  }
}

function isIPv4(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s)
}

function isIPv6(s) {
  return s.includes(":") && !s.includes(".")
}

function isIP(s) {
  return isIPv4(s) || isIPv6(s)
}

async function resolveHostname(domain) {
  return domain
}

function classifyIP(info, domain) {
  if (!info) return { severity: null, reasons: [] }
  let reasons = []
  let severity = null
  let tldFlag = false

  let domLow = (domain || "").toLowerCase()
  for (let tld of cfg.SUSPICIOUS_TLDS) {
    if (domLow.endsWith(tld) || domLow.includes(tld + "/")) {
      severity = "HIGH"
      tldFlag = true
      reasons.push(`TLD suspeito detectado: "${tld}" — padrão comum em cheats/proxies`)
      break
    }
  }
  if (!tldFlag) {
    let parts = domLow.split(".")[0]
    for (let word of cfg.SUSPICIOUS_DOMAIN_WORDS) {
      if (parts.includes(word) || domLow.includes(word + ".")) {
        severity = "HIGH"
        tldFlag = true
        reasons.push(`Palavra suspeita no domínio: "${word}"`)
        break
      }
    }
  }

  if (info.hosting) {
    severity = "HIGH"
    reasons.push(`VPS/HOSTING — ISP: ${info.isp}`)
  }
  if (info.proxy) {
    severity = "HIGH"
    reasons.push("PROXY / VPN detectado")
  }

  let asn = (info.as || "").split(" ")[0].toUpperCase()
  if (cfg.CHEAT_PROXY_ASN[asn]) {
    let isCloudflare = asn === "AS13335"
    if (isCloudflare) {
      let domainIsIP = /^[\d.:]+$/.test(domain || "")
      if (domainIsIP) {
        severity = "HIGH"
        reasons.push(`Cloudflare acessado via IP direto — padrão de proxy cheat (${asn})`)
      }
    } else {
      severity = "HIGH"
      reasons.push(`ASN de cheat proxy conhecido: ${asn} — ${cfg.CHEAT_PROXY_ASN[asn]}`)
    }
  }

  let rdns = (info.reverse || "").toLowerCase()
  if (rdns) {
    for (let pattern of cfg.RDNS_HOSTING_PATTERNS) {
      if (rdns.includes(pattern)) {
        severity = severity || "HIGH"
        reasons.push(`rDNS de servidor: ${info.reverse}`)
        break
      }
    }
    if (rdns.match(/^srv\d+\.hstgr\.cloud$/)) {
      severity = "HIGH"
      reasons.push(`Hostinger VPS (padrao cheat proxy BR): ${info.reverse}`)
    }
  } else if (info.hosting) {
    reasons.push("Sem rDNS (PTR) — tipico de VPS usado como proxy")
  }

  let orgLower = ((info.org || "") + " " + (info.isp || "") + " " + (info.as || "")).toLowerCase()
  for (let kw of cfg.VPS_HOSTING_KEYWORDS) {
    if (orgLower.includes(kw)) {
      severity = severity || "MEDIUM"
      reasons.push(`Org/ISP associado a hospedagem/cheat proxy: ${kw}`)
      break
    }
  }

  return { severity, reasons }
}

async function probeHost(domain) {
  let safe = ["apple.com","icloud.com","google.com","googleapis.com",
              "gstatic.com","amazon.com","microsoft.com","iphone","localhost",
              "akamai","cloudfront","fastly","edgekey","aaplimg"]
  if (safe.some(s => domain.toLowerCase().includes(s))) return null

  let result = { status: null, banner: null, online: false, suspicious: false }
  let headers = null

  for (let scheme of ["https", "http"]) {
    try {
      let req = new Request(`${scheme}://${domain}`)
      req.timeoutInterval = 6
      req.allowInsecureRequest = true
      let body = await req.loadString()

      result.online = true
      let resp = req.response || {}
      result.status = resp.statusCode || 0
      headers = resp.headers || {}

      let serverHeader = (headers["Server"] || headers["server"] || "").toLowerCase()
      let bodyLow = (body || "").slice(0, 600).toLowerCase()
      let combined = serverHeader + " " + bodyLow

      let suspiciousBanners = [
        "nginx", "apache", "ubuntu", "debian", "centos", "mitmproxy",
        "squid", "haproxy", "openresty", "caddy", "traefik",
        "403 forbidden", "bad gateway", "bad request", "proxy error"
      ]

      if (serverHeader) {
        result.banner = serverHeader.split("/")[0].trim()
        result.suspicious = true
      } else {
        for (let b of suspiciousBanners) {
          if (combined.includes(b)) {
            result.banner = b
            result.suspicious = true
            break
          }
        }
      }

      let sc = result.status
      if (sc === 403 || sc === 502 || sc === 504 || sc === 400) result.suspicious = true

      break
    } catch(e) {
      result.online = false
    }
  }

  return result
}


function wait(ms) {
  return new Promise(resolve => Timer.schedule(ms, false, resolve))
}

module.exports = { lookupBatch, isIPv4, isIPv6, isIP, resolveHostname, classifyIP, probeHost, wait }
