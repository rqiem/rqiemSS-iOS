// rqiemSS — Módulo de análisis
// Combina los datos de rqiemSS-config.js con los parsers/network para producir los findings.

const cfg = importModule("rqiemSS-config")
const network = importModule("rqiemSS-network")

function analyzeIps(parsed) {
  let entries = parsed.entries || parsed || []
  let results = []
  let seen = new Set()

  for (let e of entries) {
    let bid = e.bundleId || ""
    if (!bid || seen.has(bid)) continue
    seen.add(bid)

    let reason = null
    let category = "warning"

    if (cfg.IPS_CHEAT_EXACT.has(bid)) {
      reason = cfg.CHEAT_APPS[bid] || bid
      category = cfg.IPS_CHEAT_CATEGORIES[bid] || "warning"
    } else {
      let bidLower = bid.toLowerCase()
      for (let kw of cfg.IPS_CHEAT_KEYWORDS) {
        if (bidLower.includes(kw)) {
          reason = "Keyword suspeita: \"" + kw + "\" no bundle ID"
          break
        }
      }
    }

    if (!reason) {
      let bidLower = bid.toLowerCase()
      const FF_LEGIT = ["com.dts.freefireth", "com.dts.freefiremax"]
      const FF_PREFIXES = ["com.dts.freefireth", "com.dts.freefiremax"]
      if (!FF_LEGIT.includes(bid) && FF_PREFIXES.some(p => bidLower.startsWith(p) || (bidLower.includes("freefire") && !FF_LEGIT.includes(bid)))) {
        reason = "Cópia suspeita do Free Fire — bundle ID modificado"
        category = "critical"
      }
    }

    if (reason) {
      results.push({
        bundleId:    bid,
        version:     e.shortAppVersion || "?",
        eventType:   e.eventType || "?",
        count:       e.count || 0,
        reason:      reason,
        category:    category,
      })
    }
  }

  return results
}

async function analyze(entries) {
  let netEntries = entries.filter(e => e.type === "networkActivity")

  let domainHits = {}
  let domainBundles = {}
  for (let e of netEntries) {
    if (cfg.IGNORED_BUNDLES.has(e.bundleID)) continue
    let d = e.domain || ""
    if (!d) continue
    domainHits[d] = (domainHits[d] || 0) + (e.hits || 1)
    if (!domainBundles[d]) domainBundles[d] = new Set()
    domainBundles[d].add(e.bundleID || "?")
  }

  let allDomains = Object.entries(domainHits)
    .sort((a, b) => b[1] - a[1])
    .map(([d]) => d)

  console.log(`Total dominios unicos: ${allDomains.length}`)

  let allBundles = new Set()
  for (let e of netEntries) { if (e.bundleID && !cfg.IGNORED_BUNDLES.has(e.bundleID)) allBundles.add(e.bundleID) }

  const FF_LEGIT_BUNDLES = new Set(["com.dts.freefireth", "com.dts.freefiremax"])
  let ffFakeFindings = []
  for (let bid of allBundles) {
    if (FF_LEGIT_BUNDLES.has(bid)) continue
    let bidLower = bid.toLowerCase()
    let isFFClone = bidLower.startsWith("com.dts.freefireth") ||
                    bidLower.startsWith("com.dts.freefiremax") ||
                    (bidLower.includes("freefire") && !FF_LEGIT_BUNDLES.has(bid)) ||
                    (bidLower.includes("freefir") && !FF_LEGIT_BUNDLES.has(bid))
    if (isFFClone) {
      let appEntries = netEntries.filter(e => e.bundleID === bid)
      let appHits = appEntries.reduce((s, e) => s + (e.hits || 1), 0)
      let appDomains = [...new Set(appEntries.map(e => e.domain).filter(Boolean))]
      ffFakeFindings.push({ bundleID: bid, desc: "Cópia suspeita do Free Fire — bundle ID modificado", hits: appHits, domains: appDomains })
    }
  }

  let cheatAppFindings = []
  for (let [bundleID, desc] of Object.entries(cfg.CHEAT_APPS)) {
    if (allBundles.has(bundleID)) {
      let appEntries = netEntries.filter(e => e.bundleID === bundleID)
      let appHits = appEntries.reduce((s, e) => s + (e.hits || 1), 0)
      let appDomains = [...new Set(appEntries.map(e => e.domain).filter(Boolean))]
      cheatAppFindings.push({ bundleID, desc, hits: appHits, domains: appDomains })
    }
  }
  cheatAppFindings = [...ffFakeFindings, ...cheatAppFindings]

  // Coleta quais domínios FF foram chamados pelos apps legítimos do FF
  let ffLegitDomainsSeen = new Set()
  for (let e of netEntries) {
    let d = (e.domain || "").toLowerCase()
    let bid = e.bundleID || ""
    if (cfg.FF_LEGIT_CALLERS.has(bid) && cfg.FF_PROXY_LOGIN_DOMAINS.has(d)) {
      ffLegitDomainsSeen.add(d)
    }
  }

  let proxyLoginFindings = []
  let proxyLoginSeen = {}
  for (let e of netEntries) {
    let d = (e.domain || "").toLowerCase()
    let bid = e.bundleID || ""
    if (!bid) continue
    if (cfg.FF_LEGIT_CALLERS.has(bid)) continue
    if (cfg.IGNORED_BUNDLES.has(bid)) continue
    if (!cfg.FF_PROXY_LOGIN_DOMAINS.has(d)) continue
    // Só dispara se o domínio NÃO foi chamado pelos apps legítimos do FF na mesma sessão
    // Isso evita falsos positivos de janela de tempo (iOS agrupando apps diferentes)
    if (ffLegitDomainsSeen.has(d)) continue
    if (!proxyLoginSeen[d]) proxyLoginSeen[d] = { domain: e.domain, bundles: new Set(), hits: 0 }
    proxyLoginSeen[d].bundles.add(bid)
    proxyLoginSeen[d].hits += (e.hits || 1)
  }
  for (let [d, info] of Object.entries(proxyLoginSeen)) {
    proxyLoginFindings.push({ domain: info.domain, bundles: [...info.bundles], hits: info.hits })
  }

  let knownCheatFindings = []
  for (let e of netEntries) {
    let d = (e.domain || "").toLowerCase()
    let bid = e.bundleID || ""
    // Se o bundle é o app legítimo do FF e o domínio é um domínio oficial de proxy/login do FF,
    // não dispara como cheat — é tráfego normal do próprio jogo.
    if (cfg.FF_LEGIT_CALLERS.has(bid) && cfg.FF_PROXY_LOGIN_DOMAINS.has(d)) continue
    for (let [indicator, desc] of Object.entries(cfg.KNOWN_CHEAT_INFRA)) {
      if (d === indicator.toLowerCase() || d.endsWith("." + indicator.toLowerCase())) {
        // Domínios que fazem parte do cfg.FF_PROXY_LOGIN_DOMAINS só são cheat se chamados por bundle não-legítimo
        if (cfg.FF_PROXY_LOGIN_DOMAINS.has(indicator.toLowerCase()) && cfg.FF_LEGIT_CALLERS.has(bid)) continue
        let existing = knownCheatFindings.find(k => k.indicator === indicator)
        if (existing) {
          existing.hits += (e.hits || 1)
          if (bid) existing.bundles.add(bid)
        } else {
          knownCheatFindings.push({
            indicator,
            desc,
            hits: e.hits || 1,
            bundles: new Set(bid ? [bid] : []),
          })
        }
      }
    }
  }
  knownCheatFindings = knownCheatFindings.map(k => ({ ...k, bundles: [...k.bundles] }))

  const CHUNK = 100
  let candidates = []

  for (let i = 0; i < allDomains.length; i += CHUNK) {
    let chunk = allDomains.slice(i, i + CHUNK)
    let chunkNum = Math.floor(i / CHUNK) + 1
    let totalChunks = Math.ceil(allDomains.length / CHUNK)
    console.log(`Batch ${chunkNum}/${totalChunks} — ${chunk.length} dominios`)

    let results = await network.lookupBatch(chunk)

    if (chunkNum === Math.ceil(totalChunks / 2) && totalChunks > 1) {
      Speech.speak(S.half)
    }

    for (let j = 0; j < results.length; j++) {
      let info = results[j]
      let domain = chunk[j]
      let ip = (info && info.query) || domain

      if (cfg.FALSE_POSITIVE_IPS.has(ip) || cfg.FALSE_POSITIVE_IPS.has(domain)) continue

      let domLow2 = domain.toLowerCase()
      let isTldSuspect = cfg.SUSPICIOUS_TLDS.some(t => domLow2.endsWith(t)) ||
                         cfg.SUSPICIOUS_DOMAIN_WORDS.some(w => domLow2.split(".")[0].includes(w))

      let severity = null
      let reasons = []

      if (info && info.status === "success") {
        let classified = network.classifyIP(info, domain)
        severity = classified.severity
        reasons  = classified.reasons
      }

      if (!severity && isTldSuspect) {
        severity = "HIGH"
        reasons = [`TLD suspeito: domínio com extensão de alto risco — padrão comum em servidores de cheat`]
      }

      if (!severity && !isTldSuspect) continue

      candidates.push({
        severity, domain, ip,
        country: (info && info.country) || "?",
        city:    (info && info.city)    || "?",
        isp:     (info && info.isp)     || "?",
        org:     (info && info.org)     || "?",
        as:      (info && info.as)      || "?",
        hosting: (info && info.hosting) || false,
        proxy:   (info && info.proxy)   || false,
        reverse: (info && info.reverse) || "",
        hits:    domainHits[domain],
        bundles: [...domainBundles[domain]].slice(0, 4),
        reasons,
        tldSuspect: isTldSuspect,
      })
    }

    if (i + CHUNK < allDomains.length) await network.wait(1400)
  }

  console.log(`Iniciando probe HTTP em ${candidates.length} suspeitos...`)
  Speech.speak(S.probe)
  let probeResults = await Promise.all(candidates.map(c => network.probeHost(c.domain)))

  let findings = candidates.map((c, idx) => {
    let probe = probeResults[idx]
    let severity = c.severity
    let reasons = [...c.reasons]

    if (probe) {
      if (probe.suspicious && probe.banner) {
        severity = "HIGH"
        reasons.push(`Servidor: ${probe.banner}`)
      }
      if (probe.status === 403) {
        reasons.push("HTTP 403 — ativo mas bloqueando acesso (padrão de proxy)")
      }
      if (!probe.online) {
        reasons.push("Servidor offline ou sem resposta HTTP")
      }
    }

    return { ...c, severity, reasons, probe, tldSuspect: c.tldSuspect }
  })

  const ASN_SET = new Set(Object.keys(cfg.CHEAT_PROXY_ASN))

  function hasSuspiciousTLD(domain) {
    let d = (domain || "").toLowerCase()
    return cfg.SUSPICIOUS_TLDS.some(t => d.endsWith(t) || d.includes(t + "/")) ||
           cfg.SUSPICIOUS_DOMAIN_WORDS.some(w => d.split(".")[0].includes(w))
  }

  findings.sort((a, b) => {
    let aTld = hasSuspiciousTLD(a.domain) ? 0 : 1
    let bTld = hasSuspiciousTLD(b.domain) ? 0 : 1
    if (aTld !== bTld) return aTld - bTld

    let aAsn = (a.as || "").split(" ")[0].toUpperCase()
    let bAsn = (b.as || "").split(" ")[0].toUpperCase()
    let aKnown = ASN_SET.has(aAsn) ? 0 : 1
    let bKnown = ASN_SET.has(bAsn) ? 0 : 1
    if (aKnown !== bKnown) return aKnown - bKnown

    let sevOrder = { HIGH: 0, MEDIUM: 1 }
    if (a.severity !== b.severity) return sevOrder[a.severity] - sevOrder[b.severity]

    let aOnline = (a.probe && a.probe.online) ? 0 : 1
    let bOnline = (b.probe && b.probe.online) ? 0 : 1
    if (aOnline !== bOnline) return aOnline - bOnline

    return b.hits - a.hits
  })

  let ghostAppFindings = []
  if (typeof window !== "undefined") {
  } else {
  }
  const GHOST_SUSPECT_DOMAINS = new Set(Object.keys(cfg.KNOWN_CHEAT_INFRA))
  cfg.SUSPICIOUS_TLDS.forEach(t => {})

  let suspectByBundle = {}
  for (let e of netEntries) {
    let bid = e.bundleID || ""
    let dom = (e.domain || "").toLowerCase()
    if (!bid) continue
    // Não flagra o app legítimo do FF acessando seus próprios domínios de proxy/login
    if (cfg.FF_LEGIT_CALLERS.has(bid) && cfg.FF_PROXY_LOGIN_DOMAINS.has(dom)) continue
    let isKnown = GHOST_SUSPECT_DOMAINS.has(dom)
    let isTld   = cfg.SUSPICIOUS_TLDS.some(t => dom.endsWith(t))
    if (isKnown || isTld) {
      if (!suspectByBundle[bid]) suspectByBundle[bid] = { domains: [], hits: 0 }
      suspectByBundle[bid].domains.push(e.domain)
      suspectByBundle[bid].hits += (e.hits || 1)
    }
  }
  for (let [bid, info] of Object.entries(suspectByBundle)) {
    ghostAppFindings.push({ bundleID: bid, domains: [...new Set(info.domains)], hits: info.hits })
  }

  return { findings, netEntries, cheatAppFindings, knownCheatFindings, ghostAppFindings, proxyLoginFindings }
}


module.exports = { analyze, analyzeIps }
