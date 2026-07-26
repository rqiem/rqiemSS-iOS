// rqiemSS — Módulo de parsers/validación de archivos
// Antes los catch() quedaban vacíos y silenciaban errores de parseo sin dejar rastro.
// Ahora cada catch loguea con console.error para poder diagnosticar por qué un análisis salió vacío.

async function findNdjsonFile() {
  let path = await DocumentPicker.openFile()
  if (!path) return null
  return { path: path, fm: FileManager.local() }
}

function parseNdjson(content) {
  let trimmed = content.trim()
  if (trimmed.startsWith("[")) {
    try { return JSON.parse(trimmed) } catch(e) { console.error("parseNdjson: línea inválida — " + e); return null }
  }
  return trimmed
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0)
    .map(l => { try { return JSON.parse(l) } catch(e) { return null } })
    .filter(Boolean)
}

function parseIpsFile(content) {
  try {
    let trimmed = content.trim()
    let lines = trimmed.split("\n").map(l => l.trim()).filter(Boolean)
    let headerLine = lines.find(l => l.startsWith("{"))
    let dataLine   = lines.find(l => l.startsWith("["))
    let header = null
    try { header = headerLine ? JSON.parse(headerLine) : null } catch(e) { console.error("parseIpsFile: header inválido — " + e) }
    let entries = []
    try { entries = dataLine ? JSON.parse(dataLine) : [] } catch(e) { console.error("parseIpsFile: entries inválido — " + e) }
    return { header, entries }
  } catch(e) {
    return { header: null, entries: [] }
  }
}

function looksLikePrivacyReport(content) {
  let sample = content.trim().slice(0, 500)
  return sample.includes("networkActivity") || sample.includes("bundleID") || sample.includes("timeStamp")
}

function looksLikeUsageFile(content) {
  let sample = content.trim().slice(0, 300)
  return sample.includes("xp_amp_app_usage") || sample.includes("roots_installed") || sample.includes("usageClientId")
}

function validateReport(entries) {
  if (!entries || entries.length === 0)
    return { ok: false, reason: "Arquivo vazio ou sem entradas válidas." }

  let hasNet    = entries.some(e => e.type === "networkActivity")
  let hasAccess = entries.some(e => e.type === "access")
  let hasBundleID = entries.some(e => e.bundleID || (e.accessor && e.accessor.identifier))
  let hasTimestamp = entries.some(e => e.timeStamp)

  if (!hasNet && !hasAccess)
    return { ok: false, reason: "Nenhuma entrada de rede ou acesso encontrada.\nEste nao parece ser um App Privacy Report valido." }
  if (!hasBundleID)
    return { ok: false, reason: "Nenhum bundleID encontrado.\nO arquivo pode estar corrompido ou foi modificado." }
  if (!hasTimestamp)
    return { ok: false, reason: "Nenhum timestamp encontrado.\nO arquivo pode estar corrompido ou foi modificado." }

  let timestamps = entries.map(e => e.timeStamp).filter(Boolean)
  let valid = timestamps.filter(t => {
    let y = parseInt(t.slice(0,4))
    return y >= 2020 && y <= 2030
  })
  if (valid.length < timestamps.length * 0.5)
    return { ok: false, reason: "Timestamps fora do intervalo esperado.\nO arquivo pode ter sido adulterado." }

  let netEntries = entries.filter(e => e.type === "networkActivity")
  let validNet = netEntries.filter(e => e.domain && e.bundleID)
  if (netEntries.length > 0 && validNet.length < netEntries.length * 0.3)
    return { ok: false, reason: "Muitas entradas de rede sem domain/bundleID.\nO arquivo pode ter sido manipulado." }

  return { ok: true }
}

async function readFile(path) {
  let content = null
  let fm = FileManager.iCloud()
  try {
    if (fm.isFileStoredIniCloud && fm.isFileStoredIniCloud(path)) {
      await fm.downloadFileFromiCloud(path)
    }
    content = fm.readString(path)
  } catch(e) { console.error("readFile: fallo iCloud — " + e) }
  if (!content) {
    try { content = FileManager.local().readString(path) } catch(e2) { console.error("readFile: fallo local — " + e2) }
  }
  return content
}

module.exports = { findNdjsonFile, parseNdjson, parseIpsFile, looksLikePrivacyReport, looksLikeUsageFile, validateReport, readFile }
