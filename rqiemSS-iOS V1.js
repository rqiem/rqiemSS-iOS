// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: pink; icon-glyph: chart-bar;

// rqiemSS — Script principal
// Refactor: la lógica está dividida en módulos separados (mismo folder de Scriptable):
//   rqiemSS-config.js   → listas de detección (hosting, ASN, cheat apps, TLDs...)
//   rqiemSS-i18n.js      → SPEECH (voz) + TRANSLATIONS/setLang (WebView), fuente única
//   rqiemSS-parsers.js   → lectura/parseo/validación de archivos, con errores logueados
//   rqiemSS-network.js   → lookup de IPs, DNS, clasificación de host
//   rqiemSS-analysis.js  → analyze() / analyzeIps(): arma los findings
//   rqiemSS-html.js      → buildHTML(): arma el reporte
// Todos deben estar en la misma carpeta de Scriptable que este archivo.

const cfg      = importModule("rqiemSS-config")
const i18n     = importModule("rqiemSS-i18n")
const parsers  = importModule("rqiemSS-parsers")
const network  = importModule("rqiemSS-network")
const analysis = importModule("rqiemSS-analysis")
const htmlMod  = importModule("rqiemSS-html")

const { S } = i18n
const { readFile } = parsers
const { analyze, analyzeIps } = analysis
const { buildHTML } = htmlMod
const { parseNdjson, parseIpsFile, looksLikePrivacyReport, looksLikeUsageFile, validateReport } = parsers
const { wait } = network

async function showResult(html) {
  let wv = new WebView()
  await wv.loadHTML(html, "http://localhost")
  await wv.evaluateJavaScript(i18n.buildLangScriptBody())
  Speech.speak(S.done)
  await wait(1200)
  await wv.present(false)
}

async function main() {
  let step1 = new Alert()
  step1.title = "📋 Paso 1 de 3 — Reporte de Privacidad"
  step1.message = "Ir en:\n\nAjustes → Privacidad y Seguridad → Reporte de privacidad de apps\n\nBaje hasta el final y toque en\n\"Activar el reporte de privacidad de apps\"\n\nDespués toque en\n\"Exportar Reporte de privacidad de apps\"\nY guarda el archivo .ndjson en cualquier lugar (Archivos, iCloud, etc)."
  step1.addAction("Entendido, siguiente →")
  step1.addCancelAction("Cancelar")
  if (await step1.present() === -1) { Script.complete(); return }

  let step2 = new Alert()
  step2.title = "📊 Paso 2 de 3 — Datos de Análisis"
  step2.message = "Ir en:\n\nAjustes → Privacidad y Seguridad → Análisis y mejoras\n\nActiva las opciones:\n• Compartir análisis (iPhone)\n• Compartir análisis (iCloud)\n• Compartir con desarrolladores\n\nDespués regrese y toque en\n\"Datos de análisis\"\nBaje hasta el final y selecciona el archivo más reciente que comienza en\n\"xp_amp_app_usage_dnu\"\n\nToca el archivo → toque el icono de compartir → Guárdalo en archivos."
  step2.addAction("Entendido, siguiente →")
  step2.addCancelAction("Cancelar")
  if (await step2.present() === -1) { Script.complete(); return }

  let step3 = new Alert()
  step3.title = "✅ Paso 3 de 3 — Seleccionar archivos"
  step3.message = "Ahora selecciona los 2 archivos guardados anteriormente.\n\nLos puedes seleccionar en cualquier orden — el sistema identifica automáticamente cada uno.\n\n📋 App_Privacy_Report.ndjson\n📊 xp_amp_app_usage_dnu*.ips"
  step3.addAction("Seleccionar Archivo 1")
  step3.addCancelAction("Cancelar")
  if (await step3.present() === -1) { Script.complete(); return }

  let path1 = await DocumentPicker.openFile()
  if (!path1) { Script.complete(); return }
  let content1 = await readFile(path1)
  if (!content1) {
    let a = new Alert(); a.title = "Error"; a.message = "No fue posible leer el Archivo 1."; a.addAction("OK"); await a.present(); return
  }

  let notice2 = new Alert()
  notice2.title = "Archivo 2"
  notice2.message = "Selecciona el segundo archivo (O pasa para analizar solamente el primero)."
  notice2.addAction("Seleccionar archivo 2")
  notice2.addCancelAction("Pasar")
  let path2 = null
  let content2 = null
  if (await notice2.present() !== -1) {
    path2 = await DocumentPicker.openFile()
    if (path2) content2 = await readFile(path2)
  }

  let ndjsonContent = null, ndjsonPath = null
  let ipsContent = null

  function classifyContent(content, path) {
    if (looksLikePrivacyReport(content)) return "ndjson"
    if (looksLikeUsageFile(content)) return "ips"
    let name = (path || "").split("/").pop().toLowerCase()
    if (name.endsWith(".ndjson") || name.includes("privacy")) return "ndjson"
    if (name.endsWith(".ips") || name.includes("xp_amp")) return "ips"
    return "unknown"
  }

  let type1 = classifyContent(content1, path1)
  let type2 = content2 ? classifyContent(content2, path2) : null

  if (type2 && type1 === type2) {
    let a = new Alert()
    a.title = "Archivos del mismo tipo"
    a.message = type1 === "ndjson"
      ? "Los 2 archivos parecen ser App Privacy Reports. Seleccione un xp_amp_app_usage_dnu*.ips como segundo archivo."
      : "Los 2 archivos parecen ser Datos de análisis. Selecciona un App_Privacy_Report.ndjson como primer archivo."
    a.addAction("OK")
    await a.present()
    return
  }

  if (type1 === "ndjson" || type2 === "ips") {
    ndjsonContent = content1; ndjsonPath = path1
    ipsContent = content2
  } else if (type1 === "ips" || type2 === "ndjson") {
    ipsContent = content1
    ndjsonContent = content2; ndjsonPath = path2
  } else {
    let a = new Alert()
    a.title = "Archivo no reconocido"
    a.message = "No fue posible identificar el tipo de los archivos.\n\nVerifique si seleccionó:\n• App_Privacy_Report.ndjson\n• xp_amp_app_usage_dnu*.ips"
    a.addAction("OK")
    await a.present()
    return
  }

  if (!ndjsonContent) {
    let a = new Alert()
    a.title = "App Privacy Report ausente"
    a.message = "El archivo App_Privacy_Report.ndjson es obligatorio.\n\nAjustes → Privacidad → Reporte de privacidad de apps → Exportar"
    a.addAction("OK")
    await a.present()
    return
  }

  let entries = parseNdjson(ndjsonContent)
  let validation = validateReport(entries)
  if (!validation.ok) {
    let a = new Alert()
    a.title = "App Privacy Report inválido"
    a.message = validation.reason + "\n\nExporte en: Ajustes → Privacidad → Reporte de privacidad de apps → Exportar"
    a.addAction("OK")
    await a.present()
    return
  }

  let ipsFindings = []
  let ipsMeta = { iosVersion: null, rootsInstalled: 0 }
  if (ipsContent) {
    let parsed = parseIpsFile(ipsContent)
    ipsFindings = analyzeIps(parsed)
    if (parsed.header) {
      let osMatch = (parsed.header.os_version || "").match(/iPhone OS ([\d.]+)/)
      ipsMeta.iosVersion = osMatch ? osMatch[1] : parsed.header.os_version || null
      ipsMeta.rootsInstalled = parsed.header.roots_installed || 0
    }
  }

  let filename = (ndjsonPath || "archivo").split("/").pop()

  Speech.speak(S.start)

  let { findings, netEntries, cheatAppFindings, knownCheatFindings, ghostAppFindings, proxyLoginFindings } = await analyze(entries)

  let html = buildHTML(findings, netEntries, cheatAppFindings, knownCheatFindings, ipsFindings, ipsMeta, [], ghostAppFindings, proxyLoginFindings, filename)
  await showResult(html)
}

main()
