const semver = require('semver')

function percentVulnerable (vulns, downloads) {
  if (!Array.isArray(vulns)) return null
  if (!(downloads instanceof Object)) return null

  const semvers = vulns.map(vuln => vuln.version.replace(/,/g, ' || '))

  let allDownloads = 0
  let vulnerableCount = 0

  Object.keys(downloads).forEach(current => {
    for (const pattern of semvers) {
      if (semver.satisfies(current, pattern)) {
        vulnerableCount += downloads[current]
        break
      }
    }

    allDownloads += downloads[current]
  })

  return vulnerableCount / allDownloads
}

module.exports = percentVulnerable
