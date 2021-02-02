const cheerio = require('cheerio')
const fetch = require('node-fetch')
const t2j = require('tabletojson').Tabletojson
const redis = require('redis')
const { promisify } = require('util')
const pino = require('pino')()
const info = pino.info.bind(pino)
const warn = pino.warn.bind(pino)
const percentVulnerable = require('./percent-vulnerable')

const client = redis.createClient()
const redisGet = promisify(client.get).bind(client)
const _package = process.argv.slice(2)[0]; // TODO: Print help.

(async function (_package) {
  let vulns = null
  try {
    info(`Checking the cache for ${_package}'s vulnerabilities.`)
    const cached = await redisGet(_package)
    if (!cached) {
      info(`No vulnerabilities cached for ${_package}.`)
      vulns = await getVulns(_package)
    } else {
      info(`We had ${_package}'s vulnerabilities stored.`)
      vulns = JSON.parse(cached)
    }
  } catch (error) {
    warn(`Error getting vulns for ${_package} from cache.`)
  }

  let downloads = null
  try {
    downloads = await getDownloads(_package)
  } catch (error) {
    warn(`Error getting downloads for ${_package} from web.`)
  }

  console.log(`${percentVulnerable(vulns, downloads) * 100}% of ${_package} installs vulnerable.`)
})(_package)

async function getVulns (_package) {
  const vulnURL = `https://snyk.io/vuln/npm:${encodeURIComponent(_package)}`
  let vulns = null
  try {
    const response = await fetch(vulnURL)
    const html = await response.text()
    vulns = html2Vulns(html)
    if (vulns) {
      info(`Storing vulnerabilities for ${_package}.`)
      client.set(_package, JSON.stringify(vulns))
      info(`Stored ${vulns.length} vulnerabilities for ${_package}.`)
    } else {
      info(`No vulnerabilities found for ${_package}.`)
    }
  } catch (error) {
    warn(`Error fetching vulnerabilities for ${_package} from web.`)
    warn(error)
  }
  return vulns
}

async function getDownloads (_package) {
  const downloadsURL = `https://api.npmjs.org/versions/${encodeURIComponent(_package)}/last-week`
  let downloads = null
  try {
    const response = await fetch(downloadsURL)
    const json = await response.json()
    downloads = json.downloads
  } catch (error) {
    warn(error)
  }
  return downloads
}

function html2Vulns (html) {
  const $ = cheerio.load(html)
  const table = t2j.convert(`<table> ${$('.table--comfortable').html()} </table>`)[0]
  const vulns = table.map(entry => {
    return {
      type: entry.Vulnerability.substr(1).trim(),
      version: entry['Vulnerable versions'],
      published: entry.Published
    }
  })
  return vulns
}
