/* global describe, it */
const assert = require('chai').assert
const percentVulnerable = require('./percent-vulnerable')

describe('Percent Vulnerable', () => {
  it('should return null when arguments are wrong types', () => {
    assert.equal(percentVulnerable('', {}), null)
    assert.equal(percentVulnerable(), null)
    assert.notEqual(percentVulnerable([], {}), null)
  })

  it('should return the correct percentage', () => {
    assert.equal(percentVulnerable(
      [{ version: '>1.0.0' }], { '1.0.1': 1 }
    ), 1)
  })

  it('should deal with multiple versions and single semver', () => {
    assert.equal(percentVulnerable([{ version: '<7.4.4' }], {
      '7.4.1': 1,
      '7.4.2': 2,
      '7.4.3': 3,
      '7.4.4': 15,
      '7.4.5': 20,
      '7.4.6': 30
    }), 6 / (1 + 2 + 3 + 15 + 20 + 30))
  })

  it('should deal with multiple versions and single semver', () => {
    const vulns = [{ version: '<7.4.4' }]
    const downloads = {
      '6.0.0': 1,
      '6.0.1': 2,
      '7.4.4': 5,
      '7.4.6': 30
    }
    const totalDownloads = Object.keys(downloads).reduce((t, c) => t + downloads[c], 0)
    const vulnDownloads = 3

    assert.equal(percentVulnerable(vulns, downloads), vulnDownloads / totalDownloads)
  })

  it('should deal with multiple versions and two rule semver', () => {
    const vulns = [{ version: '>=0.0.5 <1.1.1' }]
    const downloads = {
      '0.0.1': 1,
      '0.0.6': 2,
      '1.1.0': 5,
      '1.1.2': 30
    }
    const totalDownloads = Object.keys(downloads).reduce((t, c) => t + downloads[c], 0)
    const vulnDownloads = downloads['0.0.6'] + downloads['1.1.0']

    assert.equal(percentVulnerable(vulns, downloads), vulnDownloads / totalDownloads)
  })

  it('should deal with multiple versions and two semver rules', () => {
    const vulns = [{ version: '>=0.0.1 <0.14.0' }, { version: '>=0.5.0 <0.5.2' }]
    const downloads = {
      '0.0.1': 1,
      '0.0.6': 2,
      '1.1.0': 5,
      '1.1.2': 30
    }
    const totalDownloads = Object.keys(downloads).reduce((t, c) => t + downloads[c], 0)
    const vulnDownloads = downloads['0.0.1'] + downloads['0.0.6']

    assert.equal(percentVulnerable(vulns, downloads), vulnDownloads / totalDownloads)
  })

  it('should deal with comma separated semver patterns', () => {
    const vulns = [{ version: '>=16.0.0 <16.0.1,>=16.1.0 <16.1.2,>=16.2.0 <16.2.1,>=16.3.0 <16.3.3,>=16.4.0 <16.4.2' }]
    const downloads = {
      '0.0.1': 1,
      '0.0.6': 2,
      '1.1.0': 5,
      '1.1.2': 30
    }
    const totalDownloads = Object.keys(downloads).reduce((t, c) => t + downloads[c], 0)
    const vulnDownloads = downloads['0.0.1'] + downloads['0.0.6']

    assert.equal(percentVulnerable(vulns, downloads), vulnDownloads / totalDownloads)
  })
})
