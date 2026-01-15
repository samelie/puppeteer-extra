'use strict'

const { PuppeteerExtraPlugin } = require('puppeteer-extra-plugin')

// Static imports of all evasion modules - enables bundling without dynamic requires
const evasionChromeApp = require('./evasions/chrome.app')
const evasionChromeCsi = require('./evasions/chrome.csi')
const evasionChromeLoadTimes = require('./evasions/chrome.loadTimes')
const evasionChromeRuntime = require('./evasions/chrome.runtime')
const evasionDefaultArgs = require('./evasions/defaultArgs')
const evasionIframeContentWindow = require('./evasions/iframe.contentWindow')
const evasionMediaCodecs = require('./evasions/media.codecs')
const evasionNavigatorHardwareConcurrency = require('./evasions/navigator.hardwareConcurrency')
const evasionNavigatorLanguages = require('./evasions/navigator.languages')
const evasionNavigatorPermissions = require('./evasions/navigator.permissions')
const evasionNavigatorPlugins = require('./evasions/navigator.plugins')
const evasionNavigatorWebdriver = require('./evasions/navigator.webdriver')
const evasionSourceurl = require('./evasions/sourceurl')
const evasionUserAgentOverride = require('./evasions/user-agent-override')
const evasionWebglVendor = require('./evasions/webgl.vendor')
const evasionWindowOuterdimensions = require('./evasions/window.outerdimensions')

// Registry mapping evasion names to their factory functions
const EVASION_REGISTRY = {
  'chrome.app': evasionChromeApp,
  'chrome.csi': evasionChromeCsi,
  'chrome.loadTimes': evasionChromeLoadTimes,
  'chrome.runtime': evasionChromeRuntime,
  'defaultArgs': evasionDefaultArgs,
  'iframe.contentWindow': evasionIframeContentWindow,
  'media.codecs': evasionMediaCodecs,
  'navigator.hardwareConcurrency': evasionNavigatorHardwareConcurrency,
  'navigator.languages': evasionNavigatorLanguages,
  'navigator.permissions': evasionNavigatorPermissions,
  'navigator.plugins': evasionNavigatorPlugins,
  'navigator.webdriver': evasionNavigatorWebdriver,
  'sourceurl': evasionSourceurl,
  'user-agent-override': evasionUserAgentOverride,
  'webgl.vendor': evasionWebglVendor,
  'window.outerdimensions': evasionWindowOuterdimensions
}

/**
 * Stealth mode: Applies various techniques to make detection of headless puppeteer harder. 💯
 *
 * ### Purpose
 * There are a couple of ways the use of puppeteer can easily be detected by a target website.
 * The addition of `HeadlessChrome` to the user-agent being only the most obvious one.
 *
 * The goal of this plugin is to be the definite companion to puppeteer to avoid
 * detection, applying new techniques as they surface.
 *
 * As this cat & mouse game is in it's infancy and fast-paced the plugin
 * is kept as flexibile as possible, to support quick testing and iterations.
 *
 * ### Modularity
 * This plugin uses static imports for all evasions, making it compatible with bundlers
 * like webpack, ncc, and esbuild. All evasion techniques are included by default.
 *
 * @example
 * const puppeteer = require('puppeteer-extra')
 * // Enable stealth plugin with all evasions
 * puppeteer.use(require('puppeteer-extra-plugin-stealth')())
 *
 *
 * ;(async () => {
 *   // Launch the browser in headless mode and set up a page.
 *   const browser = await puppeteer.launch({ args: ['--no-sandbox'], headless: true })
 *   const page = await browser.newPage()
 *
 *   // Navigate to the page that will perform the tests.
 *   const testUrl = 'https://intoli.com/blog/' +
 *     'not-possible-to-block-chrome-headless/chrome-headless-test.html'
 *   await page.goto(testUrl)
 *
 *   // Save a screenshot of the results.
 *   const screenshotPath = '/tmp/headless-test-result.png'
 *   await page.screenshot({path: screenshotPath})
 *   console.log('have a look at the screenshot:', screenshotPath)
 *
 *   await browser.close()
 * })()
 *
 * @param {Object} [opts] - Options
 * @param {Set<string>} [opts.enabledEvasions] - Specify which evasions to use (by default all)
 *
 */
class StealthPlugin extends PuppeteerExtraPlugin {
  constructor(opts = {}) {
    super(opts)
    this._evasionInstances = []
  }

  get name() {
    return 'stealth'
  }

  get defaults() {
    const availableEvasions = new Set(Object.keys(EVASION_REGISTRY))
    return {
      availableEvasions,
      // Enable all available evasions by default
      enabledEvasions: new Set([...availableEvasions])
    }
  }

  /**
   * No dynamic dependencies - all evasions are statically imported and managed internally.
   * This enables bundling with tools like webpack, ncc, esbuild.
   * @private
   */
  get dependencies() {
    return new Set()
  }

  /**
   * Get all available evasions.
   *
   * @type {Set<string>} - A Set of all available evasions.
   *
   * @example
   * const pluginStealth = require('puppeteer-extra-plugin-stealth')()
   * console.log(pluginStealth.availableEvasions) // => Set { 'chrome.app', 'chrome.csi', ... }
   * puppeteer.use(pluginStealth)
   */
  get availableEvasions() {
    return this.defaults.availableEvasions
  }

  /**
   * Get all enabled evasions.
   *
   * Enabled evasions can be configured either through `opts` or by modifying this property.
   *
   * @type {Set<string>} - A Set of all enabled evasions.
   *
   * @example
   * // Remove specific evasion from enabled ones dynamically
   * const pluginStealth = require('puppeteer-extra-plugin-stealth')()
   * pluginStealth.enabledEvasions.delete('chrome.app')
   * puppeteer.use(pluginStealth)
   */
  get enabledEvasions() {
    return this.opts.enabledEvasions
  }

  /**
   * @private
   */
  set enabledEvasions(evasions) {
    this.opts.enabledEvasions = evasions
  }

  /**
   * Instantiate all enabled evasion plugins.
   * Called lazily before first use.
   * @private
   */
  _ensureEvasionsInstantiated() {
    if (this._evasionInstances.length > 0) {
      return
    }
    for (const name of this.opts.enabledEvasions) {
      const factory = EVASION_REGISTRY[name]
      if (factory) {
        this._evasionInstances.push(factory())
      }
    }
  }

  /**
   * Hook: Before browser launch.
   * Delegates to all enabled evasion plugins that have beforeLaunch.
   */
  async beforeLaunch(options) {
    this._ensureEvasionsInstantiated()
    for (const evasion of this._evasionInstances) {
      if (evasion.beforeLaunch) {
        await evasion.beforeLaunch(options)
      }
    }
  }

  /**
   * Hook: Before browser connect.
   * Delegates to all enabled evasion plugins that have beforeConnect.
   */
  async beforeConnect(options) {
    this._ensureEvasionsInstantiated()
    for (const evasion of this._evasionInstances) {
      if (evasion.beforeConnect) {
        await evasion.beforeConnect(options)
      }
    }
  }

  /**
   * Hook: When browser is available.
   * Increases max listeners and delegates to evasions.
   */
  async onBrowser(browser) {
    if (browser && browser.setMaxListeners) {
      // Increase event emitter listeners to prevent MaxListenersExceededWarning
      browser.setMaxListeners(30)
    }
    this._ensureEvasionsInstantiated()
    for (const evasion of this._evasionInstances) {
      if (evasion.onBrowser) {
        await evasion.onBrowser(browser)
      }
    }
  }

  /**
   * Hook: When a new page is created.
   * Delegates to all enabled evasion plugins that have onPageCreated.
   * Handles TargetCloseError gracefully - if page closes mid-setup, abort remaining evasions.
   */
  async onPageCreated(page) {
    this._ensureEvasionsInstantiated()
    for (const evasion of this._evasionInstances) {
      if (evasion.onPageCreated) {
        try {
          await evasion.onPageCreated(page)
        } catch (err) {
          // If target/page closed during evasion setup, abort remaining evasions
          // This prevents cascading TargetCloseError/ProtocolError noise
          if (
            err.name === 'TargetCloseError' ||
            (err.message && err.message.includes('Target closed')) ||
            (err.message && err.message.includes('Session closed'))
          ) {
            return
          }
          throw err
        }
      }
    }
  }
}

/**
 * Default export, PuppeteerExtraStealthPlugin
 *
 * @param {Object} [opts] - Options
 * @param {Set<string>} [opts.enabledEvasions] - Specify which evasions to use (by default all)
 */
const defaultExport = opts => new StealthPlugin(opts)
module.exports = defaultExport
