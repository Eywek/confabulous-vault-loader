var debug = require('debug')('confabulous:loaders:vault')
var EventEmitter = require('events').EventEmitter
var request = require('request')
var async = require('async')
var duration = require('parse-duration')
var merge = require('lodash.merge')
var contains = require('lodash.contains')
var format = require('util').format
var crypto = require('crypto')

module.exports = function (_options, postProcessors) {
  if (_options && _options.path && !_options.paths) {
    _options.paths = [_options.path]
  }
  var options = merge({}, { mandatory: true, keepPaths: false, watch: false, request: { json: true, timeout: 10000, gzip: true, forever: false, headers: {} } }, _options)
  var exists = false
  var allowedResponseCodes = [200].concat(options.mandatory ? [] : 404)
  var checksums = new Map()
  var emitter = new EventEmitter()

  return function (confabulous, cb) {
    debug('running')
    setImmediate(function () {
      async.waterfall([validate, authenticate, watch, load], function (err, results) {
        if (err) return cb(err)
        results = Object.assign({}, ...results)
        if (!options.keepPaths) {
          results = Object.assign({}, ...Object.values(results))
        }
        async.seq.apply(async, postProcessors)(results, cb)
      })
    })
    return emitter

    function validate (cb) {
      debug('validate: %s', JSON.stringify(options))
      if (options.mandatory && !options.url) return cb(new Error('url is required'))
      if (options.mandatory && !options.paths) return cb(new Error('paths is required'))
      if (options.mandatory && !options.method) return cb(new Error('method is required'))
      if (options.method === 'app-id' && !options.appId) return cb(new Error('appId is required'))
      if (options.method === 'app-id' && !options.userId) return cb(new Error('userId is required'))
      if (options.method === 'token' && !options.token) return cb(new Error('token is required'))
      if (options.watch && !options.watch.interval) return cb(new Error('watch interval is required'))
      cb(!options.url || !options.paths || !options.method) // eslint-disable-line
    }

    function authenticate (cb) {
      debug('authenticate: method=%s url=%s', options.method, options.url)
      switch (options.method) {
        case 'app-id': {
          var loginUrl = options.url + '/v1/auth/app-id/login'
          post({ url: loginUrl, body: { app_id: options.appId, user_id: options.userId } }, function (err, res, body) {
            if (err) return cb(err)
            if (res.statusCode !== 200) return cb(new Error(format('%s returned %d', options.url, res.statusCode)))
            options.request.headers['X-Vault-Token'] = body.auth.client_token
            cb()
          })
          break
        }
        case 'token': {
          options.request.headers['X-Vault-Token'] = options.token
          cb()
          break
        }
        default: {
          cb(new Error(format('Unsupported authentication method: %s', options.method)))
        }
      }
    }

    function watch (cb) {
      async.each(options.paths, (path, next) => {
        var configUrl = options.url + '/v1/' + path
        debug('watch: %s, interval:%s', configUrl, options.watch.interval)
        if (!options.watch) return next()
        var watcher = setInterval(function () {
          debug('checking for changes to: %s', options.url)
          get({ url: configUrl }, function (err, res) {
            if (!watcher) return
            if (err) return emitter.emit('error', err)
            if (!contains(allowedResponseCodes, res.statusCode)) return emitter.emit('error', new Error(format('%s returned %d', configUrl, res.statusCode)))
            if ((res.statusCode === 404 && exists) || (res.statusCode === 200 && (!exists || isModified(res, path)))) emitter.emit('change')
          })
        }, duration(options.watch.interval))
        watcher.unref()
        confabulous.on('reloading', function () {
          clearInterval(watcher)
          watcher = null
        })
        return next()
      }, cb)
    }

    function load (cb) {
      async.map(options.paths, (path, next) => {
        var configUrl = options.url + '/v1/' + path
        debug('load: %s', configUrl)
        exists = false
        get({ url: configUrl }, function (err, res, body) {
          if (err) return next(err)
          if (!contains(allowedResponseCodes, res.statusCode)) return next(new Error(format('%s returned %d', configUrl, res.statusCode)))
          if (res.statusCode === 404) return next(null, { [path]: [] })
          exists = true
          checksums.set(path, generateChecksum(res.body.data))
          next(err, { [path]: body.data })
        })
      }, cb)
    }

    function get (args, cb) {
      if (arguments.length === 1) return get({}, arguments[0])
      request(merge({ method: 'GET' }, options.request, args), cb)
    }

    function post (args, cb) {
      if (arguments.length === 1) return get({}, arguments[0])
      request(merge({ method: 'POST' }, options.request, args), cb)
    }

    function isModified (res, path) {
      var newChecksum = generateChecksum(res.body.data)
      var modified = checksums.get(path) !== newChecksum
      checksums.set(path, newChecksum)
      return modified
    }

    function generateChecksum (data) {
      return crypto.createHash('md5').update(JSON.stringify(data)).digest('hex')
    }
  }
}
