'use strict'
const crypto = require('crypto')
const program = require('commander');

class EdgeAuth {
    constructor(options) {
        this.options = options

        if (!this.options.secret) {
            throw new Error('Secret must be provided to generate a token.')
        }

        if(!this.options.streamId) {
          throw new Error('Stream ID must be provided to generate a token.')
        }

    }

    _generateToken() {
        var startTime = this.options.startTime
        var endTime = this.options.endTime

        if (typeof startTime === 'string' && startTime.toLowerCase() === 'now') {
            startTime = parseInt(Date.now() / 1000)
        } else if (startTime) {
            if (typeof startTime === 'number' && startTime <= 0) {
                throw new Error('startTime must be number ( > 0 ) or "now"')
            }
        }

        if (typeof endTime === 'number' && endTime <= 0) {
            throw new Error('endTime must be number ( > 0 )')
        }

        if (typeof this.options.lifetimeSeconds === 'number' && this.options.lifetimeSeconds <= 0) {
            throw new Error('lifetimeSeconds must be number( > 0 )')
        }

        if (!endTime) {
            if (this.options.lifetimeSeconds) {
                if (!startTime) {
                    startTime = parseInt(Date.now() / 1000)
                }
                endTime = parseInt(startTime) + parseInt(this.options.lifetimeSeconds)
            } else {
                throw new Error('You must provide endTime or lifetimeSeconds')
            }
        }

        if (startTime && (endTime < startTime)) {
            throw new Error('Token will have already expired')
        }

        if (this.options.verbose) {
            console.log("Fastly Token Generation Parameters")

            console.log("    Key/Secret      : " + this.options.secret)
            console.log("    IP              : " + this.options.ip)
            console.log("    Stream ID      : " + this.options.streamId)
            console.log("    Start Time      : " + startTime)
            console.log("    Lifetime(seconds) : " + this.options.lifetimeSeconds)
            console.log("    End Time        : " + endTime)
        }

        var hashSource = []
        var newToken = []

        if (this.options.ip) {
            newToken.push("ip=" + this.options.ip)
        }

        if (this.options.startTime) {
            newToken.push("st=" + startTime)
        }
        newToken.push("exp=" + endTime)

        hashSource = newToken.slice()

        hashSource.push("stream_id=" + this.options.streamId)

        var hmac = crypto.createHmac(
            'sha256',
            this.options.secret
        )

        hmac.update(hashSource.join('~'))
        newToken.push("hmac=" + hmac.digest('hex'))

        return newToken.join('~')
    }

}

module.exports = EdgeAuth
////////////////////////
// END lib/edgeauth.js
////////////////////////

program
	.version('0.1.1')
	.option('-l, --lifetime <n>', 'Token expires after SECONDS. --lifetime or --end_time is mandatory.')
  .option('-e, --end_time <n>', 'Token expiration in Unix Epoch seconds. --end_time overrides --lifetime.')
	.option('-u, --stream_id [value]', 'STREAMID to validate the token against.')
  .option('-k, --key [value]', 'Secret required to generate the token. Do not share this secret.')
  .option('-s, --start_time [value]', "(Optional) Start time in Unix Epoch seconds. Use 'now' for the current time.")
  .option('-i, --ip [value]', '(Optional) The token is only valid for this IP Address.')
	.parse(process.argv);

var ea = new EdgeAuth({
	secret: program.key,
	startTime: program.start_time,
	endTime: program.end_time,
	lifetimeSeconds: program.lifetime,
	ip: program.ip,
	streamId: program.stream_id
})


var token

token = ea._generateToken()

console.log("")
console.log(`hdnts=${token}`)
