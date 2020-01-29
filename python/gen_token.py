APP_VERSION = '2.0.7'

import hashlib
import hmac
import optparse
import sys
import time


class FastlyTokenError(Exception):
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return ':%s' % self._text

    def _getText(self):
        return str(self)
    text = property(_getText, None, None,
        'Formatted error text.')

class FastlyTokenConfig:
    def __init__(self):
        self.ip = ''
        self.start_time = None
        self.end_time = None
        self.lifetime = 300
        self.secret = 'aabbccddeeff00112233445566778899'
        self.stream_id = ''

class FastlyToken:
    def __init__(self, ip=None, start_time=None, end_time=None,
            lifetime=None, secret=None, stream_id=None):
        self._ip = ip
        self._start_time = start_time
        self._end_time = end_time
        self._lifetime = lifetime
        self._secret = secret
        self._stream_id = stream_id

    def generateToken(self):

        #start by checking for Secret
        if self._secret is None or len(self._secret) <= 0:
            raise FastlyTokenError('You must provide a secret.')

        if self._stream_id is None:
            raise FastlyTokenError('You must provide a stream ID.')

        if str(self._start_time).lower() == 'now':
            # Initialize the start time if we are asked for a starting time of
            # now.
            self._start_time = int(time.time())
        elif self._start_time is not None:
            try:
                self._start_time = int(self._start_time)
            except:
                raise FastlyTokenError('start_time must be numeric or \'now\'')

        if self._end_time is not None:
            try:
                self._end_time = int(self._end_time)
            except:
                raise FastlyTokenError('end_time must be numeric.')

        if self._lifetime is not None:
            try:
                self._lifetime = int(self._lifetime)
            except:
                raise FastlyTokenError('lifetime must be numeric.')

        if self._end_time is not None:
            if self._start_time is not None and self._start_time >= self._end_time:
                raise FastlyTokenError('Token start time is equal to or after expiration time.')
        else:
            if self._lifetime is not None:
                if self._start_time is None:
                    self._end_time = time.time() + self._lifetime
                else:
                    self._end_time = self._start_time + self._lifetime
            else:
                raise FastlyTokenError('You must provide an expiration time '
                    '--end_time or a lifetime --lifetime.')

        hash_source = ''
        new_token = ''
        if self._ip is not None:
            new_token += 'ip=%s~' % (self._ip)

        if self._start_time is not None:
            new_token += 'st=%d~' % (self._start_time)

        new_token += 'exp=%d' % (self._end_time)

        hash_source += new_token
        hash_source += '~stream_id=%s' % (self._stream_id)

        token_hmac = hmac.new(
            self._secret,
            hash_source,
            getattr(hashlib, 'sha256')).hexdigest()

        return 'hdnts=%shmac=%s' % (new_token, token_hmac)

if __name__ == '__main__':
    usage = 'python gen_token.py [options]\n'\
            'ie.\n' \
            'python gen_token.py'
    parser = optparse.OptionParser(usage=usage, version=APP_VERSION)
    parser.add_option(
        '-l', '--lifetime',
        action='store', type='string', dest='lifetime',
        help='Token expires after SECONDS. --lifetime or --end_time is mandatory.')
    parser.add_option(
        '-e', '--end_time',
        action='store', type='string', dest='end_time',
        help='Token expiration in Unix Epoch seconds. --end_time overrides --lifetime.')
    parser.add_option(
        '-u', '--stream_id',
        action='store', type='string', dest='stream_id',
        help='STREAMID to validate the token against.')
    parser.add_option(
        '-k', '--key',
        action='store', type='string', dest='secret',
        help='Secret required to generate the token. Do not share this secret.')
    parser.add_option(
        '-s', '--start_time',
        action='store', type='string', dest='start_time',
        help='(Optional) Start time in Unix Epoch seconds. Use \'now\' for the current time.')
    parser.add_option(
        '-i', '--ip',
        action='store', type='string', dest='ip_address',
        help='(Optional) The token is only valid for this IP Address.')
    (options, args) = parser.parse_args()
    try:
        generator = FastlyToken(
            options.ip_address,
            options.start_time,
            options.end_time,
            options.lifetime,
            options.secret,
            options.stream_id)

        new_token = generator.generateToken()
        print('%s' % new_token)
    except FastlyTokenError, ex:
        print('%s\n' % ex)
        sys.exit(1)
    except Exception, ex:
        print(str(ex))
        sys.exit(1)
