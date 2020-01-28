APP_VERSION = '2.0.7'

import binascii
import hashlib
import hmac
#might need to use argparse
import optparse
import os
import re
import sys
import time
import urllib
import time

# Force the local timezone to be GMT.
os.environ['TZ'] = 'GMT'
time.tzset()

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

#     def _parseQueryStrings(self):
#         '''
# Query String Parameters:
# secret -- Secret required to generate the token.
# stream_id -- The session identifier for single use tokens or other advanced cases.
# end_time -- When does this token expire? end_time overrides lifetime
# lifetime -- How long is this token valid for?
# ip -- (Optional) IP Address to restrict this token to.
# start_time -- (Optional) What is the start time? (Use now for the current time)
#
# Use + for embedded spaces in query string parameters.
#         '''
#         param_list = self._query_strings.split('&')
#         for param in param_list:
#             if '=' in param:
#                 (key, value) = param.split('=')
#                 if key == 'ip':
#                     self._ip = value
#                 elif key == 'start_time':
#                     self._start_time = value
#                 elif key == 'end_time':
#                     self._end_time = value
#                 elif key == 'lifetime':
#                     self._lifetime = value
#                 elif key == 'secret':
#                     self._secret = value
#                 elif key == 'stream_id':
#                     self._stream_id = value
#             elif 'escape_early' in param:
#                 self._escape_early = True
#             elif 'escape_early_upper' in param:
#                 self._escape_early_upper = True

    def generateToken(self):
        #print(self._start_time, self._end_time, self._stream_id, self._lifetime, self._ip, self._secret)

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

        new_token += 'exp=%d~' % (self._end_time)

        hash_source += new_token
        hash_source += 'stream_id=%s' % (self._stream_id)

        token_hmac = hmac.new(
            binascii.a2b_hex(self._secret),
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
