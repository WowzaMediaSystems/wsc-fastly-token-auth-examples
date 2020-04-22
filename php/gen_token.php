
<?php

/**
* This code and all components (c) Copyright 2019-2020, Wowza Media Systems, LLC. All rights reserved.
* This code is licensed pursuant to the BSD 3-Clause License.
*/

class TokenAuth_ParameterException extends Exception {
}

class TokenAuth_Config {
	protected $vod_stream_id = '';
	protected $ip = '';
	protected $start_time = 0;
	protected $lifetime = 0;
	protected $end_time = 0;
	protected $stream_id = '';
	protected $secret = '';

	public function set_vod_stream_id($vod_stream_id) {$this->vod_stream_id = $vod_stream_id;}
	public function get_vod_stream_id() {return $this->vod_stream_id;}
	public function get_vod_stream_id_field() {
		if ( strcasecmp($this->vod_stream_id, '') != 0 ) {
			return 'vod='.$this->vod_stream_id.'~';
		}
		return "";
	}

	public function set_ip($ip) {$this->ip = $ip;}
	public function get_ip() {return $this->ip;}
	public function get_ip_field() {
		if ( strcasecmp($this->ip, '') != 0 ) {
			return 'ip='.$this->ip.'~';
		}
		return '';
	}

	public function set_start_time($start_time) {
    if ( strcasecmp($start_time, "now") == 0 ) {
        $this->start_time = time();
    } else {
        if ( is_numeric($start_time) ) {
            $this->start_time = 0+$start_time;
        } else {
            throw new TokenAuth_ParameterException("start time input invalid or out of range");
        }
    }
	}
	public function get_start_time() {return $this->start_time;}
	protected function get_start_time_value() {
		if ( $this->start_time ) {
			return $this->start_time;
		} else {
			return time();
		}
	}
	public function get_start_time_field() {
    if ( is_numeric($this->start_time) && $this->start_time > 0 && $this->start_time < 4294967295 ) {
        return 'st='.$this->get_start_time_value().'~';
    } else {
        return '';
    }
	}

	public function set_lifetime($lifetime) {
		// verify lifetime is sane
		if ( is_numeric($lifetime) && $lifetime > 0 ) {
			$this->lifetime = 0+$lifetime; // faster then intval
		} else {
			throw new TokenAuth_ParameterException("lifetime input invalid");
		}
	}
	public function get_lifetime() {return $this->lifetime;}

  public function set_end_time($end_time) {
    // verify endtime is sane
    if ( is_numeric($end_time) && $end_time > 0 && $end_time < 4294967295 ) {
        $this->end_time = 0+$end_time; // faster than intval
    } else {
        throw new TokenAuth_ParameterException("end time input invalid or out of range");
    }
	}
  public function get_end_time() {return $this->end_time;}
	public function get_expr_field() {
    //need to implement ruby logic - check if end_time is there first, otherwise use lifetime to calculate it
		if ( $this->get_end_time() ) {
			if ( $this->get_start_time() && ($this->get_start_time() >= $this->get_end_time()) ) {
				throw new TokenAuth_ParameterException('Token start time is equal to or after expiration time.');
			} else {
				return 'exp='.$this->get_end_time().'~';
			}
		} else {
			if ( $this->get_lifetime() ) {
				if ( $this->get_start_time_value() ) {
					return 'exp='.($this->get_start_time_value()+$this->get_lifetime()).'~';
				} else {
					return 'exp='.(time()+$this->get_lifetime()).'~';
				}
			} else {
				throw new TokenAuth_ParameterException('You must provide an expiration time --end_time or a lifetime --lifetime. See --help for further info.');
			}
		}
	}

	public function set_stream_id($stream_id) {$this->stream_id = $stream_id;}
	public function get_stream_id() {return $this->stream_id;}
	public function get_stream_id_field() {
		if ($this->stream_id) {
			return 'stream_id='.$this->stream_id.'~';
		}
		return "";
	}

	public function set_secret($secret) {$this->secret = $secret;}
	public function get_secret() {return $this->secret;}

}

class TokenAuth_Generate {

	public function generate_token($config) {

    $m_token = $config->get_vod_stream_id_field();
    $m_token .= $config->get_ip_field();
		$m_token .= $config->get_start_time_field();
		$m_token .= $config->get_expr_field();
    $m_token_digest = $m_token;
		$m_token_digest .= $config->get_stream_id_field();

    if ( strcasecmp($config->get_secret(), '') == 0 ) {
      throw new TokenAuth_ParameterException('You must provide a secret.');
    }
		if ( strcasecmp($config->get_stream_id(), '') == 0 ) {
			throw new TokenAuth_ParameterException('You must provide a stream ID.');
		}

		$signature = hash_hmac('sha256', rtrim($m_token_digest, '~'), $config->get_secret());
		return 'hdnts='.$m_token.'hmac='.$signature;
	}
}


// CLI Parameter Control
if (!empty($argc) && strstr($argv[0], basename(__FILE__))) {
	define('NO_ARGS',10);
	define('INVALID_OPTION',11);
	$long_opts = array( 'help', 'lifetime::', 'starttime::', 'ip::', 'endtime::', 'streamid:',
			'secret:', "vodstreamid::");
	$opts = getopt('hs::e::l::u:k:i::v::', $long_opts);

	if (!empty($opts)) {
		$c = new TokenAuth_Config();
		$g = new TokenAuth_Generate();
		foreach ($opts as $o => $v) {
			if (($o == 'help') || ($o == 'h')) {
								print "gen_token: A short script to generate valid authentication tokens for
Fastly stream targets in Wowza Streaming Cloud.

To access to a protected stream target, requests must provide
a parameter block generated by this script, otherwise the request
will be blocked.

Any token is tied to a specific stream id and has a limited lifetime.
Optionally, additional parameters can be factored in, for example the
client's IP address, or a start time denoting from when on the token is valid.
See below for supported values. Keep in mind that the stream target
configuration has to match these optional parameters in some cases.

Examples:

# Generate a token that is valid for 1 hour (3600 seconds)
# and protects the stream id YourStreamId with a secret value of
# demosecret123abc
php gen_token.php -l3600 -u YourStreamId -k demosecret123abc
hdnts=exp=1579792240~hmac=efe1cef703a1951c7e01e49257ae33487adcf80ec91db2d264130fbe0daeb7ed

# Generate a token that is valid from 1578935505 to 1578935593
# seconds after 1970-01-01 00:00 UTC (Unix epoch time)
php gen_token.php -s1578935505 -e1578935593 -u YourStreamId -k demosecret123abc
hdnts=st=1578935505~exp=1578935593~hmac=aaf01da130e5554eeb74159e9794c58748bc9f6b5706593775011964612b6d99

# Generate a token that is valid from 1578935505 to 1578935593
# seconds after 1970-01-01 00:00 UTC (Unix epoch time)
# with VOD_STREAM_ID = YOURVOD
php gen_token.php -s1578935505 -e1578935593 -u YourStreamId -k demosecret123abc -vYourVOD
hdnts=vod=YourVOD~st=1578935505~exp=1578935593~hmac=722d989e175ac0c288603e44d552ab5d11cb1b86077657ee867adcfded7cb0f8";
                print "\n";
                print "-lLIFETIME_SECONDS, --lifetime=LIFETIME_SECONDS	Token expires after SECONDS. --lifetime or --end_time is mandatory.\n";
                print "-eEND_TIME, --endtime=END_TIME	Token expiration in Unix Epoch seconds. --end_time overrides --lifetime.\n";
                print "-u STREAM_ID, --streamid=STREAM_ID	STREAMID required to validate the token against.\n";
                print "-vVOD_STREAM_ID, --vodstreamid=VOD_STREAM_ID	VODSTREAMID required to validate the token against.\n";
                print "-k SECRET, --key=SECRET	Secret required to generate the token. Do not share this secret.\n";
                print "-sSTART_TIME, --starttime=START_TIME	(Optional) Start time in Unix Epoch seconds. Use 'now' for the current time.\n";
                print "-iIP_ADDRESS, --ip=IP_ADDRESS	(Optional) The token is only valid for this IP Address.\n";
								print "-h --help	Display this help info\n";
                exit(0);
			} elseif (($o == 'lifetime=') || ($o == 'l')) {
				$c->set_lifetime($v);
			} elseif (($o == 'starttime=') || ($o == 's')) {
				$c->set_start_time($v);
			} elseif (($o == 'ip=') || ($o == 'i')) {
				$c->set_ip($v);
			} elseif (($o == 'endtime=') || ($o == 'e')) {
				$c->set_end_time($v);
			} elseif (($o == 'streamid=') || ($o == 'u')) {
				$c->set_stream_id($v);
			} elseif (($o == 'vodstreamid=') || ($o == 'v')) {
				$c->set_vod_stream_id($v);
			} elseif (($o == 'secret') || ($o == 'k')) {
				$c->set_secret($v);
			}
		}
		$token = $g->generate_token($c);
		print "\n$token\n";
	}
}

?>
