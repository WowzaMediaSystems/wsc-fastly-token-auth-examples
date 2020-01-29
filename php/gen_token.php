<?php

class Fastly_EdgeAuth_ParameterException extends Exception {
}

/**
 * Class for handling the configuration of the token generator
 */
class Fastly_EdgeAuth_Config {
	protected $ip = '';
	protected $start_time = 0;
	protected $lifetime = 0;
	protected $end_time = 0;
	protected $stream_id = '';
	protected $secret = '';

	public function set_ip($ip) {
		// @TODO: Validate IPV4 & IPV6 addrs
		$this->ip = $ip;
	}
	public function get_ip() {return $this->ip;}
	public function get_ip_field() {
		if ( strcasecmp($this->ip, '') != 0 ) {
			return 'ip='.$this->ip.'~';
		}
		return '';
	}

	public function set_start_time($start_time) {
		// verify starttime is sane
    if ( strcasecmp($start_time, "now") == 0 ) {
        $this->start_time = time();
    } else {
        if ( is_numeric($start_time) && $start_time > 0 && $start_time < 4294967295 ) {
            $this->start_time = 0+$start_time; // faster than intval
        } else {
            throw new Fastly_EdgeAuth_ParameterException("start time input invalid or out of range");
        }
    }
	}
	public function get_start_time() {return $this->start_time;}
	protected function get_start_time_value() {
		if ( $this->start_time > 0 ) {
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
			throw new Fastly_EdgeAuth_ParameterException("lifetime input invalid");
		}
	}
	public function get_lifetime() {return $this->lifetime;}

  public function set_end_time($end_time) {
    // verify endtime is sane
    if ( is_numeric($end_time) && $end_time > 0 && $end_time < 4294967295 ) {
        $this->end_time = 0+$end_time; // faster than intval
    } else {
        throw new Fastly_EdgeAuth_ParameterException("end time input invalid or out of range");
    }
	}
  public function get_end_time() {return $this->end_time;}
	public function get_expr_field() {
    //need to implement ruby logic - check if end_time is there first, otherwise use lifetime to calculate it
    if ( $this->get_end_time() == 0 ) {
      if( $this->get_lifetime() == 0 ) {
        throw new Fastly_EdgeAuth_ParameterException('You must provide an expiration time --end_time or a lifetime --lifetime. See --help for further info.');
      } else {
        return 'exp='.($this->get_start_time_value()+$this->lifetime).'~';
      }
    } else {
      if ( $this->get_end_time() <= $this->get_start_time() ){
        throw new Fastly_EdgeAuth_ParameterException('Token start time is equal to or after expiration time.');
      } else {
        return 'exp='.($this->get_end_time()).'~';
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

class Fastly_EdgeAuth_Generate {

	public function generate_token($config) {
		// ASSUMES:($ip='', $start_time=null, $lifetime=0, $end_time=0, $stream_id="", $secret="")

    $m_token = $config->get_ip_field();
		$m_token .= $config->get_start_time_field();
		$m_token .= $config->get_expr_field();
    $m_token_digest = $m_token;
		$m_token_digest .= $config->get_stream_id_field();
		//$m_token_digest = (string)$m_token;
    if ( strcasecmp($config->get_secret(), '') == 0 ) {
      throw new Fastly_EdgeAuth_ParameterException('You must provide a secret.');
    }
		// produce the signature and append to the tokenized string
		$signature = hash_hmac('sha256', rtrim($m_token_digest, '~'), $config->get_secret());
		return 'hdnts='.$m_token.'hmac='.$signature;
	}
}


// CLI Parameter Control
if (!empty($argc) && strstr($argv[0], basename(__FILE__))) {
	// bring in getopt and define some exit codes
	define('NO_ARGS',10);
	define('INVALID_OPTION',11);
	// parse args to opts
	$long_opts = array( 'help', 'lifetime:', 'start-time:', 'ip:', 'end-time:', 'stream-id:',
			'secret:', 'debug',);
	$opts = getopt('h:s:e:l:u:k:i:', $long_opts);
	// Check the options are valid

	if (!empty($opts)) {
		$c = new Fastly_EdgeAuth_Config();
		$g = new Fastly_EdgeAuth_Generate();
		foreach ($opts as $o => $v) {
			if (($o == 'help') || ($o == 'h')) {
				//@TODO
                print "php gen_token.php [options]\n";
                print "ie.\n";
                print "php gen_token.php --start:now --lifetime:86400\n";
                print "\n";
                print "-l LIFETIME_SECONDS, --lifetime=LIFETIME_SECONDS\n";
                print "                    How long is this token valid for?\n";
                print "-e END_TIME, --end-time=END_TIME     Token expiration in Unix Epoch seconds.\n";
                print "                    --end_time overrides --lifetime.\n";
                print "-u STREAM_ID, --stream_id=STREAM_ID\n";
                print "                    STREAMID required to validate the token against.\n";
                print "-k SECRET, --key=SECRET           Secret required to generate the token.\n";
                print "-s START_TIME, --start-time=START_TIME       (Optional) What is the start time. (Use now for the current time)\n";
                print "-i IP_ADDRESS, --ip=IP_ADDRESS     (Optional) IP Address to restrict this token to.\n";
                exit(0);
			} elseif (($o == 'lifetime=') || ($o == 'l')) {
				$c->set_lifetime($v);
			} elseif (($o == 'start-time=') || ($o == 's')) {
				$c->set_start_time($v);
			} elseif (($o == 'ip=') || ($o == 'i')) {
				$c->set_ip($v);
			} elseif (($o == 'end-time=') || ($o == 'e')) {
				$c->set_end_time($v);
			} elseif (($o == 'stream-id=') || ($o == 'u')) {
				$c->set_stream_id($v);
			} elseif (($o == 'secret') || ($o == 'k')) {
				$c->set_secret($v);
			} elseif ($o == 'debug') {
				//@TODO
			}
		}
		$token = $g->generate_token($c);
		print "\n$token\n";
	}
}

?>
