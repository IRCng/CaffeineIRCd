<?php

class aClient {
	function __construct($nick, $ident, $host, $dhost, $numeric, aServer &$servptr) {
		$this->nick = $nick;
		$this->ident = $ident;
		$this->host = $host;
		$this->dhost = $dhost;
		$this->user = new anUser($nick,$ident,$host,$dhost);
		$this->numeric = $numeric;
		$this->servptr = &$servptr;
	}
	
	function __invoke($detail) {
		return $this->{$detail};
	}
	
	function __toString() {
		return protocolEnc($this);
	}
	
	function update($detail,$newval) {
		$this->{$detail} = $newval;
	}
}

class aServer {
	function __construct($name, $numeric, aServer &$servptr, $fp) {
		$this->name = $name;
		$this->numeric = $numeric;
		$this->fp = $fp; // Is 0 if this server.
		$this->servptr = &$servptr;
	}
}

class anUser {
	function __construct($nick,$ident,$host,$dhost) {
		$this->nick = $nick;
		$this->ident = $ident;
		$this->host = $host;
		$this->dhost = ($dhost)?$dhost:$host;
	}
	
	function __invoke($utype,$dtype = DTYPE_ARRAY) {
		foreach ($this as $type => $data) {
			if ($utype & ~TYPE_OPER) if (strtolower($type) == "host") $ret["host"] = $this->dhost;
			if ($type[0] == "_") continue;
			if (!(strtolower($type) == "host") or ($utype & ~TYPE_OPER)) $ret[$type] = $data;
		}
		return ($dtype & DTYPE_RFC2812)?sprintf("%s!%s@%s",$ret["nick"],$ret["user"],$ret["host"]):$ret;
	}
}
