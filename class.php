<?php

/*
 * Some kind of pseudohash table.
 */
class by {
	function __construct() {
		$this->fd = array();
		$this->remotenumeric = array();
		$this->chan = array();
		$this->server = array();
		return;
		// This function gets initiated once.
	}
	
	function addlocalfd($fd,aClient &$struct) {
		$this->fd[(int)$fd] = &$struct;
	}
	
	function addnumeric($servnum,$clinum,aClient &$struct) {
		$this->remotenumeric[$servnum][$clinum] = &$struct;
	}
	
	function addchannel($channame,Channel &$chan) {
		$this->chan[$channame] = &$chan;
	}
	
	function addserver($servnum,aClient &$struct) {
		$this->server[$servnum] = &$struct;
	}
}

/*
 * Welcome to my worst nightmare.
 * 
 * CaffeineIRCd has a channels system in which all channels are registered on create.
 * This can only work, however, if the aClient in question has a client certificate.
 * 
 */

class Channel {
	public $name, $ts, $owner, $memb, $privs;
	
	function __construct(
		string $name,
		float $ts,
		string $owner,
		array $memb
	) {
		// Constructing a new channel class.
		// Welcome to my worst daymare.
		$this->name = $name;
		$this->ts = $ts;
		$this->owners[] = $owner; // Is "0" if the newly crowned op doesn't have a certfp
		// Channel privileges are a bitmask in the Privilege.
		$this->memb = $memb;
		$this->lsmode = array();
	}
	
	function addMember(
		Membership &$memb
	) {
		$this->memb[] = &$memb;
	}
	
	function addPrivilege(
		string $certfp,
		Privilege &$priv
	) {
		$this->privs[$certfp] = &$priv;
	}
}

class Membership {
	function __construct(
		aClient &$member,
		Privilege &$privilege
	) {
		$this->member = &$member;
		$this->privileges = &$privilege;
	}
}

class Privilege {
	/*
	 * A Privilege class is just a fancy way of defining channel modes using a bitmask.
	 */
	function __construct(
		int $bitmask,
		string $extbanmask
	) {
		
	}
}


// Generic connection class.
// Requires a specific connection class referenced inside it.
class aClient {
	function __construct($ts, $numeric, aServer &$servptr, &$uptr) {
		$this->ts = $ts;
		$this->fp = $fp;
		if (get_class($uptr) == "anUser") $this->user =& $uptr; // a "user" is any client, including servers
		else $this->server =& $uptr;
		$this->numeric = $numeric;
		$this->servptr = &$servptr;
		// server is used if server, otherwise user is used.
		$this->cert = GetCert();
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
		$this->servptr = &$servptr;
	}
}

class anUser {
	function __construct($nick,$ident,$host,$dhost=NULL) {
		$this->nick = $nick;
		$this->ident = $ident;
		$this->host = $host;
		$this->sockhost = $host;
		$this->dhost = ($dhost)?$dhost:$host;
	}
	
	function chghost($newhost) {
		// This function should be used after a change in fakehost
		$this->dhost = $newhost;
	}
	
	function chgrealhost($newhost) {
		// The SockHost is always saved.
		// ONLY EVER TO BE USED AFTER A SUCCESSFUL SPOOF AUTH
		$this->host = $newhost;
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
