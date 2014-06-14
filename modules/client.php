<?php

class client {
	function __construct() {
		$GLOBALS["callbacks"]["%new%"][] = array($this,"accept");
		$GLOBALS["callbacks"]["%exit%"][] = array($this,"unaccept");
		return;
	}
	
	function accept($fd) {
		$GLOBALS["mods"]["%fdtype%"][(int)$fd] = TYPE_UNREGISTERED;
		$GLOBALS["callbacks"]["%input%"][(int)$fd][] = array($this, "p");
	}
	
	function unaccept($fd) {
		unset($GLOBALS["mods"]["%fdtype%"][(int)$fd],$GLOBALS["callbacks"]["%input%"][(int)$fd],$GLOBALS["state"]["%clients%"]["local"][(int)$fd]);
	}
	
	function operup($fd) {
		$GLOBALS["mods"]["%fdtype%"][(int)$fd] &= ~TYPE_UNREGISTERED;
		$GLOBALS["mods"]["%fdtype%"][(int)$fd] |= TYPE_OPER;
	}
	
	function jsonup($fd) {
		$GLOBALS["mods"]["%fdtype%"][(int)$fd] |= TYPE_JSON;
	}
	
	function jsondown($fd) {
		$GLOBALS["mods"]["%fdtype%"][(int)$fd] &= ~TYPE_JSON;
	}
	
	function userreg($fd) {
		$GLOBALS["mods"]["%fdtype%"][(int)$fd] &= ~TYPE_UNREGISTERED;
		$GLOBALS["mods"]["%fdtype%"][(int)$fd] |= TYPE_CLIENT;
		$motd = file_get_contents($GLOBALS["conf"]["me"]["motdfile"]);
		if ($GLOBALS["mods"]["%fdtype%"][(int)$fd] & TYPE_JSON) {
			$data = array(
				"source"=>
				array(
					"server"=>$GLOBALS["conf"]["me"]["name"]
				),
				"cmd"=>"MYMOTD",
				"isupport"=>array(
					"MINPROTOVER"=>"1000/RFC1459", "MAXPROTOVER"=>"1001/JSON"
				),
				"motd"=>$motd,
				"yourcert"=>GetCert($fd)
			);
			$this->sendto_one($fd,$data);
			// Handle the new case first.
		} else {
			foreach (explode("\n",$motd) as $line) {
				$this->legacy_sendto_one($fd,$GLOBALS["conf"]["me"]["name"],"MOTD",array("*"),$line);
			}
			$this->legacy_sendto_one($fd,$GLOBALS["conf"]["me"]["name"],"ISUPPORT",array("MINPROTOVER=1000/RFC1459","MAXPROTOVER=1001/JSON"),"are my supported features");
			// Handle the old case
		}
	}
	
	function srvreg($fd) {
		$GLOBALS["mods"]["%fdtype%"][(int)$fd] &= ~TYPE_UNREGISTERED;
		$GLOBALS["mods"]["%fdtype%"][(int)$fd] |= TYPE_SERVER;
		$this->sendburst($fd);
	}
	
	function p($fd,$data) {
		$protocolver = ($data[0] == "{")?1:0;
		if (!$protocolver) {
			$this->jsondown($fd);
			$data = oldParse($data);
		}
		if ($protocolver) $data = protocolParse($data);
		$data["__protover"] = $protocolver; //Serves the client right if they use magic keys
		if (isset($data[0])) $data["cmd"] = $data[0]; // The user can specify 0: rather than "cmd":;
		// this is not a problem except for the user (protoctl messages)
		if ($GLOBALS["mods"]["%fdtype%"][(int)$fd] & TYPE_UNREGISTERED) {
			switch ($data["cmd"]) {
				case "USER":
					$this->m_introduce($fd,$data);
				break;
				case "SERVER":
					$this->serv_introduce($fd,$data);
				break;
				case "PROTOCTL":
					$this->mr_protoctl($fd,$data);
				break;
			}
		}
		
		if ($GLOBALS["mods"]["%fdtype%"][(int)$fd] & TYPE_CLIENT) {
			switch ($data["cmd"]) {
				case "PRIVMSG":
					$this->m_privmsg($fd,$data);
					break;
				case "NOTICE":
					$this->m_notice($fd,$data);
					break;
				case "PROTOCTL":
					$this->m_protoctl($fd,$data);
					break;
			}
		}
		
		if ($GLOBALS["mods"]["%fdtype%"][(int)$fd] & TYPE_OPER) {
		}
		
		if ($GLOBALS["mods"]["%fdtype%"][(int)$fd] & TYPE_SERVER) {
			switch ($data["cmd"]) {
				case "CLIENT":
					$this->ms_client($fd,$data);
					break;
			}
		} 
	}
	
	function m_privmsg($fd,$d) {
		if (!$d["dest"]) $d["dest"] = $d[1];
		$this->m_message($fd,$d["dest"],$data);
	}
	
	function m_message($fd,$dest,$data) {
		if ($dest[0] == "#") $type = DEST_CHANNEL;
		
	}
	
	function mr_protoctl($fd,$d) {
		$m = $d["__protover"];
		// PROTOCTL:
		// parv[src] = should be NULL (we're an mr_*) but we ignore anyway
		// parv[0/cmd] = command
		// parv[1/protover] = protocol version
		// parv[2/extensions] = unused, will soon be protocol extensions (like client encap)
		// parv[3/message] = Only sent from server, message is the human readable message.
		$protover = ($m)?$d["protover"]:$d[1]; // Fairly simple comparison, eh?
		// The Upgrade:
		// If $protover includes TYPE_JSON, we upgrade their protocol.
		// This isn't useful, but serves to mark a user as
		// a JSON user (say, if we ever implement WHOIS, it will have that)
		// $protover is a bitmask of PROTOCTL flags
		if ($protover & TYPE_JSON) {
			$this->jsonup($fd);
			$this->legacy_sendto_one($fd,$GLOBALS["conf"]["me"]["name"],"PROTOCTL",array($protover),"JSON protocol enabled. Go ahead with USER message.");
		}
	}
	
	function m_protoctl($fd,$d) {
		$m = $d["__protover"];
		// PROTOCTL:
		// parv[src] = should be NULL (we're an m_*) but we ignore anyway
		// parv[0/cmd] = command
		// parv[1/protover] = protocol version
		// parv[2/extensions] = unused, will soon be protocol extensions (like client encap)
		// parv[3/message] = Only sent from server, message is the human readable message.
		$protover = ($m)?$d["protover"]:$d[1]; // Fairly simple comparison, eh?
		// The Upgrade:
		// If $protover includes TYPE_JSON, we upgrade their protocol.
		// This isn't useful, but serves to mark a user as
		// a JSON user (say, if we ever implement WHOIS, it will have that)
		// $protover is a bitmask of PROTOCTL flags
		if ($protover & TYPE_JSON) {
			$this->jsonup($fd);
			$this->legacy_sendto_one($fd,$GLOBALS["conf"]["me"]["name"],"PROTOCTL",array($protover),"JSON protocol enabled. Go ahead with JSON protocol use.");
		}
	}
	
	function m_introduce($fd,$d) {
		$m = $d["__protover"];
		global $state, $by;
		$sockname = $GLOBALS["mods"]["%sockname%"][(int)$fd];
		$send = array();
		if (!washclinick($d[($m)?"nick":0])) return; // Let's not warn :P
		$send["cmd"] = "CLIENT";
		$send["ts"]  = microtime(true);
		$send["nick"] = $d[($m)?"nick":0];
		$send["ident"] = $d[($m)?"ident":1];
		$send["host"] = $sockname;
		$send["num"] = (int)$fd;
		$data["uplink"] = $by->fd[0];
		$send["uplink"] = $by->fd[0]->server->name;
		$this->sendto_all_type(TYPE_OPER|TYPE_SERVER,$send);
		$this->userreg($fd);
	}
	
	function ms_client($fd,$d) {
		global $state;
		$send = array();
		if (!washservnick($d["nick"])) return; // Let's not warn :P
		$send["cmd"] = "CLIENT";
		$send["ts"]  = $d["ts"];
		// Nick collision time.
		// If we know of a $d["nick"], we should check the TSes.
		// If ours is lower, kill theirs.
		// Todo: Server TS
		$send["nick"] = $d["nick"];
		$send["ident"] = $d["ident"];
		$send["host"] = $d["host"];
		$send["dhost"] = $d["dhost"];
		$send["num"] = (int)$fd;
		$send["uplink"] = $state["%servers%"]["fd"];
		$this->sendto_allbutone_type($fd,TYPE_OPER|TYPE_SERVER,$send);
	}
	
	function serv_introduce($fd,$d) {
		$sockname = $GLOBALS["mods"]["%sockname%"][(int)$fd];
		$send = array();
		$send["cmd"] = "SERVER";
	}
	
	function legacy_sendto_one($fd,$source,$command,$args,$payload) {
		/*
		 * Reason we're not compatible with new sendto_one/all/etc:
		 *   Protocol
		 * 
		 * We're gonna change this up a lil.
		 */
		$arg = implode(" ",$args);
		$GLOBALS["socket"]->write($fd,sprintf(":%s %s %s :%s",$source,$command,$arg,$payload));
	}
	
	function legacy_sendto_channel($channel,$source,$command,$args,$payload) {
		/*
		 * Reason we're not compatible with new sendto_one/all/etc:
		 *   Protocol
		 * 
		 * We're gonna change this up a lil.
		 */
		$arg = implode(" ",$args);
		foreach ($this->memb[$channel]["local"] as $luser)
			$GLOBALS["socket"]->write($luser,sprintf(":%s %s %s :%s",$source,$command,$arg,$payload));
		foreach ($this->memb[$channel]["remote"] as $ruser)
			$GLOBALS["socket"]->write($ruser->servptr["fd"],sprintf(":%s %s %s :%s",$source,$command,$arg,$payload));
	}
	
	function sendto_channel($channel,$data) {
		/*
		 * Reason we're not compatible with new sendto_one/all/etc:
		 *   Protocol
		 * 
		 * We're gonna change this up a lil.
		 */
		$arg = implode(" ",$args);
		foreach ($this->memb[$channel]["local"] as $luser)
			$GLOBALS["socket"]->write($luser,protocolEnc($data));
		foreach ($this->memb[$channel]["remote"] as $ruser)
			$GLOBALS["socket"]->write($ruser->servptr["fd"],protocolEnc($data));
	}
	
	function legacy_sendto_allbutone_type($one,$type,$source,$command,$args,$payload) {
		/*
		 * Reason we're not compatible with new sendto_one/all/etc:
		 *   Protocol
		 * 
		 * We're gonna change this up a lil.
		 */
		$arg = implode(" ",$args);
		foreach ($GLOBALS["mods"]["%socket%"] as $fd) {
			if ($GLOBALS["mods"]["%fdtype%"][(int)$fd] & $type) {
				$GLOBALS["socket"]->write($fd,sprintf(":%s %s %s :%s",$source,$command,$arg,$payload));
			}
		}
	}
	
	function sendto_all_type($type,$data) {
		foreach ($GLOBALS["mods"]["%socket%"] as $fd) {
			if ($GLOBALS["mods"]["%fdtype%"][(int)$fd] & $type) {
				$GLOBALS["socket"]->write($fd,protocolEnc($data));
			}
		}
	}
	
	function sendto_one($one,$data) {
		$fd = $one;
		if ($one["fd"]) $fd = $one["fd"];
		$GLOBALS["socket"]->write($fd,protocolEnc($data));
	}
	
	function sendto_allbutone_type($type,$one,$data) {
		foreach ($GLOBALS["mods"]["%socket%"] as $fd) {
			if ($GLOBALS["mods"]["%fdtype%"][(int)$fd] & $type) {
				if ($fd != $one["fd"])
					$GLOBALS["socket"]->write($fd,protocolEnc($data));
			}
		}
	}
}
