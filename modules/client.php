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
				"motd"=>$motd
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
		if (!$protocolver) $this->jsondown($fd);
		$data = oldParse($data);
		if ($data[0] == "{") $data = protocolParse($data);
		$data["__protover"] = $protocolver; //Serves the client right if they use magic keys
		
		if ($GLOBALS["mods"]["%fdtype%"][(int)$fd] & TYPE_UNREGISTERED) {
			if (isset($data[0])) $data["cmd"] = $data[0]; // The user can specify 0: rather than "cmd":;
			// this is not a problem except for the user (protoctl messages)
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
			$this->legacy_sendto_one($fd,$GLOBALS["conf"]["me"]["name"],"PROTOCTL",array($protover),"JSON protocol enabled. Go ahead with USER message. If you are not capable of sending JSON protocol but you can understand it, most commands will accept the old format (COMMAND ARGS :PAYLOAD)");
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
			$this->legacy_sendto_one($fd,$GLOBALS["conf"]["me"]["name"],"PROTOCTL",array($protover),"JSON protocol enabled. Go ahead with USER message. If you are not capable of sending JSON protocol but you can understand it, most commands will accept the old format (COMMAND ARGS :PAYLOAD)");
		}
	}
	
	function m_introduce($fd,$d) {
		$m = $d["__protover"];
		$sockname = $GLOBALS["mods"]["%sockname%"][(int)$fd];
		$send = array();
		if (!washclinick($d[($m)?"nick":0])) return; // Let's not warn :P
		$send["cmd"] = "CLIENT";
		$send["ts"] = $GLOBALS["state"]["%clients%"]["local"][(int)$fd]["ts"] = microtime(true);
		$send["nick"] = $GLOBALS["state"]["%clients%"]["local"][(int)$fd]["nick"] = $d[($m)?"nick":0];
		$send["ident"] = $GLOBALS["state"]["%clients%"]["local"][(int)$fd]["ident"] = $d[($m)?"ident":1];
		$send["host"] = $GLOBALS["state"]["%clients%"]["local"][(int)$fd]["host"] = $sockname;
		$send["num"] = $GLOBALS["state"]["%clients%"]["local"][(int)$fd]["num"] = (int)$fd;
		$send["server"] = $GLOBALS["state"]["%clients%"]["local"][(int)$fd]["server"] = $GLOBALS["conf"]["me"]["numeric"];
		$this->sendto_all_type(TYPE_OPER|TYPE_SERVER,$send);
		$this->userreg($fd);
	}
	
	function ms_introduce($fd,$d) {
		$sockname = $GLOBALS["mods"]["%sockname%"][(int)$fd];
		$send = array();
		if (!washservnick($d["nick"])) return; // Let's not warn :P
		$send["cmd"] = "CLIENT";
		$send["ts"] = $GLOBALS["state"]["%servers%"]["local"][(int)$fd]["ts"] = microtime(true);
		$send["nick"] = $GLOBALS["state"]["%servers%"]["local"][(int)$fd]["nick"] = $d["nick"];
		$send["ident"] = $GLOBALS["state"]["%servers%"]["local"][(int)$fd]["ident"] = $d["ident"];
		$send["host"] = $GLOBALS["state"]["%servers%"]["local"][(int)$fd]["host"] = $sockname;
		$send["num"] = $GLOBALS["state"]["%servers%"]["local"][(int)$fd]["num"] = (int)$fd;
		$send["uplink"] = $GLOBALS["state"]["%servers%"]["local"][(int)$fd]["server"] = $GLOBALS["state"]["%servers%"];
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
