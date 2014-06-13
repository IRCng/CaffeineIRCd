<?php
define("DNSBL",0x1);
define("NORMLOOKUP",0x2);
define("V6LOOKUP",0x4);
define("REVLOOKUP",0x8);

class SockSelect {

	function dig($name, $qtype, $dnsbl = ".", $isdnsbl = false) {
		$type = 0;
		if ($isdnsbl >= 1) {
			$isipv6 = (strpos($name, ":") !== FALSE);
			if ($dnsbl == ".") return false;
			if ($isipv6) {
				$type = $type | V6LOOKUP;
			}
			$type = $type | DNSBL;
			$type = $type | REVLOOKUP;
		}
		if (!$isdnsbl) $type = NORMLOOKUP;
		if ($qtype == "PTR") {
			$isipv6 = (strpos($name, ":") !== FALSE);
			if ($isipv6) {
				$type = $type | REVLOOKUP;
			}
			$type = $type | REVLOOKUP;
		}
		if ($type & 0x8) {
			if ($type & V6LOOKUP) $rdns = implode(".",str_split(strrev(implode("",explode(":",$name)))));
			else $rdns = implode(".",array_reverse(explode(".",$name)));
			$dname = $rdns;
			if (($type & 0x4) and ($type & 0x1)) $dname .= ".ip6.arpa";
			else if ($type & 0x2) $dname .= ".in-addr.arpa";
			else {
				$dname .= ".".$dnsbl;
			}
		} else $dname = $name;
		$dnsname = "dig +short +time=1 ".escapeshellarg($dname)." ".escapeshellarg(strtoupper($qtype))." | tail -n 1";
		echo $dnsname.PHP_EOL;
		$out = shell_exec($dnsname);
		echo $out.PHP_EOL;
		if ($type & 0x1) {
			$num = explode(".",$out);
			$numreply = 0;
			$numreply = $numreply + $num[3];
			$numreply = $numreply + ($num[2] << 8);
			$numreply = $numreply + ($num[1] << 16);
			// We'll return the pton result :P
			return $numreply;
		}
		return $out;
	}
	function __construct() {
		/*
		switch (TRUE) {
			case ($bck & Ev::BACKEND_KQUEUE):
				$backend = Ev::BACKEND_KQUEUE;
			break;
			case ($bck & Ev::BACKEND_EPOLL):
				$backend = Ev::BACKEND_EPOLL;
			break;
			default: die("Could not find suitable I/O backend");
			break;
		}
		$this->bck = $backend;
		$this->r = Ev::READ;
		$this->w = Ev::WRITE;
		$this->ev = new EvLoop($backend); 
		* No more do we use Ev. Back to plain simple Select looping. :)
		*/
		$GLOBALS["mods"]["%socket%"] = array();
		$GLOBALS["callbacks"]["%input%"] = array();
		foreach ($GLOBALS["conf"]["listen"]["ssl"] as $sockname => $pem) $this->listeners[] = $this->listen_ssl($sockname,$pem);
		foreach ($GLOBALS["conf"]["listen"]["plain"] as $sockname => $pem) $this->listeners[] = $this->listen($sockname);
		return;
	}
	
	function loop(){
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$lis = $this->listeners;
		stream_select($lis, $r = NULL, $e = NULL, 0, 20000);
		foreach ($lis as $soc) $this->accept($soc);
		$r = $w = $e = $GLOBALS["mods"]["%socket%"];
		if (!isset($r[0])) {
			usleep(40000);
			return;
		}
		stream_select($r, $w, $e, 0, 2000);
		foreach ($r as $fi) call_user_func(array($this,"do_read"),$fi);
		foreach ($w as $fi) call_user_func(array($this,"do_write"),$fi);
		foreach ($e as $fi) {
			unset($GLOBALS["mods"]["%socket%"][(int)$fi],$callbacks["%readable%"][(int)$fi],$callbacks["%writable%"][(int)$fi]);
			foreach ($callbacks["%exit%"] as $cb) call_user_func($cb,$fi);
		}
		foreach ($r as $fi) if (feof($fi)) unset($GLOBALS["mods"]["%client%"][(int)$fi]);
		//echo $this->ev->run(); //Not going to use our ev system.
	}
	
	function accept($fd) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$fi = stream_socket_accept($fd);
		$GLOBALS["mods"]["%writebuf%"][(int)$fi] = "";
		foreach ($callbacks["%new%"] as $cb) call_user_func($cb,$fi);
		$GLOBALS["mods"]["%socket%"][] = $fi;
		$callbacks["%readable%"][(int)$fi] = array($this,"do_read");
		$callbacks["%writable%"][(int)$fi] = array($this,"do_write");
		$this->do_write($fi);
		$sockname = stream_socket_get_name($fi, TRUE);
		$sockname = implode(":",explode(":",$sockname,-1));
		$sockdns = trim($this->dig($sockname,"PTR"));
		if ($sockdns == ";; connection timed out; no servers could be reached") {
			$GLOBALS["mods"]["%sockname%"][(int)$fi] = $sockname;
			return;
		}
		if ($sockname == $this->dig($sockdns,"A")) {
			$sockname = $this->dig($sockdns,"A");
		} else if ($sockname == $this->dig($sockdns,"AAAA")) {
			$sockname = $this->dig($sockdns,"AAAA");
		}
		$GLOBALS["mods"]["%sockname%"][(int)$fi] = $sockname;
	}
	
	function do_read($fd) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$data = trim(fgets($fd,20000),"\r\n");
		if (feof($fd)) {	foreach ($callbacks["%exit%"] as $cb) call_user_func($cb,$fd);
											unset($GLOBALS["mods"]["%socket%"][array_search($fd,$GLOBALS["mods"]["%socket%"])],$callbacks["%readable%"][(int)$fd],$callbacks["%writable%"][(int)$fd]);
											return;
										}
		foreach ($callbacks["%input%"][$fd] as $cb) {
			call_user_func($cb,$fd,$data); // Call the callback with the data we received.
		}
	}
	
	function do_write($fd) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		if ($GLOBALS["mods"]["%writebuf%"][(int)$fd] == "") return;
		fwrite($fd,$GLOBALS["mods"]["%writebuf%"][(int)$fd]);
		$GLOBALS["mods"]["%writebuf%"][(int)$fd] = "";
	}
	
	function write($fd,$data) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$GLOBALS["mods"]["%writebuf%"][(int)$fd] .= $data."\n";
	}
	
	function listen_ssl ($listen, $pem) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$opt = array("ssl" => array("local_cert" => $pem,
		                            "capture_peer_cert" => 1));
		$opts = stream_context_create($opt);
		$fd = stream_socket_server("ssl://".$listen,$err,$errs,STREAM_SERVER_BIND|STREAM_SERVER_LISTEN,$opts);
		return $fd;
	}
	
	function listen ($listen) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$fd = stream_socket_server("tcp://".$listen);
		return $fd;
	}
}
