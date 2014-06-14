<?php

global $conf, $state, $mods, $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;

define("TYPE_UNREGISTERED"       ,0x000001);
define("TYPE_JSON"               ,0x000002);
define("TYPE_CLIENT"             ,0x000004);
define("TYPE_OPER"               ,0x000008);
define("TYPE_SERVER"             ,0x000010);

define("DEST_CHANNEL"            ,0x000020);

define("DTYPE_RFC2812"           ,0x000001);
define("DTYPE_ARRAY"             ,0x000002);

ini_set('precision', 22);

function __autoload($c) {
	$c = strtr($c,"_","/");
	require_once("./modules/".$c.".php");
}
function rehash(){
	global $conf;
	$f = file_get_contents("./ircd.conf");
	$conf = json_decode($f,true);
	    switch (json_last_error()) {
        case JSON_ERROR_NONE:
            echo ' - Dynconf loaded'.PHP_EOL;
            return;
        break;
        case JSON_ERROR_DEPTH:
            echo ' - Maximum stack depth exceeded';
        break;
        case JSON_ERROR_STATE_MISMATCH:
            echo ' - Underflow or the modes mismatch';
        break;
        case JSON_ERROR_CTRL_CHAR:
            echo ' - Unexpected control character found';
        break;
        case JSON_ERROR_SYNTAX:
            echo ' - Syntax error, malformed JSON';
        break;
        case JSON_ERROR_UTF8:
            echo ' - Malformed UTF-8 characters, possibly incorrectly encoded';
        break;
        default:
            echo ' - Unknown error';
        break;
    }
    echo PHP_EOL;
    die("Fail");
}

function washclinick($nick) {
	$safe = str_split("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[]{}/~");
	$edgy = str_split("0123456789~");
	$issafe = 0;
	foreach ($safe as $char) {
		if (strpos($nick,$char) !== FALSE) $issafe = 1;
	}
	foreach ($edgy as $char) {
		if ($nick[0] == $char) $issafe = 0;
	}
	return $issafe;
}

function washsrvnick($nick) {
	$safe = str_split("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.");
	$edgy = str_split("0123456789.");
	$issafe = 0;
	foreach ($safe as $char) {
		if (strpos($nick,$char) !== FALSE) $issafe = 1;
	}
	foreach ($edgy as $char) {
		if ($nick[0] == $char) $issafe = 0;
	}
	return $issafe;
}

function protocolParse($data) {
	return json_decode($data,true);
}

// More macros!

function IsSSL($fp) {
	$fopt = stream_context_get_options($fp);
	return (isset($fopt["ssl"]));
}

function GetCert($fp) {
	$fopt = stream_context_get_options($fp);
	return (isset($fopt["ssl"]["peer_certificate"]))?$fopt["ssl"]["peer_certificate"]:"0";
}

require_once("class.php");

function oldParse($line) {
	$lina = " ";
	$lina .= $line;
	if ($lina[1] == ":") $serv = 3;
	else $serv = 2;
	$line = explode(" :",$lina,$serv);
	$args = explode(" ",$line[$serv-2]);
	if ($serv == 3) {
		$ret["src"] = $args[0];
	}
	unset($args[0]);
	foreach ($args as $arg) {
		$ret[] = $arg;
	}
	if (isset($line[($serv-1)])) if ($line[($serv-1)] != "") {
		$ret[] = $line[$serv-1];
		$ret["payload"] = $line[$serv-1];
	}
	return $ret;
}

function protocolEnc($json) {
	return json_encode($json,JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT/*|JSON_PRETTY_PRINT*/);
}

require_once("core.php");
rehash();
var_dump($conf);
foreach ($conf["modules"] as $mod => $arg) {
	$mods[$mod] = new $mod($arg);
}
$socket = new SockSelect();
global $by;
$by = new by();

while (true) $socket->loop();

$by->addlocalfd(0,new aClient(microtime(true), $conf["me"]["numeric"], NULL, new aServer($conf["me"]["name"],$conf["me"]["numeric"],NULL,0)));
