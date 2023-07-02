<?php

$foreground_colors = array();
$background_colors = array();

$foreground_colors['black'] = '0;30';
$foreground_colors['dark_gray'] = '1;30';
$foreground_colors['blue'] = '0;34';
$foreground_colors['light_blue'] = '1;34';
$foreground_colors['green'] = '0;32';
$foreground_colors['light_green'] = '1;32';
$foreground_colors['cyan'] = '0;36';
$foreground_colors['light_cyan'] = '1;36';
$foreground_colors['red'] = '0;31';
$foreground_colors['light_red'] = '1;31';
$foreground_colors['purple'] = '0;35';
$foreground_colors['light_purple'] = '1;35';
$foreground_colors['brown'] = '0;33';
$foreground_colors['yellow'] = '1;33';
$foreground_colors['light_gray'] = '0;37';
$foreground_colors['white'] = '1;37';
$foreground_colors['magenta'] = '0;95';

$background_colors['black'] = '40';
$background_colors['red'] = '41';
$background_colors['green'] = '42';
$background_colors['yellow'] = '43';
$background_colors['blue'] = '44';
$background_colors['magenta'] = '45';
$background_colors['cyan'] = '46';
$background_colors['light_gray'] = '47';


// Returns colored string
function getColoredString($string, $foreground_color = null, $background_color = null) {
	
	global $background_colors, $foreground_colors;
	$colored_string = "";
	if (isset($foreground_colors[$foreground_color])) {
			$colored_string .= "\033[" . $foreground_colors[$foreground_color] . "m";
	}

	if (isset($background_colors[$background_color])) {
			$colored_string .= "\033[" . $background_colors[$background_color] . "m";
	}

	$colored_string .=  $string . "\033[0m";
	return $colored_string;
}

$serverClients = array();
$authClients = array();

class MyDB extends SQLite3
{
	function __construct() {
		$this->open(getcwd().'/database', SQLITE3_OPEN_READWRITE | SQLITE3_OPEN_CREATE);
	}

}

class AuthClient {
	
	public $id = -1;
	public $nameList = "";
	public $lastIp = "";
	public $ac_status = 0;
	public $ac_group = 0;
	public $device_id = 0;
	public $report_count = 0;
	public $ph_key = "";
	public $vl_key = "";
	public $tr_key = "";
	public $pEncryptionKey = "";

	function __construct($c, $db, $add_to_list=true) {
		global $authClients;
		$this->db = $db;
		$this->client = $c;
		$this->pEncryptionKey = generateRandomString(32);
		if($add_to_list == true) {
			$authClients[] = $this;
		}
	}

	public function fetchAccountDataFromID($accountId) {

		/* Try to fetch data from database */
		$req = $this->db->prepare("SELECT * FROM user_list WHERE user_id = :id");
		$req->bindValue(':id', $accountId, SQLITE3_INTEGER);
		$result = $req->execute();
		$potential_user = $result->fetchArray(SQLITE3_ASSOC);

		/* If the user doesn't exist, return -1 */
		if($potential_user === FALSE) {
			return -1;
		} 
		/* If the entry exists, fill class data */
		else {
			$this->id = $potential_user["user_id"];
			$this->nameList = $potential_user["username_list"];
			$this->lastIp = $potential_user["last_ipaddr"];
			$this->ac_status = $potential_user["ac_status"];
			$this->ac_group = $potential_user["ac_group"];
			$this->device_id = $potential_user["device_id"];
			$this->report_count = $potential_user["report_count"];
			$this->ph_key = $potential_user["ph_key"];
			$this->vl_key = $potential_user["vl_key"];
			$this->tr_key = $potential_user["tr_key"];
		}

		return 0;

	}

	public function fetchAccountDataFromDeviceID($deviceId, $licenceKey = "a") {

		$arrayOfUser = array();
		$result = $this->db->query('SELECT * FROM user_list');
		while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
			$arrayOfUser[] = $row;
		}

		$checkForKey = false;
		if(strlen($licenceKey) > 4) {
			$checkForKey = true;
		}

		foreach($arrayOfUser as $potential_user) {

			if($potential_user["device_id"] == $deviceId) {

				$this->id = $potential_user["user_id"];
				$this->nameList = $potential_user["username_list"];
				$this->lastIp = $potential_user["last_ipaddr"];
				$this->ac_status = $potential_user["ac_status"];
				$this->ac_group = $potential_user["ac_group"];
				$this->device_id = $potential_user["device_id"];
				$this->report_count = $potential_user["report_count"];
				$this->ph_key = $potential_user["ph_key"];
				$this->vl_key = $potential_user["vl_key"];
				$this->tr_key = $potential_user["tr_key"];

				return 0;

			}

			if($checkForKey) {
				if((strcmp($potential_user["ph_key"], $licenceKey) == 0) ||
				(strcmp($potential_user["vl_key"], $licenceKey) == 0) ||
				(strcmp($potential_user["tr_key"], $licenceKey) == 0)) {

					$this->id = $potential_user["user_id"];
					$this->nameList = $potential_user["username_list"];
					$this->lastIp = $potential_user["last_ipaddr"];
					$this->ac_status = $potential_user["ac_status"];
					$this->ac_group = $potential_user["ac_group"];
					$this->device_id = $potential_user["device_id"];
					$this->report_count = $potential_user["report_count"];
					$this->ph_key = $potential_user["ph_key"];
					$this->vl_key = $potential_user["vl_key"];
					$this->tr_key = $potential_user["tr_key"];
	
					$req1 = $this->db->prepare("UPDATE user_list SET device_id = ".strval($deviceId)." WHERE ph_key = :id");
					$req1->bindValue(':id', $licenceKey);
					$req1->execute();

					$req2 = $this->db->prepare("UPDATE user_list SET device_id = ".strval($deviceId)." WHERE vl_key = :id");
					$req2->bindValue(':id', $licenceKey);
					$req2->execute();

					$req3 = $this->db->prepare("UPDATE user_list SET device_id = ".strval($deviceId)." WHERE tr_key = :id");
					$req3->bindValue(':id', $licenceKey);
					$req3->execute();

					return 0;					
				}
			}
		}


		return -1;

	}

	public function CreateAccountFromBaseLoginData($deviceId, $nintendoNetworkId, $typeOfMod, $licenceKey) {

		$phKey = "";
		$vlKey = "";
		$trKey = "";

		switch($typeOfMod) {
			case 0:
				$phKey = $licenceKey;
				break;
			case 1:
				$vlKey = $licenceKey;
				break;
			case 2:
				$trKey = $licenceKey;
				break;
		}

		socket_getpeername($this->client, $clientIp, $clientPort);
		$this->db->exec("INSERT INTO user_list (last_connection, username_list, last_ipaddr, ac_status, ac_group, device_id, report_count, ph_key, vl_key, tr_key) VALUES ('".date("d-m-Y H:i:s")."', '".$nintendoNetworkId."', '".$clientIp."', 0, 1, ".strval($deviceId).", 0, '".$phKey."', '".$vlKey."', '".$trKey."')");
		$this->nameList = $nintendoNetworkId;
		$this->lastIp = $clientIp;
		$this->ac_group = 1;
		$this->device_id = $deviceId;
		$this->ph_key = $phKey;
		$this->vl_key = $vlKey;
		$this->tr_key = $trKey;

		return 0;

	}

	public function UpdateAccountData($nintendoNetworkId, $typeOfMod, $licenceKey, $deviceId) {

		$newUserName = $this->nameList;
		if(strpos($this->nameList, $nintendoNetworkId) === false) {
			$newUserName = $newUserName.", ".$nintendoNetworkId;
		}

		socket_getpeername($this->client, $clientIp, $clientPort);

		switch($typeOfMod) {
			case 0:
				$req = $this->db->prepare("UPDATE user_list SET username_list = '".$newUserName."', last_ipaddr = '".$clientIp."', ph_key = '".$licenceKey."', last_connection = '".date("d-m-Y H:i:s")."' WHERE device_id=:id");
				$req->bindValue(':id', $deviceId, SQLITE3_INTEGER);
				$req->execute();
				break;
			case 1:
				$req = $this->db->prepare("UPDATE user_list SET username_list = '".$newUserName."', last_ipaddr = '".$clientIp."', vl_key = '".$licenceKey."', last_connection = '".date("d-m-Y H:i:s")."' WHERE device_id=:id");
				$req->bindValue(':id', $deviceId, SQLITE3_INTEGER);
				$req->execute();
				break;
			case 2:
				$req = $this->db->prepare("UPDATE user_list SET username_list = '".$newUserName."', last_ipaddr = '".$clientIp."', tr_key = '".$licenceKey."', last_connection = '".date("d-m-Y H:i:s")."' WHERE device_id=:id");
				$req->bindValue(':id', $deviceId, SQLITE3_INTEGER);
				$req->execute();
				break;
		}

		return 0;

	}

	public function UpdateAccountStatus($deviceId, $newStatus) {

		$req = $this->db->prepare("UPDATE user_list SET ac_status = ".strval($newStatus)." WHERE device_id=:id");
		$req->bindValue(':id', $deviceId, SQLITE3_INTEGER);
		$req->execute();

	}

	
	public function UpdateAccountGroup($deviceId, $newGroup) {

		$req = $this->db->prepare("UPDATE user_list SET ac_group = ".strval($newGroup)." WHERE device_id=:id");
		$req->bindValue(':id', $deviceId, SQLITE3_INTEGER);
		$req->execute();

	}

	public function BanAccount($deviceId, $reason) {

		$req = $this->db->prepare("UPDATE user_list SET ban_reason = '".$reason."' WHERE device_id=:id");
		$req->bindValue(':id', $deviceId, SQLITE3_INTEGER);
		$req->execute();

	}

	
	public function UpdateAccountStatusGroupFromID($ActId, $status, $group) {

		$req = $this->db->prepare("UPDATE user_list SET ac_group = ".strval($group).", ac_status = ".strval($status)." WHERE user_id = :id");
		$req->bindValue(':id', $ActId, SQLITE3_INTEGER);
		$req->execute();

	}

}

function getAuthClient($client) {
	global $authClients;
	foreach($authClients as $c) {
		if($c->client == $client) {
			$key = array_search($c, $authClients);
			return $authClients[$key];
		}
	}
}

$globalRC4Key = file_get_contents(getcwd()."/rc4_key", $maxlen=32);

function addLog($data) {
	file_put_contents(getcwd()."/log_server", date('d/m/Y H:i:s')." ".$data, FILE_APPEND);
}

function hex_dump($string, array $options = null) {
    if (!is_scalar($string)) {
        throw new InvalidArgumentException('$string argument must be a string');
    }
    if (!is_array($options)) {
        $options = array();
    }
    $line_sep       = isset($options['line_sep'])   ? $options['line_sep']          : "\n";
    $bytes_per_line = @$options['bytes_per_line']   ? $options['bytes_per_line']    : 16;
    $pad_char       = isset($options['pad_char'])   ? $options['pad_char']          : '.'; # padding for non-readable characters

    $text_lines = str_split($string, $bytes_per_line);
    $hex_lines  = str_split(bin2hex($string), $bytes_per_line * 2);

    $offset = 0;
    $output = array();
    $bytes_per_line_div_2 = (int)($bytes_per_line / 2);
    foreach ($hex_lines as $i => $hex_line) {
        $text_line = $text_lines[$i];
        $output []=
            sprintf('%08X',$offset) . '  ' .
            str_pad(
                strlen($text_line) > $bytes_per_line_div_2
                ?
                    implode(' ', str_split(substr($hex_line,0,$bytes_per_line),2)) . '  ' .
                    implode(' ', str_split(substr($hex_line,$bytes_per_line),2))
                :
                implode(' ', str_split($hex_line,2))
            , $bytes_per_line * 3) .
            '  |' . preg_replace('/[^\x20-\x7E]/', $pad_char, $text_line) . '|';
        $offset += $bytes_per_line;
    }
    $output []= sprintf('%08X', strlen($string));
    return @$options['want_array'] ? $output : join($line_sep, $output) . $line_sep;
}

function crypto_rc4($key, $str) {
	$s = array();
	for ($i = 0; $i < 256; $i++) {
		$s[$i] = $i;
	}
	$j = 0;
	for ($i = 0; $i < 256; $i++) {
		$j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
		$x = $s[$i];
		$s[$i] = $s[$j];
		$s[$j] = $x;
	}
	$i = 0;
	$j = 0;
	$res = '';
	for ($y = 0; $y < strlen($str); $y++) {
		$i = ($i + 1) % 256;
		$j = ($j + $s[$i]) % 256;
		$x = $s[$i];
		$s[$i] = $s[$j];
		$s[$j] = $x;
		$res .= $str[$y] ^ chr($s[($s[$i] + $s[$j]) % 256]);
	}
	return $res;
}

function calc_checksum($data) {
	$sum = 0;
	for ($i=0; $i < strlen($data); $i++) { 
		$sum += ord($data[$i]);
	}
	$sum *= 14253;
	return ($sum & 0xFFFF);
}

function kick_client($client) {
	global $serverClients, $authClients;
	socket_close($client);
	if(($key = array_search($client, $serverClients)) !== false) {
		unset($serverClients[$key]);
	}
	foreach ($authClients as &$ac) {
		if($ac->client == $client) {
			unset($ac);
		}
	}
}

function generateRandomString($length) {
    return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
}

?>