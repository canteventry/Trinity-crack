<?php

include_once 'Globals.php';
include_once 'StreamMgr.php';
include_once 'AuthentificationProtocol.php';

error_reporting(E_ALL);
set_time_limit(0);
ob_implicit_flush();
date_default_timezone_set('Europe/Paris');

/* Manage database, open, and create tables if not exist */
$db = new MyDB();
$req = 'CREATE TABLE IF NOT EXISTS user_list (user_id INTEGER PRIMARY KEY AUTOINCREMENT, last_connection TEXT, username_list TEXT NOT NULL, last_ipaddr TEXT NOT NULL, ac_status INTEGER, ac_group INTEGER, device_id INTEGER, report_count INTEGER, ph_key TEXT, vl_key TEXT, tr_key TEXT, ban_reason TEXT)';
$db->exec($req);




class RAS_InvalidProtocol {
	public function handleMethod($client, $method, $data) {
		kick_client($client);
	}
}

$gListProtocols = array(
	0x00 => new RAS_InvalidProtocol(),
	0x01 => new RAS_AuthentificationProtocol($db),
);







/*
$rsaKey = openssl_pkey_new(array( 
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
));

openssl_pkey_export($rsaKey, $privKey);
$pubKey = openssl_pkey_get_details($rsaKey);
$pubKey = $pubKey["key"];

$data = 'plaintext data goes here';

openssl_private_encrypt($data, $encrypted, $privKey);
openssl_public_decrypt($encrypted, $decrypted, $pubKey);

echo $decrypted;

exit(0);
*/

$globalRC4Key = file_get_contents(getcwd()."/rc4_key", $maxlen=32);


/* Create TCP socket */
$server = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if($server === false) {
	$out->Error("socket_create: ".socket_strerror(socket_last_error()));
	exit(0x00);
}

/* Re-use address */
socket_set_option($server, SOL_SOCKET, SO_REUSEADDR, 1);

/* Bind it to port 50057 */
if(socket_bind($server, "0.0.0.0", 50058) === false) {
	$out->Error("socket_bind: ".socket_strerror(socket_last_error($server)));
	socket_close($server);
	exit(0x01);
}

/* Accept up to 2bl connections simultaneously */
socket_listen($server, 2000000000);
socket_set_nonblock($server);

while(true) {

	/* Accept clients until there are none. */
	while(true) {
		$new_client = socket_accept($server);
		if ($new_client !== false) {
				socket_set_nonblock($new_client);
				socket_getpeername($new_client, $ip, $port);
				$serverClients[] = $new_client; // add last entry
				socket_set_option($new_client, SOL_SOCKET, SO_RCVTIMEO, array("sec"=>1, "usec"=>0));
		} else {
			break;
		}
	}

	/* check if clients have something to say */
	foreach ($serverClients as $client) {
		$data = @socket_read($client, 4, PHP_BINARY_READ);
		if($data !== false)
		{

			if(strlen($data) == 4) {
				$header = unpack("N", substr($data, 0, 4))[1];
				if($header == 0x524D4236) { // RMB6
					$packetData = socket_read($client, 4, PHP_BINARY_READ);
					$pkt_size = unpack("n", substr($packetData, 0, 2))[1];
					$pkt_chks = unpack("n", substr($packetData, 2, 2))[1];
					if($pkt_size < 4) {
						kick_client($client);
					}

					$payload = crypto_rc4($globalRC4Key, socket_read($client, $pkt_size, PHP_BINARY_READ));
					if(/*calc_checksum($payload) == $pkt_chks*/true) {
						$protocol = unpack("n", substr($payload, 0, 2))[1];
						$method = unpack("n", substr($payload, 2, 2))[1];
						$realData = substr($payload, 4, $pkt_size - 4);
						if(array_key_exists($protocol, $gListProtocols)) {
							$gListProtocols[$protocol]->handleMethod($client, $method, $realData);
						} else {
							$gListProtocols[0x00]->handleMethod($client, $method, $realData);
						}
					} else {
						kick_client($client);
					}
					
				}
			}

			if(strlen($data) != 4) {
				kick_client($client);
			}

		} else {

			if(socket_last_error($client) === 10054) {
				kick_client($client);
				continue;
			}

			if(socket_last_error($client) === 10038) {
				kick_client($client);
				continue;
			}

			if(socket_last_error($client) === 10053) {
				kick_client($client);
				continue;
			}
		}

	}

	sleep(1);
}

/*


struct paquet:

int32 magic // RMB6 = 0x524D4236 en hex
int16 size
int16 checksum (see calc_checksum)

int16 protocol
int16 method
char payload[size]

*/

?>