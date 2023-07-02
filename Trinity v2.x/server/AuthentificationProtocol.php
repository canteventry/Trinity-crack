<?php

include_once 'Globals.php';
include_once 'StreamMgr.php';

class RAS_AuthentificationProtocol {

	const AuthStatus_Banned = 1 << 29;
	const AuthStatus_Vulcain = 1 << 17;
	const AuthStatus_Phantom = 1 << 16;
	const AuthStatus_Trinity = 1 << 15;

	const Auth_TrialAccount = 0x03;
	const Auth_AllowedAccount = 0x04;
	const Auth_BannedAccount = 0x05;
	const Auth_OK = 0x07;
	const Auth_NotEnoughPerm = 0x08;
	const Auth_DoesntExist = 0x09;

	function __construct($db) {
		$this->db = $db;
		$this->key = file_get_contents(getcwd()."/rc4_key", $maxlen=32);
	}
	
	// Method 0x01
	private function AP_SimpleAuthentification($client, $data) {

		global $authClients;

		/* Init I/O Data Streams */
		$stream = new StreamData($data);
		$respData = new StreamData("");
		$respData->max_off = 0x100;

		/* Get input data */
		$typeOfMod = $stream->u8();
		$deviceId = $stream->u32();
		$nintendoNetworkId = $stream->c_str();
		$licenceKey = $stream->c_str();

		printf(	"Type: %d\n".
				"DeviceID: %d\n".
				"NNID: %s\n".
				"Licence Key: %s\n", $typeOfMod, $deviceId, $nintendoNetworkId, $licenceKey);

		socket_getpeername($client, $cIp);
		addLog("Connection of ".getColoredString($cIp, "light_cyan")." ".getColoredString($nintendoNetworkId, "light_red")." with key ".getColoredString($licenceKey, "light_red")."\n");

		/* If size matched what we needed, continue, else drop connection */
		if($stream->error == -1) {
			kick_client($client);
			return;
		}

		/* Create AuthClient and get account data */
		$aCl = new AuthClient($client, $this->db);
		if($aCl->fetchAccountDataFromDeviceID($deviceId, $licenceKey) < 0 ) {
			$aCl->CreateAccountFromBaseLoginData($deviceId, $nintendoNetworkId, $typeOfMod, $licenceKey);
		} else {
			$aCl->UpdateAccountData($nintendoNetworkId, $typeOfMod, $licenceKey, $deviceId);
		}

		$outCode = $this::Auth_AllowedAccount;

		printf("Code: %d (%d %08X)\n\n", $outCode, $aCl->ac_status, $aCl->ac_status);

		$respData->w_u32($outCode);
		$respData->w_c_str($aCl->pEncryptionKey);
		$respData->data = crypto_rc4($this->key, $respData->data);

		socket_write($client, pack("N", strlen($respData->data)).pack("N", calc_checksum($respData->data)).$respData->data, strlen($respData->data) + 8);

	}

	// Method 0x02
	private function AP_VerifyConnection($client, $data) {

		global $authClients;
		$data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $data);

		/* Init I/O Data Streams */
		$stream = new StreamData($data);
		$respData = new StreamData("");
		$respData->max_off = 0x100;
		
		/* Get input data */
		$code = $stream->u32();

		/* If size matched what we needed, continue, else drop connection */
		if($stream->error == -1) {
			kick_client($client);
			return;
		}

		if($code == 0x13371337) {
			$respData->w_u32(0x13371337);
		} else {
			$respData->w_u32(0xCAFEDEAD);
		}

		$respData->data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $respData->data);
		$respData->data = crypto_rc4($this->key, $respData->data);
		socket_write($client, pack("N", strlen($respData->data)).pack("N", calc_checksum($respData->data)).$respData->data, strlen($respData->data) + 8);

	}

	// Method 0x05
	private function AP_UpdateAccountStatus($client, $data) {

		global $authClients;
		$data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $data);

		/* Init I/O Data Streams */
		$stream = new StreamData($data);
		$respData = new StreamData("");
		$respData->max_off = 0x100;
		
		/* Get input data */
		$deviceId = $stream->u32();
		$newStatus = $stream->u32();

		/* If size matched what we needed, continue, else drop connection */
		if($stream->error == -1) {
			kick_client($client);
			return;
		}

		if(getAuthClient($client)->ac_group >= 5) {
			/* Create AuthClient and get account data */
			$aCl = new AuthClient($client, $this->db, false);
			if($aCl->fetchAccountDataFromDeviceID($deviceId) < 0 ) {
				$respData->w_u32($this::Auth_DoesntExist);
			} else {
				$aCl->UpdateAccountStatus($deviceId, $newStatus);
				$respData->w_u32($this::Auth_OK);
			}
		} else {
			$respData->w_u32($this::Auth_NotEnoughPerm);
		}

		printf("Status: %d -> 0x%08X\n", $deviceId, $newStatus);

		$respData->data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $respData->data);
		$respData->data = crypto_rc4($this->key, $respData->data);
		socket_write($client, pack("N", strlen($respData->data)).pack("N", calc_checksum($respData->data)).$respData->data, strlen($respData->data) + 8);

	}

	// Method 0x06
	private function AP_UpdateAccountGroup($client, $data) {

		global $authClients;
		$data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $data);

		/* Init I/O Data Streams */
		$stream = new StreamData($data);
		$respData = new StreamData("");
		$respData->max_off = 0x100;
		
		/* Get input data */
		$deviceId = $stream->u32();
		$newGroup = $stream->u32();

		/* If size matched what we needed, continue, else drop connection */
		if($stream->error == -1) {
			kick_client($client);
			return;
		}

		if(getAuthClient($client)->ac_group >= 5) {
			/* Create AuthClient and get account data */
			$aCl = new AuthClient($client, $this->db, false);
			if($aCl->fetchAccountDataFromDeviceID($deviceId) < 0 ) {
				$respData->w_u32($this::Auth_DoesntExist);
			} else {
				$aCl->UpdateAccountGroup($deviceId, $newGroup);
				$respData->w_u32($this::Auth_OK);
			}
		} else {
			$respData->w_u32($this::Auth_NotEnoughPerm);
		}

		printf("Group: %d -> 0x%08X\n", $deviceId, $newGroup);

		$respData->data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $respData->data);
		$respData->data = crypto_rc4($this->key, $respData->data);
		socket_write($client, pack("N", strlen($respData->data)).pack("N", calc_checksum($respData->data)).$respData->data, strlen($respData->data) + 8);
	
	}

	// Method 0x07
	public function AP_BanAccount($client, $data) {
		global $authClients;
		$data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $data);

		/* Init I/O Data Streams */
		$stream = new StreamData($data);
		$respData = new StreamData("");
		$respData->max_off = 0x100;
		
		/* Get input data */
		$deviceId = $stream->u32();
		$banReason = $stream->c_str();

		/* If size matched what we needed, continue, else drop connection */
		if($stream->error == -1) {
			kick_client($client);
			return;
		}

		if(getAuthClient($client)->ac_group >= 5) {
			/* Create AuthClient and get account data */
			$aCl = new AuthClient($client, $this->db, false);
			if($aCl->fetchAccountDataFromDeviceID($deviceId) < 0 ) {
				$respData->w_u32($this::Auth_DoesntExist);
			} else {
				$aCl->BanAccount($deviceId, $banReason);
				$aCl->UpdateAccountStatus($deviceId, $aCl->ac_status | $this::AuthStatus_Banned);
				$respData->w_u32($this::Auth_OK);
			}
		} else {
			$respData->w_u32($this::Auth_NotEnoughPerm);
		}

		$respData->data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $respData->data);
		$respData->data = crypto_rc4($this->key, $respData->data);
		socket_write($client, pack("N", strlen($respData->data)).pack("N", calc_checksum($respData->data)).$respData->data, strlen($respData->data) + 8);
	}

	// Method 0x08
	public function AP_GetAllAccountData($client, $data) {

		global $authClients;
		$data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $data);

		/* Init I/O Data Streams */
		$stream = new StreamData($data);
		$respData = new StreamData("");
		$respData->max_off = 0x100000;

		/* Get input data */
		$useless = $stream->u32();

		/* If size matched what we needed, continue, else drop connection */
		if($stream->error == -1) {
			kick_client($client);
			return;
		}
		
		if(getAuthClient($client)->ac_group >= 5) {
			$counter = 0;
			$arrayOfUser = array();
			$result = $this->db->query('SELECT * FROM user_list');
			while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
				$arrayOfUser[] = $row;
				$counter++;
			}
			$respData->w_u32($counter);
			foreach($arrayOfUser as $act) {
				$respData->w_u32($act["user_id"]);
				$respData->w_c_str($act["last_connection"]);
				$respData->w_c_str($act["username_list"]);
				$respData->w_c_str($act["last_ipaddr"]);
				$respData->w_u32($act["ac_group"]);
				$respData->w_u32($act["device_id"]);
				$respData->w_c_str($act["ph_key"]);
				$respData->w_c_str($act["vl_key"]);
				$respData->w_c_str($act["tr_key"]);
				$respData->w_c_str($act["ban_reason"]);
				$respData->w_u32($act["ac_status"]);
				$respData->w_u32($act["report_count"]);
			}
		} else {
			$respData->w_u32(0);
		}

		$respData->data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $respData->data);
		$respData->data = crypto_rc4($this->key, $respData->data);
		socket_write($client, pack("N", strlen($respData->data)).pack("N", calc_checksum($respData->data)).$respData->data, strlen($respData->data) + 8);

	}

	// Method 0x09
	public function AP_UpdateAccountFromID($client, $data) {

		global $authClients;
		$data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $data);

		/* Init I/O Data Streams */
		$stream = new StreamData($data);
		$respData = new StreamData("");
		$respData->max_off = 0x4000;

		/* Get input data */
		$account_id = $stream->u32();
		$account_status = $stream->u32();
		$account_group = $stream->u32();

		/* If size matched what we needed, continue, else drop connection */
		if($stream->error == -1) {
			kick_client($client);
			return;
		}

		if(getAuthClient($client)->ac_group >= 5) {
			/* Create AuthClient and get account data */
			$aCl = new AuthClient($client, $this->db, false);
			if($aCl->fetchAccountDataFromID($account_id) < 0 ) {
				$respData->w_u32($this::Auth_DoesntExist);
			} else {
				$aCl->UpdateAccountStatusGroupFromID($account_id, $account_status, $account_group);
				$respData->w_u32($this::Auth_OK);
			}
		} else {
			$respData->w_u32($this::Auth_NotEnoughPerm);
		}

		$respData->data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $respData->data);
		$respData->data = crypto_rc4($this->key, $respData->data);
		socket_write($client, pack("N", strlen($respData->data)).pack("N", calc_checksum($respData->data)).$respData->data, strlen($respData->data) + 8);
	}

	// Method 0x0D
	public function AP_LogToFile($client, $data) {

		global $authClients;
		$data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $data);

		/* Init I/O Data Streams */
		$stream = new StreamData($data);
		$respData = new StreamData("");
		$respData->max_off = 0x4000;

		/* Get input data */
		$nnid = $stream->c_str();
		$logdata = $stream->c_str();

		/* If size matched what we needed, continue, else drop connection */
		if($stream->error == -1) {
			kick_client($client);
			return;
		}

		$respData->w_u32(0);
		addLog(getColoredString("[".str_replace("\x00", "", $nnid)."] ".$logdata, "light_purple")."\n");
		
		$respData->data = crypto_rc4(getAuthClient($client)->pEncryptionKey, $respData->data);
		$respData->data = crypto_rc4($this->key, $respData->data);
		socket_write($client, pack("N", strlen($respData->data)).pack("N", calc_checksum($respData->data)).$respData->data, strlen($respData->data) + 8);
	}

	public function handleMethod($client, $method, $data) {

		if($method == 1) {
			$this->AP_SimpleAuthentification($client, $data);
		}

		if($method == 2) {
			$this->AP_VerifyConnection($client, $data);
		}

		if($method == 5) {
			$this->AP_UpdateAccountStatus($client, $data);
		}

		if($method == 6) {
			$this->AP_UpdateAccountGroup($client, $data);
		}

		if($method == 7) {
			$this->AP_BanAccount($client, $data);
		}

		if($method == 8) {
			$this->AP_GetAllAccountData($client, $data);
		}

		if($method == 9) {
			$this->AP_UpdateAccountFromID($client, $data);
		}

		if($method == 13) {
			$this->AP_LogToFile($client, $data);
		}

	}
}

?>
