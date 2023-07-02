<?php

class StreamData {

	function __construct($data) {
		$this->data = $data;
		$this->offset = 0;
		$this->max_off = strlen($data);
		$this->error = 0;
	}

	private function rangeChk($size) {
		return (($this->offset + $size) <= $this->max_off);
	}

	public function u8() {
		if($this->rangeChk(1)) {
			$c = unpack("C", substr($this->data, $this->offset, 1))[1];
			$this->offset += 1;
			return $c;
		} else {
			$this->error = -1;
			return 0;
		}
	}

	public function w_u8($d) {
		if($this->rangeChk(1)) {
			$this->data .= pack("C", $d);
			$this->offset += 1;
		} else {
			$this->error = -1;
		}
	}

	public function u16() {
		if($this->rangeChk(2)) {
			$c = unpack("n", substr($this->data, $this->offset, 2))[1];
			$this->offset += 2;
			return $c;
		} else {
			$this->error = -1;
			return 0;
		}
	}

	public function w_u16($d) {
		if($this->rangeChk(2)) {
			$this->data .= pack("n", $d);
			$this->offset += 2;
		} else {
			$this->error = -1;
		}
	}

	public function u32() {
		if($this->rangeChk(4)) {
			$c = unpack("N", substr($this->data, $this->offset, 4))[1];
			$this->offset += 4;
			return $c;
		} else {
			$this->error = -1;
			return 0;
		}
	}

	public function w_u32($d) {
		if($this->rangeChk(4)) {
			$this->data .= pack("N", $d);
			$this->offset += 4;
		} else {
			$this->error = -1;
		}
	}

	public function c_str() {
		$size = $this->u16();
		if($this->rangeChk($size)) {
			$c = substr($this->data, $this->offset, $size - 1);
			$this->offset += $size;
			return $c;
		} else {
			$this->error = -1;
			return 0;
		}
	}

	public function w_c_str($d) {
		$size = strlen($d) + 1;
		if($this->rangeChk($size)) {
			$this->w_u16($size);
			$this->data .= $d;
			$this->data .= "\x00";
			$this->offset += $size;
		} else {
			$this->error = -1;
		}
	}

}

?>