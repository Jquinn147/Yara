rule xmrig {
	strings:
		$cf = "\"id\":%lld,\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":" nocase
		$s2 = "nicehash" nocase
		$s3 = "xmrig" nocase
	condition:
		all of them
}
