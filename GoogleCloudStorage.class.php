<?php
/**
 * GoogleCloudStorage.class.php
 *
 * Google Cloud Storage (PHP5.3+)
 *
 * @author	 Marlon Colhado
 * @link	   http://github.com/marloncolhado/GoogleCloudStoragePHP
 */

class GoogleCloudStorage {
	
	private $keyfile_cached;
	public $access_token;
	private $assertion_cached;
	private $bucketname;

	const ENDPOINT_TOKEN = "https://oauth2.googleapis.com/token";
	const ENDPOINT_STORAGE = "https://storage.googleapis.com";
	
	private static $supported_algs = array(
		'ES384' => array('openssl', 'SHA384'),
		'ES256' => array('openssl', 'SHA256'),
		'HS256' => array('hash_hmac', 'SHA256'),
		'HS384' => array('hash_hmac', 'SHA384'),
		'HS512' => array('hash_hmac', 'SHA512'),
		'RS256' => array('openssl', 'SHA256'),
		'RS384' => array('openssl', 'SHA384'),
		'RS512' => array('openssl', 'SHA512'),
		'EdDSA' => array('sodium_crypto', 'EdDSA'),
	);

	public function __construct($keyFile, $bucketName = "") {
		$this->bucketname = $bucketName;
		$this->keyfile_cached = json_decode($keyFile, true);
		$this->assertion_cached = $this->createAssertion($this->keyfile_cached);
		if($this->assertion_cached != null) {
			$this->accessTokenGenerator();
		}

		if($this->access_token == null) {
			echo("GoogleCloudStorage: Unable to initialize.");
			error_log("GoogleCloudStorage: Error in construct!");
		}
	}
	
	public function Bucket($bucketName) {
		$this->bucketname = $bucketName;
	}

	private function accessTokenGenerator() {
		$params = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=".urlencode(utf8_encode($this->assertion_cached));

		$ch = curl_init(self::ENDPOINT_TOKEN);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
		curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array(
			"Content-Type: application/x-www-form-urlencoded",
			"User-Agent: GuzzleHttp/6.5.5 curl/7.47.1 PHP/7.0.7",
			"Cache-Control: no-store"
			)
		);

		$result = curl_exec($ch);
		$info = curl_getinfo($ch);

		if($info['http_code'] == 200) {
			$result = json_decode($result, true);
			$this->access_token = $result['access_token'];
		} else error_log("GoogleCloudStorage: Error getting access token\n".json_encode($info), 0);
	}

	private function urlsafeB64Encode($input)
	{
		return \str_replace('=', '', \strtr(\base64_encode($input), '+/', '-_'));
	}
	
	private function readDER($der, $offset = 0)
	{
		$pos = $offset;
		$size = \strlen($der);
		$constructed = (\ord($der[$pos]) >> 5) & 0x01;
		$type = \ord($der[$pos++]) & 0x1f;

		// Length
		$len = \ord($der[$pos++]);
		if ($len & 0x80) {
			$n = $len & 0x1f;
			$len = 0;
			while ($n-- && $pos < $size) {
				$len = ($len << 8) | \ord($der[$pos++]);
			}
		}

		// Value
		if ($type == 0x03) {
			$pos++; // Skip the first contents octet (padding indicator)
			$data = \substr($der, $pos, $len - 1);
			$pos += $len - 1;
		} elseif (!$constructed) {
			$data = \substr($der, $pos, $len);
			$pos += $len;
		} else {
			$data = null;
		}

		return array($pos, $data);
	}
	
	private function signatureFromDER($der, $keySize)
	{
		// OpenSSL returns the ECDSA signatures as a binary ASN.1 DER SEQUENCE
		list($offset, $_) = $this->readDER($der);
		list($offset, $r) = $this->readDER($der, $offset);
		list($offset, $s) = $this->readDER($der, $offset);

		// Convert r-value and s-value from signed two's compliment to unsigned
		// big-endian integers
		$r = \ltrim($r, "\x00");
		$s = \ltrim($s, "\x00");

		// Pad out r and s so that they are $keySize bits long
		$r = \str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
		$s = \str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);

		return $r . $s;
	}
	
	private function sign($msg, $key, $alg = 'HS256')
	{
		if (empty(self::$supported_algs[$alg])) {
			throw new DomainException('Algorithm not supported');
		}
		list($function, $algorithm) = self::$supported_algs[$alg];
		switch ($function) {
			case 'hash_hmac':
				return \hash_hmac($algorithm, $msg, $key, true);
			case 'openssl':
				$signature = '';
				$success = \openssl_sign($msg, $signature, $key, $algorithm);
				if (!$success) {
					throw new DomainException("OpenSSL unable to sign data");
				}
				if ($alg === 'ES256') {
					$signature = $this->signatureFromDER($signature, 256);
				} elseif ($alg === 'ES384') {
					$signature = $this->signatureFromDER($signature, 384);
				}
				return $signature;
			case 'sodium_crypto':
				if (!function_exists('sodium_crypto_sign_detached')) {
					throw new DomainException('libsodium is not available');
				}
				try {
					// The last non-empty line is used as the key.
					$lines = array_filter(explode("\n", $key));
					$key = base64_decode(end($lines));
					return sodium_crypto_sign_detached($msg, $key);
				} catch (Exception $e) {
					throw new DomainException($e->getMessage(), 0, $e);
				}
		}
	}
	
	private function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null)
	{
		$header = array('typ' => 'JWT', 'alg' => $alg);
		if ($keyId !== null) {
			$header['kid'] = $keyId;
		}
		if (isset($head) && \is_array($head)) {
			$header = \array_merge($head, $header);
		}
		$segments = array();
		$segments[] = $this->urlsafeB64Encode(json_encode($header));
		$segments[] = $this->urlsafeB64Encode(json_encode($payload));
		$signing_input = \implode('.', $segments);

		$signature = $this->sign($signing_input, $key, $alg);
		$segments[] = $this->urlsafeB64Encode($signature);

		return \implode('.', $segments);
	}
	
	private function createPayload($key) {
		$iat = time();
		
		$payload['iss'] = $key['client_email'];
		$payload['exp'] = $iat+3660;
		$payload['iat'] = $iat;
		$payload['aud'] = $key['token_uri'];
		$payload['scope'] = "https://www.googleapis.com/auth/iam https://www.googleapis.com/auth/devstorage.full_control";
		
		return $payload;
	}

	private function createAssertion($key) {
		
		$payLoad = $this->createPayload($key);
		return $this->encode($payLoad, $key['private_key'], 'RS256');
	}

	private function fromFilename($filename)
	{
		return $this->fromExtension(pathinfo($filename, PATHINFO_EXTENSION));
	}

	private function fromExtension($extension)
	{
		$mimetypes = array(
			'3gp' => 'video/3gpp',
			'7z' => 'application/x-7z-compressed',
			'aac' => 'audio/x-aac',
			'ai' => 'application/postscript',
			'aif' => 'audio/x-aiff',
			'asc' => 'text/plain',
			'asf' => 'video/x-ms-asf',
			'atom' => 'application/atom+xml',
			'avi' => 'video/x-msvideo',
			'bmp' => 'image/bmp',
			'bz2' => 'application/x-bzip2',
			'cer' => 'application/pkix-cert',
			'crl' => 'application/pkix-crl',
			'crt' => 'application/x-x509-ca-cert',
			'css' => 'text/css',
			'csv' => 'text/csv',
			'cu' => 'application/cu-seeme',
			'deb' => 'application/x-debian-package',
			'doc' => 'application/msword',
			'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
			'dvi' => 'application/x-dvi',
			'eot' => 'application/vnd.ms-fontobject',
			'eps' => 'application/postscript',
			'epub' => 'application/epub+zip',
			'etx' => 'text/x-setext',
			'flac' => 'audio/flac',
			'flv' => 'video/x-flv',
			'gif' => 'image/gif',
			'gz' => 'application/gzip',
			'htm' => 'text/html',
			'html' => 'text/html',
			'ico' => 'image/x-icon',
			'ics' => 'text/calendar',
			'ini' => 'text/plain',
			'iso' => 'application/x-iso9660-image',
			'jar' => 'application/java-archive',
			'jpe' => 'image/jpeg',
			'jpeg' => 'image/jpeg',
			'jpg' => 'image/jpeg',
			'js' => 'text/javascript',
			'json' => 'application/json',
			'latex' => 'application/x-latex',
			'log' => 'text/plain',
			'm4a' => 'audio/mp4',
			'm4v' => 'video/mp4',
			'mid' => 'audio/midi',
			'midi' => 'audio/midi',
			'mov' => 'video/quicktime',
			'mkv' => 'video/x-matroska',
			'mp3' => 'audio/mpeg',
			'mp4' => 'video/mp4',
			'mp4a' => 'audio/mp4',
			'mp4v' => 'video/mp4',
			'mpe' => 'video/mpeg',
			'mpeg' => 'video/mpeg',
			'mpg' => 'video/mpeg',
			'mpg4' => 'video/mp4',
			'oga' => 'audio/ogg',
			'ogg' => 'audio/ogg',
			'ogv' => 'video/ogg',
			'ogx' => 'application/ogg',
			'pbm' => 'image/x-portable-bitmap',
			'pdf' => 'application/pdf',
			'pgm' => 'image/x-portable-graymap',
			'png' => 'image/png',
			'pnm' => 'image/x-portable-anymap',
			'ppm' => 'image/x-portable-pixmap',
			'ppt' => 'application/vnd.ms-powerpoint',
			'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
			'ps' => 'application/postscript',
			'qt' => 'video/quicktime',
			'rar' => 'application/x-rar-compressed',
			'ras' => 'image/x-cmu-raster',
			'rss' => 'application/rss+xml',
			'rtf' => 'application/rtf',
			'sgm' => 'text/sgml',
			'sgml' => 'text/sgml',
			'svg' => 'image/svg+xml',
			'swf' => 'application/x-shockwave-flash',
			'tar' => 'application/x-tar',
			'tif' => 'image/tiff',
			'tiff' => 'image/tiff',
			'torrent' => 'application/x-bittorrent',
			'ttf' => 'application/x-font-ttf',
			'txt' => 'text/plain',
			'wav' => 'audio/x-wav',
			'webm' => 'video/webm',
			'webp' => 'image/webp',
			'wma' => 'audio/x-ms-wma',
			'wmv' => 'video/x-ms-wmv',
			'woff' => 'application/x-font-woff',
			'wsdl' => 'application/wsdl+xml',
			'xbm' => 'image/x-xbitmap',
			'xls' => 'application/vnd.ms-excel',
			'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
			'xml' => 'application/xml',
			'xpm' => 'image/x-xpixmap',
			'xwd' => 'image/x-xwindowdump',
			'yaml' => 'text/yaml',
			'yml' => 'text/yaml',
			'zip' => 'application/zip',
		);

		$extension = strtolower($extension);

		return isset($mimetypes[$extension])
			? $mimetypes[$extension]
			: null;
	}

	public function ListAllObjects($directory = "") {
		$objects = array();
		if($this->access_token != null) {
			$prefix = "";
			if($directory != "") $prefix = "prefix=".$directory."&";

			$ch = curl_init(self::ENDPOINT_STORAGE."/storage/v1/b/".$this->bucketname."/o?".$prefix."prettyPrint=false");
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array(
				"x-goog-api-client: gl-php/7.0.7 gccl/1.25.2",
				"User-Agent: gcloud-php/1.25.2",
				"Authorization: Bearer ".$this->access_token
				)
			);

			$result = curl_exec($ch);
			$info = curl_getinfo($ch);

			if($info['http_code'] == 200) {
				$result = json_decode($result, true);
				foreach($result['items'] as $item) {
					if($item['size'] > 0) {
						$object['id'] = $item['id'];
						$object['name'] = str_replace($directory."/", "", $item['name']);
						$object['created'] = substr($item['generation'], 0, 10);
						$object['contentType'] = $item['contentType'];
						$object['size'] = $item['size'];
						$object['url'] = self::ENDPOINT_STORAGE."/".$this->bucketname."/".$item['name'];
						$objects[] = $object;
					}
				}
			} else error_log("GoogleCloudStorage: Error getting objects\n".json_encode($info), 0);
		}
		return $objects;
	}

	public function ListObjects($page = 1, $maxResults = 10, $directory = "") {
		if($page <= 0) $page = 1;
		$result = null;

		$allObjects = $this->ListAllObjects($directory);
		$allObjectsCount = count($allObjects);

		if($allObjectsCount > 0) {
			$result['totalObjects'] = $allObjectsCount;
			$result['maxPages'] = ceil($allObjectsCount/$maxResults);
			$result['currentPage'] = $page;

			if($result['currentPage'] > $result['maxPages']) return null;

			if($allObjectsCount > $maxResults) {
				$chunkObjects = array_chunk($allObjects, $maxResults);
				if(count($chunkObjects) >= $page) $result['objects'] = $chunkObjects[$page-1];
			} else $result['objects'] = $allObjects;
		}

		return $result;
	}

	public function UploadObject($content, $name, $directory = "") {
		$object = null;
		if($this->access_token != null) {
			$directory = !empty($directory) ? $directory."/" : "";
			$metadata = json_encode(array("name" => $directory.$name));

			$n = "\r\n";
			$body = "--boundary".$n;
			$body .= "Content-Type: application/json; charset=UTF-8".$n;
			$body .= "Content-Disposition: form-data; name=\"metadata\"".$n;
			$body .= "Content-Length: ".strlen($metadata).$n;
			$body .= $n;
			$body .= $metadata.$n;
			$body .= "--boundary".$n;
			$body .= "Content-Type: ".$this->fromFilename($name).$n;
			$body .= "Content-Disposition: form-data; name=\"data\"".$n;
			$body .= "Content-Length: ".strlen($content).$n;
			$body .= $n;
			$body .= $content.$n;
			$body .= "--boundary--";

			$ch = curl_init(self::ENDPOINT_STORAGE."/upload/storage/v1/b/".$this->bucketname."/o?uploadType=multipart");
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
			curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array(
				"x-goog-api-client: gl-php/7.0.7 gccl/1.25.2",
				"User-Agent: gcloud-php/1.25.2",
				"Authorization: Bearer ".$this->access_token,
				"Content-Type: multipart/related; boundary=boundary"
				)
			);

			$result = curl_exec($ch);
			$info = curl_getinfo($ch);

			if($info['http_code'] == 200) {
				$result = json_decode($result, true);

				$object = array();
				$object['id'] = $result['id'];
				$object['name'] = str_replace($directory."/", "", $result['name']);
				$object['created'] = substr($result['generation'], 0, 10);
				$object['contentType'] = $result['contentType'];
				$object['size'] = $result['size'];
				$object['url'] = self::ENDPOINT_STORAGE."/".$this->bucketname."/".$result['name'];
			} else error_log("GoogleCloudStorage: Error getting objects\n".json_encode($info), 0);
		}
		return $object;
	}
}
?>
