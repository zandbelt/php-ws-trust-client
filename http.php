<?php 

/***************************************************************************
 * Copyright (C) 2011-2012 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * You may not copy or use this file, in either source code or executable
 * form, except in compliance with terms set by Ping Identity Corporation.
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *      
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/

class HTTP {
	
	static $HTTP_DEBUG = 1;
	// don't use this in production!
	static $HTTP_SSL_VERIFY_PEER = 0;
	static $HTTP_SSL_VERIFYHOST = 0;

	private $ch;

	private function HTTP($url, $username, $password) {
		$this->ch = curl_init();
		curl_setopt($this->ch, CURLOPT_VERBOSE, HTTP::$HTTP_DEBUG);
		curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, HTTP::$HTTP_SSL_VERIFY_PEER);
		curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, HTTP::$HTTP_SSL_VERIFYHOST);
		curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, 1);
//		curl_setopt($this->ch, CURLOPT_HEADER, 1);
		if ( ($username != NULL) and ($password != NULL) ) {
			curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC ) ; 
			curl_setopt($this->ch, CURLOPT_USERPWD, $username . ':' . $password); 
		}
		curl_setopt($this->ch, CURLOPT_URL, $url);
	}
	
	private function doExec($url, $post = NULL, $cookies = NULL) {
		if ($post != NULL) {
			curl_setopt($this->ch, CURLOPT_POSTFIELDS, $post);
		}
		if ($cookies != NULL) {
			curl_setopt($this->ch, CURLOPT_COOKIEJAR, $cookies);
			curl_setopt($this->ch, CURLOPT_COOKIEFILE, $cookies);			
		}
		$result = curl_exec($this->ch);
		print_r(curl_error($this->ch));
		curl_close($this->ch);
		if (HTTP::$HTTP_DEBUG) {
			print "\n # Response from $url: #\n\n";
			print $result;
			print "\n\n";
		}
		return $result;
	}

	private function getHandle() {
		return $this->ch;
	}
	
	static private function getInstance($url, $username = NULL, $password = NULL) {
		return new HTTP($url, $username, $password);
	}

	static public function doGet($url, $cookies = NULL) {
		$o = HTTP::getInstance($url);
		if (HTTP::$HTTP_DEBUG) {
			print "\n # GET Request to $url: #\n\n";
			print $url;
			print "\n\n";
		}		
		return $o->doExec($url, NULL, $cookies);
	}

	static public function doPost($url, $parms, $cookies = NULL) {
		$o = HTTP::getInstance($url);
		$content = '';
		foreach ($parms as $key => $value) {
			if ($content != '') $content .= '&';
			$content .= urlencode($key) . '=' . urlencode($value);
		}
		if (HTTP::$HTTP_DEBUG) {
			print "\n # POST Request to $url: #\n\n";
			print $content;
			print "\n\n";
		}		
		return $o->doExec($url, $content, $cookies);
	}
	
	static public function doSoap($url,  $header, $body, $user = NULL, $password = NULL, $version = 'http://www.w3.org/2003/05/soap-envelope', $ctype = 'application/soap+xml') {
		$o = HTTP::getInstance($url, $user, $password);
		$request = <<<XML
<s:Envelope xmlns:s="$version">
  <s:Header>$header</s:Header>
  <s:Body>$body</s:Body>
</s:Envelope>	
XML;
		if (HTTP::$HTTP_DEBUG) {
			print "\n # SOAP Request to $url: #\n\n";
			print $request;
			print "\n\n";
		}
		// workaround curl version peculiarity
		curl_setopt($o->getHandle(), CURLOPT_POST, 1);
		curl_setopt($o->getHandle(), CURLOPT_POSTFIELDS, $request);
		curl_setopt($o->getHandle(), CURLOPT_HTTPHEADER, array(
					'soapAction: ' . $url,
					'Content-Type: ' . $ctype . '; charset=utf-8',
		)
		);
		return $o->doExec($url);
	}
}
?>
