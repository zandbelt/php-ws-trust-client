<?php

/***************************************************************************
 * Copyright (C) 2011-2015 Ping Identity Corporation
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
	
class WSTRUST {

	const TOKENTYPE_SAML11 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1';
	const TOKENTYPE_SAML20 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';
	const TOKENTYPE_STATUS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status';

	const KEYTYPE_SYMMETRIC = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey';
	const KEYTYPE_BEARER    = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer';
		
	static function getRST($tokenType, $appliesTo, $keyType = WSTRUST::KEYTYPE_BEARER, $action = 'Issue') {
		return <<<XML
<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <wst:TokenType>$tokenType</wst:TokenType>
  <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/$action</wst:RequestType>
  <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
    <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
      <wsa:Address>$appliesTo</wsa:Address>
    </wsa:EndpointReference>
  </wsp:AppliesTo>
  <wst:KeyType>$keyType</wst:KeyType>
</wst:RequestSecurityToken>
XML;
	}
	
	static function parseRSTR($result) {
		$dom = new DOMDocument();
		$dom->loadXML($result);
		$doc = $dom->documentElement;
		$xpath = new DOMXpath($dom);
		$xpath->registerNamespace('s', 'http://www.w3.org/2003/05/soap-envelope');
		$xpath->registerNamespace('wst', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512');
		$xpath->registerNamespace('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
		$token = $xpath->query('/s:Envelope/s:Body/wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken', $doc);
		$proofKey = $xpath->query('/s:Envelope/s:Body/wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse/wst:RequestedProofToken/wst:BinarySecret', $doc);
		if ($proofKey->length > 0) {
			$proofKey = base64_decode($proofKey->item(0)->textContent);
		} else {
			$proofKey = NULL;
		}
		return array ($dom, $xpath, $token->item(0), $proofKey);
	}
	
	static function getUserNameToken($username, $password) {
		return <<<XML
<wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="Me">
  <wsse:Username>$username</wsse:Username>
  <wsse:Password>$password</wsse:Password>
</wsse:UsernameToken>
XML;
	}

	static function getTimestamp($offset = 0) {
		return gmdate("Y-m-d\TH:i:s\Z", time() + $offset);
	}

	static function getTimestampHeader($timestampID = "_0") {
		$c = WSTRUST::getTimestamp();
		$e = WSTRUST::getTimestamp(300);
		return <<<XML
<wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="$timestampID">
  <wsu:Created>$c</wsu:Created>
  <wsu:Expires>$e</wsu:Expires>
</wsu:Timestamp>
XML;
}

	static function getRSTHeader($token, $timestamp, $to, $action = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue') {
		return <<<XML
  <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    $timestamp
	$token
  </wsse:Security>
  <wsa:To xmlns:wsa="http://www.w3.org/2005/08/addressing">$to</wsa:To>
  <wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">$action</wsa:Action>
XML;
	}

	static function getSigned($data, $proofKey, $samlID, $refURI) {
		$dom = new DOMDocument();
		$dom->loadXML($data);
		$canonicalXML = $dom->documentElement->C14N(TRUE, FALSE);
		$digestValue = base64_encode(hash('sha1', $canonicalXML, TRUE));
		$signedInfo = <<<XML
<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>
  <Reference URI="#$refURI">
    <Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms>
    <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
    <DigestValue>$digestValue</DigestValue>
  </Reference>
</SignedInfo>
XML;
		$d = new DOMDocument();
		$d->loadXML($signedInfo);	
		$canonicalXml = $d->documentElement->C14N(TRUE, FALSE);
		$signatureValue = base64_encode(hash_hmac('sha1', $canonicalXml , $proofKey, TRUE));
		return <<<XML
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  $signedInfo
  <SignatureValue>$signatureValue</SignatureValue>
  <KeyInfo>
    <wsse:SecurityTokenReference xmlns:b="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" b:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0">
      <wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">$samlID</wsse:KeyIdentifier>
    </wsse:SecurityTokenReference>
  </KeyInfo>
</Signature>
XML;
	}

	static function getDecrypted($dom, $xpath, $token, $type, $pkey) {
		$doc = $dom->documentElement;
		$xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
		$xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
		$xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
		$xpath_prefix = '/s:Envelope/s:Body/wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken';
		$xpath_key = '/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue';
		$xpath_encrypted = '/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue';
		switch ($type) {
			case WSTRUST::TOKENTYPE_SAML11:
				$xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:1.0:assertion');
				$xpath_suffix = '';
				break;
			case WSTRUST::TOKENTYPE_SAML20:
				$xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
				$xpath_suffix = '/saml:EncryptedAssertion';
				break;
		}
		$key = $xpath->query($xpath_prefix . $xpath_suffix . $xpath_key, $doc);		
		if ($key->length > 0) {
			// decrypt encrypted token
			$key = $key->item(0)->textContent;
			
			$encrypted = $xpath->query($xpath_prefix . $xpath_suffix . $xpath_encrypted, $doc);
			$encrypted = $encrypted->item(0)->textContent;
		
			$encryptedData = base64_decode($encrypted);
			$encryptedKey= base64_decode($key);
		
			//$privateKey = openssl_pkey_get_private('file://./example.key');
			$privateKey = openssl_pkey_get_private('file://./' . $pkey);
		
			// TODO: get the padding from
			//       <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
		
			openssl_private_decrypt($encryptedKey, $sessionKey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
			while ($msg = openssl_error_string()) echo $msg . "\n";
			openssl_free_key($privateKey);
		
			$cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
			$ivSize = mcrypt_enc_get_iv_size($cipher);
			$iv = substr($encryptedData, 0, $ivSize);
		
			mcrypt_generic_init($cipher, $sessionKey, $iv);
		
			$decryptedData = mdecrypt_generic($cipher, substr($encryptedData, $ivSize));
			mcrypt_generic_deinit($cipher);
			mcrypt_module_close($cipher);
		
			$dataLen = strlen($decryptedData);
			$paddingLength = substr($decryptedData, $dataLen - 1, 1);
			$data = substr($decryptedData, 0, $dataLen - ord($paddingLength));

			$dom = new DOMDocument();
			$dom->loadXML($data);
			$token = $dom->documentElement;
				
		} else {
			$xpath_suffix = '/saml:Assertion';
			$data = $xpath->query($xpath_prefix . $xpath_suffix, $doc);
			if ($data->length > 0) $token = $data->item(0);
		}
		
		
		return array($dom, $token);
	}
}

?>
