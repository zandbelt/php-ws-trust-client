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

include_once dirname(dirname(__FILE__)) . '/http.php';
include_once dirname(dirname(__FILE__)) . '/wstrust.php';

// username/password for authenticating the user to the IP-STS
$username = 'joe';
$password = 'Changeit1';

// partner SP Entity ID
$appliesTo = 'urn:hansz-adfs';
//$appliesTo = 'urn:hzandbelt-mbpr';

// PingFederate 6.x IP-STS endpoint
// $targetIPSTS = 'https://localhost:9031/idp/sts.wst?TokenProcessorId=usernameldap0';
$targetIPSTS = 'https://localhost:9031/idp/sts.wst?TokenProcessorId=ad0';
// ADFS 2.0 IP-STS endpoint
//$targetIPSTS = 'https://hansz-adfs/adfs/services/trust/13/usernamemixed';

// exercise1
// $tokenTypeIPSTS = WSTRUST::$TOKENTYPE_SAML11;
$tokenTypeIPSTS = WSTRUST::TOKENTYPE_SAML20;
$keyTypeIPSTS = WSTRUST::KEYTYPE_SYMMETRIC;

// call to IP-STS, authenticate with uname/pwd, retrieve RSTR with generated token
$result = HTTP::doSOAP(
		$targetIPSTS,
		WSTRUST::getRSTHeader(
				WSTRUST::getUserNameToken($username, $password),
				WSTRUST::getTimestampHeader(),
				$targetIPSTS),
		WSTRUST::getRST($tokenTypeIPSTS, $appliesTo, $keyTypeIPSTS)
);

// parse the RSTR that is returned
list($dom, $xpath, $token, $proofKey) = WSTRUST::parseRSTR($result);

// get the (possibyly encrypted) token from the response
list($dom, $token) = WSTRUST::getDecrypted($dom, $xpath, $token, $tokenTypeIPSTS, 'example.key');

if ($token != NULL) {
	print "\n # (decrypted) security token: #\n\n";
	print $dom->saveXML($token);
	print "\n\n";
}

?>
