<?php

/***************************************************************************
 * Copyright (C) 2015 Ping Identity Corporation
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

// partner SP Entity ID for PF IP-STS
$appliesToIPSTS = 'PF-DEMO';

// PingFederate 7.x IP-STS endpoint
$targetIPSTS = 'https://localhost:9031/idp/sts.wst?TokenProcessorId=usernameldap0';

// PingFederate 7.x RP-STS endpoint
$targetRPSTS = 'https://localhost:9031/sp/sts.wst';

// SAML 2.0 Token at the IP
$tokenTypeIPSTS = WSTRUST::$TOKENTYPE_SAML20;
// Status Token Type at the RP
$tokenTypeRPSTS = WSTRUST::$TOKENTYPE_STATUS;

// call to IP-STS, authenticate with uname/pwd, retrieve RSTR with generated token
$result = HTTP::doSOAP($targetIPSTS, WSTRUST::getRSTHeader(WSTRUST::getUserNameToken($username, $password), WSTRUST::getTimestampHeader(), $targetIPSTS), WSTRUST::getRST($tokenTypeIPSTS, $appliesToIPSTS));

// parse the RSTR that is returned
list($dom, $xpath, $token, $proofKey) = WSTRUST::parseRSTR($result);

// get the (possibyly encrypted) token from the response
list($dom, $token) = WSTRUST::getDecrypted($dom, $xpath, $token, $tokenTypeIPSTS, 'example.key');

$ts = WSTRUST::getTimestampHeader('_0');
$token = $dom->saveXML($token) . WSTRUST::getSigned($ts, $proofKey, $token->getAttribute('ID'), '_0');
$result = HTTP::doSOAP($targetRPSTS, WSTRUST::getRSTHeader($token, $ts, $targetRPSTS), WSTRUST::getRST($tokenTypeRPSTS, $appliesToRPSTS, 'Validate'));

// parse the RSTR that is returned
list($dom, $xpath, $token, $proofKey) = WSTRUST::parseRSTR($result);

if ($dom != NULL) {
	$dom->formatOutput = true;
	print "\n # validate response: #\n\n";
	print $dom->saveXML();
	print "\n\n";
}
?>
