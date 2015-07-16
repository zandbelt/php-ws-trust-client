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
 * OAuth 2.0 SAML bearer assertion flow.
 * Get around the Subject Confirmation issue (/token/oauth2) with SSO assertions
 * - get a SAML SSO assertion from PF-DEMO IDP (sign assertion)
 * - paste from browser in assertion.xml
 * - exchange at the SP STS for another SAML assertion with the right audience (PF AS)
 * - use that 2nd assertion in a SAML bearer assertion flow
 * 
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/

include_once dirname(dirname(__FILE__)) . '/http.php';
include_once dirname(dirname(__FILE__)) . '/wstrust.php';

// username/password of a user in the LDAP directory
// LDAP as configured in the PingFederate Username Token WS-Trust connection settings for Salesforce
$username = 'joe';
$password = '2Federate';

// RST appliesTo
$appliesTo = 'https://ba_client';

// PingFederate 6.x/7.x IP-STS endpoint
$IPSTS = 'https://localhost:9031/idp/sts.wst?TokenProcessorId=usernametoken0';

// ask for the standard SAML 2.0 token type
$tokenType = WSTRUST::TOKENTYPE_SAML20;

// call to IP-STS, authenticate with uname/pwd, retrieve RSTR with generated token
$result = HTTP::doSOAP(
		$IPSTS,
		WSTRUST::getRSTHeader(WSTRUST::getUserNameToken($username, $password),
				WSTRUST::getTimestampHeader(),
				$IPSTS),
		WSTRUST::getRST($tokenType, $appliesTo)
);

// parse the RSTR that is returned
list($dom, $xpath, $token, $proofKey) = WSTRUST::parseRSTR($result);

// retrieve the actual token contents from the RSTR cq. the SAML Assertion 
$element = 'saml:Assertion';
$xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
$token =  $xpath->query($element, $token);
$token = $token->item(0);

//$token = $dom->saveXML();

print " # SAML 2.0 Token:\n\n" . $dom->saveXML() . "\n";

$dom = new DOMDocument();
$dom->load('assertion.xml');
$token = $dom->documentElement;

// PingFederate 6.x RP-STS endpoint
$targetRPSTS = 'https://localhost:9031/sp/sts.wst';

// Status Token Type at the RP
$tokenTypeRPSTS = WSTRUST::TOKENTYPE_SAML20;

#$ts = WSTRUST::getTimestampHeader('_0');
#$token = $dom->saveXML($token) . WSTRUST::getSigned($ts, $proofKey, $token->getAttribute('ID'), '_0');
#$result = HTTP::doSOAP($targetRPSTS, WSTRUST::getRSTHeader($token, $ts, $targetRPSTS), WSTRUST::getRST($tokenTypeRPSTS, $appliesToRPSTS, 'Issue'));

// parse the RSTR that is returned
#list($dom, $xpath, $token, $proofKey) = WSTRUST::parseRSTR($result);

#$element = 'saml:Assertion';
#$xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
#$token =  $xpath->query($element, $token);
#$token = $token->item(0);
$token = $dom->saveXML($token);

$endpoint = 'https://localhost:9031/as/token.oauth2';
$client_id = 'ba_client';
$grantType = 'urn:ietf:params:oauth:grant-type:saml2-bearer';

// post the base4-url-encoded SAML Assertion token to the AS
$result = HTTP::doPost($endpoint, array(
	'grant_type' => $grantType,
	'client_id' => $client_id,
	'assertion' => base64_encode($token)
));

print_r($result);

?>
