<?php

/***************************************************************************
 * Copyright (C) 2011-2013 Ping Identity Corporation
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
 * Implements the non-standard OAuth 2.0 "browser SSO bearer response" flow as documented in:
 * https://na7.salesforce.com/help/doc/en/remoteaccess_oauth_web_sso_flow.htm#assertion_for_access_token
 * 
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/

include_once dirname(dirname(__FILE__)) . '/http.php';
include_once dirname(dirname(__FILE__)) . '/wstrust.php';

// username/password of a user in the LDAP directory
// LDAP as configured in the PingFederate Username Token WS-Trust connection settings for Salesforce
$username = 'joe';
$password = 'Changeit1';

// RST appliesTo
$appliesTo = 'https://login.salesforce.com';

// PingFederate 6.x/7.x IP-STS endpoint
$IPSTS = 'https://localhost:9031/idp/sts.wst?TokenProcessorId=usernametokenldap';

// special token type (needs to be enabled in run.properties)
$tokenType = 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser';

// call to IP-STS, authenticate with uname/pwd, retrieve RSTR with generated token
$result = HTTP::doSOAP($IPSTS, WSTRUST::getRSTHeader(WSTRUST::getUserNameToken($username, $password), WSTRUST::getTimestampHeader(), $IPSTS), WSTRUST::getRST($tokenType, $appliesTo));

// parse the RSTR that is returned
list($dom, $xpath, $token, $proofKey) = WSTRUST::parseRSTR($result);

// retrieve the actual token contents from the RSTR
// NB: it is a SAML Response+Assertion in base64-encoded format embedded in a BinaryToken
$token =  $xpath->query('wsse:BinarySecurityToken', $token);
$token = $token->item(0)->textContent;

print " # SAML 2.0 Token:\n\n" . base64_decode($token) . "\n";

// post the base4-encoded SAML Response/Assertion token to Salesforce
$result = HTTP::doPost('https://login.salesforce.com/services/oauth2/token', array(
	'grant_type' => 'assertion',
	'assertion_type' => $tokenType,
	'assertion' => $token
));

print_r($result);

?>
