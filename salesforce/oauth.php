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
 * Implements the (standardized) OAuth 2.0 SAML bearer assertion flow as documented in:
 * https://na7.salesforce.com/help/doc/en/remoteaccess_oauth_SAML_bearer_flow.htm
 * 
 * Note:
 * - as a Salesforce admin create an OAuth client with:
 *   App Setup -> Create -> Apps -> Connected Apps -> New
 *   give it some dummy values and tick "Enable OAuth Settings", and "Use digital signatures" in there
 *   and upload the IDP signing cert in there
 * - as a Salesforce admin pre-authorize this app for users with:
 *   Administration Setup -> Manage Apps -> Connected Apps -> OAuth policies -> Permitted Users to "Admin approved users are pre-authorized"
 * - as a Salesforce admin enable this app for a standard user profile with:
 *   Administration Setup -> Manage Users -> Profiles -> Edit (the right profile for your user) -> Connected App Access
 *   and tick the box for the remote access app you've just created
 *   
 * - as a PingFed administrator copy the generated Consumer Key from the salesforce app
 *   in to the Virtual ID field for the SP connection
 * - as a PingFed administrator use the entityid https://login.salesforce.com (instead of https://saml.salesforce.com for SAML connections...)
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

// ask for the standard SAML 2.0 token type
$tokenType = WSTRUST::TOKENTYPE_SAML20;

// call to IP-STS, authenticate with uname/pwd, retrieve RSTR with generated token
$result = HTTP::doSOAP(
		$IPSTS,
		WSTRUST::getRSTHeader(
				WSTRUST::getUserNameToken($username, $password),
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
$token = $dom->saveXML($token->item(0));

print " # SAML 2.0 Token:\n\n" . $token . "\n";

$endpoint = 'https://login.salesforce.com/services/oauth2/token';
$grantType = 'urn:ietf:params:oauth:grant-type:saml2-bearer';

// post the base4-url-encoded SAML Assertion token to Salesforce
$result = HTTP::doPost($endpoint, array(
	'grant_type' => $grantType,
	'assertion' => strtr(base64_encode($token), '+/=', '-_,')
));

print_r($result);

?>
