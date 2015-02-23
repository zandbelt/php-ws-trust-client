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

include_once dirname(dirname(__FILE__)) . '/http.php';
include_once dirname(dirname(__FILE__)) . '/wstrust.php';

// username/password for authenticating the user to the IP-STS
$username = 'joe@pingidentity.org';
$password = '********';

// Sharepoint 2010 Claims Based Site
$sharepoint = 'https://ad:16001/';

// test URL
$page = '/sites/test';

// partner identifier
$appliesTo = 'https://ad:16001/_trust';

// PingFederate 6.x IP-STS endpoint
$targetIPSTS = 'https://localhost:9031/idp/sts.wst?TokenProcessorId=salesforce0';

$tokenTypeIPSTS = WSTRUST::$TOKENTYPE_SAML11;

// call to IP-STS, authenticate with uname/pwd, retrieve RSTR with generated token
$result = HTTP::doSOAP($targetIPSTS, WSTRUST::getRSTHeader(WSTRUST::getUserNameToken($username, $password), WSTRUST::getTimestampHeader(), $targetIPSTS), WSTRUST::getRST($tokenTypeIPSTS, $appliesTo));

// parse the RSTR that is returned
list($rdom, $xpath, $token, $proofKey) = WSTRUST::parseRSTR($result);

// get the (possibyly encrypted) token from the response
list($dom, $token) = WSTRUST::getDecrypted($rdom, $xpath, $token, $tokenTypeIPSTS, null);

if ($token != NULL) {
	print "\n # SAML 1.1 token for Sharepoint: #\n\n";
	print $dom->saveXML($token);
	print "\n\n";
}

// !! make sure CommonName and subject are correctly formatted (ie. "short" name and syntactically correct e-mail address !!
// !! modify the sharepoint site web.config so that it accepts the fedauth cookies !!
$rstr = $xpath->query('/s:Envelope/s:Body/wst:RequestSecurityTokenResponseCollection', $rdom->documentElement);

$wctx = $sharepoint . '_layouts/Authenticate.aspx?Source=' . urlencode($page);
$wresult = $rdom->saveXML($rstr->item(0));
$target = $sharepoint . '_trust/';

$cookiefile = '/tmp/sharepoint-cookies.txt';
$result = HTTP::doPost($target, array('wa' => 'wsignin1.0', 'wctx' => $wctx, 'wresult' => $wresult), $cookiefile);

# !! do not do this call ?!
#$result = HTTP::doGet($wctx, $cookiefile);

$result = HTTP::doGet($sharepoint . 'sites/test/SitePages/Home.aspx', $cookiefile);
unlink($cookiefile);

print_r($result);
?>
