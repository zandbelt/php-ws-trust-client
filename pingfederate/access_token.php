<?php

/***************************************************************************
 * 
 * Exchange OAuth 2.0 Bearer Access token for a SAML/custom token
 * 
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

include_once dirname(dirname(__FILE__)) . '/http.php';
include_once dirname(dirname(__FILE__)) . '/wstrust.php';

// RST appliesTo
$appliesTo = 'localhost:default:entityId';

// ask for the the sample/bogus token type
$tokenType = "urn:bogus:token";

// PingFederate 8.x token translator STS endpoint
$IPSTS = 'https://localhost:9031/pf/sts.wst';

function getBearerAccessToken($token) {
		$b64 = base64_encode($token);
		return <<<XML
<wsse:BinarySecurityToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="Me" ValueType="urn:pingidentity.com:oauth2:grant_type:validate_bearer">$b64</wsse:BinarySecurityToken>
XML;
}

$result = HTTP::doSOAP(
		$IPSTS,
		WSTRUST::getRSTHeader(getBearerAccessToken($argv[1]),
				WSTRUST::getTimestampHeader(),
				$IPSTS),
		WSTRUST::getRST($tokenType, $appliesTo, WSTRUST::KEYTYPE_SYMMETRIC)
);

list($dom, $xpath, $token, $proofKey) = WSTRUST::parseRSTR($result);

list($dom, $token) = WSTRUST::getDecrypted($dom, $xpath, $token, $tokenType, null);

$xpath->registerNamespace('wst13', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512');
$xpath->registerNamespace('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
	
$mytoken = $xpath->query("//wst13:RequestedSecurityToken/wsse:BinarySecurityToken[@ValueType='$tokenType']", $token);
if ($mytoken->length > 0) {
	print "\n # bogus token: #\n\n";
	print base64_decode($mytoken->item(0)->textContent);
	print "\n\n";
}

?>
