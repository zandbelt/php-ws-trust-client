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

$username = 'joe@pingidentity.org';
$password = '********';

$url = 'https://login.salesforce.com/services/Soap/u/24.0';

$body = <<<XML
<sfdc:login xmlns:sfdc="urn:partner.soap.sforce.com">
  <sfdc:username>$username</sfdc:username>
  <sfdc:password>$password</sfdc:password>
</sfdc:login>
XML;

$result = HTTP::doSoap($url, '', $body, NULL, NULL, 'http://schemas.xmlsoap.org/soap/envelope/', 'text/xml');

print_r($result);
?>
