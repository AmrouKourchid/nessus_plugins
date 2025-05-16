#TRUSTED 819619a3b71ce92ee6db60b588c63405f8a7770c019b78ac74ef19783be9c2b38e50e9be4248ecaacb5c8ae27b155f5f6c0ebc93addd8322b694ea4c7297d3cdefd34b9a958e9a9f322e00e795e9401c13f76c680c3a3b07fda89cd5823b747d0ba53b8eca338c66c29abb8afd18c927336cc1dbaeb4fee3c8e3ab30a5e8d1e6ba23842aa818f349d5042f35a79435aed31d8f482ff99eed4673205b4a56a770c8e0eeb96bdd72f2bcd088e858fe61a298d64f72446f8ed487a7977a429d36d8bdbf6d1331bcee09582e03ad61a7b63f753cd98810cce868a0a56454b2155b2c7264b54b9b9f8808127fc6af455b96497a3b507e12168cb221a82a8a29f2ca01a0bb880d083bddb48c42c9e17f47216f356eead72cddf762170bb76df33ea34b7714d84534d69a8e48c4a8ee6fa3501af11b24de7bf0a3d7fc6a171fe2a2afaa988776c9ee0345c216bae5bf1c164c01b0e9fde308272355fc80778c68ea3ab290d4fd039f30f10154d4a5c5f70b11f12166f5ec11cd18ad2e487af7d929488c2314ed754f786a5d43e10f0585845cecb43dbe36d68900018354cf1aa91bf3f9ffabe940136fb5e601e7e50c5c9d8b48a2092611759594caf0c2cb630b93e2e24bf8a1804ce440de1fa1dadacf87797658a3a7df8ba9c1cee1ece2f08045fd5f2765f43b94e95dd0a84c3f63c53c0b3e7aedcf78002cbc7b6871186338f783c3
#TRUST-RSA-SHA256 994b2f77a210156668cfa2c0e95cfae2a1dc3abcce9aa4e7ed073bd17e82abf4be93ed31e17a4b0c8f9367a995fbec9ef2e2c76d1f67a9e611230bf2273354a604d25fec7269caa514b31eb8792ce93c5ffa89c3f105e12b379e24ca4d857246def2fc57497a38f0efd1b147aefb0483e7374a3c5fcc1413820e48da17dfa01f58bd03d49c8640a22f0e2a47aacd72b750b0a1783d2a66816f0d3ab6d24d288aa361268a7e15fdfeedcab4f121144fdf9f55257165b539ee53e4c3ebb9acb36caa33093e378fd54dd5da5952b0a487edc1bb2fb2f6c361a267ffa5b8feea0787020c26cd7b62c68b49edcb74af85b011de5dff5caf661522f9a5e5ff6c717fbe20963c2d5e86e929d063a5ff315f2bc0eaf9c9b01f110f0ade59b7a18cfa57de4e0a1057781cd412be41083db2db1f31b48cb496ec47f111589c3d596a99b8efdef752e1e8f376010b2939031b10cbc1d407a60dc6480329351fde62591a2623519832d7f54876ed552fd8c480231f3313fd6363f436991242808abf773354523e6738112d7244b205b9d364c21643ed8561ffe7eebbf5f2b87fa5780a7b794bdbc0996e54986c4ca726913a4e4e79cbdb56b3ddb46144a2fe2c1eb5d0b1d703644df98373ebb97eae11b4a04ab9a41610fa8ff188dc8e1948ea37bdffefabd14a26bbd675f5234142a180e0bdeee65b149628bef30356b793c7a05a13c585e8

###
#
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# collection_metadata.inc
#
# Revision: 1.1
#
###

include('compat_shared.inc');
include('xml_func.inc');

# All entries MUST be lower case for matching to be successfull
var EXCHANGE_BACKEND_PATHS = [
  'exchange back end/api', 
  'exchange back end/autodiscover', 
  'exchange back end/ecp', 
  'exchange back end/ews', 
  'exchange back end/microsoft-server-activesync', 
  'exchange back end/microsoft-server-activesync/proxy',
  'exchange back end/oab', 
  'exchange back end/powershell', 
  'exchange back end/owa', 
  'exchange back end/rpc', 
  'exchange back end/pushnotifications', 
  'exchange back end/rpcwithcert', 
  'exchange back end/mapi/emsmdb', 
  'exchange back end/mapi/nspi'
];

var DEFAULT_WEB_SITE_PATHS = [
  'default web site/api',
  'default web site/autodiscover',
  'default web site/ecp',
  'default web site/microsoft-server-activesync',
  'default web site/microsoft-server-activesync/proxy',
  'default web site/oab',
  'default web site/powershell',
  'default web site/owa',
  'default web site/rpc',
  'default web site/mapi',
];

##
# Parse <location> configs from the provided xml object
#
# @param xml_obj Nasl XML object
#
# @return Select location config data
##
function get_location_configs(xml_obj)
{
  var ret = {
    'Exchange Back End': [],
    'Default Web Site': []
  };

  var locations = xml_get_children(table:xml_obj, name:'location');
  foreach var location (locations)
  {
    if(empty_or_null(location.attributes)) continue;
    
    if(contains_element(var:EXCHANGE_BACKEND_PATHS, value:tolower(location.attributes.path)))
    {
      append_element(
        var: ret['Exchange Back End'],
        value: {
          'component' : tolower(location.attributes.path) - 'exchange back end/',
          'ep'        : get_location_extended_protection_config(location:location)
        }
      );
    }
    
    if(contains_element(var:DEFAULT_WEB_SITE_PATHS, value:tolower(location.attributes.path)))
    {
      append_element(
        var: ret['Default Web Site'],
        value: {
          'component' : tolower(location.attributes.path) - 'default web site/',
          'ep'        : get_location_extended_protection_config(location:location)
        }
      );
    }
  }
  return ret;
}

##
# Targets and returns the <extendedProtection> node in the XML Object
#
# @param <location> node provided as a Nasl XML object.
#
# @return Extended Protection config value. A return value of NULL means Extended Protection
#         has not been configured for the location.
##
function get_location_extended_protection_config(location)
{
  var ep = xml_get_child(table:location, name:'system.webServer');
  ep = xml_get_child(table:ep, name:'security');
  ep = xml_get_child(table:ep, name:'authentication');
  ep = xml_get_child(table:ep, name:'windowsAuthentication');
  ep = xml_get_child(table:ep, name:'extendedProtection');

  if(ep == NULL || empty_or_null(ep.attributes) || !ep.attributes.tokenChecking) 
    return NULL;
  
  return ep.attributes.tokenChecking;
}
