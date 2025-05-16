#TRUSTED 5f7d5cb16c721f77c85e859afdf6432437c5758408356f03ff951826555ec91d0a1ac206d06d77985eb57942f570489796dac1826d17d637aa8ab06ccc780b82345259895864cceeb232bdc30080973e8443307abe37b72a82a639a5133892bbf580aa1340389be73adbf1d748d55c9bcf5bebb0959ca54dbd75b4513eb91c762fcf5a23ca7e09838358ffafe55c95e11e27976d153d96c4682e7b3c24a24d83de1c942b16b817e1c3d4b1bb1e0c228c53227ecb81c64d7f13e6202ab14b0a37a0d8865d6a09188c7cef657ca6f7968fbac30e4abdb254fdb3ac40c51ca09c17f9eb615f3f5d55a64fd107cb82baee16ddb9856ea2f97278b075babbccb9edd90dd40b7de9b16e0c9cfc3ece023c14defdf23c448fea4462b3122ec4f0d98378069a44f30fd079c76ce59025a9e40523c81032e4b3997e48dbc41460ec6d356399ce25b891c00f74ba8f1e322344251f89a470e5c6cdc39e3884f6c004639b61af3221b04f923d4c3f376d1f3543ae828c6ff0e6a308fe3479e5568135bfa58e8f417e45942aa49af237cbb004bd35114e9cf3c2211343a5215f2601d2563076786c25cebdc4f5a355e3ff0a960e0cb5b022c9ab3f3cfd7be393e8e612391f462b9b70e3210fee10433816852bb42cba4f2293a372eb20419be35718191e244969555eff4155e24c5e69d71b4127660b65687aaa5469c287aabb375147ab903e
#TRUST-RSA-SHA256 4591902c617cbe47be1c669cd63dbca6cebf2a9fd60da052536d9df4d3e03ee68586207742c2a199fe37ef28926c56814954ce194d614bde98dc87e110cf23b470325eb38e2766790ba1b9ce49a054ae1e78a07fe86fc57c336623e7a668d69bb40e11a527702730dee17bbf7a3cd8c5dfe4f79565de018a516282d431f737e5d1de8c996232f41fffa424a5cd3e5d2f0d3e75c87b41bf572d865ec9044b7a6e23ff767856c9f36b2c01842d58ea8d2df9d83258057e813f789092b4c917f2412ad45ff24b5ffc3e2eb75f64259b49884dbd1fb894593e57bdca2f8302698d4985ab5c4b5e48be711d1719f22d6636ac6b7b43af004e35b50f5d654502ca4b49b3bbdc251a430ef70e31023159ccbabbf8c9fa56fbb8f96f0819ff07f9bf048819b8829f6da68d8e18cbda53c4b5e1492e326141a395d8c0e5f65b5dac0d98e3caf622c1fd91b240071c65eb89dfa9704f688ae8f91e57ecdc0b14c6b1c77e4ba2f937e5fd341c4d8cf3f44f48c8cbe7dc9a307794f85d71a000611379e2517c4ee9ec12ab1b4a34da5d9a8240fc6030d95000f945e420fa67f8ef9463961dd4681c9eb4e4f781b26902c6ce0d0d13ec9819a3621cca3cbb4e377af52a04d7245ba11d981bfc9e8585a5e60e8512e9f003925f60ebe20bbc89b141a133edb386af7951c75f774f913de51b08505230659dfd0c2bc78ceed78e7b80b6a0df3eaf

###
# Microsoft Graph API Library
#
# @license
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# Revision: 1.1
###

include('compat_shared.inc');
include("http.inc");
include("url_func.inc");
include("debug.inc");
include("json.inc");
include("base64.inc");

##
# Authorize as a Registered App and get an Access Token
#
# @param  [tenant_id:string]  Tenant UUID for the Azure/Entra Instance we're auth'ing with
# @param  [app_id:string]     Client UUID for the Registered Application we're auth'ing as
# @param  [secret:string]     Client Secret for the Registered Application we're auth'ing as
#                             
# @return [string|NULL]       Access Token needed to make further API requests,
#                             NULL if the Authorization failed
##
function graph_auth_as_app(tenant_id, app_id, secret)
{
  var ret, res, access_token;;
  var errs = [];
  var host = "login.microsoftonline.com";
  var http_headers = {
    "Host": host,
    "User-Agent": "Nessus",
    "Content-Type": "application/x-www-form-urlencoded"};

  if (empty_or_null(tenant_id)) append_element(var:errs, value:'No Tenant ID was provided');
  if (empty_or_null(app_id)) append_element(var:errs, value:'No App ID was provided');
  if (empty_or_null(secret)) append_element(var:errs, value:'Client Secret was not found');

  if (max_index(errs) > 0)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Unable to Attempt App Authorization',
      msg_details:{'Errors':{'lvl':1, 'value':errs}
    });

    return NULL;
  }

  var content = "client_id="+urlencode(str:app_id)+
    "&scope="+urlencode(str:"https://graph.microsoft.com/.default")+ #.default REQUIRED for Client Credentails flow!
    "&client_secret="+urlencode(str:secret)+
    "&grant_type=client_credentials";

  var item = "https://"+host+"/"+tenant_id+"/oauth2/v2.0/token";

  if (get_kb_item('TEST/is_test'))
  {
    ret = get_kb_item("TEST/auth_response");
    if (!empty_or_null(ret)) ret = deserialize(ret);
  }
  else
  {
    ret = http_send_recv3(
      method       : "POST",
      target       : host,
      item         : item,
      port         : 443,
      add_headers  : http_headers,
      data         : content,
      transport    : ENCAPS_SSLv23 | ENCAPS_DISABLE_SSLv2 | ENCAPS_DISABLE_SSLv3);
  }

  if (empty_or_null(ret))
    append_element(var:errs, value:'No Response to Auth Rewuest');
  else
  {
    if (ret[0] !~ "200")
      append_element(var:errs, value:'Auth Request was unsuccesful: '+obj_rep(ret));

    if (empty_or_null(ret[2]))
      append_element(var:errs, value:'Response contained no body');
  }

  if (max_index(errs) > 0)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'App Authorization Failed',
      msg_details:{'Errors':{'lvl':1, 'value':errs}
    });

    return NULL;
  }

  # Parse the Token out of the response body
  res = json_read(ret[2]);
  access_token = res[0]['access_token'];

  if (empty_or_null(access_token))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Auth Request did not return an Access Token');
    return NULL;
  }

  return access_token;
}


##
# List all deviceLocalCredentialInfo (dLCI) objects within the Tenant
#
# @param  [token:string]  Authorization Token for making API calls
#
# @return [array|NULL]    Returns an array of ``Device Name: dLCI ID`` key:value pairs,
#                         NULL if the Request failed or no dLCIs were found
##
function graph_list_deviceLocalCredentialInfo(token)
{
  var ret, res;
  var errs = [];
  var host = "graph.microsoft.com";

  if (empty_or_null(token))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Unable to List deviceLocalCredentials: No Auth token provided');
    return NULL;
  }

  var http_headers = {
    "Host": host,
    "Authorization": "Bearer "+token,
    "User-Agent": "Nessus",
    "Content-Type": "application/json"};

  var item = "https://"+host+"/v1.0/directory/deviceLocalCredentials";

  if (get_kb_item('TEST/is_test'))
  {
    ret = get_kb_item("TEST/list_response");
    if (!empty_or_null(ret)) ret = deserialize(ret);
  }
  else
  {
    ret = http_send_recv3(
      method       : "GET",
      target       : host,
      item         : item,
      port         : 443,
      add_headers  : http_headers,
      follow_redirect: 1,
      transport    : ENCAPS_SSLv23 | ENCAPS_DISABLE_SSLv2 | ENCAPS_DISABLE_SSLv3);
  }

  if (empty_or_null(ret))
    append_element(var:errs, value:'No Response to List Request');
  else
  {
    if (ret[0] !~ "200")
      append_element(var:errs, value:'List Request was unsuccesful: '+obj_rep(ret));

    if (empty_or_null(ret[2]))
      append_element(var:errs, value:'Response contained no body');
  }

  if (max_index(errs) > 0)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'List deviceLocalCredentials Failed',
      msg_details:{'Errors':{'lvl':1, 'value':errs}});

    return NULL;
  }

  # Parse the deviceLocalCredentialInfo IDs out of the response body
  res = json_read(ret[2]);
  res = res[0];

  res = res['value'];

  if (empty_or_null(res) || typeof(res) != 'array')
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'List Request returned no results');
    return NULL;
  }

  return res;
}

##
# Get the deviceLocalCredentialInfo (with actual credentials) for the specified Device
#
# @param  [token:string]      Authorization Token for making API calls
# @param  [device_id:string]  dLCI ID of the Device to pull Credentials from
#
# @return [array|NULL]        Returns a list of deviceLocalCredentials (dLCs) containing the usernames and passwords 
#                             of Local Accounts on the specified Device,
#                             NULL if the Request failed or no dLCs were found
##
function graph_get_deviceLocalCredentialInfo(token, device_id)
{
  var ret, res;
  var errs = [];
  var host = "graph.microsoft.com";

  if (empty_or_null(token))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Unable to Get deviceLocalCredentialInfo: No Auth token provided');
    return NULL;
  }

  if (empty_or_null(device_id))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Unable to Get deviceLocalCredentialInfo: No Device ID provided');
    return NULL;
  }

  var http_headers = {
    "Host": host,
    "Authorization":"Bearer "+token,
    "User-Agent": "Nessus"};

  var item = "https://"+host+"/v1.0/directory/deviceLocalCredentials/"+device_id+"?$select=credentials";

  if (get_kb_item('TEST/is_test'))
  {
    ret = get_kb_item("TEST/get_response");
    if (!empty_or_null(ret)) ret = deserialize(ret);
  }
  else
  {
    ret = http_send_recv3(
      method       : "GET",
      target       : host,
      item         : item,
      port         : 443,
      add_headers  : http_headers,
      follow_redirect: 1,
      transport    : ENCAPS_SSLv23 | ENCAPS_DISABLE_SSLv2 | ENCAPS_DISABLE_SSLv3);
  }

  if (empty_or_null(ret))
    append_element(var:errs, value:'No Response to Get Request');
  else
  {
    if (ret[0] !~ "200") append_element(var:errs, value:'Get Request was unsuccesful: '+obj_rep(ret));
    if (empty_or_null(ret[2])) append_element(var:errs, value:'Response contained no body');
  }

  if (max_index(errs) > 0)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME,
      msg:'Get deviceLocalCredentials Failed',
      msg_details:{'Errors':{'lvl':1, 'value':errs}});

    return NULL;
  }

  # Parse the username + encoded passwords out of the response body
  res = json_read(ret[2]);
  res = res[0];
  res = res['credentials'];

  if (empty_or_null(res))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'No Credentials returned for '+device_id);
    return NULL;
  }

  return res;
}


##
# Attempt to pull LAPS credentials in an Azure/Entra Tenant via a Registered App
#
# @remark
# Basically this is a wrapper to call:
#
#   - `graph_auth_as_app()`_
#   - `graph_list_deviceLocalCredentialInfo()`_
#   - `graph_get_deviceLocalCredentialInfo()`_
#
# and format + return the output (with decrypted passwords)
#
# @param  [tenant_id:string]      Tenant UUID for the Azure/Entra Instance we're auth'ing with
# @param  [app_id:string]         Client UUID for the Registered Application we're auth'ing as
# @param  [client_secret:string]  Client Secret for the Registered Application we're auth'ing as
#
# @return [array|NULL]            Returns list consisting of deviceLocalCredentials (dLCs) that have an
#                                 additional field `password` containing the decrypted password for that account,
#                                 NULL if we ecountered failures or found no results
##
function laps_get_credentials(tenant_id, app_id, client_secret)
{
  var auth_token, dLCI_list, dLCI, dLC_list, i, total_creds;
  var LAPS_creds = [];

  auth_token = graph_auth_as_app(tenant_id:tenant_id, app_id:app_id, secret:client_secret);

  if (empty_or_null(auth_token))
    return NULL;

  # Get all our deviceLocalCredentialInfo objects (dLCIs)
  dLCI_list = graph_list_deviceLocalCredentialInfo(token:auth_token);

  if (empty_or_null(dLCI_list))
    return NULL;

  # For each dLCI, get the associated dLCs
  for (dLCI of dLCI_list)
  {
    dLC_list = graph_get_deviceLocalCredentialInfo(token:auth_token, device_id:dLCI.id);

    # For each dLC found, Decrypt the password and store the info 
    for (i=0; i<max_index(dLC_list); i++)
    {
      dLC_list[i]['password'] = base64decode(str:dLC_list[i].passwordBase64);
      append_element(var:LAPS_creds, value:dLC_list[i]);
    }
  }

  total_creds = int(max_index(LAPS_creds));
  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Found '+total_creds+' LAPS Credentials');

  return LAPS_creds;
}

