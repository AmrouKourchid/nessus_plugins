#TRUSTED 68591d792afdebea0a79a989f0258bb4ec283ce6e6a52b73bc2893d951ffb46e170cf482b3acb91e7fb1dde6990754d1fa96c52249067ee04cd1546c06fd417a35a77feaa512b631fa8b76844b7df7b79f1e3dece95f9885a1e63ca81504d6249f5f820ef8057d4a308029c987dee468ed200b86dea417bb6ec79462a6d370b9269fcfa9bc2b6ee40064786762564428b9a3c1c21af78ebfeeccac12e03826948ca705446f01e39acadd08a2ce3ad564036a0378398c54bf5bfbd98f3597edcf0c103a88134dbb5a1cb402a686e2ae5e0c41db07bcdffeae7fa7fe14f8785f51d8f5154c8ecacbe6224e23585d540002a3e4916f1e0f088b742ed24ee2b5ae486301594b065992b5aa42297273bf57f5f6779c57ad9806a0bbe960e945ef9ce6bb7525a32b18b66b09bb53c98c9b9489d0a56daf82d6bcbd1519631d1c409fef8e82c3fb503458e0789c2ffb97407312e07797113703768c673e005dba1a92106c4c82fc9e5e77cc110bcad1814ae9a27ae7b22f79a3a47c5cc69e877a0ebf47c873717500de07a334cc1d6f0f53b29aac0f84a846bf6e1115f72f88365cbd0e6e231355a2a83109b827c27af00037e582b19dbf436ad3351a2297b4eca4496daf31b357ed2836867788266eb730bb0e10212fec12413f0a9cc6fd40f16ea73feaa3d6b077b16d67ba2d5ca1b6c43aaabfdc820f299b043860b2c25ad0ccd525
#TRUST-RSA-SHA256 936b70cb4cf14f2da27e8319073918ec12e808c1949202ec583b0fe85c0157f690ad6f5f1bc80bbd17f0c4c0c8389127c73ae0f1a9c11a07127dc0880bfc54b7763cf4da196d7201974d8b3b55b4dcddd8dc7bc28de1b75286c8705ec3a211d208508a3bdd98a895d422e174f7af4db01b6f4dd718a81eff6e8c59c278a01a2a02bcc8799994d253f6d371cfd79655482aa746110da5784adfb9e35c37c4e3646247ee486034620af61ebcf14f2d68cd64946a6ef0b504f6f94fa75999138ce109ac3edd3866bb00f44c52bc137e089cbaf369b56408624bf90d5ad0dec18811e539ba5b0ef314d9c6539e4b48125f4356d66bce91cbf8f6005c7d41a38bbb17008180c56a6574f9eb649c7685bb130225cf7453193ac4e0881d118231b2df38586df0ac62a6acc599a8dd0dad71b4d417ba9d2928c42bf128a3c9ffe3060793950cd0dba0970c04a38ba132d74a8f1d9b4b4e3cb88d224e5b6d2db195ccbf86f36b490191341445823737832323ea4463107774098762420f8bb12ff28c11694e2cc4177e30aa6c3f9739b092e118d4bdd5c20cf68cab963517dcd3ca4970866324e6639da3fcf0dbc5ef0291a85693cd034cf24b777e6f72926f8f11c6d8edd24843f5457172c33ecf6d6b1db104b5d4341bd0b7e9cb7409a87fd09a63e06bf7dd0643cdacf70b7bd5dc369812ee90a3ecf02cc5370f78c48d03d81a3ca5d2
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# ldap_func.inc
# Revision: 1.25
#

include("compat_shared.inc");
include("der_funcs.inc");
include("debug.inc");

global_var _ldap_socket, _ldap_error, _msgid;

global_var _ldap_search_settings; # For paginated searches, we need to store some info

# LDAP request/response codes
global_var LDAP_BIND_REQUEST          = 0x60; # [01 1 00000] Int 96
global_var LDAP_BIND_RESPONSE         = 0x61; # [01 1 00001] Int 97
global_var LDAP_UNBIND_REQUEST        = 0x62; # [01 1 00010] Int 98
global_var LDAP_SEARCH_REQUEST        = 0x63; # [01 1 00011] Int 99
global_var LDAP_SEARCH_RES_ENTRY      = 0x64; # [01 1 00100] Int 100
global_var LDAP_SEARCH_RES_DONE       = 0x65; # [01 1 00101] Int 101
global_var LDAP_MODIFY_REQUEST        = 0x66; # [01 1 00110] Int 102
global_var LDAP_MODIFY_RESPONSE       = 0x67; # [01 1 00111] Int 103
global_var LDAP_ADD_REQUEST           = 0x68; # [01 1 01000] Int 104
global_var LDAP_ADD_RESPONSE          = 0x69; # [01 1 01001] Int 105
global_var LDAP_DEL_REQUEST           = 0x6a; # [01 1 01010] Int 106
global_var LDAP_DEL_RESPONSE          = 0x6b; # [01 1 01011] Int 107
global_var LDAP_MODIFYDN_REQUEST      = 0x6c; # [01 1 01100] Int 108
global_var LDAP_MODIFYDN_RESPONSE     = 0x6d; # [01 1 01101] Int 109
global_var LDAP_COMPARE_REQUEST       = 0x6e; # [01 1 01110] Int 110
global_var LDAP_COMPARE_RESPONSE      = 0x6f; # [01 1 01111] Int 111
global_var LDAP_ABANDON_REQUEST       = 0x70; # [01 1 10000] Int 112
global_var LDAP_SEARCH_RES_REF        = 0x73; # [01 1 10011] Int 115
global_var LDAP_EXTENDED_REQUEST      = 0x77; # [01 1 10111] Int 119
global_var LDAP_EXTENDED_RESPONSE     = 0x78; # [01 1 11000] Int 120
global_var LDAP_INTERMEDIATE_RESPONSE = 0x79; # [01 1 11001] Int 121

global_var ldap_operation_lookup = make_array(
  LDAP_BIND_REQUEST,      'LDAP BindRequest',             # App 0
  LDAP_BIND_RESPONSE,     'LDAP BindResponse',            # App 1
  LDAP_UNBIND_REQUEST,    'LDAP UnbindRequest',           # App 2
  LDAP_SEARCH_REQUEST,    'LDAP SearchRequest',           # App 3
  LDAP_SEARCH_RES_ENTRY,  'LDAP SearchResultEntry',       # App 4
  LDAP_SEARCH_RES_DONE,   'LDAP SearchResultDone',        # App 5
  LDAP_MODIFY_REQUEST,    'LDAP ModifyRequest',           # App 6
  LDAP_MODIFY_RESPONSE,   'LDAP ModifyResponse',          # App 7
  LDAP_ADD_REQUEST,       'LDAP AddRequest',              # App 8
  LDAP_ADD_RESPONSE,      'LDAP AddResponse',             # App 9
  LDAP_DEL_REQUEST,       'LDAP DelRequest',              # App 10
  LDAP_DEL_RESPONSE,      'LDAP DelResponse',             # App 11
  LDAP_MODIFYDN_REQUEST,  'LDAP ModifyDNRequest',         # App 12
  LDAP_MODIFYDN_RESPONSE, 'LDAP ModifyDNResponse',        # App 13
  LDAP_COMPARE_REQUEST,   'LDAP CompareRequest',          # App 14
  LDAP_COMPARE_RESPONSE,  'LDAP CompareResponse',         # App 15
  LDAP_ABANDON_REQUEST,   'LDAP AbandonRequest',          # App 16
  LDAP_SEARCH_RES_REF,    'LDAP SearchResultReference',   # App 19
  LDAP_EXTENDED_REQUEST,  'LDAP ExtendedRequest',         # App 23
  LDAP_EXTENDED_RESPONSE, 'LDAP ExtendedResponse',        # App 24
  LDAP_INTERMEDIATE_RESPONSE, 'LDAP IntermediateResponse' # App 25
);

# LDAP control oids
global_var LDAP_CTRL_PAGED_RESULTS = '1.2.840.113556.1.4.319';

# LDAP internal error codes
global_var LDAP_ERROR_SOCK_NO_DATA      = 1001;
global_var LDAP_ERROR_SOCK_INVALID_TAG  = 1002;
global_var LDAP_ERROR_INVALID_ID        = 1003;
global_var LDAP_ERROR_DECODE            = 1004;

global_var _ldap_error_lookup = make_array(
  LDAP_ERROR_SOCK_NO_DATA,      'LDAP_ERROR_SOCK_NO_DATA',
  LDAP_ERROR_SOCK_INVALID_TAG,  'LDAP_ERROR_SOCK_INVALID_TAG',
  LDAP_ERROR_INVALID_ID,        'LDAP_ERROR_INVALID_ID',
  LDAP_ERROR_DECODE,            'LDAP_ERROR_DECODE'
);

# LDAP filter codes
global_var LDAP_FILTER_AND          = 0xa0;
global_var LDAP_FILTER_OR           = 0xa1;
global_var LDAP_FILTER_NOTEQUAL     = 0xa2;
global_var LDAP_FILTER_EQUAL        = 0xa3;
global_var LDAP_FILTER_SUBSTRING_OR = 0xa4;

# codes
global_var MODIFY_DELETE = 2;

global_var soc_error_lookup = {
  ETIMEDOUT:    'The last send() or recv() operation timed out',
  ECONNRESET:   'The connection was reset during the last send() or '+
                'recv() attempted to read on the socket even though the remote side closed the connection',
  EUNREACH:     'The remote host is unreachable',
  EUNKNOWN:     'An Unknown Error was encountered',
  ESSL:         'Something went wrong during the SSL negotiation',
  EINPROGRESS:  'Another operation is still in progress on this socket',
  ECONNREFUSED: 'The connection was refused'
};

# LDAP Result Codes
global_var LDAP_SUCCESS                         = 0x00; # 0
global_var LDAP_OPERATIONS_ERROR                = 0x01; # 1
global_var LDAP_PROTOCOL_ERROR                  = 0x02; # 2
global_var LDAP_TIME_LIMIT_EXCEEDED             = 0x03; # 3
global_var LDAP_SIZE_LIMIT_EXCEEDED             = 0x04; # 4
global_var LDAP_COMPARE_FALSE                   = 0x05; # 5
global_var LDAP_COMPARE_TRUE                    = 0x06; # 6
global_var LDAP_AUTH_METHOD_NOT_SUPPORTED       = 0x07; # 7
global_var LDAP_STRONGER_AUTH_REQUIRED          = 0x08; # 8
                                                        # 9 RESERVED
global_var LDAP_REFERRAL                        = 0x0a; # 10
global_var LDAP_ADMIN_LIMIT_EXCEEDED            = 0x0b; # 11
global_var LDAP_UNAVAILABLE_CRITICAL_EXTENSION  = 0x0c; # 12
global_var LDAP_CONFIDENTIALITY_REQUIRED        = 0x0d; # 13
global_var LDAP_SASL_BIND_IN_PROGRESS           = 0x0e; # 14
                                                        # 15 RESERVED
global_var LDAP_NO_SUCH_ATTRIBUTE               = 0x10; # 16
global_var LDAP_UNDEFINED_ATTRIBUTE_TYPE        = 0x11; # 17
global_var LDAP_INAPPROPRIATE_MATCHING          = 0x12; # 18
global_var LDAP_CONSTRAINT_VIOLATION            = 0x13; # 19
global_var LDAP_ATTRIBUTE_OR_VALUE_EXISTS       = 0x14; # 20
global_var LDAP_INVALID_ATTRIBUTE_SYNTAX        = 0x15; # 21
                                                        # 22-31 UNUSED
global_var LDAP_NO_SUCH_OBJECT                  = 0x20; # 32
global_var LDAP_ALIAS_PROBLEM                   = 0x21; # 33
global_var LDAP_INVALID_DN_SYNTAX               = 0x22; # 34
                                                        # 35 RESERVED for undefined isLeaf
global_var LDAP_ALIAS_DEREFERENCING_PROBLEM     = 0x24; # 36
                                                        # 37-47 UNUSED
global_var LDAP_INAPPROPRIATE_AUTHENTICATION    = 0x30; # 48
global_var LDAP_INVALID_CREDENTIALS             = 0x31; # 49
global_var LDAP_INSUFFICIENT_ACCESS_RIGHTS      = 0x32; # 50
global_var LDAP_BUSY                            = 0x33; # 51
global_var LDAP_UNAVAILABLE                     = 0x34; # 52
global_var LDAP_UNWILLING_TO_PERFORM            = 0x35; # 53
global_var LDAP_LOOP_DETECT                     = 0x36; # 54
                                                        # 55-63 UNUSED
global_var LDAP_NAMING_VIOLATION                = 0x40; # 64
global_var LDAP_OBJECTCLASS_VIOLATION           = 0x41; # 65
global_var LDAP_NOT_ALLOWED_ON_NONLEAF          = 0x42; # 66
global_var LDAP_NOT_ALLOWED_ON_RDN              = 0x43; # 67
global_var LDAP_ENTRY_ALREADY_EXISTS            = 0x44; # 68
global_var LDAP_OBJECTCLASS_MODS_PROHIBITED     = 0x45; # 69
                                                        # 70 RESERVED for CLDAP
global_var LDAP_AFFECTS_MULTIPLE_DSAS           = 0x47; # 71
                                                        # 72-79 UNUSED
global_var LDAP_OTHER                           = 0x50; # 80


global_var ldap_result_lookup = make_array(
  LDAP_SUCCESS,                         'Success: The Operation completed successfully',
  LDAP_OPERATIONS_ERROR,                'Operations Error: The requested operation is not properly sequenced '+
                                          'with relation to other operations',
  LDAP_PROTOCOL_ERROR,                  'Protocol Error: The requested operation is malformed or unsupported',
  LDAP_TIME_LIMIT_EXCEEDED,             'Time Limit Exceeded: The time limit specified by the client was exceeded '+
                                          'before the requested operation could be completed',
  LDAP_SIZE_LIMIT_EXCEEDED,             'Size Limit Exceeded: The size limit specified by the client was exceeded '+
                                          'before the requested operation could be completed',
  LDAP_COMPARE_FALSE,                   'Compare False: The Compare operation has successfully completed and the '+
                                          'assertion has evaluated to FALSE or Undefined',
  LDAP_COMPARE_TRUE,                    'Compare True: The Compare operation has successfully completed and the '+
                                          'assertion has evaluated to TRUE',
  LDAP_AUTH_METHOD_NOT_SUPPORTED,       'Auth Method Not Supported: The authentication method is not supported',
  LDAP_STRONGER_AUTH_REQUIRED,          'Stronger Auth Required: The server requires strong(er) authentication in '+
                                          'order to complete the operation',
  LDAP_REFERRAL,                        'Referral: A referral needs to be chased to complete the requested operation',
  LDAP_ADMIN_LIMIT_EXCEEDED,            'Admin Limit Exceeded: An administrative limit has been exceeded',
  LDAP_UNAVAILABLE_CRITICAL_EXTENSION,  'Unavailable Critical Extension: A critical control is unrecognized',
  LDAP_CONFIDENTIALITY_REQUIRED,        'Confidentiality Required: Data confidentiality protections are required '+
                                          'to complete the requested operation',
  LDAP_SASL_BIND_IN_PROGRESS,           'SASL Bind In Progress: The server requires the client to send a new bind '+
                                          'request, with the same SASL mechanism, to continue the authentication process',
  LDAP_NO_SUCH_ATTRIBUTE,               'No Such Attribute: The named entry does not contain the specified attribute or attribute value',
  LDAP_UNDEFINED_ATTRIBUTE_TYPE,        'Undefined Attribute Type: The request contains an unrecognized attribute description',
  LDAP_INAPPROPRIATE_MATCHING,          'Inappropriate Matching: An attempt was made to use a matching rule not '+
                                          'defined for the attribute type concerned',
  LDAP_CONSTRAINT_VIOLATION,            'Constraint Violation: The client supplied an attribute value that does not '+
                                          'conform to the constraints placed upon it by the data model',
  LDAP_ATTRIBUTE_OR_VALUE_EXISTS,       'Attribute or Value Exists: The client supplied an attribute or value to be '+
                                          'added to an entry, but the attribute or value already exists',
  LDAP_INVALID_ATTRIBUTE_SYNTAX,        'Invalid Attribute Syntax: A purported attribute value does not conform to '+
                                          'the syntax of the attribute',
  LDAP_NO_SUCH_OBJECT,                  'No Such Object: The object does not exist in the DIT',
  LDAP_ALIAS_PROBLEM,                   'Alias Problem: An alias problem has occurred',
  LDAP_INVALID_DN_SYNTAX,               'Invalid DN Syntax: An LDAPDN or RelativeLDAPDN field of the request does '+
                                          'not conform to the required syntax or contains attribute values that do '+
                                          'not conform to the syntax of the attribute\'s type',
  LDAP_ALIAS_DEREFERENCING_PROBLEM,     'Alias Dereferencing Problem: A problem occurred while dereferencing an alias',
  LDAP_INAPPROPRIATE_AUTHENTICATION,    'Inappropriate Authentication: The server requires the client that had '+
                                          'attempted to bind anonymously or without supplying credentials to '+
                                          'provide some form of credentials',
  LDAP_INVALID_CREDENTIALS,             'Invalid Credentials: The provided credentials are invalid',
  LDAP_INSUFFICIENT_ACCESS_RIGHTS,      'Insufficient Access Rights: The client does not have sufficient access '+
                                          'rights to perform the operation',
  LDAP_BUSY,                            'Busy: The server is too busy to service the operation',
  LDAP_UNAVAILABLE,                     'Unavailable: The server is shutting down or a subsystem necessary to '+
                                          'complete the operation is offline',
  LDAP_UNWILLING_TO_PERFORM,            'Unwilling to Perform: The server is unwilling to perform the operation',
  LDAP_LOOP_DETECT,                     'Loop Detect: The server has detected an internal loop',
  LDAP_NAMING_VIOLATION,                'Naming Violation: The entry\'s name violates naming restrictions',
  LDAP_OBJECTCLASS_VIOLATION,           'ObjectClass Violation: The entry violates object class restrictions',
  LDAP_NOT_ALLOWED_ON_NONLEAF,          'Not Allowed on Non Leaf: The requested operation is inappropriately '+
                                          'acting upon a non-leaf entry',
  LDAP_NOT_ALLOWED_ON_RDN,              'Not Allowed on RDN: The requested operation is inappropriately attempting '+
                                          'to remove a value that forms the entry\'s relative distinguished name',
  LDAP_ENTRY_ALREADY_EXISTS,            'Entry Already Exists: The request cannot be fulfilled as the target '+
                                          'entry already exists',
  LDAP_OBJECTCLASS_MODS_PROHIBITED,     'ObjectClass Mods Prohibited: An attempt to modify the object class(es) '+
                                          'of an entry\'s \'objectClass\' attribute is prohibited',
  LDAP_AFFECTS_MULTIPLE_DSAS,           'Affects Multiple DSAs: The operation cannot be performed as it would '+
                                          'affect multiple servers (DSAs)',
  LDAP_OTHER,                           'Other: The server has encountered an internal error'
);

##
# Inits internal ldap data.
# @remark Starts ``_msgid`` at 1
#
# @param  [socket:int]  Socket to use for LDAP communication
##

function ldap_init(socket)
{
  _msgid = 1;
  _ldap_socket = socket;
}

##
# Get the Error Code of the last error LDAP encountered
#
# @return [int|NULL]  int representation of LDAP Error,
#                     NULL if no error is present
##

function ldap_get_last_error()
{
  if (isnull(_ldap_error))
    return NULL;
  else
    return _ldap_error;
}

##
# Flag that LDAP has encountered an error
#
# @anonparam  [l:int] The code corrosponding to the LDAP Error being reported
#
# @return     [NULL]
##

function ldap_set_error()
{
  var l;
  l = _FCT_ANON_ARGS[0];

  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Experienced an LDAP Error: '+_ldap_error_lookup[l]);

  _ldap_error = l;
  return NULL;
}


##
# Sends an LDAP Request and parse the response
#
# @param  [data:data]   The DER encoded LDAP Request Message to send
#
# @return [array|NULL]  The next Response from LDAP, (result of `ldap_recv()`_)
#                       NULL if failures or no response
##

function ldap_request_sendrecv(data)
{
  var soc_port = get_source_port(_ldap_socket);

  if (empty_or_null(soc_port)) soc_port = 'CLOSED';

  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'['+soc_port+']['+_msgid+'] Sending LDAP Request...',
    msg_details:{'Message':{'lvl':3, 'value':'DER encoded:\n'+display_der(data:data)+'\n'}});

  send(socket:_ldap_socket, data:data);
  return ldap_recv();
}

##
# Receives the next LDAP response and keeps the current Message ID the same.
#
# @remark Used when a Request has multiple responses
#
# @return [array|NULL]  The next Response from LDAP, (result of `ldap_recv()`_)
#                       NULL if failures or no response
##

function ldap_recv_next()
{
  _msgid--; # -1 on the ID since the "next" response will match the orginal ID sent
  return ldap_recv();
}

##
# Sends an LDAP Request to peform a Search.
#
# @remark
# Only SENDS the Request! Does NOT recv or return the response.
# Use in conjunction with `ldap_recv_search_result()`_ to get response(s)
#
# @param  [data:data] DER encoded LDAP Request Message
##

function ldap_start_search(data)
{
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'['+_msgid+'] Starting LDAP search...',
    msg_details:{'Message':{'lvl':3, 'value':'DER encoded:\n'+display_der(data:data)+'\n'}});

  send(socket:_ldap_socket, data:data);
}

##
# Creates the LDAP Request to get the next page of results in the current search
#
# @remark
# Each Page of results is a separate search request
#
# @return [data|NULL] A DER encoded LDAP Paged Results Control for requesting the next page of results,
#                     NULL if there are no more pages to get or if we cannot construct the Control
##

function ldap_request_next_page()
{
  var next_page_ctrl;

  if (empty_or_null(_ldap_search_settings.search))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'No Saved Search in Search Settings...');
    return NULL;
  }

  # If we don't have a cookie for the next page, then there are no more pages to get!
  if (empty_or_null(_ldap_search_settings.controls[LDAP_CTRL_PAGED_RESULTS]['next_page']))
    return NULL;

  if (get_kb_item('TEST/is_test'))
    return _ldap_search_settings.controls[LDAP_CTRL_PAGED_RESULTS]['next_page'];

  # Create the Paged Results Control to fetch the next page!
  # This Control shoule be EXACTLY THE SAME as the original Paged Results Control sent in the Search Request with the
  # ONLY DIFFERENCE being the Cookie (next_page here)
  next_page_ctrl = ldap_paged_results_ctrl(
    critical:   _ldap_search_settings.controls[LDAP_CTRL_PAGED_RESULTS]['criticality'],
    size:       _ldap_search_settings.controls[LDAP_CTRL_PAGED_RESULTS]['page_size'],
    next_page:  _ldap_search_settings.controls[LDAP_CTRL_PAGED_RESULTS]['next_page']);

  return next_page_ctrl;
}

##
# Recvs the next Response from LDAP and if it's a Search Result, return it!
#
# @remark
# If we hit the end of a page, we go ahead and start fetching the results from the next one.
# If there is no Response, or the Response is not a Search Result, return NULL
#
# Return List format:
# ```
# [
#   LDAP Search Result Type,
#   DER encoded result data,
#   next_page # Only if this was a Search Result Done and there is a next page to get
# ]
# ```
#
# @param [auto_page:bool] If TRUE, automatically start the Search for the Next page once the current page completes
#
# @return [list|NULL]     The next Search Result for the current search,
#                         NULL if the next Message from LDAP was not a search result
##

function ldap_recv_search_result(auto_page)
{
  var result, next_page;

  if (!auto_page)
    auto_page = false;
  else
    auto_page = true;

  # recv the next message
  result = ldap_recv();

  if (isnull(result))
    return NULL;

  _msgid--;

  # Handle the different result responses

  if (result[0] == LDAP_SEARCH_RES_ENTRY)
    return result;

  if (result[0] == LDAP_SEARCH_RES_REF)
    return result;

  if (result[0] == LDAP_SEARCH_RES_DONE)
  {
    # Go ahead and try and make the LDAP Request for the Next Page of results
    next_page = ldap_request_next_page();

    # If we couldn't get the next page (or if there are no more pages to get), go ahead and finish this search)
    if (!empty_or_null(next_page))
    {
      result[2] = next_page;

      if (auto_page)
      {
        if (get_kb_item('TEST/is_test'))
          replace_kb_item(name:'TEST/auto_paged', value:next_page);
        else
        {
          dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Fetching Next Page of Results...');

          # Start the Search for the next page of results
          ldap_start_search(data:ldap_request(
            code:LDAP_SEARCH_REQUEST,
            data:_ldap_search_settings.search,
            controls:[next_page]));
        }
      }

      return result;
    }
    else
    {
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'LDAP Search is complete!');
      _ldap_search_settings = NULL; # Search is now complete, so clear out our saved search settings
        return NULL;
    }
  }
  # if the response wasn't a valid search result response, return NULL
  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Received something other than a Search Result...');
  return NULL;
}

##
# Receives search results via pagination and offers some advanced options
#
# @remark
# Calls `ldap_recv_search_result()`_ to get results
# Relies on data stored in ``_ldap_search_settings`` and will fail if no data is found
# Return Array format:
# ```
# {
#   results:    [list], # List of Results returned by the search 
#   next_page:  [array] # LDAP Paged Results Control for next page (NULL if no further pages)
# }
# ```
#
# @param  [auto_page:bool]    If TRUE, automatically start the Search for the Next page once the current page completes
# @param  [auto_parse:bool]   If TRUE, automatically parse the results
# @param  [full_values:bool]  If TRUE, automatically parse the results and fetch the full range of Attribute Values
# @param  [include_refs:bool] If TRUE, Search Result References will be included in the results
#
# @return [array]             An array containing the results of the search and the LDAP Control needed for
#                             fetching the next page (if applicable)
##

function ldap_recv_search_advanced(auto_page, auto_parse, full_values, include_refs)
{
  var results = [];
  var ret, i, parsed_entry;
  var next_page_ctrl, next_search;
  var base_obj, encoded_search;
  var recv_attempts, max_recvs = 1500;

  # Save the info we stored in _ldap_search_settings, since it'll get overwritten if we fetch full values
  if (!empty_or_null(_ldap_search_settings['base_object']))
    base_obj = _ldap_search_settings.base_object;

  if (!empty_or_null(_ldap_search_settings['search']))
    encoded_search = _ldap_search_settings.search;

  if (!empty_or_null(_ldap_search_settings.controls[LDAP_CTRL_PAGED_RESULTS]['page_size']))
    max_recvs = 2 * _ldap_search_settings.controls[LDAP_CTRL_PAGED_RESULTS].page_size;

  if (!auto_page)
    auto_page = false;
  else
    auto_page = true;

  if (!auto_parse)
    auto_parse = false;
  else
    auto_parse = true;

  if (!full_values)
    full_values = false;
  else
    full_values = true;

  if (!include_refs)
    include_refs = false;
  else
    include_refs = true;

  recv_attempts = max_recvs;
  repeat {

    ret = ldap_recv_search_result();

    if (ret[0] == LDAP_SEARCH_RES_ENTRY)
      append_element(var:results, value:ret);

    if (ret[0] == LDAP_SEARCH_RES_REF && include_refs == true)
      append_element(var:results, value:ret);

    if (ret[0] == LDAP_SEARCH_RES_DONE && !empty_or_null(ret[2]))
      next_page_ctrl = ret[2];

    recv_attempts--;
  } until(recv_attempts <= 0 || empty_or_null(ret) || ret[0] == LDAP_SEARCH_RES_DONE);


  if (recv_attempts <= 0)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Exhausted attempts to receive next search results...');
  }

  # Now results contains all the Search Result Entries for the current page
  # So, lets parse the results and fetch any missing attribute values as needed

  if (!empty_or_null(results) && (auto_parse || full_values))
  {
    for (i=0; i<max_index(results); i++)
    {
      # Only parse Result Entries
      if (results[i][0] != LDAP_SEARCH_RES_ENTRY)
        continue;

      # If user wants full attribute values, (and we have the base_object)
      # Also, we need the base object in order to do subsequent searches for attributes values
      # so if we don't have one, the best we can do is the usual parse
      if (full_values == true && !empty_or_null(base_obj))
        results[i] = ldap_fetch_full_attributes(object:base_obj, search_entry:results[i]);
      else # Otherwise, pull the full range of values for all attributes
        results[i] = ldap_parse_search_entry(data:results[i][1]);
    }
  }

  # All the Result Entries have been parsed and any ranged attributs have been fully fetched

  # If the user enabled Auto-Paging, go ahead and start the search for the next page
  if (auto_page && !empty_or_null(encoded_search) && !empty_or_null(next_page_ctrl))
  {
    if (get_kb_item('TEST/is_test'))
      replace_kb_item(name:'TEST/auto_paged', value:next_page_ctrl);
    else
    {
      dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Fetching Next Page of Results...');
      next_search = ldap_search_request(object:base_obj, encoded:encoded_search, controls:[next_page_ctrl]);
      ldap_start_search(data:next_search);
    }
  }

  return {
    'results': results,
    'next_page': next_page_ctrl
  };
}

##
# Receives a Message from LDAP
#
# @remark
# We receive the message in a series of stages:
#
# 1. | ``recv()`` the first two Octets (the response Type and Length respectively)
#    | The only valid Type is SEQUENCE: 0x30 (binary:[00 1 10000])
#    | Any other Type will result in a return of NULL
# 2. If we detect that the Length is in Long-Form, ``recv()`` the remaining Length Octets
# 3. ``recv()`` the next ``len`` Octets (the response Content)
# 4. | Decode Message ID from the Content (should be first element)
#    | If the Decoded ID matches ``_msgid`` (the Message ID for our current operation),
#    | increment ``_msgid`` by one (``_msgid`` is now the ID we'll used for our next request)
#    | If the Decoded ID does not match our current ``_msgid``, return NULL
# 5. | Decode the LDAP Operation Type (the second element)
#    | Note that we just decode the Type+Length here, not the content itself
# 6. If the LDAP Operation is one that supports an LDAP Result message, Decode it
# 7. If present, decode the LDAP Control data (the third element)
#
# Return List format:
# ```
# [
#   LDAP Operation Type,
#   LDAP Operation Content, # Still DER encoded
#   Index of next Octet after Content  
# ]
# ```
#
# @return [list|NULL]  A List representing the LDAP Operation of the response
##

function ldap_recv()
{
  var buf, len, length_buf, msgid, id, content, controls;
  var tag_octs, len_octs, content_octs, controls_octs, operation, ldap_result;
  var soc_port = get_source_port(_ldap_socket);

  # These LDAP Operations have result codes we can grab!
  var response_ops = raw_string(0x61, 0x65, 0x67, 0x69, 0x6b, 0x6d, 0x6f, 0x78, 0x79);

  if (empty_or_null(soc_port)) soc_port = 'CLOSED';

  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'['+soc_port+'][#'+_msgid+'] Fetching the next LDAP Response...');

  if (get_kb_item('TEST/is_test'))
  {
    operation = get_kb_item('TEST/test_response');
    if (isnull(operation))
      return NULL;
    else
    {
      rm_kb_item(name:'TEST/test_response');
      return deserialize(operation);
    }
  }

  # Fetch the Response Type and Length (first two octets)
  buf = recv(socket:_ldap_socket, length:2, min:2);

  if (empty_or_null(buf) || strlen(buf) < 2)
    return handle_recv_error(buf:buf, socket:_ldap_socket, msg:'Error receiving Response Metadata');

  tag_octs = buf[0]; # Message type
  len_octs = buf[1]; # Message length

  # All LDAP Messages should be a SEQUENCE, 0x30 (00 1 10000)
  if (ord(tag_octs) != BER_SEQUENCE_TAG)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'['+soc_port+'][#'+_msgid+'] Response is an invalid type',
      msg_details:{
        'Type Received':{'lvl':1, 'value':data2hexstr(data:tag_octs)},
        'Raw Buffer':{'lvl':3, 'value':data2hexstr(data:buf)}
      });

    return ldap_set_error(LDAP_ERROR_SOCK_INVALID_TAG);
  }

  len = ord(len_octs);

  if (len > 127)
  {
    len -= 128;

    length_buf = recv(socket:_ldap_socket, length:len, min:len);

    if (empty_or_null(length_buf) || strlen(length_buf) < len)
      return handle_recv_error(buf:buf, socket:_ldap_socket, msg:'Error receiving Response Length data');

    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'['+soc_port+'][#'+_msgid+'] Received '+strlen(length_buf)+'/'+len+' Length Octets');

    len_octs += length_buf;
    len = integer (i:length_buf);
  }

  # Now that we know the size of the message, pull the fetch the rest of it!
  buf = recv(socket:_ldap_socket, length:len, min:len);

  if (empty_or_null(buf) || strlen(buf) < len)
    return handle_recv_error(buf:buf, socket:_ldap_socket, msg:'Error receiving Response content');

  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'['+soc_port+'][#'+_msgid+'] Received '+strlen(buf)+'/'+len+' Content Octets');

  content_octs = buf;

  # The firest element of the message content is the call ID for the message
  msgid = der_decode(data:content_octs, pos:0);
  if (isnull(msgid) || msgid[0] != BER_INTEGER_TAG)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'['+soc_port+'][#'+_msgid+'] Error decoding Response messaged ID');
    return ldap_set_error(LDAP_ERROR_DECODE);
  }

  id = integer(i:msgid[1]);

  # if the response call ID isn't what we're expecting, that's a problem
  if (id != _msgid)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'['+soc_port+'][#'+_msgid+'] Response messaged ID is Invalid',
      msg_details:{
        'Expected Call ID':{'lvl':2, 'value':_msgid},
        'Response ID':{'lvl':2, 'value':id}
      });
    return ldap_set_error(LDAP_ERROR_INVALID_ID);
  }
  _msgid++;

  # The next element will be the LDAP Operation Content. These are all Application specific SEQUENCEs
  # Meaning we'll need bespoke decoding for the actual content of the operation
  operation = der_decode(data:content_octs, pos:msgid[2]);

  if (isnull(operation))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'['+soc_port+'][#'+id+'] Unable to decode Response LDAP Operation');
    return ldap_set_error(LDAP_ERROR_DECODE);
  }

  # If the operation is a response, let's grab the result code
  if (raw_string(operation[0]) >< response_ops)
  {
    ldap_result = ldap_parse_response(data:operation[1]);

    if (!empty_or_null(ldap_result))
    {
      ldap_result = ldap_result[0]; # The Result Code
      ldap_result = ldap_result_lookup[ldap_result];

      if (empty_or_null(ldap_result))
        ldap_result = 'Unknown Result Code';
    }
  }

  # The final (and OPTIONAL) element is a list of LDAP Controls
  controls_octs = substr(content_octs, operation[2]); # Everything after the LDAP Operation

  if (strlen(controls_octs) > 0)
    ldap_parse_controls(ctrls:controls_octs);

  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'['+soc_port+'][#'+id+'] Received LDAP Response!',
    msg_details:{
      'Content Size':{'lvl':2, 'value':len+' Bytes'},
      'Operation':{'lvl':2, 'value':ldap_operation_lookup[operation[0]]},
      'Operation Data':{'lvl':4, 'value':display_der(data:operation[1])},
      'Result':{'lvl':2, 'value':ldap_result},
      'Controls':{'lvl':3, 'value':keys(_ldap_search_settings.controls)},
      'Controls Data':{'lvl':4, 'value':display_der(data:controls_octs)}
    });

  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'['+soc_port+'][#'+id+'] Raw LDAP Response',
    msg_details:{
      'DER Encoded':{'lvl':3, 'value':display_der(data:(tag_octs+len_octs+content_octs))}
    });

  return operation;
}

##
# Handles errors that occur when attempting to receive response data from ldap 
# 
# @remark
# Will attempt to debug log out what data we did manage to get (if any)
#
# @param  [buf:data]    Raw data we got from ``recv()``
# @param  [socket:int]  ID of the Socket that was used for the communication
# @param  [msg:string]  String describing the context of what went wrong
#
# @return [NULL]        Result of `ldap_set_error()`_
#
##

function handle_recv_error(buf, socket, msg)
{
  var soc_error;

  # So what did we actually get?
  if (empty_or_null(buf))
    buf = 'No Data Received';
  else
    buf = data2hexstr(data:buf);

  # Did something go wrong with the socket?
  if (empty_or_null(socket))
    soc_error = 'Socket Info Unavailable';
  else
    soc_error = socket_get_error(_ldap_socket);

  if (isnull(soc_error))
    soc_error = EUNKNOWN;

  if (empty_or_null(msg))
    msg = 'Error receiving LDAP Response';

  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:msg,
    msg_details:{
      'Raw Buffer':{'lvl':1, 'value':buf},
      'Socket Error':{'lvl':1, 'value':soc_error_lookup[soc_error]}
    });

  return ldap_set_error(LDAP_ERROR_SOCK_NO_DATA);
}

##
# Creates an LDAP Request Message
#
# @remark
# The LDAP Message created will have the current value of ``_msgid`` as its Message ID
# (So be careful when making multiple LDAP Requests in a row with out actually sending them)
#
# @param  [code:int]      The LDAP Operation Type of this Request
# @param  [data:data]     The DER encoded Content of the LDAP Operation Request
# @param  [controls:list] Optional List of LDAP Controls to send with the Request
#
# @return [data]          A DER encoded LDAP Request Message
##

function ldap_request(code, data, controls)
{
  var l, i, c;

  l = der_encode_int(i:_msgid) +       # Message ID
      der_encode(tag:code, data:data); # Protocol Operation

  # If any Controls were provided, process them and add them to the Message
  if (!empty_or_null(controls) && typeof_ex(controls) == 'list')
  {
    _ldap_search_settings['controls'] = {};

    c = '';
    for (i=0; i<max_index(controls); i++)
    {
      # Store the control settings as we build our request (With Control Type OID as the Key)
      _ldap_search_settings.controls[controls[i].type] = controls[i].settings;

      # Add the DER encoding of the control to the list
      c = c + controls[i].encoded;
    }

    # 0xa0 -> 10 1 00000 -> Contextual, Constructed, End of Content (APP 0 = Controls)
    l = l + der_encode(tag:0xa0, data:c);
  }

  # Wrap it all up in a SEQUENCE!
  l = der_encode_list(list:l);

  return l;
}


##
# Creates an LDAP Bind Request
#
# @param  [name:string] Username of the user to bind as
# @param  [pass:string] Password of the user to bind as
#
# @return [data]        A DER encoded LDAP Bind Request Message
##
function ldap_bind_request(name, pass)
{
  var data, ret;
  if (isnull(name)) name = "";
  if (isnull(pass)) pass = "";

  data =
    der_encode_int(i:3) +                   # LDAP version
    der_encode_octet_string(string:name) +  # name
    der_encode(tag:BER_AUTHENTICATION_TAG, data:pass);

  return ldap_request(code:LDAP_BIND_REQUEST, data:data);
}

##
# Parses a DER encoded Enumeration
#
# @param  [data:data] The DER Encoded Enumeration to decode
#
# @return [int|NULL]  The Integer representation of the Enumeration Value,
#                     NULL if we were unable to decode the data
##
function ldap_parse_enumerated(data)
{
  var tmp;

  tmp = der_parse_data(tag:BER_ENUMERATED_TAG, data:data);

  if (isnull(tmp))
    return ldap_set_error(LDAP_ERROR_DECODE);

  return integer(i:tmp);
}

##
# Parses an LDAP Response
#
# @remark
# Format of return List:
# ```
# [
#   Result Code,
#   Matched DN,
#   Diagnostic Message
# ]
# ```
#
# @param  [data:data] The DER encoded LDAP Response to parse
#
# @return [list|NULL] A list containing the decoded data elements,
#                     NULL if we encountered errors while decoding
##
function ldap_parse_response(data)
{
  var list, result, dn, msg;

  list = der_parse_list(list:data);
  if (isnull(list) || list[0] < 3)
    return ldap_set_error(LDAP_ERROR_DECODE);

  # Parse the LDAPResult

  # Result Code
  result = ldap_parse_enumerated(data:list[1]);
  if (isnull(result))
    return ldap_set_error(LDAP_ERROR_DECODE);

  # Matched DN
  dn = der_parse_octet_string(string:list[2]);
  if (isnull(result))
    return ldap_set_error(LDAP_ERROR_DECODE);

  # Diagnostic Message
  msg = der_parse_octet_string(string:list[3]);
  if (isnull(result))
    return ldap_set_error(LDAP_ERROR_DECODE);

  return mklist(result, dn, msg);
}

##
# Parses a DER encoded LDAP Bind Response
#
# @remark
# Since the Response for an LDAP Bind is an LDAP Response, this just calls `ldap_parse_response()`_
#
# @param  [data:data] The DER encoded LDAP Bind Response
#
# @return [list|NULL] A list containing the decoded data elements,
#                     NULL if we encountered errors while decoding
##
function ldap_parse_bind_response(data)
{
  return ldap_parse_response(data:data);
}

##
# Parses a DER encoded LDAP Modify Response
#
# @remark
# Since the Response for an LDAP Modify is an LDAP Response, this just calls `ldap_parse_response()`_
#
# @param  [data:data] The DER encoded LDAP Modify Response
#
# @return [list|NULL] A list containing the decoded data elements,
#                     NULL if we encountered errors while decoding
##
function ldap_parse_modify_response(data)
{
  return ldap_parse_response(data:data);
}


##
# Creates an LDAP Modify Request
#
# @param  [object:string] Search Base DN
# @param  [operation:int] Operation to be performed on the object
# @param  [data:list]     List of properties to modify
#
# @return [data]          The DER encoded LDAP Modify Request Message
##
function ldap_modify_request(object, operation, data)
{
  var item, mlist, req, list;

  item =
    der_encode_int(i:operation) +
    der_encode_list(list:data);

  mlist = der_encode_list(list:item); # ItemList

  req =
    der_encode_octet_string (string:object) +
    der_encode_list(list:mlist);

  return ldap_request(code:LDAP_MODIFY_REQUEST, data:req);
}


##
# Creates an LDAP Search Request
#
# @remark
# This function updates ``_ldap_search_settings`` with the settings provided.
# (Be careful not to accidentally overwrite an ongoing search's data by calling this!)
#
# @param  [object:string]   Search Base DN
# @param  [filter:list]     List of LDAP Filter Criteria to apply to the search
# @param  [scope:int]       Scope of the Search Request. Defaults to 0 (baseDN)
# @param  [attributes:list] List of the attributes to pull for each Search Result
# @param  [encoded:data]    Optional DER encoded LDAP Search Settings (used for repeat searches)
# @param  [control:list]    Optional list of LDAP Controls to apply to the Search Request
#
# @return [data]            A DER encoded LDAP Search Request Message
##
function ldap_search_request(object, filter, scope, attributes, encoded, controls)
{
  var req, attr, attrstr, items, filterstr, item;

  # If the user already has an encoded search request, we can skip to the end
  if (empty_or_null(encoded))
  {
    # Convert the attributes to a list if it isn't one already
    if (isnull(attributes))
      attributes = make_list("");
    else
    {
      if (typeof(attributes) != 'array')
        attributes = make_list(attributes);
    }

    if (isnull(scope))
      scope = 0;

    attrstr = "";
    foreach attr (attributes)
    {
      attrstr = attrstr + der_encode_octet_string(string:attr);
    }

    # Construct the filter if it is passed in as a list
    if (isnull(filter))
      filter = '';

    filterstr = '';
    if (typeof(filter) != 'array')
    {
      filterstr = der_encode_filter(filter:filter);
    }
    else
    {
      item = filter[0];
      if (!isnull(item['left']) && !isnull(item['conditional']) && !isnull(item['right']))
      {
        filterstr += der_encode_octet_string(string:item['left']);
        filterstr += der_encode_octet_string(string:item['right']);
        filterstr = der_encode_filter(code:item['conditional'], filter:filterstr);
      }
      else
        filterstr = der_encode_filter(filter:'objectClass');
    }

    req =                                       # LDAP_SEARCH_REQUEST Protocol Op
      der_encode_octet_string(string:object) +  # Base Object
      der_encode_enumerated(e:scope) +          # Scope
      der_encode_enumerated(e:0) +              # Deref Aliases
      der_encode_int(i:0) +                     # Size Limit
      der_encode_int(i:0) +                     # Time Limit
      der_encode_boolean(b:FALSE) +             # Types Only
      filterstr +                               # Filter
      der_encode_list(list:attrstr);            # Attributes
  }
  else
    req = encoded;

  # Store the search settings in case we need them
  _ldap_search_settings['search'] = req;          # The DER encoded SearchRquest
  _ldap_search_settings['base_object'] = object;  # The Base Object (needed for fetching full attr values)

  return ldap_request(code:LDAP_SEARCH_REQUEST, data:req, controls:controls);
}


##
# Parses a DER encoded LDAP Search Entry and returns the Object Name of the result
# 
# @remark
# This function ONLY returns the Object Name of the Result Entry!
# Use `ldap_parse_search_entry()`_ to get the decoded result's Attributes!
#
# @param  [data:data]   The DER Encoded LDAP Search Result Entry
#
# @return [string|NULL] The decoded Object Name,
#                       NULL if we failed to decode or if no Object Name is present
##
function ldap_parse_search_object_name(data)
{
  var list, object, ret, i, tlist, type, values, vlist, j;

  list = der_parse_list(list:data);
  if (isnull(list) || list[0] < 2)
    return ldap_set_error(LDAP_ERROR_DECODE);

  object = der_parse_octet_string(string:list[1]);
  if (isnull(object))
    return ldap_set_error(LDAP_ERROR_DECODE);

  return object;
}


##
# Parses a DER encoded LDAP Search Entry
#
# @remark
# Return List format:
# ```
# [
#   [ # Attribute A
#     Attribute Type,
#     Attribute Values [
#       Value 0,
#       Value 1,
#       ...
#     ]
#   ],
#   [ # Attribute B
#     ...
#   ],
#   ...
# ]
# ```
#
# @param  [data:data] The DER encoded LDAP Search Result Entry to parse
#
# @result [list|NULL] List representing the decoded Search Result data,
#                     NULL if we encountered errors or there was no data to parse
#
##
function ldap_parse_search_entry(data)
{
  var list, object, ret, i, tlist, type, values, vlist, j;

  if (get_kb_item('TEST/is_test'))
  {
    data = get_kb_item('TEST/test_parse');

    if (isnull(data))
      return NULL;
    else
      return data;
  }

  list = der_parse_list(list:data);
  if (isnull(list) || list[0] < 2)
    return ldap_set_error(LDAP_ERROR_DECODE);

  # Decode the Object Name
  object = der_parse_octet_string(string:list[1]);

  # Decode the Partial Attribute List
  list = der_parse_data(tag:BER_SEQUENCE_TAG, data:list[2]);
  if (isnull(list))
    return ldap_set_error(LDAP_ERROR_DECODE);

  # Decode the Partial Attributes
  list = der_parse_list(list:list);
  if (isnull(list))
    return ldap_set_error(LDAP_ERROR_DECODE);

  ret = NULL;
  for (i=1; i<=list[0]; i++)
  {
    tlist = der_parse_data(tag:BER_SEQUENCE_TAG, data:list[i]);
    if (isnull(tlist))
      return ldap_set_error(LDAP_ERROR_DECODE);

    tlist = der_parse_list(list:tlist);
    if (isnull(tlist) || tlist[0] != 2)
      return ldap_set_error(LDAP_ERROR_DECODE);

    type = der_parse_octet_string(string:tlist[1]);
    values = der_parse_data(tag:BER_STRING_SEQUENCE_TAG, data:tlist[2]);
    if (isnull(tlist))
      return ldap_set_error(LDAP_ERROR_DECODE);

    values = der_parse_list(list:values);
    if (isnull(values))
      return ldap_set_error(LDAP_ERROR_DECODE);

    vlist = NULL;
    for (j=1; j<=values[0]; j++)
      vlist[j-1] = der_parse_octet_string(string:values[j]);

    ret[i-1] = mklist(type, vlist);
  }
  return ret;
}


##
# Creates an LDAP Extended Request
#
# @param  [oid:string]    OID of the Extended Operation to perform
# @param  [value:string]  Operation to be perform
#
# @return [data]          A DER encoded LDAP Extended Request Message
##
function ldap_extended_request(oid, val)
{
  var req;

  # nb: the args are octet strings that that must use a
  #     context-specific rather than universal class.
  req = der_encode(tag:(0x04|0x80), data:oid);
  if (!isnull(val))
    req += der_encode(tag:(0x04|0x80), data:val);

  return ldap_request(code:LDAP_EXTENDED_REQUEST, data:req);
}


##
# Parses a DER encoded LDAP Extended Response
#
# @remark
# Return List format:
# ```
# [
#   LDAP Result Code,
#   LDAPDN,
#   Diagnostic Message,
#   OID of the Extended Response,
#   Value of the Extended Response
# ]
# ```
#
# @param [data:data]  The DER encoded LDAP Extended Response to parse
#
# @return [list|NULL] List representation of the decoded Response,
#                     NULL if we encountered errors
#
##
function ldap_parse_extended_response(data)
{
  var list, result, dn, msg, respName, resp, val;

  list = der_parse_list(list:data);
  if (isnull(list) || list[0] < 3)
    return ldap_set_error(LDAP_ERROR_DECODE);

  result = ldap_parse_enumerated(data:list[1]);
  if (isnull(result))
    return ldap_set_error(LDAP_ERROR_DECODE);

  if (substr_at_offset(str:list[2], blob:'\x04\x00', offset:0))
    dn = "";
  else
  {
    dn = der_parse_octet_string(string:list[2]);
    if (isnull(dn))
      return ldap_set_error(LDAP_ERROR_DECODE);
  }

  if (substr_at_offset(str:list[3], blob:'\x04\x00', offset:0))
    msg = "";
  else
  {
    msg = der_parse_octet_string(string:list[3]);
    if (isnull(msg))
      return ldap_set_error(LDAP_ERROR_DECODE);
  }

  if (list[0] > 3)
  {
    if (substr_at_offset(str:list[4], blob:'\x04\x00', offset:0))
      respName = "";
    else
    {
      val = der_decode(data:list[4]);

      # IBM Tivoli Directory Server uses tag 0x8a for respName
      if (!isnull(val) && (val[0] == 0x8a || val[0] == 0x4))
        respName = val[1];
      else
        return ldap_set_error(LDAP_ERROR_DECODE);
    }
  }
  else
    respName = "";

  if (list[0] > 4)
  {
    if (substr_at_offset(str:list[5], blob:'\x04\x00', offset:0))
      resp = "";
    else
    {
      val = der_decode(data:list[5]);

      # IBM Tivoli Directory Server uses tag 0x8b for resp
      if (!isnull(val) && (val[0] == 0x8b || val[0] == 0x4))
        resp = val[1];
      else
        return ldap_set_error(LDAP_ERROR_DECODE);
    }
  }
  else
    resp = "";

  return mklist(result, dn, msg, respName, resp);
}


##
# Sends a START TLS LDAP Extended Request to an open socket
#
# @remark
# Attempting to complete the SSL handshake will always result in a failure 
# if the function ``socket_negotiante_ssl()`` is not defined.
#
# @param  [encaps:string] Optional transport type
#
# @return [int|NULL]      The socket if the connection could be upgraded,
#                         NULL otherwise
##
function ldap_starttls(encaps)
{
  var res, xres;

  res = ldap_request_sendrecv(data:ldap_extended_request(oid:'1.3.6.1.4.1.1466.20037'));
  if (isnull(res) || res[0] != LDAP_EXTENDED_RESPONSE)
    return NULL;

  xres = ldap_parse_extended_response(data:res[1]);
  if (isnull(xres) || xres[0] != 0)
    return NULL;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl"))
      return NULL;

    return socket_negotiate_ssl(socket:_ldap_socket, transport:encaps);
  }

  return _ldap_socket;
}


##
# Extracts the domain information from the namingContext
#
# @remark
# Return Array format:
# ```
# {
#   obj:    [data]  # Domain Context,
#   domain: [data]  # Domain
# }
# ```
#
# @param  [namingcontext:string]  The namingContext to examine
#
# @return [array|NULL]            An array with the domain context as well as the domain to use in a bind request,
#                                 NULL otherwise
##
function ldap_extract_dc(namingcontext)
{
  var ret, i, obj, domain, item;

  if (isnull(namingcontext)) return NULL;

  obj = '';
  domain = '';
  namingcontext = split(namingcontext, sep:',');
  for (i=0; i<max_index(namingcontext); i++)
  {
    item = tolower(namingcontext[i]);
    if ('dc=' >< item && ('dc=domaindnszones' >!< item && 'dc=forestdnszones' >!< item))
    {
      obj += namingcontext[i];
      namingcontext[i] = namingcontext[i] - 'DC=';
      namingcontext[i] = namingcontext[i] - ',';
      domain += namingcontext[i];
      if (i < max_index(namingcontext) -1)
      {
        domain += '.';
      }
    }
  }

  return {
    'obj':obj,
    'domain':domain};
}

##
# Creates a DER encoded LDAP Control structure
#
# @remark
# This should be called by a specific LDAP Control creation function (ie: ``ldap_[CONTROL TYPE]_ctrl()``)
# 
# Example:
# `ldap_paged_results_ctrl()`_ calls this function with the specifics needed for a page_resuts type LDAP Control
#
# Return Array format:
# ```
# {
#   type:     [string], # OID of the LDAP Control Type
#   settings: [array],  # Array of settings for this Control (contents depend on Control type_)
#   encoded:  [data]    # The DER encoded LDAP Control sructure
# }
# ```
#
# @param  [type:string]       OID of the type of LDAP Control to create
# @param  [criticality:bool]  Criticality of the LDAP Control (Default is FALSE)
#                             If LDAP doesn't support the control and criticality is TRUE, 
#                             the requested operation will NOT be performed. If criticality is FALSE, 
#                             the control will be ignored, and requested operation will be performed
#
# @param  [scv:data]          Search Control Value: The DER encoded Sequence of Settings for the LDAP Control
# @param  [settings:array]    An array representation of the settings encoded in the ``scv`` argument.
#                             (used for easy storage and retrievl of Control settings)
#
# @return [array]             An array containing the LDAP Control Type, Settings, and the DER Encoded LDAP Control
#
##

function ldap_control(type, criticality, scv, settings)
{
  var l;

  if (empty_or_null(type) || typeof(type) !~ '(data|string)')
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Unable to create LDAP Control: Invalid Control ID');
    return NULL;
  }

  if (empty_or_null(scv) || typeof(scv) != 'data')
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Unable to create LDAP Control: Invalid Search Control Value');
    return NULL;
  }

  if (empty_or_null(criticality))
    criticality = 0x00; # FALSE
  else
    criticality = 0xFF; # TRUE

  l = der_encode_octet_string(string:type) +  # <OID>       control type
      der_encode_boolean(b:criticality) +     # <BOOL>      criticality
      der_encode_octet_string(string:scv);    # <OCTET STR> Search Control Value for the Control Type

  return {
    'type':     type,
    'settings': settings,
    'encoded':  der_encode_list(list:l)
  };
}

##
# Creates a Paged Results LDAP Control
#
# @param  [size:int]        Requested number of results to be returned per page
# @param  [next_page:data]  String representation of the cookie denoting the next page to get.
#                           If creating a new control, LEAVE THIS BLANK.
#                           If continuing a search provide the cookie here to get the next page of results
# @param  [critical:bool]   Criticality of control (Default is FALSE)
#
# @return [array]           Result of `ldap_control()`_ with the supplied settings for this Paged Results Control            
##

function ldap_paged_results_ctrl(size, critical, next_page)
{
  var l;

  if (isnull(size))
    size = 1000;
  else
  {
    if (typeof(size) != 'int')
      size = int(size);

    if (size < 0 || size > 1000) # Default Max Page Size is 1000
      size = 1000;
  }

  if (empty_or_null(next_page)) next_page = ''; # If no next_page is provided, then this is a new control

  l = der_encode_int(i:size) +                    # requested size of the page
      der_encode_octet_string(string:next_page);  # cookie (MUST be an empty string when creating a new control)

  l = der_encode_list(list:l); # Encode as a sequence

  return ldap_control(
    type:LDAP_CTRL_PAGED_RESULTS,
    criticality:critical,
    scv:l,
    settings:{
      'criticality': critical,
      'page_size': size,
      'next_page': next_page
    });
}

##
# Decodes and parses LDAP Control structures returned from the server and updates tracking where needed
#
# @remark
# This functions stores the decoded LDAP Control data in ``_ldap_search_settings``
# It does NOT return the data
#
# @param  [ctrls:data]  DER Encoded sequence of LDAP Controls returned by LDAP
#
# @return [NULL]
##

function ldap_parse_controls(ctrls)
{
  var controls_list, control, decoded_controls;
  var type, crit, value, decoded_value, i, key;

  if (isnull(ctrls))
    return NULL;

  controls_list = der_decode(data:ctrls);
  if (isnull(controls_list))
    return NULL;
  controls_list = der_parse_list(list:controls_list[1]);

  if (get_kb_item('TEST/is_test'))
  {
    controls_list = get_kb_item('TEST/test_controls');
    if (!isnull(controls_list))
        controls_list = deserialize(controls_list);
    else
      controls_list = [];
  }

  decoded_controls = {};
  for (i=1; i<max_index(controls_list); i++)
  {
    control = der_decode(data:controls_list[i]);
    # if we can't parse the control, or the control is malformed, skip it
    if (isnull(control) || control[0] < 2)
      continue;

    # Decode the list of Control fields
    control = der_parse_list(list:control[1]);

    # Control Type
    type = der_decode(data:control[1]);
    if (isnull(type)) continue;
    type = type[1];

    # If the control type returned isn't something we requested for, skip it
    if (isnull(_ldap_search_settings.controls[type]))
      continue;

    # Note that Controls returned from the Server DO NOT HAVE the Criticality Field

    # Real Search Control Value
    value = der_decode(data:control[2]);
    if (isnull(value)) continue;
    value = value[1];

    # Parsing search control value depends on control type
    switch (type)
    {
      case  LDAP_CTRL_PAGED_RESULTS:
            value = ldap_parse_paged_results_ctrl(ctrl:value);
            break;
      # Add more cases here for other control we want to support
    }

    # value will be NULL if we weren't able to parse it
    if (isnull(value))
      continue;

    # format and save the control we parsed!
    foreach key (keys(value))
      _ldap_search_settings.controls[type][key] = value[key];
  }

  return NULL;
}

##
# Parses the Search Control Value of a Paged Results LDAP Control
#
# @remark
# Return Array format:
# ```
# {
#   expected_total: [int],  # Expected total results
#   next_page:      [data]  # Data representing the Cookie for the next page
# }
# ```
#
# @param  [ctrl:data]   A DER Encoded Real Search Control Value of a Paged Results Control
#
# @return [array|NULL]  a human readable array structure containing the properties and values of
#                       the Paged Results Control Value or NULL if the value could not be parsed
##

function ldap_parse_paged_results_ctrl(ctrl)
{
  var expected, cookie, decoded_value;

  decoded_value = der_decode(data:ctrl);
  if (isnull(decoded_value))
    return NULL;
  decoded_value = der_parse_list(list:decoded_value[1]);

  if (isnull(decoded_value) || decoded_value[0] != 2)
    return NULL;

  # When retruned from the Server, size is the expected total number of results instead of page size. Not all LDAPs
  # will bother with this though, so it's not uncommon for it to just be 0
  expected = der_decode(data:decoded_value[1]);
  if (isnull(expected))
    expected = 0;
  else
    expected = integer(i:expected[1]);

  # The cookie returned will be the cookie we need to provide for requesting the Next Page of results
  # If the cookie returned is Empty, that signals that there are no more pages of results.
  cookie = der_decode(data:decoded_value[2]);
  if (isnull(cookie) || isnull(cookie[1]))
    cookie = '';
  else
    cookie = cookie[1];

  return {
    'expected_total': expected,
    'next_page':cookie};
}


##
# Given a LDAP Search Result Entry, parse it and pull the full range of attribute values
#
# @remark
# Pulling the full values for all attributes requires performing SEVERAL SEARCH REQUESTS
# Calling this function while there's already an in-progress Search Request WILL CAUSE ERRORS!
#
# Return List format: (Same as `ldap_parse_search_entry()`_)
# ```
# [
#   [ # Attribute A
#     Attribute Type,
#     Attribute Values [
#       Value 0,
#       Value 1,
#       ...
#     ]
#   ],
#   [ # Attribute B
#     ...
#   ],
#   ...
# ]
# ```
#
# @param  [object:object]     The LDAP Base Object needed to perform LDAP Searches
# @param  [search_entry:data] The DER Encoded Search Result Entry Data to be parsed
#
# @return [list|NULL]         Returns the parsed search entry with the full ranges of 
#                             values for any multi-valued attributes,
#                             NULL if no Base Object was supplied, or if the Search 
#                             Entry provided is not a valid DER encoded LDAP Search Result Entry
##

function ldap_fetch_full_attributes(object, search_entry)
{
  var i, search, search_cn, filter, ret, data;
  var attr, attr_name, attr_range, range_idx;
  var tracked_attrs = [];
  var attr_order = {};
  var next_attrs;
  var complete_attributes = [];
  var recv_attempts, max_recvs = 100; # Limit how many recvs we do when searching for additional attribute values
  # The search in question should only have 1 important result: an LDAP_SEARCH_RESULT_ENTRY containingg the next
  # ranges of attributes. But there could be any number of LDAP_SEARCH_RESULT_REFs returned as well before we finally
  # hit the LDAP_SEARCH_RESULT_DONE signaling the completion of the Search Request.
  # We MUST complete the search before attempting to start a new one. Otherwise we may end up receiving results from a
  # previous incomplete search.

  if (empty_or_null(object))
    return NULL;

  data = search_entry;

  repeat {

    next_attrs = [];

    if (empty_or_null(data) || typeof(data) != 'array' || data[0] != LDAP_SEARCH_RES_ENTRY)
      break;

    if (get_kb_item('TEST/is_test'))
    {
      data = get_kb_item('TEST/test_parse');
      if (isnull(data))
        return NULL;
      else
        return data;
    }

    data = ldap_parse_search_entry(data:data[1]);

    # Figure out if we have an attributes we need to get the full range for
    for (i=0; i<max_index(data); i++)
    {
      attr = data[i];

      if (isnull(attr[1]))
        continue;

      # We'll need to know the CN of the object in order to filter the search, so when we come across it,
      # we save the value of the cn attribute
      if (attr[0] == 'cn' && empty_or_null(search_cn))
        search_cn = attr[1][0];

      # check for a range in the name:
      range_idx = stridx(attr[0], ';range=');
      if (range_idx < 0) # No range -> we have all the values we need!
      {
        attr_order[attr[0]] = i;
        tracked_attrs[i] = attr;
        continue;
      }

      attr_name = substr(attr[0], 0, range_idx-1);

      if (empty_or_null(attr_order[attr_name]))
      {
        attr_order[attr_name] = i;
        tracked_attrs[i] = [attr_name, attr[1]];
      }
      else
      {
        tracked_attrs[attr_order[attr_name]][1] = make_list(tracked_attrs[attr_order[attr_name]][1], attr[1]);
      }

      # Attribute is ranged, so set up progress tracking so we can get the rest!
      attr_range = substr(attr[0], range_idx+7); # the range part of the name
      attr_range = split(attr_range, sep:'-', keep:FALSE); # the actual start and end range values [start, end]

      if (attr_range[1] == "*") # Range end of * means this was the last range!
        continue;

      # queue the next range for this attribute
      append_element(var:next_attrs, value:(attr_name + ';range=' + (int(attr_range[1]) + 1) + '-*'));
    }

    # No ranged attributes to get, so we're done!
    if (empty_or_null(next_attrs))
      break;

    if (empty_or_null(search_cn))
      break;

    filter = {'left':'cn', 'conditional':LDAP_FILTER_EQUAL, 'right':search_cn};

    search = ldap_search_request(object:object, filter:[filter], attributes:next_attrs, scope:0x02);

    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'Fetching additional Attribute Values for: '+search_cn);
    ldap_start_search(data:search);

    data = NULL;
    recv_attempts = max_recvs;
    # Even though we only need the one search entry, we have to recv until we get a SEARCH_RES_DONE to "complete" the request
    repeat {
      ret = ldap_recv_search_result();

      if (isnull(ret))
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'No Attribute data received...');

      if (ret[0] == LDAP_SEARCH_RES_ENTRY)
        data = ret;

      recv_attempts--;
    } until (recv_attempts <= 0 || isnull(ret) || ret[0] == LDAP_SEARCH_RES_DONE);

    # If we did have to give up on getting the next set of values for our attrs, go ahead and kill the whole process
    # and return what we have
    if (recv_attempts <= 0 && isnull(data))
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Exhausted attempts to receive next set of attribute values...');
      break;
    }

  } until (empty_or_null(next_attrs) || max_index(next_attrs) == 0);


  # Format our tracked attributes for returning

  for (i=0; i<max_index(tracked_attrs); i++)
  {
    if (!empty_or_null(tracked_attrs[i]))
      append_element(var:complete_attributes, value:tracked_attrs[i]);
  }

  return complete_attributes;
}
