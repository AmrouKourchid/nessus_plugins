#TRUSTED afdc879707187833057ca6950d7dce75ce024f93f96c7423c53b1b52d1087ecbcefac9c32418ccee2ce124d1b8880b800af1e4b21b89968d127398651fe7ca02064bc29dbd9de92988a6ba2be98bd86b8cc1752f18ee2b1f0ebc4549c6690e09c111ebd1bc18d40eab4d5f503c3b2e4712296ec73be5124774248548e39b588ee538d513bd79a9859bae7741a7c25ff9a73326c8aba81339be873e7105420481200b01079872c3cce8ec95770c5b9718cb7ebdb9a489c7b6cee177ca78bbfb61e5746b1f4b877b0d419f38dc10ba69212369ccbd4bcf80f853690a66ec098d8c2cc1ae2eef6d0710daeaa5e5acdf17e028a92ad95ab7ebc2a41567a9bbe962d2f8e0ec371bfa67cb22fa9534aef2ca44c7770727e88d447ba6e8db078838e026afc1caa25aa1b3b528fcbe840c97c51e4bcf12f1f4c37d766eb2c70e28af308a45dbd49509c988f4ea6bb730af0a63764c4ac5484052333b4b8fd6c7602101832d1e175fb9b2c160b51afb93269709de98c1ff3fd15b426306e91be27c106a2ecb47ea12e4f318a824659de17a6038cca9dba1b92f15b952d11ab0f8112c9e03b846865f65689bd7ca1a58c6e37d7e612cdeed43be1865dfb19cdaf020914544fd6314b6669efdd2dde8c95a64bf26cf04e1a4c90ef28ae1e1697c9de85a3c0002866cb5f9e39f1972cdeb7ba4cfa0a41d89487006ec473ec607dbd48a5b923b
#TRUST-RSA-SHA256 9d62c092a803e9fea2e439f7e1bdca298b4e17231e883216771ac92efd4b33e15560fa7fbfc196a217af9b1a825b66066f9d7531481f2bb87e00eaab259aa3542e5525611c49f1effc259126187cba35feab18ff1eac53618905572f7f6316c2e619b54c95cb36570683c8a956f01fe46d1703ee6e83ae3392cc231f9d9f87c4ede5ef928e72a9e47e77243550e61ed6d70b45645b81935ffee76bc087908623d00250e7afb41730ae16d7984558adae54c6637320a2597c50f25b3b0f28d756c092c6c3604e9b90ff33ae90ea5703b2d9d8a1f68f0cc03e7bb66dee0ad33367fd906bf34860817a24e29c0b8c4a819faecbea56e1709ab7fabcc1d0a38f2681ce79922f3ed71ce1573bcf65a1245c9929d2dcbed0faa651bebc3df9318621500fde78d058bc744e614c59e6c50a962a626b08c8dd60d34365bdd035886183340d45336176240fd3dfa08b1d5e7ff37cdc51d23aaa97b5b70ff9a6d6b3d92d0476a08576d8d15c293e0b43ca4fe9650bd40b600a3294dff0a0fa71b79cd350589134879d9bd7bc24bdb88d6a5eb9969f9e48899a00cf9c97bb60262a9991f8f4449f3e0fc33d39b9e7071c1a97fb7b9faab6bc4b7df3be6f55c177fba78e82e0404bdb45ac22f0d00dadf66f318d36c1d7f8204807da0a4146f5b77608d9d7f17bc98f028287b8cdeb7e77fab7db00e58a20006ebbabad4efa68dc79da235adf
#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(40448);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_name(english:"SNMP Supported Protocols Detection");
  script_summary(english:"Reports all supported SNMP versions.");

  script_set_attribute( attribute:'synopsis', value:
"This plugin reports all the protocol versions successfully negotiated
with the remote SNMP agent."  );
  script_set_attribute( attribute:'description', value:
"Extend the SNMP settings data already gathered by testing for\
SNMP versions other than the highest negotiated."  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/07/31' );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category( ACT_GATHER_INFO );
  script_family( english:'SNMP' );

  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

  script_require_keys( 'SNMP/community', 'SNMP/community_v1_v2c', 'SNMP/version' );
  exit(0);
}

include ('misc_func.inc');
include ('snmp_func.inc');


function do_initial_snmp_get (community, port)
{

  local_var soc, result;
  soc = open_sock_udp(port);

  if (! soc)
    audit(AUDIT_SOCK_FAIL, port, 'UDP');

  result = snmp_request(socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0", timeout:2);
  close(soc);

  return result;
}


# Real check for snmpv3 existence. Other plugins are marking
# the protocol version as failed if we cannot auth. This plugin
# is interested in marking the protocl as present regardless
# of auth status (and having no effect on anything else).
function check_for_snmpv3 (port)
{

  local_var local_copy_of_global_msg_id = 0;
  local_var msg_global_data = NULL;
  local_var authentication_data = NULL;
  local_var data_to_send = NULL;
  local_var snmp_header = NULL;
  local_var request = NULL;
  local_var sock = NULL;
  local_var rep = NULL;

  dbg::detailed_log(lvl:1, src:'check_for_snmpv3',
    msg:'Entering check_for_snmpv3',
    msg_details:{
      'port':{'lvl':1, value:port}
    });

  set_snmp_version(version:3);

  # save a copy of a global var that should not be global
  local_copy_of_global_msg_id = msg_id;
  msg_id = rand();

  sock = open_sock_udp(port);
  if (!sock)
  {
    # restore global var that should not be a global var
    msg_id = local_copy_of_global_msg_id;

    dbg::detailed_log(lvl:1, src:'check_for_snmpv3',
       msg:'Could not open UDP socket. Returning FALSE.',
       msg_details:{
         'port':{'lvl':1, value:port}
       });
    return FALSE;
  }

  msg_global_data = snmpv3_put_msg_global_data(
    msg_max_size       : MSG_MAX_SIZE,
    msg_flags          : raw_string(MSG_REPORTABLE_FLAG),
    msg_security_model : USM_SECURITY_MODEL);


  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'Creating msg_global_data',
    msg_details:{
      'MSG_MAX_SIZE':{'lvl':3, 'value':MSG_MAX_SIZE},
      'MSG_REPORTABLE_FLAG':{'lvl':3, 'value':MSG_REPORTABLE_FLAG},
      'USM_SECURITY_MODEL':{'lvl':3, 'value':USM_SECURITY_MODEL},
      'Data':{'lvl':3, 'value':msg_global_data}
    });

  authentication_data = snmp_assemble_authentication_data(
    auth_engine_data : snmp_put_engine_data(),
    msg_user_name    : '',
    msg_auth_param   : string (0),
    msg_priv_param   : NULL);

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'Creating authentication_data',
    msg_details:{
      'Data':{'lvl':3, 'value':msg_global_data}
    });

  snmp_header = raw_string(
    ber_put_int(i: 3),
    msg_global_data,
    authentication_data);

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'Creating snmp_header',
    msg_details:{
      'Data':{'lvl':3, 'value':snmp_header}
    });

  request = snmp_assemble_request_data(
    seq : make_list(),
    op  : OP_GET_REQUEST);

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'Creating request',
    msg_details:{
      'Data':{'lvl':3, 'value':request}
    });

  data_to_send = ber_put_sequence(seq:make_list(snmp_header, request));

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'SEND',
    msg_details:{
      'Data':{'lvl':3, 'value':data_to_send}
    });

  send(
    socket : sock,
    data   : data_to_send);

  rep = snmp_reply(
    socket  : sock,
    timeout : 100,
    ret_err : TRUE);

  dbg::detailed_log(lvl:2, src:'check_for_snmpv3',
    msg:'RECV',
    msg_details:{
      'Data':{'lvl':3, 'value':rep}
    });

  close(sock);

  # restore global snmp version data that should not be global
  reset_snmp_version();

  # restore global var that should not be a global var
  msg_id = local_copy_of_global_msg_id;

  if (empty_or_null(rep))
  {
    dbg::detailed_log(lvl:1, src:'check_for_snmpv3',
       msg:'Did not receive reply. Returning FALSE',
       msg_details:{
         'port':{'lvl':1, value:port}
       });

    return FALSE;
  }
  else
  {
    dbg::detailed_log(lvl:1, src:'check_for_snmpv3',
       msg:'Returning TRUE',
       msg_details:{
         'port':{'lvl':1, value:port}
       });

    return TRUE;
  }
}


supported = make_list(0, 0, 0, 0 );

v3_supported = get_kb_item('SNMP/v3/Supported');
community_v1_v2c = get_kb_item('SNMP/community_v1_v2c');
version = get_kb_item('SNMP/version');

port = get_kb_item('SNMP/port');
if (!port)
   port = 161;

if (empty_or_null(v3_supported))
  v3_supported = check_for_snmpv3(port:port);

# We already know that this version works.
# Where 'this version' is whatever the KB has
# in SNMP/version. A value that it set elsewhere.
if  (!isnull(version) && version <= 3)
  supported[version] = 1;

# We have detected presense of SNMPv3, let's try for SNMPv1/2c
if (v3_supported)
{
  supported[3] = 1;
  set_snmp_version(version:1); # SNMPv2c
  res = do_initial_snmp_get(community:community_v1_v2c, port:port);

  if  (!isnull(res))
    supported[SNMP_VERSION] = 1;

  reset_snmp_version();

  set_snmp_version(version:0); # SNMPv1
  res = do_initial_snmp_get(community:community_v1_v2c, port:port);

  if  (!isnull(res))
    supported[SNMP_VERSION] = 1;

  reset_snmp_version();
}

# Otherwise, we've found a community string that works
# We already know if v3 works from v3_supported,
# But, there may be a lower supported version
# If version is 1, try version 0.  If version is 0, we have already tried 1 and it failed.
else if (version == 1)
{
  set_snmp_version(version:0); # SNMPv1
  res = do_initial_snmp_get(community:community_v1_v2c, port:port);

  if  (!isnull(res))
    supported[SNMP_VERSION] = 1;

  reset_snmp_version();
}

version_result = NULL;
report = '';

for (i=0; i<max_index(supported); i++ )
{
  if  (supported[i])
  {
    version_result = version_result | supported[i];
    version = 'SNMPv';
    if (i == 0)
      version += '1';
    else if(i == 1)
      version += '2c';
    else if(i == 3)
      version += '3';
    report += 'This host supports SNMP version ' +  version + '.\n';
  }
}

if (!version_result)
  audit(AUDIT_NOT_LISTEN, 'SNMP', port, 'UDP');

security_note(port:port, proto:'udp', extra:report);
