#TRUSTED 0630cd5b4c95ab0fdd309ae9ade37cbd03736e510cb365352fbadba55ffc6d5fd3ba826941405a1c33fea135b7a733f37b514268da873093953896bcbc6a543748915fd034f5b76811ff99be0bd4c137808291e5bd9143685697a3b512769a8c8bd37c5c98672da715ae1af2969dddadb070cebe2144fd44aabbf06c42e03c6ba4951054e4c1980270437369eef665271feef5228eb922c07d97ed33d82cea04141c47257dab80e9a8811f29b00697ce22f3302194002602a4f3b0296f0a2edd1019405448c2f10770283460f182a562301d8fb81b8cb9ec7207f93ef2c86dc18c4814717731804300f71ba265446b55d1c942fa88bb67774e9dcf294a28d8f54f943429bec23bbde9bf230c1148bdb824d2ce5fd68920b12a6c01fb43c5643942554b8940c389903f910a8d26e879f4125ef002ad3c2b25da72317361dc3fc8b5c643304415fd735b904803191c51aa69f01f7c349ff1e1b2425e3c2d61e6a1bcf91c237c834cac0121966341e2d60d3398ad4a3a11b771e2057b9c07dd0272c1b3fc7b495b704cabf8d064b90cf390deff1c20e8078ef6b3fd6fa252390645c01e9187b36a51f39627e254749b1f54264d7f9d2e2b63ea371022c6e533a1672dea011836a3c8e4d8046b316ecfcdda6c725cc4ac5c1d5d48cdf0cb8a81eaec2a05d294f4cdcf54ad3408f85adbcf77294e08d1dc17c3c9239468f11bbd4743
#TRUST-RSA-SHA256 0f0cdad5b545705de8d66dc7eddbd294eac85ac63bb143029735b8f4b5464d004ccaa77d1f3ddbfd546622c5839556b297d172f69733c0917d36e0fd7c39e2791f04457fb732e37267cd52cccdd68a378e881c1bc693426d315cb6e6c672e08398eb8109b92f62d51fdcc7ecb8861dfaac4a3c73f2f4bd7688c61563ca87438ec1ec6c2a75487618128d105def034ea5a248dae585ab243b9c7d638c44e8162da24536fc6a8ca61337a4abac03b73a7d8ebce6c1a8c97266f8fc2aa783272962412400ca05ac594596a038a164f114fd36063645b20069550324b49a52abd5c0552298800bda90f462f0b8d6c893cc09b68b821f1d5145ca74e07eb60bd36c1e4582286f115db6906d529d8f5a328996bb1e69fef1cb25daf4883e2cf41085789e1548bdd9e5f4252b02c34431428fc7cd1cf8bba237111d3f4655000cb69bd6a114e65015ac57996eaf26324e1ed20c60145d111571bee55b1058ef3badf7aa22d9649ed2e352700f7e2cc54d2b2a2202a243a758b9753c57d7f99fb2e33b5c441ee44c5363f068e975831a071f91ec825892aa3b540f0cbbdd91442a1b5c86f1c003c4c232e63027e3433179a44c30506c8794c532fbacd886c8ee4f8d5b13c86b0f776190e30c264edb68d9bb9e27dbe245b15bd452811c54d0963a1828123966bab8e55983281a3b2b81e2134c1f3f22ec67f40ff04898627cf04303dd0e
#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69181);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/03");

  script_name(english:"OS Identification : NETCONF Over SSH");

  script_set_attribute(attribute:"synopsis", value:
"It may be possible to fingerprint the remote host's operating system
by querying its management protocol."
  );
  script_set_attribute(attribute:"description", value:
"The remote host is using the NETCONF protocol over SSH.  The NETCONF
protocol is used to manage network devices.

It may be possible to determine the operating system name and version
by using the SSH credentials provided in the scan policy."
  );
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc6241");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_settings.nasl", "ssh_check_compression.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('ssh_lib.inc');
include('os_install.inc');

var CISCO = 0;
var CISCO_IOS_XR = 0;
enable_ssh_wrappers();

##
# Sends a netconf payload over an already-established SSH channel,
# wrapping it in a SSH_MSG_CHANNEL_DATA header
#
# @anonparam data netconf request
# @return whatever send_ssh_packet() returns (don't know if that functions returns anything)
##
function _netconf_send()
{
  local_var data, payload;
  data = _FCT_ANON_ARGS[0];
  payload =
    raw_int32(i:remote_channel) + # global from ssh_func.inc
    putstring(buffer:data);

  return send_ssh_packet(payload:payload, code:raw_int8(i:94));
}

##
# Receives a netconf payload, removing the SSH-related header
#
# @return netconf payload
##
function _netconf_recv()
{
  local_var res, payload;
  res = recv_ssh_packet();
  payload = substr(res, 9); # code, channel, and length ignored
  return payload;
}

port = sshlib::kb_ssh_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

var CISCO = 0;
var CISCO_IOS_XR = 0;

var ssh_banner = get_kb_item("SSH/banner/" + port);
if(isnull(ssh_banner))
{
  var session;

  sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:TRUE);

  if(!isnull(session))
  {
    ssh_banner = session.remote_version;
    session.close_connection();
  }
}

if ( "-Cisco-" >< ssh_banner )
{
  CISCO++;
  if ("-Cisco-2." >< ssh_banner)
    CISCO_IOS_XR++;
}

# nb: needed for Cisco Wireless LAN Controllers and Sonicwall.
if (!CISCO)
{
  set_kb_item(name:"/tmp/ssh/try_none", value:TRUE);
  var timeout = get_ssh_read_timeout();
  if (timeout <= 5) set_ssh_read_timeout(10);
}

if(CISCO_IOS_XR || "force10networks.com" >< ssh_banner)
  sleep(1);

var success = ssh_open_connection();

# nb: Sonicwall needs a delay between the initial banner grab
#     and  calling 'ssh_open_connection()'.
if (
  !success &&
  "please try again" >< get_ssh_error()
)
{
  for (var i=0; i<5 && !success; i++)
  {
    # We need to unset login failure if we are going to try again
    if(get_kb_item("SSH/login/failed")) rm_kb_item(name:"SSH/login/failed");
    sleep(i*2);
    success = ssh_open_connection();
  }
}

if (!success)
{
  var error = get_ssh_error();
  var msg;

  if (strlen(error) == 0)
    msg = 'SSH authentication failed on port ' + port + ': unknown error.';
  else
    msg = 'SSH authentication failed on port ' + port + ': ' + error;
  exit(1, msg);
}

var ssh_protocol = get_kb_item("SSH/protocol");
if (!isnull(ssh_protocol) && ssh_protocol == 1) exit(0, "The SSH server listening on port "+port+" only supports version 1 of the SSH protocol.");


var ret = ssh_open_channel();
if (ret != 0)
{
  ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, 'SSH', port);
}

# SSH_MSG_CHANNEL_REQUEST
var channel_req =
  raw_int32(i:remote_channel) +
  putstring(buffer:'subsystem') +
  raw_int8(i:1) +  # want reply
  putstring(buffer:'netconf');
send_ssh_packet(payload:channel_req, code:raw_int8(i:98));

# skip over any packets that we don't care about
var res = recv_ssh_packet();
while((ord(res[0]) == 93) || (ord(res[0]) == 95) || (ord(res[0])  == 98))
{
  if (ord(res[0]) == 95)
  {
    var payload = getstring(buffer:res, pos:9);
    _ssh_cmd_error += payload;
    var val = update_window_size(size:strlen(payload));
    if (val != 0)
      break;
  }
  res = recv_ssh_packet();
}

if (ord(res[0]) == SSH2_MSG_CHANNEL_FAILURE)
{
  ssh_close_connection();
  audit(AUDIT_NOT_LISTEN, 'netconf', port);
}
else if (ord(res[0]) != SSH2_MSG_CHANNEL_SUCCESS) # expected response
{
  if (!bugged_sshd) ssh_close_channel();
  ssh_close_connection();
  audit(AUDIT_RESP_BAD, port, 'netconf subsystem request');
}

res = recv_ssh_packet();
while((ord(res[0]) == 93) || (ord(res[0]) == 95) || (ord(res[0])  == 98))
{
  if (ord(res[0]) == 95)
  {
    payload = getstring(buffer:res, pos:9);
    _ssh_cmd_error += payload;
    val = update_window_size(size:strlen(payload));
    if (val != 0)
      break;
  }
  res = recv_ssh_packet();
}

var hello = substr(res, 9);
if (hello !~ '^<hello' || 'netconf' >!< hello)
{
  ssh_close_connection();
  audit(AUDIT_NOT_LISTEN, 'netconf', port);
}

set_kb_item(name:'Host/netconf/' + port + '/hello', value:hello);

var report;

# Juniper IVE SA & IVE IC
if (hello =~ '<capability>http://xml.juniper.net/dmi/ive-(sa|ic)')
{
  _netconf_send('<rpc message-id="1"><get-system-information /></rpc>');
  var sys_info = _netconf_recv();
  _netconf_send('<rpc message-id="2"><close-session/></rpc>'); # cleanup, response ignored
  ssh_close_connection();

  if (sys_info !~ '<os-name>ive-(sa|ic)') # sanity check
    audit(AUDIT_RESP_BAD, port, 'get-system-information');

  var os = 'Pulse Connect Secure (formerly Juniper IVE OS)';

  var match = eregmatch(string:sys_info, pattern:'<os-version>([^<]+)</os-version>');
  if (isnull(match))
    audit(AUDIT_RESP_BAD, port, 'get-system-information');
  else
    var version = match[1];

  match = eregmatch(string:sys_info, pattern:'<hardware-model>([^<]+)</hardware-model>');
  if (!isnull(match))
  {
    var model = match[1];
    set_kb_item(name:'Host/netconf/' + port + '/model', value:model);
  }

  var type       = 'remote';
  var method     = 'netconf';
  var confidence = 100;

  var vendor  = 'Juniper';
  var product = 'IVE OS';
  var os_name = strcat(vendor, ' ', product);

  var cpe = 'cpe:/o:juniper:ive_os';

  register_os(
    type        : type,
    port        : port,
    method      : method,
    confidence  : confidence,

    vendor      : vendor,
    product     : product,

    version     : version,
    os_name     : os_name,

    cpe         : cpe
  );

  set_kb_item(name:'Host/netconf/' + port + '/os', value:'Juniper IVE OS');
  set_kb_item(name:'Host/Juniper/IVE OS/Version', value:version);
  set_kb_item(name:'Host/OS/netconf', value:'Juniper IVE OS ' + version);
  set_kb_item(name:'Host/OS/netconf/Confidence', value:100);
  set_kb_item(name:'Host/OS/netconf/Type', value:'embedded');

  report =
    '\n  Operating system : ' + os +
    '\n  Version          : ' + version;
  if (!isnull(model))
    report += '\n  Model            : ' + model;
  report += '\n';
}
else
{
  ssh_close_connection();

  report =
    '\n' + 'Nessus was able to access the NETCONF SSH subsystem but was' +
    '\n' + 'unable to identify the device based on its hello message :\n\n' +
    hello;
}

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
