#TRUSTED 26e156db728e511ba64e0a62a32d17ffb24209115fc1d0e354cb3a500edc5d319196df199892011affd28d3484711a46cbc0552be89bfaf362aac4508661a101cb3a75f307e20cf393ba29114c0352af27e37293a6a25b280bb7a943b4041e32768d8dcbc520cf514e1f899eba5e9f4cc50b042f4ac43545388447abe1ac9694510b0182222cb519a36b480435e67ba3785a8cc6fd01c186f55109053560b3550b2329600d90815f3fc70ee56536d994a9eed917b02522179d7001a67d9661601aedd870ffeb845493172ab4da387ee3e766fa99474f9b0c4397b8ca06e6a01eab84670f49b726323e75b3c9f17065ddae96e6004590d55e54000e447250341af85042c088048a58131bf32b85170b3c26871b4385e83a673cfad090f7d443192691c897eaed5b42af3ec761350ffac6cc6070ec6ea43b381085c568a41a6dda5160be347e5fa2f1c686b85e5722156e6d75629960bc851587270093ddcfd09eb5256e248d57933f012f285982abeb826cbb1ab3689e113b9ab113ac8a6dc0a78c04b7d64cd3364df561417f6feef53e28bb228151d675fa5b10a14a12496114f4386b492ea419f015399d17b95d664f4fbeaabca4c95bea7b9a27f38ed701dde54a01ef5d2ab27364281ca3ededfb1848fb2d36691341e87e150744e6b701dfdd94b5eb0c46af403651e5bfaef0874e1f377950e23e83e72109fa1b695f7057
#TRUST-RSA-SHA256 a64c5f96581030ee9a1cf4cc66a64890c5c0e5973269ba36c631b3c297c8c870af03e0e61c0a987ba6c2dd07927d772f6be45371e4111b92d95b19a523eedec882bf28353dba5d14c250f0face0fca503efdbce22a0b502e15bb04638edc0e49fc075f222b6e082bb47b08fd19423bde60b78364a92d03b795f278b7e8fc7d813688d2126849405ddf249abd3120b73339b123863d9971ac0173052262debbd6594b3d1d3dcc445a30b851521c9e93e2eae951100f4831a6d4629b771b0bbe69cbe49747dbf4f7d482f5e901cf3f9ae9ed2dc4c7e0edeb7a69752c2cc3f490f8a1a5a228cbed0e088f3eb40848a9314123d665058ee22f0cbe0983273ff1e30ffb1e47447bb38acd45fc92866c37236def90c780f44accdb879abdcee41de1771454d96a8fcbee6d7befb2af0c677b3d329b74994f87331c9230e73a9767a1766f4952233a26d0b562e0d9fcc795f4fb96f1f204be9f80da4e9081b2073290480e0e78822e9cd8369c48fb3762c00da10e48dcfa315eb4dc1e80b32a1783c76da8664f5515599c90f806b7b3d7be120e2010a942437a9bd0c5a6fde066bcfcd00c0d0d36f164350196cfe56c51dbac392d1f9979c652e74c29cd459cd2a82f3e3400bad6250e6fa11df15c49497738450ea83ac0157b3dd9a073007680fc5b997b7d8f7a847d5cabb91e17300659afa6d30db38e2a49c8d5d15ba302de6e89c1
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42149);
  script_version("1.16");

  script_name(english:"FTP Service AUTH TLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(attribute:"synopsis", value:
"The remote directory service supports encrypting traffic.");
  script_set_attribute(attribute:"description",  value:
"The remote FTP service supports the use of the 'AUTH TLS' command to
switch from a cleartext to an encrypted communications channel.");
  script_set_attribute(attribute:"see_also", value:
"https://en.wikipedia.org/wiki/STARTTLS");
  script_set_attribute(attribute:"see_also", value:
"https://tools.ietf.org/html/rfc4217");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english: "This script is Copyright (C) 2009-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/disable_test_ssl_based_services");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("ftp_func.inc");
include("x509_func.inc");

if (get_kb_item("global_settings/disable_test_ssl_based_services"))
  exit(1, "Not testing SSL based services per user config.");

var port = get_ftp_port(default:21);

var encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The FTP server on port "+port+" always encrypts traffic.");


var soc = open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) exit(1, "Can't open socket on port "+port+".");
dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME, lvl:2, msg:"Getting the FTP banner.");

var s = ftp_recv_line(socket:soc);
if (!strlen(s))
{
  close(soc);
  exit(1, "Failed to receive a banner from the FTP server on port "+port+".");
}


var c = "AUTH TLS";
var s = ftp_send_cmd(socket:soc, cmd:c);
if (strlen(s) < 4) 
{
  ftp_close(socket:soc);

  if (strlen(s)) var errmsg = ('The FTP server on port '+port+' sent an invalid response (' + s + ').');
  else errmsg = ('Failed to receive a response from the FTP server on port ' + port + '.');
  exit(1, errmsg);
}
var resp = substr(s, 0, 2);
replace_kb_item(name:"ftp/"+port+"/starttls_tested", value:TRUE);

if (resp && resp == "234")
{
  # nb: call get_server_cert() regardless of report_verbosity so
  #     the cert will be saved in the KB.
  var cert = get_server_cert(
    port     : port, 
    socket   : soc, 
    encoding : "der", 
    encaps   : ENCAPS_TLSv1
  );
  if (report_verbosity > 0)
  {
    var info = "";

    var cert = parse_der_cert(cert:cert);
    if (!isnull(cert)) info = dump_certificate(cert:cert);

    if (info)
    {
      var report = (
        '\n' +
        'Here is the FTP server\'s SSL certificate that Nessus was able to\n' +
        'collect after sending a \'AUTH TLS\' command :\n' +
        '\n' +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n' +
        info +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n'
      );
    }
    else
    {
      var report = (
        '\n' +
        'The remote FTP service responded to the \'AUTH TLS\' command with a\n' +
        '\'' + resp + '\' response code, suggesting that it supports that command.  However,\n' +
        'Nessus failed to negotiate a TLS connection or get the associated SSL\n' +
        'certificate, perhaps because of a network connectivity problem or the\n' +
        'service requires a peer certificate as part of the negotiation.'
      );
    }
    if (COMMAND_LINE) display(report);
    else security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
  }
  else security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  replace_kb_item(name:"ftp/"+port+"/starttls", value:TRUE);

  # nb: we haven't actually completed the SSL handshake so just bail.
  close(soc);
  exit(0);
}
ftp_close(socket:soc);
