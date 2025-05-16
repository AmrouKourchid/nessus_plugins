#TRUSTED 32fbd51227672ca96d5dfd6039730331bf07186180b24b91de4f7cd13584a3da5d1785f4b16aa80eccbd05debed3c88a8e38040f3375a2f9f7212ced4a6412ef4c2f1066a1ce16a68ce9acb96483974ec185e4288e0fe88f9f83f5d04108d5792357515779ee90692c2c5b08da3ac20a6d404c2a077a9aeaf2360700886704beb12dc7d645d50d65a87fb3d2e40213c32c05e413ca9bc1a3b391f3f612612cdb4094f5b3ef8595aefa01df184629bda6e2dcfc52ea774601b67a530e6351cd7c241ef845cd250fd757c9eb1ee27b4ef1eef1391840fa745ea370ddfca465949a0923377908424eb930e4fe95eaf82b8992dee06695d38e7fbbde49a9e8cd76665daf19d31d5a85492149795b5c0f70d153ee864cb5661e8e0416045cc2d479c3c18cbd0d9c5ef1a0729845cc063e06715e4b1ac6a27b33482baa990938de5b64a30d3ae13521ff48f1d3ebce6f5b1300063077a4e53a9a7380e707f42bb98be2446a48bb1e1fab719f56de3cac5ce54f8a8588a1b9ba4f17e552510eafc114b3e0f87733268ca08507936be752f4b9462577e45e713f93da1b7c6c687d8911a1d757ee7b693fb92b5be804843646d9256dfdc89c1c254349070ca09fb66af9c108f4098034d44053fbd59d113f5502099c1626d1b5dffe44af29913b705a8a388e1fea2d9c7dc7f25b9e8c3784921a6c3ea3b3aa090991eeb5fcb4204834ff3b
#TRUST-RSA-SHA256 a205cae34ce7ceb81eef2809183ed7261c03cdca2e94aca7f3373f0591f54dc5f337bceca7fd00c776d4d963eba9088ffe0b88f818a0f208050eeab638590e7f3ed411e33b738583f8988d76ccde0cd775222219f2505667fba5b1b0284870789006b416aa7586822bccb9dd42ef57ab4477c01f2081a63b4de3173e291355b1138d04dcea30baad464e68585e764a8066412e36ba5d88eaeac596ba4d463727c228f614b3d37d1fd6bde393c1e0ffd064ac6856b2c439c00227668b583bec573fcf25fed56734cb82ec2dd8bc30f97aa43938a901eca9ff7f72ce5ba468da13dff78f9f94fc45bacd882177a31ccebe4af07f6fe76d385bb5922812d240c0c31ff383a66904d4026116effdf556043717e3f4a926066ccdae31ae24cd52a4a092b1a35147a1d51c273ea8f3406fe033c41e27676219f4a59176a8b865d1a6926b0d286032880a82619fd0c74fb49c58911dae539974ce6af9f2c8bc064334e9afab41ae5384a8da57768d43fe060e387e08c98e2167ab1e5cf52484e6a9eee66bcbe3ec396f4a653acb03dbbd22bf13df4411cf392992e14a53ba82c2d47d66535f414197c5f3e08118c0fe3f61601404940368bff83bdf01e9fb370e8144a1a17e7a64b52561f6ae7d31839d16b9dd06ec2f194475fe4d0789541ccfa9ceec2b83670f9942fd72e028dadf61e591d466b30046def2637e582dbce09db45ec3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22482);
  script_version("1.18");

  script_xref(name:"IAVB", value:"0001-B-0525");

  script_name(english:"Do not scan Novell NetWare");
  script_summary(english:"Marks Novell NetWare systems as dead");

 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running Novell NetWare and will not be
scanned." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Novell NetWare.  This operating
system has a history of crashing or otherwise being adversely affected
by scans.  As a result, the scan has been disabled against this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08f07636" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87d03f4c" );
 script_set_attribute(attribute:"solution", value:
"If you want to scan the remote host enable the option 'Scan Novell
NetWare hosts' in the Nessus client and re-scan it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/02");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_SETTINGS);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2006-2023 Tenable Network Security, Inc.");
  script_dependencies("dont_scan_settings.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("snmp_func.inc");

if (  get_kb_item("Scan/Do_Scan_Novell") ) exit(0);



# Check SNMP.
if (get_kb_item("SNMP/community"))
{
  port = get_kb_item("SNMP/port"); 
  community = get_kb_item("SNMP/community");
  if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
  soc = open_sock_udp(port);
  if (soc) 
  {
    desc = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.23.1.6");
    close(soc);
    if (desc && "Novell NetWare" >< desc)
    {
      set_kb_item(name:"Host/Netware", value:TRUE);
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0, extra:'\nSNMP reports the host as running Novell NetWare.\n');
      exit(0);
    }
  }
}



# Check web servers.
foreach port (make_list(81, 8009))
{
  if (get_port_state(port))
  {
    r = http_send_recv3(port:port, item: "/", version: 10, method:"GET");
    if (isnull(r)) continue;
    banner = strcat(r[0], r[1], '\r\n', r[2]);
    # nb: don't save banners from an HTTP 1.0 request as they may 
    #     cause problems for scans of name-based virtual hosts.
    # set_kb_item(name: 'www/banner/'+port, value: banner);
    if ("Server: NetWare HTTP Stack" >< r[1])
    {
      set_kb_item(name:"Host/Netware", value:TRUE);
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0, extra:'\nThe web server on port ' + port + ' uses a Server response header that suggests\nit runs under NetWare.\n');
      exit(0);
    }
  }
}

foreach port (make_list(80))
{
  if (get_port_state(port))
  {
    r = http_send_recv3(method:"GET", port:port, item:"/", version: 10);
    if (isnull(r)) continue;
    banner = strcat(r[0], r[1], '\r\n', r[2]);
    # nb: don't save banners from an HTTP 1.0 request as they may 
    #     cause problems for scans of name-based virtual hosts.
    # set_kb_item(name: 'www/banner/'+port, value: banner);
    if (
      "(NETWARE)" >< banner &&
      egrep(pattern:"^Server: Apache(/[^ ]*)? \(NETWARE\)", string:r[1])
    )
    {
      set_kb_item(name:"Host/Netware", value:TRUE);
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0, extra:'\nThe web server on port ' + port + ' uses a Server response header that suggests\nit runs under NetWare.\n');
      exit(0);
    }
  }
}
