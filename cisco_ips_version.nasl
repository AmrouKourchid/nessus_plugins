#TRUSTED 3fb0fa0cd7242152792441c12dfaa995bc23a62aea607c222786397f59b0a6e89f686069b23e8413959bc4228537eae7b0fed41de15202d8a55231228d0eee86bdfa9c7c63809fc67de087b98b823f1da5253b07e31f6e4efe9f89047b2a6ac23e980eb8398ba93f8a2a8453d32019bfc1aea8bb32bfd5a2ee687a784536af2e27781f23b7c2dd8a699e459d0448b4b9cb6013e7b2439379a0272578d9b31421d07200b57bd38f3e5f63fad98b24ab54bd82f451018b2fe9676fd6e26f237df737e2abe45cb7598121b64f0a64cae8e7445b0942715a2effdc1e539c967312068c900ff64a67f32f73814791c3409120b27bc0f33a0f3e8099984d0577a0e4588824c5e6618b22090751b8efcec1c8af8abcb8a3a45344549d1e9ccd0f67bac57a933e725281f475779774d2c6440717d0ecdd60c300361267eccc78f3a9dda8dea88bd9554b63eb54a23a97a45f4f7d1e37ea975068cda6eb0d83b138fda903b431ec6443555c88339372bc8e3967bda08bc14d008bf4f362a948ede6afbded71c3e0372e2d576d07183aef01a4bd04c95ef7471daf363cab83e999e888d3e3a607d703396103973b68cbd883eeb75f429956d082e9ec4c561ae8fbc1f5ee097c7549006facbbcf5044d36cce83ecb143a5afde43b750bee16a324d3db33c5fa3a2d9ac582a62d14a41b80bac4156f4170e813e9c3ec31da0d4d81191677f65
#TRUST-RSA-SHA256 3ce2f30a7246bd926adb2529f38b586072a100bb69f8c1c379f651669845edbbb4c2b800c1a78ba8f6ae08bd741733f7c5546e02c83a12af17f07d6b6d3855da989bab29fc52e757a41677bd96d9fd93ce7f6905b2e593da0d2cd36f7145410df6980022c66961bf3aa22c8724d1c29575d06ae09da9f0e9bcc0c26d0339c9edeb50b49725809879cd4425aa7a05f32f19a68399e7e0976aec61c9631ac98e47c4d3fb810076841835c5b8df530c9443f83ff8f2cb7e08925ede19c799493e028044b888c77b5b60bb0a13a5aac8c8f2c8fa028f4b1a9f5bb35f8c58f657148c7646337dd78fad3eabeb9ace2d2aa51740c4fed5c5bca19a85a4349a31bec7a5895a00cb9f9af6090bc5225255b2ad0e4c0ae4db08296671170739879305f62914b29c6e44cb604959d00f1593496de3efa181382d2928a8819b8ed3061c6e3678dae1d4119e8672f83eec5025a8142ee1495caa3adb3e3016b5e96934af8d6cfd8f30b40b3c1aaee1e6fd58edae5631af86957b8d062e4d65c2ba48f360b8e967ceed7f13a0350cb4cdddd913b9d7c78aa53a6b2ff55648a52bf07526dee27b2dc074bc5798c160f5053a6ef132bce2752bbf8ad56790ad68e2d4a7ff7203552cb7c4903c23f3ae0c7e68b585dd4a06687c21f47f643a0305b573c14aa563c6ce84fc00ec2f1ce012efd51432db2b4cb35a1d02ef5f93b7c9ad7924e6020f56
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(69102);
 script_version("1.7");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

 script_name(english:"Cisco IPS Version");
 script_summary(english:"Obtains the version of the remote Cisco IPS device");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the Cisco IPS version number, model number,
and/or serial number of the remote Cisco IPS device.");
 script_set_attribute(attribute:"description", value:
"The remote host is a Cisco Intrusion Prevention System (IPS). 

It is possible to read the Cisco IPS version number, model number,
and/or serial number by connecting to the device via SSH or SNMP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:intrusion_prevention_system");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"CISCO");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("snmp_func.inc");
include("misc_func.inc");

##
# Saves the provided IPS version number in the KB, generates plugin output,
# and exits.  If a model or serial number is provided it is also saved in
# the KB and reported, but a model and serial number is not required.
#
# @anonparam ver IPS version number
# @anonparam model IPS model number
# @anonparam serial IPS serial number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, model, serial, source)
{
  local_var report, display_ver;

  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/IPS/Model", value:model);

  if (!isnull(serial))
    set_kb_item(name:"Host/Cisco/IPS/Serial", value:serial);

  set_kb_item(name:"Host/Cisco/IPS/Version", value:ver);

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + ver;
    if (!isnull(model))
      report += '\n  Model   : ' + model;
    if (!isnull(serial))
      report += '\n  Serial  : ' + serial;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH
ips_ssh = get_kb_item("Host/Cisco/show_ver");
if (ips_ssh)
{
  version = pregmatch(string:ips_ssh, pattern:"Cisco\s+Intrusion\s+Prevention\s+System,\s+Version\s+([^\s\r\n]+)");
  model = pregmatch(string:ips_ssh, pattern:"Platform\s*:\s+([^\s\r\n]+)");
  serial = pregmatch(string:ips_ssh, pattern:"Serial\s+Number\s*:\s+([^\s\r\n]+)");

  if ((!isnull(version)) && (!isnull(model))&&(!isnull(serial)))
  {
    report_and_exit(ver:version[1], model:model[1], serial:serial[1], source:'SSH');
    # never reached
  }
}

# 2. SNMP
ips_snmp = get_kb_item("SNMP/sysDesc");
if (ips_snmp)
{
  community = get_kb_item("SNMP/community");
  if ( (community) && (!model) )
  {
    port = get_kb_item("SNMP/port");
    if(!port)port = 161;
    if (! get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

    soc = open_sock_udp(port);
    if (soc)
    {
      # Sanity Check. are we looking at a IPS device?
      txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.2.1");
      if ( (txt) && (txt =~ "IPS") )
      {
        # get version
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.10.1");
        if (txt) version = txt;

        # get model
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.13.1");
        if (txt) model = txt;

        # get serial
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.11.1");
        if (txt) serial = txt;
      }
    }
  }

  if (!isnull(version))
  {
    report_and_exit(ver:version, model:model, serial:serial, source:'SNMP');
    # never reached
  }
}

failed_methods = make_list();
if (ips_ssh)
  failed_methods = make_list(failed_methods, 'SSH');
if (ips_snmp)
  failed_methods = make_list(failed_methods, 'SNMP');

if (max_index(failed_methods) > 0)
  exit(1, 'Unable to determine Cisco IPS version number obtained via ' + join(failed_methods, sep:'/') + '.');
else
  exit(0, 'The Cisco IPS version is not available (the remote host may not be Cisco IPS).');
