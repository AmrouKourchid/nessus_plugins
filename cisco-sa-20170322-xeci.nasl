#TRUSTED 93e1791951992dda9e724e734222019e5b5aae8c7c13ed0e884b7ee0858a36f182e6c19ec6d1a5138061c2ae3318cc0efd9cf4bc16b2f39d7afa8b94288c47cd0c0153eadb98169061b8a31909d9c494f804a900742331748f7b7a80c3e02c1c851b8d3f3d41159a36778ea0750cb4627e4dab5c2d004ca2a6998a93b4ebdbc188416d5b8212e668c87042af39bc3056422941a46379905937c6473fa837655a83c1796b119895db9123d4d6176c8a714c7369a476f652dd4f0aa91ce17af1b1bec4117473f12c45e4c7df3dcf0d60c08c49ffc0615dac7dc3676a6f75f3b3968ff2ffe208d4f179ac647edb742f29835a535fc061a16480ef682a2473e81a83001d792272a616f726f73b9305c3edd447d3644706ff2c7d64bd859d4f010b672c2d9df09e60d688878b7a0ed3a6e444935a11058cb00390a2ef66bbd86f980431f62f9e73dd810cf63f98fc9b1f27188985c51ab1effef0e09f99e69c59a5f4718705b51db55c156f9c8a25f8c0edfddc8c397f3d0b4c27e6c8567f2cdaebd7649ee8c0e5fe141e03fc0350c4950f604345d42fdf960fe27a8849ddeb1261dc5a3c39a8202a8b3550596b84fe64d7f4a99940f5b6c4ee761d99549b658e4e3dc25a9bad374c505743895da1768a318273fb677b623a94c46e48843334ad1d95a508ecd0e7201cb8ca1258e8c4cbc7329ed45d386feb67bae20824e7adef937d
#TRUST-RSA-SHA256 897c3e15aca2b04a9724032b2d3827769de6ee1f122af0688406ac313b7d456f49ed60eaa8495232c8b2228de47a87643a2f614c044ed257cbd017113e050b5a1359318ce1f8311aa8d137ba4a520ac06d378d8fd822aca4dc29dd8fb3137303437f50d7f2c34eeb0dd5d6795511fb3bc569c39a6960ac1485d5699b536849cb42f9394353fd9284df5f40ddc285fb5826530ce3f5c6628ec12fd3d9194ca9515f79797dafdb45452dd719a53866f4cf1d24d4573dde9cd71f2246d19bd07f768fc56257c872375132f54285ec7842bc3eab923754b18b56736f6ae18fc3b2b2efe1c2839811feddd1f9bb8c01bd5335e6612e7f02e2f237a5046539a53a9e2a97b7a1b7e9fa5df50ae996627b9cbdb92fb46e60c8e5deb594a5199c7f66dca9c5bc300fbad14caf2224ef9c62809942ee7db21496e3b0421a29a9f6887607246707a57a0ee42ee5fd07960525bcd5f945a19bace99a6482b95364c059f09404bfc0e224c2b69c32ee8e1fff9cb82039e862b859e712d23333f543ed80413c24d3ed2a2354140e85bf33b3eba81855bc887bc9cdfeccb225b7168f1130abc71b4fe5f4f25e13350bbfd885fe777c4dcb7db844d69c0a2cfa4fda1dfc79875bdb438f91ac0f342a629ddd29c422030918e9b5ff9a33bd2d25cab9f254ea1c815c9051fe887c415fecfe0aa38a015099290b251eeacd809b90c4900136f16e0f2c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99032);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-3858");
  script_bugtraq_id(97009);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy83069");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-xeci");

  script_name(english:"Cisco IOS XE HTTP Parameters Command Injection (cisco-sa-20170322-xeci)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by an command injection
vulnerability due to insufficient validation of user-supplied HTTP
input parameters. An authenticated, remote attacker can exploit this
issue, via a specially crafted request, to execute arbitrary commands
with root level privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-xeci
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33e0fa8b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy83069");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy83069.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
flag = 0;
override = 0;

if (ver == "16.2.1") flag = 1;

cmds = make_list();
# Confirm whether a device is listening on the DHCP server port
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  pat = "HTTP server status:\s+Enabled";

  buf = cisco_command_kb_item("Host/Cisco/Config/show ip http server status", "show ip http server status");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:pat, string:buf, icase:TRUE))
    {
      cmds = make_list(cmds, "show ip http server status");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCuy83069",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
