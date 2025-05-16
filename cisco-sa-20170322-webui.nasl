#TRUSTED 1af68ffdd3ec22898ee7e30b341988cbe3bbc9f6ffd1f4dfffe7698f32e2d688f8889c69f6f40526c7a1115b8ec0bdcd57e86d1e878412120425b80e15a0ccb9ab432e698bfd4a77257cbd55dd0a4f62536c556ae9391b60fc22bdbab6817910d0d758a478c39830f63c10c6ccedab27080950ab52a2ed589aa0fcfad8d29ee066d77ccc78cb1f758e78ae2ab5ffa54dc840e6d1fe1bdfe3670e9d36fde63d6e731467b2debffbcb1136cfaa513ca7f66ab21418d4e7616ead4349e601172c4f39fb6c11979de64e2c1cc014fcb01a51142dc4b18353350b3cbbc23114aba5b3910cd59b18bbdec85c75a84db561320fce3d15ba7c754dee5e7742b8017ac45977dc3a8f898180e79ff194a270a3b418e7dc669c376ae26fa6081ec37a55d01886e733cb9fdd9192f31825d94d373cbba07404db2383a2e3ea370d790ad22a5fa0c7aa848f049afbaa618410e08a862545c23c25187ac37f4dd2430691d2bb22f93af74e63fdd557a979506ca25b1c7d5a6f702180113eea3d09717adf2b968a20b751981c5bf778f30152787ce54fd3cadb7e6ee6bd48a43f2bd59d3c0c3c32b77cd9d71bcb0c4f7f8fae5cf8c11be14474464a8feee20aeb7498e790d42c1b7fc8df7b21d8ec1788ccd1653ace7b6d77d6d2c38da5d94e5db9c3463c5c4343168dc7d64ae0b7932636772acf2bf7090546a85d09b7e197dca64f4c18d743b6
#TRUST-RSA-SHA256 3e0f739d9dcf96f6ca434b01ac48ae76c6194cc2f3340e35a122fb33b7b378791f45ad7453b5307648e529b3e8d17e9e07f16839945e27f0c91ceca42d8345029ca6f66acf643d9b4a42dc4cf9808b294ef908160bbb19832e98bf5292b1111b1ce525cc8d29567e85324513d99ee36893646a50316542c859e67db3c201d6e3d3547d9948127e46ba9f1381834bf3d8a84987b4009e0d9b6713141e8d805b1528ad2ebb44abd61e85c4034cd424c529637d31f9e1137aa0223835939839759d9bb5dbe01583941fc3aa9374ca97dda0ffc9c08dfc1651d1b0f30756a075e9a045ece3b3adbcbaf7bbd97490878766331c894a6e6bb7fadf7646794d5be36282240725f2cce356091b5dcc3d4553e9db7adc2ea229ded04d6808da21250e0b534d7993261b40fcb0e706f5e8981d107a7871f45d1eee509c70f69dfdb387d1f4f60e3ee0ee073d3d58635209e8615bde133786e11ae071afde2e10be290888aa41380689389ecb8b8877dd9d45d9d51aafa931f11a0a7910b2f92677a2015e09a99ac0f314de8b6172296c1d8427c499bdff322e72f91c8852cc990607daf3dda1c12fe44e4a9756242ccc165e0ed0088b31188a162bcad6abce1c0a9ee00e69d00b170dc6f477893bab26199c67ae884a917c963dab71eb8d58d0a77d28fd29e6883da4abd6901466f9613db19b2c863b2b24cd1a5aed3783b3ca0cad3e65d3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99031);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-3856");
  script_bugtraq_id(97007);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup70353");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-webui");

  script_name(english:"Cisco IOS XE Web User Interface DoS (cisco-sa-20170322-webui)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the web user interface due to insufficient resource
handling. An unauthenticated, remote attacker can exploit this issue,
by sending a high number of requests to the web user interface, to
cause the device to reload.

Note that for this vulnerability to be exploited, the web user
interface must be enabled and publicly exposed. Typically, it is
connected to a restricted management network. By default, the web user
interface is not enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-webui
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?072bd138");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup70353");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup70353.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
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

if (
  ver == "3.1.0S" ||
  ver == "3.1.0SG" ||
  ver == "3.1.1S" ||
  ver == "3.1.1SG" ||
  ver == "3.1.2S" ||
  ver == "3.1.3aS" ||
  ver == "3.1.3S" ||
  ver == "3.1.4aS" ||
  ver == "3.1.4S" ||
  ver == "3.10.0S" ||
  ver == "3.10.1S" ||
  ver == "3.10.1xbS" ||
  ver == "3.10.2S" ||
  ver == "3.10.2tS" ||
  ver == "3.10.3S" ||
  ver == "3.10.4S" ||
  ver == "3.10.5S" ||
  ver == "3.10.6S" ||
  ver == "3.10.7S" ||
  ver == "3.10.8S" ||
  ver == "3.11.0S" ||
  ver == "3.11.1S" ||
  ver == "3.11.2S" ||
  ver == "3.11.3S" ||
  ver == "3.11.4S" ||
  ver == "3.12.0aS" ||
  ver == "3.12.0S" ||
  ver == "3.12.1S" ||
  ver == "3.12.2S" ||
  ver == "3.12.3S" ||
  ver == "3.12.4S" ||
  ver == "3.13.0aS" ||
  ver == "3.13.0S" ||
  ver == "3.13.1S" ||
  ver == "3.13.2aS" ||
  ver == "3.13.2S" ||
  ver == "3.13.3S" ||
  ver == "3.13.4S" ||
  ver == "3.14.0S" ||
  ver == "3.14.1S" ||
  ver == "3.14.2S" ||
  ver == "3.14.3S" ||
  ver == "3.14.4S" ||
  ver == "3.15.0S" ||
  ver == "3.15.1cS" ||
  ver == "3.15.1S" ||
  ver == "3.15.2S" ||
  ver == "3.15.3S" ||
  ver == "3.16.0cS" ||
  ver == "3.16.0S" ||
  ver == "3.16.1aS" ||
  ver == "3.16.1S" ||
  ver == "3.17.0S" ||
  ver == "3.17.1aS" ||
  ver == "3.17.1S" ||
  ver == "3.17.2S " ||
  ver == "3.17.3S" ||
  ver == "3.2.0JA" ||
  ver == "3.2.0SE" ||
  ver == "3.2.0SG" ||
  ver == "3.2.0XO" ||
  ver == "3.2.11SG" ||
  ver == "3.2.1S" ||
  ver == "3.2.1SE" ||
  ver == "3.2.1SG" ||
  ver == "3.2.1XO" ||
  ver == "3.2.2S" ||
  ver == "3.2.2SE" ||
  ver == "3.2.2SG" ||
  ver == "3.2.3SE" ||
  ver == "3.2.3SG" ||
  ver == "3.2.4SG" ||
  ver == "3.2.5SG" ||
  ver == "3.2.6SG" ||
  ver == "3.2.7SG" ||
  ver == "3.2.8SG" ||
  ver == "3.2.9SG" ||
  ver == "3.3.0S" ||
  ver == "3.3.0SE" ||
  ver == "3.3.0SG" ||
  ver == "3.3.0SQ" ||
  ver == "3.3.0XO" ||
  ver == "3.3.1S" ||
  ver == "3.3.1SE" ||
  ver == "3.3.1SG" ||
  ver == "3.3.1SQ" ||
  ver == "3.3.1XO" ||
  ver == "3.3.2S" ||
  ver == "3.3.2SE" ||
  ver == "3.3.2SG" ||
  ver == "3.3.2XO" ||
  ver == "3.3.3SE" ||
  ver == "3.3.4SE" ||
  ver == "3.3.5SE" ||
  ver == "3.4.0aS" ||
  ver == "3.4.0S" ||
  ver == "3.4.0SG" ||
  ver == "3.4.0SQ" ||
  ver == "3.4.1S" ||
  ver == "3.4.1SG" ||
  ver == "3.4.1SQ" ||
  ver == "3.4.2S" ||
  ver == "3.4.2SG" ||
  ver == "3.4.3S" ||
  ver == "3.4.3SG" ||
  ver == "3.4.4S" ||
  ver == "3.4.4SG" ||
  ver == "3.4.5S" ||
  ver == "3.4.5SG" ||
  ver == "3.4.6S" ||
  ver == "3.4.6SG" ||
  ver == "3.4.7SG" ||
  ver == "3.4.8SG" ||
  ver == "3.5.0E" ||
  ver == "3.5.0S" ||
  ver == "3.5.0SQ" ||
  ver == "3.5.1E" ||
  ver == "3.5.1S" ||
  ver == "3.5.1SQ" ||
  ver == "3.5.2E" ||
  ver == "3.5.2S" ||
  ver == "3.5.2SQ" ||
  ver == "3.5.3E" ||
  ver == "3.5.3SQ" ||
  ver == "3.5.4SQ" ||
  ver == "3.5.5SQ" ||
  ver == "3.6.0E" ||
  ver == "3.6.0S" ||
  ver == "3.6.1E" ||
  ver == "3.6.1S" ||
  ver == "3.6.2aE" ||
  ver == "3.6.2S" ||
  ver == "3.6.3E" ||
  ver == "3.6.4E" ||
  ver == "3.6.5aE" ||
  ver == "3.6.5bE" ||
  ver == "3.6.5E" ||
  ver == "3.7.0bS" ||
  ver == "3.7.0E" ||
  ver == "3.7.0S" ||
  ver == "3.7.1E" ||
  ver == "3.7.1S" ||
  ver == "3.7.2E" ||
  ver == "3.7.2S" ||
  ver == "3.7.2tS" ||
  ver == "3.7.3E" ||
  ver == "3.7.3S" ||
  ver == "3.7.4E" ||
  ver == "3.7.4S" ||
  ver == "3.7.5S" ||
  ver == "3.7.6S" ||
  ver == "3.7.7S" ||
  ver == "3.8.0E" ||
  ver == "3.8.0EX" ||
  ver == "3.8.0S" ||
  ver == "3.8.1E" ||
  ver == "3.8.1S" ||
  ver == "3.8.2E" ||
  ver == "3.8.2S" ||
  ver == "3.9.0E" ||
  ver == "3.9.0S" ||
  ver == "3.9.1S" ||
  ver == "3.9.2S"
)
{
  flag++;
}

cmds = make_list();
# Check if the web user interface is enabled and configured
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include http|transport","show running-config | include http|transport");
  if (check_cisco_result(buf))
  {
    if (
      ("transport-map type persistent webui" >< buf) &&
      ("transport type persistent webui input" >< buf) &&
      ("ip http server" >< buf || "ip http secure-server" >< buf)
    )
    {
      cmds = make_list(cmds, "show running-config | include http|transport");
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
    bug_id   : "CSCup70353",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
