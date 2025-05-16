#TRUSTED 1f7f5f2672a02216793d190d60274eac52791532d8cb4a58a68f1bcc2dfc82d43093f1574c3d63833d0887296508fdbe952f7ebac3b8dd0edbabfdf5c6511bf538fd4900530ff01417986f513dfc70b7a487d46e3b6e1f7e78915cd23c03c16f8c9589bde00577a385135ff7cdf15d5e2251f6f88c111053c7c4faec2d4a5ffbbd12f49a7fb3dd08210e21685f14359975edffad1589620795b45a7b8b1dbe110e3bf7192b608786da5aca14c35ba0d50cd9cbe142e9dee7ea5fc53364341102a5e1e967a6ef99abfcdbb73a9b0c37586fc6acf947c85f56651f3c786967a3939025f2cf499552a7add1f2c1ca9f71e5638eb9f793e8ff1ceb0c5c2ca9888898a4793c3d7c2281d8123b252c28d44faf1f62b3372c9545d3d7d301cb92ee26b5d176e8fe908d321b83e89b099d5a98ce305a8fa0b451543260422c45aaa58e0bfe85567bb83cc1317636d4dd56bbf752e2712813501266c2c372e891b1f0e29217ea19ae832b6b72d5d1e938fa1ca2a644b79bb2ea11272c4f8b4e4d667e9ed8a218fc66af4368ba9e4f1b94475750485bb4753ccbbc8c2565dad9402f7e787d032bfab6b74c1dde601439ec4c49a0964890e3c500bd685d51faddc7528c0dab21617f3b7cb9db96298398f302ef70679bd3908ca19f75ca2c7247ca15a88647cb0a70d6afa5f0b626897ffa1e9180a9df3431e6a783b68d1e275adb4eadf7bd
#TRUST-RSA-SHA256 387257cb6017b86bcf0ae4956e2c9e35723a071a54eadbda6df71ef7173f2d9b6cd42527218369c1df3f63ad97c69e929702fe01b6c8a8d6da5effbfe44c9efa73f5308f6f629527784294e7363d4ab587fca0a887e37364d0e4db5241f245f366094324c8a9569009d619abc9a3bd2d471502dd7039839db2c232086e5b9f1e1d37381b2308f175a7001e49eedc97f3acca1055e2865d06d7c28d4c12afbb7a995a74d639202ffd31416d30425a9c9ef2f36c8f121c88f1ddf66e1ff44300936474c277111d9d64e74380f3fce3d19800ce7c28454a9fcf1cb593aba0f9d9b4b0cb6bdc32eea7c56ca329c1c6780650e183465b1e607dd8ed6179627ee4d45e61f3f1faf79296807a59b0a3f779553ba1635b0ac44efb2e4677d9906ac1ae63ab6143eae0890db066c63746ac39941032a45d32ec91afa4a97338a4eaf396ef940581646af2bd29b5b4955cd5251a59145ef5ac5cdb89b2f141b2825300c276f0fdb7b2f3dffd791d4e51c321e4505c833aea1686e53a4d08b30b813c026833aae06bda7d7e88f738fca894b716ea0ef7dbeb441c943c2e6bcf34249b4851b0d5b673098b4c30133fe1ba05ea26e6a15a199882781302efedc6c0908ffc54732477f560830ca259582f4a8b5665bb3a5e60adb9cb8f866b64f983e73372b87eee3cf162a86be99c89ba765b9cdb758382bcf5ecdbf80ec1cbb5ef86becf7def
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77053);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3309");
  script_bugtraq_id(68463);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj66318");

  script_name(english:"Cisco IOS XE NTP Information Disclosure (CSCuj66318)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device potentially contains an issue with the 'ntp
access-group' which could allow a remote attacker to bypass the NTP
access group and query an NTP server configured to deny-all requests.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34884
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d368fe89");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuj66318.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
# Per the advisory, IOS XE affected:
# 3.5S Base, .0, .1, .2
# 3.6S Base, .0, .1, .2
# 3.8S Base, .0, .1, .2
# 3.7S Base, .0, .1, .2, .3, .4
# 3.9S .0, .1
# 3.10S .0, .0a, .1, .2
# 3.11S .1, .2
# No specific hardware conditions
# No workarounds
flag = 0;
if (
  version =~ "^3\.(5|6|8)\.[0-2]S?$" ||
  version =~ "^3\.7\.[0-4]S$"        ||
  version =~ "^3\.9\.[0-1]S?$"       ||
  version =~ "^3\.10\.(0|0a|1|2)S$"  ||
  version =~ "^3\.11\.[1-2]S$"
) flag++;

override = 0;
if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  # Check if NTP actually enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      "ntp master" >< buf           ||
      "ntp peer" >< buf             ||
      "ntp broadcast client" >< buf ||
      "ntp multicast client" >< buf
    ) flag++;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuj66318' +
    '\n  Installed release : ' + version +
    '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
