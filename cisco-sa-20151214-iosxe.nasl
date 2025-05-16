#TRUSTED 7417388f6d56a77ef465e445cdc0cd958b7626ef8a7a51727cfff3f99845c3005601ce6c89c7bb29643f7eb418ece3781d94c776f56ddf693b8120649510e3300267cba736e657d9d62118851ca90b8d1c816ae598cb2e2b8eba9160756f54bc3d832a53f8e3f05673e0b308b5070ecd409908bcc4b4d6bca00935499a58c88a085b9c146b3e45912c0bbf55c481cb23075c9f11e9fbbdb9418d8757ae4e11040bc8b029861e44df6b91d55b39f318884ab9c33e29983d7312f881173b1b89090fdad4b55a67da34e85c1ff2f56488f1059ff67cd31ffe4145a0efa6b698fb76187b5db572b0174cd014e4ae5da69b6d4b0c3ddb75ba9980f57871fc41440d6e1dd953cdb0d4f199e33d69749ace74ef65db7d328e43102b9861ed2eb6e3f5ec8efa70ec9533d3db108b3e8789b7ea94cb9931cc338be388d6c5e8a5c63c37dc5091e1f6ca1d8bb65b904f187ecb1eb866992fb1faff375f10b5535dafc3e565b8ca4c56c4ed2160d378db4514a4a3945dd0610486c7446597c94c204c7163f8399b78242b25e23156d02e306eff4c6651b666cc5f98781ae1e19affcf81e8dbdc4af410084c7d669b8afb823e1f16c1a391b6d7d1c989c72d965bb40cd5921af54c85daf8ccaabd8d083cb68a49b564ae51bcd217ae5b4574c6d7bd4e42879f30ac7f66d3e07ab68b5d6e36fed8779696e94140485daeb19db53d22a85c1476
#TRUST-RSA-SHA256 5427bbe1c57b8ab61ef8bab66ede6984114d4293df46aa12e096696287992ec79dd22d1d3c0526264c17387cf71ed40513295075d120179a2131c07a2a90bf1838c3d86fe469de09fffd48555e81cc5d9ab2a6948d492f5980be9c6157c1e1e613f603b734fca8c732248b648f1b77b70f7d84a3fdf0b52d8bf647dad97f38add06e9dc32db21c406c24929cd2a529d29e4f9453256559618c3f179e44334d80d49554e8548ec1d35517ba993471a805de5e61009d4b00da010b469729e328b43f42b5f1a8b866d5e94beab87e348fbcd6a1b72ff550e29e5c5e96258321a6352ac40deb46d1c6b685b7bceaa9f5b469d32674bf3ba1f54e7c9436eb580d6a32202e221c70374ad79c21f3cf8c7b9ff9bb1b9259e2ed0f6fc28d01da3ad0ab6a35d5f68a2c4612e4c37fbb30b64f43021b2b8e6c59f9d8844d4cab33ab9aa171085df511a8da7b5c17c9a181801a9ef4896859f6e1045e7d5f8f9bf000138e83570151ac863d494230f57a60412e2a9f5eac9ed10afddc57b73c9c62a2a4dea9937128c441921eb62165318feb6f5e4e98849636a3aac2eb93b4393049834142f76c98108f2bdaa8f50f6b56714cb73d35540f35a05249ba516efe75848c30d3e6ad40e25245d2cc46a274f1e2cd42726754cec45af49f8e1280a7129c80d4d839bd32e5bf5d30e77e6c5d1569cc0136fc9470372e9fbc36a29beaa4408e4f38
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87504);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-6359");
  script_bugtraq_id(79200);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup28217");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151214-ios");

  script_name(english:"Cisco IOS XE Software IPv6 Neighbor Discovery DoS (CSCup28217)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch, and is not configured to limit the IPv6 neighbor discovery (ND)
cache. It is, therefore, affected by a denial of service vulnerability
due to insufficient bounds on internal tables. An unauthenticated,
adjacent attacker can exploit this, via a continuous stream of ND
messages, to exhaust available memory resources, resulting in a denial
of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151214-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dba1bec0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup28217");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup28217.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if ( "ASR" >!< model ) audit(AUDIT_HOST_NOT, "affected");

flag     = 0;
override = FALSE;

if (
  version =~ '^[0-2]\\.' ||
  version =~ '^3\\.([0-9]|1[0-4])\\.' ||
  version =~ '^3\\.15\\.[01]($|[^0-9])' ||
  version =~ '^3\\.16\\.0($|[^0-9])'
) flag = 1;
else audit(AUDIT_HOST_NOT, "affected");

if (flag && get_kb_item("Host/local_checks_enabled") && (report_paranoia < 2))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ("ipv6 nd cache interface-limit" >!< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (flag || override)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup28217' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
} else audit(AUDIT_HOST_NOT, "affected");
