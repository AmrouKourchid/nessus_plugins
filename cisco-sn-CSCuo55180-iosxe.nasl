#TRUSTED 9fecc74c58829861a8a23c74ee32eaadb57daadafd0de1cedd4664af645db06c8be3841e27c0f30011b3381d15c087f7009473ff6683b4a7ca5a3ef7d0d48b4033a05a4d3761fb5a7d7c5274076bc6b64240740ad1c357797f2a2003e94c45e4a931507c350d6b610957f3327a9241755c44a81c3f45e2ae279f94bfd0ec3f44b0f3e0e375bb79e876c69a443363d5904248d6df7a6df8108b28e3f62ea1580afcfaa1bedd0af8474578bec5bbfae4dd15e2e125db8eeebdd512a03c0c0a19e578960087a9cbc48c8510eae32f91f20ba779ecf95b70539aafcceaecbdf432eb3c380c346647eee284b3d6f08eb55172694a06f93549505e3d0b8cfe2b4b9f4ec942dad86243d271de8ca87665f71888863951fc76c2047e494c38819ea651c0470f4493174ad291d7da0b037b6f5b1fcc677e0b3afad3056fe5590e8d0bc97c6dbd5eee70db4e1485ad8cab2b6852e35bbccfe3d44b0860a72e8ddfa5bd6bf294e7768d5e02a2a188550a759f43ff47140082404757f224a5f7031da99cf94f9e14dd6b4dc804836c66393126eac431362b497b2100128f43bb22c4b5ad60a8efc80d49caebbccb1e63e6b228ff47405d7fc0ea38e5f5396bcf61d9a44903ebc903de3e97db355d752c3eb4d378252770cafda861bf502474c7762c8e5e4a5a1621c38ca22ce83139b7d2544170e8c4f441c6d76d08547567eecff836f8f332
#TRUST-RSA-SHA256 740ddba8446b70a3559067e07f8f3685cdf36f7af6b1b3ad155a1fbb005b9391e854e9695f05b426ecf95fa42e3cf7138b52639899c4ba384ee367cba2e52c0d13e13f8f99c2bd15ad201e413b6a352385d2d3fef37e8c6a79074183473ee716cc79cf93c93dfb135ee976086d8817afb0fbe4e8d421d547cbb729986a0d58748f814f35b507eac07a83d16198d4c386f7c24cb6ea75d3faad8ac59cddacefebd9359e70e7629090d21f717b04f248bcad754590ce7e86f87c647ff6f7250754270a399aa3276011955754ced6d84c2d7064f4593b6dbc74983d65af2df1fa9958317cb06f34a4260fd8d68ecb2320dad86f7ae0fe31d1b124686a22ec0d74497c3f412251aa305e6f1d5ece46f591b7746eab17a67f1bc6d57bf072d8e866fc9d12235f0faeffc7126d3a55307572d2b5704a8a97cada20353bc6823e99aefe73e12d9aff4e0793fb05c40532c515464fb2bb9351b2ed465fd14c10c232ca42fe1a0c5fa12cb8bed6d22830ce24cb9ba2143f3047ae89266c57e2d9ec625a49cdb1c9c37377b4744e26f565501f40974196d7ba79139f24ae05f84c6a0d75ebd71c25252805d9d68ce2e3d5382cfbb5327c6218798ed56ed06cf075e7f7dab673176648149b4e40f965030a2c892d995e34a6e2b51f1dc5b549a2f126891cd5470a4a02996d2cd4b937a7d7ae7255a316b82473ce8159e2bda69ccd75b09ed0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76790);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3284");
  script_bugtraq_id(67603);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo55180");

  script_name(english:"Cisco IOS XE PPPoE Packet DoS (CSCuo55180)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability.

The issue is due to improper processing of malformed PPPoE packets. A
remote attacker, with a specially crafted PPPoE packet, could cause
the device to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34346");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34346
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e780a5c3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuo55180.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");


version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model = '';

if (get_kb_item("Host/local_checks_enabled"))
{
  # this advisory only addresses CISCO ASR 1000 series
  buf = cisco_command_kb_item("Host/Cisco/Config/show_platform", "show platform");
  if (buf)
  {
    match = eregmatch(pattern:"Chassis type:\s+ASR([^ ]+)", string:buf);
    if (!isnull(match)) model = match[1];
  }
}
if (model !~ '^10[0-9][0-9]') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

flag = 0;

if (version == '3.7.0S') flag++;
if (version == '3.7.1S') flag++;
if (version == '3.7.2S') flag++;

# Check to see if PPPoE is actually enabled on the host
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ( (preg(multiline:TRUE, pattern:"pppoe enable", string:buf)) && (preg(multiline:TRUE, pattern:"ipv6 address", string:buf)) ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuo55180' +
    '\n  Installed release : ' + version;
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
