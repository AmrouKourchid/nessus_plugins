#TRUSTED 74be6ab0211896cd84f9b543062d0648e5c860c4c9d63fb168a646d62fa4c5c21c90c1134f5fae0686fdc4837d6444785ffa0c4c3c8144811a3241205f0e18288b3eae53d5751e157bbfbe8b7b86dc7f81e1383bdc6b69752541166a11b9058946452cd1f330e5a5be527ae1ae06e280e96adec60d3064046a49b88cbc9db6f8bcaac40b300089e2a7b7026abb4d6daaa552da1fac2792fb4ec71de0bd750e94886ede0bbff33ae8f7464402c40f7c81d3fd83057c90c5f281e2ed620ac49015fa3fdb766bc8caa81dbaf5786b2512d4c5523dd931fb3b69c5488d03f2aa668ab368a3d01438089225f113ded5978dc4d164be96030f841e25c4477eaa7addbb0d83f4480f0bc487986e7bc25e9ec1fa0125cb05e4665082f90958e9ef0e97bd2de1adc3d1d5991c9ff008dc1d0f55302f9883c578cb68bb2271f1a400658c9e7c935e162cf3231e29bfba73b941902e03bd6a8771f424070bb0a5f9cdbcd24b9f54430b0a29df0399c6a52067ee10e5ea385dd7e124e0d233c0498e98fbe4fb13d615719f54c956990a5fc70a68111c70d04ecb0773552a8bb722d2c3afed3399ff333dbe3934615bb846eff2660124ef05ac444fbb44b79506a80cfbdd35b511ee5a560aa163865abcb5d00e4b5e1c9fcafbd1afef9826a0d048bfadbf68d604b7d40fcf12da274d449b6a68eccb089aef017b0f6ab2f71abf7914db62c518
#TRUST-RSA-SHA256 7c5ad6170113f12cf6f865c5dfed9d44982dfe4ed7a57344b20071fd2dea36d3750c6554cb2f4884676e96433f5bb80e97ee81a94a602e85a9c50adfa45b14f58d0da022e3e99ce7227c1fda3a76d3ec14f66b1c9760c6215ba606cfab7a9eb14d00cd441a9cdbc055016de6a22ec3160153968e143af549e739d17b268ad37a895cedd730ff55db851cd836ac46f1e622095d9f8fe99d92b330053858fda0238bc3fe904a4bac41db5ca3e2d8cc5429a7c3e1f7dac18a0407a505632409d8f15b8ea6951ec9d4297aca4fe729cf75e5c6d5216cf6c0c5c156565911387214d159608f04c09a020c8a480b33ade9e368003837ec6699d367ffffb8c26febc1a952d4d8e3eb4704013aa7c3d0e025e141ca9fa234ad1c15d1a8e99f7abc77431a515c57edcee77e0a2d7081596a9f50a13a48b08b7d673b9002733aab80ddbc729820452196ba9fb1b195ba36cea15d00186d494df4f5aa25b49a2dda3c448e018c7ba5306ae2a29daec9b6ccf8a0ddf9b6b854ad47622aff6fdc9fc807b82c7ebaa849122f4d2392dc4df34f7062e96c1a25c55d607ec1757a731e376537c8beeaa6a65a0f41718e2c8a9b376f7cb00228bc508ede2620466e5c83d75d02a201ba862558b4764c601c5fe7391a0e5aa08737e924220b59ee6733b9be8b4cc26f61f1312c714c625cd43676dcec20eac6c9484d113280606c4fa5ca70446b4850
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76882);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2013-6692");
  script_bugtraq_id(63855);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh04949");

  script_name(english:"Cisco IOS XE DHCP AAA Clients DoS (CSCuh04949)");
  script_summary(english:"Checks IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability.

A denial of service flaw exists in the DHCP function when handling AAA
client IP address assignment. An authenticated attacker, with a
specially crafted AAA packet, could cause the device to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31860");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31860
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e08811a4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuh04949.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/29");

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

flag = 0;
override = 0;

if (version == '3.7.0S') flag++;
if (version == '3.7.1S') flag++;
if (version == '3.7.2S') flag++;
if (version == '3.7.3S') flag++;
if (version == '3.8.0S') flag++;
if (version == '3.8.1S') flag++;
if (version == '3.8.2S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"aaa", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuh04949' +
    '\n  Installed release : ' + version;
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
