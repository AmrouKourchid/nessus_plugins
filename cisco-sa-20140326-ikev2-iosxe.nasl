#TRUSTED 5a70ef2a82ba015041d170e75e0aa87445155f4d4b2969aad5ce45e20d28ad836741e247ae20331c09882a6956a5f4b52903f1b4b84d181e8a527058b23bd96abe07ccf0f5c3c21255fc5a5a32002cd15927b8156db5d16cc9df0be3f1538e13d43c7475e3c4091a8072fe5ad918db6f1105d48599782ff98a1eefda427b06743547527a25fa3c3669f53524152b475f45cd6f93686e26324a32943d9ba65441942b75c2e9aabf9f2c3f2d7a60bcc66d32f8dd045f4d70a3accd2d046eb6d86ce56ae6deaffb453372804226d35f4ba013d1d5729d3570c76f098be8d993a9354ec14ce36026f3411e23d9eb9c008ca5d15b6ed71971eb518c654c0a0c0057b6ee53276749abdf10f3d30770d1d7dc0a3034496662518f28b9b1475510a04ed9b0177b3a350fc34984f95d23cba1a2b933dd5f4a94cc6ed588f2b98e8b4126aad465dcf0f3c489fc685b5c1f874cb223ad52a8a2d2e6a1032ab49b3b96168e759483f27c20663c998606b45124fd57c0bb893daab160fabc9b04dfcf826fa7369c65d891e52c614fa616366b2b64ac2b3c30fba4f3403fb091eb0d36642e6f3bd33d8d04f5e340c71371df35adc13addf382d47d78449fd67e1bebdaa5310ae3eeeaff0b43647161193ec73a34e347ea1c54cdcbfdfa83f536bd60f22d0708f69bda62e04a5677e7acb67a1d1f3d850d8eda2de7eb5df8d7cee967b1cd247a91
#TRUST-RSA-SHA256 0f145c48da6f42c008751c7d747e0f7d5d2c8600782be51d1a3317dede614ac53d6ad33913190e6c2313ffb1f13994e3e706e9b884de6d5bd03843a01768dbbd96ce8a723869b560cf9534ec6c2b0ed3749bcd17d5fe5dc626a152300f927ff0194b50b7c123bda784d63e7b55ffab47d482fe53bbd8b6e2bc9ef1a056687757fa3b45c33cf982d0a47bee1b740d8e5a52496fdb6687ab689f0d30708913660d382e7173e186f3f272a2e9cb224ce4fcab4cfca016fe98f35b992ae92537e09289e0b2be3e221ebe4846847a86e1f409dd2a7200cf5c1314d42bad037048216c48cfa829bc778b6f13c3a1e7ed6357a5a797b005ab8c1372c7a05918272da44050234b2c2c068411fe2d3001f2863c380b31f327a6aae40b7204f5b65bf6431142071143eea54cb2aceaaf30454cf2e9d79ac15046e967f8ecd356fa551676627070eb6f1d44c1a4a2a0b9da06278b70b4a3e916a6776bff6ea285bfb6519f93a3030fcaf9a69d232d6319fa691dd843745cea2fbe8b690f3b564ffb9bcaca220e83f8c80c33fa7d91f5378b736f89793d048ad3feda9cd67e455622bf2428714f1ac8af600cc3fb67fff9a3d6198588c409937429cac95974f971611d0ffffba1150fdac2e12ab814d03f59a9de19d7c5f408802bc368e5e41e7784473c996a08abb3c13fe856bb6885e83ab20a8ac85ab7cb6353a7b1ebee8f2d20ba543f97
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73340);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-2108");
  script_bugtraq_id(66471);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui88426");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ikev2");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Version 2 (IKEv2) Denial of Service (cisco-sa-20140326-ikev2)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the Internet Key Exchange Version 2 (IKEv2) module.
An unauthenticated, remote attacker could potentially exploit this
issue by sending a malformed IKEv2 packet resulting in a denial of
service.

Note that this issue only affects hosts when Internet Security
Association and Key Management Protocol (ISAKMP) is enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec115086");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33346");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ikev2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}


include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

override = 0;
report = "";
cbi = "CSCui88426";
fixed_ver = "";

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# 3.2xS
if (ver == '3.2.0S' || ver == '3.2.1S' || ver == '3.2.2S')
         fixed_ver = '3.7.5S';
# 3.3xS
else if (ver == '3.3.0S' || ver == '3.3.1S' || ver == '3.3.2S')
         fixed_ver = '3.7.5S';
# 3.4xS
else if (ver == '3.4.0S' || ver == '3.4.1S' || ver == '3.4.2S' || ver == '3.4.3S' || ver == '3.4.4S' || ver == '3.4.5S' || ver == '3.4.6S')
         fixed_ver = '3.7.5S';
# 3.6xS
else if (ver == '3.6.0S' || ver == '3.6.1S' || ver == '3.6.2S')
         fixed_ver = '3.7.5S';
# 3.7xS
else if (ver == '3.7.0S' || ver == '3.7.1S' || ver == '3.7.2S' || ver == '3.7.3S' || ver == '3.7.4S')
         fixed_ver = '3.7.5S';

# 3.3xSG
else if (ver == '3.3.0SG' || ver == '3.3.1SG' || ver == '3.3.2SG')
         fixed_ver = '3.5.2E';
# 3.4xSG
else if (ver == '3.4.0SG' || ver == '3.4.1SG' || ver == '3.4.2SG')
         fixed_ver = '3.5.2E';
# 3.5xS
else if (ver == '3.5.0S' || ver == '3.5.1S' || ver == '3.5.2S')
         fixed_ver = '3.5.2E';
# 3.5xE
else if (ver == '3.5.0E' || ver == '3.5.1E')
         fixed_ver = '3.5.2E';

# 3.3xXO
else if (ver == '3.3.0XO)')
         fixed_ver = '3.6.0E';

# 3.8xS
else if (ver == '3.8.0S' || ver == '3.8.1S' || ver == '3.8.2S')
         fixed_ver = '3.10.1S';
# 3.9xS
else if (ver == '3.9.0S' || ver == '3.9.1S')
         fixed_ver = '3.10.1S';
# 3.10xS
else if (ver == '3.10.0S')
         fixed_ver = '3.10.1S';


if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"17\s[^\r\n]*\s(500|4500|848|4848)", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_subsys", "show subsys");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ikev2\s+Library", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
