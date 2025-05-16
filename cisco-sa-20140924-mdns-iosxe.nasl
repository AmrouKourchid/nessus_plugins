#TRUSTED 810f99d9d0d55a4cf79fb35251119c0254a8a4617806dc497681341395f8058e86d87c5eecb0120107ca3dcba0cb8b0a60750fe9c22fcc8ed673f846f4260c53b25da4cf7b6eb4c299e332a04b771f9dac8697ab06b8b4f6c7fb65093bea0f95c210e2263e508c6bed10a5dcc03a0fed63748bb24ecfb623d1721c39ca4f4c5db8bf1826a1a5730f367c3211c22ca0499af463ff54a3bbec02963b857006f3a87167c42079a47d9692a70bfce1f2f8ff3e385bd54278f64b51080e39f1171a8174afaa813fb7afc68445fe500d4220cbdbf83e763fb8864a9cb9cb678edbf280021790c8e249b9dc5ef94d96740e7f188853d807624040878b25269f71e9782bf87b078e8e35be0111253bd69b7d0aab954c1b05f53f0095ef2e349e51d1578ebe2ac229575dd5fcf85366e50986e6691a54e0406168e6ef2b65c92b460fcc83b6100120fd3f24f118b11e51bef2975cd5fcee90269027c00c863094c895533c4a769933a292ed7b962082d061cc9e99b14ab2e8d729375ef489f3f0f498e779ecb2bf30d7e33195a9b4ab0196b5c02ca34051672ca26694ff33d388e303cca7e95e6cd5196c87f87462856d5e7840af5d29bc5c377549b5de7f1ea18c5c1c1a3f4ccf3badab71a38fa9e1cf1d186d6e2d70e954afd561a1a257fabf8fa2541bb964cfd4c8b3f2e067f6ab086f4ed6292d47ffd63ce98f532df6a310c0347af0
#TRUST-RSA-SHA256 74745159246318d12885a869fbd190f982c29154c724e35168189bbfe406a73f519068223843d6f6ed5458a47a99de3a9f4bc4ea8661088712a8f1ad94bf04c31a183bc3909b1b92fa52f298b3c3d13fb1acdbf03ba55be16fa692ec9bac899011dd2d478e07c12fad9396c7cdd0bcd6d11e07188892ba7898e19c58630e328e6a3cd79b8463a3815f8cf5a82f3df4e5aa3d2adc72d2e8203a6b98fac3d9382273199fe3c5eab496555169f8bc6672ef93edb3635318b92c3d84fdd310c22cea6424378c1aa67dd9f161705a0fb887611832cd2bb2c6235399caae44e65192d6c359f4db2dd190a66a7751011159cf3b0bcfa001f732417b3aa70ab08cc9864b8cb60e75a32da4667fe85728ae3e559fd0899a0197abf065898eec1f4255988e522f3e3d5f601530067be23c59be65bdc51e4d195f4bca64d335d9ceeaaa0f87b13f01130b359b921d9ddf17906180d0ceef4b165667cb72a2cbbbb8e8ccc50efbdf047fdae58811e4253294645cb2c8074def784d7f19f21091e1811d53b75cd4d5e5a9f02ae17e214a40d22b23ca1cb6a1478fa61079fb1f731f8557df4a040486cb75e833ec42ed309ca51c8aca640f90b586f9f409ac6632c91164fcff6423fb001a03c6910aeaa6f9615f88b4adbf5ea386fdf36da84575d4f41a1e1d395f56c2699ddd7ecd46e59ff317a4b52b1fb64baf4ffbf4d7ed0f51e72eb3e10b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78030);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3357", "CVE-2014-3358");
  script_bugtraq_id(70132, 70139);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj58950");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul90866");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-mdns");

  script_name(english:"Cisco IOS XE Software Multiple mDNS Gateway DoS Vulnerabilities (cisco-sa-20140924-mdns)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by two unspecified denial of
service vulnerabilities in the multicast DNS (mDNS) implementation. A
remote attacker can exploit this issue by sending a specially crafted
mDNS packet to cause the device to reload.

Note that mDNS is enabled by default if the fix for bug CSCum51028 has
not been applied.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-mdns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2f51db1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35023");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35607");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35608");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuj58950");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul90866");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-mdns.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

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

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCuj58950 and CSCul90866";
fixed_ver = NULL;


if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-4]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[0-3]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (ver =~ "^3\.3\.[0-2]SG$")
{
  cbi = "CSCuj58950";
  fixed_ver = "3.4.4SG";
}
else if (ver =~ "^3\.4\.[0-3]SG$")
  fixed_ver = "3.4.4SG";

else if (ver == "3.3.0XO")
  fixed_ver = "3.3.1XO";

else if (ver == "3.5.0E")
  fixed_ver = "3.5.2E";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$" ||
  ver =~ "^3\.10\.(0|0a)S$"
)
  fixed_ver = "3.10.4S";

else if (ver =~ "^3\.11\.[12]S$")
  fixed_ver = "3.12.0S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# mDNS check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^17\S+\s+\S+\s+5353\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because mDNS is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
