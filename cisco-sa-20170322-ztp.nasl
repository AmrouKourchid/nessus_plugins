#TRUSTED aefef89401a328dcd3faac90334cc752b0572046476831b3e9b4d23eb706604dbad4b46f1cd43faf85fe2b923c7c4e2b5e47a7d87b398226a33dbc5182eb4261f00337f11700af5e77c79efa6fab19ad3ac08af8fe10b7de6e376a4b9de904a2efdd05cfc71e10be3027cc41a82aaff24d021ebb89f0accb8aeb63e4b43d39614834ae70b341b3d905cdf28174dde4f225dcdd3dddf4f150d180b9d0087dad4fdbddac380d710856b254ccfb765fd53c290a269358051d9959d6e5a8f6d7909aa54f7a73cb3074d16187d324eeec958f41079c2d23362ceaf5b893c786cecdaf7ac2ba1f6e0a6ac5f40d1c5ffcbbe7444fb5e13f658047d446c0dd774a733144b18df1548afc056151af969e4e24778c2149b4ebedd6d7fe7dfbf21f8326fa60f9c28f006fc0ad38b269aaa8c0923410ab99c016e82b393880ee68e756874989059fcfe49553bb9ed1a9f860e75cd72bba0c9d581eba630f34dab5554711b061485e3839bcbd8549e92acb01c6b09f7085920d0a7c3f64c86751dbe70d71721c1e2720c4b9b593c5d1d12f01f7f4f184c3ef27eb2e341f208b1112703cc066274c25cb1fe229aa82a72d7676d5e9e6a05342e1327f48f75c07c39239bb24e508ce4a42d5570526c268da45ecca6aebd401f90d0cd4d5d3a509c391b56cbf1755d3f9e3bc814682bd5c42c510204e8f2d9d1622be28ef76242cb73b7aab028c30
#TRUST-RSA-SHA256 410daba9e57d0948f5bfa7ec6d800d4857f070a1ff2a9fbfb0933917d3da4c9533f7288391d25038d8c44bfc16a57feacfcde460eac856bb6bd7be3a7dedb96eaec79994d3f69416b364ed1cf3253f756d89306d7021ebabe9dde4d85dfcc7ca08048a841da7ba4af21ae79d1f7a04f6521f2e3e017e8d1e70cee9cbb429351cdc024bb82785850443b7163f3a1f07d474daf1cd41cab4b116aa6f76a42839e0cc041c48dbb4a39d40eb507ace6d8f891a3f5b5c87985d4b1ef5fe3d50af45bad5e29bbe9e3ba002bc84f363743f54bfc1b9b42ec4550e311638e04bdcb717aea1880cf78bd709872509611042c772f0aae2bba117494f8a16d7d6be4cbe6110aad808636bc2c79ddfed852a2ad255972ec1b8d7648cd73683f6923692ede5bec1482758a700f46a4da32483f02979fefa24c6240e3154c3b1563fc6f34c2948463bd593f1e7a4d118e19b5e89f3239cfb272c4de2be13b5e9d379219cb777a8c07ddbbfa25b7beab9c80f883039820a5af6ced5a5a83855120b384dda2eb6b6d00c15e24785f64f75cabebcd712fce25f0f3c30ee08d24caebe61a27258941d1c9b24601684f9df156ea0e4c1d5445505a861dc196a24be4f34e2b18aa5e0d7573851e4887322d43c4156ee33bc086ab1a7503b860060fc272adb2bf15044e3e4aa2f9ca942c87dafcd6f31e48de1e71841d24475b69824f0eb854fbe6e71c1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99033);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-3859");
  script_bugtraq_id(97008);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy56385");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-ztp");

  script_name(english:"Cisco IOS XE for Cisco ASR 920 Series Routers Zero Touch Provisioning DoS (cisco-sa-20170322-ztp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote Cisco ASR 920 Series device is affected by a
denial of service vulnerability due to a format string flaw when
processing DHCP packets for Zero Touch Provisioning. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted DHCP packet, to cause the device to reload.

Note that for this vulnerability to be exploited, the device must be
configured to listen on the DHCP server port. By default, the device
does not listen on this port.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-ztp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?339c4225");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy56385");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy56385");
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
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if (model !~ "^ASR920$")
  audit(AUDIT_HOST_NOT, "an affected model");

flag = 0;
override = 0;

if (
  ver == "3.13.4S" ||
  ver == "3.13.5S" ||
  ver == "3.13.5aS" ||
  ver == "3.13.6S" ||
  ver == "3.13.6aS" ||
  ver == "3.14.3S" ||
  ver == "3.14.4S" ||
  ver == "3.15.2S" ||
  ver == "3.15.3S" ||
  ver == "3.15.4S" ||
  ver == "3.16.0S" ||
  ver == "3.16.1S" ||
  ver == "3.16.1aS" ||
  ver == "3.16.2S" ||
  ver == "3.16.2aS" ||
  ver == "3.16.0cS" ||
  ver == "3.16.3S" ||
  ver == "3.16.2bS" ||
  ver == "3.16.3aS" ||
  ver == "3.17.0S" ||
  ver == "3.17.1S" ||
  ver == "3.17.2S " ||
  ver == "3.17.1aS" ||
  ver == "3.18.0aS" ||
  ver == "3.18.0S" ||
  ver == "3.18.1S" ||
  ver == "3.18.2S" ||
  ver == "3.18.3vS" ||
  ver == "3.18.0SP" ||
  ver == "3.18.1SP" ||
  ver == "3.18.1aSP" ||
  ver == "3.18.1bSP" ||
  ver == "3.18.1cSP"
)
{
  flag++;
}

cmds = make_list();
# Confirm whether a device is listening on the DHCP server port
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  pat = "^(Proto|\d+)?.*17(\(v6\))?\s+(--listen--|\d+.\d+.\d+.\d+).*\s67\s";

  buf = cisco_command_kb_item("Host/Cisco/Config/show ip sockets", "show ip sockets");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:pat, string:buf))
    {
      cmds = make_list(cmds, "show ip sockets");
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
    bug_id   : "CSCuy56385",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
