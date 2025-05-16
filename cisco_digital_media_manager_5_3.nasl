#TRUSTED a94fce9bc62278279d7dcc3838b13fd3362fbb0fb40b06b263741aff29bb9428580da12e462ed5cd4a8eed2d43f3416b7d180422f1ef28a4d38041187a944970361c76eacbb1998eb45c2134f0a1e2c986c9f892dc2baa15795a20ce828b804ce302a4c70fa6112cc80656b5668d240ab65443b820e6dbb3afe0f96aaf7d215469e4cd91ea9533cb3e2389306f818921d69a6943bd9ea5b526d806a7b765bbf9a8f10211aca885fbc17550427137c726de214ad5358412d685e2f01dfcf5dac4f609c99aad11bbb140ea3fb2061baf02f1562ebddda586ee06357568ea02fabaf76b63bc0a6576ab4f826e59b3f33922cd6e37279c1fb348b0a798899b30945de9c87d6c616ebe07ca78178a50f40b25d99e41be25dceb0b1f5b15429f27554c3902559bae13cc6bb356dc61b59c6bd75cb2bbbb23ce7eed8a50c5f4353966b1dbed76836f107f44c569984453adbb96775559d7ab12a369db8466e441d9d16f7bbaeeffe8ca15e360f7f667e8ca9847d84d62b40fa44a65326eca3271889bda9c0fcc97be73816a5d59f127fd58810e5b99f7b6a23ea44ac872bcf8ffdf20471913241a5cf3ac7325a8e769498e9f84aeac3b24ea69775fbbb417f011712775feae2e1a6786740d2ff865cee56735248eb001457ae1c1e352c4c7a355632d4ec8f7020b4a689a34c7a1e7842cdc39bb8b05be759d9026585e4ed67751d9c150
#TRUST-RSA-SHA256 8ad349110d81c596325155e8f5dee1189fbe6d8f8c66dfc8334794cc9370f7ac26a7fbbbaf6ad6e4df6c69d5bd2f812a4260ac7931cda409464b04268693a3a3d2319ec21a140d111c566b483f9ef666cd0eb90632d4e255d5e8889c91cad0ce2e94b7663644991a1b7ccd2deb5a706079a76ba9bd1e60b7cbef62009fbc9c1b3512a80590ad8127ecd7a6f1120a1e0b1eb8c3ad0ff116ed8eab5ee92154513fc1ca8d32d0cd5e66892f126857dd641203df6c832f04ce133ef768299cb150a4905284b6e8caceb0244c3f6e5ffc9c171f4603d13c4ada0be8e6006d64a774949e3a66da5896d397ca8364860b804234ee843be3f48d6f1996bb253e899315a41a5603017ea0548a00ddcc77a7067b17840fd0010174fdd325a5607a1eabd1be8c2e29bb7920702c7602a5ce520cd60c08a2000cf36e1123af7839b2982062a74be4707a36109870f937e17edc5f1a6f4c383ee4cf9c8c5e1e6e86e58391197e210dd8896d7e15a9ac0adc960377fef4c79262de21101d513695112a03d41b713bd1a057d75781a024c390a26b311d013870ca1c776b0cba42ad50835deac213b2a496179b1c5bdd70d66b87f8e8f58cf58c9a7a57bfab97808744fdf511ed27689326dfefa89188634a1ef2d5efe9a47dd4be534a8b4d1934d5ffe813df4ed13476b4ceeb958c18e5c0499a204e4d3cece1925f8ebdf2214bce86dc864c675c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(69948);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2012-0329");
  script_bugtraq_id(51537);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts63878");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120118-dmm");
  script_xref(name:"IAVB", value:"2012-B-0010-S");

  script_name(english:"Cisco Digital Media Manager < 5.3 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote device is running a version of Cisco Digital Media Manager
prior to 5.3.  As such, it is affected by a privilege escalation
vulnerability.  A remote, authenticated attacker could leverage this to
execute arbitrary code on the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120118-dmm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfa1bf96");
  script_set_attribute(attribute:"see_also", value:"https://securitytracker.com/id/1026541");
  script_set_attribute(attribute:"solution", value:
"Update to Cisco Digital Media Manager version 5.3 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:digital_media_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SNMP");

  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");

  script_dependencies("snmp_sysDesc.nasl");
  script_require_keys("SNMP/community");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");

community = get_kb_item_or_exit("SNMP/community");

port = get_kb_item("SNMP/port");
if (!port) port = 161;
if (!get_udp_port_state(port))  audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (isnull(soc)) audit(AUDIT_SOCK_FAIL, port, "UDP");

major = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.9.9.655.1.1.1");
minor = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.9.9.655.1.1.2");
patch = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.9.9.655.1.1.3");

if (isnull(major)) audit(AUDIT_NOT_DETECT, "Cisco Digital Media Manager");
if (isnull(minor)) minor = "0";
if (isnull(patch)) patch = "0";

version = major + "." + minor + "." + patch;
fixed = "5.3";

if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}

audit(AUDIT_INST_VER_NOT_VULN, "Cisco Digital Media Manager", version);
