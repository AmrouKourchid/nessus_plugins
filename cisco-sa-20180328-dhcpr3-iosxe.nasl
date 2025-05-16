#TRUSTED af2b8829e51596f7c2c9acad09f6ff0d6fb82cbfc76ea85b259318735e0a48e6fd098e028d6dbdb84a2eded65ebfeb80942dfb5a2d65eebd6d40ae91ee943785259e51bb1d214242958fd3958a9239f71ab1e044e8feb79f792c1b5f384cd82247701de9e8121c20e66911034833a5170a7fe57aa01c96540fec1bceb63effae620cb7ba5bf2ed9fce31d527aa0137b6b71608d78ccf557cb26bf6f9cdadcfdbca8edc941afc09afa1911c6d1b7ef19f4daa7322ff0d5b7c412f142a42826c1e55e1f8228e7a59d5712d34a93c3e73f3c7c5b0218d0b7b8134919c6ef6e1e45cac7576b28b5342b96e4c846ece72020611efea5215c58382264475cab955d6185bf3b0ca73e88bc5092ebdbdf54c9604f7f751bccf7d71881d0272e39a0ca47a6b2048fc19482473be253a290c452c4e6576e1544194f0fe2aeb78bcca524827191aa4a0cfd13e2c8b10b7ac3634d13a2071367521942e87af4d21bf588921ce7f633b82c4524720b14ffa82de86bacdf1c3942d99a01546125204723fc7b361d411062278cedbb2f934e64b08d7c40fff9f2d5177c39df407d36f575dac0ed7fc23d0038322c55f93cf58b6923d55d0713ee783aa7b2e6301bd65227e73d05da120eb60464fb79735b41e397a46ec4835d2bfabafbcac4b92a1edb7b774063fb32881ad44cb240c14507f42cfbe42de8fb8cae453706572e84b7bdd0e7f026e
#TRUST-RSA-SHA256 762c80fc9c47655900f6a2a2ef2a7256d698603483fc3c853bbf7e78b4318d089983977c8e5f208bf273649b2b0f2c288ccd45d164b32beefbb30411345ca54ce1c90b249c6e3fed0cabf3543bb4557b237b0ae0b94927d906aeafe724184c8cd628228274c5268014dbfd661b8d2b4bd757850b965e4c104628f51c58df19ac9bc781a87b7138d3f5c7ed0512d856c2b21ce4699090e09c60220d27de0e6e32a37d7d5f801eb99051653bc69e839392e76164f113c35268f1e7bd13ffd2a8d789d1deede0e94fcfe59b57f60718b59de49598048e4711da99bc514b4fa456029a4552016bcc437d36fa4e59a3526f749723c9b59e346e0dbaf3f9e008d97d5c5dadf7a61d067fc991822dc7c30733dd2336f87ee4fb5a624bd6aefb93b347a15ffc661fac99135eff54010ad663178fc4e7c9a9cc8d63eb90e19217ed5552736e3b6b3e2222e384ae5a6a3aa2335d323ea24774f6e501fad5efd5989f33a5bf856b9969d060636296472b87731d6c8aba68bfb3c30370257b43d04b042cc72c91750efb22e386e79340b71b903373dd1df9100112e77c6727dbe6a2cfb75706a7921f65c25cd40983a0059764a0ba7e1f0e11f5b95446e3e4a231bae7fe77007ac3e790525b423245009e3092ad3a0653e1a5c70e02898cae25cf5bd71fd9e40e6d54d99b648f09e8b4b9c84b26558e47547ff6cb67f6402f198e2a6aeb63c2
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109088);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0172", "CVE-2018-0173", "CVE-2018-0174");
  script_bugtraq_id(103545, 103552, 103554);
  script_xref(name:"TRA", value:"TRA-2018-06");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg62730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg62754");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh91645");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dhcpr1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dhcpr2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dhcpr3");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS DHCP Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by multiple denial of service
vulnerabilities in the DHCP client implementation when parsing DHCP
packets. An unauthenticated, remote attacker can exploit these issues,
via specially crafted DHCP packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dhcpr1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfe8b7e0");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dhcpr2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2af6e16d");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dhcpr3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?570bb167");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg62730");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg62754");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuh91645");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg62730, CSCvg62754, and CSCuh91645.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0174");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
port = get_kb_item("Host/Cisco/IOS-XE/Port");
if (empty_or_null(port))
  port = 0;

flag = 0;

if (
  ver == "3.2.0JA" ||
  ver == "3.2.0SE" ||
  ver == "3.2.0SG" ||
  ver == "3.2.1SE" ||
  ver == "3.2.1SG" ||
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
  ver == "3.2.10SG" ||
  ver == "3.2.11SG" ||
  ver == "3.3.0SE" ||
  ver == "3.3.0SG" ||
  ver == "3.3.0SQ" ||
  ver == "3.3.0XO" ||
  ver == "3.3.1SE" ||
  ver == "3.3.1SG" ||
  ver == "3.3.1SQ" ||
  ver == "3.3.1XO" ||
  ver == "3.3.2SE" ||
  ver == "3.3.2SG" ||
  ver == "3.3.2XO" ||
  ver == "3.3.3SE" ||
  ver == "3.3.4SE" ||
  ver == "3.3.5SE" ||
  ver == "3.4.0SG" ||
  ver == "3.4.0SQ" ||
  ver == "3.4.1SG" ||
  ver == "3.4.1SQ" ||
  ver == "3.4.2SG" ||
  ver == "3.4.3SG" ||
  ver == "3.4.4SG" ||
  ver == "3.4.5SG" ||
  ver == "3.4.6SG" ||
  ver == "3.4.7SG" ||
  ver == "3.4.8SG" ||
  ver == "3.5.0E" ||
  ver == "3.5.0SQ" ||
  ver == "3.5.1E" ||
  ver == "3.5.1SQ" ||
  ver == "3.5.2E" ||
  ver == "3.5.2SQ" ||
  ver == "3.5.3E" ||
  ver == "3.5.3SQ" ||
  ver == "3.5.4SQ" ||
  ver == "3.5.5SQ" ||
  ver == "3.5.6SQ" ||
  ver == "3.5.7SQ" ||
  ver == "3.5.8SQ" ||
  ver == "3.6.0E" ||
  ver == "3.6.0aE" ||
  ver == "3.6.0bE" ||
  ver == "3.6.1E" ||
  ver == "3.6.2E" ||
  ver == "3.6.2aE" ||
  ver == "3.6.3E" ||
  ver == "3.6.4E" ||
  ver == "3.6.5E" ||
  ver == "3.6.5aE" ||
  ver == "3.6.5bE" ||
  ver == "3.6.6E" ||
  ver == "3.6.7E" ||
  ver == "3.6.7aE" ||
  ver == "3.6.7bE" ||
  ver == "3.6.8E" ||
  ver == "3.7.0E" ||
  ver == "3.7.0S" ||
  ver == "3.7.0bS" ||
  ver == "3.7.1E" ||
  ver == "3.7.1S" ||
  ver == "3.7.1aS" ||
  ver == "3.7.2E" ||
  ver == "3.7.2S" ||
  ver == "3.7.2tS" ||
  ver == "3.7.3E" ||
  ver == "3.7.3S" ||
  ver == "3.7.4E" ||
  ver == "3.7.4S" ||
  ver == "3.7.4aS" ||
  ver == "3.7.5E" ||
  ver == "3.7.5S" ||
  ver == "3.7.6S" ||
  ver == "3.7.7S" ||
  ver == "3.7.8S" ||
  ver == "3.8.0E" ||
  ver == "3.8.0S" ||
  ver == "3.8.1E" ||
  ver == "3.8.1S" ||
  ver == "3.8.2E" ||
  ver == "3.8.2S" ||
  ver == "3.8.3E" ||
  ver == "3.8.4E" ||
  ver == "3.8.5E" ||
  ver == "3.8.5aE" ||
  ver == "3.9.0E" ||
  ver == "3.9.0S" ||
  ver == "3.9.0aS" ||
  ver == "3.9.1E" ||
  ver == "3.9.1S" ||
  ver == "3.9.1aS" ||
  ver == "3.9.2E" ||
  ver == "3.9.2S" ||
  ver == "3.9.2bE" ||
  ver == "3.10.0E" ||
  ver == "3.10.0S" ||
  ver == "3.10.0cE" ||
  ver == "3.10.1S" ||
  ver == "3.10.2S" ||
  ver == "3.10.2aS" ||
  ver == "3.10.2tS" ||
  ver == "3.10.3S" ||
  ver == "3.10.4S" ||
  ver == "3.10.5S" ||
  ver == "3.10.6S" ||
  ver == "3.10.7S" ||
  ver == "3.10.8S" ||
  ver == "3.10.8aS" ||
  ver == "3.10.9S" ||
  ver == "3.10.10S" ||
  ver == "3.11.0S" ||
  ver == "3.11.1S" ||
  ver == "3.11.2S" ||
  ver == "3.11.3S" ||
  ver == "3.11.4S" ||
  ver == "3.12.0S" ||
  ver == "3.12.0aS" ||
  ver == "3.12.1S" ||
  ver == "3.12.2S" ||
  ver == "3.12.3S" ||
  ver == "3.12.4S" ||
  ver == "3.13.0S" ||
  ver == "3.13.0aS" ||
  ver == "3.13.1S" ||
  ver == "3.13.2S" ||
  ver == "3.13.2aS" ||
  ver == "3.13.3S" ||
  ver == "3.13.4S" ||
  ver == "3.13.5S" ||
  ver == "3.13.5aS" ||
  ver == "3.13.6S" ||
  ver == "3.13.6aS" ||
  ver == "3.13.6bS" ||
  ver == "3.13.7S" ||
  ver == "3.13.7aS" ||
  ver == "3.13.8S" ||
  ver == "3.14.0S" ||
  ver == "3.14.1S" ||
  ver == "3.14.2S" ||
  ver == "3.14.3S" ||
  ver == "3.14.4S" ||
  ver == "3.15.0S" ||
  ver == "3.15.1S" ||
  ver == "3.15.1cS" ||
  ver == "3.15.2S" ||
  ver == "3.15.3S" ||
  ver == "3.15.4S" ||
  ver == "3.16.0S" ||
  ver == "3.16.0aS" ||
  ver == "3.16.0bS" ||
  ver == "3.16.0cS" ||
  ver == "3.16.1S" ||
  ver == "3.16.1aS" ||
  ver == "3.16.2S" ||
  ver == "3.16.2aS" ||
  ver == "3.16.2bS" ||
  ver == "3.16.3S" ||
  ver == "3.16.3aS" ||
  ver == "3.16.4S" ||
  ver == "3.16.4aS" ||
  ver == "3.16.4bS" ||
  ver == "3.16.4cS" ||
  ver == "3.16.4dS" ||
  ver == "3.16.4eS" ||
  ver == "3.16.4gS" ||
  ver == "3.16.5S" ||
  ver == "3.16.5aS" ||
  ver == "3.16.5bS" ||
  ver == "3.16.6S" ||
  ver == "3.16.6bS" ||
  ver == "3.17.0S" ||
  ver == "3.17.1S" ||
  ver == "3.17.1aS" ||
  ver == "3.17.2S " ||
  ver == "3.17.3S" ||
  ver == "3.17.4S" ||
  ver == "3.18.0S" ||
  ver == "3.18.0SP" ||
  ver == "3.18.0aS" ||
  ver == "3.18.1S" ||
  ver == "3.18.1SP" ||
  ver == "3.18.1aSP" ||
  ver == "3.18.1bSP" ||
  ver == "3.18.1cSP" ||
  ver == "3.18.1gSP" ||
  ver == "3.18.1hSP" ||
  ver == "3.18.1iSP" ||
  ver == "3.18.2S" ||
  ver == "3.18.2SP" ||
  ver == "3.18.2aSP" ||
  ver == "3.18.3S" ||
  ver == "3.18.3SP" ||
  ver == "3.18.3aSP" ||
  ver == "3.18.3bSP" ||
  ver == "3.18.4S" ||
  ver == "16.1.1" ||
  ver == "16.1.2" ||
  ver == "16.1.3" ||
  ver == "16.2.1" ||
  ver == "16.2.2" ||
  ver == "16.3.1" ||
  ver == "16.3.1a" ||
  ver == "16.3.2" ||
  ver == "16.3.3" ||
  ver == "16.3.4" ||
  ver == "16.3.5" ||
  ver == "16.3.5b" ||
  ver == "16.4.1" ||
  ver == "16.4.2" ||
  ver == "16.4.3" ||
  ver == "16.5.1" ||
  ver == "16.5.1a" ||
  ver == "16.5.1b" ||
  ver == "16.5.2" ||
  ver == "16.6.1" ||
  ver == "16.6.2" ||
  ver == "16.6.6" ||
  ver == "16.7.1" ||
  ver == "16.7.1a" ||
  ver == "16.7.1b" ||
  ver == "16.7.3" ||
  ver == "16.9.1b" ||
  ver == "16.9.1c" ||
  ver == "16.9.1d" ||
  ver == "16.12.1"
)
{
  flag++;
}

cmds = make_list();
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include ip helper-address", "show running-config | include ip helper-address");
  if (check_cisco_result(buf))
  {
    if (preg(string:buf, pattern:"ip helper-address", multiline:TRUE))
    {
      cmds = make_list(cmds, "show running-config | include ip helper-address");
      buf2 =  cisco_command_kb_item("Host/Cisco/Config/show running-config | include ip dhcp relay information option", "show running-config | include ip dhcp relay information option");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"ip dhcp relay information option", string:buf2))
        {
          cmds = make_list(cmds,"show running-config | include ip dhcp relay information option");
          flag = 1;
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : port,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCvg62730, CSCvg62754, CSCuh91645",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
