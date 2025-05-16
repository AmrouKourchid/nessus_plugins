#TRUSTED 0b11479b3a3045580b61e76e3963094a788af29792b57aa1b1f87e3d215ab08ee224fd751a3e61fc3238d7e65b3c7e99f8ba0f0ba7aab34636b24aba32bff0d19adf1753aaaeda6cdb7448bd8f142f12f9c90c0c2d52788f874fdd351e9a2eb47406cb1dce853673c1f3288e47e0174eec1ac5e8bcf43c13102b22c823f61a999ae339df2303f514483f98de7074c58f9378c1917ccc2b04b6a6b0bdaf7eee7c2c0a0989199e8c1339fbaf168486ced6e6cc98009b7fb5edcc353d876875caf30a7dea33cfc6b7958f40c5f16e53d903daf951c77279e7d42ec0f29d274f8cdf6293ab4e274500bf3e222965f4b6139a38ecfc50986f159fefbe27ed38bb903c11960353adbc79a594f0d753147c30fc5c03f5b2278a3f56122ffd9579907fb9bba574046cefa2b4f3b2c2a3260d8a905bf455614a503a895074daca70eee899acfcbf42ddf724b7d9e7d02106a0ba2a6e1415262a963f29ec722f3596f031b4fa3013bd2d6e581fc997ab31a9696900d263083cdf1bb4b9b37f9151f8e4deec049511514d1504a4ba402b0ea05348b83c321c54d7f01d20251b0bda505432fe9f27d628bc71740e59390b140debee1240c48e5bfc8f9ef33d1091f0a16890ec2bdfcca2d2026ac42f4fd4f75618bcb77e985f72b92c50cd3ce24ecde02388bb60b47b0513f991bb2e409681c3bf604abf0e13ee4fd61c3f69c4ec74684a9719
#TRUST-RSA-SHA256 4189ab3b19c823f4658654158b4175ab7c65c4dd9e26a689431ea278d1b657fb589a3610618aae8f9e8e603842f9bb8ebaa7954b460e0a3b6a204277094046cbf71fa871bb04130360be9252c16ee8c71b0212b5db6be20b40ba9234bf268daf6b74fa0b01122bbc9a248aece919396afb33bf2938b876df9bf69cf2a761bdc42c4e45e0c39c54a3b8167149ef3b1f673b814f78c202b791c6e9fdad85d7ecc7e1789cbb4a9f3f7add62d62b1518139603cb2148c7e83c62ff77962f79f25b2c81e043f1682a3b560c53fb63df24afda7596268fa23137e1c61f02424d31e93953b65be46750ef738b7dc3bcc8d994bae59c129536eff772066e0ad34784f0a83d4c4919622f406d309b0ce5a9daa0bc86bed33d4a98494e548c1ddd7e5a0f51af9f3de45c997ea0e67c23151625285427f55b0398ecd7ac3b13f29ac67fdd4493250260fcc76f914cd416257cc316ea409623589175876088ebff0e3666bcd48ef6277e36c7f2861cc7c8e9fae65df3e176a396f6e97b5ef164aa421cc332bd7fe25a0aedf41947c8caa94367911560ce6197edda8e2c9d2c07941ac861bd06e72751e9a86bcabd52f508c73e7f32d95a3f7ccbf982f63189702dc1bd93b5d45941b2730855d305132a5d20db9781754e1f0b5ac1e8bdb98583568477b0f03537318af2f0b9e864c3c978be00c5aa1547237758bf27a4c7b3723a1a8abc2fc4
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209660);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2024-20329");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe93558");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ssh-rce-gRAuPEUF");
  script_xref(name:"IAVA", value:"2024-A-0687");

  script_name(english:"Cisco Adaptive Security Appliance Software SSH Remote Command Injection Vulnerability (cisco-sa-asa-ssh-rce-gRAuPEUF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the SSH subsystem of Cisco Adaptive Security Appliance (ASA) Software could allow an 
authenticated, remote attacker to execute operating system commands as root.

This vulnerability is due to insufficient validation of user input. An attacker could exploit this vulnerability by 
submitting crafted input when executing remote CLI commands over SSH. A successful exploit could allow the attacker to 
execute commands on the underlying operating system with root-level privileges. An attacker with limited user 
privileges could use this vulnerability to gain complete control over the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ssh-rce-gRAuPEUF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dbc4626");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe93558");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.17', 'fix_ver': '9.17.1.39'},
  {'min_ver': '9.18', 'fix_ver': '9.18.4'},
  {'min_ver': '9.19', 'fix_ver': '9.19.1.22'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['ciscossh_stack_enabled']];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe93558'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
