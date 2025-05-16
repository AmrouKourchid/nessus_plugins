#TRUSTED 5dc8a6937c0f8308147448e10b49078a7342381e7e59e3323f7d0dd522a0e44e562e01737d1afbd21f47056b5e84cae24986974d23db7432cfca4b11b18fc9b68287646cc5e74990ef82f5af14400b56a23622ca58ddcd9c71831a8bedcefe17462b417b88437be4b8051cceca50cd4c00307f815f12b6dea171f1bbc5d1d8d1f0b2e15db48c58411fdf666a31efa40064c20960827f30ebf8d223336d94ae33c2d15151265171c6744d6738533d40d65e77e0944b17adeef04c9d42bfd8309feedcc67751258c898309214dff8894a55e5c5fece9547a3bc8e14cc7dc552ac867aa5c4c1af22f15e4b2f87274db6a5abd9a51179548e81ca28071ec2fc7f3a74c5f3aa406722395872e42816693934ee2445dc6eb5cc349db9b7165fbd372e6acace3601c7cace386b97842aa51e04589672d447e3a419d0ffe95cca536e975d856ed17d14ac344e2874cfc064f7323ef7fb315e5b0aaaad431066f83759c84e66c53abe249d547958bfaf7ac9d3f0560c0fc289ef61e9c57376e7fce18537ef47c8c54496144b241687e98acf5f92f04a7c8116c1afd370d188e71ba65fc7e4740e66927446884ac24a3461362cd7b32fb616d276a91b0067daed83369069455bef45b662ccd421b60c75e3ab3ed4a146042225cfb9df70e426c20ac64d0f478f33500eb1bd6f77a1743a4707afd4e129148d27b79d0102555e911738a7df3
#TRUST-RSA-SHA256 0fff56ba4c8ad57324e620be3d6ee964464f7cf357d8fded1385141b00abe688666d9c1919be43f092a9ca0e6a314c0ff683d8fe9634bd0a1573696a0ab77918fbe2d7cfa4f83c4cb6fadf66a1b6aa9afd456c58dba8008f37d3b04819e2423c4ed1ba873d64eff9241f0c1f5f01a8d26a9566fa6f11f9a5b4c77ed146af9f81120de6e027ff3fbf7bb45ded9697cbec5698a3f3fcd923832affa28801c640fb2db9bc84e885f6005eafc8f8b2c05f26ba08ece13f9818cf4d56cc75d71cc5bc8b1335e054cd0c20ec8cd381dbd9720589ed748fe883f381e9287967ba3f7e92bafd5a730bb236a7750f3d526697af489bb65f27e780193149897dbade500a6b77844f4dc1020de1d8ce2454f07a02e62d44c61ff4d1c9f7f7b2dcf04639c405f70b1a5c1e26b07b278695a4b6eaed48a24fe97a75a31fb40c7591c21a8cc22deabd4c31178274620a90c3a0957ce20577173d8bed2a144c5afe13578241e1bc56e7f3f37baa1d974348341b9ce41224345397bbd317fa2d96d11f4053172e4d174c17d08c57ca10ef4dd4438a7d4efa51bfaae652d4ecae18ce2e1bb4c62d52c2e396fa275b789ed557208c90fa3b65ab4cc0e135876d0d9a2986bc1bc96163d3b0bee7bd95a24510c888125585a896056712093b2cd024574455389ab2db72fe4557a7db36586207528a1505425e0191a4d0c98c1072dcffd1d7f7fa3cd93b
#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(131283);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/12");

  script_cve_id("CVE-2018-9195");

  script_name(english:"Fortinet FortiOS < 5.6.12 / 6.x < 6.0.8 Information Disclosure MitM (FG-IR-18-100)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.6.12 or 6.x prior to 6.0.8. It is, therefore, affected by 
an information disclosure man-in-the-middle vulnerability in the FortiGuard services communication protocol due to the 
use of a hardcoded cryptographic key. A remote attacker with knowledge of the hardcoded key can exploit this via the 
network to eavesdrop and modify information sent and received from FortiGuard servers.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-100");
  # https://sec-consult.com/en/blog/advisories/weak-encryption-cipher-and-hardcoded-cryptographic-keys-in-fortinet-products/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca502f28");
  #https://docs.fortinet.com/document/fortigate/6.0.8/fortios-release-notes/901852/fortiguard-protocol-and-port-number
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db9c0891");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.12, 6.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin", "ssh_get_info.nasl");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");
  script_exclude_keys("Host/windows_local_checks");

  exit(0);
}

include('hostlevel_funcs.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

if (app_info.version !~ "^[0-6][\.\d]+")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, app_info.version);
  
constraints = [
  {'min_version': '0.0', 'fixed_version': '5.6.12' },
  {'min_version': '6.0', 'fixed_version': '6.0.8' }
];

report =
  '\n  One or both of the following FortiOS settings are not present in the config;\n'
  +'    - set protocol https\n'
  +'    - set port 8888\n'
  +'  Ensure Fortiguard protocol and port are set appropriately,\n'
  +'  as per vendor instructions at http://www.nessus.org/u?db9c0891\n'
  +'\n'
  +'  Tenable does not print the user entry here for security & privacy reasons.';


vuln_settings = [ # Not_equal flag below ensure it only triggers if it can't find any of these three.
  {config_command:'full-configuration system fortiguard', config_value:"port (?:8888|443|53)"},  # So if it's not port 8888, 443, or 53
  {config_command:'full-configuration system fortiguard', config_value:"protocol https"}         # Or it's not protocol https
];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, report:report, vuln_settings:vuln_settings, regex: TRUE, all_required:TRUE, not_equal:TRUE, show_check:'config');