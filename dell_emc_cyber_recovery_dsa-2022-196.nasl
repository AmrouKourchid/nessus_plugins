#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180054);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/29");

  script_cve_id("CVE-2022-34372");
  script_xref(name:"IAVA", value:"2022-A-0448-S");

  script_name(english:"Dell Cyber Recovery < 19.11.0.2 Authentication Bypass (DSA-2022-196)");

  script_set_attribute(attribute:"synopsis", value:
"Dell Cyber Recover is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"Dell PowerProtect Cyber Recovery versions before 19.11.0.2 contain an authentication bypass vulnerability. A remote,
unauthenticated attacker may potentially access and interact with the docker registry API leading to an authentication
bypass. The attacker may potentially alter the docker images leading to a loss of integrity and confidentiality

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000201970/dsa-2022-196-dell-cyber-recovery-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87399f67");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Cyber Recovery 19.11.0.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:powerprotect_cyber_recovery");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_cyber_recovery_nix_installed.nbin");
  script_require_keys("installed_sw/Dell Cyber Recovery");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell Cyber Recovery');

var constraints = [
  {'fixed_version' : '19.11.0.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
