#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208732);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/14");

  script_cve_id("CVE-2024-41902");
  script_xref(name:"IAVA", value:"2024-A-0637");

  script_name(english:"Siemens JT2Go < 2406.0003 Buffer Overflow (SSA-626178)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Siemens JT2Go installed on the remote host is prior to 2406.0003. It is, therefore, affected by a 
stack-based buffer overflow vulnerability as referenced in the SSA-626178 advisory that could be triggered while 
parsing specially crafted PDF files. This could allow an attacker to execute code in the context of the current 
process.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/html/ssa-626178.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JT2Go 15.0.x with Copyright Version 2406.0003 or higher.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:siemens:jt2go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_jt2go_win_installed.nbin");
  script_require_keys("installed_sw/Siemens JT2Go");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Siemens JT2Go');

var constraints = [
  { 'fixed_version' : '2406.0003', 'fixed_display' : 'Upgrade to JT2Go 15.0.x with Copyright Version 2406.0003 or higher.'}
];

vcf::jt2go::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    use_copyright_ver:TRUE
);
