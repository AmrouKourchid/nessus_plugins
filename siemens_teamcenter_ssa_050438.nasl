#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232735);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2025-23396", 
    "CVE-2025-23397", 
    "CVE-2025-23398", 
    "CVE-2025-23399", 
    "CVE-2025-23400", 
    "CVE-2025-23401", 
    "CVE-2025-23402", 
    "CVE-2025-27438" 
    );
  script_xref(name:"IAVA", value:"2025-A-0168");

  script_name(english:"Siemens Teamcenter Multiple Vulnerabilities (SSA-050438)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Siemens Teamcenter installed on the remote host is prior to 14.3.0.13, 
2000.x prior to 2312.0009, 2400.x prior to 2406.0007, or 2412.x prior to 2412.0002. It is, therefore, 
affected by multiple vulnerabilities:

  - The affected application is vulnerable to memory corruption while parsing specially 
    crafted WRL files. This could allow an attacker to execute code in the context of 
    the current process. (CVE-2025-23400)

  - The affected applications contain an out of bounds read past the end of an allocated 
    structure while parsing specially crafted WRL files. This could allow an attacker to 
    execute code in the context of the current process. (CVE-2025-23401)

  - The affected applications contain a use-after-free vulnerability that could be triggered 
    while parsing specially crafted WRL files. An attacker could leverage this vulnerability 
    to execute code in the context of the current process. (CVE-2025-23402)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://cert-portal.siemens.com/productcert/html/ssa-050438.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cba4f45e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Siemens Teamcenter version 14.3.0.13, 2312.0009, 2406.0007, 2412.0002, or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23396");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:seimens:teamccenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_teamcenter_installed.nbin");
  script_require_keys("installed_sw/Siemens Teamcenter");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Siemens Teamcenter');

var constraints = [
  { 'min_version': '14.0', 'fixed_version' : '14.3.0.13' },
  { 'min_version': '2300.0', 'fixed_version' : '2312.0009' },
  { 'min_version': '2400.0', 'fixed_version' : '2406.0007' },
  { 'min_version': '2412.0', 'fixed_version' : '2412.0002' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
