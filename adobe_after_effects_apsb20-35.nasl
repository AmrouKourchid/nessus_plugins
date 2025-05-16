#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137646);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2020-9637",
    "CVE-2020-9638",
    "CVE-2020-9660",
    "CVE-2020-9661",
    "CVE-2020-9662"
  );
  script_xref(name:"IAVA", value:"2020-A-0262-S");

  script_name(english:"Adobe After Effects < 17.1.1 Multiple Arbitrary Code Execution (APSB20-35)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe After Effects instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 17.1.1. It is, therefore, affected
by multiple vulnerabilities as referenced in the APSB20-35 advisory.

  - Adobe After Effects versions 17.1 and earlier have an out-of-bounds write vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2020-9660, CVE-2020-9662)

  - Adobe After Effects versions 17.1 and earlier have an out-of-bounds read vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2020-9661)

  - Adobe After Effects versions 17.1 and earlier have a heap overflow vulnerability. Successful exploitation
    could lead to arbitrary code execution . (CVE-2020-9637, CVE-2020-9638)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/after_effects/apsb20-35.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 17.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9662");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '17.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
