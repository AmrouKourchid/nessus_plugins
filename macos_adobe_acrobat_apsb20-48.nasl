#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139578);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2020-9693",
    "CVE-2020-9694",
    "CVE-2020-9695",
    "CVE-2020-9696",
    "CVE-2020-9697",
    "CVE-2020-9698",
    "CVE-2020-9699",
    "CVE-2020-9700",
    "CVE-2020-9701",
    "CVE-2020-9702",
    "CVE-2020-9703",
    "CVE-2020-9704",
    "CVE-2020-9705",
    "CVE-2020-9706",
    "CVE-2020-9707",
    "CVE-2020-9710",
    "CVE-2020-9711",
    "CVE-2020-9712",
    "CVE-2020-9713",
    "CVE-2020-9714",
    "CVE-2020-9715",
    "CVE-2020-9716",
    "CVE-2020-9717",
    "CVE-2020-9718",
    "CVE-2020-9719",
    "CVE-2020-9720",
    "CVE-2020-9721",
    "CVE-2020-9722",
    "CVE-2020-9723"
  );
  script_xref(name:"IAVA", value:"2020-A-0363-S");

  script_name(english:"Adobe Acrobat < 2015.006.30527 / 2017.011.30175 / 2020.001.30005 / 2020.012.20041 Multiple Vulnerabilities (APSB20-48) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior to 2015.006.30527, 2017.011.30175,
2020.001.30005, or 2020.012.20041. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions 2020.009.20074 and earlier, 2020.001.30002, 2017.011.30171 and earlier,
    and 2015.006.30523 and earlier have an use-after-free vulnerability. Successful exploitation could lead to
    arbitrary code execution . (CVE-2020-9715, CVE-2020-9722)

  - Adobe Acrobat and Reader versions 2020.009.20074 and earlier, 2020.001.30002, 2017.011.30171 and earlier,
    and 2015.006.30523 and earlier have a disclosure of sensitive data vulnerability. Successful exploitation
    could lead to memory leak. (CVE-2020-9697)

  - Adobe Acrobat and Reader versions 2020.009.20074 and earlier, 2020.001.30002, 2017.011.30171 and earlier,
    and 2015.006.30523 and earlier have a security bypass vulnerability. Successful exploitation could lead to
    privilege escalation . (CVE-2020-9714)

  - Adobe Acrobat and Reader versions 2020.009.20074 and earlier, 2020.001.30002, 2017.011.30171 and earlier,
    and 2015.006.30523 and earlier have an out-of-bounds write vulnerability. Successful exploitation could
    lead to arbitrary code execution . (CVE-2020-9693, CVE-2020-9694)

  - Adobe Acrobat and Reader versions 2020.009.20074 and earlier, 2020.001.30002, 2017.011.30171 and earlier,
    and 2015.006.30523 and earlier have a security bypass vulnerability. Successful exploitation could lead to
    security feature bypass. (CVE-2020-9696, CVE-2020-9712)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-48.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2015.006.30527 / 2017.011.30175 / 2020.001.30005 / 2020.012.20041 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9722");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_acrobat_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Adobe Acrobat');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '15.6', 'max_version' : '15.006.30523', 'fixed_version' : '15.006.30527', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30171', 'fixed_version' : '17.011.30175', 'track' : 'DC Classic' },
  { 'fixed_version' : '20.001.30005', 'equal' : '20.001.30002', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '20.009.20074', 'fixed_version' : '20.012.20041', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
