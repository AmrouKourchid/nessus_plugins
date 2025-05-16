#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124008);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2019-7061",
    "CVE-2019-7088",
    "CVE-2019-7109",
    "CVE-2019-7110",
    "CVE-2019-7111",
    "CVE-2019-7112",
    "CVE-2019-7113",
    "CVE-2019-7114",
    "CVE-2019-7115",
    "CVE-2019-7116",
    "CVE-2019-7117",
    "CVE-2019-7118",
    "CVE-2019-7119",
    "CVE-2019-7120",
    "CVE-2019-7121",
    "CVE-2019-7122",
    "CVE-2019-7123",
    "CVE-2019-7124",
    "CVE-2019-7125",
    "CVE-2019-7127",
    "CVE-2019-7128"
  );
  script_bugtraq_id(
    107805,
    107809,
    107811,
    107812,
    107815
  );

  script_name(english:"Adobe Reader < 2015.006.30493 / 2017.011.30138 / 2019.010.20099 Multiple Vulnerabilities (APSB19-17)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior to 2015.006.30493, 2017.011.30138,
or 2019.010.20099. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions 2019.010.20098 and earlier, 2019.010.20098 and earlier, 2017.011.30127
    and earlier version, and 2015.006.30482 and earlier have a type confusion vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2019-7117, CVE-2019-7128)

  - Adobe Acrobat and Reader versions 2019.010.20098 and earlier, 2019.010.20098 and earlier, 2017.011.30127
    and earlier version, and 2015.006.30482 and earlier have an out-of-bounds read vulnerability. Successful
    exploitation could lead to information disclosure . (CVE-2019-7061, CVE-2019-7109, CVE-2019-7110,
    CVE-2019-7114, CVE-2019-7115, CVE-2019-7116, CVE-2019-7121, CVE-2019-7122, CVE-2019-7123, CVE-2019-7127)

  - Adobe Acrobat and Reader versions 2019.010.20098 and earlier, 2019.010.20098 and earlier, 2017.011.30127
    and earlier version, and 2015.006.30482 and earlier have an out-of-bounds write vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2019-7111, CVE-2019-7118, CVE-2019-7119,
    CVE-2019-7120, CVE-2019-7124)

  - Adobe Acrobat and Reader versions 2019.010.20098 and earlier, 2019.010.20098 and earlier, 2017.011.30127
    and earlier version, and 2015.006.30482 and earlier have an use after free vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2019-7088, CVE-2019-7112)

  - Adobe Acrobat and Reader versions 2019.010.20098 and earlier, 2019.010.20098 and earlier, 2017.011.30127
    and earlier version, and 2015.006.30482 and earlier have a heap overflow vulnerability. Successful
    exploitation could lead to arbitrary code execution . (CVE-2019-7113, CVE-2019-7125)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-17.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2015.006.30493 / 2017.011.30138 / 2019.010.20099 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7128");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe Reader', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '15.6', 'max_version' : '15.006.30482', 'fixed_version' : '15.006.30493', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30127', 'fixed_version' : '17.011.30138', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '19.010.20098', 'fixed_version' : '19.010.20099', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
