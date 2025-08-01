#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(127903);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2019-7965",
    "CVE-2019-8002",
    "CVE-2019-8003",
    "CVE-2019-8004",
    "CVE-2019-8005",
    "CVE-2019-8006",
    "CVE-2019-8007",
    "CVE-2019-8008",
    "CVE-2019-8009",
    "CVE-2019-8010",
    "CVE-2019-8011",
    "CVE-2019-8012",
    "CVE-2019-8013",
    "CVE-2019-8014",
    "CVE-2019-8015",
    "CVE-2019-8016",
    "CVE-2019-8017",
    "CVE-2019-8018",
    "CVE-2019-8019",
    "CVE-2019-8020",
    "CVE-2019-8021",
    "CVE-2019-8022",
    "CVE-2019-8023",
    "CVE-2019-8024",
    "CVE-2019-8025",
    "CVE-2019-8026",
    "CVE-2019-8027",
    "CVE-2019-8028",
    "CVE-2019-8029",
    "CVE-2019-8030",
    "CVE-2019-8031",
    "CVE-2019-8032",
    "CVE-2019-8033",
    "CVE-2019-8034",
    "CVE-2019-8035",
    "CVE-2019-8036",
    "CVE-2019-8037",
    "CVE-2019-8038",
    "CVE-2019-8039",
    "CVE-2019-8040",
    "CVE-2019-8041",
    "CVE-2019-8042",
    "CVE-2019-8043",
    "CVE-2019-8044",
    "CVE-2019-8045",
    "CVE-2019-8046",
    "CVE-2019-8047",
    "CVE-2019-8048",
    "CVE-2019-8049",
    "CVE-2019-8050",
    "CVE-2019-8051",
    "CVE-2019-8052",
    "CVE-2019-8053",
    "CVE-2019-8054",
    "CVE-2019-8055",
    "CVE-2019-8056",
    "CVE-2019-8057",
    "CVE-2019-8058",
    "CVE-2019-8059",
    "CVE-2019-8060",
    "CVE-2019-8061",
    "CVE-2019-8066",
    "CVE-2019-8077",
    "CVE-2019-8094",
    "CVE-2019-8095",
    "CVE-2019-8096",
    "CVE-2019-8097",
    "CVE-2019-8098",
    "CVE-2019-8099",
    "CVE-2019-8100",
    "CVE-2019-8101",
    "CVE-2019-8102",
    "CVE-2019-8103",
    "CVE-2019-8104",
    "CVE-2019-8105",
    "CVE-2019-8106",
    "CVE-2019-8237",
    "CVE-2019-8249",
    "CVE-2019-8250",
    "CVE-2019-8251",
    "CVE-2019-8252",
    "CVE-2019-8257"
  );
  script_bugtraq_id(108320);
  script_xref(name:"IAVA", value:"2020-A-0211-S");

  script_name(english:"Adobe Acrobat < 2015.006.30499 / 2017.011.30144 / 2019.012.20036 Multiple Vulnerabilities (APSB19-41)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a version prior to 2015.006.30499, 2017.011.30144,
or 2019.012.20036. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions 2019.012.20035 and earlier, 2019.012.20035 and earlier, 2017.011.30142
    and earlier, 2017.011.30143 and earlier, 2015.006.30497 and earlier, and 2015.006.30498 and earlier have
    an insufficiently robust encryption vulnerability. Successful exploitation could lead to security feature
    bypass. (CVE-2019-8237)

  - Adobe Acrobat and Reader versions 2019.012.20035 and earlier, 2019.012.20035 and earlier, 2017.011.30142
    and earlier, 2017.011.30143 and earlier, 2015.006.30497 and earlier, and 2015.006.30498 and earlier have
    an use after free vulnerability. Successful exploitation could lead to arbitrary code execution .
    (CVE-2019-8003, CVE-2019-8013, CVE-2019-8024, CVE-2019-8025, CVE-2019-8026, CVE-2019-8028, CVE-2019-8029,
    CVE-2019-8030, CVE-2019-8031, CVE-2019-8033, CVE-2019-8034, CVE-2019-8036, CVE-2019-8038, CVE-2019-8039,
    CVE-2019-8047, CVE-2019-8051, CVE-2019-8053, CVE-2019-8054, CVE-2019-8055, CVE-2019-8056, CVE-2019-8057,
    CVE-2019-8058, CVE-2019-8059, CVE-2019-8061, CVE-2019-8257)

  - Adobe Acrobat and Reader versions 2019.012.20035 and earlier, 2019.012.20035 and earlier, 2017.011.30142
    and earlier, 2017.011.30143 and earlier, 2015.006.30497 and earlier, and 2015.006.30498 and earlier have
    an out-of-bounds read vulnerability. Successful exploitation could lead to information disclosure .
    (CVE-2019-8002, CVE-2019-8004, CVE-2019-8005, CVE-2019-8007, CVE-2019-8010, CVE-2019-8011, CVE-2019-8012,
    CVE-2019-8018, CVE-2019-8020, CVE-2019-8021, CVE-2019-8032, CVE-2019-8035, CVE-2019-8037, CVE-2019-8040,
    CVE-2019-8043, CVE-2019-8052, CVE-2019-8077, CVE-2019-8094, CVE-2019-8095, CVE-2019-8096, CVE-2019-8102,
    CVE-2019-8103, CVE-2019-8104, CVE-2019-8105, CVE-2019-8106)

  - Adobe Acrobat and Reader versions 2019.012.20035 and earlier, 2019.012.20035 and earlier, 2017.011.30142
    and earlier, 2017.011.30143 and earlier, 2015.006.30497 and earlier, and 2015.006.30498 and earlier have
    an out-of-bounds write vulnerability. Successful exploitation could lead to arbitrary code execution .
    (CVE-2019-7965, CVE-2019-8008, CVE-2019-8009, CVE-2019-8016, CVE-2019-8022, CVE-2019-8023, CVE-2019-8027,
    CVE-2019-8098, CVE-2019-8100)

  - Adobe Acrobat and Reader versions 2019.012.20035 and earlier, 2019.012.20035 and earlier, 2017.011.30142
    and earlier, 2017.011.30143 and earlier, 2015.006.30497 and earlier, and 2015.006.30498 and earlier have a
    command injection vulnerability. Successful exploitation could lead to arbitrary code execution .
    (CVE-2019-8060)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-41.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2015.006.30499 / 2017.011.30144 / 2019.012.20036 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8237");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-8257");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe Acrobat', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '15.6', 'max_version' : '15.006.30498', 'fixed_version' : '15.006.30499', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30143', 'fixed_version' : '17.011.30144', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '19.012.20035', 'fixed_version' : '19.012.20036', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
