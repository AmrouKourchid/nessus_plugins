#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129977);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2019-8064",
    "CVE-2019-8160",
    "CVE-2019-8161",
    "CVE-2019-8162",
    "CVE-2019-8163",
    "CVE-2019-8164",
    "CVE-2019-8165",
    "CVE-2019-8166",
    "CVE-2019-8167",
    "CVE-2019-8168",
    "CVE-2019-8169",
    "CVE-2019-8170",
    "CVE-2019-8171",
    "CVE-2019-8172",
    "CVE-2019-8173",
    "CVE-2019-8174",
    "CVE-2019-8175",
    "CVE-2019-8176",
    "CVE-2019-8177",
    "CVE-2019-8178",
    "CVE-2019-8179",
    "CVE-2019-8180",
    "CVE-2019-8181",
    "CVE-2019-8182",
    "CVE-2019-8183",
    "CVE-2019-8184",
    "CVE-2019-8185",
    "CVE-2019-8186",
    "CVE-2019-8187",
    "CVE-2019-8188",
    "CVE-2019-8189",
    "CVE-2019-8190",
    "CVE-2019-8191",
    "CVE-2019-8192",
    "CVE-2019-8193",
    "CVE-2019-8194",
    "CVE-2019-8195",
    "CVE-2019-8196",
    "CVE-2019-8197",
    "CVE-2019-8198",
    "CVE-2019-8199",
    "CVE-2019-8200",
    "CVE-2019-8201",
    "CVE-2019-8202",
    "CVE-2019-8203",
    "CVE-2019-8204",
    "CVE-2019-8205",
    "CVE-2019-8206",
    "CVE-2019-8207",
    "CVE-2019-8208",
    "CVE-2019-8209",
    "CVE-2019-8210",
    "CVE-2019-8211",
    "CVE-2019-8212",
    "CVE-2019-8213",
    "CVE-2019-8214",
    "CVE-2019-8215",
    "CVE-2019-8216",
    "CVE-2019-8217",
    "CVE-2019-8218",
    "CVE-2019-8219",
    "CVE-2019-8220",
    "CVE-2019-8221",
    "CVE-2019-8222",
    "CVE-2019-8223",
    "CVE-2019-8224",
    "CVE-2019-8225",
    "CVE-2019-8226"
  );

  script_name(english:"Adobe Acrobat < 2015.006.30504 / 2017.011.30150 / 2019.021.20047 Multiple Vulnerabilities (APSB19-49)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a version prior to 2015.006.30504, 2017.011.30150,
or 2019.021.20047. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions , 2019.012.20040 and earlier, 2017.011.30148 and earlier, 2017.011.30148
    and earlier, 2015.006.30503 and earlier, and 2015.006.30503 and earlier have an untrusted pointer
    dereference vulnerability. Successful exploitation could lead to arbitrary code execution .
    (CVE-2019-8174, CVE-2019-8195, CVE-2019-8196, CVE-2019-8205)

  - Adobe Acrobat and Reader versions , 2019.012.20040 and earlier, 2017.011.30148 and earlier, 2017.011.30148
    and earlier, 2015.006.30503 and earlier, and 2015.006.30503 and earlier have an use after free
    vulnerability. Successful exploitation could lead to arbitrary code execution . (CVE-2019-8175,
    CVE-2019-8176, CVE-2019-8177, CVE-2019-8178, CVE-2019-8179, CVE-2019-8180, CVE-2019-8181, CVE-2019-8187,
    CVE-2019-8188, CVE-2019-8192, CVE-2019-8203, CVE-2019-8208, CVE-2019-8209, CVE-2019-8210, CVE-2019-8211,
    CVE-2019-8212, CVE-2019-8213, CVE-2019-8214, CVE-2019-8215, CVE-2019-8217, CVE-2019-8219, CVE-2019-8221,
    CVE-2019-8223, CVE-2019-8224, CVE-2019-8225)

  - Adobe Acrobat and Reader versions , 2019.012.20040 and earlier, 2017.011.30148 and earlier, 2017.011.30148
    and earlier, 2015.006.30503 and earlier, and 2015.006.30503 and earlier have an out-of-bounds read
    vulnerability. Successful exploitation could lead to information disclosure . (CVE-2019-8064,
    CVE-2019-8163, CVE-2019-8164, CVE-2019-8168, CVE-2019-8172, CVE-2019-8173, CVE-2019-8182, CVE-2019-8184,
    CVE-2019-8185, CVE-2019-8189, CVE-2019-8190, CVE-2019-8193, CVE-2019-8194, CVE-2019-8198, CVE-2019-8201,
    CVE-2019-8202, CVE-2019-8204, CVE-2019-8207, CVE-2019-8216, CVE-2019-8218, CVE-2019-8222)

  - Adobe Acrobat and Reader versions , 2019.012.20040 and earlier, 2017.011.30148 and earlier, 2017.011.30148
    and earlier, 2015.006.30503 and earlier, and 2015.006.30503 and earlier have an out-of-bounds write
    vulnerability. Successful exploitation could lead to arbitrary code execution . (CVE-2019-8165,
    CVE-2019-8171, CVE-2019-8186, CVE-2019-8191, CVE-2019-8199, CVE-2019-8206)

  - Adobe Acrobat and Reader versions, 2019.012.20040 and earlier, 2017.011.30148 and earlier, 2017.011.30148
    and earlier, 2015.006.30503 and earlier, and 2015.006.30503 and earlier have an use after free
    vulnerability. Successful exploitation could lead to arbitrary code execution . (CVE-2019-8220)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-49.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2015.006.30504 / 2017.011.30150 / 2019.021.20047 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8196");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-8221");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'min_version' : '15.6', 'max_version' : '15.006.30503', 'fixed_version' : '15.006.30504', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30148', 'fixed_version' : '17.011.30150', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '19.012.20040', 'fixed_version' : '19.021.20047', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
