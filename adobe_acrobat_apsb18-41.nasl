#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119675);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2018-12830",
    "CVE-2018-15984",
    "CVE-2018-15985",
    "CVE-2018-15986",
    "CVE-2018-15987",
    "CVE-2018-15988",
    "CVE-2018-15989",
    "CVE-2018-15990",
    "CVE-2018-15991",
    "CVE-2018-15992",
    "CVE-2018-15993",
    "CVE-2018-15994",
    "CVE-2018-15995",
    "CVE-2018-15996",
    "CVE-2018-15997",
    "CVE-2018-15998",
    "CVE-2018-15999",
    "CVE-2018-16000",
    "CVE-2018-16001",
    "CVE-2018-16002",
    "CVE-2018-16003",
    "CVE-2018-16004",
    "CVE-2018-16005",
    "CVE-2018-16006",
    "CVE-2018-16007",
    "CVE-2018-16008",
    "CVE-2018-16009",
    "CVE-2018-16010",
    "CVE-2018-16012",
    "CVE-2018-16013",
    "CVE-2018-16014",
    "CVE-2018-16015",
    "CVE-2018-16016",
    "CVE-2018-16017",
    "CVE-2018-16019",
    "CVE-2018-16020",
    "CVE-2018-16021",
    "CVE-2018-16022",
    "CVE-2018-16023",
    "CVE-2018-16024",
    "CVE-2018-16025",
    "CVE-2018-16026",
    "CVE-2018-16027",
    "CVE-2018-16028",
    "CVE-2018-16029",
    "CVE-2018-16030",
    "CVE-2018-16031",
    "CVE-2018-16032",
    "CVE-2018-16033",
    "CVE-2018-16034",
    "CVE-2018-16035",
    "CVE-2018-16036",
    "CVE-2018-16037",
    "CVE-2018-16038",
    "CVE-2018-16039",
    "CVE-2018-16040",
    "CVE-2018-16041",
    "CVE-2018-16042",
    "CVE-2018-16043",
    "CVE-2018-16044",
    "CVE-2018-16045",
    "CVE-2018-16046",
    "CVE-2018-16047",
    "CVE-2018-19698",
    "CVE-2018-19699",
    "CVE-2018-19700",
    "CVE-2018-19701",
    "CVE-2018-19702",
    "CVE-2018-19703",
    "CVE-2018-19704",
    "CVE-2018-19705",
    "CVE-2018-19706",
    "CVE-2018-19707",
    "CVE-2018-19708",
    "CVE-2018-19709",
    "CVE-2018-19710",
    "CVE-2018-19711",
    "CVE-2018-19712",
    "CVE-2018-19713",
    "CVE-2018-19714",
    "CVE-2018-19715",
    "CVE-2018-19716",
    "CVE-2018-19717",
    "CVE-2018-19719",
    "CVE-2018-19720",
    "CVE-2018-19728"
  );

  script_name(english:"Adobe Acrobat < 2015.006.30461 / 2017.011.30110 / 2019.010.20064 Multiple Vulnerabilities (APSB18-41)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a version prior to 2015.006.30461, 2017.011.30110,
or 2019.010.20064. It is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat and Reader versions 2019.008.20081 and earlier, 2019.008.20080 and earlier, 2019.008.20081
    and earlier, 2017.011.30106 and earlier version, 2017.011.30105 and earlier version, 2015.006.30457 and
    earlier, and 2015.006.30456 and earlier have a heap overflow vulnerability. Successful exploitation could
    lead to arbitrary code execution. (CVE-2018-12830, CVE-2018-16021, CVE-2018-19716)

  - Adobe Acrobat and Reader versions 2019.008.20081 and earlier, 2019.008.20080 and earlier, 2019.008.20081
    and earlier, 2017.011.30106 and earlier version, 2017.011.30105 and earlier version, 2015.006.30457 and
    earlier, and 2015.006.30456 and earlier have a use after free vulnerability. Successful exploitation could
    lead to arbitrary code execution. (CVE-2018-16008, CVE-2018-16014, CVE-2018-16025, CVE-2018-16026,
    CVE-2018-16027, CVE-2018-16029, CVE-2018-16036, CVE-2018-16037, CVE-2018-16039, CVE-2018-16040,
    CVE-2018-16046, CVE-2018-19698, CVE-2018-19700, CVE-2018-19707, CVE-2018-19708, CVE-2018-19713,
    CVE-2018-19715)

  - Adobe Acrobat and Reader versions 2019.008.20081 and earlier, 2019.008.20080 and earlier, 2019.008.20081
    and earlier, 2017.011.30106 and earlier version, 2017.011.30105 and earlier version, 2015.006.30457 and
    earlier, and 2015.006.30456 and earlier have a buffer errors vulnerability. Successful exploitation could
    lead to arbitrary code execution. (CVE-2018-15987, CVE-2018-15998)

  - Adobe Acrobat and Reader versions 2019.008.20081 and earlier, 2019.008.20080 and earlier, 2019.008.20081
    and earlier, 2017.011.30106 and earlier version, 2017.011.30105 and earlier version, 2015.006.30457 and
    earlier, and 2015.006.30456 and earlier have an untrusted pointer dereference vulnerability. Successful
    exploitation could lead to arbitrary code execution. (CVE-2018-16004, CVE-2018-19720)

  - Adobe Acrobat and Reader versions 2019.008.20081 and earlier, 2019.008.20080 and earlier, 2019.008.20081
    and earlier, 2017.011.30106 and earlier version, 2017.011.30105 and earlier version, 2015.006.30457 and
    earlier, and 2015.006.30456 and earlier have a security bypass vulnerability. Successful exploitation
    could lead to privilege escalation. (CVE-2018-16044, CVE-2018-16045)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-41.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2015.006.30461 / 2017.011.30110 / 2019.010.20064 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19715");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-19716");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '15.6', 'max_version' : '15.006.30457', 'fixed_version' : '15.006.30461', 'track' : 'DC Classic' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30106', 'fixed_version' : '17.011.30110', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '19.008.20081', 'fixed_version' : '19.010.20064', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
