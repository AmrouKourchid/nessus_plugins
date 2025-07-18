#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117875);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/01");

  script_cve_id(
    "CVE-2018-12759",
    "CVE-2018-12769",
    "CVE-2018-12831",
    "CVE-2018-12832",
    "CVE-2018-12833",
    "CVE-2018-12834",
    "CVE-2018-12835",
    "CVE-2018-12836",
    "CVE-2018-12837",
    "CVE-2018-12838",
    "CVE-2018-12839",
    "CVE-2018-12841",
    "CVE-2018-12842",
    "CVE-2018-12843",
    "CVE-2018-12844",
    "CVE-2018-12845",
    "CVE-2018-12846",
    "CVE-2018-12847",
    "CVE-2018-12851",
    "CVE-2018-12852",
    "CVE-2018-12853",
    "CVE-2018-12855",
    "CVE-2018-12856",
    "CVE-2018-12857",
    "CVE-2018-12858",
    "CVE-2018-12859",
    "CVE-2018-12860",
    "CVE-2018-12861",
    "CVE-2018-12862",
    "CVE-2018-12863",
    "CVE-2018-12864",
    "CVE-2018-12865",
    "CVE-2018-12866",
    "CVE-2018-12867",
    "CVE-2018-12868",
    "CVE-2018-12869",
    "CVE-2018-12870",
    "CVE-2018-12871",
    "CVE-2018-12872",
    "CVE-2018-12873",
    "CVE-2018-12874",
    "CVE-2018-12875",
    "CVE-2018-12876",
    "CVE-2018-12877",
    "CVE-2018-12878",
    "CVE-2018-12879",
    "CVE-2018-12880",
    "CVE-2018-12881",
    "CVE-2018-15920",
    "CVE-2018-15922",
    "CVE-2018-15923",
    "CVE-2018-15924",
    "CVE-2018-15925",
    "CVE-2018-15926",
    "CVE-2018-15927",
    "CVE-2018-15928",
    "CVE-2018-15929",
    "CVE-2018-15930",
    "CVE-2018-15931",
    "CVE-2018-15932",
    "CVE-2018-15933",
    "CVE-2018-15934",
    "CVE-2018-15935",
    "CVE-2018-15936",
    "CVE-2018-15937",
    "CVE-2018-15938",
    "CVE-2018-15939",
    "CVE-2018-15940",
    "CVE-2018-15941",
    "CVE-2018-15942",
    "CVE-2018-15943",
    "CVE-2018-15944",
    "CVE-2018-15945",
    "CVE-2018-15946",
    "CVE-2018-15947",
    "CVE-2018-15948",
    "CVE-2018-15949",
    "CVE-2018-15950",
    "CVE-2018-15951",
    "CVE-2018-15952",
    "CVE-2018-15953",
    "CVE-2018-15954",
    "CVE-2018-15955",
    "CVE-2018-15956",
    "CVE-2018-15966",
    "CVE-2018-15968"
  );
  script_bugtraq_id(
    105432,
    105435,
    105436,
    105437,
    105438,
    105439,
    105440,
    105441,
    105442,
    105443,
    105444
  );

  script_name(english:"Adobe Reader <= 15.006.30452 / 17.011.30102 / 18.011.20063 Multiple Vulnerabilities (APSB18-30) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS or Mac OS X
host is a version prior or equal to 15.006.30452,  17.011.300102, or
18.011.20063. It is, therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-30.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 15.006.30456 / 17.011.30105 / 19.008.20071 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15966");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"Adobe Reader");
base_dir = app_info['path'] - "/Applications";
track = get_kb_item("MacOSX/Adobe_Reader"+base_dir+"/Track");

if (!empty_or_null(track) && track == '2017')
{
  constraints = [
    { "min_version" : "17.8", "max_version":"17.011.30102", "fixed_version" : "17.011.30105" }
  ];
}
else
{
  constraints = [
    { "min_version" : "15.6", "max_version":"15.006.30452", "fixed_version" : "15.006.30456" },
    { "min_version" : "18.8", "max_version":"18.011.20063", "fixed_version" : "19.008.20071" }
  ];
}
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
