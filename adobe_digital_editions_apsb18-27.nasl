#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118085);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id(
    "CVE-2018-12813",
    "CVE-2018-12814",
    "CVE-2018-12816",
    "CVE-2018-12818",
    "CVE-2018-12819",
    "CVE-2018-12820",
    "CVE-2018-12821",
    "CVE-2018-12822",
    "CVE-2018-12823"
  );

  script_name(english:"Adobe Digital Editions < 4.5.9 Multiple Vulnerabilities (APSB18-27)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Digital Editions instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote Windows host is prior to 4.5.9. It is, therefore, affected
by multiple vulnerabilities as referenced in the APSB18-27 advisory.

  - Adobe Digital Editions versions 4.5.8 and below have a heap overflow vulnerability. Successful
    exploitation could lead to arbitrary code execution. (CVE-2018-12813, CVE-2018-12814, CVE-2018-12823)

  - Adobe Digital Editions versions 4.5.8 and below have an out of bounds read vulnerability. Successful
    exploitation could lead to information disclosure. (CVE-2018-12816, CVE-2018-12818, CVE-2018-12819,
    CVE-2018-12820, CVE-2018-12821)

  - Adobe Digital Editions versions 4.5.8 and below have an use after free vulnerability. Successful
    exploitation could lead to arbitrary code execution. (CVE-2018-12822)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb18-27.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec146552");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.9 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12823");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_digital_editions_installed.nbin");
  script_require_keys("installed_sw/Adobe Digital Editions", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Digital Editions', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '4.5.9' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
