#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209396);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2016-4256",
    "CVE-2016-4257",
    "CVE-2016-4258",
    "CVE-2016-4259",
    "CVE-2016-4260",
    "CVE-2016-4261",
    "CVE-2016-4262",
    "CVE-2016-4263",
    "CVE-2016-6980"
  );

  script_name(english:"Adobe Digital Editions < 4.5.2 Multiple Vulnerabilities (APSB16-28) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Digital Editions instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote macOS host is prior to 4.5.2. It is, therefore, affected
by multiple vulnerabilities as referenced in the APSB16-28 advisory.

  - Use-after-free vulnerability in Adobe Digital Editions before 4.5.2 allows attackers to execute arbitrary
    code via unspecified vectors, a different vulnerability than CVE-2016-4263. (CVE-2016-6980)

  - Adobe Digital Editions before 4.5.2 allows attackers to execute arbitrary code or cause a denial of
    service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-4257,
    CVE-2016-4258, CVE-2016-4259, CVE-2016-4260, CVE-2016-4261, and CVE-2016-4262. (CVE-2016-4256)

  - Adobe Digital Editions before 4.5.2 allows attackers to execute arbitrary code or cause a denial of
    service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-4256,
    CVE-2016-4258, CVE-2016-4259, CVE-2016-4260, CVE-2016-4261, and CVE-2016-4262. (CVE-2016-4257)

  - Adobe Digital Editions before 4.5.2 allows attackers to execute arbitrary code or cause a denial of
    service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-4256,
    CVE-2016-4257, CVE-2016-4259, CVE-2016-4260, CVE-2016-4261, and CVE-2016-4262. (CVE-2016-4258)

  - Adobe Digital Editions before 4.5.2 allows attackers to execute arbitrary code or cause a denial of
    service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-4256,
    CVE-2016-4257, CVE-2016-4258, CVE-2016-4260, CVE-2016-4261, and CVE-2016-4262. (CVE-2016-4259)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb16-28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fee76481");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_digital_editions_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Digital Editions");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Digital Editions');

var constraints = [
  { 'fixed_version' : '4.5.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
