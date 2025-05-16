#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180503);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/06");

  script_cve_id("CVE-2022-29093", "CVE-2022-29094", "CVE-2022-29095");

  script_name(english:"Dell SupportAssist Multiple Vulnerabilities (DSA-2022-139)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a Dell SupportAssist that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Dell SupportAssist Client is affected by multiple
vulnerabilities.

  - Dell SupportAssist Client Consumer versions (3.10.4 and versions prior) and Dell SupportAssist Client
    Commercial versions (3.1.1 and versions prior) contain an arbitrary file deletion vulnerability.
    Authenticated non-admin user could exploit the issue and delete arbitrary files on the system.
    (CVE-2022-29093)

  - Dell SupportAssist Client Consumer versions (3.10.4 and versions prior) and Dell SupportAssist Client
    Commercial versions (3.1.1 and versions prior) contain an arbitrary file deletion/overwrite vulnerability.
    Authenticated non-admin user could exploit the issue and delete or overwrite arbitrary files on the
    system. (CVE-2022-29094)

  - Dell SupportAssist Client Consumer versions (3.10.4 and prior) and Dell SupportAssist Client Commercial
    versions (3.1.1 and prior) contain a cross-site scripting vulnerability. A remote unauthenticated
    malicious user could potentially exploit this vulnerability under specific conditions leading to execution
    of malicious code on a vulnerable system. (CVE-2022-29095)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000200456/dsa-2022-139-dell-supportassist-for-home-pcs-and-business-pcs-security-update-for-multiple-security-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?936a539e");
  script_set_attribute(attribute:"solution", value:
"Update Dell SupportAssist Client Consumer to version 3.11.4, Dell Client Commercial 3.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29095");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:supportassist");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_supportassist_installed.nbin");
  script_require_keys("installed_sw/Dell SupportAssist");

  exit(0);
}
include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell SupportAssist', win_local:TRUE);
var dell_edition = tolower(app_info['Edition']);

if ('business' >< dell_edition)
  var constraints = [
    {'max_version':'3.1.1', 'fixed_version':'3.2.0'}
  ];
else constraints = [{'max_version':'3.10.4', 'fixed_version':'3.11.4'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{'xss':TRUE});
