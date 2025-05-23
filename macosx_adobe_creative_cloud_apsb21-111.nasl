#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155137);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/26");

  script_cve_id("CVE-2021-43017", "CVE-2021-43019");
  script_xref(name:"IAVA", value:"2021-A-0547");

  script_name(english:"Adobe Creative Cloud Desktop Application < 5.6 Multiple Vulnerabilities (APSB21-111) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop Application installed on the remote macOS host is prior to 5.6. It is,
therefore, affected by multiple vulnerabilities.

  - Creation of a temporary file in a directory with incorrect permissions allows an authenticated, local
    attacker to execute arbitrary code. (CVE-2021-43017)

  - Improper access control allows an unauthenticated, local attacker to escalate privileges. (CVE-2021-43019)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb21-111.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6eea7a58");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud Desktop Application version 5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43019");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-43017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_creative_cloud_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Creative Cloud");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) 
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version')) 
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Creative Cloud');
var constraints = [{ 'fixed_version' : '5.6' }];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
