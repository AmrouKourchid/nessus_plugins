#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187659);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id(
    "CVE-2012-5639",
    "CVE-2022-43680",
    "CVE-2023-1183",
    "CVE-2023-47804"
  );
  script_xref(name:"IAVA", value:"2024-A-0001");

  script_name(english:"Apache OpenOffice < 4.1.15 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a
version prior to 4.1.15. It is, therefore, affected by multiple vulnerabilities as
stated in the vendor advisories and release notes.

  - Apache OpenOffice documents can contain links that call internal macros with arbitrary 
    arguments. Several URI Schemes are defined for this purpose. Links can be activated by 
    clicks, or by automatic document events. The execution of such links must be subject 
    to user approval. In the affected versions of Apache OpenOffice, approval for certain 
    links is not requested; when activated, such links could therefore result in arbitrary 
    script execution. This is a corner case of 2022-47502. (CVE-2023-47804)

  - An attacker can craft an OBD containing a 'database/script' file with a SCRIPT command 
    where the contents of the file could be written to a new file whose location was determined 
    by the attacker. (CVE-2023-1183)

  - In Apache OpenOffice and LibreOffice embedded content will be opened automatically without 
    that a warning is shown. (CVE-2012-5639)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2023-47804.html");
  # https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.15+Release+Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8b539cd");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2012-5639.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2022-43680.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2023-1183.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2023-47804.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5639");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-47804");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("installed_sw/OpenOffice");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::openoffice::get_app_info();

# https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.15+Release+Notes
var constraints = [{'fixed_version': '9813', 'fixed_display': '4.1.15 (Build 9813)'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);