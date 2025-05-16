#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213005);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2020-26870",
    "CVE-2024-45709",
    "CVE-2024-45801",
    "CVE-2024-47875",
    "CVE-2024-48910",
    "CVE-2024-52316"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0001");
  script_xref(name:"IAVA", value:"2024-A-0817-S");

  script_name(english:"SolarWinds Web Help Desk < 12.8.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Solarwinds Web Help Desk installed on the remote host is prior to 12.8.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the 12.8.4 release notes.

  - Cure53 DOMPurify before 2.0.17 allows mutation XSS. This occurs because a serialize-parse roundtrip does
    not necessarily return the original DOM tree, and a namespace can change from HTML to MathML, as
    demonstrated by nesting of FORM elements. (CVE-2020-26870)

  - SolarWinds Web Help Desk was susceptible to a local file read vulnerability. This vulnerability requires
    the software be installed on Linux and configured to use non-default development/test mode making exposure
    to the vulnerability very limited. (CVE-2024-45709)

  - DOMPurify is a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG. It has been
    discovered that malicious HTML using special nesting techniques can bypass the depth checking added to
    DOMPurify in recent releases. It was also possible to use Prototype Pollution to weaken the depth check.
    This renders dompurify unable to avoid cross site scripting (XSS) attacks. This issue has been addressed
    in versions 2.5.4 and 3.1.3 of DOMPurify. All users are advised to upgrade. There are no known workarounds
    for this vulnerability. (CVE-2024-45801)

  - DOMPurify is a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG. DOMpurify was
    vulnerable to nesting-based mXSS. This vulnerability is fixed in 2.5.0 and 3.1.3. (CVE-2024-47875)

  - DOMPurify is a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG. DOMPurify was
    vulnerable to prototype pollution. This vulnerability is fixed in 2.4.2. (CVE-2024-48910)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://documentation.solarwinds.com/en/success_center/whd/content/release_notes/whd_12-8-4_release_notes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c24befe0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Solarwinds Web Help Desk version 12.8.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26870");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:web_help_desk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_web_help_desk_detect.nbin", "solarwinds_web_help_desk_installed.nbin");
  script_require_keys("installed_sw/Solarwinds Web Help Desk");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Solarwinds Web Help Desk');

var constraints = [
  { 'fixed_version' : '12.8.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
