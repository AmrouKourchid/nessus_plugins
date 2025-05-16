#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208035);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id(
    "CVE-2024-45514",
    "CVE-2024-45516",
    "CVE-2024-45517",
    "CVE-2024-45518",
    "CVE-2024-45519"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/10/24");
  script_xref(name:"IAVA", value:"2024-A-0613-S");

  script_name(english:"Zimbra Collaboration Server 8.0.0 < 8.8.15 Patch 46, 9.0.0 < 9.0.0 Patch 41, 10.0 < 10.0.9, 10.1.0 < 10.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is affected by multiple vulnerabilities
including:

 - Fixed a security vulnerability in the postjournal service which may allow
   unauthenticated users to execute commands. (CVE-2024-45519)

 - A Server-Side Request Forgery (SSRF) vulnerability that allowed unauthorized
   access to internal services has been addressed. (CVE-2024-45518)

  - A Cross-Site Scripting (XSS) vulnerability in the `/h/rest` endpoint has
    been fixed. (CVE-2024-45517)

  - A Cross-Site Scripting (XSS) vulnerability via crafted HTML content in the
    Zimbra Classic UI has been fixed. (CVE-2024-45516)

  - A Cross-Site Scripting (XSS) vulnerability caused by a non-sanitized
    `packages` parameter has been resolved. (CVE-2024-45514)

  - A Cross-Site Scripting (XSS) vulnerability via crafted HTML content in the
    Zimbra Classic UI has been fixed. (TBD)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P46");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/9.0.0/P41");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/10.0.9");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.1");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Security_Center");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.8.15 Patch 46, 9.0.0 Patch 41, 10.0.9, 10.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45519");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zimbra_web_detect.nbin", "zimbra_nix_installed.nbin");
  script_require_keys("installed_sw/zimbra_zcs");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::zimbra::combined_get_app_info();

var constraints = [
  {'min_version':'8.8', 'max_version':'8.8.15', 'fixed_display':'8.8.15 Patch 46', 'Patch':'46'},
  {'min_version':'9.0', 'max_version':'9.0.0', 'fixed_display':'9.0.0 Patch 41', 'Patch':'41'},
  {'min_version':'10.0', 'fixed_version':'10.0.9', 'fixed_display':'10.0.9'},
  {'min_version':'10.1', 'fixed_version':'10.1.1', 'fixed_display':'10.1.1'}
];

vcf::zimbra::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);
