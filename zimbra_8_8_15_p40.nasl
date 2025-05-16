#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178617);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/25");

  script_cve_id(
    "CVE-2022-22970",
    "CVE-2022-46364",
    "CVE-2023-25690",
    "CVE-2023-29381",
    "CVE-2023-29382",
    "CVE-2023-34192",
    "CVE-2023-34193"
  );
  script_xref(name:"IAVA", value:"2023-A-0359-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/18");

  script_name(english:"Zimbra Collaboration Server 8.8.x < 8.8.15 Patch 40 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is affected by multiple vulnerabilities
including:

  - Vulnerability in the sfdc_preauth.jsp component. A remote, unauthenticated attacker can exploit this
    vulnerability to execute arbitrary code. (CVE-2023-29382)

  - HTTP request smuggling vulnerability in the bundled Apache HTTP Server component. Exploitation of this
    vulnerability can result in the bypass of access controls in the proxy server, proxying unintended URLs
    to existing origin servers and cache poisoning. (CVE-2023-25690)

  - An server-side request forgery vulnerability in the bundled Apache CXF component. (CVE-2022-46364)

  - A cross-site scripting (XSS) vulnerability in the /h/autoSaveDraft function. A remote authenticated
    attacker can executed arbitrary code in the context of another user. (CVE-2023-34192)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P40");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Security_Center");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.8.15 Patch 40, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22970");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-29382");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zimbra_web_detect.nbin", "zimbra_nix_installed.nbin");
  script_require_keys("installed_sw/zimbra_zcs");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::zimbra::combined_get_app_info();

var constraints = [
  {'min_version':'8.8', 'max_version':'8.8.15', 'fixed_display':'8.8.15 Patch 40', 'Patch':'40'}
];

vcf::zimbra::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss': TRUE}
);
