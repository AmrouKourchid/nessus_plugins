#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164989);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id(
    "CVE-2022-28851",
    "CVE-2022-30677",
    "CVE-2022-30678",
    "CVE-2022-30680",
    "CVE-2022-30681",
    "CVE-2022-30682",
    "CVE-2022-30683",
    "CVE-2022-30684",
    "CVE-2022-30685",
    "CVE-2022-30686",
    "CVE-2022-34218",
    "CVE-2022-35664",
    "CVE-2022-38438",
    "CVE-2022-38439"
  );
  script_xref(name:"IAVA", value:"2022-A-0362-S");

  script_name(english:"Adobe Experience Manager 6.5.0.0 < 6.5.14.0 Multiple Vulnerabilities (APSB22-40)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.5.14.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB22-40 advisory.

  - Adobe Experience Manager versions 6.5.13.0 (and earlier) is affected by a reflected Cross-Site Scripting
    (XSS) vulnerability. If an attacker is able to convince a victim to visit a URL referencing a vulnerable
    page, malicious JavaScript content may be executed within the context of the victim's browser.
    Exploitation of this issue requires low-privilege access to AEM. (CVE-2022-28851, CVE-2022-30677,
    CVE-2022-30678, CVE-2022-30680, CVE-2022-30681, CVE-2022-30682, CVE-2022-30684, CVE-2022-30685,
    CVE-2022-30686, CVE-2022-34218, CVE-2022-35664, CVE-2022-38438, CVE-2022-38439)

  - Adobe Experience Manager versions 6.5.13.0 (and earlier) is affected by a Violation of Secure Design
    Principles vulnerability that could lead to bypass the security feature of the encryption mechanism in the
    backend . An attacker could leverage this vulnerability to decrypt secrets, however, this is a high-
    complexity attack as the threat actor needs to already possess those secrets. Exploitation of this issue
    requires low-privilege access to AEM. (CVE-2022-30683)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb22-40.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db43df1e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.14.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38439");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 657);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_experience_manager_http_detect.nbin");
  script_require_keys("installed_sw/Adobe Experience Manager");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:4502);
var app_info = vcf::get_app_info(app:'Adobe Experience Manager', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '6.5.0.0', 'fixed_version' : '6.5.14.0' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
