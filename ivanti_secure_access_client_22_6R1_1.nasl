#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187131);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/22");

  script_cve_id("CVE-2023-35080", "CVE-2023-38543", "CVE-2023-38043");

  script_name(english:"Ivanti Secure Access Client < 22.6R1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A VPN client installed on the remote windows system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Ivanti Secure Access Client installed on the remote Windows system is prior to 22.6R1.1. It is, therefore,
affected by multiple vulnerabilities.

 - A vulnerability exists on all versions of the Ivanti Secure Access Client
   below 22.6R1.1, which could allow a locally authenticated attacker to exploit
   a vulnerable configuration, potentially leading to various security risks,
   including the escalation of privileges, denial of service on the user
   machine, or information disclosure. (CVE-2023-35080)

 - A vulnerability exists on all versions of the Ivanti Secure Access Client
   below 22.6R1.1, which could allow a locally authenticated attacker to exploit
   a vulnerable configuration, potentially leading to a denial of service (DoS)
   condition on the user machine. (CVE-2023-38543)

 - A vulnerability exists on all versions of the Ivanti Secure Access Client
   below 22.6R1.1, which could allow a locally authenticated attacker to exploit
   a vulnerable configuration, potentially leading to a denial of service (DoS)
   condition on the user machine and, in some cases, resulting in a full
   compromise of the system. (CVE-2023-38043)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-fixes-included-in-the-latest-Ivanti-Secure-Access-Client-Release?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88821bb2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ivanti Secure Access Client version 22.3R1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ivanti:ivanti_secure_access_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("juniper_pulse_client_installed.nbin");
  script_require_keys("installed_sw/Ivanti Secure Access Client");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Ivanti Secure Access Client', win_local:TRUE);

# Advisory indicates 22.6R1 and 22.6R1.1
# Release notes show only Ivanti Secure Access Client for Desktop 22.6R1 Build 26825
var constraints = [
  {'fixed_version':'22.6.1.1000', 'fixed_display':'22.6R1.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
