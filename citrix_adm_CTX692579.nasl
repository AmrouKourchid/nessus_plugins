#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216607);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/24");

  script_cve_id("CVE-2024-12284");
  script_xref(name:"IAVA", value:"2025-A-0118");

  script_name(english:"Citrix NetScaler Console (ADM) 13.1.x < 13.0.56.18 / 14.1.x < 14.1.38.53 Authenticated privilege escalation Vulnerability (CTX692579)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a Authenticated privilege escalation Vulnerability");
  script_set_attribute(attribute:"description", value:
"An Authenticated privilege escalation vulnerability exists in Citrix NetScaler Console (ADM) 13.1 prior to 13.1-56.18 
and 14.1 prior to 14.1-38.53. An unauthenticated, remote attacker can exploit this to reset the administrator password
and gain administrative access to the appliance. The issue arises due to inadequate privilege management and could 
be exploited by an authenticated malicious actor to execute commands without additional authorization. However, only 
authenticated users with existing access to the NetScaler Console can exploit this vulnerability, thereby limiting 
the threat surface to only authenticated users

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's self-reported
version number.");
  # https://support.citrix.com/s/article/CTX692579-netscaler-console-and-netscaler-agent-security-bulletin-for-cve202412284?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8b37448");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 13.1.38.53 or 14.1.38.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-12284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:application_delivery_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_adm_ssh_detect.nbin");
  script_require_keys("installed_sw/Citrix ADM");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix ADM');

var constraints = [
  {'min_version': '14.0', 'fixed_version': '14.1.38.53', 'fixed_display': '14.1-38.53'},
  {'min_version': '13.1', 'fixed_version': '13.1.56.18', 'fixed_display': '13.1-56.18'}
];

vcf::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
