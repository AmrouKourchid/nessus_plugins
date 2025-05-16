#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197301);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-3289", "CVE-2024-3290");
  script_xref(name:"IAVA", value:"2024-A-0295-S");

  script_name(english:"Tenable Nessus < 10.7.3 Multiple Vulnerabilities (TNS-2024-08)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is prior to 10.7.3. It
is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2024-08 advisory.

  - Two separate vulnerabilities were discovered, reported and fixed:When installing Nessus to a directory
    outside of the default location on a Windows host, Nessus versions prior to 10.7.3 did not enforce secure
    permissions for sub-directories. This could allow for local privilege escalation if users had not secured
    the directories in the non-default installation location. - CVE-2024-3289A race condition vulnerability
    exists where an authenticated, local attacker on a Windows Nessus host could modify installation
    parameters at installation time, which could lead to the execution of arbitrary code on the Nessus host. -
    CVE-2024-3290 Tenable has released Nessus 10.7.3 to address these issues. The installation files can be
    obtained from the Tenable Downloads Portal (https://www.tenable.com/downloads/nessus). (CVE-2024-3289,
    CVE-2024-3290)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93a5b221");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-08");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus 10.7.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3290");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

var os = get_kb_item('Host/OS');
if (!empty_or_null(os) && 'windows' >!< tolower(os))
  audit(AUDIT_OS_NOT, 'Windows', os);
else if (empty_or_null(os) && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version' : '10.7.2', 'fixed_display' : '10.7.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
