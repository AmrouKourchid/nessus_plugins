#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207713);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id(
    "CVE-2024-6119",
    "CVE-2024-6197",
    "CVE-2024-7264",
    "CVE-2024-8096",
    "CVE-2024-9158",
    "CVE-2024-34459",
    "CVE-2024-45491",
    "CVE-2024-45492"
  );
  script_xref(name:"IAVA", value:"2024-A-0611");

  script_name(english:"Nessus Network Monitor < 6.5.0 Multiple Vulnerabilities (TNS-2024-17)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable NNM installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Nessus Network Monitor running on the remote host is prior to 6.5.0. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2024-17 advisory.

  - Nessus Network Monitor leverages third-party software to help provide underlying functionality. Several of
    the third-party components (OpenSSL, expat, curl, and libxml2)were found to contain vulnerabilities,
    and updated versions have been made available by the providers.Out of caution and in line with best
    practice, Tenable has opted to upgrade these components to address the potential impact of the issues.
    Nessus Network Monitor 6.5.0 updates OpenSSL to version 3.0.15, expat to version 2.6.3, curl to version
    8.10.0, and libxml2 to to version 2.13.1 to address the identified vulnerabilities.Additionally, one
    separate vulnerability was discovered, reported and fixed:A stored cross site scripting vulnerability
    exists in Nessus Network Monitor where an authenticated, privileged local attacker could inject arbitrary
    code into the NNM UI via the local CLI. - CVE-2024-9158 Tenable has released Nessus Network Monitor 6.5.0
    to address these issues. The installation files can be obtained from the Tenable Downloads Portal
    (https://www.tenable.com/downloads/nessus-network-monitor). (CVE-2024-34459, CVE-2024-45491,
    CVE-2024-45492, CVE-2024-6119, CVE-2024-6197, CVE-2024-7264, CVE-2024-8096, CVE-2024-9158)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/nessus-network-monitor/2024.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95833b3e");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-17");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor 6.5.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable NNM';

var app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version' : '6.4.1', 'fixed_version' : '6.5.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
