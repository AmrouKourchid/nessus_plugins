#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183921);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id(
    "CVE-2018-25050",
    "CVE-2021-23445",
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-1255",
    "CVE-2023-2650",
    "CVE-2023-3446",
    "CVE-2023-3817",
    "CVE-2023-4807",
    "CVE-2023-5622",
    "CVE-2023-5623",
    "CVE-2023-5624",
    "CVE-2023-38039"
  );
  script_xref(name:"IAVA", value:"2023-A-0605-S");

  script_name(english:"Nessus Network Monitor < 6.3.0 Multiple Vulnerabilities (TNS-2023-34)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable NNM installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Nessus Network Monitor running on the remote host is prior to 6.3.0. 
It is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2023-34 advisory.

  - Nessus Network Monitor leverages third-party software to help provide underlying functionality. Several of
    the third-party components (OpenSSL, curl, chosen, datatables) were found to contain vulnerabilities, and 
    updated versions have been made available by the providers. Out of caution and in line with best practice, 
    Tenable has opted to upgrade these components to address the potential impact of the issues. Nessus Network 
    Monitor 6.3.0 updates OpenSSL to version 3.0.11, curl to version 8.4.0, chosen to version 1.8.7 and datatables
    to version 1.13.6. (CVE-2018-25050, CVE-2021-23445, CVE-2023-0465, CVE-2023-0466, CVE-2023-1255, CVE-2023-2650,
    CVE-2023-3446, CVE-2023-38039, CVE-2023-3817, CVE-2023-4807)

  - Under certain conditions, Nessus Network Monitor could allow a low privileged user to escalate privileges to 
    NT AUTHORITY\SYSTEM on Windows hosts. (CVE-2023-5622)

  - NNM failed to properly set ACLs on its installation directory, which could allow a low privileged user to run
    arbitrary code with SYSTEM privileges where NNM is installed to a non-standard location. (CVE-2023-5623)

  - Under certain conditions, Nessus Network Monitor was found to not properly enforce input validation. This 
    could allow an admin user to alter parameters that could potentially allow a blindSQL injection. (CVE-2023-5624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-34");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor 6.3.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23445");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-5622");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable NNM';

var app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version' : '6.2.3', 'fixed_version' : '6.3.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'sqli':TRUE}
);
