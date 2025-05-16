#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180253);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/13");

  script_cve_id("CVE-2023-3251", "CVE-2023-3252", "CVE-2023-3253");
  script_xref(name:"IAVA", value:"2023-A-0445-S");

  script_name(english:"Tenable Nessus < 10.6.0 Multiple Vulnerabilities (TNS-2023-29)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is prior to 10.6.0. It
is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2023-29 advisory.

  - A pass-back vulnerability exists where an authenticated, remote attacker with administrator privileges
    could uncover stored SMTP credentials within the Nessus application. (CVE-2023-3251)
    
  - An arbitrary file write vulnerability exists where an authenticated, remote attacker with administrator privileges
    could alter logging variables to overwrite arbitrary files on the remote host with log data, which could
    lead to a denial of service condition. (CVE-2023-3252)

  - An improper authorization vulnerability exists where an authenticated, low privileged remote attacker could 
    view a list of all the users available in the application. (CVE-2023-3253)

    The installation files can be obtained from the Tenable Downloads Portal
    (https://www.tenable.com/downloads/nessus). (CVE-2023-3251, CVE-2023-3252, CVE-2023-3253)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/nessus/nessus2023.htm#10.6.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db90e0fd");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus 10.6.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3252");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version' : '10.5.4', 'fixed_display' : '10.6.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
