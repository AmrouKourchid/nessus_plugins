#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166600);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/16");

  script_cve_id(
    "CVE-2020-28458",
    "CVE-2021-23445",
    "CVE-2022-2309",
    "CVE-2022-23308",
    "CVE-2022-24785",
    "CVE-2022-29824",
    "CVE-2022-31129",
    "CVE-2022-37434",
    "CVE-2022-40674"
  );
  script_xref(name:"IAVA", value:"2023-A-0059-S");

  script_name(english:"Tenable Nessus 10.x < 10.3.1 Multiple Vulnerabilities (TNS-2022-20)");

  script_set_attribute(attribute:"synopsis", value:
"Tenable Nessus running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is 10.x prior to 
10.3.1. It is, therefore, affected by multiple vulnerabilities, including:

  - A use-after-free vulnerability in the doContent function in xmlparse.c in libexpat. (CVE-2022-40674)

  - A path traversal vulnerability in the locale string handling functionality of Moment.js. (CVE-2022-24785)

  - A denial of service vulnerability in the string-to-date parsing functinality in Moment.js (CVE-2022-31129)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 10.3.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28458");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

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

include('vcf_extras.inc');

var app_info, constraints;

app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'min_version':'10.0.0', 'fixed_version':'10.3.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);