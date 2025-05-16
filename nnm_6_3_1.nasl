#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186472);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/19");

  script_cve_id(
    "CVE-2018-9206",
    "CVE-2021-23369",
    "CVE-2021-23383",
    "CVE-2023-5363"
  );

  script_name(english:"Nessus Network Monitor < 6.3.1 Multiple Vulnerabilities (TNS-2023-43)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable NNM installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Nessus Network Monitor running on the remote host is prior to 6.3.1. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2023-43 advisory.

  - Nessus Network Monitor leverages third-party software to help provide underlying functionality. Several of
    the third-party components (HandlebarsJS, OpenSSL, and jquery-file-upload)were found to contain
    vulnerabilities, and updated versions have been made available by the providers.Out of caution and in line
    with best practice, Tenable has opted to upgrade these components to address the potential impact of the
    issues. Nessus Network Monitor 6.3.1 updates HandlebarsJS to version 4.7.8, OpenSSL to version 3.0.12, and
    jquery-file-upload to version 10.8.0. Tenable has released Nessus Network Monitor 6.3.1 to address these
    issues. The installation files can be obtained from the Tenable Downloads Portal
    (https://www.tenable.com/downloads/nessus-network-monitor). (CVE-2018-9206, CVE-2021-23369,
    CVE-2021-23383, CVE-2023-5363)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-43");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor 6.3.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23383");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"jQuery File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'blueimps jQuery (Arbitrary) File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable NNM';

var app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version' : '6.3.0', 'fixed_version' : '6.3.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
