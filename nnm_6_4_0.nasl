#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194747);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/30");

  script_cve_id(
    "CVE-2023-28711",
    "CVE-2023-46218",
    "CVE-2023-46219",
    "CVE-2024-25629"
  );

  script_name(english:"Nessus Network Monitor < 6.4.0 Multiple Vulnerabilities (TNS-2024-07)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable NNM installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Nessus Network Monitor running on the remote host is prior to 6.4.0. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2024-07 advisory.

  - Nessus Network Monitor leverages third-party software to help provide underlying functionality. Several of
    the third-party components (hyperscan, curl and c-ares)were found to contain vulnerabilities, and
    updated versions have been made available by the providers.Out of caution and in line with best practice,
    Tenable has opted to upgrade these components to address the potential impact of the issues. Nessus
    Network Monitor 6.4.0 updates hyperscan to version 5.4.2, curl to version 8.6.0, and c-ares to version
    1.28.0. Tenable has released Nessus Network Monitor 6.4.0 to address these issues. The installation files
    can be obtained from the Tenable Downloads Portal (https://www.tenable.com/downloads/nessus-network-
    monitor). (CVE-2023-28711, CVE-2023-46218, CVE-2023-46219, CVE-2024-25629)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/nessus-network-monitor/nnm.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c44d58f0");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor 6.4.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46218");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Medium");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
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
  { 'max_version' : '6.3.1', 'fixed_version' : '6.4.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
