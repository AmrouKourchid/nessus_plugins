#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201234);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id("CVE-2023-33733");

  script_name(english:"Splunk Enterprise 9.0.0 < 9.0.10, 9.1.0 < 9.1.5, 9.2.0 < 9.2.2 (SVD-2024-0701)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Splunk installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the SVD-2024-0701 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://advisory.splunk.com/advisories/SVD-2024-0701.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to versions 9.2.2, 9.1.5, and 9.0.10, or higher.Splunk is performing upgrades on Splunk Cloud
Platform instances as part of Emergency Maintenance for customers, as described in the Splunk Cloud Platform Maintenance
Policy. In the meantime, Splunk is actively monitoring for potential issues that could arise from this vulnerability.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33733");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin", "splunk_nix_installed.nbin");
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.10', 'license' : 'Enterprise' },
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.5', 'license' : 'Enterprise' },
  { 'min_version' : '9.2.0', 'fixed_version' : '9.2.2', 'license' : 'Enterprise' }
];
vcf::splunk::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
