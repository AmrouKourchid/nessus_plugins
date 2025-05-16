#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194921);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/30");

  script_cve_id(
    "CVE-2023-5678",
    "CVE-2023-28319",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322",
    "CVE-2023-38039",
    "CVE-2023-38545",
    "CVE-2023-38546",
    "CVE-2023-46218",
    "CVE-2023-46219",
    "CVE-2024-0727"
  );
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"Splunk Universal Forwarder 9.0.0 < 9.0.9, 9.1.0 < 9.1.4, 9.2.0 < 9.2.1 (SVD-2024-0304)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Splunk installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the SVD-2024-0304 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://advisory.splunk.com/advisories/SVD-2024-0304.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Universal Forwarder to versions 9.2.1, 9.1.4, and 9.0.9, or higher.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:universal_forwarder");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin", "splunk_nix_installed.nbin", "splunk_universal_forwarder_nix_installed.nbin", "splunk_universal_forwarder_win_installed.nbin");
  script_require_ports("installed_sw/Splunk", "installed_sw/Splunk Universal Forwarder");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.9', 'license' : 'Forwarder' },
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.4', 'license' : 'Forwarder' },
  { 'min_version' : '9.2.0', 'fixed_version' : '9.2.1', 'license' : 'Forwarder' }
];
vcf::splunk::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
