#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216268);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2025-0556");
  script_xref(name:"IAVB", value:"2025-B-0025");

  script_name(english:"Progress Telerik Report Server < 11.0.25.211 Cleartext Transmission");

  script_set_attribute(attribute:"synopsis", value:
"The version of Progress Telerik Report Server installed on the remote host is affected by an cleartext transmission vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Progress Telerik Report Server installed on the remote host is affected by an cleartext transmission
vulnerability. In Progress® Telerik® Report Server, versions prior to 2025 Q1 (11.0.25.211) when using the older .NET 
Framework implementation, communication of non-sensitive information between the service agent process and app host 
process occurs over an unencrypted tunnel, which can be subjected to local network traffic sniffing.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.telerik.com/report-server/knowledge-base/kb-security-cleartext-transmission-cve-2025-0556
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e25b532");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress Telerik Report Server 2025 Q1 (11.0.25.211) or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0556");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:progress:telerik_report_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("progress_telerik_report_server_web_interface_detect.nbin", "progress_telerik_report_server_win_installed.nbin");
  script_require_keys("installed_sw/Progress Telerik Report Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Progress Telerik Report Server');

# We aren't testing for older .NET Framework implementation so require paranoia
var constraints = [
  { 'max_version':'10.3.24.1218', 'fixed_version':'11.0.25.211', 'require_paranoia':TRUE}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
