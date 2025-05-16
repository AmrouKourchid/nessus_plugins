#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215005);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2025-22218",
    "CVE-2025-22219",
    "CVE-2025-22220",
    "CVE-2025-22221"
  );
  script_xref(name:"VMSA", value:"2025-0003");
  script_xref(name:"IAVA", value:"2025-A-0078-S");

  script_name(english:"VMware Aria Operations for Logs < 8.18.3 Multiple Vulnerabilities (VMSA-2025-0003)");

  script_set_attribute(attribute:"synopsis", value:
"VMware Aria Operations for Logs running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Aria Operations for Logs (formerly VMware vRealize Log Insight) running on the remote host is
affected by multiple vulnerabilities, including the following:

  - VMware Aria Operations for Logs contains an information disclosure vulnerability. A malicious actor with
    View Only Admin permissions may be able to read the credentials of a VMware product integrated with VMware
    Aria Operations for Logs. (CVE-2025-22218)

  - VMware Aria Operations for Logs contains a stored cross-site scripting vulnerability. A malicious actor
    with non-administrative privileges may be able to inject a malicious script that (can perform stored
    cross-site scripting) may lead to arbitrary operations as admin user. (CVE-2025-22219)

  - VMware Aria Operation for Logs contains a stored cross-site scripting vulnerability. A malicious actor
    with admin privileges to VMware Aria Operations for Logs may be able to inject a malicious script that
    could be executed in a victim's browser when performing a delete action in the Agent Configuration.
    (CVE-2025-22221)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25329
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69bcb33e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Aria Operations version 8.18.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22218");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_log_insight");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:aria_operations_for_logs");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_log_insight_webui_detect.nbin", "vmware_vrealize_log_insight_nix.nbin");
  script_require_keys("installed_sw/VMware vRealize Log Insight");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'VMware vRealize Log Insight');

if (app_info.Build)
  app_info.display_version = app_info.version + ' Build ' + app_info.Build;

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.18.3' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE} 
);
