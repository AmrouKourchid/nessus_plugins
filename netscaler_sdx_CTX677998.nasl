#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202323);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/15");

  script_cve_id("CVE-2024-6236");
  script_xref(name:"IAVA", value:"2024-A-0379");

  script_name(english:"NetScaler SDX Denial of Service (CTX677998)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by a denial of service.");
  script_set_attribute(attribute:"description", value:
"The remote NetScaler SDX device is version 13.0 before 13.0-92.31, 13.1 before 13.1-53.17, or 14.1 before 14.1-25.53.
It is, therefore, affected by a denial of service (DoS) vulnerability. An unauthenticated, adjacent attacker can exploit
this issue to cause the process to stop responding.

Please refer to advisory CTX584986 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/article/CTX677998/netscaler-console-agent-and-sdx-svm-security-bulletin-for-cve20246235-and-cve20246236
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?145c970a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 13.0-92.31, 13.1-53.17, 14.1-25.53, or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6236");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_sdx");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

include('vcf_extras_netscaler.inc');

var app_info = vcf::citrix_netscaler::get_app_info();
var show_systemstatus_kb = get_kb_item('Host/NetScaler/show_systemstatus');

if (show_systemstatus_kb =~ "Product Name: NetScaler SDX")
  audit(AUDIT_DEVICE_NOT_VULN, 'NetScaler SDX');

var constraints = [
  {'min_version': '13.0', 'fixed_version': '13.0.92.21', 'fixed_display': '13.0-92.31'},
  {'min_version': '13.1', 'fixed_version': '13.1.51.15', 'fixed_display': '13.1-53.17'},
  {'min_version': '14.1', 'fixed_version': '14.1.12.35', 'fixed_display': '14.1-25.53'},
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
