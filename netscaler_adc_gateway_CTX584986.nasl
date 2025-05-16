#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189070);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/05");

  script_cve_id("CVE-2023-6548", "CVE-2023-6549");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/07");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/01/24");
  script_xref(name:"IAVA", value:"2024-A-0037");

  script_name(english:"NetScaler ADC and NetScaler Gateway Multiple Vulnerabilities (CTX584986l)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NetScaler ADC (formerly Citrix ADC) or NetScaler Gateway (formerly Citrix Gateway) device is version 12.1,
12.1-FIPS before 12.1-55.302-FIPS, 13.0 before 13.0-92.21, 13.1 before 13.1-51.15, 13.1-FIPS before 13.1-37.176-FIPS,
or 14.1 before 14.1-12.35. It is, therefore, affected by multiple vulnerabilities:

  - Authenticated (low privileged) remote code execution on Management Interface (CVE-2023-6548)

  - Denial of Service (CVE-2023-6549)

Please refer to advisory CTX584986 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/article/CTX584986/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20236548-and-cve20236549
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76040a00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 13.0-92.21, 13.1-51.15, 14.1-12.35, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6548");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
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

if (show_systemstatus_kb =~ "Product Name: (ADC|NetScaler) SDX")
  audit(AUDIT_DEVICE_NOT_VULN, 'ADC SDX / NetScaler SDX');

  var constraints = [
  {'fips':TRUE, 'min_version': '12.1', 'fixed_version': '12.1.55.302', 'fixed_display': '12.1-55.302 and later releases of 12.1-FIPS.'},
  {'fips':TRUE, 'min_version': '13.1', 'fixed_version': '13.1.37.176', 'fixed_display': '13.1-37.176 and later releases of 13.1-FIPS.'},
  {'min_version': '12.1', 'fixed_version': '12.9999999', 'fixed_display': '12.1 is now End Of Life (EOL) and is vulnerable. Contact the vendor.'},
  {'min_version': '13.0', 'fixed_version': '13.0.92.21', 'fixed_display': '13.0-92.21'},
  {'min_version': '13.1', 'fixed_version': '13.1.51.15', 'fixed_display': '13.1-51.15'},
  {'min_version': '14.1', 'fixed_version': '14.1.12.35', 'fixed_display': '14.1-12.35'}
];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
