#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211474);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");

  script_cve_id("CVE-2024-8534", "CVE-2024-8535");
  script_xref(name:"IAVA", value:"2024-A-0724");

  script_name(english:"NetScaler ADC and NetScaler Gateway Multiple Vulnerabilities (CTX691608)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NetScaler ADC (formerly Citrix ADC) or NetScaler Gateway (formerly Citrix Gateway) device is version 12.1,
13.0, 13.1  before  13.1-55.34 or 14.1 before  14.1-29.72. It is, therefore, affected by multiple vulnerabilities: 

  - Memory safety vulnerability leading to memory corruption and Denial of Service (CVE-2024-8534)
  
  - Authenticated user can access unintended user capabilities (CVE-2024-8535) 

Please refer to advisory CTX691608 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/s/article/CTX691608-netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20248534-and-cve20248535
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f45b6ddc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 13.1-55.34, 14.1-29.72 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8535");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

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

var constraints;

if (app_info['fips_status'] == 1)
  constraints = [
    {'fips':TRUE, 'min_version': '12.1', 'fixed_version': '12.1.55.321', 'fixed_display': '12.1-55.321 and later releases of 12.1-FIPS.'},
    {'fips':TRUE, 'min_version': '13.1', 'fixed_version': '13.1.37.207', 'fixed_display': '13.1-37.207 and later releases of 13.1-FIPS.'}
  ];
else
  constraints = [
    {'min_version': '12.1', 'fixed_version': '12.9999999',
      'fixed_display': '12.1 is now End Of Life (EOL) and is vulnerable. Upgrade to a supported fixed release.'},
    {'min_version': '13.0', 'fixed_version': '13.0.9999999',
      'fixed_display': '13.0 is now End Of Life (EOL) and is vulnerable. Upgrade to a supported fixed release.'},
    {'min_version': '13.1', 'fixed_version': '13.1.55.34', 'fixed_display': '13.1-55.34'},
    {'min_version': '14.1', 'fixed_version': '14.1.29.72', 'fixed_display': '14.1-29.72'}
  ];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

