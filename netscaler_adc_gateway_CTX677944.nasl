#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202083);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/11");

  script_cve_id("CVE-2024-5491", "CVE-2024-5492");

  script_name(english:"NetScaler ADC and NetScaler Gateway Multiple Vulnerabilities (CTX677944)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NetScaler ADC (formerly Citrix ADC) or NetScaler Gateway (formerly Citrix Gateway) device is version 12.1,
13.0 before 13.0-92.31, 13.1 before 13.1-53.17, or 14.1 before 14.1-25.53. It is, therefore, affected by multiple
vulnerabilities: 

  - Denial of Service (CVE-2024-5491)
  
  - Open redirect vulnerability allows a remote unauthenticated attacker to redirect users to arbitrary 
  websites (CVE-2024-5492)

Please refer to advisory CTX677944 for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/article/CTX677944/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20245491-and-cve20245492
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fb81241");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 13.0-92.31, 13.1-53.17, 14.1-25.53, or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5491");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
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
    {'min_version': '12.1', 'fixed_version': '12.1.55.304', 'fixed_display': '12.1.55.304 and later releases of 12.1-FIPS.'},
    {'min_version': '13.1', 'fixed_version': '13.1.37.183', 'fixed_display': '13.1.37.183 and later releases of 13.1-FIPS.'}
  ];
else
  constraints = [
    {'min_version': '12.1', 'fixed_version': '12.9999999',
      'fixed_display': '12.1 is now End Of Life (EOL) and is vulnerable. Upgrade to a supported fixed release.'},
    {'min_version': '13.0', 'fixed_version': '13.0.92.31', 'fixed_display': '13.0-92.31'},
    {'min_version': '13.1', 'fixed_version': '13.1.53.17', 'fixed_display': '13.1-53.17'},
    {'min_version': '14.1', 'fixed_version': '14.1.25.53', 'fixed_display': '14.1-25.53'}
  ];

vcf::citrix_netscaler::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
