#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210481);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id("CVE-2024-42509", "CVE-2024-47460");
  script_xref(name:"IAVA", value:"2024-A-0707");

  script_name(english:"ArubaOS 10.4.x < 10.4.1.5 / 10.7.0.0 Multiple Vulnerabilities (HPESBNW04722)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS installed on the remote host is prior to 10.4.1.5 / 10.7.0.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the HPESBNW04722 advisory.

  - Command injection vulnerability in the underlying CLI service could lead to unauthenticated remote code
    execution by sending specially crafted packets destined to the PAPI (Aruba's Access Point management
    protocol) UDP port (8211). Successful exploitation of this vulnerability results in the ability to execute
    arbitrary code as a privileged user on the underlying operating system. (CVE-2024-42509, CVE-2024-47460)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04722en_us&docLocale=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7265dfb7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ArubaOS version 10.4.1.5 / 10.7.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_detect.nbin", "arubaos_installed.nbin");
  script_require_keys("installed_sw/ArubaOS");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::aruba::combined_get_app_info(os_flavour:'ArubaOS');
if (!empty_or_null(app_info.ver_model))
    audit(AUDIT_INST_VER_NOT_VULN, 'ArubaOS', app_info.version);

var constraints = [
  { 'min_version' : '10.4', 'fixed_version' : '10.4.1.5', 'fixed_display' : '10.4.1.5 / 10.7.0.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
