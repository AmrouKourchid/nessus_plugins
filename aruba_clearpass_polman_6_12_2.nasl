#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(212131);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id(
    "CVE-2024-51771",
    "CVE-2024-51772",
    "CVE-2024-51773",
    "CVE-2024-53672"
  );
  script_xref(name:"IAVA", value:"2024-A-0775-S");

  script_name(english:"Aruba ClearPass Policy Manager <= 6.12.x < 6.12.2 / 6.11.x < 6.11.9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Aruba ClearPass Policy Manager installed on the remote host is prior or equal to 6.12.2 or 6.11.9. It is, therefore,
affected by multiple vulnerabilities as referenced in the HPESBNW04761 advisory.

  - A vulnerability in the HPE Aruba Networking ClearPass Policy Manager web-based management interface could allow 
    an authenticated remote threat actor to conduct a remote code execution attack. Successful exploitation could 
    enable the attacker to run arbitrary commands on the underlying operating system. (CVE-2024-51771)

  - An authenticated RCE vulnerability in the ClearPass Policy Manager web-based management interface allows remote 
   authenticated users to run arbitrary commands on the underlying host. Successful exploitation could allow an 
   attacker to execute arbitrary commands on the underlying operating system. (CVE-2024-51772)

  - An authenticated RCE vulnerability in the ClearPass Policy Manager web-based management interface allows remote
    authenticated users to run arbitrary commands on the underlying host. Successful exploitation could allow an 
    attacker to execute arbitrary commands on the underlying operating system. (CVE-2024-51773)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04761en_us&docLocale=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70dfb4c9");
  script_set_attribute(attribute:"solution", value:
"Please see vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-51772");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-51771");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:arubanetworks:clearpass");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("aruba_clearpass_polman_detect.nbin");
  script_require_keys("Host/Aruba_Clearpass_Policy_Manager/version");

  exit(0);
}

include('vcf.inc');

var app = 'Aruba ClearPass Policy Manager';
var app_info = vcf::get_app_info(app:app, kb_ver:'Host/Aruba_Clearpass_Policy_Manager/version');

constraints = [
  { 'min_version' : '6.11', 'max_version' : '6.11.9', 'fixed_display': 'Please see vendor advisory'},
  { 'min_version' : '6.12', 'max_version' : '6.12.2', 'fixed_display': 'Please see vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
