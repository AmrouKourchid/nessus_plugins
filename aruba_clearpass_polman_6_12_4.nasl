#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215058);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2024-7348",
    "CVE-2025-23058",
    "CVE-2025-23059",
    "CVE-2025-23060",
    "CVE-2025-25039"
  );
  script_xref(name:"IAVA", value:"2025-A-0081");

  script_name(english:"Aruba ClearPass Policy Manager 6.11.x < 6.11.10 / 6.12.x < 6.12.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Aruba ClearPass Policy Manager installed on the remote host is prior to 6.11.10 and 6.12.4. It is, therefore,
affected by multiple vulnerabilities as referenced in the HPESBNW04784 advisory.

    - A vulnerability in the ClearPass Policy Manager web-based management interface allows a low-privileged 
      (read-only) authenticated remote attacker to gain unauthorized access to data and the ability to 
      execute functions that should be restricted to administrators only with read/write privileges. 
      Successful exploitation could enable a low-privileged user to execute administrative functions leading 
      to an escalation of privileges. (CVE-2025-23058)

    - A vulnerability in the web-based management interface of HPE Aruba Networking ClearPass Policy Manager 
      exposes directories containing sensitive information. If exploited successfully, this vulnerability 
      allows an authenticated remote attacker with high privileges to access and retrieve sensitive data, 
      potentially compromising the integrity and security of the entire system. (CVE-2025-23059)

    - A vulnerability in HPE Aruba Networking ClearPass Policy Manager may, under certain circumstances,
      expose sensitive unencrypted information. Exploiting this vulnerability could allow an attacker to 
      perform a man-in-the-middle attack, potentially granting unauthorized access to network resources as 
      well as enabling data tampering. (CVE-2025-23060)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04784en_us&docLocale=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfd5561b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.11.10, 6.12.4 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-25039");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:arubanetworks:clearpass");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("aruba_clearpass_polman_detect.nbin");
  script_require_keys("Host/Aruba_Clearpass_Policy_Manager/version");

  exit(0);
}

include('vcf.inc');

var app = 'Aruba ClearPass Policy Manager';
var app_info = vcf::get_app_info(app:app, kb_ver:'Host/Aruba_Clearpass_Policy_Manager/version');

constraints = [
  { 'min_version' : '6.11.0', 'fixed_version' : '6.11.10' },
  { 'min_version' : '6.12.0', 'fixed_version' : '6.12.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
