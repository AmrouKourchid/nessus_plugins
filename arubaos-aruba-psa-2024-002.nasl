#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191712);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/02");

  script_cve_id(
    "CVE-2024-1356",
    "CVE-2024-25611",
    "CVE-2024-25612",
    "CVE-2024-25613",
    "CVE-2024-25614",
    "CVE-2024-25615",
    "CVE-2024-25616"
  );
  script_xref(name:"IAVA", value:"2024-A-0136-S");

  script_name(english:"ArubaOS  < 8.10.0.10 / 8.11.2.1 / 10.4.1.0 / 10.5.1.0 Multiple Vulnerabilities (ARUBA-PSA-2024-002)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS installed on the remote host is 8.x prior to 8.10.0.10, 8.11 prior to 8.11.2.1, 10.4 prior to
10.4.1.0, or 10.5 prior to 10.5.1.0. It is, therefore, affected by multiple vulnerabilities including:

  - An authenticated command injection vulnerabilities exist in the ArubaOS command line interface. 
    Successful exploitation of these vulnerabilities result in the ability to execute arbitrary 
    commands as a privileged user on the underlying operating system. (CVE-2024-1356, CVE-2024-25611,
    CVE-2024-25612, CVE-2024-25613)

  - There is an arbitrary file deletion vulnerability in the CLI used by ArubaOS. Successful exploitation 
    of this vulnerability results in the ability to delete arbitrary files on the underlying operating 
    system, which could lead to denial-of-service conditions and impact the integrity of the controller. 
    (CVE-2024-25614)                                            
  
  -  An unauthenticated Denial-of-Service (DoS) vulnerability exists in the Spectrum service accessed via the 
    PAPI protocol in ArubaOS 8.x. Successful exploitation of this vulnerability results in the ability to 
    interrupt the normal operation of the affected service. (CVE-2024-25615)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2024-002.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the ArubaOS version mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-25611");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-25613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_installed.nbin", "arubaos_detect.nbin");
  script_require_keys("installed_sw/ArubaOS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::aruba::combined_get_app_info(os_flavour:'ArubaOS');
# Having a model indicates a different form of version number not handled by this plugin
if (!empty_or_null(app_info.ver_model))
    audit(AUDIT_INST_VER_NOT_VULN, 'ArubaOS', app_info.version);

var constraints = [
  { 'min_version': '6.5.4', 'max_version': '6.5.4.99999', 'fixed_display': 'Product End Of Life, Upgrade to latest OS for continued support'},
  { 'min_version': '8.6', 'max_version': '8.6.99999', 'fixed_display': 'Product End Of Life, Upgrade to latest OS for continued support'},
  { 'min_version': '8.7', 'max_version': '8.7.99999', 'fixed_display': 'Product End Of Life, Upgrade to latest OS for continued support'},
  { 'min_version': '8.8', 'max_version': '8.8.99999', 'fixed_display': 'Product End Of Life, Upgrade to latest OS for continued support'},
  { 'min_version': '8.9', 'max_version': '8.9.99999', 'fixed_display': 'Product End Of Life, Upgrade to latest OS for continued support'},
  { 'min_version': '10.3', 'max_version': '10.3.99999', 'fixed_display': 'Product End Of Life, Upgrade to latest OS for continued support'},
  { 'min_version': '8.10', 'fixed_version': '8.10.0.10' },
  { 'min_version': '8.11', 'fixed_version': '8.11.2.1' },
  { 'min_version': '10.4', 'fixed_version': '10.4.1.0' },
  { 'min_version': '10.5', 'fixed_version': '10.5.1.0' }

];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
