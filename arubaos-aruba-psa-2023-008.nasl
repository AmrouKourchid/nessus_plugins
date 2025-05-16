#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178240);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id(
    "CVE-2023-35971",
    "CVE-2023-35972",
    "CVE-2023-35973",
    "CVE-2023-35974",
    "CVE-2023-35975",
    "CVE-2023-35976",
    "CVE-2023-35977",
    "CVE-2023-35978",
    "CVE-2023-35979"
  );
  script_xref(name:"IAVA", value:"2023-A-0334-S");

  script_name(english:"ArubaOS  < 8.6.0.21 / 8.10.0.7 / 8.11.1.1 / 10.4.0.2 Multiple Vulnerabilities (ARUBA-PSA-2023-008)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS installed on the remote host is 8.6 prior to 8.6.0.21, 8.10 prior to 8.10.0.7, 8.11 prior to
8.11.1.1, or 10.4 prior to 10.4.0.2. It is, therefore, affected by multiple vulnerabilities including:

  - A cross-site scripting (XSS) vulnerability in the web-based management interface. An unauthenticated,
    network-adjacent attacker can conduct a stored XSS attacker against an authorized user of the interface
    resulting in the execution of arbitrary code in the victim's browser (CVE-2023-35971)

  - A command injection vulnerability in the web-based management interface. An authenticated, remote
    attacker can execute arbitrary commands as a privileged user in the underlying operating system
    of an affected device. (CVE-2023-35972)

  - Multiple command injection vulnerabilities in the ArubaOS command line interface. An authenticated,
    remote attacker can execute arbitrary commands as a privileged user in the underlying operating system
    of an affected device. (CVE-2023-35973, CVE-2023-35974)

  - A path-traversal vulnerability in the ArubaOS command line interface. An authenticated, remote attacker
    can delete arbitrary files in the underlying operating system. (CVE-2023-25975)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  #https://csaf.arubanetworks.com/2023/hpe_aruba_networking_-_2023-008.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4fdfea6d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the ArubaOS version mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35975");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version': '6.5.4', 'max_version': '6.5.4.99999', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '8.7', 'max_version': '8.7.99999', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '8.8', 'max_version': '8.8.99999', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '8.9', 'max_version': '8.9.99999', 'fixed_display': 'See vendor advisory'},
  { 'min_version': '8.6', 'fixed_version': '8.6.0.21' },
  { 'min_version': '8.10', 'fixed_version': '8.10.0.7' },
  { 'min_version': '8.11', 'fixed_version': '8.11.1.1' },
  { 'min_version': '10.4', 'fixed_version': '10.4.0.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
