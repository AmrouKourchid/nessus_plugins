#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185516);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id("CVE-2023-38545", "CVE-2023-38546");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");
  script_xref(name:"IAVA", value:"2023-A-0531-S");

  script_name(english:"Tenable Security Center Multiple Vulnerabilities (TNS-2023-35)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable Security Center installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Security Center running on the remote host is affected by multiple 
vulnerabilities as referenced in the TNS-2023-35 advisory.

  - Security Center leverages third-party software to help provide underlying functionality. One of the third-
    party components (curl) was found to contain vulnerabilities, and an updated version has been made
    available by the provider.Out of caution, and in line with best practice, Tenable has upgraded the bundled
    components to address the potential impact of these issues. Security Center Patch SC-202310.1 updates curl
    to 8.4.0 to address the identified vulnerabilities. Tenable has released Patch SC-202310.1 to address
    these issues. The installation files can be obtained from the Tenable Downloads Portal::
    https://www.tenable.com/downloads/security-center (CVE-2023-38545, CVE-2023-38546)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-35");
  script_set_attribute(attribute:"solution", value:
"Apply Tenable Security Center Patch SC-202310.1.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/SecurityCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

var patches = make_list("SC-202310.1");
vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'equal' : '5.23.1', 'fixed_display' : 'Apply Patch SC-202310.1' },
  { 'equal' : '6.0.0', 'fixed_display' : 'Apply Patch SC-202310.1' },
  { 'equal' : '6.1.0', 'fixed_display' : 'Apply Patch SC-202310.1' },
  { 'equal' : '6.1.1', 'fixed_display' : 'Apply Patch SC-202310.1' },
  { 'equal' : '6.2.0', 'fixed_display' : 'Apply Patch SC-202310.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
