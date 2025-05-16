#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187074);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2023-43622", "CVE-2023-45802");

  script_name(english:"Tenable SecurityCenter Multiple Vulnerabilities (TNS-2023-44)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable SecurityCenter installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter running on the remote host is . It is, therefore,
affected by multiple vulnerabilities as referenced in the TNS-2023-44 advisory.

  - Security Center leverages third-party software to help provide underlying functionality. One of the third-
    party components (Apache) was found to contain vulnerabilities, and updated versions have been made
    available by the providers. Out of caution and in line with best practice, Tenable has opted to upgrade
    these components to address the potential impact of the issues. Security Center Patch SC-202312.1 updates
    Apache to version 2.4.58 to address the identified vulnerabilities. Tenable has released Security Center
    Patch SC-202312.1 to address these issues. The installation files can be obtained from the Tenable
    Downloads Portal: https://www.tenable.com/downloads/security-center (CVE-2023-43622, CVE-2023-45802)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-44");
  script_set_attribute(attribute:"solution", value:
"Apply Tenable Security Center Patch SC-202312.1.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

var patches = make_list('SC-202312.1');
vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'equal' : '5.23.1', 'fixed_display' : 'Apply Patch SC-202312.1' },
  { 'equal' : '6.0.0', 'fixed_display' : 'Apply Patch SC-202312.1' },
  { 'equal' : '6.1.0', 'fixed_display' : 'Apply Patch SC-202312.1' },
  { 'equal' : '6.1.1', 'fixed_display' : 'Apply Patch SC-202312.1' },
  { 'equal' : '6.2.0', 'fixed_display' : 'Apply Patch SC-202312.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
