#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179954);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2023-0465", "CVE-2023-0466", "CVE-2023-2650");

  script_name(english:"Tenable Security Center Multiple Vulnerabilities (TNS-2023-25)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable SecurityCenter installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Security Center running on the remote host is . It is, therefore,
affected by multiple vulnerabilities as referenced in the TNS-2023-25 advisory.

  - Tenable Security Center leverages third-party software to help provide underlying functionality. One of
    the third-party components (OpenSSL) was found to contain vulnerabilities, and updated versions have been
    made available by the providers.  Out of caution, and in line with best practice, Tenable has upgraded
    the bundled components to address the potential impact of these issues. Tenable Security Center Patch
    SC-202307.1-5.23.1 updates OpenSSL to 1.1.1u to address the identified vulnerabilities.
    (CVE-2023-0465, CVE-2023-0466, CVE-2023-2650)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/security-center/tenablesc2023.htm#2023071-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6480b7a2");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-25");
  script_set_attribute(attribute:"solution", value:
"Apply Tenable Security Center Patch SC-202307.1-5.23.1.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/SecurityCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

var patches = make_list("SC-202307.1");
vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'equal' : '5.23.1', 'fixed_display' : 'Apply Patch SC-202307.1-5.23.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
