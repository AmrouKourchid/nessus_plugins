#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206166);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id("CVE-2023-45249");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/19");

  script_name(english:"Acronis Cyber Infrastructure 5.1.x < 5.1.1-71 / 5.2.x < 5.2.1-69 / 5.3.x < 5.3.1-53 / 5.4.x < 5.4.4-132 / < 5.0.1-61 (SEC-6452)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Acronis Cyber Infrastructure installed on the remote host is prior to 5.0.1-61, 5.1.1-71, 5.2.1-69,
5.3.1-53, or 5.4.4-132. It is, therefore, affected by a vulnerability as referenced in the SEC-6452 advisory.

  - Remote command execution due to use of default passwords. The following products are affected: Acronis
    Cyber Infrastructure (ACI) before build 5.0.1-61, Acronis Cyber Infrastructure (ACI) before build
    5.1.1-71, Acronis Cyber Infrastructure (ACI) before build 5.2.1-69, Acronis Cyber Infrastructure (ACI)
    before build 5.3.1-53, Acronis Cyber Infrastructure (ACI) before build 5.4.4-132. (CVE-2023-45249)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-advisory.acronis.com/advisories/SEC-6452");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Acronis Cyber Infrastructure version 5.0.1-61 / 5.1.1-71 / 5.2.1-69 / 5.3.1-53 / 5.4.4-132 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45249");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Acronis Cyber Infrastructure default password remote code execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:acronis:cyber_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("acronis_cyber_infrastructure_service_detect.nbin");
  script_require_keys("installed_sw/Acronis Cyber Infrastructure");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::acronis_aci::get_app_info(app:'Acronis Cyber Infrastructure');

var constraints = [
  { 'fixed_version' : '5.0.1.61', 'fixed_display' : '5.0.1-61' },
  { 'min_version' : '5.1', 'fixed_version' : '5.1.1.71', 'fixed_display' : '5.1.1-71' },
  { 'min_version' : '5.2', 'fixed_version' : '5.2.1.69', 'fixed_display' : '5.2.1-69' },
  { 'min_version' : '5.3', 'fixed_version' : '5.3.1.53', 'fixed_display' : '5.3.1-53' },
  { 'min_version' : '5.4', 'fixed_version' : '5.4.4.132', 'fixed_display' : '5.4.4-132' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
