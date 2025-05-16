#%NASL_MIN_LEVEL 80900
##
# Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178157);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id("CVE-2023-36868");
  script_xref(name:"IAVA", value:"2023-A-0350");

  script_name(english:"Azure Service Fabric Explorer Information Disclosure (July 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Azure Service Fabric installed on the remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Azure Service Fabric installed on the remote host is affected by an information disclosure vulnerability. A remote,
unauthenticated attacker can exploit this to compromise confidentiality.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/azure/service-fabric/service-fabric-versions
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?477258c9");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-36868
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?260c0c05");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 9.0 CU9 (9.0.1526.9590), 9.1 CU4 (9.1.1799.9590) or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36868");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_service_fabric");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_service_fabric_web_detect.nbin", "microsoft_azure_service_fabric_installed.nbin");
  script_require_keys("installed_sw/Microsoft Azure Service Fabric");

  exit(0);
}

include('vcf.inc');

var appname = 'Microsoft Azure Service Fabric';

var app_info = vcf::combined_get_app_info(app:appname);

var constraints = [
    { 'min_version': '9.0', 'fixed_version' : '9.0.1526.9590', 'fixed_display': '9.0 CU9 (9.0.1526.9590)' },
    { 'min_version': '9.1', 'fixed_version' : '9.1.1799.9590', 'fixed_display': '9.1 CU4 (9.1.1799.9590)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
