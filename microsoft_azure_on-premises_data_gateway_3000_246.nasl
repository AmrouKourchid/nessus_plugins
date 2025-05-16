#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214114);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/16");

  script_cve_id("CVE-2025-21403");

  script_name(english:"Microsoft Azure On-Premises Data Gateway Information Disclosure (CVE-2025-21403)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Azure On-Premises Data Gateway installed on the remote Windows host is < 3000.246. It is, therefore, 
affected by an information disclosure vulnerability. This vulnerability only affects systems where an SAP HANA data
source is configured for single sign-on (SSO).

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21403
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93b8f757");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Azure On-Premises Data Gateway version 3000.246 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21403");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:azure_on-premises_data_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_on-premises_data_gateway_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Azure On-Premises Data Gateway", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Can't determine if SSO is configured with an SAP HANA data source or not
# https://learn.microsoft.com/en-us/power-bi/connect-data/service-gateway-sso-overview
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Microsoft Azure On-Premises Data Gateway', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '3000.246' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
