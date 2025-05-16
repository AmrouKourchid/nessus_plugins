#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193949);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/29");

  script_cve_id("CVE-2024-21400");

  script_name(english:"Microsoft Azure CLI Confcom Extension < 0.3.3 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A Microsoft Azure CLI extension installed on the remote Windows host is affected by a privilege escalation vulnerability");
  script_set_attribute(attribute:"description", value:
"An elevation of privilege vulnerability exists in Microsoft Azure CLI Confcom extension. An unauthenticated, remote
attacker can exploit this, to gain elevated privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/cli/azure/confcom?view=azure-cli-latest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8442730");
  # https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21400
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d289ad0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Azure Command-Line Interface (CLI) Confcom Extension version 0.3.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21400");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_command-line_interface");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("azure_cli_extensions_win_detect.nbin");
  script_require_keys("installed_sw/Microsoft Azure CLI/extensions");

  exit(0);
}

include('vcf.inc');

var extensions = deserialize(get_kb_item_or_exit('installed_sw/Microsoft Azure CLI/extensions'));

var extension = 'confcom';
if (empty_or_null(extensions[extension])) audit(AUDIT_LISTEN_NOT_VULN, extension);

var app_info = {
  'version'      : extensions[extension],
  'parsed_version': vcf::parse_version(extensions[extension]),
  'app'         : 'Microsoft Azure CLI Confcom Extension'
};

var constraints = [
  { 'fixed_version' : '0.3.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
