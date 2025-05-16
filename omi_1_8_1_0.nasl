#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192299);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/30");

  script_cve_id("CVE-2024-21330", "CVE-2024-21334");

  script_name(english:"Security Updates for Microsoft Open Management Infrastructure (March 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Open Management Infrastructure server affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Open Management Infrastructure on the remote host is missing a security update. It is,
therefore, affected by the following vulnerability:

  - A remote code execution vulnerability. An attacker can exploit this to bypass 
    authentication and execute unauthorized arbitrary commands. (CVE-2024-21334)

  - An elevation of privilege vulnerability. An attacker can exploit this to gain
    elevated privileges. (CVE-2024-21330)
   
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21330
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d59d5ef3");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21334
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?644f4a7f");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Open Management Infrastructure.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21334");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:open_management_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_omi_nix_installed.nbin");
  script_require_keys("installed_sw/omi");

  exit(0);
}

include('vcf.inc');

vcf::add_separator('-'); # used in parsing version for vcf
var app_info = vcf::combined_get_app_info(app:'omi');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '1.8.1.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
