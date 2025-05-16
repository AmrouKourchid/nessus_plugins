#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216271);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id("CVE-2025-21117");
  script_xref(name:"IAVA", value:"2025-A-0093");

  script_name(english:"Dell Avamar / AVE < 19.12 privilege elevation (DSA-2025-071)");

  script_set_attribute(attribute:"synopsis", value:
"A backup solution running on the remote host is affected by a privilege elevation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Dell Avamar or Avamar Virtual Edition (AVE)
software running on the remote host is 19.4 prior to 19.12. It is, 
therefore, affected by a privilege elevation vulnerability: 

  - Dell Avamar, version 19.4 or later, contains an access token reuse vulnerability in the AUI. A low privileged local 
    attacker could potentially exploit this vulnerability, leading to fully impersonating the user. (CVE-2025-21117)
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000281275/dsa-2025-071-security-update-for-dell-avamar-for-multiple-component-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b39dc10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Avamar version 19.12 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21117");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_data_store");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_server_virtual_edition");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_avamar_server_detect.nbin", "emc_avamar_server_installed_nix.nbin");
  script_require_keys("installed_sw/EMC Avamar");

  exit(0);
}

include("vcf.inc");

var app_info = vcf::combined_get_app_info(app:'EMC Avamar');

var constraints =[
  {'min_version':'19.4', 'fixed_version':'19.5', 'fixed_display':'19.12'},
  {'min_version':'19.7', 'fixed_version':'19.11', 'fixed_display':'19.12'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
