#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209229);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id("CVE-2024-30117");
  script_xref(name:"IAVA", value:"2024-A-0666");

  script_name(english:"HCL BigFix Server 9.5.x < 9.5.25 / 10.0.x < 10.0.12 / 11.0.x < 11.0.3 DLL Hijacking (KB0116659)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of HCL BigFix Server installed on the remote host is 9.5.x prior to 9.5.25, 10.0.x prior to 10.0.12 or
11.x prior to 11.0.3. It is, therefore, affected by a DLL hijacking vulnerability as referenced in the KB0116659 
advisory, where a dynamic search for a prerequisite library could allow the possibility for an attacker to replace the 
correct file under some circumstances.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.hcl-software.com/csm?id=kb_article&sysparm_article=KB0116659
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4a535f4");
  script_set_attribute(attribute:"solution", value:
"Upgrade HCL BigFix Server based upon the guidance specified in KB0116659.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30117");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hcltech:bigfix_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hcl_bigfix_server_win_installed.nbin");
  script_require_keys("installed_sw/HCL BigFix Server", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'HCL BigFix Server', win_local:TRUE);

var constraints = [
  { 'min_version' : '9.5', 'fixed_version' : '9.5.25' },
  { 'min_version' : '10.0', 'fixed_version' : '10.0.12' },
  { 'min_version' : '11.0', 'fixed_version' : '11.0.3' }
];


vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
