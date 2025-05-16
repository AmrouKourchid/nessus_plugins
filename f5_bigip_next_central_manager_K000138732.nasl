#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000138732.
#
##

include('compat.inc');

if (description)
{
  script_id(195237);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/13");

  script_cve_id("CVE-2024-21793");
  script_xref(name:"IAVA", value:"2024-A-0273");
  script_xref(name:"CEA-ID", value:"CEA-2024-0008");

  script_name(english:"F5 BIG-IP Next Central Manager 20.0.1 < 20.2.0 OData Injection (K000138732)");

  script_set_attribute(attribute:"synopsis", value:
"F5 BIG-IP Next Central Manager installed on the remote Linux host is affected by an OData Injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Big-IP Next Central Manager installed on the remote Windows host is between 20.0.1 and 20.1.0.
It is, therefore, affected by an OData Injection vulnerability as referenced in the K000138732 advisory. An 
unauthenticated attacker can exploit this vulnerability to execute malicious SQL statements through the BIG-IP NEXT
Central Manager API (URI).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000138732");
  script_set_attribute(attribute:"solution", value:
"Upgrade client software to a version referenced in the advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21793");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:bigip_next_central_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_next_central_manager_nix_installed.nbin");
  script_require_keys("installed_sw/F5 BIG-IP Next Central Manager");

  exit(0);
}

include("vcf.inc");

var app = 'F5 BIG-IP Next Central Manager';

var app_info = vcf::get_app_info(app:app);

var constraints = [
  { 'min_version' : '20.0.1', 'fixed_version' : '20.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
