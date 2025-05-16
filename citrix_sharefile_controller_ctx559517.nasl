#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(179932);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/18");

  script_cve_id("CVE-2023-24489");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/09/06");

  script_name(english:"ShareFile Documents Unauthenticated Access (CTX559517)");

  script_set_attribute(attribute:"synopsis", value:
"The Citrix Sharefile Storage Zones Controller instance found
on the remote host is affected by an unauthenticated access vulnerability.");
  script_set_attribute(attribute:"description", value:
"Security issues have been identified in customer-managed Citrix ShareFile storage zone 
controllers. These vulnerabilities, if exploited, would allow an unauthenticated attacker 
to compromise the storage zones controller potentially giving an attacker the ability 
to remotely compromise the customer-managed ShareFile storage zones controller.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX559517");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24489");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:sharefile");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sharefile_controller_win_installed.nbin", "citrix_sharefile_controller_web_detect.nbin");
  script_require_keys("installed_sw/Citrix ShareFile StorageZones Controller");

  exit(0);
}

include('vcf.inc');

var app = 'Citrix ShareFile StorageZones Controller';

var app_info = vcf::get_app_info(app:app);

var constraints = [
  { "min_version" : "1", "max_version": "5.11.23", "fixed_version" : "5.11.24" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
