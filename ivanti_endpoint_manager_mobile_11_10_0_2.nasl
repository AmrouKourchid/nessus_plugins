#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178783);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2023-35078");
  script_xref(name:"CEA-ID", value:"CEA-2023-0036");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/15");
  script_xref(name:"IAVA", value:"2023-A-0383-S");

  script_name(english:"Ivanti Endpoint Manager Mobile < 11.8.1.1 / 11.9.x < 11.9.1.1 / 11.10.x < 11.10.0.2 Remote Unauthenticated API Access (CVE-2023-35078)");

  script_set_attribute(attribute:"synopsis", value:
"Ivanti Endpoint Manager Mobile, formerly MobileIron Core, running on the remote host is affected by a remote
unauthenticated api access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager Mobile, formerly MobileIron Core, running on the remote host is < 11.8.1.1,
11.9.x < 11.9.1.1, or 11.10.x < 11.10.0.2. It is, therefore, affected by an undisclosed unauthenticated API access
vulnerability.

Note that Nessus has not tested for the temporary RPM-based mitigations that Ivanti has provided for unsupported EPMM
versions.

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  # https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d43cfc54");
  # https://forums.ivanti.com/s/article/KB-Remote-unauthenticated-API-access-vulnerability-CVE-2023-35078
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1598cf70");
  script_set_attribute(attribute:"solution", value:
"Update to Ivanti Endpoint Manager Mobile version 11.8.1.1, 11.9.1.1, or 11.10.0.2 or later");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35078");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mobileiron:core");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:mobileiron");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mobileiron_core_detect.nbin");
  script_require_keys("installed_sw/MobileIron Core");

  exit(0);
}

include('vcf.inc');

var app_name = 'MobileIron Core';
var app_info = NULL;

if (report_paranoia < 2)
  app_info = vcf::get_app_info(app:app_name);
else
  app_info = vcf::combined_get_app_info(app:app_name);

var constraints = [
  { 'fixed_version':'11.8', 'fixed_display':'11.8.1.1'}, 
  { 'min_version':'11.8', 'fixed_version':'11.8.1.1'},
  { 'min_version':'11.9', 'fixed_version':'11.9.1.1'},
  { 'min_version':'11.10', 'fixed_version':'11.10.0.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
