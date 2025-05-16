#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208734);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id("CVE-2024-7612");
  script_xref(name:"IAVA", value:"2024-A-0646");

  script_name(english:"Ivanti Endpoint Manager Mobile < 12.0.0.5, 12.1.x < 12.1.0.4 Improper Authorization (CVE-2024-7612)");

  script_set_attribute(attribute:"synopsis", value:
"Ivanti Endpoint Manager Mobile, formerly MobileIron Core, running on the remote host is affected by a remote
unauthenticated api access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager Mobile, formerly MobileIron Core, running on the remote host is prior to 
12.0.0.5 or prior to 12.1.0.4. It is, therefore, affected by an improper authorization vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM-CVE-2024-7612?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6728e2b0");
  script_set_attribute(attribute:"solution", value:
"Update to Ivanti Endpoint Manager Mobile version 12.0.0.5, 12.1.0.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mobileiron:core");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:mobileiron");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version' : '12.0.0.5' },
  { 'min_version' : '12.1.0.0', 'fixed_version' : '12.1.0.4'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
