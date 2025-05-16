#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187129);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id("CVE-2023-39335", "CVE-2023-39337");

  script_name(english:"Ivanti Endpoint Manager Mobile < 11.10.0.4 / 11.11.x < 11.11.0.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Ivanti Endpoint Manager Mobile, formerly MobileIron Core, running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager Mobile, formerly MobileIron Core, running on the remote host is < 11.10.0.4, or
11.11.x < 11.11.0.2. It is, therefore, affected by multiple vulnerabilities.

 - A security vulnerability has been identified allowing an unauthenticated
   threat actor to impersonate any existing user during the device enrollment
   process. This issue poses a significant security risk, as it enables
   unauthorized access and potential misuse of user accounts and resources.
   (CVE-2023-39335)

 - A security vulnerability that allows a threat actor with knowledge of an
   enrolled device identifier to access and extract sensitive information,
   including device and environment configuration details, as well as secrets.
   This vulnerability poses a serious security risk, potentially exposing
   confidential data and system integrity. (CVE-2023-39337)

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  # https://forums.ivanti.com/s/article/CVE-2023-39335
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf18bc2b");
  # https://forums.ivanti.com/s/article/CVE-2023-39337
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af3bbd40");
  # https://forums.ivanti.com/s/article/KB-Authorized-user-obtain-restricted-abilities-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34b6aef2");
  script_set_attribute(attribute:"solution", value:
"Update to Ivanti Endpoint Manager Mobile version 11.10.0.4, 11.11.0.2, 11.12.0.0 or later");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39335");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mobileiron:core");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:mobileiron");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version':'11.10.0.4'},
  { 'min_version':'11.11', 'fixed_version':'11.11.0.2', 'fixed_display':'11.11.0.2 or 11.12.0.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
