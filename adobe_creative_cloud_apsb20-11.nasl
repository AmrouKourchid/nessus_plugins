#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209507);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2020-3808");

  script_name(english:"Adobe Creative Cloud < 5.1 Arbitrary File Deletion (APSB20-11)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Creative Cloud instance installed on the remote host is affected by an arbitrary file deletion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud installed on the remote Windows host is prior to 5.1. It is, therefore, affected by
a vulnerability as referenced in the APSB20-11 advisory.

  - Creative Cloud Desktop Application versions 5.0 and earlier have a time-of-check to time-of-use (toctou)
    race condition vulnerability. Successful exploitation could lead to arbitrary file deletion.
    (CVE-2020-3808)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb20-11.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10db490c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud version 5.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Creative Cloud", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Creative Cloud', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '5.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
