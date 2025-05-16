#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197879);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2024-3372");
  script_xref(name:"IAVB", value:"2024-B-0063-S");

  script_name(english:"MongoDB 5.0.x < 5.0.25 / 6.0.x < 6.0.14 / 7.0.x < 7.0.6 Improper Input Validation (SERVER-85263)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of MongoDB installed on the remote host is prior to 5.0.25, 6.0.14, or 7.0.6. It is, therefore, affected by
a vulnerability as referenced in the SERVER-85263 advisory.

  - Improper validation of certain metadata input may result in the server not correctly serialising BSON.
    This can be performed pre-authentication and may cause unexpected application behavior including
    unavailability of serverStatus responses. This issue affects MongoDB Server v7.0 versions prior to 7.0.6,
    MongoDB Server v6.0 versions prior to 6.0.14 and MongoDB Server v.5.0 versions prior to 5.0.25.
    (CVE-2024-3372)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-85263");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB version 5.0.25 / 6.0.14 / 7.0.6 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mongodb_win_installed.nbin", "mongodb_detect.nasl");
  script_require_keys("installed_sw/MongoDB");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MongoDB');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '5.0', 'fixed_version' : '5.0.25' },
  { 'min_version' : '6.0', 'fixed_version' : '6.0.14' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.6' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
