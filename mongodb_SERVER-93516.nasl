#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205615);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/25");

  script_cve_id("CVE-2024-6384");
  script_xref(name:"IAVB", value:"2024-B-0115-S");

  script_name(english:"MongoDB 6.0.x < 6.0.13 / 7.0.x < 7.0.11 / 7.3.x < 7.3.3 (SERVER-93516)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of MongoDB installed on the remote host is prior to 6.0.13, 7.0.11, or 7.3.3. It is, therefore, affected by
a vulnerability as referenced in the SERVER-93516 advisory.

  - Hot backup files may be downloaded by underprivileged users, if they are capable of acquiring a unique
    backup identifier. This issue affects MongoDB Enterprise Server v6.0 versions prior to 6.0.16, MongoDB
    Enterprise Server v7.0 versions prior to 7.0.11 and MongoDB Enterprise Server v7.3 versions prior to 7.3.3
    (CVE-2024-6384)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-93516");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB version 6.0.13 / 7.0.11 / 7.3.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mongodb_win_installed.nbin", "mongodb_detect.nasl");
  script_require_ports("installed_sw/MongoDB", "Services/mongodb");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MongoDB');

var constraints = [
  { 'min_version' : '6.0', 'fixed_version' : '6.0.13' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.11' },
  { 'min_version' : '7.3', 'fixed_version' : '7.3.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
