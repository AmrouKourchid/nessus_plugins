#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181677);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2021-26920");

  script_name(english:"Apache Druid < 0.21.0 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP
InputSource allows authenticated users to read data from other sources than intended, such as the local file system,
with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly,
since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users
interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the
Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP
InputSource.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.apache.org/thread.html/r29e45561343cc5cf7d3290ee0b0e94e565faab19c20d022df9b5e29c%40%3Cdev.druid.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2d9eac4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Druid version 0.21.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26920");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:druid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_druid_detect.nbin");
  script_require_keys("installed_sw/Apache Druid");

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:8081);
var app_info = vcf::get_app_info(app:'Apache Druid', port:port, service:TRUE);

var constraints = [
  {'fixed_version' : '0.21.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
