#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181678);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2021-44791", "CVE-2022-28889");

  script_name(english:"Apache Druid < 0.23.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Druid installed on the remote host is affected by the following vulnerabilities:

  - Certain specially-crafted links result in unescaped URL parameters being sent back in HTML responses. This
    makes it possible to execute reflected XSS attacks. (CVE-2021-44791)

  - The server did not set appropriate headers to prevent clickjacking. Druid 0.23.0 and later prevent
    clickjacking using the Content-Security-Policy header. (CVE-2022-28889)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/lh2kcl4j45q7xj4w6rqf6kwf0mvyp2o6");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/t3nsq4crdr8wqgmj721d2wg6pf26s5cw");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Druid version 0.23.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28889");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-44791");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
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
  {'max_version' : '0.22.1', 'fixed_version' : '0.23.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
