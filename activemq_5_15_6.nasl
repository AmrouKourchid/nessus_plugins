#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117483);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id("CVE-2018-11775");
  script_bugtraq_id(105335);

  script_name(english:"Apache ActiveMQ Client 5.x < 5.15.6 TLS Hostname Verification Weakness");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by an
man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x
prior to 5.15.6. It is, therefore, affected by a flaw related to TLS
hostname verification and ActiveMQ Client that allows
man-in-the-middle attacks.");
  # https://activemq.apache.org/security-advisories.data/CVE-2018-11775-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2be62caa");
  script_set_attribute(attribute:"see_also", value:"https://activemq.apache.org/activemq-5156-release.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.15.6 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11775");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl", "apache_activemq_nix_installed.nbin", "activemq_listen_port_detect.nbin");
  script_require_keys("installed_sw/Apache ActiveMQ");

  exit(0);
}

include("vcf.inc");

# Client has the problem

var app = vcf::combined_get_app_info(app:'Apache ActiveMQ');

var constraints = [
  { "min_version" : "5.0", "fixed_version" : "5.15.6" }
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING);
