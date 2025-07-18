#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81374);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id(
    "CVE-2014-3576",
    "CVE-2014-3600",
    "CVE-2014-3612",
    "CVE-2014-8110"
  );
  script_bugtraq_id(72510, 72511, 72513);

  script_name(english:"Apache ActiveMQ 5.x < 5.10.1 / 5.11.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior
to 5.10.1 / 5.11.0. It is, therefore, potentially affected by multiple
vulnerabilities :

  - An unauthenticated, remote attacker can crash the broker
    listener by sending a packet to the same port that a
    message consumer or product connects to, resulting in a
    denial of service condition. (CVE-2014-3576)

  - An XML external entity (XXE) injection vulnerability 
    exists that is related to XPath selectors. A remote
    attacker can exploit this, via specially crafted XML
    data, to disclose the contents of arbitrary files.
    (CVE-2014-3600)

  - A flaw exists in the LDAPLoginModule of the Java
    Authentication and Authorization Service (JAAS) which
    can be triggered by the use of wildcard operators
    instead of a username or by invalid passwords. A remote
    attacker can exploit this to bypass authentication.
    (CVE-2014-3612)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the web administrative console. (CVE-2014-8110)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://activemq.apache.org/security-advisories.data/CVE-2014-3600-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8309341");
  # http://activemq.apache.org/security-advisories.data/CVE-2014-3612-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3d4e09f");
  # http://activemq.apache.org/security-advisories.data/CVE-2014-8110-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b2b5313");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 5.10.1 / 5.11.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl", "apache_activemq_nix_installed.nbin", "activemq_listen_port_detect.nbin");
  script_require_keys("installed_sw/Apache ActiveMQ");

  exit(0);
}

include('vcf.inc');

var app = vcf::combined_get_app_info(app:'Apache ActiveMQ');

var constraints = [
  {'min_version' : '5.0.0', 'fixed_version' : '5.10.1'}
];

vcf::check_version_and_report(
  app_info:app, 
  constraints:constraints,
  severity:SECURITY_HOLE
);

