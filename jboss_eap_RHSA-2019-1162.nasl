#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132311);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_cve_id("CVE-2018-8034", "CVE-2018-10934", "CVE-2018-1000632");
  script_bugtraq_id(104895, 106608);
  script_xref(name:"RHSA", value:"2019:1162");

  script_name(english:"Red Hat JBoss Enterprise Application Platform 6.x < 6.4.22 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat JBoss Enterprise Application Platform installation is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Red Hat JBoss Enterprise Application Platform (EAP) installed
on the remote host is 6.x prior to 6.4.22. It is therefore, affected my multiple
vulnerabilities as referenced in the RHSA-2019:1162 advisory:

  - admin-cli: wildfly-core: Cross-site scripting (XSS) in JBoss Management
    Console (CVE-2018-10934)

  - dom4j: XML Injection in Class: Element. Methods: addElement, addAttribute
    which can impact the integrity of XML documents (CVE-2018-1000632)

  - jbossweb: tomcat: host name verification missing in WebSocket client
    (CVE-2018-8034)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:1162");
  script_set_attribute(attribute:"solution", value:
"Update to Red Hat JBoss Enterprise Application Platform 6.4.22 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8034");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jboss_detect.nbin");
  script_require_keys("installed_sw/JBoss");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras.inc');


vcf::jboss::eap::initialize();
app_info = vcf::jboss::eap::get_app_info();

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '6', 'fixed_version' : '6.4.22' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
