#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192396);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id("CVE-2024-23944");
  script_xref(name:"IAVB", value:"2024-B-0025-S");

  script_name(english:"Apache ZooKeeper  3.6.x <= 3.7.2, 3.8.x < 3.8.4, 3.9.x < 3.9.2 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache ZooKeeper server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ZooKeeper listening on the remote host is 3.6. up to 3.7.2, 3.8.x prior to 3.8.4 or 3.9.x prior 
to 3.9.2. It is, therefore, affected by the following:

  - Information disclosure in persistent watchers handling in Apache ZooKeeper due to missing ACL check. It 
    allows an attacker to monitor child znodes by attaching a persistent watcher (addWatch command) to a 
    parent which the attacker has already access to. ZooKeeper server doesn't do ACL check when the 
    persistent watcher is triggered and as a consequence, the full path of znodes that a watch event gets 
    triggered upon is exposed to the owner of the watcher. It's important to note that only the path is 
    exposed by this vulnerability, not the data of znode, but since znode path can contain sensitive 
    information like user name or login ID, this issue is potentially critical. (CVE-2024-23944)
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://zookeeper.apache.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Update to Apache ZooKeeper 3.8.3, 3.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an in-depth analysis by Tenable.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:zookeeper");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_zookeeper_detect.nasl");
  script_require_keys("installed_sw/Apache Zookeeper");
  script_require_ports("Services/zookeeper", 2181);

  exit(0);
}

include("vcf.inc");

var port = get_service(svc:"zookeeper", default:2181, exit_on_fail:TRUE);
var app_info = vcf::get_app_info(app:"Apache Zookeeper", port:port, service:TRUE);

var constraints = [
  { 'min_version' : '3.6.0', 'max_version' : '3.7.2', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '3.8.0', 'fixed_version' : '3.8.4' },
  { 'min_version' : '3.9.0', 'fixed_version' : '3.9.2' } 
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
