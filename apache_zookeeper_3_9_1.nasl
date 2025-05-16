#%NASL_MIN_LEVEL 80900
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(183520);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/23");

  script_cve_id("CVE-2023-44981");

  script_name(english:"Apache ZooKeeper  3.7.x < 3.7.2, 3.8.x < 3.8.3, 3.9.x < 3.9.1 Authorization Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache ZooKeeper server is affected by an authorization bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ZooKeeper listening on the remote host is prior to 3.7.2, 3.8.x prior to 3.8.3 or 3.9.x prior 
to 3.9.1. It is, therefore, affected by the following:

  - Authorization Bypass Through User-Controlled Key vulnerability in Apache ZooKeeper. If SASL Quorum Peer 
    authentication is enabled in ZooKeeper (quorum.auth.enableSasl=true), the authorization is done by verifying 
    that the instance part in SASL authentication ID is listed in zoo.cfg server list. The instance part in SASL 
    auth ID is optional and if it's missing, like 'eve@EXAMPLE.COM', the authorization check will be skipped. As 
    a result an arbitrary endpoint could join the cluster and begin propagating counterfeit changes to the leader, 
    essentially giving it complete read-write access to the data tree. Quorum Peer authentication is not enabled 
    by default. (CVE-2023-44981)
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://zookeeper.apache.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Update to Apache ZooKeeper 3.7.2, 3.8.3, 3.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:zookeeper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_zookeeper_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/zookeeper", 2181);

  exit(0);
}

include("vcf.inc");

var port = get_service(svc:"zookeeper", default:2181, exit_on_fail:TRUE);
var app_info = vcf::get_app_info(app:"Apache Zookeeper", port:port, service:TRUE);

# We can't check whether SASL Quorum Peer authentication is enabled
# so paranoid report. 
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  { "min_version" : "0.0", "fixed_version" : "3.7.2" },
  { "min_version" : "3.8.0", "fixed_version" : "3.8.3" },
  { "min_version" : "3.9.0", "fixed_version" : "3.9.1" },
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);