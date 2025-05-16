#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210584);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/11");

  script_cve_id("CVE-2024-51504");
  script_xref(name:"IAVB", value:"2024-B-0169");

  script_name(english:"Apache ZooKeeper  3.9.x < 3.9.3 Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache ZooKeeper server is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ZooKeeper listening on the remote host is 3.9.x prior to 3.9.3. It is, therefore, 
affected by an authentication bypass vulnerability:

  - When using IPAuthenticationProvider in ZooKeeper Admin Server there is a possibility of Authentication 
    Bypass by Spoofing -- this only impacts IP based authentication implemented in ZooKeeper Admin Server. 
    Default configuration of client's IP address detection in IPAuthenticationProvider, which uses HTTP 
    request headers, is weak and allows an attacker to bypass authentication via spoofing client's IP address 
    in request headers. Default configuration honors X- Forwarded-For HTTP header to read client's IP 
    address. X-Forwarded-For request header is mainly used by proxy servers to identify the client and can be 
    easily spoofed by an attacker pretending that the request comes from a different IP address. Admin Server 
    commands, such as snapshot and restore arbitrarily can be executed on successful exploitation which could 
    potentially lead to information leakage or service availability issues. Users are recommended to upgrade 
    to version 3.9.3, which fixes this issue. (CVE-2024-51504)
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://zookeeper.apache.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Update to Apache ZooKeeper 3.9.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-51504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

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
  { 'min_version' : '3.9.0', 'fixed_version' : '3.9.3' } 
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
