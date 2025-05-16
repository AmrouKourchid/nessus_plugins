#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181481);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/18");

  script_cve_id("CVE-2021-27905", "CVE-2021-29262", "CVE-2021-29943");

  script_name(english:"Apache Solr 7.x < 7.7.4 / 8.x < 8.8.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Solr running on the remote host is 7.x prior to 7.7.4, or 8.x prior to 8.8.2. It is, therefore,
affected by multiple vulnerabilities, including the following: 

  - The ReplicationHandler (normally registered at '/replication' under a Solr core) has a 'masterUrl' (also
    'leaderUrl' alias) parameter that is used to designate another ReplicationHandler on another Solr core to
    replicate index data into the local core. To prevent a SSRF vulnerability, Solr ought to check these
    parameters against a similar configuration it uses for the 'shards' parameter. Prior to this bug getting
    fixed, it did not. (CVE-2021-27905)

  - When starting Apache Solr versions prior to 8.8.2, configured with the SaslZkACLProvider or 
    VMParamsAllAndReadonlyDigestZkACLProvider and no existing security.json znode, if the optional read-only
    user is configured then Solr would not treat that node as a sensitive path and would allow it to be
    readable. Additionally, with any ZkACLProvider, if the security.json is already present, Solr will not
    automatically update the ACLs. (CVE-2021-29262)
    
  - When using ConfigurableInternodeAuthHadoopPlugin for authentication, Apache Solr versions prior to 8.8.2
    would forward/proxy distributed requests using server credentials instead of original client credentials.
    This would result in incorrect authorization resolution on the receiving hosts. (CVE-2021-29943)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://lucene.apache.org/solr/news.html");
  # https://solr.apache.org/security.html#cve-2021-27905-ssrf-vulnerability-with-the-replication-handler
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61459c8d");
  # https://solr.apache.org/security.html#cve-2021-29262-misapplied-zookeeper-acls-can-result-in-leakage-of-configured-authentication-and-authorization-settings
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f89b966c");
  # https://solr.apache.org/security.html#cve-2021-29943-apache-solr-unprivileged-users-may-be-able-to-perform-unauthorized-readwrite-to-collections
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f699570a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Solr version 8.8.2 or later, or apply any of the mitigations provided in the vendor's advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27905");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:solr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solr_detect.nbin");
  script_require_keys("installed_sw/Apache Solr");

  exit(0);
}

include('vcf.inc');

var app = 'Apache Solr';

var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version': '7.0.0', 'max_version': '7.7.3', 'fixed_version': '8.8.2'},
  {'min_version': '8.0.0', 'fixed_version': '8.8.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
