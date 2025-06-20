#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88937);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id(
    "CVE-2015-5346",
    "CVE-2015-5351",
    "CVE-2016-0706",
    "CVE-2016-0714",
    "CVE-2016-0763"
  );
  script_bugtraq_id(
    83323,
    83324,
    83326,
    83327,
    83330
  );

  script_name(english:"Apache Tomcat 8.0.0.RC1 < 8.0.32 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.0.32. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_8.0.32_security-8 advisory.

  - Session fixation vulnerability in Apache Tomcat 7.x before 7.0.66, 8.x before 8.0.30, and 9.x before
    9.0.0.M2, when different session settings are used for deployments of multiple versions of the same web
    application, might allow remote attackers to hijack web sessions by leveraging use of a
    requestedSessionSSL field for an unintended request, related to CoyoteAdapter.java and Request.java.
    (CVE-2015-5346)

  - The (1) Manager and (2) Host Manager applications in Apache Tomcat 7.x before 7.0.68, 8.x before 8.0.31,
    and 9.x before 9.0.0.M2 establish sessions and send CSRF tokens for arbitrary new requests, which allows
    remote attackers to bypass a CSRF protection mechanism by using a token. (CVE-2015-5351)

  - Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.68, 8.x before 8.0.31, and 9.x before 9.0.0.M2 does not
    place org.apache.catalina.manager.StatusManagerServlet on the
    org/apache/catalina/core/RestrictedServlets.properties list, which allows remote authenticated users to
    bypass intended SecurityManager restrictions and read arbitrary HTTP requests, and consequently discover
    session ID values, via a crafted web application. (CVE-2016-0706)

  - The session-persistence implementation in Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.68, 8.x before
    8.0.31, and 9.x before 9.0.0.M2 mishandles session attributes, which allows remote authenticated users to
    bypass intended SecurityManager restrictions and execute arbitrary code in a privileged context via a web
    application that places a crafted object in a session. (CVE-2016-0714)

  - The setGlobalContext method in org/apache/naming/factory/ResourceLinkFactory.java in Apache Tomcat 7.x
    before 7.0.68, 8.x before 8.0.31, and 9.x before 9.0.0.M3 does not consider whether
    ResourceLinkFactory.setGlobalContext callers are authorized, which allows remote authenticated users to
    bypass intended SecurityManager restrictions and read or write to arbitrary application data, or cause a
    denial of service (application disruption), via a web application that sets a crafted global context.
    (CVE-2016-0763)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.32
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3861b317");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1713185");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1720658");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1720660");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1722800");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1723506");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1725929");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1726196");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1726203");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.0.32 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5351");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-0714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '8.0.0.RC1', 'max_version' : '8.0.30', 'fixed_version' : '8.0.32' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE}
);
