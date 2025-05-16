#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74248);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id(
    "CVE-2014-0075",
    "CVE-2014-0095",
    "CVE-2014-0096",
    "CVE-2014-0099"
  );
  script_bugtraq_id(
    67667,
    67668,
    67671,
    67673
  );

  script_name(english:"Apache Tomcat 8.0.0-RC1 < 8.0.5 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.0.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_8.0.5_security-8 advisory.

  - Integer overflow in the parseChunkHeader function in
    java/org/apache/coyote/http11/filters/ChunkedInputFilter.java in Apache Tomcat before 6.0.40, 7.x before
    7.0.53, and 8.x before 8.0.4 allows remote attackers to cause a denial of service (resource consumption)
    via a malformed chunk size in chunked transfer coding of a request during the streaming of data.
    (CVE-2014-0075)

  - java/org/apache/coyote/ajp/AbstractAjpProcessor.java in Apache Tomcat 8.x before 8.0.4 allows remote
    attackers to cause a denial of service (thread consumption) by using a Content-Length: 0 AJP request to
    trigger a hang in request processing. (CVE-2014-0095)

  - java/org/apache/catalina/servlets/DefaultServlet.java in the default servlet in Apache Tomcat before
    6.0.40, 7.x before 7.0.53, and 8.x before 8.0.4 does not properly restrict XSLT stylesheets, which allows
    remote attackers to bypass security-manager restrictions and read arbitrary files via a crafted web
    application that provides an XML external entity declaration in conjunction with an entity reference,
    related to an XML External Entity (XXE) issue. (CVE-2014-0096)

  - Integer overflow in java/org/apache/tomcat/util/buf/Ascii.java in Apache Tomcat before 6.0.40, 7.x before
    7.0.53, and 8.x before 8.0.4, when operated behind a reverse proxy, allows remote attackers to conduct
    HTTP request smuggling attacks via a crafted Content-Length HTTP header. (CVE-2014-0099)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1519838");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1578337");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1578392");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1578610");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1578611");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1578812");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.0.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0099");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('vcf_extras.inc');

vcf::tomcat::initialize();
var app_info = vcf::combined_get_app_info(app:'Apache Tomcat');

var constraints = [
  { 'min_version' : '8.0.0-RC1', 'max_version' : '8.0.3', 'fixed_version' : '8.0.5' }
];

vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
