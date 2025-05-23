#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46753);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/06");

  script_cve_id(
    "CVE-2008-5515",
    "CVE-2009-0033",
    "CVE-2009-0580",
    "CVE-2009-0781",
    "CVE-2009-0783"
  );
  script_bugtraq_id(
    35193,
    35196,
    35263,
    35416
  );
  script_xref(name:"SECUNIA", value:"35326");
  script_xref(name:"SECUNIA", value:"35344");

  script_name(english:"Apache Tomcat < 4.1.40 / 5.5.28 / 6.0.20 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
server listening on the remote host is prior to 4.1.40, 5.5.28, or
6.0.20. It is, therefore, affected by the following vulnerabilities :

  - The remote server is affected by a directory traversal
    vulnerability if a RequestDispatcher obtained from a
    Request object is used. A specially crafted value for a
    request parameter can be used to access potentially
    sensitive configuration files or other files, e.g.,
    files in the WEB-INF directory. (CVE-2008-5515)

  - The remote server is affected by a denial of service
    vulnerability if configured to use the Java AJP
    connector. An attacker can send a malicious request with
    invalid headers which causes the AJP connector to be put
    into an error state for a short time. This behavior can
    be used as a denial of service attack. (CVE-2009-0033)

  - The remote server is affected by a username enumeration
    vulnerability if configured to use FORM authentication
    along with the 'MemoryRealm', 'DataSourceRealm', or
    'JDBCRealm' authentication realms. (CVE-2009-0580)

  - The remote server is affected by a script injection
    vulnerability if the example JSP application,
    'cal2.jsp', is installed. An unauthenticated, remote
    attacker can exploit this issue to inject arbitrary HTML
    or script code into a user's browser to be executed
    within the security context of the affected site.
    (CVE-2009-0781)

  - The remote server is vulnerable to unauthorized
    modification of 'web.xml', 'context.xml', or TLD files
    of arbitrary web applications. This vulnerability allows
    the XML parser, used to process the XML and TLD files,
    to be replaced. (CVE-2009-0783)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/504125");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.40");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.28");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 4.1.40 / 5.5.28 / 6.0.20 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0580");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"D2ExploitPack");
  script_cwe_id(20, 22, 79, 200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:6");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:make_list("6.0.20", "5.5.28", "4.1.40"), severity:SECURITY_WARNING, all_vuln_ceiling: "4.1.0", granularity_regex:"^(6(\.0)?|5(\.5)?|4(\.1)?)$");
