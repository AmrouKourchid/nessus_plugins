#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47578);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/06");

  script_cve_id("CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370");
  script_bugtraq_id(30494, 30496);
  script_xref(name:"SECUNIA", value:"31379");
  script_xref(name:"SECUNIA", value:"30500");

  script_name(english:"Apache Tomcat < 6.0.18 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat listening on the remote host is prior to 6.0.18. It is,
therefore, affected by multiple vulnerabilities :

  - The remote Apache Tomcat installation is affected by a
    cross-site scripting vulnerability in the
    HttpServletResponse.sendError method due to improper
    validation of user-supplied input to the 'message'
    argument. An attacker can exploit this to execute
    arbitrary script code in a user's browser session.
    (CVE-2008-1232)

  - A cross-site scripting vulnerability exists in the host
    manager application due to improper validation of
    user-supplied input to the 'hostname' parameter. An
    attacker can exploit this to execute arbitrary script
    code in a user's browser session. (CVE-2008-1947)

  - A traversal vulnerability exists when using a
    RequestDispatcher in combination with a servlet or JSP
    that allows a remote attacker to utilize a specially
    crafted request parameter to access protected web
    resources. (CVE-2008-2370)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.18");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.18 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-1232");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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

tomcat_check_version(fixed:"6.0.18", min:"6.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^6(\.0)?$");

