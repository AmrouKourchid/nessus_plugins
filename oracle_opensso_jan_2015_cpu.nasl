#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81023);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-2014-6592", "CVE-2015-0389");
  script_bugtraq_id(72161, 72199);

  script_name(english:"Oracle OpenSSO SAML Multiple Vulnerabilities (January 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple unspecified vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle OpenSSO component in the Oracle Fusion Middleware
install is missing a vendor-supplied security update. It is,
therefore, affected by multiple unspecified vulnerabilities in the
SAML subcomponent.

Note that these vulnerabilities are unspecified by Oracle but appear
to be cross-site scripting vulnerabilities.");
  # https://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75c6cafb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0389");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_opensso_detect.nbin");
  script_require_keys("www/oracle_opensso");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 7001, 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

appname = "Oracle OpenSSO";
port = get_http_port(default:7001);

install = get_install_from_kb(appname:"oracle_opensso", port:port, exit_on_fail:TRUE);
dir = install['dir'];

install_url = build_url(port:port, qs:dir);

uri = "/saml2/jsp/validate.jsp";
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : uri,
  qs       : "idpMetaAlias=" + xss + "&spEntity=url&realmName=realm",
  pass_str : "Make sure the values realm and " + xss + " are correct",
  pass_re  : "SSO Validation Test"
);

if (!exploit) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
