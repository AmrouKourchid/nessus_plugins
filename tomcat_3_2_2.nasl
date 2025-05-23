#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50448);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/06");

  script_cve_id("CVE-2001-0829");
  script_bugtraq_id(2982);

  script_name(english:"Apache Tomcat 3.x < 3.2.2 JSP Error Condition XSS");
  script_summary(english:"Checks Apache Tomcat Version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Apache Tomcat server is affected by a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The instance of Apache Tomcat 3.x listening on the remote host is
affected by a cross-site scripting vulnerability. An attacker is able
to embed JavaScript into a request for a JSP file creating an error
condition. The request is not sanitized before being displayed on the
application error page."
  );
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-3.html#Fixed_in_Apache_Tomcat_3.2.2");
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mail-archive.com/tomcat-dev@jakarta.apache.org/msg06679.html"
  );
  script_set_attribute(attribute:"solution", value:"Update to Apache Tomcat version 3.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat:3");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

get_install_count(app_name:"Apache Tomcat", exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:"Apache Tomcat", port:port);

vuln_dir = '/';
exploit  = "<script>alert('NESSUS:" + SCRIPT_NAME + "-" + unixtime() + "')</script>";

r = http_send_recv3(
  port         : port,
  method       : 'GET',
  item         : vuln_dir + exploit + ".jsp",
  fetch404     : TRUE,
  exit_on_fail : TRUE
);

if ('<b>Not found request:</b> '+vuln_dir+exploit+".jsp" >< r[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(port:port, items:vuln_dir+exploit+".jsp");
    security_warning(port:port, extra:report);
  }
  else
    security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache Tomcat", port, install["version"]);
