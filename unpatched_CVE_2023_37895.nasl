#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227103);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-37895");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-37895");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - Java object deserialization issue in Jackrabbit webapp/standalone on all platforms allows attacker to
    remotely execute code via RMIVersions up to (including) 2.20.10 (stable branch) and 2.21.17 (unstable
    branch) use the component commons-beanutils, which contains a class that can be used for remote code
    execution over RMI. Users are advised to immediately update to versions 2.20.11 or 2.21.18. Note that
    earlier stable branches (1.0.x .. 2.18.x) have been EOLd already and do not receive updates anymore. In
    general, RMI support can expose vulnerabilities by the mere presence of an exploitable class on the
    classpath. Even if Jackrabbit itself does not contain any code known to be exploitable anymore, adding
    other components to your server can expose the same type of problem. We therefore recommend to disable RMI
    access altogether (see further below), and will discuss deprecating RMI support in future Jackrabbit
    releases. How to check whether RMI support is enabledRMI support can be over an RMI-specific TCP port, and
    over an HTTP binding. Both are by default enabled in Jackrabbit webapp/standalone. The native RMI protocol
    by default uses port 1099. To check whether it is enabled, tools like netstat can be used to check. RMI-
    over-HTTP in Jackrabbit by default uses the path /rmi. So when running standalone on port 8080, check
    whether an HTTP GET request on localhost:8080/rmi returns 404 (not enabled) or 200 (enabled). Note that
    the HTTP path may be different when the webapp is deployed in a container as non-root context, in which
    case the prefix is under the user's control. Turning off RMIFind web.xml (either in JAR/WAR file or in
    unpacked web application folder), and remove the declaration and the mapping definition for the
    RemoteBindingServlet: <servlet> <servlet-name>RMI</servlet-name> <servlet-
    class>org.apache.jackrabbit.servlet.remote.RemoteBindingServlet</servlet-class> </servlet> <servlet-
    mapping> <servlet-name>RMI</servlet-name> <url-pattern>/rmi</url-pattern> </servlet-mapping> Find the
    bootstrap.properties file (in $REPOSITORY_HOME), and set rmi.enabled=false and also remove rmi.host
    rmi.port rmi.url-pattern If there is no file named bootstrap.properties in $REPOSITORY_HOME, it is located
    somewhere in the classpath. In this case, place a copy in $REPOSITORY_HOME and modify it as explained.
    (CVE-2023-37895)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-37895");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": "libjackrabbit-java",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match_one": {
        "os_version": [
         "11",
         "12"
        ]
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
