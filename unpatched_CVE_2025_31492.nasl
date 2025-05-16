#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234195);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id("CVE-2025-31492");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-31492");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - mod_auth_openidc is an OpenID Certified authentication and authorization module for the Apache 2.x HTTP
    server that implements the OpenID Connect Relying Party functionality. Prior to 2.4.16.11, a bug in a
    mod_auth_openidc results in disclosure of protected content to unauthenticated users. The conditions for
    disclosure are an OIDCProviderAuthRequestMethod POST, a valid account, and there mustn't be any
    application-level gateway (or load balancer etc) protecting the server. When you request a protected
    resource, the response includes the HTTP status, the HTTP headers, the intended response (the self-
    submitting form), and the protected resource (with no headers). This is an example of a request for a
    protected resource, including all the data returned. In the case where mod_auth_openidc returns a form, it
    has to return OK from check_userid so as not to go down the error path in httpd. This means httpd will try
    to issue the protected resource. oidc_content_handler is called early, which has the opportunity to
    prevent the normal output being issued by httpd. oidc_content_handler has a number of checks for when it
    intervenes, but it doesn't check for this case, so the handler returns DECLINED. Consequently, httpd
    appends the protected content to the response. The issue has been patched in mod_auth_openidc versions >=
    2.4.16.11. (CVE-2025-31492)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-31492");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31492");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

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
    "name": "libapache2-mod-auth-openidc",
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
         "12",
         "13"
        ]
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
