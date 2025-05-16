#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230637);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-50345");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-50345");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - symfony/http-foundation is a module for the Symphony PHP framework which defines an object-oriented layer
    for the HTTP specification. The `Request` class, does not parse URI with special characters the same way
    browsers do. As a result, an attacker can trick a validator relying on the `Request` class to redirect
    users to another domain. The `Request::create` methods now assert the URI does not contain invalid
    characters as defined by https://url.spec.whatwg.org/. This issue has been patched in versions 5.4.46,
    6.4.14, and 7.1.7. Users are advised to upgrade. There are no known workarounds for this vulnerability.
    (CVE-2024-50345)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50345");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": [
     "php-symfony",
     "php-symfony-asset",
     "php-symfony-browser-kit",
     "php-symfony-cache",
     "php-symfony-config",
     "php-symfony-console",
     "php-symfony-css-selector",
     "php-symfony-debug",
     "php-symfony-dependency-injection",
     "php-symfony-dom-crawler",
     "php-symfony-dotenv",
     "php-symfony-error-handler",
     "php-symfony-event-dispatcher",
     "php-symfony-expression-language",
     "php-symfony-filesystem",
     "php-symfony-finder",
     "php-symfony-form",
     "php-symfony-http-client",
     "php-symfony-http-foundation",
     "php-symfony-http-kernel",
     "php-symfony-inflector",
     "php-symfony-intl",
     "php-symfony-ldap",
     "php-symfony-lock",
     "php-symfony-mailer",
     "php-symfony-messenger",
     "php-symfony-mime",
     "php-symfony-options-resolver",
     "php-symfony-process",
     "php-symfony-property-access",
     "php-symfony-property-info",
     "php-symfony-routing",
     "php-symfony-security",
     "php-symfony-security-core",
     "php-symfony-security-csrf",
     "php-symfony-security-guard",
     "php-symfony-security-http",
     "php-symfony-serializer",
     "php-symfony-stopwatch",
     "php-symfony-templating",
     "php-symfony-translation"
    ],
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
       "match": {
        "os_version": "11"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "symfony",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match_one": {
        "os_version": [
         "16.04",
         "18.04"
        ]
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
