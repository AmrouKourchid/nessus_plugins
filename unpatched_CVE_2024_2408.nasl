#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228000);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-2408");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-2408");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - The openssl_private_decrypt function in PHP, when using PKCS1 padding (OPENSSL_PKCS1_PADDING, which is the
    default), is vulnerable to the Marvin Attack unless it is used with an OpenSSL version that includes the
    changes from this pull request: https://github.com/openssl/openssl/pull/13817
    (rsa_pkcs1_implicit_rejection). These changes are part of OpenSSL 3.2 and have also been backported to
    stable versions of various Linux distributions, as well as to the PHP builds provided for Windows since
    the previous release. All distributors and builders should ensure that this version is used to prevent PHP
    from being vulnerable. PHP Windows builds for the versions 8.1.29, 8.2.20 and 8.3.8 and above include
    OpenSSL patches that fix the vulnerability. (CVE-2024-2408)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2408");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
     "libapache2-mod-php7.4",
     "libphp7.4-embed",
     "php7.4",
     "php7.4-bcmath",
     "php7.4-bz2",
     "php7.4-cgi",
     "php7.4-cli",
     "php7.4-common",
     "php7.4-curl",
     "php7.4-dba",
     "php7.4-dev",
     "php7.4-enchant",
     "php7.4-fpm",
     "php7.4-gd",
     "php7.4-gmp",
     "php7.4-imap",
     "php7.4-interbase",
     "php7.4-intl",
     "php7.4-json",
     "php7.4-ldap",
     "php7.4-mbstring",
     "php7.4-mysql",
     "php7.4-odbc",
     "php7.4-opcache",
     "php7.4-pgsql",
     "php7.4-phpdbg",
     "php7.4-pspell",
     "php7.4-readline",
     "php7.4-snmp",
     "php7.4-soap",
     "php7.4-sqlite3",
     "php7.4-sybase",
     "php7.4-tidy",
     "php7.4-xml",
     "php7.4-xmlrpc",
     "php7.4-xsl",
     "php7.4-zip"
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
    "name": "php",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match_one": {
        "os_version": [
         "8",
         "9"
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
