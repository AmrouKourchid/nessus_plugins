#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227161);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-4806");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-4806");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - A flaw was found in glibc. In an extremely rare situation, the getaddrinfo function may access memory that
    has been freed, resulting in an application crash. This issue is only exploitable when a NSS module
    implements only the _nss_*_gethostbyname2_r and _nss_*_getcanonname_r hooks without implementing the
    _nss_*_gethostbyname3_r hook. The resolved name should return a large number of IPv6 and IPv4, and the
    call to the getaddrinfo function should have the AF_INET6 address family with AI_CANONNAME, AI_ALL and
    AI_V4MAPPED as flags. (CVE-2023-4806)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4806");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/18");
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
     "glibc-doc",
     "glibc-source",
     "libc-bin",
     "libc-dev-bin",
     "libc-devtools",
     "libc-l10n",
     "libc0.1",
     "libc0.1-dbg",
     "libc0.1-dev",
     "libc0.1-dev-i386",
     "libc0.1-i386",
     "libc0.1-udeb",
     "libc0.3",
     "libc0.3-dbg",
     "libc0.3-dev",
     "libc0.3-udeb",
     "libc0.3-xen",
     "libc6",
     "libc6-amd64",
     "libc6-dbg",
     "libc6-dev",
     "libc6-dev-amd64",
     "libc6-dev-i386",
     "libc6-dev-mips32",
     "libc6-dev-mips64",
     "libc6-dev-mipsn32",
     "libc6-dev-powerpc",
     "libc6-dev-ppc64",
     "libc6-dev-s390",
     "libc6-dev-sparc",
     "libc6-dev-sparc64",
     "libc6-dev-x32",
     "libc6-i386",
     "libc6-mips32",
     "libc6-mips64",
     "libc6-mipsn32",
     "libc6-powerpc",
     "libc6-ppc64",
     "libc6-s390",
     "libc6-sparc",
     "libc6-sparc64",
     "libc6-udeb",
     "libc6-x32",
     "libc6-xen",
     "libc6.1",
     "libc6.1-alphaev67",
     "libc6.1-dbg",
     "libc6.1-dev",
     "libc6.1-udeb",
     "locales",
     "locales-all",
     "nscd"
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
    "name": [
     "compat-glibc",
     "glibc"
    ],
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
       "match": {
        "os_version": "7"
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
