#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230589);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-7347");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-7347");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_mp4_module, which might allow an
    attacker to over-read NGINX worker memory resulting in its termination, using a specially crafted mp4
    file. The issue only affects NGINX if it is built with the ngx_http_mp4_module and the mp4 directive is
    used in the configuration file. Additionally, the attack is possible only if an attacker can trigger the
    processing of a specially crafted mp4 file with the ngx_http_mp4_module. Note: Software versions which
    have reached End of Technical Support (EoTS) are not evaluated. (CVE-2024-7347)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "libnginx-mod-http-geoip",
     "libnginx-mod-http-image-filter",
     "libnginx-mod-http-perl",
     "libnginx-mod-http-xslt-filter",
     "libnginx-mod-mail",
     "libnginx-mod-stream",
     "libnginx-mod-stream-geoip",
     "nginx",
     "nginx-common",
     "nginx-core",
     "nginx-dev",
     "nginx-doc",
     "nginx-extras",
     "nginx-full",
     "nginx-light"
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
        "os_version": "12"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "libnginx-mod-http-auth-pam",
     "libnginx-mod-http-cache-purge",
     "libnginx-mod-http-dav-ext",
     "libnginx-mod-http-echo",
     "libnginx-mod-http-fancyindex",
     "libnginx-mod-http-geoip",
     "libnginx-mod-http-geoip2",
     "libnginx-mod-http-headers-more-filter",
     "libnginx-mod-http-image-filter",
     "libnginx-mod-http-lua",
     "libnginx-mod-http-ndk",
     "libnginx-mod-http-perl",
     "libnginx-mod-http-subs-filter",
     "libnginx-mod-http-uploadprogress",
     "libnginx-mod-http-upstream-fair",
     "libnginx-mod-http-xslt-filter",
     "libnginx-mod-mail",
     "libnginx-mod-nchan",
     "libnginx-mod-rtmp",
     "libnginx-mod-stream",
     "libnginx-mod-stream-geoip",
     "libnginx-mod-stream-geoip2",
     "nginx",
     "nginx-common",
     "nginx-core",
     "nginx-doc",
     "nginx-extras",
     "nginx-full",
     "nginx-light"
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
    "name": "nginx",
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
