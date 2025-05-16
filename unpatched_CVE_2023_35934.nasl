#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227081);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-35934");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-35934");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - yt-dlp is a command-line program to download videos from video sites. During file downloads, yt-dlp or the
    external downloaders that yt-dlp employs may leak cookies on HTTP redirects to a different host, or leak
    them when the host for download fragments differs from their parent manifest's host. This vulnerable
    behavior is present in yt-dlp prior to 2023.07.06 and nightly 2023.07.06.185519. All native and external
    downloaders are affected, except for `curl` and `httpie` (version 3.1.0 or later). At the file download
    stage, all cookies are passed by yt-dlp to the file downloader as a `Cookie` header, thereby losing their
    scope. This also occurs in yt-dlp's info JSON output, which may be used by external tools. As a result,
    the downloader or external tool may indiscriminately send cookies with requests to domains or paths for
    which the cookies are not scoped. yt-dlp version 2023.07.06 and nightly 2023.07.06.185519 fix this issue
    by removing the `Cookie` header upon HTTP redirects; having native downloaders calculate the `Cookie`
    header from the cookiejar, utilizing external downloaders' built-in support for cookies instead of passing
    them as header arguments, disabling HTTP redirectiong if the external downloader does not have proper
    cookie support, processing cookies passed as HTTP headers to limit their scope, and having a separate
    field for cookies in the info dict storing more information about scoping Some workarounds are available
    for those who are unable to upgrade. Avoid using cookies and user authentication methods. While extractors
    may set custom cookies, these usually do not contain sensitive information. Alternatively, avoid using
    `--load-info-json`. Or, if authentication is a must: verify the integrity of download links from unknown
    sources in browser (including redirects) before passing them to yt-dlp; use `curl` as external downloader,
    since it is not impacted; and/or avoid fragmented formats such as HLS/m3u8, DASH/mpd and ISM.
    (CVE-2023-35934)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/06");
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
    "name": [
     "youtube-dl",
     "yt-dlp"
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
    "name": "youtube-dl",
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
