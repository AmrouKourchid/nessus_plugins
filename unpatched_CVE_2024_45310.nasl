#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229501);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-45310");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-45310");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - runc is a CLI tool for spawning and running containers according to the OCI specification. runc 1.1.13 and
    earlier, as well as 1.2.0-rc2 and earlier, can be tricked into creating empty files or directories in
    arbitrary locations in the host filesystem by sharing a volume between two containers and exploiting a
    race with `os.MkdirAll`. While this could be used to create empty files, existing files would not be
    truncated. An attacker must have the ability to start containers using some kind of custom volume
    configuration. Containers using user namespaces are still affected, but the scope of places an attacker
    can create inodes can be significantly reduced. Sufficiently strict LSM policies (SELinux/Apparmor) can
    also in principle block this attack -- we suspect the industry standard SELinux policy may restrict this
    attack's scope but the exact scope of protection hasn't been analysed. This is exploitable using runc
    directly as well as through Docker and Kubernetes. The issue is fixed in runc v1.1.14 and v1.2.0-rc3. Some
    workarounds are available. Using user namespaces restricts this attack fairly significantly such that the
    attacker can only create inodes in directories that the remapped root user/group has write access to.
    Unless the root user is remapped to an actual user on the host (such as with rootless containers that
    don't use `/etc/sub[ug]id`), this in practice means that an attacker would only be able to create inodes
    in world-writable directories. A strict enough SELinux or AppArmor policy could in principle also restrict
    the scope if a specific label is applied to the runc runtime, though neither the extent to which the
    standard existing policies block this attack nor what exact policies are needed to sufficiently restrict
    this attack have been thoroughly tested. (CVE-2024-45310)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45310");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/03");
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
     "golang-github-opencontainers-runc-dev",
     "runc"
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
