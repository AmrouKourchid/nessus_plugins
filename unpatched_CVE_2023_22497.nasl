#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226257);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-22497");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-22497");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - Netdata is an open source option for real-time infrastructure monitoring and troubleshooting. Each Netdata
    Agent has an automatically generated MACHINE GUID. It is generated when the agent first starts and it is
    saved to disk, so that it will persist across restarts and reboots. Anyone who has access to a Netdata
    Agent has access to its MACHINE_GUID. Streaming is a feature that allows a Netdata Agent to act as parent
    for other Netdata Agents (children), offloading children from various functions (increased data retention,
    ML, health monitoring, etc) that can now be handled by the parent Agent. Configuration is done via
    `stream.conf`. On the parent side, users configure in `stream.conf` an API key (any random UUID can do) to
    provide common configuration for all children using this API key and per MACHINE GUID configuration to
    customize the configuration for each child. The way this was implemented, allowed an attacker to use a
    valid MACHINE_GUID as an API key. This affects all users who expose their Netdata Agents (children) to
    non-trusted users and they also expose to the same users Netdata Agent parents that aggregate data from
    all these children. The problem has been fixed in: Netdata agent v1.37 (stable) and Netdata agent
    v1.36.0-409 (nightly). As a workaround, do not enable streaming by default. If you have previously enabled
    this, it can be disabled. Limiting access to the port on the recipient Agent to trusted child connections
    may mitigate the impact of this vulnerability. (CVE-2023-22497)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22497");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/14");
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
     "netdata",
     "netdata-apache2",
     "netdata-core",
     "netdata-core-no-sse",
     "netdata-plugins-bash",
     "netdata-plugins-nodejs",
     "netdata-plugins-python",
     "netdata-web"
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
