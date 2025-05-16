#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228964);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-45769");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-45769");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - A vulnerability was found in Performance Co-Pilot (PCP). This flaw allows an attacker to send specially
    crafted data to the system, which could cause the program to misbehave or crash. (CVE-2024-45769)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45769");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/19");
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
     "libpcp-archive1",
     "libpcp-archive1-dev",
     "libpcp-gui2",
     "libpcp-gui2-dev",
     "libpcp-import-perl",
     "libpcp-import1",
     "libpcp-import1-dev",
     "libpcp-logsummary-perl",
     "libpcp-mmv-perl",
     "libpcp-mmv1",
     "libpcp-mmv1-dev",
     "libpcp-pmda-perl",
     "libpcp-pmda3",
     "libpcp-pmda3-dev",
     "libpcp-trace2",
     "libpcp-trace2-dev",
     "libpcp-web1",
     "libpcp-web1-dev",
     "libpcp3",
     "libpcp3-dev",
     "pcp",
     "pcp-conf",
     "pcp-doc",
     "pcp-export-pcp2elasticsearch",
     "pcp-export-pcp2graphite",
     "pcp-export-pcp2influxdb",
     "pcp-export-pcp2json",
     "pcp-export-pcp2spark",
     "pcp-export-pcp2xlsx",
     "pcp-export-pcp2xml",
     "pcp-export-pcp2zabbix",
     "pcp-export-zabbix-agent",
     "pcp-gui",
     "pcp-import-collectl2pcp",
     "pcp-import-ganglia2pcp",
     "pcp-import-iostat2pcp",
     "pcp-import-mrtg2pcp",
     "pcp-import-sar2pcp",
     "pcp-import-sheet2pcp",
     "pcp-pmda-infiniband",
     "pcp-testsuite",
     "pcp-zeroconf",
     "python3-pcp"
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
