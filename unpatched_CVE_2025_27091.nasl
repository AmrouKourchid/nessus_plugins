#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231459);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2025-27091");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-27091");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - OpenH264 is a free license codec library which supports H.264 encoding and decoding. A vulnerability in
    the decoding functions of OpenH264 codec library could allow a remote, unauthenticated attacker to trigger
    a heap overflow. This vulnerability is due to a race condition between a Sequence Parameter Set (SPS)
    memory allocation and a subsequent non Instantaneous Decoder Refresh (non-IDR) Network Abstraction Layer
    (NAL) unit memory usage. An attacker could exploit this vulnerability by crafting a malicious bitstream
    and tricking a victim user into processing an arbitrary video containing the malicious bistream. An
    exploit could allow the attacker to cause an unexpected crash in the victim's user decoding client and,
    possibly, perform arbitrary commands on the victim's host by abusing the heap overflow. This vulnerability
    affects OpenH264 2.5.0 and earlier releases. Both Scalable Video Coding (SVC) mode and Advanced Video
    Coding (AVC) mode are affected by this vulnerability. OpenH264 software releases 2.6.0 and later contained
    the fix for this vulnerability. Users are advised to upgrade. There are no known workarounds for this
    vulnerability. ### For more information If you have any questions or comments about this advisory: * [Open
    an issue in cisco/openh264](https://github.com/cisco/openh264/issues) * Email Cisco Open Source Security
    ([oss-security@cisco.com](mailto:oss-security@cisco.com)) and Cisco PSIRT
    ([psirt@cisco.com](mailto:psirt@cisco.com)) ### Credits: * **Research:** Octavian Guzu and Andrew Calvano
    of Meta * **Fix ideation:** Philipp Hancke and Shyam Sadhwani of Meta * **Fix implementation:** Benzheng
    Zhang (@BenzhengZhang) * **Release engineering:** Benzheng Zhang (@BenzhengZhang) (CVE-2025-27091)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "openh264",
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
         "22.04",
         "24.04",
         "24.10"
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
