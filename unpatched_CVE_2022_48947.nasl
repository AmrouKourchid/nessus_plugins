#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225192);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48947");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48947");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: Bluetooth: L2CAP: Fix u8 overflow By
    keep sending L2CAP_CONF_REQ packets, chan->num_conf_rsp increases multiple times and eventually it will
    wrap around the maximum number (i.e., 255). This patch prevents this by adding a boundary check with
    L2CAP_MAX_CONF_RSP Btmon log: Bluetooth monitor ver 5.64 = Note: Linux version 6.1.0-rc2 (x86_64) 0.264594
    = Note: Bluetooth subsystem version 2.22 0.264636 @ MGMT Open: btmon (privileged) version 1.22 {0x0001}
    0.272191 = New Index: 00:00:00:00:00:00 (Primary,Virtual,hci0) [hci0] 13.877604 @ RAW Open: 9496
    (privileged) version 2.22 {0x0002} 13.890741 = Open Index: 00:00:00:00:00:00 [hci0] 13.900426 (...) > ACL
    Data RX: Handle 200 flags 0x00 dlen 1033 #32 [hci0] 14.273106 invalid packet size (12 != 1033) 08 00 01 00
    02 01 04 00 01 10 ff ff ............ > ACL Data RX: Handle 200 flags 0x00 dlen 1547 #33 [hci0] 14.273561
    invalid packet size (14 != 1547) 0a 00 01 00 04 01 06 00 40 00 00 00 00 00 ........@..... > ACL Data RX:
    Handle 200 flags 0x00 dlen 2061 #34 [hci0] 14.274390 invalid packet size (16 != 2061) 0c 00 01 00 04 01 08
    00 40 00 00 00 00 00 00 04 ........@....... > ACL Data RX: Handle 200 flags 0x00 dlen 2061 #35 [hci0]
    14.274932 invalid packet size (16 != 2061) 0c 00 01 00 04 01 08 00 40 00 00 00 07 00 03 00
    ........@....... = bluetoothd: Bluetooth daemon 5.43 14.401828 > ACL Data RX: Handle 200 flags 0x00 dlen
    1033 #36 [hci0] 14.275753 invalid packet size (12 != 1033) 08 00 01 00 04 01 04 00 40 00 00 00
    ........@... (CVE-2022-48947)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48947");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

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
    "name": "kernel-rt",
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
