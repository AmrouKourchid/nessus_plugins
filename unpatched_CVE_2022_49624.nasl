#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226875);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49624");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49624");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: atlantic: remove aq_nic_deinit()
    when resume aq_nic_deinit() has been called while suspending, so we don't have to call it again on resume.
    Actually, call it again leads to another hang issue when resuming from S3. Jul 8 03:09:44
    u-Precision-7865-Tower kernel: [ 5910.992345] Call Trace: Jul 8 03:09:44 u-Precision-7865-Tower kernel: [
    5910.992346] <TASK> Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992348] aq_nic_deinit+0xb4/0xd0
    [atlantic] Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992356] aq_pm_thaw+0x7f/0x100 [atlantic]
    Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992362] pci_pm_resume+0x5c/0x90 Jul 8 03:09:44
    u-Precision-7865-Tower kernel: [ 5910.992366] ? pci_pm_thaw+0x80/0x80 Jul 8 03:09:44
    u-Precision-7865-Tower kernel: [ 5910.992368] dpm_run_callback+0x4e/0x120 Jul 8 03:09:44
    u-Precision-7865-Tower kernel: [ 5910.992371] device_resume+0xad/0x200 Jul 8 03:09:44
    u-Precision-7865-Tower kernel: [ 5910.992373] async_resume+0x1e/0x40 Jul 8 03:09:44 u-Precision-7865-Tower
    kernel: [ 5910.992374] async_run_entry_fn+0x33/0x120 Jul 8 03:09:44 u-Precision-7865-Tower kernel: [
    5910.992377] process_one_work+0x220/0x3c0 Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992380]
    worker_thread+0x4d/0x3f0 Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992382] ?
    process_one_work+0x3c0/0x3c0 Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992384]
    kthread+0x12a/0x150 Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992386] ?
    set_kthread_struct+0x40/0x40 Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992387]
    ret_from_fork+0x22/0x30 Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992391] </TASK> Jul 8
    03:09:44 u-Precision-7865-Tower kernel: [ 5910.992392] ---[ end trace 1ec8c79604ed5e0d ]--- Jul 8 03:09:44
    u-Precision-7865-Tower kernel: [ 5910.992394] PM: dpm_run_callback(): pci_pm_resume+0x0/0x90 returns -110
    Jul 8 03:09:44 u-Precision-7865-Tower kernel: [ 5910.992397] atlantic 0000:02:00.0: PM: failed to resume
    async: error -110 (CVE-2022-49624)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "linux-buildinfo-5.15.0-1004-intel-iotg",
     "linux-cloud-tools-5.15.0-1004-intel-iotg",
     "linux-headers-5.15.0-1004-intel-iotg",
     "linux-image-unsigned-5.15.0-1004-intel-iotg",
     "linux-image-unsigned-5.15.0-1004-intel-iotg-dbgsym",
     "linux-intel-iotg-cloud-tools-5.15.0-1004",
     "linux-intel-iotg-cloud-tools-common",
     "linux-intel-iotg-headers-5.15.0-1004",
     "linux-intel-iotg-tools-5.15.0-1004",
     "linux-intel-iotg-tools-common",
     "linux-intel-iotg-tools-host",
     "linux-modules-5.15.0-1004-intel-iotg",
     "linux-modules-extra-5.15.0-1004-intel-iotg",
     "linux-tools-5.15.0-1004-intel-iotg"
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
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "kernel",
     "kernel-rt"
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
        "os_version": "9"
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
