#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227439);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26783");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26783");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/vmscan: fix a bug calling
    wakeup_kswapd() with a wrong zone index With numa balancing on, when a numa system is running where a numa
    node doesn't have its local memory so it has no managed zones, the following oops has been observed. It's
    because wakeup_kswapd() is called with a wrong zone index, -1. Fixed it by checking the index before
    calling wakeup_kswapd(). > BUG: unable to handle page fault for address: 00000000000033f3 > #PF:
    supervisor read access in kernel mode > #PF: error_code(0x0000) - not-present page > PGD 0 P4D 0 > Oops:
    0000 [#1] PREEMPT SMP NOPTI > CPU: 2 PID: 895 Comm: masim Not tainted 6.6.0-dirty #255 > Hardware name:
    QEMU Standard PC (i440FX + PIIX, 1996), BIOS > rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 >
    RIP: 0010:wakeup_kswapd (./linux/mm/vmscan.c:7812) > Code: (omitted) > RSP: 0000:ffffc90004257d58 EFLAGS:
    00010286 > RAX: ffffffffffffffff RBX: ffff88883fff0480 RCX: 0000000000000003 > RDX: 0000000000000000 RSI:
    0000000000000000 RDI: ffff88883fff0480 > RBP: ffffffffffffffff R08: ff0003ffffffffff R09: ffffffffffffffff
    > R10: ffff888106c95540 R11: 0000000055555554 R12: 0000000000000003 > R13: 0000000000000000 R14:
    0000000000000000 R15: ffff88883fff0940 > FS: 00007fc4b8124740(0000) GS:ffff888827c00000(0000)
    knlGS:0000000000000000 > CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 > CR2: 00000000000033f3 CR3:
    000000026cc08004 CR4: 0000000000770ee0 > DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
    > DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 > PKRU: 55555554 > Call Trace: >
    <TASK> > ? __die > ? page_fault_oops > ? __pte_offset_map_lock > ? exc_page_fault > ? asm_exc_page_fault >
    ? wakeup_kswapd > migrate_misplaced_page > __handle_mm_fault > handle_mm_fault > do_user_addr_fault >
    exc_page_fault > asm_exc_page_fault > RIP: 0033:0x55b897ba0808 > Code: (omitted) > RSP:
    002b:00007ffeefa821a0 EFLAGS: 00010287 > RAX: 000055b89983acd0 RBX: 00007ffeefa823f8 RCX: 000055b89983acd0
    > RDX: 00007fc2f8122010 RSI: 0000000000020000 RDI: 000055b89983acd0 > RBP: 00007ffeefa821a0 R08:
    0000000000000037 R09: 0000000000000075 > R10: 0000000000000000 R11: 0000000000000202 R12: 0000000000000000
    > R13: 00007ffeefa82410 R14: 000055b897ba5dd8 R15: 00007fc4b8340000 > </TASK> (CVE-2024-26783)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26783");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
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
     "btrfs-modules-6.1.0-29-alpha-generic-di",
     "cdrom-core-modules-6.1.0-29-alpha-generic-di",
     "ext4-modules-6.1.0-29-alpha-generic-di",
     "fat-modules-6.1.0-29-alpha-generic-di",
     "isofs-modules-6.1.0-29-alpha-generic-di",
     "jfs-modules-6.1.0-29-alpha-generic-di",
     "kernel-image-6.1.0-29-alpha-generic-di",
     "linux-doc",
     "linux-doc-6.1",
     "linux-headers-6.1.0-29-common",
     "linux-headers-6.1.0-29-common-rt",
     "linux-source",
     "linux-source-6.1",
     "linux-support-6.1.0-29",
     "loop-modules-6.1.0-29-alpha-generic-di",
     "nic-modules-6.1.0-29-alpha-generic-di",
     "nic-shared-modules-6.1.0-29-alpha-generic-di",
     "nic-wireless-modules-6.1.0-29-alpha-generic-di",
     "pata-modules-6.1.0-29-alpha-generic-di",
     "ppp-modules-6.1.0-29-alpha-generic-di",
     "scsi-core-modules-6.1.0-29-alpha-generic-di",
     "scsi-modules-6.1.0-29-alpha-generic-di",
     "scsi-nic-modules-6.1.0-29-alpha-generic-di",
     "serial-modules-6.1.0-29-alpha-generic-di",
     "usb-serial-modules-6.1.0-29-alpha-generic-di",
     "xfs-modules-6.1.0-29-alpha-generic-di"
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
