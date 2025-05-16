#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225383);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48758");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48758");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: bnx2fc: Flush destroy_work queue
    before calling bnx2fc_interface_put() The bnx2fc_destroy() functions are removing the interface before
    calling destroy_work. This results multiple WARNings from sysfs_remove_group() as the controller rport
    device attributes are removed too early. Replace the fcoe_port's destroy_work queue. It's not needed. The
    problem is easily reproducible with the following steps. Example: $ dmesg -w & $ systemctl enable --now
    fcoe $ fipvlan -s -c ens2f1 $ fcoeadm -d ens2f1.802 [ 583.464488] host2: libfc: Link down on port (7500a1)
    [ 583.472651] bnx2fc: 7500a1 - rport not created Yet!! [ 583.490468] ------------[ cut here ]------------
    [ 583.538725] sysfs group 'power' not found for kobject 'rport-2:0-0' [ 583.568814] WARNING: CPU: 3 PID:
    192 at fs/sysfs/group.c:279 sysfs_remove_group+0x6f/0x80 [ 583.607130] Modules linked in: dm_service_time
    8021q garp mrp stp llc bnx2fc cnic uio rpcsec_gss_krb5 auth_rpcgss nfsv4 ... [ 583.942994] CPU: 3 PID: 192
    Comm: kworker/3:2 Kdump: loaded Not tainted 5.14.0-39.el9.x86_64 #1 [ 583.984105] Hardware name: HP
    ProLiant DL120 G7, BIOS J01 07/01/2013 [ 584.016535] Workqueue: fc_wq_2 fc_rport_final_delete
    [scsi_transport_fc] [ 584.050691] RIP: 0010:sysfs_remove_group+0x6f/0x80 [ 584.074725] Code: ff 5b 48 89
    ef 5d 41 5c e9 ee c0 ff ff 48 89 ef e8 f6 b8 ff ff eb d1 49 8b 14 24 48 8b 33 48 c7 c7 ... [ 584.162586]
    RSP: 0018:ffffb567c15afdc0 EFLAGS: 00010282 [ 584.188225] RAX: 0000000000000000 RBX: ffffffff8eec4220 RCX:
    0000000000000000 [ 584.221053] RDX: ffff8c1586ce84c0 RSI: ffff8c1586cd7cc0 RDI: ffff8c1586cd7cc0 [
    584.255089] RBP: 0000000000000000 R08: 0000000000000000 R09: ffffb567c15afc00 [ 584.287954] R10:
    ffffb567c15afbf8 R11: ffffffff8fbe7f28 R12: ffff8c1486326400 [ 584.322356] R13: ffff8c1486326480 R14:
    ffff8c1483a4a000 R15: 0000000000000004 [ 584.355379] FS: 0000000000000000(0000) GS:ffff8c1586cc0000(0000)
    knlGS:0000000000000000 [ 584.394419] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 584.421123] CR2:
    00007fe95a6f7840 CR3: 0000000107674002 CR4: 00000000000606e0 [ 584.454888] Call Trace: [ 584.466108]
    device_del+0xb2/0x3e0 [ 584.481701] device_unregister+0x13/0x60 [ 584.501306]
    bsg_unregister_queue+0x5b/0x80 [ 584.522029] bsg_remove_queue+0x1c/0x40 [ 584.541884]
    fc_rport_final_delete+0xf3/0x1d0 [scsi_transport_fc] [ 584.573823] process_one_work+0x1e3/0x3b0 [
    584.592396] worker_thread+0x50/0x3b0 [ 584.609256] ? rescuer_thread+0x370/0x370 [ 584.628877]
    kthread+0x149/0x170 [ 584.643673] ? set_kthread_struct+0x40/0x40 [ 584.662909] ret_from_fork+0x22/0x30 [
    584.680002] ---[ end trace 53575ecefa942ece ]--- (CVE-2022-48758)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/20");
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
        "os_version": "8"
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
