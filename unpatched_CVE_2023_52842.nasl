#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227166);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52842");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52842");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: virtio/vsock: Fix uninit-value in
    virtio_transport_recv_pkt() KMSAN reported the following uninit-value access issue:
    ===================================================== BUG: KMSAN: uninit-value in
    virtio_transport_recv_pkt+0x1dfb/0x26a0 net/vmw_vsock/virtio_transport_common.c:1421
    virtio_transport_recv_pkt+0x1dfb/0x26a0 net/vmw_vsock/virtio_transport_common.c:1421
    vsock_loopback_work+0x3bb/0x5a0 net/vmw_vsock/vsock_loopback.c:120 process_one_work
    kernel/workqueue.c:2630 [inline] process_scheduled_works+0xff6/0x1e60 kernel/workqueue.c:2703
    worker_thread+0xeca/0x14d0 kernel/workqueue.c:2784 kthread+0x3cc/0x520 kernel/kthread.c:388
    ret_from_fork+0x66/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x11/0x20
    arch/x86/entry/entry_64.S:304 Uninit was stored to memory at: virtio_transport_space_update
    net/vmw_vsock/virtio_transport_common.c:1274 [inline] virtio_transport_recv_pkt+0x1ee8/0x26a0
    net/vmw_vsock/virtio_transport_common.c:1415 vsock_loopback_work+0x3bb/0x5a0
    net/vmw_vsock/vsock_loopback.c:120 process_one_work kernel/workqueue.c:2630 [inline]
    process_scheduled_works+0xff6/0x1e60 kernel/workqueue.c:2703 worker_thread+0xeca/0x14d0
    kernel/workqueue.c:2784 kthread+0x3cc/0x520 kernel/kthread.c:388 ret_from_fork+0x66/0x80
    arch/x86/kernel/process.c:147 ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304 Uninit was created
    at: slab_post_alloc_hook+0x105/0xad0 mm/slab.h:767 slab_alloc_node mm/slub.c:3478 [inline]
    kmem_cache_alloc_node+0x5a2/0xaf0 mm/slub.c:3523 kmalloc_reserve+0x13c/0x4a0 net/core/skbuff.c:559
    __alloc_skb+0x2fd/0x770 net/core/skbuff.c:650 alloc_skb include/linux/skbuff.h:1286 [inline]
    virtio_vsock_alloc_skb include/linux/virtio_vsock.h:66 [inline] virtio_transport_alloc_skb+0x90/0x11e0
    net/vmw_vsock/virtio_transport_common.c:58 virtio_transport_reset_no_sock
    net/vmw_vsock/virtio_transport_common.c:957 [inline] virtio_transport_recv_pkt+0x1279/0x26a0
    net/vmw_vsock/virtio_transport_common.c:1387 vsock_loopback_work+0x3bb/0x5a0
    net/vmw_vsock/vsock_loopback.c:120 process_one_work kernel/workqueue.c:2630 [inline]
    process_scheduled_works+0xff6/0x1e60 kernel/workqueue.c:2703 worker_thread+0xeca/0x14d0
    kernel/workqueue.c:2784 kthread+0x3cc/0x520 kernel/kthread.c:388 ret_from_fork+0x66/0x80
    arch/x86/kernel/process.c:147 ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304 CPU: 1 PID: 10664
    Comm: kworker/1:5 Not tainted 6.6.0-rc3-00146-g9f3ebbef746f #3 Hardware name: QEMU Standard PC (i440FX +
    PIIX, 1996), BIOS 1.16.2-1.fc38 04/01/2014 Workqueue: vsock-loopback vsock_loopback_work
    ===================================================== The following simple reproducer can cause the issue
    described above: int main(void) { int sock; struct sockaddr_vm addr = { .svm_family = AF_VSOCK, .svm_cid =
    VMADDR_CID_ANY, .svm_port = 1234, }; sock = socket(AF_VSOCK, SOCK_STREAM, 0); connect(sock, (struct
    sockaddr *)&addr, sizeof(addr)); return 0; } This issue occurs because the `buf_alloc` and `fwd_cnt`
    fields of the `struct virtio_vsock_hdr` are not initialized when a new skb is allocated in
    `virtio_transport_init_hdr()`. This patch resolves the issue by initializing these fields during
    allocation. (CVE-2023-52842)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52842");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
