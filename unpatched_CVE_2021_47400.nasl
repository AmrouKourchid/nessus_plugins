#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230148);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47400");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47400");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: hns3: do not allow call
    hns3_nic_net_open repeatedly hns3_nic_net_open() is not allowed to called repeatly, but there is no
    checking for this. When doing device reset and setup tc concurrently, there is a small oppotunity to call
    hns3_nic_net_open repeatedly, and cause kernel bug by calling napi_enable twice. The calltrace information
    is like below: [ 3078.222780] ------------[ cut here ]------------ [ 3078.230255] kernel BUG at
    net/core/dev.c:6991! [ 3078.236224] Internal error: Oops - BUG: 0 [#1] PREEMPT SMP [ 3078.243431] Modules
    linked in: hns3 hclgevf hclge hnae3 vfio_iommu_type1 vfio_pci vfio_virqfd vfio pv680_mii(O) [ 3078.258880]
    CPU: 0 PID: 295 Comm: kworker/u8:5 Tainted: G O 5.14.0-rc4+ #1 [ 3078.269102] Hardware name: , BIOS
    KpxxxFPGA 1P B600 V181 08/12/2021 [ 3078.276801] Workqueue: hclge hclge_service_task [hclge] [
    3078.288774] pstate: 60400009 (nZCv daif +PAN -UAO -TCO BTYPE=--) [ 3078.296168] pc :
    napi_enable+0x80/0x84 tc qdisc sho[w 3d0e7v8 .e3t0h218 79] lr : hns3_nic_net_open+0x138/0x510 [hns3] [
    3078.314771] sp : ffff8000108abb20 [ 3078.319099] x29: ffff8000108abb20 x28: 0000000000000000 x27:
    ffff0820a8490300 [ 3078.329121] x26: 0000000000000001 x25: ffff08209cfc6200 x24: 0000000000000000 [
    3078.339044] x23: ffff0820a8490300 x22: ffff08209cd76000 x21: ffff0820abfe3880 [ 3078.349018] x20:
    0000000000000000 x19: ffff08209cd76900 x18: 0000000000000000 [ 3078.358620] x17: 0000000000000000 x16:
    ffffc816e1727a50 x15: 0000ffff8f4ff930 [ 3078.368895] x14: 0000000000000000 x13: 0000000000000000 x12:
    0000259e9dbeb6b4 [ 3078.377987] x11: 0096a8f7e764eb40 x10: 634615ad28d3eab5 x9 : ffffc816ad8885b8 [
    3078.387091] x8 : ffff08209cfc6fb8 x7 : ffff0820ac0da058 x6 : ffff0820a8490344 [ 3078.396356] x5 :
    0000000000000140 x4 : 0000000000000003 x3 : ffff08209cd76938 [ 3078.405365] x2 : 0000000000000000 x1 :
    0000000000000010 x0 : ffff0820abfe38a0 [ 3078.414657] Call trace: [ 3078.418517] napi_enable+0x80/0x84 [
    3078.424626] hns3_reset_notify_up_enet+0x78/0xd0 [hns3] [ 3078.433469] hns3_reset_notify+0x64/0x80 [hns3]
    [ 3078.441430] hclge_notify_client+0x68/0xb0 [hclge] [ 3078.450511] hclge_reset_rebuild+0x524/0x884
    [hclge] [ 3078.458879] hclge_reset_service_task+0x3c4/0x680 [hclge] [ 3078.467470]
    hclge_service_task+0xb0/0xb54 [hclge] [ 3078.475675] process_one_work+0x1dc/0x48c [ 3078.481888]
    worker_thread+0x15c/0x464 [ 3078.487104] kthread+0x160/0x170 [ 3078.492479] ret_from_fork+0x10/0x18 [
    3078.498785] Code: c8027c81 35ffffa2 d50323bf d65f03c0 (d4210000) [ 3078.506889] ---[ end trace
    8ebe0340a1b0fb44 ]--- Once hns3_nic_net_open() is excute success, the flag HNS3_NIC_STATE_DOWN will be
    cleared. So add checking for this flag, directly return when HNS3_NIC_STATE_DOWN is no set.
    (CVE-2021-47400)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47400");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
