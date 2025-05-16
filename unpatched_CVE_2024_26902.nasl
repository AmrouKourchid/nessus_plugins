#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227930);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26902");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26902");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: perf: RISCV: Fix panic on pmu overflow
    handler (1 << idx) of int is not desired when setting bits in unsigned long overflowed_ctrs, use BIT()
    instead. This panic happens when running 'perf record -e branches' on sophgo sg2042. [ 273.311852] Unable
    to handle kernel NULL pointer dereference at virtual address 0000000000000098 [ 273.320851] Oops [#1] [
    273.323179] Modules linked in: [ 273.326303] CPU: 0 PID: 1475 Comm: perf Not tainted 6.6.0-rc3+ #9 [
    273.332521] Hardware name: Sophgo Mango (DT) [ 273.336878] epc : riscv_pmu_ctr_get_width_mask+0x8/0x62 [
    273.342291] ra : pmu_sbi_ovf_handler+0x2e0/0x34e [ 273.347091] epc : ffffffff80aecd98 ra :
    ffffffff80aee056 sp : fffffff6e36928b0 [ 273.354454] gp : ffffffff821f82d0 tp : ffffffd90c353200 t0 :
    0000002ade4f9978 [ 273.361815] t1 : 0000000000504d55 t2 : ffffffff8016cd8c s0 : fffffff6e3692a70 [
    273.369180] s1 : 0000000000000020 a0 : 0000000000000000 a1 : 00001a8e81800000 [ 273.376540] a2 :
    0000003c00070198 a3 : 0000003c00db75a4 a4 : 0000000000000015 [ 273.383901] a5 : ffffffd7ff8804b0 a6 :
    0000000000000015 a7 : 000000000000002a [ 273.391327] s2 : 000000000000ffff s3 : 0000000000000000 s4 :
    ffffffd7ff8803b0 [ 273.398773] s5 : 0000000000504d55 s6 : ffffffd905069800 s7 : ffffffff821fe210 [
    273.406139] s8 : 000000007fffffff s9 : ffffffd7ff8803b0 s10: ffffffd903f29098 [ 273.413660] s11:
    0000000080000000 t3 : 0000000000000003 t4 : ffffffff8017a0ca [ 273.421022] t5 : ffffffff8023cfc2 t6 :
    ffffffd9040780e8 [ 273.426437] status: 0000000200000100 badaddr: 0000000000000098 cause: 000000000000000d
    [ 273.434512] [<ffffffff80aecd98>] riscv_pmu_ctr_get_width_mask+0x8/0x62 [ 273.441169]
    [<ffffffff80076bd8>] handle_percpu_devid_irq+0x98/0x1ee [ 273.447562] [<ffffffff80071158>]
    generic_handle_domain_irq+0x28/0x36 [ 273.454151] [<ffffffff8047a99a>] riscv_intc_irq+0x36/0x4e [
    273.459659] [<ffffffff80c944de>] handle_riscv_irq+0x4a/0x74 [ 273.465442] [<ffffffff80c94c48>]
    do_irq+0x62/0x92 [ 273.470360] Code: 0420 60a2 6402 5529 0141 8082 0013 0000 0013 0000 (6d5c) b783 [
    273.477921] ---[ end trace 0000000000000000 ]--- [ 273.482630] Kernel panic - not syncing: Fatal exception
    in interrupt (CVE-2024-26902)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
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
