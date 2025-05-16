#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226536);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52635");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52635");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: PM / devfreq: Synchronize
    devfreq_monitor_[start/stop] There is a chance if a frequent switch of the governor done in a loop result
    in timer list corruption where timer cancel being done from two place one from cancel_delayed_work_sync()
    and followed by expire_timers() can be seen from the traces[1]. while true do echo simple_ondemand >
    /sys/class/devfreq/1d84000.ufshc/governor echo performance > /sys/class/devfreq/1d84000.ufshc/governor
    done It looks to be issue with devfreq driver where device_monitor_[start/stop] need to synchronized so
    that delayed work should get corrupted while it is either being queued or running or being cancelled.
    Let's use polling flag and devfreq lock to synchronize the queueing the timer instance twice and work data
    being corrupted. [1] ... .. <idle>-0 [003] 9436.209662: timer_cancel timer=0xffffff80444f0428 <idle>-0
    [003] 9436.209664: timer_expire_entry timer=0xffffff80444f0428 now=0x10022da1c
    function=__typeid__ZTSFvP10timer_listE_global_addr baseclk=0x10022da1c <idle>-0 [003] 9436.209718:
    timer_expire_exit timer=0xffffff80444f0428 kworker/u16:6-14217 [003] 9436.209863: timer_start
    timer=0xffffff80444f0428 function=__typeid__ZTSFvP10timer_listE_global_addr expires=0x10022da2b
    now=0x10022da1c flags=182452227 vendor.xxxyyy.ha-1593 [004] 9436.209888: timer_cancel
    timer=0xffffff80444f0428 vendor.xxxyyy.ha-1593 [004] 9436.216390: timer_init timer=0xffffff80444f0428
    vendor.xxxyyy.ha-1593 [004] 9436.216392: timer_start timer=0xffffff80444f0428
    function=__typeid__ZTSFvP10timer_listE_global_addr expires=0x10022da2c now=0x10022da1d flags=186646532
    vendor.xxxyyy.ha-1593 [005] 9436.220992: timer_cancel timer=0xffffff80444f0428 xxxyyyTraceManag-7795 [004]
    9436.261641: timer_cancel timer=0xffffff80444f0428 [2] 9436.261653][ C4] Unable to handle kernel paging
    request at virtual address dead00000000012a [ 9436.261664][ C4] Mem abort info: [ 9436.261666][ C4] ESR =
    0x96000044 [ 9436.261669][ C4] EC = 0x25: DABT (current EL), IL = 32 bits [ 9436.261671][ C4] SET = 0, FnV
    = 0 [ 9436.261673][ C4] EA = 0, S1PTW = 0 [ 9436.261675][ C4] Data abort info: [ 9436.261677][ C4] ISV =
    0, ISS = 0x00000044 [ 9436.261680][ C4] CM = 0, WnR = 1 [ 9436.261682][ C4] [dead00000000012a] address
    between user and kernel address ranges [ 9436.261685][ C4] Internal error: Oops: 96000044 [#1] PREEMPT SMP
    [ 9436.261701][ C4] Skip md ftrace buffer dump for: 0x3a982d0 ... [ 9436.262138][ C4] CPU: 4 PID: 7795
    Comm: TraceManag Tainted: G S W O 5.10.149-android12-9-o-g17f915d29d0c #1 [ 9436.262141][ C4] Hardware
    name: Qualcomm Technologies, Inc. (DT) [ 9436.262144][ C4] pstate: 22400085 (nzCv daIf +PAN -UAO +TCO
    BTYPE=--) [ 9436.262161][ C4] pc : expire_timers+0x9c/0x438 [ 9436.262164][ C4] lr :
    expire_timers+0x2a4/0x438 [ 9436.262168][ C4] sp : ffffffc010023dd0 [ 9436.262171][ C4] x29:
    ffffffc010023df0 x28: ffffffd0636fdc18 [ 9436.262178][ C4] x27: ffffffd063569dd0 x26: ffffffd063536008 [
    9436.262182][ C4] x25: 0000000000000001 x24: ffffff88f7c69280 [ 9436.262185][ C4] x23: 00000000000000e0
    x22: dead000000000122 [ 9436.262188][ C4] x21: 000000010022da29 x20: ffffff8af72b4e80 [ 9436.262191][ C4]
    x19: ffffffc010023e50 x18: ffffffc010025038 [ 9436.262195][ C4] x17: 0000000000000240 x16:
    0000000000000201 [ 9436.262199][ C4] x15: ffffffffffffffff x14: ffffff889f3c3100 [ 9436.262203][ C4] x13:
    ffffff889f3c3100 x12: 00000000049f56b8 [ 9436.262207][ C4] x11: 00000000049f56b8 x10: 00000000ffffffff [
    9436.262212][ C4] x9 : ffffffc010023e50 x8 : dead000000000122 [ 9436.262216][ C4] x7 : ffffffffffffffff x6
    : ffffffc0100239d8 [ 9436.262220][ C4] x5 : 0000000000000000 x4 : 0000000000000101 [ 9436.262223][ C4] x3
    : 0000000000000080 x2 : ffffff8 ---truncated--- (CVE-2023-52635)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52635");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-bluefield",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-buildinfo-5.4.0-1009-aws",
     "linux-buildinfo-5.4.0-1009-gcp",
     "linux-buildinfo-5.4.0-1009-kvm",
     "linux-buildinfo-5.4.0-1009-oracle",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-buildinfo-5.4.0-26-generic",
     "linux-buildinfo-5.4.0-26-generic-lpae",
     "linux-cloud-tools-5.4.0-1009-aws",
     "linux-cloud-tools-5.4.0-1009-kvm",
     "linux-cloud-tools-5.4.0-1009-oracle",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-26",
     "linux-cloud-tools-5.4.0-26-generic",
     "linux-cloud-tools-5.4.0-26-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-fips",
     "linux-gcp-headers-5.4.0-1009",
     "linux-gcp-tools-5.4.0-1009",
     "linux-headers-5.4.0-1008-raspi",
     "linux-headers-5.4.0-1009-aws",
     "linux-headers-5.4.0-1009-gcp",
     "linux-headers-5.4.0-1009-kvm",
     "linux-headers-5.4.0-1009-oracle",
     "linux-headers-5.4.0-1010-azure",
     "linux-headers-5.4.0-26",
     "linux-headers-5.4.0-26-generic",
     "linux-headers-5.4.0-26-generic-lpae",
     "linux-ibm",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-image-5.4.0-1009-aws",
     "linux-image-5.4.0-1009-aws-dbgsym",
     "linux-image-5.4.0-1009-kvm",
     "linux-image-5.4.0-1009-kvm-dbgsym",
     "linux-image-unsigned-5.4.0-1009-gcp",
     "linux-image-unsigned-5.4.0-1009-gcp-dbgsym",
     "linux-image-unsigned-5.4.0-1009-oracle",
     "linux-image-unsigned-5.4.0-1009-oracle-dbgsym",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic",
     "linux-image-unsigned-5.4.0-26-generic-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic-lpae",
     "linux-image-unsigned-5.4.0-26-generic-lpae-dbgsym",
     "linux-image-unsigned-5.4.0-26-lowlatency",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-modules-5.4.0-1008-raspi",
     "linux-modules-5.4.0-1009-aws",
     "linux-modules-5.4.0-1009-gcp",
     "linux-modules-5.4.0-1009-kvm",
     "linux-modules-5.4.0-1009-oracle",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-5.4.0-26-generic",
     "linux-modules-5.4.0-26-generic-lpae",
     "linux-modules-5.4.0-26-lowlatency",
     "linux-modules-extra-5.4.0-1009-aws",
     "linux-modules-extra-5.4.0-1009-gcp",
     "linux-modules-extra-5.4.0-1009-kvm",
     "linux-modules-extra-5.4.0-1009-oracle",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-26-generic",
     "linux-modules-extra-5.4.0-26-generic-lpae",
     "linux-modules-extra-5.4.0-26-lowlatency",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-source-5.4.0",
     "linux-tools-5.4.0-1008-raspi",
     "linux-tools-5.4.0-1009-aws",
     "linux-tools-5.4.0-1009-gcp",
     "linux-tools-5.4.0-1009-kvm",
     "linux-tools-5.4.0-1009-oracle",
     "linux-tools-5.4.0-1010-azure",
     "linux-tools-5.4.0-26",
     "linux-tools-5.4.0-26-generic",
     "linux-tools-5.4.0-26-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm",
     "linux-xilinx-zynqmp"
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
        "os_version": "20.04"
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
