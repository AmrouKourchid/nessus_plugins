#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228717);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35818");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35818");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: LoongArch: Define the __io_aw() hook
    as mmiowb() Commit fb24ea52f78e0d595852e (drivers: Remove explicit invocations of mmiowb()) remove all
    mmiowb() in drivers, but it says: NOTE: mmiowb() has only ever guaranteed ordering in conjunction with
    spin_unlock(). However, pairing each mmiowb() removal in this patch with the corresponding call to
    spin_unlock() is not at all trivial, so there is a small chance that this change may regress any drivers
    incorrectly relying on mmiowb() to order MMIO writes between CPUs using lock-free synchronisation. The
    mmio in radeon_ring_commit() is protected by a mutex rather than a spinlock, but in the mutex fastpath it
    behaves similar to spinlock. We can add mmiowb() calls in the radeon driver but the maintainer says he
    doesn't like such a workaround, and radeon is not the only example of mutex protected mmio. So we should
    extend the mmiowb tracking system from spinlock to mutex, and maybe other locking primitives. This is not
    easy and error prone, so we solve it in the architectural code, by simply defining the __io_aw() hook as
    mmiowb(). And we no longer need to override queued_spin_unlock() so use the generic definition. Without
    this, we get such an error when run 'glxgears' on weak ordering architectures such as LoongArch: radeon
    0000:04:00.0: ring 0 stalled for more than 10324msec radeon 0000:04:00.0: ring 3 stalled for more than
    10240msec radeon 0000:04:00.0: GPU lockup (current fence id 0x000000000001f412 last fence id
    0x000000000001f414 on ring 3) radeon 0000:04:00.0: GPU lockup (current fence id 0x000000000000f940 last
    fence id 0x000000000000f941 on ring 0) radeon 0000:04:00.0: scheduling IB failed (-35).
    [drm:radeon_gem_va_ioctl [radeon]] *ERROR* Couldn't update BO_VA (-35) radeon 0000:04:00.0: scheduling IB
    failed (-35). [drm:radeon_gem_va_ioctl [radeon]] *ERROR* Couldn't update BO_VA (-35) radeon 0000:04:00.0:
    scheduling IB failed (-35). [drm:radeon_gem_va_ioctl [radeon]] *ERROR* Couldn't update BO_VA (-35) radeon
    0000:04:00.0: scheduling IB failed (-35). [drm:radeon_gem_va_ioctl [radeon]] *ERROR* Couldn't update BO_VA
    (-35) radeon 0000:04:00.0: scheduling IB failed (-35). [drm:radeon_gem_va_ioctl [radeon]] *ERROR* Couldn't
    update BO_VA (-35) radeon 0000:04:00.0: scheduling IB failed (-35). [drm:radeon_gem_va_ioctl [radeon]]
    *ERROR* Couldn't update BO_VA (-35) radeon 0000:04:00.0: scheduling IB failed (-35).
    [drm:radeon_gem_va_ioctl [radeon]] *ERROR* Couldn't update BO_VA (-35) (CVE-2024-35818)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35818");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

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
    "name": [
     "linux-aws-fips",
     "linux-azure-fips",
     "linux-fips",
     "linux-gcp-fips",
     "linux-intel-iot-realtime",
     "linux-realtime"
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
