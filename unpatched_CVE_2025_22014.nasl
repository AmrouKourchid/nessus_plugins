#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234191);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-22014");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-22014");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - soc: qcom: pdr: Fix the potential deadlock When some client process A call pdr_add_lookup() to add the
    look up for the service and does schedule locator work, later a process B got a new server packet
    indicating locator is up and call pdr_locator_new_server() which eventually sets
    pdr->locator_init_complete to true which process A sees and takes list lock and queries domain list but it
    will timeout due to deadlock as the response will queued to the same qmi->wq and it is ordered workqueue
    and process B is not able to complete new server request work due to deadlock on list lock. Fix it by
    removing the unnecessary list iteration as the list iteration is already being done inside locator work,
    so avoid it here and just call schedule_work() here. Process A Process B process_scheduled_works()
    pdr_add_lookup() qmi_data_ready_work() process_scheduled_works() pdr_locator_new_server()
    pdr->locator_init_complete=true; pdr_locator_work() mutex_lock(&pdr->list_lock); pdr_locate_service()
    mutex_lock(&pdr->list_lock); pdr_get_domain_list() pr_err(PDR: %s get domain list txn wait failed: %d\n,
    req->service_name, ret); Timeout error log due to deadlock:  PDR: tms/servreg get domain list txn wait
    failed: -110 PDR: service lookup for msm/adsp/sensor_pd:tms/servreg failed: -110  Thanks to Bjorn and
    Johan for letting me know that this commit also fixes an audio regression when using the in-kernel pd-
    mapper as that makes it easier to hit this race. [1] (CVE-2025-22014)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-22014");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22014");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

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
     "btrfs-modules-6.1.0-32-alpha-generic-di",
     "cdrom-core-modules-6.1.0-32-alpha-generic-di",
     "ext4-modules-6.1.0-32-alpha-generic-di",
     "fat-modules-6.1.0-32-alpha-generic-di",
     "isofs-modules-6.1.0-32-alpha-generic-di",
     "jfs-modules-6.1.0-32-alpha-generic-di",
     "kernel-image-6.1.0-32-alpha-generic-di",
     "linux-doc",
     "linux-doc-6.1",
     "linux-headers-6.1.0-32-common",
     "linux-headers-6.1.0-32-common-rt",
     "linux-source",
     "linux-source-6.1",
     "linux-support-6.1.0-32",
     "loop-modules-6.1.0-32-alpha-generic-di",
     "nic-modules-6.1.0-32-alpha-generic-di",
     "nic-shared-modules-6.1.0-32-alpha-generic-di",
     "nic-wireless-modules-6.1.0-32-alpha-generic-di",
     "pata-modules-6.1.0-32-alpha-generic-di",
     "ppp-modules-6.1.0-32-alpha-generic-di",
     "scsi-core-modules-6.1.0-32-alpha-generic-di",
     "scsi-modules-6.1.0-32-alpha-generic-di",
     "scsi-nic-modules-6.1.0-32-alpha-generic-di",
     "serial-modules-6.1.0-32-alpha-generic-di",
     "usb-serial-modules-6.1.0-32-alpha-generic-di",
     "xfs-modules-6.1.0-32-alpha-generic-di"
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
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
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
        "os_version": "11"
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
