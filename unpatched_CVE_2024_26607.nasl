#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227640);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26607");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26607");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/bridge: sii902x: Fix probing race
    issue A null pointer dereference crash has been observed rarely on TI platforms using sii9022 bridge: [
    53.271356] sii902x_get_edid+0x34/0x70 [sii902x] [ 53.276066] sii902x_bridge_get_edid+0x14/0x20 [sii902x] [
    53.281381] drm_bridge_get_edid+0x20/0x34 [drm] [ 53.286305] drm_bridge_connector_get_modes+0x8c/0xcc
    [drm_kms_helper] [ 53.292955] drm_helper_probe_single_connector_modes+0x190/0x538 [drm_kms_helper] [
    53.300510] drm_client_modeset_probe+0x1f0/0xbd4 [drm] [ 53.305958]
    __drm_fb_helper_initial_config_and_unlock+0x50/0x510 [drm_kms_helper] [ 53.313611]
    drm_fb_helper_initial_config+0x48/0x58 [drm_kms_helper] [ 53.320039]
    drm_fbdev_dma_client_hotplug+0x84/0xd4 [drm_dma_helper] [ 53.326401] drm_client_register+0x5c/0xa0 [drm] [
    53.331216] drm_fbdev_dma_setup+0xc8/0x13c [drm_dma_helper] [ 53.336881] tidss_probe+0x128/0x264 [tidss] [
    53.341174] platform_probe+0x68/0xc4 [ 53.344841] really_probe+0x188/0x3c4 [ 53.348501]
    __driver_probe_device+0x7c/0x16c [ 53.352854] driver_probe_device+0x3c/0x10c [ 53.357033]
    __device_attach_driver+0xbc/0x158 [ 53.361472] bus_for_each_drv+0x88/0xe8 [ 53.365303]
    __device_attach+0xa0/0x1b4 [ 53.369135] device_initial_probe+0x14/0x20 [ 53.373314]
    bus_probe_device+0xb0/0xb4 [ 53.377145] deferred_probe_work_func+0xcc/0x124 [ 53.381757]
    process_one_work+0x1f0/0x518 [ 53.385770] worker_thread+0x1e8/0x3dc [ 53.389519] kthread+0x11c/0x120 [
    53.392750] ret_from_fork+0x10/0x20 The issue here is as follows: - tidss probes, but is deferred as
    sii902x is still missing. - sii902x starts probing and enters sii902x_init(). - sii902x calls
    drm_bridge_add(). Now the sii902x bridge is ready from DRM's perspective. - sii902x calls
    sii902x_audio_codec_init() and platform_device_register_data() - The registration of the audio platform
    device causes probing of the deferred devices. - tidss probes, which eventually causes
    sii902x_bridge_get_edid() to be called. - sii902x_bridge_get_edid() tries to use the i2c to read the edid.
    However, the sii902x driver has not set up the i2c part yet, leading to the crash. Fix this by moving the
    drm_bridge_add() to the end of the sii902x_init(), which is also at the very end of sii902x_probe().
    (CVE-2024-26607)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26607");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/Ubuntu", "Host/Ubuntu/release");

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
  },
  {
   "product": {
    "name": "linux-azure-fde",
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
    "name": "linux-azure-fde-5.15",
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
