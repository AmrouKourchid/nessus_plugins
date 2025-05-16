#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231266);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-49875");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-49875");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: nfsd: map the EBADMSG to nfserr_io to
    avoid warning Ext4 will throw -EBADMSG through ext4_readdir when a checksum error occurs, resulting in the
    following WARNING. Fix it by mapping EBADMSG to nfserr_io. nfsd_buffered_readdir iterate_dir // -EBADMSG
    -74 ext4_readdir // .iterate_shared ext4_dx_readdir ext4_htree_fill_tree htree_dirblock_to_tree
    ext4_read_dirblock __ext4_read_dirblock ext4_dirblock_csum_verify warn_no_space_for_csum
    __warn_no_space_for_csum return ERR_PTR(-EFSBADCRC) // -EBADMSG -74 nfserrno // WARNING [ 161.115610]
    ------------[ cut here ]------------ [ 161.116465] nfsd: non-standard errno: -74 [ 161.117315] WARNING:
    CPU: 1 PID: 780 at fs/nfsd/nfsproc.c:878 nfserrno+0x9d/0xd0 [ 161.118596] Modules linked in: [ 161.119243]
    CPU: 1 PID: 780 Comm: nfsd Not tainted 5.10.0-00014-g79679361fd5d #138 [ 161.120684] Hardware name: QEMU
    Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qe mu.org 04/01/2014 [
    161.123601] RIP: 0010:nfserrno+0x9d/0xd0 [ 161.124676] Code: 0f 87 da 30 dd 00 83 e3 01 b8 00 00 00 05 75
    d7 44 89 ee 48 c7 c7 c0 57 24 98 89 44 24 04 c6 05 ce 2b 61 03 01 e8 99 20 d8 00 <0f> 0b 8b 44 24 04 eb b5
    4c 89 e6 48 c7 c7 a0 6d a4 99 e8 cc 15 33 [ 161.127797] RSP: 0018:ffffc90000e2f9c0 EFLAGS: 00010286 [
    161.128794] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000 [ 161.130089] RDX:
    1ffff1103ee16f6d RSI: 0000000000000008 RDI: fffff520001c5f2a [ 161.131379] RBP: 0000000000000022 R08:
    0000000000000001 R09: ffff8881f70c1827 [ 161.132664] R10: ffffed103ee18304 R11: 0000000000000001 R12:
    0000000000000021 [ 161.133949] R13: 00000000ffffffb6 R14: ffff8881317c0000 R15: ffffc90000e2fbd8 [
    161.135244] FS: 0000000000000000(0000) GS:ffff8881f7080000(0000) knlGS:0000000000000000 [ 161.136695] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 161.137761] CR2: 00007fcaad70b348 CR3: 0000000144256006
    CR4: 0000000000770ee0 [ 161.139041] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [
    161.140291] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 161.141519] PKRU: 55555554
    [ 161.142076] Call Trace: [ 161.142575] ? __warn+0x9b/0x140 [ 161.143229] ? nfserrno+0x9d/0xd0 [
    161.143872] ? report_bug+0x125/0x150 [ 161.144595] ? handle_bug+0x41/0x90 [ 161.145284] ?
    exc_invalid_op+0x14/0x70 [ 161.146009] ? asm_exc_invalid_op+0x12/0x20 [ 161.146816] ? nfserrno+0x9d/0xd0 [
    161.147487] nfsd_buffered_readdir+0x28b/0x2b0 [ 161.148333] ? nfsd4_encode_dirent_fattr+0x380/0x380 [
    161.149258] ? nfsd_buffered_filldir+0xf0/0xf0 [ 161.150093] ? wait_for_concurrent_writes+0x170/0x170 [
    161.151004] ? generic_file_llseek_size+0x48/0x160 [ 161.151895] nfsd_readdir+0x132/0x190 [ 161.152606] ?
    nfsd4_encode_dirent_fattr+0x380/0x380 [ 161.153516] ? nfsd_unlink+0x380/0x380 [ 161.154256] ?
    override_creds+0x45/0x60 [ 161.155006] nfsd4_encode_readdir+0x21a/0x3d0 [ 161.155850] ?
    nfsd4_encode_readlink+0x210/0x210 [ 161.156731] ? write_bytes_to_xdr_buf+0x97/0xe0 [ 161.157598] ?
    __write_bytes_to_xdr_buf+0xd0/0xd0 [ 161.158494] ? lock_downgrade+0x90/0x90 [ 161.159232] ?
    nfs4svc_decode_voidarg+0x10/0x10 [ 161.160092] nfsd4_encode_operation+0x15a/0x440 [ 161.160959]
    nfsd4_proc_compound+0x718/0xe90 [ 161.161818] nfsd_dispatch+0x18e/0x2c0 [ 161.162586]
    svc_process_common+0x786/0xc50 [ 161.163403] ? nfsd_svc+0x380/0x380 [ 161.164137] ? svc_printk+0x160/0x160
    [ 161.164846] ? svc_xprt_do_enqueue.part.0+0x365/0x380 [ 161.165808] ? nfsd_svc+0x380/0x380 [ 161.166523]
    ? rcu_is_watching+0x23/0x40 [ 161.167309] svc_process+0x1a5/0x200 [ 161.168019] nfsd+0x1f5/0x380 [
    161.168663] ? nfsd_shutdown_threads+0x260/0x260 [ 161.169554] kthread+0x1c4/0x210 [ 161.170224] ?
    kthread_insert_work_sanity_check+0x80/0x80 [ 161.171246] ret_from_fork+0x1f/0x30 (CVE-2024-49875)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49875");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "linux-azure-fde-5.15",
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
    "name": [
     "linux-azure-cloud-tools-6.8.0-1007",
     "linux-azure-headers-6.8.0-1007",
     "linux-azure-tools-6.8.0-1007",
     "linux-buildinfo-6.8.0-1005-ibm",
     "linux-buildinfo-6.8.0-1005-oem",
     "linux-buildinfo-6.8.0-1007-azure",
     "linux-cloud-tools-6.8.0-1005-ibm",
     "linux-cloud-tools-6.8.0-1005-oem",
     "linux-cloud-tools-6.8.0-1007-azure",
     "linux-headers-6.8.0-1005-ibm",
     "linux-headers-6.8.0-1005-oem",
     "linux-headers-6.8.0-1007-azure",
     "linux-ibm-cloud-tools-6.8.0-1005",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-6.8.0-1005",
     "linux-ibm-source-6.8.0",
     "linux-ibm-tools-6.8.0-1005",
     "linux-ibm-tools-common",
     "linux-image-unsigned-6.8.0-1005-ibm",
     "linux-image-unsigned-6.8.0-1005-ibm-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oem",
     "linux-image-unsigned-6.8.0-1005-oem-dbgsym",
     "linux-image-unsigned-6.8.0-1007-azure",
     "linux-image-unsigned-6.8.0-1007-azure-dbgsym",
     "linux-lowlatency-hwe-6.11",
     "linux-modules-6.8.0-1005-ibm",
     "linux-modules-6.8.0-1005-oem",
     "linux-modules-6.8.0-1007-azure",
     "linux-modules-extra-6.8.0-1005-ibm",
     "linux-modules-extra-6.8.0-1005-oem",
     "linux-modules-extra-6.8.0-1007-azure",
     "linux-modules-ipu6-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1005-ibm",
     "linux-modules-iwlwifi-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1007-azure",
     "linux-oem-6.8-headers-6.8.0-1005",
     "linux-oem-6.8-lib-rust-6.8.0-1005-oem",
     "linux-oem-6.8-tools-6.8.0-1005",
     "linux-raspi-realtime",
     "linux-realtime",
     "linux-tools-6.8.0-1005-ibm",
     "linux-tools-6.8.0-1005-oem",
     "linux-tools-6.8.0-1007-azure",
     "linux-udebs-azure"
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
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-azure-6.8",
     "linux-azure-fde",
     "linux-hwe-6.8"
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
    "name": "kernel",
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
