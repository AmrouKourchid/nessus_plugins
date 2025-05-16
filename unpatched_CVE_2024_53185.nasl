#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231819);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53185");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53185");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: smb: client: fix NULL ptr deref in
    crypto_aead_setkey() Neither SMB3.0 or SMB3.02 supports encryption negotiate context, so when
    SMB2_GLOBAL_CAP_ENCRYPTION flag is set in the negotiate response, the client uses AES-128-CCM as the
    default cipher. See MS-SMB2 3.3.5.4. Commit b0abcd65ec54 (smb: client: fix UAF in async decryption)
    added a @server->cipher_type check to conditionally call smb3_crypto_aead_allocate(), but that check would
    always be false as @server->cipher_type is unset for SMB3.02. Fix the following KASAN splat by setting
    @server->cipher_type for SMB3.02 as well. mount.cifs //srv/share /mnt -o vers=3.02,seal,... BUG: KASAN:
    null-ptr-deref in crypto_aead_setkey+0x2c/0x130 Read of size 8 at addr 0000000000000020 by task
    mount.cifs/1095 CPU: 1 UID: 0 PID: 1095 Comm: mount.cifs Not tainted 6.12.0 #1 Hardware name: QEMU
    Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-3.fc41 04/01/2014 Call Trace: <TASK> dump_stack_lvl+0x5d/0x80
    ? crypto_aead_setkey+0x2c/0x130 kasan_report+0xda/0x110 ? crypto_aead_setkey+0x2c/0x130
    crypto_aead_setkey+0x2c/0x130 crypt_message+0x258/0xec0 [cifs] ? __asan_memset+0x23/0x50 ?
    __pfx_crypt_message+0x10/0x10 [cifs] ? mark_lock+0xb0/0x6a0 ? hlock_class+0x32/0xb0 ? mark_lock+0xb0/0x6a0
    smb3_init_transform_rq+0x352/0x3f0 [cifs] ? lock_acquire.part.0+0xf4/0x2a0 smb_send_rqst+0x144/0x230
    [cifs] ? __pfx_smb_send_rqst+0x10/0x10 [cifs] ? hlock_class+0x32/0xb0 ? smb2_setup_request+0x225/0x3a0
    [cifs] ? __pfx_cifs_compound_last_callback+0x10/0x10 [cifs] compound_send_recv+0x59b/0x1140 [cifs] ?
    __pfx_compound_send_recv+0x10/0x10 [cifs] ? __create_object+0x5e/0x90 ? hlock_class+0x32/0xb0 ?
    do_raw_spin_unlock+0x9a/0xf0 cifs_send_recv+0x23/0x30 [cifs] SMB2_tcon+0x3ec/0xb30 [cifs] ?
    __pfx_SMB2_tcon+0x10/0x10 [cifs] ? lock_acquire.part.0+0xf4/0x2a0 ? __pfx_lock_release+0x10/0x10 ?
    do_raw_spin_trylock+0xc6/0x120 ? lock_acquire+0x3f/0x90 ? _get_xid+0x16/0xd0 [cifs] ?
    __pfx_SMB2_tcon+0x10/0x10 [cifs] ? cifs_get_smb_ses+0xcdd/0x10a0 [cifs] cifs_get_smb_ses+0xcdd/0x10a0
    [cifs] ? __pfx_cifs_get_smb_ses+0x10/0x10 [cifs] ? cifs_get_tcp_session+0xaa0/0xca0 [cifs]
    cifs_mount_get_session+0x8a/0x210 [cifs] dfs_mount_share+0x1b0/0x11d0 [cifs] ?
    __pfx___lock_acquire+0x10/0x10 ? __pfx_dfs_mount_share+0x10/0x10 [cifs] ? lock_acquire.part.0+0xf4/0x2a0 ?
    find_held_lock+0x8a/0xa0 ? hlock_class+0x32/0xb0 ? lock_release+0x203/0x5d0 cifs_mount+0xb3/0x3d0 [cifs] ?
    do_raw_spin_trylock+0xc6/0x120 ? __pfx_cifs_mount+0x10/0x10 [cifs] ? lock_acquire+0x3f/0x90 ?
    find_nls+0x16/0xa0 ? smb3_update_mnt_flags+0x372/0x3b0 [cifs] cifs_smb3_do_mount+0x1e2/0xc80 [cifs] ?
    __pfx_vfs_parse_fs_string+0x10/0x10 ? __pfx_cifs_smb3_do_mount+0x10/0x10 [cifs] smb3_get_tree+0x1bf/0x330
    [cifs] vfs_get_tree+0x4a/0x160 path_mount+0x3c1/0xfb0 ? kasan_quarantine_put+0xc7/0x1d0 ?
    __pfx_path_mount+0x10/0x10 ? kmem_cache_free+0x118/0x3e0 ? user_path_at+0x74/0xa0
    __x64_sys_mount+0x1a6/0x1e0 ? __pfx___x64_sys_mount+0x10/0x10 ? mark_held_locks+0x1a/0x90
    do_syscall_64+0xbb/0x1d0 entry_SYSCALL_64_after_hwframe+0x77/0x7f (CVE-2024-53185)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/27");
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
     "linux-buildinfo-6.8.0-31-generic",
     "linux-buildinfo-6.8.0-31-generic-64k",
     "linux-cloud-tools-6.8.0-31",
     "linux-cloud-tools-6.8.0-31-generic",
     "linux-cloud-tools-6.8.0-31-generic-64k",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-headers-6.8.0-31",
     "linux-headers-6.8.0-31-generic",
     "linux-headers-6.8.0-31-generic-64k",
     "linux-image-unsigned-6.8.0-31-generic",
     "linux-image-unsigned-6.8.0-31-generic-64k",
     "linux-image-unsigned-6.8.0-31-generic-64k-dbgsym",
     "linux-image-unsigned-6.8.0-31-generic-dbgsym",
     "linux-lib-rust-6.8.0-31-generic",
     "linux-lib-rust-6.8.0-31-generic-64k",
     "linux-libc-dev",
     "linux-modules-6.8.0-31-generic",
     "linux-modules-6.8.0-31-generic-64k",
     "linux-modules-extra-6.8.0-31-generic",
     "linux-modules-extra-6.8.0-31-generic-64k",
     "linux-modules-ipu6-6.8.0-31-generic",
     "linux-modules-ivsc-6.8.0-31-generic",
     "linux-modules-iwlwifi-6.8.0-31-generic",
     "linux-source-6.8.0",
     "linux-tools-6.8.0-31",
     "linux-tools-6.8.0-31-generic",
     "linux-tools-6.8.0-31-generic-64k",
     "linux-tools-common",
     "linux-tools-host"
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
