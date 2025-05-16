#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228868);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46795");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46795");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ksmbd: unset the binding mark of a
    reused connection Steve French reported null pointer dereference error from sha256 lib. cifs.ko can send
    session setup requests on reused connection. If reused connection is used for binding session,
    conn->binding can still remain true and generate_preauth_hash() will not set sess->Preauth_HashValue and
    it will be NULL. It is used as a material to create an encryption key in ksmbd_gen_smb311_encryptionkey.
    ->Preauth_HashValue cause null pointer dereference error from crypto_shash_update(). BUG: kernel NULL
    pointer dereference, address: 0000000000000000 #PF: supervisor read access in kernel mode #PF:
    error_code(0x0000) - not-present page PGD 0 P4D 0 Oops: 0000 [#1] PREEMPT SMP PTI CPU: 8 PID: 429254 Comm:
    kworker/8:39 Hardware name: LENOVO 20MAS08500/20MAS08500, BIOS N2CET69W (1.52 ) Workqueue: ksmbd-io
    handle_ksmbd_work [ksmbd] RIP: 0010:lib_sha256_base_do_update.isra.0+0x11e/0x1d0 [sha256_ssse3] <TASK> ?
    show_regs+0x6d/0x80 ? __die+0x24/0x80 ? page_fault_oops+0x99/0x1b0 ? do_user_addr_fault+0x2ee/0x6b0 ?
    exc_page_fault+0x83/0x1b0 ? asm_exc_page_fault+0x27/0x30 ? __pfx_sha256_transform_rorx+0x10/0x10
    [sha256_ssse3] ? lib_sha256_base_do_update.isra.0+0x11e/0x1d0 [sha256_ssse3] ?
    __pfx_sha256_transform_rorx+0x10/0x10 [sha256_ssse3] ? __pfx_sha256_transform_rorx+0x10/0x10
    [sha256_ssse3] _sha256_update+0x77/0xa0 [sha256_ssse3] sha256_avx2_update+0x15/0x30 [sha256_ssse3]
    crypto_shash_update+0x1e/0x40 hmac_update+0x12/0x20 crypto_shash_update+0x1e/0x40 generate_key+0x234/0x380
    [ksmbd] generate_smb3encryptionkey+0x40/0x1c0 [ksmbd] ksmbd_gen_smb311_encryptionkey+0x72/0xa0 [ksmbd]
    ntlm_authenticate.isra.0+0x423/0x5d0 [ksmbd] smb2_sess_setup+0x952/0xaa0 [ksmbd]
    __process_request+0xa3/0x1d0 [ksmbd] __handle_ksmbd_work+0x1c4/0x2f0 [ksmbd] handle_ksmbd_work+0x2d/0xa0
    [ksmbd] process_one_work+0x16c/0x350 worker_thread+0x306/0x440 ? __pfx_worker_thread+0x10/0x10
    kthread+0xef/0x120 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x44/0x70 ? __pfx_kthread+0x10/0x10
    ret_from_fork_asm+0x1b/0x30 </TASK> (CVE-2024-46795)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/18");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
