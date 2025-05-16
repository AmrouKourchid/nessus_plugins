#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231909);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-49949");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-49949");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: avoid potential underflow in
    qdisc_pkt_len_init() with UFO After commit 7c6d2ecbda83 (net: be more gentle about silly gso requests
    coming from user) virtio_net_hdr_to_skb() had sanity check to detect malicious attempts from user space
    to cook a bad GSO packet. Then commit cf9acc90c80ec (net: virtio_net_hdr_to_skb: count transport header
    in UFO) while fixing one issue, allowed user space to cook a GSO packet with the following characteristic
    : IPv4 SKB_GSO_UDP, gso_size=3, skb->len = 28. When this packet arrives in qdisc_pkt_len_init(), we end up
    with hdr_len = 28 (IPv4 header + UDP header), matching skb->len Then the following sets gso_segs to 0 :
    gso_segs = DIV_ROUND_UP(skb->len - hdr_len, shinfo->gso_size); Then later we set
    qdisc_skb_cb(skb)->pkt_len to back to zero :/ qdisc_skb_cb(skb)->pkt_len += (gso_segs - 1) * hdr_len; This
    leads to the following crash in fq_codel [1] qdisc_pkt_len_init() is best effort, we only want an
    estimation of the bytes sent on the wire, not crashing the kernel. This patch is fixing this particular
    issue, a following one adds more sanity checks for another potential bug. [1] [ 70.724101] BUG: kernel
    NULL pointer dereference, address: 0000000000000000 [ 70.724561] #PF: supervisor read access in kernel
    mode [ 70.724561] #PF: error_code(0x0000) - not-present page [ 70.724561] PGD 10ac61067 P4D 10ac61067 PUD
    107ee2067 PMD 0 [ 70.724561] Oops: Oops: 0000 [#1] SMP NOPTI [ 70.724561] CPU: 11 UID: 0 PID: 2163 Comm:
    b358537762 Not tainted 6.11.0-virtme #991 [ 70.724561] Hardware name: QEMU Standard PC (i440FX + PIIX,
    1996), BIOS 1.16.3-debian-1.16.3-2 04/01/2014 [ 70.724561] RIP: 0010:fq_codel_enqueue
    (net/sched/sch_fq_codel.c:120 net/sched/sch_fq_codel.c:168 net/sched/sch_fq_codel.c:230) sch_fq_codel [
    70.724561] Code: 24 08 49 c1 e1 06 44 89 7c 24 18 45 31 ed 45 31 c0 31 ff 89 44 24 14 4c 03 8b 90 01 00 00
    eb 04 39 ca 73 37 4d 8b 39 83 c7 01 <49> 8b 17 49 89 11 41 8b 57 28 45 8b 5f 34 49 c7 07 00 00 00 00 49
    All code ======== 0: 24 08 and $0x8,%al 2: 49 c1 e1 06 shl $0x6,%r9 6: 44 89 7c 24 18 mov %r15d,0x18(%rsp)
    b: 45 31 ed xor %r13d,%r13d e: 45 31 c0 xor %r8d,%r8d 11: 31 ff xor %edi,%edi 13: 89 44 24 14 mov
    %eax,0x14(%rsp) 17: 4c 03 8b 90 01 00 00 add 0x190(%rbx),%r9 1e: eb 04 jmp 0x24 20: 39 ca cmp %ecx,%edx
    22: 73 37 jae 0x5b 24: 4d 8b 39 mov (%r9),%r15 27: 83 c7 01 add $0x1,%edi 2a:* 49 8b 17 mov (%r15),%rdx
    <-- trapping instruction 2d: 49 89 11 mov %rdx,(%r9) 30: 41 8b 57 28 mov 0x28(%r15),%edx 34: 45 8b 5f 34
    mov 0x34(%r15),%r11d 38: 49 c7 07 00 00 00 00 movq $0x0,(%r15) 3f: 49 rex.WB Code starting with the
    faulting instruction =========================================== 0: 49 8b 17 mov (%r15),%rdx 3: 49 89 11
    mov %rdx,(%r9) 6: 41 8b 57 28 mov 0x28(%r15),%edx a: 45 8b 5f 34 mov 0x34(%r15),%r11d e: 49 c7 07 00 00 00
    00 movq $0x0,(%r15) 15: 49 rex.WB [ 70.724561] RSP: 0018:ffff95ae85e6fb90 EFLAGS: 00000202 [ 70.724561]
    RAX: 0000000002000000 RBX: ffff95ae841de000 RCX: 0000000000000000 [ 70.724561] RDX: 0000000000000000 RSI:
    0000000000000001 RDI: 0000000000000001 [ 70.724561] RBP: ffff95ae85e6fbf8 R08: 0000000000000000 R09:
    ffff95b710a30000 [ 70.724561] R10: 0000000000000000 R11: bdf289445ce31881 R12: ffff95ae85e6fc58 [
    70.724561] R13: 0000000000000000 R14: 0000000000000040 R15: 0000000000000000 [ 70.724561] FS:
    000000002c5c1380(0000) GS:ffff95bd7fcc0000(0000) knlGS:0000000000000000 [ 70.724561] CS: 0010 DS: 0000 ES:
    0000 C ---truncated--- (CVE-2024-49949)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49949");

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
     "linux-aws-5.4",
     "linux-oracle-5.4",
     "linux-raspi-5.4"
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
        "os_version": "18.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-fips",
     "linux-azure-fde-5.15",
     "linux-azure-fips",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-fips",
     "linux-gcp-fips",
     "linux-headers-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-iot",
     "linux-modules-5.4.0-1008-raspi",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-tools-5.4.0-1008-raspi"
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
