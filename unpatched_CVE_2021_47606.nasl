#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224436);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2021-47606");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47606");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: netlink: af_netlink: Prevent
    empty skb by adding a check on len. Adding a check on len parameter to avoid empty skb. This prevents a
    division error in netem_enqueue function which is caused when skb->len=0 and skb->data_len=0 in the
    randomized corruption step as shown below. skb->data[prandom_u32() % skb_headlen(skb)] ^=
    1<<(prandom_u32() % 8); Crash Report: [ 343.170349] netdevsim netdevsim0 netdevsim3: set [1, 0] type 2
    family 0 port 6081 - 0 [ 343.216110] netem: version 1.3 [ 343.235841] divide error: 0000 [#1] PREEMPT SMP
    KASAN NOPTI [ 343.236680] CPU: 3 PID: 4288 Comm: reproducer Not tainted 5.16.0-rc1+ [ 343.237569] Hardware
    name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7 04/01/2014 [ 343.238707] RIP:
    0010:netem_enqueue+0x1590/0x33c0 [sch_netem] [ 343.239499] Code: 89 85 58 ff ff ff e8 5f 5d e9 d3 48 8b b5
    48 ff ff ff 8b 8d 50 ff ff ff 8b 85 58 ff ff ff 48 8b bd 70 ff ff ff 31 d2 2b 4f 74 <f7> f1 48 b8 00 00 00
    00 00 fc ff df 49 01 d5 4c 89 e9 48 c1 e9 03 [ 343.241883] RSP: 0018:ffff88800bcd7368 EFLAGS: 00010246 [
    343.242589] RAX: 00000000ba7c0a9c RBX: 0000000000000001 RCX: 0000000000000000 [ 343.243542] RDX:
    0000000000000000 RSI: ffff88800f8edb10 RDI: ffff88800f8eda40 [ 343.244474] RBP: ffff88800bcd7458 R08:
    0000000000000000 R09: ffffffff94fb8445 [ 343.245403] R10: ffffffff94fb8336 R11: ffffffff94fb8445 R12:
    0000000000000000 [ 343.246355] R13: ffff88800a5a7000 R14: ffff88800a5b5800 R15: 0000000000000020 [
    343.247291] FS: 00007fdde2bd7700(0000) GS:ffff888109780000(0000) knlGS:0000000000000000 [ 343.248350] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 343.249120] CR2: 00000000200000c0 CR3: 000000000ef4c000
    CR4: 00000000000006e0 [ 343.250076] Call Trace: [ 343.250423] <TASK> [ 343.250713] ? memcpy+0x4d/0x60 [
    343.251162] ? netem_init+0xa0/0xa0 [sch_netem] [ 343.251795] ? __sanitizer_cov_trace_pc+0x21/0x60 [
    343.252443] netem_enqueue+0xe28/0x33c0 [sch_netem] [ 343.253102] ? stack_trace_save+0x87/0xb0 [
    343.253655] ? filter_irq_stacks+0xb0/0xb0 [ 343.254220] ? netem_init+0xa0/0xa0 [sch_netem] [ 343.254837] ?
    __kasan_check_write+0x14/0x20 [ 343.255418] ? _raw_spin_lock+0x88/0xd6 [ 343.255953]
    dev_qdisc_enqueue+0x50/0x180 [ 343.256508] __dev_queue_xmit+0x1a7e/0x3090 [ 343.257083] ?
    netdev_core_pick_tx+0x300/0x300 [ 343.257690] ? check_kcov_mode+0x10/0x40 [ 343.258219] ?
    _raw_spin_unlock_irqrestore+0x29/0x40 [ 343.258899] ? __kasan_init_slab_obj+0x24/0x30 [ 343.259529] ?
    setup_object.isra.71+0x23/0x90 [ 343.260121] ? new_slab+0x26e/0x4b0 [ 343.260609] ? kasan_poison+0x3a/0x50
    [ 343.261118] ? kasan_unpoison+0x28/0x50 [ 343.261637] ? __kasan_slab_alloc+0x71/0x90 [ 343.262214] ?
    memcpy+0x4d/0x60 [ 343.262674] ? write_comp_data+0x2f/0x90 [ 343.263209] ? __kasan_check_write+0x14/0x20 [
    343.263802] ? __skb_clone+0x5d6/0x840 [ 343.264329] ? __sanitizer_cov_trace_pc+0x21/0x60 [ 343.264958]
    dev_queue_xmit+0x1c/0x20 [ 343.265470] netlink_deliver_tap+0x652/0x9c0 [ 343.266067]
    netlink_unicast+0x5a0/0x7f0 [ 343.266608] ? netlink_attachskb+0x860/0x860 [ 343.267183] ?
    __sanitizer_cov_trace_pc+0x21/0x60 [ 343.267820] ? write_comp_data+0x2f/0x90 [ 343.268367]
    netlink_sendmsg+0x922/0xe80 [ 343.268899] ? netlink_unicast+0x7f0/0x7f0 [ 343.269472] ?
    __sanitizer_cov_trace_pc+0x21/0x60 [ 343.270099] ? write_comp_data+0x2f/0x90 [ 343.270644] ?
    netlink_unicast+0x7f0/0x7f0 [ 343.271210] sock_sendmsg+0x155/0x190 [ 343.271721]
    ____sys_sendmsg+0x75f/0x8f0 [ 343.272262] ? kernel_sendmsg+0x60/0x60 [ 343.272788] ?
    write_comp_data+0x2f/0x90 [ 343.273332] ? write_comp_data+0x2f/0x90 [ 343.273869]
    ___sys_sendmsg+0x10f/0x190 [ 343.274405] ? sendmsg_copy_msghdr+0x80/0x80 [ 343.274984] ?
    slab_post_alloc_hook+0x70/0x230 [ 343.275597] ? futex_wait_setup+0x240/0x240 [ 343.276175] ?
    security_file_alloc+0x3e/0x170 [ 343.276779] ? write_comp_d ---truncated--- (CVE-2021-47606)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
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
    "name": "linux-kvm",
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
        "os_version": "16.04"
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
