#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225742);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48687");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48687");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipv6: sr: fix out-of-bounds read when
    setting HMAC data. The SRv6 layer allows defining HMAC data that can later be used to sign IPv6 Segment
    Routing Headers. This configuration is realised via netlink through four attributes: SEG6_ATTR_HMACKEYID,
    SEG6_ATTR_SECRET, SEG6_ATTR_SECRETLEN and SEG6_ATTR_ALGID. Because the SECRETLEN attribute is decoupled
    from the actual length of the SECRET attribute, it is possible to provide invalid combinations (e.g.,
    secret = , secretlen = 64). This case is not checked in the code and with an appropriately crafted
    netlink message, an out-of-bounds read of up to 64 bytes (max secret length) can occur past the skb end
    pointer and into skb_shared_info: Breakpoint 1, seg6_genl_sethmac (skb=<optimized out>, info=<optimized
    out>) at net/ipv6/seg6.c:208 208 memcpy(hinfo->secret, secret, slen); (gdb) bt #0 seg6_genl_sethmac
    (skb=<optimized out>, info=<optimized out>) at net/ipv6/seg6.c:208 #1 0xffffffff81e012e9 in
    genl_family_rcv_msg_doit (skb=skb@entry=0xffff88800b1f9f00, nlh=nlh@entry=0xffff88800b1b7600,
    extack=extack@entry=0xffffc90000ba7af0, ops=ops@entry=0xffffc90000ba7a80, hdrlen=4, net=0xffffffff84237580
    <init_net>, family=<optimized out>, family=<optimized out>) at net/netlink/genetlink.c:731 #2
    0xffffffff81e01435 in genl_family_rcv_msg (extack=0xffffc90000ba7af0, nlh=0xffff88800b1b7600,
    skb=0xffff88800b1f9f00, family=0xffffffff82fef6c0 <seg6_genl_family>) at net/netlink/genetlink.c:775 #3
    genl_rcv_msg (skb=0xffff88800b1f9f00, nlh=0xffff88800b1b7600, extack=0xffffc90000ba7af0) at
    net/netlink/genetlink.c:792 #4 0xffffffff81dfffc3 in netlink_rcv_skb (skb=skb@entry=0xffff88800b1f9f00,
    cb=cb@entry=0xffffffff81e01350 <genl_rcv_msg>) at net/netlink/af_netlink.c:2501 #5 0xffffffff81e00919 in
    genl_rcv (skb=0xffff88800b1f9f00) at net/netlink/genetlink.c:803 #6 0xffffffff81dff6ae in
    netlink_unicast_kernel (ssk=0xffff888010eec800, skb=0xffff88800b1f9f00, sk=0xffff888004aed000) at
    net/netlink/af_netlink.c:1319 #7 netlink_unicast (ssk=ssk@entry=0xffff888010eec800,
    skb=skb@entry=0xffff88800b1f9f00, portid=portid@entry=0, nonblock=<optimized out>) at
    net/netlink/af_netlink.c:1345 #8 0xffffffff81dff9a4 in netlink_sendmsg (sock=<optimized out>,
    msg=0xffffc90000ba7e48, len=<optimized out>) at net/netlink/af_netlink.c:1921 ... (gdb) p/x ((struct
    sk_buff *)0xffff88800b1f9f00)->head + ((struct sk_buff *)0xffff88800b1f9f00)->end $1 = 0xffff88800b1b76c0
    (gdb) p/x secret $2 = 0xffff88800b1b76c0 (gdb) p slen $3 = 64 '@' The OOB data can then be read back from
    userspace by dumping HMAC state. This commit fixes this by ensuring SECRETLEN cannot exceed the actual
    length of SECRET. (CVE-2022-48687)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48687");

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
    "name": "linux-gcp-5.15",
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
        "os_version": "8"
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
