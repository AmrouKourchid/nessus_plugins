#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227593);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26851");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26851");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_conntrack_h323: Add
    protection for bmp length out of range UBSAN load reports an exception of BRK#5515 SHIFT_ISSUE:Bitwise
    shifts that are out of bounds for their data type. vmlinux get_bitmap(b=75) + 712
    <net/netfilter/nf_conntrack_h323_asn1.c:0> vmlinux decode_seq(bs=0xFFFFFFD008037000, f=0xFFFFFFD008037018,
    level=134443100) + 1956 <net/netfilter/nf_conntrack_h323_asn1.c:592> vmlinux
    decode_choice(base=0xFFFFFFD0080370F0, level=23843636) + 1216 <net/netfilter/nf_conntrack_h323_asn1.c:814>
    vmlinux decode_seq(f=0xFFFFFFD0080371A8, level=134443500) + 812
    <net/netfilter/nf_conntrack_h323_asn1.c:576> vmlinux decode_choice(base=0xFFFFFFD008037280, level=0) +
    1216 <net/netfilter/nf_conntrack_h323_asn1.c:814> vmlinux DecodeRasMessage() + 304
    <net/netfilter/nf_conntrack_h323_asn1.c:833> vmlinux ras_help() + 684
    <net/netfilter/nf_conntrack_h323_main.c:1728> vmlinux nf_confirm() + 188
    <net/netfilter/nf_conntrack_proto.c:137> Due to abnormal data in skb->data, the extension bitmap length
    exceeds 32 when decoding ras message then uses the length to make a shift operation. It will change into
    negative after several loop. UBSAN load could detect a negative shift as an undefined behaviour and
    reports exception. So we add the protection to avoid the length exceeding 32. Or else it will return out
    of range error and stop decoding. (CVE-2024-26851)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26851");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

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
