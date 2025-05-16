#TRUSTED 1e8c2e4ae6cb33062ef75776e309ea90e442b7bfe1e440970c45520791c00c4e4d250d042ea018a4ff50d84a1b46f5f530e05ea43b846ee9680575881a8f30586a3d6cc8a941a9eb68a5010d9126cae23af82b6173fa22c2d17d4727613a2f12fa23fec5d9502412f3e56651209fb32bfb592a28c1461a0a0931d0cdfe7cb9c9ec1c557919cf721fa23bad3ae431b5821cbf3514b2cf1e7416fbdf0e1d2fc1f8ea78f9491203011d88c17a2099edf6c38d37f16145dfef972015afb81587ae70fec2d2b8c7b32e9008268306d3d83fce24169792801e7da5a70463b95cb944a8ec2c4764af3e8b3936c3fbc64ae9be630f2cf2839f72da5fd3cedafccb1244e168495d51fdd6b891b389a984c0bb325ffb08f99b3e5faac98a52e48464024bdf563c96e1e1d1650e602a358b024408aafb234b691ded38a27aa4fdd709753970d82f331a76e6b96bd96a28d22c976ceb1c1b09b3fc39b4a814196c094e818dbd41e357b8e802cdf1bf435ef5ce98952448e64aef4efef37968c4da91603996110a7029f97de994943a6daede82b6278a8c2fadb17caf494aa2580eb317a23f729edfb37f4cc12fc5c941f95165de5f0655bc2b4be630de1b982a6feba19a83042219c9e9731ca9d6056087f850b6c8a06642a81bea598cdd16f1d8d19baecd93286dcb6184246517bdda6f6d13357677a92396a132c59d1c8fdd0d34d87d5699
#TRUST-RSA-SHA256 06f273e50b77f8cce5efd0114f92e8e8c0236a0883d45212589ce220395d3bc47669a7d566e9e747277bc755421493aa6d54b845d260ac8ef67c96b863691589a3fde6cad38d598ccb5ddcd30aa11a17aa004790dd8ecc2a302f026bc47d12110443ba07d1e0f8ef921c677a8e739491b5627aabfb13bb900b526e83f6133e138e52198080741108e6b58e2a52c18f2dbfc0ebd9b7786aecb495fdbcc51d9b1a54ae7b254eea963b423edfbcb1f9f5753caa0f51e8ac40fc1bdf9cde68d483a43ea709d0ef4d5859f8bfb3d0d7d8b612b527d3f378b47e6f41bf92ad29d3d703b9d654af63d79060a73133bf0be7e8fed5d5f12067df0ba182d8e2bd221dca63713cd7e6152cab4d81269c1c0690883178e198be316453272b432b74bac435f410b6eb7bd9161aa42c1e664f45658210730a3c741cee735ca532e91bf9505735a5cdd98d50d14e117c19810cec274532a4d025d82eab4f97108ba3c17b3ef13c1beeb60c28a2cbdd305c9c3b6d5549ce7fa2796a7c0093357334c081fa386adaff9ea79a45fb2c17ed23633631ef08daa326abd1ba27ee7a0573d7ac95ec7a7b8efd58af90707da98c88ac99aa53e956c77487f91239e25adfeebcec1509e7d93536f14069410b827c53def7fc8539a7e0797653aacae35499423a9e851e7abea72275ce29b98dc745131df0ba6dd6c6786d21cc24fe0f824ec50b03b79bd525
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168964);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2022-22228");
  script_xref(name:"JSA", value:"JSA69880");
  script_xref(name:"IAVA", value:"2022-A-0421-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69880)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69880
advisory.

  - An Improper Validation of Specified Type of Input vulnerability in the routing protocol daemon (rpd) of
    Juniper Networks Junos OS allows an attacker to cause an RPD memory leak leading to a Denial of Service
    (DoS). This memory leak only occurs when the attacker's packets are destined to any configured IPv6
    address on the device. (CVE-2022-22228)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-On-IPv6-OAM-SRv6-network-enabled-devices-an-attacker-sending-a-specific-genuine-packet-to-an-IPv6-address-configured-on-the-device-may-cause-a-RPD-memory-leak-leading-to-an-RPD-core-CVE-2022-22228
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88ad5bd4");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69880");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22228");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S2'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S1'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set routing-options source-packet-routing srv6 locator")
   || !junos_check_config(buf:buf, pattern:"^set protocols isis source-packet-routing node-segment ipv6-index")
   || !junos_check_config(buf:buf, pattern:"^set protocols isis source-packet-routing srv6 locator.*end-sid.*flavor")
   || !junos_check_config(buf:buf, pattern:"^set protocols mpls interface all")
   || !junos_check_config(buf:buf, pattern:"^set interfaces.*unit.*family inet6 address")
   )
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
