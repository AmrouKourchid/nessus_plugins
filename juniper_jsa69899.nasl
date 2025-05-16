#TRUSTED 1a662441ab6aa5ba1d8eedbf1ec2a3789f07a9ff4f7aeaa09de653d31eb68f79c4a2396a77f1297a2c67c946422c9944afa93de4ea64247f116db716734e75ae11b5cd7c7f055c8127767d09291cc30626405b51b7808d6232ae478cbaade33405be0ebef537c2f54eeb5f749a72022c1d026f4066e5353b148a2f8c327b36ee7450832d3ee223b04a17eefe4ca3c7c563f0f102a9146fafe401c40f72661599f823a3083f2bc327926c5ec876d782ca497b8b8742c1f197e9de24740102ff95dbea731579eb676da3af82a8e0e5798254c50beca0ca6c8a1328d919aca4f5b88b5d2c85b85ac060ac90a8efc782fc0325738e575cc005157061567f8dbcc58b6481d14bb9381d4428046a97dfaf37c4f2460afbb707c8d718e04a51920bf5c537f3b0862e27d870b85e40843d4dc2bba959541149fe2a7fa15dd5f01e4ad1bcdda8f5c0e9b80a0a5c3a8bdc4e4e406301d294a4a96c4551f1785cbb7692511d11aae24440fe36c3edbc94ad313492f2fb9d0d858aa67fe1db9010373ec5480d3f08f1ddc33e8fbe2c2c05ac3663697a9aada97a63e8c35e8b57bced6ea09e4de6483c4ab5da1bd31fbc832cc939e4198131c85f1a99c0478f02b0d02e22a5238d280bd36ae064dfc2149dc7dae3fae60e629ae50bcd30c95988e5b0368b4e14a3420e9a48e52473a5dd42b5fa982f855cf849228c9f7c9d144fb476b0d3cc87
#TRUST-RSA-SHA256 5f3b6944dce56401ccc9a1184dabbe877bad11fac476c45cb873e8fdccbd631986ffc6fcdc66ecc9c0ee10da1e47b8a0a3d7d370e7d47a1d7b1069dcd47151edfae73fc77115050af50cec47d3b15c543998492968126e8459b3545a9455d907b4ac88b778463df0597a97b8ad1a28e43f0d12321f08a3c1275afe07d18f59c713f143cda3b565385ecc73e3664af50ff90a7a5d6cf0e23980cbbe66f829078cb2833c39b9d1d3dc00a58f153414f2d1dd5877a8668bc145fa40c4265d98eac93a283618ee268eefb4ffee461b2685ddbec14280d508d461bd13f5fb5bdbd6771079172d2c2bb3f05f685f31d8eef6c3909f3d30111f9182329512d6f0a1ccaee6396bd2b6ac1b561c28adee393a81e47df3ea470f24b8e7d0859fb85e40fce5d409f9bb47138e373563c9b08274658fa3573d27a6fe80c83179166f7208cc2603a22fdd8bbcd60346afa7d29ef1a4b17e4f74864ea8933a7f8b9d6cd5a3126329b0e0413386d1e88b2223866d8f770de1af87f5ba34dbb1d951178bcf2146e7f6ae38db0738fd5e5377418840ea02926e129d4d6534e211170a83ac26fb0cd60513b7ac5c64d8bcf77ecbd10c358e2373307b73065353d50d03d87267a4797f4707ae2f23d87c88941003456e5b47ce3b3dda2abbe981aa5f1f171b3ecf695b06cdf48015971f30d5a5ce0187445c03aea340928e7c6d296f594154f6b4a936
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166686);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id(
    "CVE-2022-22241",
    "CVE-2022-22242",
    "CVE-2022-22243",
    "CVE-2022-22244",
    "CVE-2022-22245",
    "CVE-2022-22246"
  );
  script_xref(name:"JSA", value:"JSA69899");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA69899)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA69899 advisory.

  - An Improper Input Validation vulnerability in the J-Web component of Juniper Networks Junos OS may allow
    an unauthenticated attacker to access data without proper authorization. Utilizing a crafted POST request,
    deserialization may occur which could lead to unauthorized local file access or the ability to execute
    arbitrary commands. This issue affects Juniper Networks Junos OS: all versions prior to 19.1R3-S9; 19.2
    versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S7,
    19.4R3-S9; 20.1 versions prior to 20.1R3-S5; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to
    20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S2; 21.2 versions prior to
    21.2R3-S1; 21.3 versions prior to 21.3R2-S2, 21.3R3; 21.4 versions prior to 21.4R1-S2, 21.4R2-S1, 21.4R3;
    22.1 versions prior to 22.1R1-S1, 22.1R2. (CVE-2022-22241)

  - A Cross-site Scripting (XSS) vulnerability in the J-Web component of Juniper Networks Junos OS allows an
    unauthenticated attacker to run malicious scripts reflected off of J-Web to the victim's browser in the
    context of their session within J-Web. This issue affects Juniper Networks Junos OS all versions prior to
    19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S7; 19.4 versions prior to
    19.4R2-S7, 19.4R3-S8; 20.1 versions prior to 20.1R3-S5; 20.2 versions prior to 20.2R3-S5; 20.3 versions
    prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S4; 21.2 versions
    prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R2; 22.1 versions prior to
    22.1R2. (CVE-2022-22242)

  - An XPath Injection vulnerability due to Improper Input Validation in the J-Web component of Juniper
    Networks Junos OS allows an authenticated attacker to add an XPath command to the XPath stream, which may
    allow chaining to other unspecified vulnerabilities, leading to a partial loss of confidentiality. This
    issue affects Juniper Networks Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to
    19.2R3-S6; 19.3 versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S7, 19.4R3-S8; 20.1 versions
    prior to 20.1R3-S5; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions
    prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S2; 21.2 versions prior to 21.2R3-S1; 21.3 versions
    prior to 21.3R2-S2, 21.3R3; 21.4 versions prior to 21.4R1-S2, 21.4R2-S1, 21.4R3; 22.1 versions prior to
    22.1R1-S1, 22.1R2. (CVE-2022-22243)

  - An XPath Injection vulnerability in the J-Web component of Juniper Networks Junos OS allows an
    unauthenticated attacker sending a crafted POST to reach the XPath channel, which may allow chaining to
    other unspecified vulnerabilities, leading to a partial loss of confidentiality. This issue affects
    Juniper Networks Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3
    versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.1 versions prior to 20.1R3-S5; 20.2
    versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1
    versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4
    versions prior to 21.4R1-S2, 21.4R2; 22.1 versions prior to 22.1R1-S1, 22.1R2. (CVE-2022-22244)

  - A Path Traversal vulnerability in the J-Web component of Juniper Networks Junos OS allows an authenticated
    attacker to upload arbitrary files to the device by bypassing validation checks built into Junos OS. The
    attacker should not be able to execute the file due to validation checks built into Junos OS. Successful
    exploitation of this vulnerability could lead to loss of filesystem integrity. This issue affects Juniper
    Networks Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior
    to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.1 versions prior to 20.1R3-S5; 20.2 versions prior to
    20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to
    21.1R3-S2; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R2-S2, 21.3R3; 21.4 versions prior
    to 21.4R1-S2, 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S1, 22.1R2. (CVE-2022-22245)

  - A PHP Local File Inclusion (LFI) vulnerability in the J-Web component of Juniper Networks Junos OS may
    allow a low-privileged authenticated attacker to execute an untrusted PHP file. By chaining this
    vulnerability with other unspecified vulnerabilities, and by circumventing existing attack requirements,
    successful exploitation could lead to a complete system compromise. This issue affects Juniper Networks
    Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to
    19.3R3-S6; 19.4 versions prior to 19.4R2-S7, 19.4R3-S8; 20.1 versions prior to 20.1R3-S5; 20.2 versions
    prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions
    prior to 21.1R3-S2; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R2-S2, 21.3R3; 21.4
    versions prior to 21.4R1-S2, 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S1, 22.1R2. (CVE-2022-22246)

Note: Nessus found J-Web enabled [set system services web-management http(s)] on this device.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Multiple-vulnerabilities-in-J-Web
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa3dba08");
  script_set_attribute(attribute:"solution", value:
"Disable J-Web, or limit access to only trusted hosts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22241");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
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
  {'min_ver':'0', 'fixed_ver':'19.1R3-S9'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S6'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S7'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S9'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S5'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S5'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S5'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S2'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S1'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  var pattern = "^set system services web-management http(s)?";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as J-Web is not enabled');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
