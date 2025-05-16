#TRUSTED 0377295309ecde7f8c232c8158c41f73828ccb98647e7309f5e8745f6f7ec5281f1d9100e25a758a214de4cad033a1848690b133caec6ab9dffb60a7a27759d8d42894c2585ca05336b761bded2e03f2c57f88dcf18bc365dde40ad6c5e73e56beff23849120a67b7a08a2486d765ca7efdabe8d12fd234dc187770c96012754f3b10e16577d694417f12002d8b751fa19810df85190281b118a3478feb7c36d3e9b383ebe71e27401d70782ad1f6dd338877f8b7fc7189b0e5e242bd78a34b691bcc6c52fdafa716623a9c82c2ce5f11f607cc69d0763d9d92df87816ebbd8255d8ae720a47a93ee542b40105367cb94aa89e0074e9e3674fcd3bf29959b12ceac34819d999c3cb7b3d09aa69d4b308cdafdaed3e2a11944cfc21b417a815546e2e0ae8178ff38ec34a5d8ec941b55edf0378999f678663f17404f5ee68f3caeb7c6f1b31bd44e518d2e85a016dcc535ee1327b3673adeff6bf9f24d84e4452c174b66ceaa5709d4801395aa5f9931be073c589f5a4c0f2f5090d35f71a16a5d91220d6a90e29585934bfaee88dbecce81a5cf085a40a20e118e5d42b4dcaa78b9b652bef9cb2f9fb1c85a106cb909fef7eefd462e636671ef5433aeffed6cfb1de3385e8919c72a19e083051ef7fc3d3c7915a58b3d546b28e784d1c81f290aecee2b4340d7858fd0639578f148c595a9cfd28b9d57eb95af2f25978612893
#TRUST-RSA-SHA256 8ce798d14829542116e199ee0893cd6e43ef87433b55c8096e7b9d9e0659fcaf86493d21158a27fb889ef2bec89d1496a3c3faf1d7776171f2dd89e09bbb89392042feda7749554234ff8a5ed434404092639b484aad73934e017ab189b51c207ab5625a05427b636c010e3303ed900dfe6c612c460766708389697d4868cc0b50c3e3c24b76535093269c78567a11d329fb5aeacd9a53e2f7665980719dd08637ab53f21e4e22be8a4645d64a2d24bb53b4ff6a91420e2c3424249496e23b5ff42bde32d4063c20bcc7ce08d9cc693447e36c26b9ff17b436e60d320a8ceec80193689ba95dc61127eaa6f9b379c004e65f846d7d7bfdfb2a10fe880d9e95d7f323575762c4d991dc1c166c99465a3a114fde1595ae11f5383a4ae9976019346771db42abc9bba0a81670f908180a1d5821d428fe313dab5fb34d46be33e38e249fc1cde97ed656aa7fafe9cde637186b43d33c2484c15249ab0f74c83d3460a30e702bc853df6580384ec8bfda3aa634e2384ed1968c4fb238f6bdd92b99b35ee5fa79790136e3de298f87e4ca4117c14c0362b5aa1e90f6dc2be7235a55b1233d1d82eba3ae3df296aea9b1825064b137db0643c54192842fbf997c2de41560785500ca0f921efe7a63fded6f8dda64a247db8fb4dc4ef9dd4e3be48188761922ede91f20947e5ac3a4b53b34aefafd285990910dc9d4e5469e01c6677507
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174741);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2023-28962", "CVE-2023-28963");
  script_xref(name:"JSA", value:"JSA70587");
  script_xref(name:"IAVA", value:"2023-A-0201");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA70587)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA70587 advisory.

  - An Improper Authentication vulnerability in upload-file.php, used by the J-Web component of Juniper
    Networks Junos OS allows an unauthenticated, network-based attacker to upload arbitrary files to temporary
    folders on the device. (CVE-2023-28962)

  - An Improper Authentication vulnerability in cert-mgmt.php, used by the J-Web component of Juniper Networks
    Junos OS allows an unauthenticated, network-based attacker to read arbitrary files from temporary folders
    on the device. (CVE-2023-28963)

Note: Nessus found J-Web enabled [set system services web-management http(s)] on this device.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2023-04-Security-Bulletin-Junos-OS-Multiple-vulnerabilities-in-J-Web
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0d623ff");
  script_set_attribute(attribute:"solution", value:
"Disable J-Web, or limit access to only trusted hosts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28962");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0',      'fixed_ver':'19.4R3-S11'},
  {'min_ver':'20.1R1', 'fixed_ver':'20.2R3-S7'},  # No fixed version for 20.1R1 and later
  {'min_ver':'20.3R1', 'fixed_ver':'20.4R3-S6'},  # No fixed version for 20.3R1 and later
  {'min_ver':'21.1R1', 'fixed_ver':'21.2R3-S4'},  # No fixed version for 21.1R1 and later
  {'min_ver':'21.3',   'fixed_ver':'21.3R3-S3'},
  {'min_ver':'21.4',   'fixed_ver':'21.4R3-S3'},
  {'min_ver':'22.1',   'fixed_ver':'22.1R3-S1'},
  {'min_ver':'22.2',   'fixed_ver':'22.2R2-S1', 'fixed_display':'22.2R2-S1, 22.2R3'},
  {'min_ver':'22.3',   'fixed_ver':'22.3R1-S2', 'fixed_display':'22.3R1-S2, 22.3R2'}
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
