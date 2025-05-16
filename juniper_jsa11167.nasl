#TRUSTED 82211a63fe55ad23a004d7a588b1fe3cc1fecb2204126ade6e35ec9b51cf643d05816c80757e6f3fa7d7437ff71e40ec2e807b3b9f364fd5186d18e66b031c4d96a8f4bf1c0b43c6bd2eedf00423f6cab62ac0dd5e1d621cfa8ea04aa8f24558b188d6ba0b784068c26bef4c6a117dfc7870d9635db7f3331ac612f611131a062009d729f6337a10d8200c95ab543026da34be0cd1e840be63eaeb0d06a7286675c80f1768e0717be9cdf25e7f7b9b9779155a66672c77db60246e3d2ff9f8b9e23b0de15b8df873cdc31f4bc734c002e54c9790d4bf1af3aa05a2f7b17250638323fa0325eea89adfd9a43c04cc96b760927b2710213bd03f54c33eb9ff99e5d461564f140bf9a39a0871e3a333f2c1abc9b52832a6ce0f727dc823191b5b38fa994d3b6cad87832cc18f7b82fac36c08ff7630b6f0906f4eb2423a9dd3a315a11705f7e8fff76639b6de77189b326a3c1c2263a9aa70bf9b8e9a0ab366a770a4b45377d5f080b4d046f8a24c71167e99063f498e663b6b8bb23e12672087e944aba5718697283b964be71722f908a296d0e3e16cc7567b1e3858f4be36dd47c079f5c821ecc169863fdb251f02a8ee3d1d718f6f1ea0efa6efc8923b176c7190bb6280259b376665d022b0034c24f9b3b6226e0c87b8a6753aa3a23fabefaa0c26f86bf5878c63f4834f2dd7e355f65d2966c38e1e442de23191d168ac266a
#TRUST-RSA-SHA256 825e4e70be0be2ab467ca7f77ed4c4382c5df30a1e34c6663a59bae1250d7af9fec037528b43cc8fea97e1f1737e8b565bcd22e96d34701fe54ee90298f9cda0adb9fde41eb143cc51bb8657df3fd89159eb25c8020839da817841af215fd3bf562684bdf03bc7d25138376d0142ac7afbd7b7e38cbc60f8e6961de6962a53de6c71bf03fd63d07bd48ab29ab416196e1c6f63dfc97d3e9c7ea2a10ffe6838bc2783861ca79f565e0888c1d5a5b876c6c010fc1244af67e04cec9c4ef78d686abe9ed901a0ec16b95c0ca219aab700e8ca091740147dca9ac3e947a0b27de7370ab05987f7851b47c7ec660bdba6b65bff278bf56f3c48f75f808620f17f020d8b55016dc8b0719fccadc921c6cb947a32ec15347503c692d0372ba33927650d37d924257ab6eb0e3a4cd4199b9a46042155fef58d2bec5722e5a72cd7da473005ec554f6948601492260d47d5035f6c697d0a8e7602a8351a1e87d9d27c80f644c82a83a9b3aa01cd5eb1ce9a1b2a7b6421a1071a109675fedf9c03bd20c1abd405a6401175f73a7a3b59da250dc0729720c05b28527e17a9a513b9cfaf6e13ffc84001787ff0a7be22887aa30556e8593596c1e22e6bbd2a7a4531b6b044b542f2e2d48854a586c3396976f28930f9f1405b62e8692f2160fdf5d9eca9f68b1a88ec7b0311641e228ef0984b43209d2ac52d831d778c40f5f669d50f30d541
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149967);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/28");

  script_cve_id(
    "CVE-2019-9511",
    "CVE-2019-9512",
    "CVE-2019-9513",
    "CVE-2019-9514",
    "CVE-2019-9515",
    "CVE-2019-9516",
    "CVE-2019-9517",
    "CVE-2019-9518"
  );
  script_xref(name:"JSA", value:"JSA11167");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Juniper Junos OS Multiple DoS Vulnerabilities (JSA11167)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple denial of service vulnerabilities as referenced
in the JSA11167 advisory:

  - Some HTTP/2 implementations are vulnerable to window size manipulation and stream prioritization manipulation, potentially
  leading to a denial of service. The attacker requests a large amount of data from a specified resource over multiple streams.
  They manipulate window size and stream priority to force the server to queue the data in 1-byte chunks. Depending on how
  efficiently this data is queued, this can consume excess CPU, memory, or both. (CVE-2019-9511)
  
  - Some HTTP/2 implementations are vulnerable to resource loops, potentially leading to a denial of service. The attacker
  creates multiple request streams and continually shuffles the priority of the streams in a way that causes substantial churn
  to the priority tree. This can consume excess CPU. (CVE-2019-9513)

  - Some HTTP/2 implementations are vulnerable to a reset flood, potentially leading to a denial of service. The attacker opens
  a number of streams and sends an invalid request over each stream that should solicit a stream of RST_STREAM frames from the
  peer. Depending on how the peer queues the RST_STREAM frames, this can consume excess memory, CPU, or both. (CVE-2019-9514)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11167");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11167");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'16.1R3', 'fixed_ver':'18.3R2-S4'},
  {'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S3'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S5'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S4'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S2'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S5', 'fixed_display':'19.2R1-S5, 19.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set system services extension-service request-response grpc", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
