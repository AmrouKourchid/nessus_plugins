#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-079.
##

include('compat.inc');

if (description)
{
  script_id(164754);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2021-4181",
    "CVE-2021-4182",
    "CVE-2021-4184",
    "CVE-2021-4185",
    "CVE-2021-4186",
    "CVE-2021-4190",
    "CVE-2021-39920",
    "CVE-2021-39921",
    "CVE-2021-39922",
    "CVE-2021-39923",
    "CVE-2021-39924",
    "CVE-2021-39925",
    "CVE-2021-39926",
    "CVE-2021-39928",
    "CVE-2021-39929",
    "CVE-2022-0581",
    "CVE-2022-0582",
    "CVE-2022-0583",
    "CVE-2022-0585",
    "CVE-2022-0586"
  );
  script_xref(name:"IAVB", value:"2022-B-0035-S");

  script_name(english:"Amazon Linux 2022 : wireshark-cli, wireshark-devel (ALAS2022-2022-079)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-079 advisory.

    A NULL pointer exception flaw was found in Wireshark. A process failure on crafted or malformed input in
    the IPPUSB dissector can cause a denial of service via a packet injection or a crafted capture file.
    (CVE-2021-39920)

    A NULL pointer exception flaw was found in Wireshark. A process failure on crafted or malformed input in
    the Modbus dissector can cause a denial of service via a packet injection or crafted capture file.
    (CVE-2021-39921)

    A flaw was found in Wireshark. A process failure on crafted or malformed ANSI C12.22  input can cause a
    denial of service via packet injection or a crafted capture file. (CVE-2021-39922)

    A flaw was found in Wireshark. A process failure consumes excessive CPU resources on crafted or malformed
    PNRP input and can cause a denial of service. (CVE-2021-39923)

    A flaw was found in Wireshark. A process failure on crafted or malformed Bluetooth DHT input can cause a
    denial of service via packet injection or a crafted capture file. (CVE-2021-39924)

    A flaw was found in Wireshark. A process failure on crafted or malformed Bluetooth SDP input can cause a
    denial of service via packet injection or a crafted capture file. (CVE-2021-39925)

    A flaw was found in Wireshark. A process failure on crafted or malformed HCI_ISO input can cause a denial
    of service via packet injection or a crafted capture file. (CVE-2021-39926)

    A flaw was found in Wireshark. A process failure on crafted or malformed IEEE 802.11 input can cause a
    denial of service via packet injection or a crafted capture file. (CVE-2021-39928)

    A flaw was found in Wireshark.  A process failure on crafted or malformed  Bluetooth DHT input can cause a
    denial of service. (CVE-2021-39929)

    A denial of service via packet injection flaw was found in wireshark. An attacker with local network
    access could pass specially crafted capture files causing an application to halt or crash, leading to a
    denial of service. (CVE-2021-4181)

    A parser infinite-loop flaw was found in wireshark. An attacker with local network access could pass
    specially crafted capture files causing an application to halt, crash, or infinite loop. (CVE-2021-4182)

    An infinite-loop flaw was found in Wireshark's DHT dissector module. This flaw allows an attacker with
    local network access to pass specially crafted capture files, causing an application to halt, crash or go
    into an infinite loop. (CVE-2021-4184)

    An infinite-loop flaw was found in Wireshark RTMPT. This flaw allows an attacker with local network access
    to pass specially crafted capture files, causing an application to halt, crash, or go into an infinite
    loop. (CVE-2021-4185)

    A segmentation issue was found in Wireshark. This flaw allows an attacker with local network access to
    pass specially crafted capture files, causing an application to halt or crash. (CVE-2021-4186)

    An infinite-loop flaw was found in Wireshark. This flaw allows an attacker with local network access to
    pass specially crafted capture files, causing an application to halt, crash, or go into an infinite loop.
    (CVE-2021-4190)

    Crash in the CMS protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows denial of
    service via packet injection or crafted capture file (CVE-2022-0581)

    Unaligned access in the CSN.1 protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows
    denial of service via packet injection or crafted capture file (CVE-2022-0582)

    Crash in the PVFS protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows denial of
    service via packet injection or crafted capture file (CVE-2022-0583)

    Large loops in multiple protocol dissectors in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allow denial
    of service via packet injection or crafted capture file (CVE-2022-0585)

    Infinite loop in RTMPT protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows denial of
    service via packet injection or crafted capture file (CVE-2022-0586)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-079.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-39920.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-39921.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-39922.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-39923.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-39924.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-39925.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-39926.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-39928.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-39929.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4181.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4182.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4184.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4185.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4186.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4190.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0581.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0582.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0583.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0585.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0586.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220518 wireshark' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0582");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark-cli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'wireshark-cli-3.6.2-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-cli-3.6.2-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-cli-3.6.2-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-cli-debuginfo-3.6.2-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-cli-debuginfo-3.6.2-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-cli-debuginfo-3.6.2-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-debugsource-3.6.2-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-debugsource-3.6.2-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-debugsource-3.6.2-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-devel-3.6.2-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-devel-3.6.2-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wireshark-devel-3.6.2-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark-cli / wireshark-cli-debuginfo / wireshark-debugsource / etc");
}
