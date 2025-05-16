#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3906. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(207910);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id(
    "CVE-2021-4181",
    "CVE-2021-4182",
    "CVE-2021-4184",
    "CVE-2021-4185",
    "CVE-2021-4186",
    "CVE-2021-4190",
    "CVE-2022-0581",
    "CVE-2022-0582",
    "CVE-2022-0583",
    "CVE-2022-0585",
    "CVE-2022-0586",
    "CVE-2022-3190",
    "CVE-2022-4344",
    "CVE-2022-4345",
    "CVE-2023-0411",
    "CVE-2023-0412",
    "CVE-2023-0413",
    "CVE-2023-0415",
    "CVE-2023-0416",
    "CVE-2023-0417",
    "CVE-2023-0666",
    "CVE-2023-0667",
    "CVE-2023-0668",
    "CVE-2023-1161",
    "CVE-2023-1992",
    "CVE-2023-1993",
    "CVE-2023-1994",
    "CVE-2023-2855",
    "CVE-2023-2856",
    "CVE-2023-2858",
    "CVE-2023-2879",
    "CVE-2023-2906",
    "CVE-2023-2952",
    "CVE-2023-3648",
    "CVE-2023-3649",
    "CVE-2023-4511",
    "CVE-2023-4512",
    "CVE-2023-4513",
    "CVE-2023-6175",
    "CVE-2024-0208",
    "CVE-2024-0209",
    "CVE-2024-0211",
    "CVE-2024-2955",
    "CVE-2024-4853",
    "CVE-2024-4854",
    "CVE-2024-8250",
    "CVE-2024-8645"
  );
  script_xref(name:"IAVB", value:"2021-B-0072-S");
  script_xref(name:"IAVB", value:"2022-B-0004-S");
  script_xref(name:"IAVB", value:"2022-B-0006-S");
  script_xref(name:"IAVB", value:"2022-B-0035-S");
  script_xref(name:"IAVB", value:"2023-B-0004-S");
  script_xref(name:"IAVB", value:"2023-B-0008-S");
  script_xref(name:"IAVB", value:"2023-B-0024-S");
  script_xref(name:"IAVB", value:"2023-B-0036-S");
  script_xref(name:"IAVB", value:"2023-B-0051-S");
  script_xref(name:"IAVB", value:"2023-B-0063-S");
  script_xref(name:"IAVB", value:"2023-B-0091-S");
  script_xref(name:"IAVB", value:"2024-B-0001-S");
  script_xref(name:"IAVB", value:"2024-B-0028-S");
  script_xref(name:"IAVB", value:"2024-B-0061-S");
  script_xref(name:"IAVB", value:"2024-B-0126-S");

  script_name(english:"Debian dla-3906 : libwireshark-data - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3906 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3906-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    September 30, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : wireshark
    Version        : 3.4.16-0+deb11u1
    CVE ID         : CVE-2021-4181 CVE-2021-4182 CVE-2021-4184 CVE-2021-4185
                     CVE-2021-4186 CVE-2021-4190 CVE-2022-0581 CVE-2022-0582
                     CVE-2022-0583 CVE-2022-0585 CVE-2022-0586 CVE-2022-3190
                     CVE-2022-4344 CVE-2022-4345 CVE-2023-0411 CVE-2023-0412
                     CVE-2023-0413 CVE-2023-0415 CVE-2023-0416 CVE-2023-0417
                     CVE-2023-0666 CVE-2023-0667 CVE-2023-0668 CVE-2023-1161
                     CVE-2023-1992 CVE-2023-1993 CVE-2023-1994 CVE-2023-2855
                     CVE-2023-2856 CVE-2023-2858 CVE-2023-2879 CVE-2023-2906
                     CVE-2023-2952 CVE-2023-3648 CVE-2023-3649 CVE-2023-4511
                     CVE-2023-4512 CVE-2023-4513 CVE-2023-6175 CVE-2024-0208
                     CVE-2024-0209 CVE-2024-0211 CVE-2024-2955 CVE-2024-4853
                     CVE-2024-4854 CVE-2024-8250 CVE-2024-8645
    Debian Bug     : 1033756 1034721 1041101 1059925 1068111 1080298

    Multiple vulnerabilities have been fixed in the network traffic analyzer
    Wireshark.

    CVE-2021-4181

        Sysdig Event dissector crash

    CVE-2021-4182

        RFC 7468 dissector crash

    CVE-2021-4184

        BitTorrent DHT dissector infinite loop

    CVE-2021-4185

        RTMPT dissector infinite loop

    CVE-2021-4186

        Gryphon dissector crash

    CVE-2021-4190

        Kafka dissector large loop DoS

    CVE-2022-0581

        CMS protocol dissector crash

    CVE-2022-0582

        CSN.1 protocol dissector unaligned access

    CVE-2022-0583

        PVFS protocol dissector crash

    CVE-2022-0585

        Large loops in multiple dissectors

    CVE-2022-0586

        RTMPT protocol dissector infinite loop

    CVE-2022-3190

        F5 Ethernet Trailer dissector infinite loop

    CVE-2022-4344

        Kafka protocol dissector memory exhaustion

    CVE-2022-4345

        Infinite loops in the BPv6, OpenFlow, and Kafka protocol dissectors

    CVE-2023-0411

        Excessive loops in the BPv6, NCP and RTPS protocol dissectors

    CVE-2023-0412

        TIPC dissector crash

    CVE-2023-0413

        Dissection engine bug DoS

    CVE-2023-0415

        iSCSI dissector crash

    CVE-2023-0416

        GNW dissector crash

    CVE-2023-0417

        NFS dissector memory leak

    CVE-2023-0666

        RTPS parsing heap overflow

    CVE-2023-0667

        MSMMS dissector buffer overflow

    CVE-2023-0668

        IEEE C37.118 Synchrophasor dissector crash

    CVE-2023-1161

        ISO 15765 dissector crash

    CVE-2023-1992

        RPCoRDMA dissector crash

    CVE-2023-1993

        LISP dissector large loop

    CVE-2023-1994

        GQUIC dissector crash

    CVE-2023-2855

        Candump log parser crash

    CVE-2023-2856

        VMS TCPIPtrace file parser crash

    CVE-2023-2858

        NetScaler file parser crash

    CVE-2023-2879

        GDSDB dissector infinite loop

    CVE-2023-2906

        CP2179 dissector crash

    CVE-2023-2952

        XRA dissector infinite loop

    CVE-2023-3648

        Kafka dissector crash

    CVE-2023-3649

        iSCSI dissector crash

    CVE-2023-4511

        BT SDP dissector infinite loop

    CVE-2023-4512

        CBOR dissector crash

    CVE-2023-4513

        BT SDP dissector memory leak

    CVE-2023-6175

        NetScreen file parser crash

    CVE-2024-0208

        GVCP dissector crash

    CVE-2024-0209

        IEEE 1609.2 dissector crash

    CVE-2024-0211

        DOCSIS dissector crash

    CVE-2024-2955

        T.38 dissector crash

    CVE-2024-4853

        Editcap byte chopping crash

    CVE-2024-4854

        MONGO dissector infinite loop

    CVE-2024-8250

        NTLMSSP dissector crash

    CVE-2024-8645

        SPRT dissector crash

    For Debian 11 bullseye, these problems have been fixed in version
    3.4.16-0+deb11u1.

    We recommend that you upgrade your wireshark packages.

    For the detailed security status of wireshark please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/wireshark

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wireshark");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4182");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4185");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4186");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4190");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0581");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0582");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0583");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0585");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3190");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4344");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4345");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0411");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0412");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0413");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0415");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0416");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0417");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0666");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0667");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0668");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1161");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1992");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1993");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1994");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2856");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2906");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2952");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3648");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3649");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4511");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4512");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4513");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6175");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0208");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0209");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0211");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2955");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-4853");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-4854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-8250");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-8645");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wireshark");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libwireshark-data packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0582");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libwireshark-data', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwireshark-dev', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwireshark14', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwiretap-dev', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwiretap11', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwsutil-dev', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwsutil12', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'tshark', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-common', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-dev', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-doc', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-gtk', 'reference': '3.4.16-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-qt', 'reference': '3.4.16-0+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwireshark-data / libwireshark-dev / libwireshark14 / libwiretap-dev / etc');
}
