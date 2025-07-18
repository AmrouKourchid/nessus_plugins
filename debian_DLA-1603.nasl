#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1603-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119425);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/17");

  script_cve_id("CVE-2017-15377", "CVE-2017-7177", "CVE-2018-6794");

  script_name(english:"Debian DLA-1603-1 : suricata security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several issues were found in suricata, an intrusion detection and
prevention tool.

CVE-2017-7177

Suricata has an IPv4 defragmentation evasion issue caused by lack of a
check for the IP protocol during fragment matching.

CVE-2017-15377

It was possible to trigger lots of redundant checks on the content of
crafted network traffic with a certain signature, because of
DetectEngineContentInspection in detect-engine-content-inspection.c.
The search engine doesn't stop when it should after no match is found;
instead, it stops only upon reaching inspection-recursion- limit (3000
by default).

CVE-2018-6794

Suricata is prone to an HTTP detection bypass vulnerability in
detect.c and stream-tcp.c. If a malicious server breaks a normal TCP
flow and sends data before the 3-way handshake is complete, then the
data sent by the malicious server will be accepted by web clients such
as a web browser or Linux CLI utilities, but ignored by Suricata IDS
signatures. This mostly affects IDS signatures for the HTTP protocol
and TCP stream content; signatures for TCP packets will inspect such
network traffic as usual.

TEMP-0856648-2BC2C9 (no CVE assigned yet)

Out of bounds read in app-layer-dns-common.c. On a zero size A or AAAA
record, 4 or 16 bytes would still be read.

For Debian 8 'Jessie', these problems have been fixed in version
2.0.7-2+deb8u3.

We recommend that you upgrade your suricata packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/suricata");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected suricata package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6794");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7177");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:suricata");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"suricata", reference:"2.0.7-2+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
