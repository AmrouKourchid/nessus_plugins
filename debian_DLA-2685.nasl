#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2685-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(150796);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id("CVE-2021-28651", "CVE-2021-28652", "CVE-2021-31806", "CVE-2021-31807", "CVE-2021-31808", "CVE-2021-33620");

  script_name(english:"Debian DLA-2685-1 : squid3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in Squid, a proxy caching
server. 

CVE-2021-28651

Due to a buffer-management bug, it allows a denial of service. When
resolving a request with the urn: scheme, the parser leaks a small
amount of memory. However, there is an unspecified attack methodology
that can easily trigger a large amount of memory consumption.

CVE-2021-28652

Due to incorrect parser validation, it allows a Denial of Service
attack against the Cache Manager API. This allows a trusted client to
trigger memory leaks that. over time, lead to a Denial of Service via
an unspecified short query string. This attack is limited to clients
with Cache Manager API access privilege.

CVE-2021-31806

Due to a memory-management bug, it is vulnerable to a Denial of
Service attack (against all clients using the proxy) via HTTP Range
request processing.

CVE-2021-31807

An integer overflow problem allows a remote server to achieve Denial
of Service when delivering responses to HTTP Range requests. The issue
trigger is a header that can be expected to exist in HTTP traffic
without any malicious intent.

CVE-2021-31808

Due to an input-validation bug, it is vulnerable to a Denial of
Service attack (against all clients using the proxy). A client sends
an HTTP Range request to trigger this.

CVE-2021-33620

Remote servers to cause a denial of service (affecting availability to
all clients) via an HTTP response. The issue trigger is a header that
can be expected to exist in HTTP traffic without any malicious intent
by the server.

For Debian 9 stretch, these problems have been fixed in version
3.5.23-5+deb9u7.

We recommend that you upgrade your squid3 packages.

For the detailed security status of squid3 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/squid3

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/squid3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28651");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squidclient");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

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
if (deb_check(release:"9.0", prefix:"squid", reference:"3.5.23-5+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"squid-cgi", reference:"3.5.23-5+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"squid-common", reference:"3.5.23-5+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"squid-dbg", reference:"3.5.23-5+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"squid-purge", reference:"3.5.23-5+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"squid3", reference:"3.5.23-5+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"squidclient", reference:"3.5.23-5+deb9u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
