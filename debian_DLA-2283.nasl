#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2283-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138782);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/29");

  script_cve_id("CVE-2020-11724");

  script_name(english:"Debian DLA-2283-1 : nginx security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An HTTP request smuggling issue was discovered in the ngx_lua plugin
for nginx, a high-performance web and reverse proxy server, as
demonstrated by the ngx.location.capture API.

For Debian 9 stretch, this problem has been fixed in version
1.10.3-1+deb9u5.

We recommend that you upgrade your nginx packages.

For the detailed security status of nginx please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/nginx

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/nginx");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nginx");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11724");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-auth-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-cache-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-dav-ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-echo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-fancyindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-headers-more-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-ndk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-subs-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-uploadprogress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-upstream-fair");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-nchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-light");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-auth-pam", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-cache-purge", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-dav-ext", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-echo", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-fancyindex", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-geoip", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-headers-more-filter", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-image-filter", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-lua", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-ndk", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-perl", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-subs-filter", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-uploadprogress", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-upstream-fair", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-xslt-filter", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-mail", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-nchan", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-stream", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"nginx", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-common", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-doc", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-extras", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-full", reference:"1.10.3-1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-light", reference:"1.10.3-1+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
