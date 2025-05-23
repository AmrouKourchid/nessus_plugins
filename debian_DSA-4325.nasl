#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4325. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118408);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id(
    "CVE-2017-7651",
    "CVE-2017-7652",
    "CVE-2017-7653",
    "CVE-2017-7654"
  );
  script_xref(name:"DSA", value:"4325");

  script_name(english:"Debian DSA-4325-1 : mosquitto - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"It was discovered that mosquitto, an MQTT broker, was vulnerable to
remote denial-of-service attacks that could be mounted using various
vectors.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=911265");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=911266");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mosquitto");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/mosquitto");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4325");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mosquitto packages.

For the stable distribution (stretch), these problems have been fixed
in version 1.4.10-3+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7652");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"9.0", prefix:"libmosquitto-dev", reference:"1.4.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libmosquitto1", reference:"1.4.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libmosquitto1-dbg", reference:"1.4.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libmosquittopp-dev", reference:"1.4.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libmosquittopp1", reference:"1.4.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libmosquittopp1-dbg", reference:"1.4.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"mosquitto", reference:"1.4.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"mosquitto-clients", reference:"1.4.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"mosquitto-dbg", reference:"1.4.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"mosquitto-dev", reference:"1.4.10-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
