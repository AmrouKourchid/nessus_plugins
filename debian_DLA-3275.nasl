#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3275. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170183);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2022-46871",
    "CVE-2022-46877",
    "CVE-2023-23598",
    "CVE-2023-23601",
    "CVE-2023-23602",
    "CVE-2023-23603",
    "CVE-2023-23605"
  );
  script_xref(name:"IAVA", value:"2023-A-0048-S");

  script_name(english:"Debian dla-3275 : firefox-esr - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3275 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3275-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/               Emilio Pozuelo Monfort
    January 19, 2023                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : firefox-esr
    Version        : 102.7.0esr-1~deb10u1
    CVE ID         : CVE-2022-46871 CVE-2022-46877 CVE-2023-23598 CVE-2023-23601
                     CVE-2023-23602 CVE-2023-23603 CVE-2023-23605

    Multiple security issues have been found in the Mozilla Firefox web
    browser, which could potentially result in the execution of arbitrary
    code, information disclosure or spoofing.

    For Debian 10 buster, these problems have been fixed in version
    102.7.0esr-1~deb10u1.

    We recommend that you upgrade your firefox-esr packages.

    For the detailed security status of firefox-esr please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/firefox-esr

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/firefox-esr");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-46871");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-46877");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23603");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23605");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/firefox-esr");
  script_set_attribute(attribute:"solution", value:
"Upgrade the firefox-esr packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23605");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ca-valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-en-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-mx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gu-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hi-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ne-np");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-son");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-trs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ca-valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-en-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-mx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gu-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hi-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ne-np");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-son");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-trs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'firefox-esr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ach', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-af', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-all', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-an', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ar', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ast', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-az', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-be', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-bg', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-bn', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-br', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-bs', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ca', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ca-valencia', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-cak', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-cs', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-cy', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-da', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-de', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-dsb', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-el', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-en-ca', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-en-gb', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-eo', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-es-ar', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-es-cl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-es-es', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-es-mx', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-et', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-eu', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-fa', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ff', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-fi', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-fr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-fur', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-fy-nl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ga-ie', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-gd', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-gl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-gn', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-gu-in', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-he', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-hi-in', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-hr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-hsb', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-hu', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-hy-am', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ia', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-id', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-is', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-it', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ja', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ka', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-kab', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-kk', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-km', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-kn', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ko', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-lij', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-lt', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-lv', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-mk', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-mr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ms', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-my', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-nb-no', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ne-np', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-nl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-nn-no', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-oc', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-pa-in', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-pl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-pt-br', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-pt-pt', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-rm', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ro', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ru', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-sc', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-sco', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-si', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-sk', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-sl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-son', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-sq', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-sr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-sv-se', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-szl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ta', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-te', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-tg', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-th', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-tl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-tr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-trs', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-uk', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-ur', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-uz', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-vi', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-xh', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-zh-cn', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'firefox-esr-l10n-zh-tw', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ach', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-af', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-all', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-an', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ar', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ast', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-az', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-be', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-bg', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-bn', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-br', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-bs', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ca', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ca-valencia', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-cak', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-cs', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-cy', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-da', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-de', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-dsb', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-el', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-en-ca', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-en-gb', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-eo', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-es-ar', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-es-cl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-es-es', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-es-mx', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-et', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-eu', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-fa', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ff', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-fi', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-fr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-fur', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-fy-nl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ga-ie', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-gd', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-gl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-gn', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-gu-in', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-he', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-hi-in', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-hr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-hsb', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-hu', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-hy-am', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ia', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-id', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-is', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-it', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ja', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ka', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-kab', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-kk', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-km', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-kn', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ko', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-lij', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-lt', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-lv', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-mk', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-mr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ms', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-my', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-nb-no', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ne-np', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-nl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-nn-no', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-oc', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-pa-in', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-pl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-pt-br', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-pt-pt', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-rm', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ro', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ru', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-sc', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-sco', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-si', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-sk', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-sl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-son', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-sq', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-sr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-sv-se', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-szl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ta', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-te', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-tg', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-th', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-tl', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-tr', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-trs', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-uk', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-ur', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-uz', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-vi', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-xh', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-zh-cn', 'reference': '102.7.0esr-1~deb10u1'},
    {'release': '10.0', 'prefix': 'iceweasel-l10n-zh-tw', 'reference': '102.7.0esr-1~deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox-esr / firefox-esr-l10n-ach / firefox-esr-l10n-af / etc');
}
