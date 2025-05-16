#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5730. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(202458);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/22");

  script_cve_id(
    "CVE-2022-43945",
    "CVE-2022-48772",
    "CVE-2024-25741",
    "CVE-2024-26629",
    "CVE-2024-27019",
    "CVE-2024-31076",
    "CVE-2024-33621",
    "CVE-2024-33847",
    "CVE-2024-34027",
    "CVE-2024-35247",
    "CVE-2024-36014",
    "CVE-2024-36015",
    "CVE-2024-36016",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-36288",
    "CVE-2024-36489",
    "CVE-2024-36894",
    "CVE-2024-36971",
    "CVE-2024-36974",
    "CVE-2024-36978",
    "CVE-2024-37078",
    "CVE-2024-37353",
    "CVE-2024-37356",
    "CVE-2024-38381",
    "CVE-2024-38546",
    "CVE-2024-38547",
    "CVE-2024-38548",
    "CVE-2024-38549",
    "CVE-2024-38552",
    "CVE-2024-38555",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38560",
    "CVE-2024-38565",
    "CVE-2024-38567",
    "CVE-2024-38578",
    "CVE-2024-38579",
    "CVE-2024-38582",
    "CVE-2024-38583",
    "CVE-2024-38586",
    "CVE-2024-38587",
    "CVE-2024-38589",
    "CVE-2024-38590",
    "CVE-2024-38596",
    "CVE-2024-38597",
    "CVE-2024-38598",
    "CVE-2024-38599",
    "CVE-2024-38601",
    "CVE-2024-38605",
    "CVE-2024-38607",
    "CVE-2024-38612",
    "CVE-2024-38613",
    "CVE-2024-38615",
    "CVE-2024-38618",
    "CVE-2024-38619",
    "CVE-2024-38621",
    "CVE-2024-38627",
    "CVE-2024-38633",
    "CVE-2024-38634",
    "CVE-2024-38635",
    "CVE-2024-38637",
    "CVE-2024-38659",
    "CVE-2024-38661",
    "CVE-2024-38662",
    "CVE-2024-38780",
    "CVE-2024-39276",
    "CVE-2024-39292",
    "CVE-2024-39301",
    "CVE-2024-39467",
    "CVE-2024-39468",
    "CVE-2024-39469",
    "CVE-2024-39471",
    "CVE-2024-39475",
    "CVE-2024-39476",
    "CVE-2024-39480",
    "CVE-2024-39482",
    "CVE-2024-39484",
    "CVE-2024-39488",
    "CVE-2024-39489",
    "CVE-2024-39493",
    "CVE-2024-39495",
    "CVE-2024-39499",
    "CVE-2024-39501",
    "CVE-2024-39502",
    "CVE-2024-39503",
    "CVE-2024-39505",
    "CVE-2024-39506",
    "CVE-2024-39509",
    "CVE-2024-40901",
    "CVE-2024-40902",
    "CVE-2024-40904",
    "CVE-2024-40905",
    "CVE-2024-40912",
    "CVE-2024-40916",
    "CVE-2024-40929",
    "CVE-2024-40931",
    "CVE-2024-40932",
    "CVE-2024-40934",
    "CVE-2024-40941",
    "CVE-2024-40942",
    "CVE-2024-40943",
    "CVE-2024-40945",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40961",
    "CVE-2024-40963",
    "CVE-2024-40968",
    "CVE-2024-40971",
    "CVE-2024-40974",
    "CVE-2024-40976",
    "CVE-2024-40978",
    "CVE-2024-40980",
    "CVE-2024-40981",
    "CVE-2024-40983",
    "CVE-2024-40984",
    "CVE-2024-40987",
    "CVE-2024-40988",
    "CVE-2024-40990",
    "CVE-2024-40993",
    "CVE-2024-40995",
    "CVE-2024-41000",
    "CVE-2024-41004",
    "CVE-2024-41005",
    "CVE-2024-41006"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"Debian dsa-5730 : affs-modules-5.10.0-29-4kc-malta-di - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5730 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5730-1                   security@debian.org
    https://www.debian.org/security/                     Salvatore Bonaccorso
    July 15, 2024                         https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : linux
    CVE ID         : CVE-2022-43945 CVE-2022-48772 CVE-2024-25741 CVE-2024-26629
                     CVE-2024-27019 CVE-2024-31076 CVE-2024-33621 CVE-2024-33847
                     CVE-2024-34027 CVE-2024-35247 CVE-2024-36014 CVE-2024-36015
                     CVE-2024-36016 CVE-2024-36270 CVE-2024-36286 CVE-2024-36288
                     CVE-2024-36489 CVE-2024-36894 CVE-2024-36971 CVE-2024-36974
                     CVE-2024-36978 CVE-2024-37078 CVE-2024-37353 CVE-2024-37356
                     CVE-2024-38381 CVE-2024-38546 CVE-2024-38547 CVE-2024-38548
                     CVE-2024-38549 CVE-2024-38552 CVE-2024-38555 CVE-2024-38558
                     CVE-2024-38559 CVE-2024-38560 CVE-2024-38565 CVE-2024-38567
                     CVE-2024-38578 CVE-2024-38579 CVE-2024-38582 CVE-2024-38583
                     CVE-2024-38586 CVE-2024-38587 CVE-2024-38589 CVE-2024-38590
                     CVE-2024-38596 CVE-2024-38597 CVE-2024-38598 CVE-2024-38599
                     CVE-2024-38601 CVE-2024-38605 CVE-2024-38607 CVE-2024-38612
                     CVE-2024-38613 CVE-2024-38615 CVE-2024-38618 CVE-2024-38619
                     CVE-2024-38621 CVE-2024-38627 CVE-2024-38633 CVE-2024-38634
                     CVE-2024-38635 CVE-2024-38637 CVE-2024-38659 CVE-2024-38661
                     CVE-2024-38662 CVE-2024-38780 CVE-2024-39276 CVE-2024-39292
                     CVE-2024-39301 CVE-2024-39467 CVE-2024-39468 CVE-2024-39469
                     CVE-2024-39471 CVE-2024-39475 CVE-2024-39476 CVE-2024-39480
                     CVE-2024-39482 CVE-2024-39484 CVE-2024-39488 CVE-2024-39489
                     CVE-2024-39493 CVE-2024-39495 CVE-2024-39499 CVE-2024-39501
                     CVE-2024-39502 CVE-2024-39503 CVE-2024-39505 CVE-2024-39506
                     CVE-2024-39509 CVE-2024-40901 CVE-2024-40902 CVE-2024-40904
                     CVE-2024-40905 CVE-2024-40912 CVE-2024-40916 CVE-2024-40929
                     CVE-2024-40931 CVE-2024-40932 CVE-2024-40934 CVE-2024-40941
                     CVE-2024-40942 CVE-2024-40943 CVE-2024-40945 CVE-2024-40958
                     CVE-2024-40959 CVE-2024-40960 CVE-2024-40961 CVE-2024-40963
                     CVE-2024-40968 CVE-2024-40971 CVE-2024-40974 CVE-2024-40976
                     CVE-2024-40978 CVE-2024-40980 CVE-2024-40981 CVE-2024-40983
                     CVE-2024-40984 CVE-2024-40987 CVE-2024-40988 CVE-2024-40990
                     CVE-2024-40993 CVE-2024-40995 CVE-2024-41000 CVE-2024-41004
                     CVE-2024-41005 CVE-2024-41006

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 5.10.221-1.

    We recommend that you upgrade your linux packages.

    For the detailed security status of linux please refer to its security
    tracker page at:
    https://security-tracker.debian.org/tracker/linux

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43945");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25741");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31076");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-33621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-33847");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-34027");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35247");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36014");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36015");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36270");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36286");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36288");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36489");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36894");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36971");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36978");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-37078");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-37353");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-37356");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38381");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38546");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38547");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38548");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38549");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38552");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38555");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38558");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38559");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38560");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38565");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38567");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38578");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38579");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38582");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38583");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38587");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38589");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38590");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38596");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38605");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38607");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38612");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38613");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38615");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38618");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38633");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38634");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38635");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38637");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38659");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38661");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39276");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39292");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39301");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39467");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39468");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39469");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39471");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39475");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39476");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39480");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39482");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39484");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39488");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39489");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39493");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39495");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39499");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39501");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39502");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39503");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39505");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39506");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39509");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40901");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40902");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40904");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40905");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40912");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40929");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40931");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40932");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40941");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40942");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40943");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40945");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40958");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40959");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40960");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40961");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40963");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40968");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40971");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40976");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40978");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40980");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40983");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40984");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40987");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40988");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40990");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40993");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40995");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41000");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41004");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41005");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41006");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affs-modules-5.10.0-29-4kc-malta-di packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41000");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-29");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-29-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-31-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-29-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-29-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-29-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-29-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-29-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-29-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-31-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-31-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-31-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-31-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-31-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-31-s390x-di");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'bpftool', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'hyperv-daemons', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'libcpupower-dev', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'libcpupower1', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-arm', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-s390', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-x86', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-cpupower', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-doc', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-4kc-malta', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-4kc-malta', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-5kc-malta', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-686', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-686-pae', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-amd64', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-arm64', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-armmp', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-armmp-lpae', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-cloud-amd64', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-cloud-arm64', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-common', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-common-rt', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-loongson-3', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-marvell', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-octeon', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-powerpc64le', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rpi', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-686-pae', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-amd64', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-arm64', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-armmp', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-s390x', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5kc-malta', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-loongson-3', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-marvell', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-octeon', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-powerpc64le', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rpi', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-headers-s390x', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-4kc-malta', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-4kc-malta-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-5kc-malta', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-5kc-malta-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-686-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-686-pae-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-amd64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-arm64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp-lpae', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp-lpae-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-cloud-amd64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-cloud-arm64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-loongson-3', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-loongson-3-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-marvell', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-marvell-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-octeon', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-octeon-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-powerpc64le', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-powerpc64le-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rpi', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rpi-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-686-pae-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-amd64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-arm64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-armmp', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-armmp-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-s390x', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-s390x-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x-dbg', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-libc-dev', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-perf', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-source', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'linux-support-5.10.0-29', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-29-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-29-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-31-armmp-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-31-marvell-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'usbip', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-29-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-29-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-29-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-29-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-29-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-29-s390x-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-31-4kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-31-5kc-malta-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-31-loongson-3-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-31-octeon-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-31-powerpc64le-di', 'reference': '5.10.221-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-31-s390x-di', 'reference': '5.10.221-1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'affs-modules-5.10.0-29-4kc-malta-di / etc');
}
