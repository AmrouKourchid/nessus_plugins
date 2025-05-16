#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5658. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(193309);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/17");

  script_cve_id(
    "CVE-2023-2176",
    "CVE-2023-6270",
    "CVE-2023-7042",
    "CVE-2023-28746",
    "CVE-2023-47233",
    "CVE-2023-52429",
    "CVE-2023-52434",
    "CVE-2023-52435",
    "CVE-2023-52583",
    "CVE-2023-52584",
    "CVE-2023-52587",
    "CVE-2023-52588",
    "CVE-2023-52589",
    "CVE-2023-52593",
    "CVE-2023-52594",
    "CVE-2023-52595",
    "CVE-2023-52597",
    "CVE-2023-52598",
    "CVE-2023-52599",
    "CVE-2023-52600",
    "CVE-2023-52601",
    "CVE-2023-52602",
    "CVE-2023-52603",
    "CVE-2023-52604",
    "CVE-2023-52606",
    "CVE-2023-52607",
    "CVE-2023-52616",
    "CVE-2023-52617",
    "CVE-2023-52618",
    "CVE-2023-52619",
    "CVE-2023-52620",
    "CVE-2023-52621",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52630",
    "CVE-2023-52631",
    "CVE-2023-52632",
    "CVE-2023-52633",
    "CVE-2023-52635",
    "CVE-2023-52637",
    "CVE-2023-52638",
    "CVE-2023-52639",
    "CVE-2023-52640",
    "CVE-2023-52641",
    "CVE-2024-0340",
    "CVE-2024-0841",
    "CVE-2024-1151",
    "CVE-2024-2201",
    "CVE-2024-22099",
    "CVE-2024-23850",
    "CVE-2024-23851",
    "CVE-2024-24857",
    "CVE-2024-24858",
    "CVE-2024-26581",
    "CVE-2024-26582",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26586",
    "CVE-2024-26590",
    "CVE-2024-26593",
    "CVE-2024-26600",
    "CVE-2024-26601",
    "CVE-2024-26602",
    "CVE-2024-26603",
    "CVE-2024-26606",
    "CVE-2024-26621",
    "CVE-2024-26622",
    "CVE-2024-26625",
    "CVE-2024-26626",
    "CVE-2024-26627",
    "CVE-2024-26629",
    "CVE-2024-26639",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26651",
    "CVE-2024-26654",
    "CVE-2024-26659",
    "CVE-2024-26660",
    "CVE-2024-26663",
    "CVE-2024-26664",
    "CVE-2024-26665",
    "CVE-2024-26667",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26675",
    "CVE-2024-26676",
    "CVE-2024-26679",
    "CVE-2024-26680",
    "CVE-2024-26681",
    "CVE-2024-26684",
    "CVE-2024-26685",
    "CVE-2024-26686",
    "CVE-2024-26687",
    "CVE-2024-26688",
    "CVE-2024-26689",
    "CVE-2024-26695",
    "CVE-2024-26696",
    "CVE-2024-26697",
    "CVE-2024-26698",
    "CVE-2024-26700",
    "CVE-2024-26702",
    "CVE-2024-26704",
    "CVE-2024-26706",
    "CVE-2024-26707",
    "CVE-2024-26710",
    "CVE-2024-26712",
    "CVE-2024-26714",
    "CVE-2024-26715",
    "CVE-2024-26717",
    "CVE-2024-26718",
    "CVE-2024-26720",
    "CVE-2024-26722",
    "CVE-2024-26723",
    "CVE-2024-26726",
    "CVE-2024-26727",
    "CVE-2024-26731",
    "CVE-2024-26733",
    "CVE-2024-26735",
    "CVE-2024-26736",
    "CVE-2024-26737",
    "CVE-2024-26741",
    "CVE-2024-26742",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26745",
    "CVE-2024-26747",
    "CVE-2024-26748",
    "CVE-2024-26749",
    "CVE-2024-26750",
    "CVE-2024-26751",
    "CVE-2024-26752",
    "CVE-2024-26753",
    "CVE-2024-26754",
    "CVE-2024-26759",
    "CVE-2024-26760",
    "CVE-2024-26761",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26765",
    "CVE-2024-26766",
    "CVE-2024-26769",
    "CVE-2024-26771",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26774",
    "CVE-2024-26775",
    "CVE-2024-26776",
    "CVE-2024-26777",
    "CVE-2024-26778",
    "CVE-2024-26779",
    "CVE-2024-26780",
    "CVE-2024-26781",
    "CVE-2024-26782",
    "CVE-2024-26787",
    "CVE-2024-26788",
    "CVE-2024-26789",
    "CVE-2024-26790",
    "CVE-2024-26791",
    "CVE-2024-26792",
    "CVE-2024-26793",
    "CVE-2024-26795",
    "CVE-2024-26798",
    "CVE-2024-26800",
    "CVE-2024-26801",
    "CVE-2024-26802",
    "CVE-2024-26803",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26809",
    "CVE-2024-26810",
    "CVE-2024-26811",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26815",
    "CVE-2024-26816",
    "CVE-2024-27437"
  );

  script_name(english:"Debian dsa-5658 : affs-modules-6.1.0-11-4kc-malta-di - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5658 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5658-1                   security@debian.org
    https://www.debian.org/security/                     Salvatore Bonaccorso
    April 13, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : linux
    CVE ID         : CVE-2023-2176 CVE-2023-6270 CVE-2023-7042 CVE-2023-28746
                     CVE-2023-47233 CVE-2023-52429 CVE-2023-52434 CVE-2023-52435
                     CVE-2023-52583 CVE-2023-52584 CVE-2023-52587 CVE-2023-52588
                     CVE-2023-52589 CVE-2023-52593 CVE-2023-52594 CVE-2023-52595
                     CVE-2023-52597 CVE-2023-52598 CVE-2023-52599 CVE-2023-52600
                     CVE-2023-52601 CVE-2023-52602 CVE-2023-52603 CVE-2023-52604
                     CVE-2023-52606 CVE-2023-52607 CVE-2023-52616 CVE-2023-52617
                     CVE-2023-52618 CVE-2023-52619 CVE-2023-52620 CVE-2023-52621
                     CVE-2023-52622 CVE-2023-52623 CVE-2023-52630 CVE-2023-52631
                     CVE-2023-52632 CVE-2023-52633 CVE-2023-52635 CVE-2023-52637
                     CVE-2023-52638 CVE-2023-52639 CVE-2023-52640 CVE-2023-52641
                     CVE-2024-0340 CVE-2024-0841 CVE-2024-1151 CVE-2024-2201
                     CVE-2024-22099 CVE-2024-23850 CVE-2024-23851 CVE-2024-24857
                     CVE-2024-24858 CVE-2024-26581 CVE-2024-26582 CVE-2024-26583
                     CVE-2024-26584 CVE-2024-26585 CVE-2024-26586 CVE-2024-26590
                     CVE-2024-26593 CVE-2024-26600 CVE-2024-26601 CVE-2024-26602
                     CVE-2024-26603 CVE-2024-26606 CVE-2024-26621 CVE-2024-26622
                     CVE-2024-26625 CVE-2024-26626 CVE-2024-26627 CVE-2024-26629
                     CVE-2024-26639 CVE-2024-26640 CVE-2024-26641 CVE-2024-26642
                     CVE-2024-26643 CVE-2024-26651 CVE-2024-26654 CVE-2024-26659
                     CVE-2024-26660 CVE-2024-26663 CVE-2024-26664 CVE-2024-26665
                     CVE-2024-26667 CVE-2024-26671 CVE-2024-26673 CVE-2024-26675
                     CVE-2024-26676 CVE-2024-26679 CVE-2024-26680 CVE-2024-26681
                     CVE-2024-26684 CVE-2024-26685 CVE-2024-26686 CVE-2024-26687
                     CVE-2024-26688 CVE-2024-26689 CVE-2024-26695 CVE-2024-26696
                     CVE-2024-26697 CVE-2024-26698 CVE-2024-26700 CVE-2024-26702
                     CVE-2024-26704 CVE-2024-26706 CVE-2024-26707 CVE-2024-26710
                     CVE-2024-26712 CVE-2024-26714 CVE-2024-26715 CVE-2024-26717
                     CVE-2024-26718 CVE-2024-26720 CVE-2024-26722 CVE-2024-26723
                     CVE-2024-26726 CVE-2024-26727 CVE-2024-26731 CVE-2024-26733
                     CVE-2024-26735 CVE-2024-26736 CVE-2024-26737 CVE-2024-26741
                     CVE-2024-26742 CVE-2024-26743 CVE-2024-26744 CVE-2024-26745
                     CVE-2024-26747 CVE-2024-26748 CVE-2024-26749 CVE-2024-26750
                     CVE-2024-26751 CVE-2024-26752 CVE-2024-26753 CVE-2024-26754
                     CVE-2024-26759 CVE-2024-26760 CVE-2024-26761 CVE-2024-26763
                     CVE-2024-26764 CVE-2024-26765 CVE-2024-26766 CVE-2024-26769
                     CVE-2024-26771 CVE-2024-26772 CVE-2024-26773 CVE-2024-26774
                     CVE-2024-26775 CVE-2024-26776 CVE-2024-26777 CVE-2024-26778
                     CVE-2024-26779 CVE-2024-26780 CVE-2024-26781 CVE-2024-26782
                     CVE-2024-26787 CVE-2024-26788 CVE-2024-26789 CVE-2024-26790
                     CVE-2024-26791 CVE-2024-26792 CVE-2024-26793 CVE-2024-26795
                     CVE-2024-26798 CVE-2024-26800 CVE-2024-26801 CVE-2024-26802
                     CVE-2024-26803 CVE-2024-26804 CVE-2024-26805 CVE-2024-26809
                     CVE-2024-26810 CVE-2024-26811 CVE-2024-26812 CVE-2024-26813
                     CVE-2024-26814 CVE-2024-26815 CVE-2024-26816 CVE-2024-27437

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    For the stable distribution (bookworm), these problems have been fixed in
    version 6.1.85-1.

    We recommend that you upgrade your linux packages.

    For the detailed security status of linux please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQKTBAEBCgB9FiEERkRAmAjBceBVMd3uBUy48xNDz0QFAmYaIyZfFIAAAAAALgAo
    aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldDQ2
    NDQ0MDk4MDhDMTcxRTA1NTMxRERFRTA1NENCOEYzMTM0M0NGNDQACgkQBUy48xND
    z0RN3A/9HbzpFDgN8uqJJVEHYgDh38m+h/8maSC2qL3G9ZPEckWX6MLBm+yBWcJ0
    l/DesFcqc5Lh25bgWSO2jJ4TY4+dbTRFzFcJ/aTnbOKGoGCUQt0W9ZHFVwmkPKQN
    tbZm1W1K3u/5dz8qow1ntsQuBarD0uDpImbhOZdrk+n88yKVB4lqAqNgel6EPt03
    6SYAz/A3S1A3cgTEwz9udrA6du7yX/2vFwd9g4CO96VflHBgsHSnWAnmJZScZjIA
    MT8jWGEXUw0zPg78w6AieLWhXTRe/bRxzhPRtYMOwXu1rX3wcPO8cbF9+hgbdj9w
    VD+qKTP3PWzP7nxJ3KLRUf8NvHjOI5CvVJFR3UFVlOE+BtYO//POTZI9eUv9tU3x
    vqXXTuHN+uXHkOtvRImx0Hf6FxjQbdh6IuvK6ipb/YH6IE2jZOw94AYi75UkDkgf
    VBbQf7eShv81Z05tZQo1rFHQMYBbGjtpudJllQ8/zmbv+hM9WuL4NCkw6EQytFPU
    51lVn/8Cqx1wt0IAmKr4FQ3hz/d766jgQvByFQWhqs1ZD7vQy2SxbzzTsKT1Zlha
    GsRB5LNZXvIwZi/A4ls7+4YM4urbRljMFgU7sUaNl+nbhqcw0y/AoLcUGO+7vl6L
    S/9Mmm8mnmXvTTYCgw9tuLo/wCP9UlF5PTEsZTQyslJYVxu/bvQ=
    =IM/D
    -----END PGP SIGNATURE-----

    Reply to:
    debian-security-announce@lists.debian.org
    Salvatore Bonaccorso (on-list)
    Salvatore Bonaccorso (off-list)

    Prev by Date:
    [SECURITY] [DSA 5657-1] xorg-server security update

    Next by Date:
    [SECURITY] [DSA 5659-1] trafficserver security update

    Previous by thread:
    [SECURITY] [DSA 5657-1] xorg-server security update

    Next by thread:
    [SECURITY] [DSA 5659-1] trafficserver security update

    Index(es):

    Date
    Thread

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2176");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28746");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-47233");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52429");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52434");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52435");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52583");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52584");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52587");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52588");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52589");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52593");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52595");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52603");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52604");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52607");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52616");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52617");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52618");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52620");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52630");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52631");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52632");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52633");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52635");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52637");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52638");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52639");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52641");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-7042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0340");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-1151");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2201");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23850");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23851");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24857");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26581");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26582");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26583");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26584");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26585");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26590");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26593");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26603");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26625");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26626");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26639");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26641");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26642");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26643");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26651");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26654");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26659");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26660");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26664");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26665");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26667");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26671");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26673");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26675");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26676");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26679");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26680");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26681");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26684");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26686");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26687");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26688");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26689");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26695");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26696");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26697");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26698");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26700");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26702");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26704");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26706");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26710");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26712");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26714");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26715");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26717");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26718");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26720");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26726");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26727");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26731");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26736");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26737");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26741");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26742");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26743");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26747");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26749");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26750");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26751");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26754");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26759");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26761");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26764");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26765");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26766");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26769");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26773");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26774");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26775");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26777");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26778");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26779");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26782");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26787");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26788");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26789");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26790");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26791");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26793");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26798");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26800");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26801");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26803");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26805");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26809");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26810");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26811");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26812");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26813");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26814");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26815");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26816");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27437");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affs-modules-6.1.0-11-4kc-malta-di packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-12-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-12-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-12-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-mips32r2el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-mips64r2el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-11-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-mips32r2el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-mips64r2el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-mips32r2el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-mips32r2el-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-mips64r2el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-mips64r2el-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-11-s390x-dbg");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-mips32r2el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-mips32r2el-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-mips64r2el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-mips64r2el-dbg");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-11-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-11-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-11-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-11-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-17-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-17-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-20-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-20-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-6.1.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-11-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-11-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-11-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-11-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-11-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-11-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-12-mips32r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-12-mips64r2el-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-6.1.0-12-octeon-di");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'affs-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ata-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'bpftool', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'btrfs-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'cdrom-core-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crc-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-dm-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'crypto-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'dasd-extra-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'dasd-extra-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'dasd-extra-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'dasd-extra-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'dasd-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'dasd-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'dasd-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'dasd-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'efi-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'efi-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'efi-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'efi-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'event-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ext4-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'f2fs-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fancontrol-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fancontrol-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fancontrol-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fancontrol-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fat-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fb-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'firewire-core-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'fuse-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'hyperv-daemons', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'hypervisor-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'hypervisor-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'hypervisor-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'hypervisor-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'i2c-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'i2c-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'i2c-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'i2c-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'i2c-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'i2c-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'i2c-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'i2c-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'input-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ipv6-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ipv6-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ipv6-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'isofs-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jffs2-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jffs2-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jffs2-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'jfs-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'kernel-image-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'leds-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'leds-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'leds-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'leds-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'leds-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'leds-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'leds-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'libcpupower-dev', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'libcpupower1', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-compiler-gcc-12-arm', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-compiler-gcc-12-s390', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-compiler-gcc-12-x86', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-config-6.1', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-cpupower', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-doc', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-doc-6.1', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-4kc-malta', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-5kc-malta', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-4kc-malta', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-5kc-malta', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-686', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-686-pae', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-amd64', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-arm64', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-armmp', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-armmp-lpae', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-cloud-amd64', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-cloud-arm64', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-common', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-common-rt', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-loongson-3', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-marvell', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-mips32r2el', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-mips64r2el', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-octeon', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-powerpc64le', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-rpi', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-rt-686-pae', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-rt-amd64', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-rt-arm64', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-rt-armmp', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-6.1.0-11-s390x', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-armmp', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-loongson-3', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-marvell', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-mips32r2el', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-mips64r2el', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-octeon', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-powerpc64le', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-rpi', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-headers-s390x', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-4kc-malta', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-4kc-malta-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-5kc-malta', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-5kc-malta-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-4kc-malta', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-4kc-malta-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-5kc-malta', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-5kc-malta-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-686-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-686-pae-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-amd64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-arm64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-armmp', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-armmp-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-armmp-lpae', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-armmp-lpae-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-cloud-amd64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-cloud-arm64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-loongson-3', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-loongson-3-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-marvell', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-marvell-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-mips32r2el', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-mips32r2el-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-mips64r2el', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-mips64r2el-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-octeon', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-octeon-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-powerpc64le', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-powerpc64le-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-rpi', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-rpi-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-rt-686-pae-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-rt-amd64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-rt-arm64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-rt-armmp', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-rt-armmp-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-s390x', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-6.1.0-11-s390x-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-686-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-armmp', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-loongson-3', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-loongson-3-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-marvell', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-marvell-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-mips32r2el', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-mips32r2el-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-mips64r2el', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-mips64r2el-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-octeon', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-octeon-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-powerpc64le', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-powerpc64le-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-rpi', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-rpi-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-rt-armmp', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-s390x', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-image-s390x-dbg', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-kbuild-6.1', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-libc-dev', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-perf', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-source', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-source-6.1', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'linux-support-6.1.0-11', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'loop-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'md-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'minix-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-core-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mmc-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mouse-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-core-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'mtd-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'multipath-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nbd-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nfs-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-shared-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-usb-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'nic-wireless-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'pata-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'ppp-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'rtla', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sata-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-core-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'scsi-nic-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'serial-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'serial-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'serial-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'serial-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'sound-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'speakup-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'squashfs-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'udf-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'uinput-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-serial-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-11-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-11-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-12-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-17-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-17-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-20-armmp-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-20-marvell-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usb-storage-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'usbip', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-11-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-11-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-11-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-11-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-11-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-11-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-11-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-11-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-12-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-12-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-12-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-12-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-12-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-12-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-12-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-12-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-17-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-17-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-17-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-17-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-17-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-17-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-17-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-17-s390x-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-20-4kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-20-5kc-malta-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-20-loongson-3-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-20-mips32r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-20-mips64r2el-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-20-octeon-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-20-powerpc64le-di', 'reference': '6.1.85-1'},
    {'release': '12.0', 'prefix': 'xfs-modules-6.1.0-20-s390x-di', 'reference': '6.1.85-1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'affs-modules-6.1.0-11-4kc-malta-di / etc');
}
