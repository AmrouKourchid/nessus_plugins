#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3912. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(208245);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id(
    "CVE-2021-3669",
    "CVE-2022-48733",
    "CVE-2023-31083",
    "CVE-2023-52889",
    "CVE-2024-27397",
    "CVE-2024-38577",
    "CVE-2024-41011",
    "CVE-2024-41042",
    "CVE-2024-41098",
    "CVE-2024-42114",
    "CVE-2024-42228",
    "CVE-2024-42246",
    "CVE-2024-42259",
    "CVE-2024-42265",
    "CVE-2024-42272",
    "CVE-2024-42276",
    "CVE-2024-42280",
    "CVE-2024-42281",
    "CVE-2024-42283",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42286",
    "CVE-2024-42287",
    "CVE-2024-42288",
    "CVE-2024-42289",
    "CVE-2024-42290",
    "CVE-2024-42292",
    "CVE-2024-42295",
    "CVE-2024-42297",
    "CVE-2024-42301",
    "CVE-2024-42302",
    "CVE-2024-42304",
    "CVE-2024-42305",
    "CVE-2024-42306",
    "CVE-2024-42308",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-42311",
    "CVE-2024-42312",
    "CVE-2024-42313",
    "CVE-2024-43828",
    "CVE-2024-43829",
    "CVE-2024-43830",
    "CVE-2024-43834",
    "CVE-2024-43835",
    "CVE-2024-43839",
    "CVE-2024-43841",
    "CVE-2024-43846",
    "CVE-2024-43849",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43856",
    "CVE-2024-43858",
    "CVE-2024-43860",
    "CVE-2024-43861",
    "CVE-2024-43867",
    "CVE-2024-43871",
    "CVE-2024-43879",
    "CVE-2024-43880",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-43884",
    "CVE-2024-43889",
    "CVE-2024-43890",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43894",
    "CVE-2024-43905",
    "CVE-2024-43907",
    "CVE-2024-43908",
    "CVE-2024-43914",
    "CVE-2024-44935",
    "CVE-2024-44944",
    "CVE-2024-44946",
    "CVE-2024-44947",
    "CVE-2024-44948",
    "CVE-2024-44952",
    "CVE-2024-44954",
    "CVE-2024-44960",
    "CVE-2024-44965",
    "CVE-2024-44968",
    "CVE-2024-44971",
    "CVE-2024-44974",
    "CVE-2024-44987",
    "CVE-2024-44988",
    "CVE-2024-44989",
    "CVE-2024-44990",
    "CVE-2024-44995",
    "CVE-2024-44998",
    "CVE-2024-44999",
    "CVE-2024-45003",
    "CVE-2024-45006",
    "CVE-2024-45008",
    "CVE-2024-45016",
    "CVE-2024-45018",
    "CVE-2024-45021",
    "CVE-2024-45025",
    "CVE-2024-45028",
    "CVE-2024-46673",
    "CVE-2024-46674",
    "CVE-2024-46675",
    "CVE-2024-46676",
    "CVE-2024-46677",
    "CVE-2024-46679",
    "CVE-2024-46685",
    "CVE-2024-46689",
    "CVE-2024-46702",
    "CVE-2024-46707",
    "CVE-2024-46713",
    "CVE-2024-46714",
    "CVE-2024-46719",
    "CVE-2024-46721",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46724",
    "CVE-2024-46725",
    "CVE-2024-46731",
    "CVE-2024-46737",
    "CVE-2024-46738",
    "CVE-2024-46739",
    "CVE-2024-46740",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46745",
    "CVE-2024-46747",
    "CVE-2024-46750",
    "CVE-2024-46755",
    "CVE-2024-46756",
    "CVE-2024-46757",
    "CVE-2024-46758",
    "CVE-2024-46759",
    "CVE-2024-46763",
    "CVE-2024-46771",
    "CVE-2024-46777",
    "CVE-2024-46780",
    "CVE-2024-46781",
    "CVE-2024-46782",
    "CVE-2024-46783",
    "CVE-2024-46791",
    "CVE-2024-46798",
    "CVE-2024-46800",
    "CVE-2024-46804",
    "CVE-2024-46814",
    "CVE-2024-46815",
    "CVE-2024-46817",
    "CVE-2024-46818",
    "CVE-2024-46819",
    "CVE-2024-46822",
    "CVE-2024-46828",
    "CVE-2024-46829",
    "CVE-2024-46840",
    "CVE-2024-46844"
  );

  script_name(english:"Debian dla-3912 : ata-modules-5.10.0-29-armmp-di - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3912 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3912-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    October 07, 2024                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux
    Version        : 5.10.226-1
    CVE ID         : CVE-2021-3669 CVE-2022-48733 CVE-2023-31083 CVE-2023-52889
                     CVE-2024-27397 CVE-2024-38577 CVE-2024-41011 CVE-2024-41042
                     CVE-2024-41098 CVE-2024-42114 CVE-2024-42228 CVE-2024-42246
                     CVE-2024-42259 CVE-2024-42265 CVE-2024-42272 CVE-2024-42276
                     CVE-2024-42280 CVE-2024-42281 CVE-2024-42283 CVE-2024-42284
                     CVE-2024-42285 CVE-2024-42286 CVE-2024-42287 CVE-2024-42288
                     CVE-2024-42289 CVE-2024-42290 CVE-2024-42292 CVE-2024-42295
                     CVE-2024-42297 CVE-2024-42301 CVE-2024-42302 CVE-2024-42304
                     CVE-2024-42305 CVE-2024-42306 CVE-2024-42308 CVE-2024-42309
                     CVE-2024-42310 CVE-2024-42311 CVE-2024-42312 CVE-2024-42313
                     CVE-2024-43828 CVE-2024-43829 CVE-2024-43830 CVE-2024-43834
                     CVE-2024-43835 CVE-2024-43839 CVE-2024-43841 CVE-2024-43846
                     CVE-2024-43849 CVE-2024-43853 CVE-2024-43854 CVE-2024-43856
                     CVE-2024-43858 CVE-2024-43860 CVE-2024-43861 CVE-2024-43867
                     CVE-2024-43871 CVE-2024-43879 CVE-2024-43880 CVE-2024-43882
                     CVE-2024-43883 CVE-2024-43884 CVE-2024-43889 CVE-2024-43890
                     CVE-2024-43892 CVE-2024-43893 CVE-2024-43894 CVE-2024-43905
                     CVE-2024-43907 CVE-2024-43908 CVE-2024-43914 CVE-2024-44935
                     CVE-2024-44944 CVE-2024-44946 CVE-2024-44947 CVE-2024-44948
                     CVE-2024-44952 CVE-2024-44954 CVE-2024-44960 CVE-2024-44965
                     CVE-2024-44968 CVE-2024-44971 CVE-2024-44974 CVE-2024-44987
                     CVE-2024-44988 CVE-2024-44989 CVE-2024-44990 CVE-2024-44995
                     CVE-2024-44998 CVE-2024-44999 CVE-2024-45003 CVE-2024-45006
                     CVE-2024-45008 CVE-2024-45016 CVE-2024-45018 CVE-2024-45021
                     CVE-2024-45025 CVE-2024-45028 CVE-2024-46673 CVE-2024-46674
                     CVE-2024-46675 CVE-2024-46676 CVE-2024-46677 CVE-2024-46679
                     CVE-2024-46685 CVE-2024-46689 CVE-2024-46702 CVE-2024-46707
                     CVE-2024-46713 CVE-2024-46714 CVE-2024-46719 CVE-2024-46721
                     CVE-2024-46722 CVE-2024-46723 CVE-2024-46724 CVE-2024-46725
                     CVE-2024-46731 CVE-2024-46737 CVE-2024-46738 CVE-2024-46739
                     CVE-2024-46740 CVE-2024-46743 CVE-2024-46744 CVE-2024-46745
                     CVE-2024-46747 CVE-2024-46750 CVE-2024-46755 CVE-2024-46756
                     CVE-2024-46757 CVE-2024-46758 CVE-2024-46759 CVE-2024-46763
                     CVE-2024-46771 CVE-2024-46777 CVE-2024-46780 CVE-2024-46781
                     CVE-2024-46782 CVE-2024-46783 CVE-2024-46791 CVE-2024-46798
                     CVE-2024-46800 CVE-2024-46804 CVE-2024-46814 CVE-2024-46815
                     CVE-2024-46817 CVE-2024-46818 CVE-2024-46819 CVE-2024-46822
                     CVE-2024-46828 CVE-2024-46829 CVE-2024-46840 CVE-2024-46844

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    For Debian 11 bullseye, these problems have been fixed in version
    5.10.226-1.  This additionally includes many more bug fixes from
    stable updates 5.10.224-5.10.226 inclusive.

    We recommend that you upgrade your linux packages.

    For the detailed security status of linux please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3669");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-31083");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52889");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27397");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38577");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41011");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41098");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42228");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42246");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42259");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42265");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42272");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42276");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42280");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42284");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42285");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42286");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42287");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42288");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42289");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42290");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42292");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42295");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42297");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42301");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42302");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42304");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42305");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42306");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42308");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42309");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42310");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42311");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42312");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42313");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43828");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43830");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43834");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43835");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43839");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43846");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43849");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43853");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43856");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43860");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43861");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43867");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43871");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43880");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43882");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43883");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43884");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43889");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43890");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43892");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43893");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43894");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43905");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43908");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43914");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44935");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44944");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44947");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44948");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44952");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44954");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44960");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44968");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44971");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44987");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44988");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44990");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44995");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44998");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44999");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45003");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45006");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45008");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45018");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45021");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45025");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45028");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46673");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46674");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46675");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46676");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46677");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46679");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46689");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46702");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46714");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46719");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46721");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46724");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46725");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46731");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46737");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46738");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46740");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46743");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46747");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46750");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46755");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46757");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46758");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46759");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46777");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46782");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46783");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46791");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46798");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46800");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46814");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46815");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46817");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46818");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46819");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46822");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46828");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46840");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46844");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ata-modules-5.10.0-29-armmp-di packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46844");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rt-armmp");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-29-rt-armmp-dbg");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-29");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-29-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-31-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-33-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
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
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'bpftool', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'hyperv-daemons', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'libcpupower-dev', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'libcpupower1', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-arm', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-x86', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-cpupower', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-doc', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-686', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-686-pae', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-amd64', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-arm64', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-armmp', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-armmp-lpae', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-cloud-amd64', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-cloud-arm64', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-common', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-common-rt', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-686-pae', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-amd64', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-arm64', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-29-rt-armmp', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-686-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-686-pae-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-amd64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-arm64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp-lpae', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-armmp-lpae-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-cloud-amd64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-cloud-arm64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-686-pae-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-amd64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-arm64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-armmp', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-29-rt-armmp-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-libc-dev', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-perf', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-source', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'linux-support-5.10.0-29', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-29-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-31-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-33-armmp-di', 'reference': '5.10.226-1'},
    {'release': '11.0', 'prefix': 'usbip', 'reference': '5.10.226-1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ata-modules-5.10.0-29-armmp-di / ata-modules-5.10.0-31-armmp-di / etc');
}
