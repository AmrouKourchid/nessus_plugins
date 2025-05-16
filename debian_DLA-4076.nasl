#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4076. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216985);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2022-49034",
    "CVE-2023-52916",
    "CVE-2023-52926",
    "CVE-2024-26595",
    "CVE-2024-27407",
    "CVE-2024-35870",
    "CVE-2024-35956",
    "CVE-2024-36476",
    "CVE-2024-36479",
    "CVE-2024-36899",
    "CVE-2024-37021",
    "CVE-2024-39282",
    "CVE-2024-41014",
    "CVE-2024-42252",
    "CVE-2024-42315",
    "CVE-2024-42319",
    "CVE-2024-43098",
    "CVE-2024-44950",
    "CVE-2024-45828",
    "CVE-2024-46809",
    "CVE-2024-46841",
    "CVE-2024-46896",
    "CVE-2024-47143",
    "CVE-2024-47408",
    "CVE-2024-47745",
    "CVE-2024-48881",
    "CVE-2024-49571",
    "CVE-2024-49861",
    "CVE-2024-49891",
    "CVE-2024-49897",
    "CVE-2024-49898",
    "CVE-2024-49899",
    "CVE-2024-49909",
    "CVE-2024-49911",
    "CVE-2024-49915",
    "CVE-2024-49917",
    "CVE-2024-49925",
    "CVE-2024-49929",
    "CVE-2024-49934",
    "CVE-2024-49939",
    "CVE-2024-49951",
    "CVE-2024-49994",
    "CVE-2024-49996",
    "CVE-2024-50014",
    "CVE-2024-50047",
    "CVE-2024-50051",
    "CVE-2024-50055",
    "CVE-2024-50121",
    "CVE-2024-50146",
    "CVE-2024-50164",
    "CVE-2024-50248",
    "CVE-2024-50258",
    "CVE-2024-50275",
    "CVE-2024-50304",
    "CVE-2024-52332",
    "CVE-2024-53099",
    "CVE-2024-53105",
    "CVE-2024-53124",
    "CVE-2024-53125",
    "CVE-2024-53128",
    "CVE-2024-53141",
    "CVE-2024-53142",
    "CVE-2024-53145",
    "CVE-2024-53146",
    "CVE-2024-53148",
    "CVE-2024-53150",
    "CVE-2024-53151",
    "CVE-2024-53154",
    "CVE-2024-53155",
    "CVE-2024-53156",
    "CVE-2024-53157",
    "CVE-2024-53158",
    "CVE-2024-53161",
    "CVE-2024-53164",
    "CVE-2024-53165",
    "CVE-2024-53170",
    "CVE-2024-53171",
    "CVE-2024-53172",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53175",
    "CVE-2024-53180",
    "CVE-2024-53181",
    "CVE-2024-53183",
    "CVE-2024-53184",
    "CVE-2024-53190",
    "CVE-2024-53194",
    "CVE-2024-53196",
    "CVE-2024-53197",
    "CVE-2024-53198",
    "CVE-2024-53206",
    "CVE-2024-53207",
    "CVE-2024-53208",
    "CVE-2024-53210",
    "CVE-2024-53213",
    "CVE-2024-53214",
    "CVE-2024-53215",
    "CVE-2024-53217",
    "CVE-2024-53220",
    "CVE-2024-53226",
    "CVE-2024-53227",
    "CVE-2024-53229",
    "CVE-2024-53230",
    "CVE-2024-53231",
    "CVE-2024-53233",
    "CVE-2024-53234",
    "CVE-2024-53237",
    "CVE-2024-53239",
    "CVE-2024-53240",
    "CVE-2024-53241",
    "CVE-2024-53680",
    "CVE-2024-53685",
    "CVE-2024-53690",
    "CVE-2024-54031",
    "CVE-2024-55881",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56531",
    "CVE-2024-56532",
    "CVE-2024-56533",
    "CVE-2024-56539",
    "CVE-2024-56546",
    "CVE-2024-56548",
    "CVE-2024-56551",
    "CVE-2024-56557",
    "CVE-2024-56558",
    "CVE-2024-56562",
    "CVE-2024-56567",
    "CVE-2024-56568",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56572",
    "CVE-2024-56574",
    "CVE-2024-56575",
    "CVE-2024-56576",
    "CVE-2024-56578",
    "CVE-2024-56579",
    "CVE-2024-56581",
    "CVE-2024-56582",
    "CVE-2024-56584",
    "CVE-2024-56585",
    "CVE-2024-56586",
    "CVE-2024-56587",
    "CVE-2024-56589",
    "CVE-2024-56590",
    "CVE-2024-56593",
    "CVE-2024-56594",
    "CVE-2024-56595",
    "CVE-2024-56596",
    "CVE-2024-56597",
    "CVE-2024-56598",
    "CVE-2024-56599",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56602",
    "CVE-2024-56603",
    "CVE-2024-56604",
    "CVE-2024-56605",
    "CVE-2024-56606",
    "CVE-2024-56608",
    "CVE-2024-56610",
    "CVE-2024-56614",
    "CVE-2024-56615",
    "CVE-2024-56616",
    "CVE-2024-56619",
    "CVE-2024-56622",
    "CVE-2024-56623",
    "CVE-2024-56625",
    "CVE-2024-56626",
    "CVE-2024-56627",
    "CVE-2024-56628",
    "CVE-2024-56629",
    "CVE-2024-56630",
    "CVE-2024-56631",
    "CVE-2024-56633",
    "CVE-2024-56634",
    "CVE-2024-56636",
    "CVE-2024-56637",
    "CVE-2024-56640",
    "CVE-2024-56642",
    "CVE-2024-56643",
    "CVE-2024-56644",
    "CVE-2024-56645",
    "CVE-2024-56648",
    "CVE-2024-56650",
    "CVE-2024-56651",
    "CVE-2024-56658",
    "CVE-2024-56659",
    "CVE-2024-56660",
    "CVE-2024-56661",
    "CVE-2024-56662",
    "CVE-2024-56663",
    "CVE-2024-56664",
    "CVE-2024-56665",
    "CVE-2024-56670",
    "CVE-2024-56672",
    "CVE-2024-56675",
    "CVE-2024-56677",
    "CVE-2024-56678",
    "CVE-2024-56679",
    "CVE-2024-56681",
    "CVE-2024-56683",
    "CVE-2024-56687",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56691",
    "CVE-2024-56693",
    "CVE-2024-56694",
    "CVE-2024-56698",
    "CVE-2024-56700",
    "CVE-2024-56701",
    "CVE-2024-56703",
    "CVE-2024-56704",
    "CVE-2024-56705",
    "CVE-2024-56707",
    "CVE-2024-56708",
    "CVE-2024-56709",
    "CVE-2024-56715",
    "CVE-2024-56716",
    "CVE-2024-56717",
    "CVE-2024-56718",
    "CVE-2024-56720",
    "CVE-2024-56722",
    "CVE-2024-56723",
    "CVE-2024-56724",
    "CVE-2024-56725",
    "CVE-2024-56726",
    "CVE-2024-56727",
    "CVE-2024-56728",
    "CVE-2024-56739",
    "CVE-2024-56741",
    "CVE-2024-56745",
    "CVE-2024-56746",
    "CVE-2024-56747",
    "CVE-2024-56748",
    "CVE-2024-56751",
    "CVE-2024-56754",
    "CVE-2024-56755",
    "CVE-2024-56756",
    "CVE-2024-56759",
    "CVE-2024-56763",
    "CVE-2024-56765",
    "CVE-2024-56766",
    "CVE-2024-56767",
    "CVE-2024-56769",
    "CVE-2024-56770",
    "CVE-2024-56774",
    "CVE-2024-56776",
    "CVE-2024-56777",
    "CVE-2024-56778",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-56781",
    "CVE-2024-56783",
    "CVE-2024-56785",
    "CVE-2024-56787",
    "CVE-2024-57791",
    "CVE-2024-57792",
    "CVE-2024-57798",
    "CVE-2024-57802",
    "CVE-2024-57807",
    "CVE-2024-57838",
    "CVE-2024-57841",
    "CVE-2024-57849",
    "CVE-2024-57850",
    "CVE-2024-57874",
    "CVE-2024-57876",
    "CVE-2024-57882",
    "CVE-2024-57884",
    "CVE-2024-57887",
    "CVE-2024-57889",
    "CVE-2024-57890",
    "CVE-2024-57892",
    "CVE-2024-57893",
    "CVE-2024-57894",
    "CVE-2024-57896",
    "CVE-2024-57897",
    "CVE-2024-57900",
    "CVE-2024-57901",
    "CVE-2024-57902",
    "CVE-2024-57903",
    "CVE-2024-57904",
    "CVE-2024-57906",
    "CVE-2024-57907",
    "CVE-2024-57908",
    "CVE-2024-57910",
    "CVE-2024-57911",
    "CVE-2024-57912",
    "CVE-2024-57913",
    "CVE-2024-57916",
    "CVE-2024-57917",
    "CVE-2024-57922",
    "CVE-2024-57925",
    "CVE-2024-57929",
    "CVE-2024-57930",
    "CVE-2024-57931",
    "CVE-2024-57938",
    "CVE-2024-57939",
    "CVE-2024-57940",
    "CVE-2024-57946",
    "CVE-2024-57948",
    "CVE-2024-57949",
    "CVE-2024-57951",
    "CVE-2025-21629",
    "CVE-2025-21631",
    "CVE-2025-21636",
    "CVE-2025-21637",
    "CVE-2025-21638",
    "CVE-2025-21639",
    "CVE-2025-21640",
    "CVE-2025-21646",
    "CVE-2025-21647",
    "CVE-2025-21648",
    "CVE-2025-21653",
    "CVE-2025-21655",
    "CVE-2025-21660",
    "CVE-2025-21662",
    "CVE-2025-21664",
    "CVE-2025-21665",
    "CVE-2025-21666",
    "CVE-2025-21667",
    "CVE-2025-21668",
    "CVE-2025-21669",
    "CVE-2025-21671",
    "CVE-2025-21675",
    "CVE-2025-21678",
    "CVE-2025-21680",
    "CVE-2025-21681",
    "CVE-2025-21683",
    "CVE-2025-21687",
    "CVE-2025-21688",
    "CVE-2025-21689",
    "CVE-2025-21690",
    "CVE-2025-21692",
    "CVE-2025-21694",
    "CVE-2025-21697",
    "CVE-2025-21699"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");

  script_name(english:"Debian dla-4076 : linux-config-6.1 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4076 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4076-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    March 01, 2025                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux-6.1
    Version        : 6.1.6.1.128-1~deb11u1
    CVE ID         : CVE-2022-49034 CVE-2023-52916 CVE-2023-52926 CVE-2024-26595
                     CVE-2024-27407 CVE-2024-35870 CVE-2024-35956 CVE-2024-36476
                     CVE-2024-36479 CVE-2024-36899 CVE-2024-37021 CVE-2024-39282
                     CVE-2024-41014 CVE-2024-42252 CVE-2024-42315 CVE-2024-42319
                     CVE-2024-43098 CVE-2024-44950 CVE-2024-45828 CVE-2024-46809
                     CVE-2024-46841 CVE-2024-46896 CVE-2024-47143 CVE-2024-47408
                     CVE-2024-47745 CVE-2024-48881 CVE-2024-49571 CVE-2024-49861
                     CVE-2024-49891 CVE-2024-49897 CVE-2024-49898 CVE-2024-49899
                     CVE-2024-49909 CVE-2024-49911 CVE-2024-49915 CVE-2024-49917
                     CVE-2024-49925 CVE-2024-49929 CVE-2024-49934 CVE-2024-49939
                     CVE-2024-49951 CVE-2024-49994 CVE-2024-49996 CVE-2024-50014
                     CVE-2024-50047 CVE-2024-50051 CVE-2024-50055 CVE-2024-50121
                     CVE-2024-50146 CVE-2024-50164 CVE-2024-50248 CVE-2024-50258
                     CVE-2024-50275 CVE-2024-50304 CVE-2024-52332 CVE-2024-53099
                     CVE-2024-53105 CVE-2024-53124 CVE-2024-53125 CVE-2024-53128
                     CVE-2024-53141 CVE-2024-53142 CVE-2024-53145 CVE-2024-53146
                     CVE-2024-53148 CVE-2024-53150 CVE-2024-53151 CVE-2024-53154
                     CVE-2024-53155 CVE-2024-53156 CVE-2024-53157 CVE-2024-53158
                     CVE-2024-53161 CVE-2024-53164 CVE-2024-53165 CVE-2024-53170
                     CVE-2024-53171 CVE-2024-53172 CVE-2024-53173 CVE-2024-53174
                     CVE-2024-53175 CVE-2024-53180 CVE-2024-53181 CVE-2024-53183
                     CVE-2024-53184 CVE-2024-53190 CVE-2024-53194 CVE-2024-53196
                     CVE-2024-53197 CVE-2024-53198 CVE-2024-53206 CVE-2024-53207
                     CVE-2024-53208 CVE-2024-53210 CVE-2024-53213 CVE-2024-53214
                     CVE-2024-53215 CVE-2024-53217 CVE-2024-53220 CVE-2024-53226
                     CVE-2024-53227 CVE-2024-53229 CVE-2024-53230 CVE-2024-53231
                     CVE-2024-53233 CVE-2024-53234 CVE-2024-53237 CVE-2024-53239
                     CVE-2024-53240 CVE-2024-53241 CVE-2024-53680 CVE-2024-53685
                     CVE-2024-53690 CVE-2024-54031 CVE-2024-55881 CVE-2024-55916
                     CVE-2024-56369 CVE-2024-56531 CVE-2024-56532 CVE-2024-56533
                     CVE-2024-56539 CVE-2024-56546 CVE-2024-56548 CVE-2024-56551
                     CVE-2024-56557 CVE-2024-56558 CVE-2024-56562 CVE-2024-56567
                     CVE-2024-56568 CVE-2024-56569 CVE-2024-56570 CVE-2024-56572
                     CVE-2024-56574 CVE-2024-56575 CVE-2024-56576 CVE-2024-56578
                     CVE-2024-56579 CVE-2024-56581 CVE-2024-56582 CVE-2024-56584
                     CVE-2024-56585 CVE-2024-56586 CVE-2024-56587 CVE-2024-56589
                     CVE-2024-56590 CVE-2024-56593 CVE-2024-56594 CVE-2024-56595
                     CVE-2024-56596 CVE-2024-56597 CVE-2024-56598 CVE-2024-56599
                     CVE-2024-56600 CVE-2024-56601 CVE-2024-56602 CVE-2024-56603
                     CVE-2024-56604 CVE-2024-56605 CVE-2024-56606 CVE-2024-56608
                     CVE-2024-56610 CVE-2024-56614 CVE-2024-56615 CVE-2024-56616
                     CVE-2024-56619 CVE-2024-56622 CVE-2024-56623 CVE-2024-56625
                     CVE-2024-56626 CVE-2024-56627 CVE-2024-56628 CVE-2024-56629
                     CVE-2024-56630 CVE-2024-56631 CVE-2024-56633 CVE-2024-56634
                     CVE-2024-56636 CVE-2024-56637 CVE-2024-56640 CVE-2024-56642
                     CVE-2024-56643 CVE-2024-56644 CVE-2024-56645 CVE-2024-56648
                     CVE-2024-56650 CVE-2024-56651 CVE-2024-56658 CVE-2024-56659
                     CVE-2024-56660 CVE-2024-56661 CVE-2024-56662 CVE-2024-56663
                     CVE-2024-56664 CVE-2024-56665 CVE-2024-56670 CVE-2024-56672
                     CVE-2024-56675 CVE-2024-56677 CVE-2024-56678 CVE-2024-56679
                     CVE-2024-56681 CVE-2024-56683 CVE-2024-56687 CVE-2024-56688
                     CVE-2024-56690 CVE-2024-56691 CVE-2024-56693 CVE-2024-56694
                     CVE-2024-56698 CVE-2024-56700 CVE-2024-56701 CVE-2024-56703
                     CVE-2024-56704 CVE-2024-56705 CVE-2024-56707 CVE-2024-56708
                     CVE-2024-56709 CVE-2024-56715 CVE-2024-56716 CVE-2024-56717
                     CVE-2024-56718 CVE-2024-56720 CVE-2024-56722 CVE-2024-56723
                     CVE-2024-56724 CVE-2024-56725 CVE-2024-56726 CVE-2024-56727
                     CVE-2024-56728 CVE-2024-56739 CVE-2024-56741 CVE-2024-56745
                     CVE-2024-56746 CVE-2024-56747 CVE-2024-56748 CVE-2024-56751
                     CVE-2024-56754 CVE-2024-56755 CVE-2024-56756 CVE-2024-56759
                     CVE-2024-56763 CVE-2024-56765 CVE-2024-56766 CVE-2024-56767
                     CVE-2024-56769 CVE-2024-56770 CVE-2024-56774 CVE-2024-56776
                     CVE-2024-56777 CVE-2024-56778 CVE-2024-56779 CVE-2024-56780
                     CVE-2024-56781 CVE-2024-56783 CVE-2024-56785 CVE-2024-56787
                     CVE-2024-57791 CVE-2024-57792 CVE-2024-57798 CVE-2024-57802
                     CVE-2024-57807 CVE-2024-57838 CVE-2024-57841 CVE-2024-57849
                     CVE-2024-57850 CVE-2024-57874 CVE-2024-57876 CVE-2024-57882
                     CVE-2024-57884 CVE-2024-57887 CVE-2024-57889 CVE-2024-57890
                     CVE-2024-57892 CVE-2024-57893 CVE-2024-57894 CVE-2024-57896
                     CVE-2024-57897 CVE-2024-57900 CVE-2024-57901 CVE-2024-57902
                     CVE-2024-57903 CVE-2024-57904 CVE-2024-57906 CVE-2024-57907
                     CVE-2024-57908 CVE-2024-57910 CVE-2024-57911 CVE-2024-57912
                     CVE-2024-57913 CVE-2024-57916 CVE-2024-57917 CVE-2024-57922
                     CVE-2024-57925 CVE-2024-57929 CVE-2024-57930 CVE-2024-57931
                     CVE-2024-57938 CVE-2024-57939 CVE-2024-57940 CVE-2024-57946
                     CVE-2024-57948 CVE-2024-57949 CVE-2024-57951 CVE-2025-21629
                     CVE-2025-21631 CVE-2025-21636 CVE-2025-21637 CVE-2025-21638
                     CVE-2025-21639 CVE-2025-21640 CVE-2025-21646 CVE-2025-21647
                     CVE-2025-21648 CVE-2025-21653 CVE-2025-21655 CVE-2025-21660
                     CVE-2025-21662 CVE-2025-21664 CVE-2025-21665 CVE-2025-21666
                     CVE-2025-21667 CVE-2025-21668 CVE-2025-21669 CVE-2025-21671
                     CVE-2025-21675 CVE-2025-21678 CVE-2025-21680 CVE-2025-21681
                     CVE-2025-21683 CVE-2025-21687 CVE-2025-21688 CVE-2025-21689
                     CVE-2025-21690 CVE-2025-21692 CVE-2025-21694 CVE-2025-21697
                     CVE-2025-21699

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    For Debian 11 bullseye, these problems have been fixed in version
    6.1.6.1.128-1~deb11u1.  This additionally includes many more bug fixes
    from stable updates 6.1.120-6.1.128 inclusive.

    We recommend that you upgrade your linux-6.1 packages.

    For the detailed security status of linux-6.1 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux-6.1

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-6.1");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-49034");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52926");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26595");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27407");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35870");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35956");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36476");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36479");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36899");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-37021");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41014");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42252");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42315");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42319");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-43098");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-44950");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45828");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46809");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-46896");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47143");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47408");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-48881");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49571");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49861");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49891");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49897");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49899");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49909");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49911");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49915");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49917");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49925");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49929");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49939");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49951");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49994");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49996");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50014");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50047");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50051");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50055");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50121");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50146");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50164");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50248");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50258");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50275");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50304");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52332");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53105");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53124");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53125");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53128");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53141");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53142");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53145");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53146");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53148");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53150");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53151");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53154");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53155");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53156");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53157");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53158");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53161");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53164");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53165");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53170");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53171");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53172");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53173");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53174");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53175");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53180");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53183");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53190");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53197");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53198");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53207");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53208");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53210");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53213");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53214");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53215");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53217");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53220");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53226");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53227");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53229");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53230");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53231");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53233");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53234");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53237");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53239");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53240");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53241");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53680");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53690");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-54031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-55881");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-55916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56369");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56531");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56532");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56533");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56539");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56546");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56548");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56551");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56557");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56558");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56562");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56567");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56568");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56569");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56570");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56572");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56574");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56575");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56576");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56578");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56579");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56581");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56582");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56584");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56585");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56587");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56589");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56590");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56593");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56595");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56596");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56603");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56604");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56605");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56608");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56610");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56614");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56615");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56616");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56625");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56626");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56628");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56630");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56631");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56633");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56634");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56636");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56637");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56642");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56643");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56644");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56645");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56648");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56650");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56651");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56658");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56659");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56660");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56661");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56664");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56665");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56670");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56672");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56675");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56677");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56678");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56679");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56681");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56683");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56687");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56688");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56690");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56691");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56693");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56694");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56698");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56700");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56701");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56703");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56704");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56705");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56708");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56709");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56715");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56716");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56717");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56718");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56720");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56724");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56725");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56726");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56727");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56728");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56741");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56746");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56747");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56751");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56754");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56755");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56759");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56765");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56766");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56767");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56769");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56770");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56774");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56777");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56778");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56779");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56783");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56787");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57791");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57798");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57807");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57838");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57849");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57850");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57874");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57876");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57882");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57884");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57887");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57889");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57890");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57892");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57893");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57894");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57896");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57897");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57900");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57901");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57902");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57903");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57904");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57906");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57908");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57910");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57911");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57912");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57913");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57917");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57922");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57925");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57929");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57930");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57931");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57938");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57939");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57940");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57948");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57949");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57951");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21631");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21636");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21637");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21638");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21639");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21646");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21647");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21648");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21653");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21655");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21660");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21664");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21665");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21666");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21667");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21668");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21669");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21671");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21675");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21678");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21680");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21681");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21683");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21687");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21688");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21689");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21690");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21692");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21694");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21697");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21699");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux-6.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-config-6.1 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21692");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-0.deb11.25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-0.deb11.26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-0.deb11.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-0.deb11.31");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'linux-config-6.1', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-doc-6.1', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-686', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-686-pae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-cloud-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-cloud-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-common', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-common-rt', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-rt-686-pae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-rt-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-rt-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-686', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-686-pae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-cloud-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-cloud-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-common', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-common-rt', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-rt-686-pae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-rt-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-rt-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-686', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-686-pae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-cloud-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-cloud-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-common', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-common-rt', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-rt-686-pae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-rt-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-rt-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-686', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-686-pae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-cloud-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-cloud-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-common', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-common-rt', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-rt-686-pae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-rt-amd64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-rt-arm64', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-686-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-amd64-signed-template', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-arm64-signed-template', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-armmp-lpae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-cloud-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-cloud-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-i386-signed-template', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-686-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-armmp-lpae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-cloud-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-cloud-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-686-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-armmp-lpae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-cloud-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-cloud-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-686-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-armmp-lpae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-cloud-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-cloud-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-686-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-armmp-lpae', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-armmp-lpae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-cloud-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-cloud-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-686-pae-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-amd64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-arm64-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-armmp', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-armmp-dbg', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-6.1', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-source-6.1', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-support-6.1.0-0.deb11.25', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-support-6.1.0-0.deb11.26', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-support-6.1.0-0.deb11.28', 'reference': '6.1.6.1.128-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-support-6.1.0-0.deb11.31', 'reference': '6.1.6.1.128-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-6.1 / linux-doc-6.1 / linux-headers-6.1-armmp / etc');
}
