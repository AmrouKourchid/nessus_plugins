#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3842. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(201105);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2022-38096",
    "CVE-2023-6270",
    "CVE-2023-7042",
    "CVE-2023-28746",
    "CVE-2023-47233",
    "CVE-2023-52429",
    "CVE-2023-52434",
    "CVE-2023-52435",
    "CVE-2023-52447",
    "CVE-2023-52458",
    "CVE-2023-52482",
    "CVE-2023-52486",
    "CVE-2023-52488",
    "CVE-2023-52489",
    "CVE-2023-52491",
    "CVE-2023-52492",
    "CVE-2023-52493",
    "CVE-2023-52497",
    "CVE-2023-52498",
    "CVE-2023-52583",
    "CVE-2023-52587",
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
    "CVE-2023-52614",
    "CVE-2023-52615",
    "CVE-2023-52616",
    "CVE-2023-52617",
    "CVE-2023-52618",
    "CVE-2023-52619",
    "CVE-2023-52620",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52627",
    "CVE-2023-52635",
    "CVE-2023-52637",
    "CVE-2023-52642",
    "CVE-2023-52644",
    "CVE-2023-52650",
    "CVE-2023-52656",
    "CVE-2023-52669",
    "CVE-2023-52670",
    "CVE-2023-52672",
    "CVE-2023-52699",
    "CVE-2023-52880",
    "CVE-2024-0340",
    "CVE-2024-0565",
    "CVE-2024-0607",
    "CVE-2024-0841",
    "CVE-2024-1151",
    "CVE-2024-22099",
    "CVE-2024-23849",
    "CVE-2024-23850",
    "CVE-2024-23851",
    "CVE-2024-24857",
    "CVE-2024-24858",
    "CVE-2024-24861",
    "CVE-2024-25739",
    "CVE-2024-26581",
    "CVE-2024-26593",
    "CVE-2024-26600",
    "CVE-2024-26601",
    "CVE-2024-26602",
    "CVE-2024-26606",
    "CVE-2024-26610",
    "CVE-2024-26614",
    "CVE-2024-26615",
    "CVE-2024-26622",
    "CVE-2024-26625",
    "CVE-2024-26627",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26644",
    "CVE-2024-26645",
    "CVE-2024-26651",
    "CVE-2024-26654",
    "CVE-2024-26659",
    "CVE-2024-26663",
    "CVE-2024-26664",
    "CVE-2024-26665",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26675",
    "CVE-2024-26679",
    "CVE-2024-26684",
    "CVE-2024-26685",
    "CVE-2024-26687",
    "CVE-2024-26688",
    "CVE-2024-26689",
    "CVE-2024-26695",
    "CVE-2024-26696",
    "CVE-2024-26697",
    "CVE-2024-26698",
    "CVE-2024-26702",
    "CVE-2024-26704",
    "CVE-2024-26707",
    "CVE-2024-26712",
    "CVE-2024-26720",
    "CVE-2024-26722",
    "CVE-2024-26727",
    "CVE-2024-26733",
    "CVE-2024-26735",
    "CVE-2024-26736",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26747",
    "CVE-2024-26748",
    "CVE-2024-26749",
    "CVE-2024-26751",
    "CVE-2024-26752",
    "CVE-2024-26753",
    "CVE-2024-26754",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26766",
    "CVE-2024-26771",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26776",
    "CVE-2024-26777",
    "CVE-2024-26778",
    "CVE-2024-26779",
    "CVE-2024-26781",
    "CVE-2024-26782",
    "CVE-2024-26787",
    "CVE-2024-26788",
    "CVE-2024-26790",
    "CVE-2024-26791",
    "CVE-2024-26793",
    "CVE-2024-26795",
    "CVE-2024-26801",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26808",
    "CVE-2024-26809",
    "CVE-2024-26810",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26816",
    "CVE-2024-26817",
    "CVE-2024-26820",
    "CVE-2024-26825",
    "CVE-2024-26833",
    "CVE-2024-26835",
    "CVE-2024-26839",
    "CVE-2024-26840",
    "CVE-2024-26843",
    "CVE-2024-26845",
    "CVE-2024-26846",
    "CVE-2024-26848",
    "CVE-2024-26851",
    "CVE-2024-26852",
    "CVE-2024-26855",
    "CVE-2024-26857",
    "CVE-2024-26859",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26863",
    "CVE-2024-26870",
    "CVE-2024-26872",
    "CVE-2024-26874",
    "CVE-2024-26875",
    "CVE-2024-26877",
    "CVE-2024-26878",
    "CVE-2024-26880",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26885",
    "CVE-2024-26889",
    "CVE-2024-26891",
    "CVE-2024-26894",
    "CVE-2024-26895",
    "CVE-2024-26897",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26906",
    "CVE-2024-26907",
    "CVE-2024-26910",
    "CVE-2024-26917",
    "CVE-2024-26922",
    "CVE-2024-26923",
    "CVE-2024-26924",
    "CVE-2024-26925",
    "CVE-2024-26926",
    "CVE-2024-26931",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26937",
    "CVE-2024-26950",
    "CVE-2024-26951",
    "CVE-2024-26955",
    "CVE-2024-26956",
    "CVE-2024-26957",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26961",
    "CVE-2024-26965",
    "CVE-2024-26966",
    "CVE-2024-26969",
    "CVE-2024-26970",
    "CVE-2024-26973",
    "CVE-2024-26974",
    "CVE-2024-26976",
    "CVE-2024-26978",
    "CVE-2024-26981",
    "CVE-2024-26984",
    "CVE-2024-26988",
    "CVE-2024-26993",
    "CVE-2024-26994",
    "CVE-2024-26997",
    "CVE-2024-26999",
    "CVE-2024-27000",
    "CVE-2024-27001",
    "CVE-2024-27004",
    "CVE-2024-27008",
    "CVE-2024-27013",
    "CVE-2024-27020",
    "CVE-2024-27024",
    "CVE-2024-27025",
    "CVE-2024-27028",
    "CVE-2024-27030",
    "CVE-2024-27038",
    "CVE-2024-27043",
    "CVE-2024-27044",
    "CVE-2024-27045",
    "CVE-2024-27046",
    "CVE-2024-27047",
    "CVE-2024-27051",
    "CVE-2024-27052",
    "CVE-2024-27053",
    "CVE-2024-27059",
    "CVE-2024-27065",
    "CVE-2024-27073",
    "CVE-2024-27074",
    "CVE-2024-27075",
    "CVE-2024-27076",
    "CVE-2024-27077",
    "CVE-2024-27078",
    "CVE-2024-27388",
    "CVE-2024-27395",
    "CVE-2024-27396",
    "CVE-2024-27405",
    "CVE-2024-27410",
    "CVE-2024-27412",
    "CVE-2024-27413",
    "CVE-2024-27414",
    "CVE-2024-27416",
    "CVE-2024-27417",
    "CVE-2024-27419",
    "CVE-2024-27431",
    "CVE-2024-27436",
    "CVE-2024-27437",
    "CVE-2024-35785",
    "CVE-2024-35789",
    "CVE-2024-35791",
    "CVE-2024-35796",
    "CVE-2024-35805",
    "CVE-2024-35806",
    "CVE-2024-35807",
    "CVE-2024-35809",
    "CVE-2024-35811",
    "CVE-2024-35813",
    "CVE-2024-35815",
    "CVE-2024-35819",
    "CVE-2024-35821",
    "CVE-2024-35822",
    "CVE-2024-35823",
    "CVE-2024-35825",
    "CVE-2024-35828",
    "CVE-2024-35829",
    "CVE-2024-35830",
    "CVE-2024-35833",
    "CVE-2024-35835",
    "CVE-2024-35837",
    "CVE-2024-35845",
    "CVE-2024-35847",
    "CVE-2024-35849",
    "CVE-2024-35852",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35871",
    "CVE-2024-35877",
    "CVE-2024-35879",
    "CVE-2024-35884",
    "CVE-2024-35886",
    "CVE-2024-35888",
    "CVE-2024-35893",
    "CVE-2024-35895",
    "CVE-2024-35896",
    "CVE-2024-35897",
    "CVE-2024-35898",
    "CVE-2024-35899",
    "CVE-2024-35900",
    "CVE-2024-35902",
    "CVE-2024-35905",
    "CVE-2024-35910",
    "CVE-2024-35915",
    "CVE-2024-35922",
    "CVE-2024-35925",
    "CVE-2024-35930",
    "CVE-2024-35933",
    "CVE-2024-35934",
    "CVE-2024-35935",
    "CVE-2024-35936",
    "CVE-2024-35940",
    "CVE-2024-35944",
    "CVE-2024-35950",
    "CVE-2024-35955",
    "CVE-2024-35958",
    "CVE-2024-35960",
    "CVE-2024-35962",
    "CVE-2024-35967",
    "CVE-2024-35969",
    "CVE-2024-35973",
    "CVE-2024-35976",
    "CVE-2024-35978",
    "CVE-2024-35982",
    "CVE-2024-35983",
    "CVE-2024-35984",
    "CVE-2024-35988",
    "CVE-2024-35990",
    "CVE-2024-35996",
    "CVE-2024-35997",
    "CVE-2024-36004",
    "CVE-2024-36005",
    "CVE-2024-36006",
    "CVE-2024-36007",
    "CVE-2024-36008",
    "CVE-2024-36020"
  );

  script_name(english:"Debian dla-3842 : linux-config-5.10 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3842 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3842-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    June 25, 2024                                 https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux-5.10
    Version        : 5.10.216-1~deb10u1
    CVE ID         : CVE-2022-38096 CVE-2023-6270 CVE-2023-7042 CVE-2023-28746
                     CVE-2023-47233 CVE-2023-52429 CVE-2023-52434 CVE-2023-52435
                     CVE-2023-52447 CVE-2023-52458 CVE-2023-52482 CVE-2023-52486
                     CVE-2023-52488 CVE-2023-52489 CVE-2023-52491 CVE-2023-52492
                     CVE-2023-52493 CVE-2023-52497 CVE-2023-52498 CVE-2023-52583
                     CVE-2023-52587 CVE-2023-52594 CVE-2023-52595 CVE-2023-52597
                     CVE-2023-52598 CVE-2023-52599 CVE-2023-52600 CVE-2023-52601
                     CVE-2023-52602 CVE-2023-52603 CVE-2023-52604 CVE-2023-52606
                     CVE-2023-52607 CVE-2023-52614 CVE-2023-52615 CVE-2023-52616
                     CVE-2023-52617 CVE-2023-52618 CVE-2023-52619 CVE-2023-52620
                     CVE-2023-52622 CVE-2023-52623 CVE-2023-52627 CVE-2023-52635
                     CVE-2023-52637 CVE-2023-52642 CVE-2023-52644 CVE-2023-52650
                     CVE-2023-52656 CVE-2023-52669 CVE-2023-52670 CVE-2023-52672
                     CVE-2023-52699 CVE-2023-52880 CVE-2024-0340 CVE-2024-0565
                     CVE-2024-0607 CVE-2024-0841 CVE-2024-1151 CVE-2024-22099
                     CVE-2024-23849 CVE-2024-23850 CVE-2024-23851 CVE-2024-24857
                     CVE-2024-24858 CVE-2024-24861 CVE-2024-25739 CVE-2024-26581
                     CVE-2024-26593 CVE-2024-26600 CVE-2024-26601 CVE-2024-26602
                     CVE-2024-26606 CVE-2024-26610 CVE-2024-26614 CVE-2024-26615
                     CVE-2024-26622 CVE-2024-26625 CVE-2024-26627 CVE-2024-26635
                     CVE-2024-26636 CVE-2024-26640 CVE-2024-26641 CVE-2024-26642
                     CVE-2024-26643 CVE-2024-26644 CVE-2024-26645 CVE-2024-26651
                     CVE-2024-26654 CVE-2024-26659 CVE-2024-26663 CVE-2024-26664
                     CVE-2024-26665 CVE-2024-26671 CVE-2024-26673 CVE-2024-26675
                     CVE-2024-26679 CVE-2024-26684 CVE-2024-26685 CVE-2024-26687
                     CVE-2024-26688 CVE-2024-26689 CVE-2024-26695 CVE-2024-26696
                     CVE-2024-26697 CVE-2024-26698 CVE-2024-26702 CVE-2024-26704
                     CVE-2024-26707 CVE-2024-26712 CVE-2024-26720 CVE-2024-26722
                     CVE-2024-26727 CVE-2024-26733 CVE-2024-26735 CVE-2024-26736
                     CVE-2024-26743 CVE-2024-26744 CVE-2024-26747 CVE-2024-26748
                     CVE-2024-26749 CVE-2024-26751 CVE-2024-26752 CVE-2024-26753
                     CVE-2024-26754 CVE-2024-26763 CVE-2024-26764 CVE-2024-26766
                     CVE-2024-26771 CVE-2024-26772 CVE-2024-26773 CVE-2024-26776
                     CVE-2024-26777 CVE-2024-26778 CVE-2024-26779 CVE-2024-26781
                     CVE-2024-26782 CVE-2024-26787 CVE-2024-26788 CVE-2024-26790
                     CVE-2024-26791 CVE-2024-26793 CVE-2024-26795 CVE-2024-26801
                     CVE-2024-26804 CVE-2024-26805 CVE-2024-26808 CVE-2024-26809
                     CVE-2024-26810 CVE-2024-26812 CVE-2024-26813 CVE-2024-26814
                     CVE-2024-26816 CVE-2024-26817 CVE-2024-26820 CVE-2024-26825
                     CVE-2024-26833 CVE-2024-26835 CVE-2024-26839 CVE-2024-26840
                     CVE-2024-26843 CVE-2024-26845 CVE-2024-26846 CVE-2024-26848
                     CVE-2024-26851 CVE-2024-26852 CVE-2024-26855 CVE-2024-26857
                     CVE-2024-26859 CVE-2024-26861 CVE-2024-26862 CVE-2024-26863
                     CVE-2024-26870 CVE-2024-26872 CVE-2024-26874 CVE-2024-26875
                     CVE-2024-26877 CVE-2024-26878 CVE-2024-26880 CVE-2024-26882
                     CVE-2024-26883 CVE-2024-26884 CVE-2024-26885 CVE-2024-26889
                     CVE-2024-26891 CVE-2024-26894 CVE-2024-26895 CVE-2024-26897
                     CVE-2024-26898 CVE-2024-26901 CVE-2024-26903 CVE-2024-26906
                     CVE-2024-26907 CVE-2024-26910 CVE-2024-26917 CVE-2024-26922
                     CVE-2024-26923 CVE-2024-26924 CVE-2024-26925 CVE-2024-26926
                     CVE-2024-26931 CVE-2024-26934 CVE-2024-26935 CVE-2024-26937
                     CVE-2024-26950 CVE-2024-26951 CVE-2024-26955 CVE-2024-26956
                     CVE-2024-26957 CVE-2024-26958 CVE-2024-26960 CVE-2024-26961
                     CVE-2024-26965 CVE-2024-26966 CVE-2024-26969 CVE-2024-26970
                     CVE-2024-26973 CVE-2024-26974 CVE-2024-26976 CVE-2024-26978
                     CVE-2024-26981 CVE-2024-26984 CVE-2024-26988 CVE-2024-26993
                     CVE-2024-26994 CVE-2024-26997 CVE-2024-26999 CVE-2024-27000
                     CVE-2024-27001 CVE-2024-27004 CVE-2024-27008 CVE-2024-27013
                     CVE-2024-27020 CVE-2024-27024 CVE-2024-27025 CVE-2024-27028
                     CVE-2024-27030 CVE-2024-27038 CVE-2024-27043 CVE-2024-27044
                     CVE-2024-27045 CVE-2024-27046 CVE-2024-27047 CVE-2024-27051
                     CVE-2024-27052 CVE-2024-27053 CVE-2024-27059 CVE-2024-27065
                     CVE-2024-27073 CVE-2024-27074 CVE-2024-27075 CVE-2024-27076
                     CVE-2024-27077 CVE-2024-27078 CVE-2024-27388 CVE-2024-27395
                     CVE-2024-27396 CVE-2024-27405 CVE-2024-27410 CVE-2024-27412
                     CVE-2024-27413 CVE-2024-27414 CVE-2024-27416 CVE-2024-27417
                     CVE-2024-27419 CVE-2024-27431 CVE-2024-27436 CVE-2024-27437
                     CVE-2024-35785 CVE-2024-35789 CVE-2024-35791 CVE-2024-35796
                     CVE-2024-35805 CVE-2024-35806 CVE-2024-35807 CVE-2024-35809
                     CVE-2024-35811 CVE-2024-35813 CVE-2024-35815 CVE-2024-35819
                     CVE-2024-35821 CVE-2024-35822 CVE-2024-35823 CVE-2024-35825
                     CVE-2024-35828 CVE-2024-35829 CVE-2024-35830 CVE-2024-35833
                     CVE-2024-35835 CVE-2024-35837 CVE-2024-35845 CVE-2024-35847
                     CVE-2024-35849 CVE-2024-35852 CVE-2024-35853 CVE-2024-35854
                     CVE-2024-35855 CVE-2024-35871 CVE-2024-35877 CVE-2024-35879
                     CVE-2024-35884 CVE-2024-35886 CVE-2024-35888 CVE-2024-35893
                     CVE-2024-35895 CVE-2024-35896 CVE-2024-35897 CVE-2024-35898
                     CVE-2024-35899 CVE-2024-35900 CVE-2024-35902 CVE-2024-35905
                     CVE-2024-35910 CVE-2024-35915 CVE-2024-35922 CVE-2024-35925
                     CVE-2024-35930 CVE-2024-35933 CVE-2024-35934 CVE-2024-35935
                     CVE-2024-35936 CVE-2024-35940 CVE-2024-35944 CVE-2024-35950
                     CVE-2024-35955 CVE-2024-35958 CVE-2024-35960 CVE-2024-35962
                     CVE-2024-35967 CVE-2024-35969 CVE-2024-35973 CVE-2024-35976
                     CVE-2024-35978 CVE-2024-35982 CVE-2024-35983 CVE-2024-35984
                     CVE-2024-35988 CVE-2024-35990 CVE-2024-35996 CVE-2024-35997
                     CVE-2024-36004 CVE-2024-36005 CVE-2024-36006 CVE-2024-36007
                     CVE-2024-36008 CVE-2024-36020
    Debian Bug     : 1064035

    Several vulnerabilities were discovered in the Linux kernel that may
    lead to a privilege escalation, denial of service or information
    leaks.

    For Debian 10 buster, these problems were fixed earlier in version
    5.10.216-1~deb10u1.  This update also fixed a regression in kernel
    documentation generation, and included many more bug fixes from stable
    updates 5.10.210-5.10.216 inclusive.

    For the detailed security status of linux-5.10 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux-5.10

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-5.10");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38096");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28746");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-47233");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52429");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52434");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52435");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52447");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52482");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52486");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52488");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52489");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52491");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52492");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52493");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52497");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52498");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52583");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52587");
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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52614");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52615");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52616");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52617");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52618");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52620");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52635");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52637");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52642");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52644");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52650");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52656");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52669");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52670");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52672");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52699");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52880");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-7042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0340");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0565");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0607");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-1151");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23849");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23850");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23851");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24857");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24861");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26581");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26593");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26610");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26614");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26615");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26625");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26635");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26636");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26641");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26642");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26643");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26644");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26645");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26651");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26654");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26659");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26664");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26665");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26671");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26673");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26675");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26679");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26684");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26687");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26688");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26689");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26695");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26696");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26697");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26698");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26702");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26704");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26712");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26720");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26727");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26736");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26743");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26747");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26749");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26751");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26754");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26764");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26766");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26773");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26777");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26778");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26779");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26782");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26787");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26788");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26790");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26791");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26793");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26801");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26805");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26808");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26809");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26810");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26812");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26813");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26814");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26816");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26817");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26820");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26825");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26833");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26835");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26839");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26840");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26843");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26845");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26846");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26848");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26851");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26852");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26857");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26859");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26861");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26862");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26863");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26870");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26872");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26874");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26875");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26877");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26878");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26880");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26882");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26883");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26884");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26885");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26889");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26891");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26894");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26895");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26897");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26901");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26903");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26906");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26910");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26917");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26922");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26923");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26924");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26925");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26926");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26931");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26935");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26937");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26950");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26951");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26955");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26956");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26957");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26958");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26960");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26961");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26969");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26970");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26973");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26976");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26978");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26984");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26988");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26993");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26994");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26997");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26999");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27000");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27004");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27008");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27013");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27020");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27024");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27025");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27028");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27030");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27038");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27043");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27044");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27045");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27046");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27047");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27051");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27052");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27053");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27059");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27065");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27073");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27074");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27075");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27076");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27077");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27078");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27388");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27395");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27396");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27405");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27410");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27412");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27413");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27414");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27416");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27417");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27419");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27431");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27436");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27437");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35789");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35791");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35796");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35805");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35806");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35807");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35809");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35811");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35813");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35815");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35819");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35821");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35822");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35823");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35825");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35828");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35830");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35833");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35835");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35837");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35845");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35847");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35849");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35852");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35853");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35871");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35877");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35884");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35886");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35888");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35893");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35895");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35896");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35897");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35899");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35900");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35902");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35905");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35910");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35915");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35922");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35925");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35930");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35933");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35935");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35936");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35940");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35944");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35950");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35955");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35958");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35960");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35962");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35967");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35969");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35973");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35976");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35978");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35982");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35983");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35984");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35988");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35990");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35996");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35997");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36004");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36005");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36006");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36007");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36008");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36020");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux-5.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-config-5.10 packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0565");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.29");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.30");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-686', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-cloud-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-cloud-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-common', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-common-rt', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-686', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-cloud-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-cloud-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-common', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-common-rt', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-686', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-cloud-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-cloud-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-common', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-common-rt', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-686', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-cloud-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-cloud-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-common', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-common-rt', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-686', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-cloud-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-cloud-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-common', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-common-rt', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-686', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-cloud-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-cloud-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-common', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-common-rt', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-686-pae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-amd64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-arm64', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-signed-template', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-signed-template', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-i386-signed-template', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-686-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp-lpae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-cloud-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-cloud-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-686-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp-lpae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-cloud-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-cloud-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-686-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp-lpae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-cloud-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-cloud-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-686-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp-lpae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-cloud-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-cloud-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-686-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp-lpae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-cloud-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-cloud-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-686-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp-lpae', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp-lpae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-cloud-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-cloud-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-686-pae-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-amd64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-arm64-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-armmp', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-armmp-dbg', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.24', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.26', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.27', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.28', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.29', 'reference': '5.10.216-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.30', 'reference': '5.10.216-1~deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-5.10 / linux-doc-5.10 / linux-headers-5.10-armmp / etc');
}
