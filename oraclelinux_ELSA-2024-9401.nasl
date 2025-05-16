#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-9401.
##

include('compat.inc');

if (description)
{
  script_id(211574);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id(
    "CVE-2023-22655",
    "CVE-2023-28746",
    "CVE-2023-38575",
    "CVE-2023-39368",
    "CVE-2023-43490",
    "CVE-2023-45733",
    "CVE-2023-46103"
  );

  script_name(english:"Oracle Linux 9 : microcode_ctl (ELSA-2024-9401)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2024-9401 advisory.

    - Addresses CVE-2024-23984, CVE-2024-24853, CVE-2024-24968, CVE-2024-24980,
      CVE-2024-25939 (RHEL-58057):
      - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode (in
        intel-06-8c-01/intel-ucode/06-8c-01) from revision 0xb6 up to 0xb8;
      - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xf4 up
        to 0xf6;
      - Update of 06-8e-09/0xc0 (KBL-U/U 2+3e/Y H0/J1) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xf4 up
        to 0xf6;
      - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0a) from revision 0xf4 up
        to 0xf6;
      - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0b) from revision 0xf4 up
        to 0xf6;
      - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0)
        microcode (in intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0c) from
        revision 0xfa up to 0xfc;
      - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0a) from revision 0xf6 up
        to 0xf8;
      - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0b) from revision 0xf4 up
        to 0xf6;
      - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0c) from revision 0xf6 up
        to 0xf8;
      - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0d) from revision 0xfc up
        to 0x100;
      - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision
        0x5003605 up to 0x5003707;
      - Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002802
        up to 0x7002904;
      - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003d1
        up to 0xd0003e7;
      - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x1000290
        up to 0x10002b0;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xc4
        up to 0xc6;
      - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x36 up
        to 0x38;
      - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x50 up
        to 0x52;
      - Update of 06-96-01/0x01 (EHL B1) microcode from revision 0x19 up
        to 0x1a;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision
        0x35 up to 0x36;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-97-02) from revision 0x35 up to 0x36;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x35 up to 0x36;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x35 up to 0x36;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-97-05) from revision 0x35 up to 0x36;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x35
        up to 0x36;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x35 up to 0x36;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x35 up to 0x36;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision
        0x433 up to 0x434;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in
        intel-ucode/06-9a-03) from revision 0x433 up to 0x434;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in
        intel-ucode/06-9a-04) from revision 0x433 up to 0x434;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x433
        up to 0x434;
      - Update of 06-a5-02/0x20 (CML-H R1) microcode from revision 0xfa up
        to 0xfc;
      - Update of 06-a5-03/0x22 (CML-S 6+2 G1) microcode from revision 0xfa
        up to 0xfc;
      - Update of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode from revision 0xfa
        up to 0xfc;
      - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from revision 0xfa
        up to 0xfe;
      - Update of 06-a6-01/0x80 (CML-U 6+2 v2 K1) microcode from revision
        0xfa up to 0xfc;
      - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x5e up
        to 0x62;
      - Update of 06-aa-04/0xe6 (MTL-H/U C0) microcode from revision 0x1c
        up to 0x1f;
      - Update of 06-b7-01/0x32 (RPL-S B0) microcode from revision 0x123 up
        to 0x129;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode from revision
        0x4121 up to 0x4122;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-02) from revision 0x4121 up to 0x4122;
      - Update of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-02) from
        revision 0x4121 up to 0x4122;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-03) from revision 0x4121 up to 0x4122;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode from revision 0x4121
        up to 0x4122;
      - Update of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-03) from
        revision 0x4121 up to 0x4122;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-08) from revision 0x4121 up to 0x4122;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-08) from revision 0x4121 up to 0x4122;
      - Update of 06-ba-08/0xe0 microcode from revision 0x4121 up to 0x4122;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-02) from revision 0x35 up to 0x36;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-02) from revision 0x35 up to 0x36;
      - Update of 06-bf-02/0x07 (ADL C0) microcode from revision 0x35 up
        to 0x36;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-bf-02)
        from revision 0x35 up to 0x36;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-05) from revision 0x35 up to 0x36;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-05) from revision 0x35 up to 0x36;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-bf-05)
        from revision 0x35 up to 0x36;
      - Update of 06-bf-05/0x07 (ADL C0) microcode from revision 0x35 up
        to 0x36;
      - Update of 06-be-00/0x19 (ADL-N A0) microcode from revision 0x17 up
        to 0x1a (old pf 0x11).
    - Update Intel CPU microcode to microcode-20240531 release, addresses
      CVE-2023-22655, CVE-2023-23583. CVE-2023-28746, CVE-2023-38575,
      CVE-2023-39368, CVE-2023-42667, CVE-2023-43490, CVE-2023-45733,
      CVE-2023-46103, CVE-2023-49141 (RHEL-30861, RHEL-30864, RHEL-30867,
      RHEL-30870, RHEL-30873, RHEL-41094, RHEL-41109):
      - Addition of 06-aa-04/0xe6 (MTL-H/U C0) microcode at revision 0x1c;
      - Addition of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-02) at
        revision 0x4121;
      - Addition of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-03) at
        revision 0x4121;
      - Addition of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-08) at revision 0x4121;
      - Addition of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-08) at revision 0x4121;
      - Addition of 06-ba-08/0xe0 microcode at revision 0x4121;
      - Addition of 06-cf-01/0x87 (EMR-SP A0) microcode at revision
        0x21000230;
      - Addition of 06-cf-02/0x87 (EMR-SP A1) microcode (in
        intel-ucode/06-cf-01) at revision 0x21000230;
      - Addition of 06-cf-01/0x87 (EMR-SP A0) microcode (in
        intel-ucode/06-cf-02) at revision 0x21000230;
      - Addition of 06-cf-02/0x87 (EMR-SP A1) microcode at revision
        0x21000230;
      - Removal of 06-8f-04/0x10 microcode at revision 0x2c000290;
      - Removal of 06-8f-04/0x87 (SPR-SP E0/S1) microcode at revision
        0x2b0004d0;
      - Removal of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-04) at revision 0x2c000290;
      - Removal of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-04) at revision 0x2b0004d0;
      - Removal of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-04) at
        revision 0x2c000290;
      - Removal of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-04) at revision 0x2b0004d0;
      - Removal of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-04) at revision 0x2b0004d0;
      - Removal of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-04) at revision 0x2c000290;
      - Removal of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-04) at revision 0x2b0004d0;
      - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode (in
        intel-06-8c-01/intel-ucode/06-8c-01) from revision 0xb4 up to 0xb6;
      - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0)
        microcode (in intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0c) from
        revision 0xf8 up to 0xfa;
      - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-09) from revision 0xf4 up
        to 0xf8;
      - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0a) from revision 0xf4 up
        to 0xf6;
      - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0c) from revision 0xf4 up
        to 0xf6;
      - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0d) from revision 0xfa up
        to 0xfc;
      - Update of 06-55-03/0x97 (SKX-SP B1) microcode from revision 0x1000181
        up to 0x1000191;
      - Update of 06-55-06/0xbf (CLX-SP B0) microcode from revision 0x4003604
        up to 0x4003605;
      - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision
        0x5003604 up to 0x5003605;
      - Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002703
        up to 0x7002802;
      - Update of 06-56-05/0x10 (BDX-NS A0/A1, HWL A1) microcode from revision
        0xe000014 up to 0xe000015;
      - Update of 06-5f-01/0x01 (DNV B0) microcode from revision 0x38 up
        to 0x3e;
      - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003b9
        up to 0xd0003d1;
      - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x1000268
        up to 0x1000290;
      - Update of 06-7a-01/0x01 (GLK B0) microcode from revision 0x3e up
        to 0x42;
      - Update of 06-7a-08/0x01 (GLK-R R0) microcode from revision 0x22 up
        to 0x24;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xc2
        up to 0xc4;
      - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x34 up
        to 0x36;
      - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x4e up
        to 0x50;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) from
        revision 0x2c000290 up to 0x2c000390;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode from revision
        0x2c000290 up to 0x2c000390;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode from revision 0x2b0004d0
        up to 0x2b0005c0;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-05) from
        revision 0x2c000290 up to 0x2c000390;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2c000290 up to 0x2c000390;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-06) from
        revision 0x2c000290 up to 0x2c000390;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-06) from revision 0x2c000290 up to 0x2c000390;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-06/0x10 microcode from revision 0x2c000290 up to
        0x2c000390;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode from revision 0x2b0004d0
        up to 0x2b0005c0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-06) from revision 0x2c000290 up to 0x2c000390;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode from revision
        0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-08) from
        revision 0x2c000290 up to 0x2c000390;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-08) from revision 0x2c000290 up to 0x2c000390;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-08) from
        revision 0x2c000290 up to 0x2c000390;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode from revision
        0x2c000290 up to 0x2c000390;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode from revision
        0x2b0004d0 up to 0x2b0005c0;
      - Update of 06-96-01/0x01 (EHL B1) microcode from revision 0x17 up
        to 0x19;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision
        0x32 up to 0x35;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-97-02) from revision 0x32 up to 0x35;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x32 up to 0x35;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x32 up to 0x35;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-97-05) from revision 0x32 up to 0x35;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x32
        up to 0x35;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x32 up to 0x35;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x32 up to 0x35;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision
        0x430 up to 0x433;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in
        intel-ucode/06-9a-03) from revision 0x430 up to 0x433;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in
        intel-ucode/06-9a-04) from revision 0x430 up to 0x433;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x430
        up to 0x433;
      - Update of 06-9a-04/0x40 (AZB A0) microcode from revision 0x5 up
        to 0x7;
      - Update of 06-9c-00/0x01 (JSL A0/A1) microcode from revision 0x24000024
        up to 0x24000026;
      - Update of 06-a5-02/0x20 (CML-H R1) microcode from revision 0xf8 up
        to 0xfa;
      - Update of 06-a5-03/0x22 (CML-S 6+2 G1) microcode from revision 0xf8
        up to 0xfa;
      - Update of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode from revision 0xf8
        up to 0xfa;
      - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from revision 0xf8
        up to 0xfa;
      - Update of 06-a6-01/0x80 (CML-U 6+2 v2 K1) microcode from revision
        0xf8 up to 0xfa;
      - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x5d up
        to 0x5e;
      - Update of 06-b7-01/0x32 (RPL-S B0) microcode from revision 0x11d up
        to 0x123;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode from revision
        0x411c up to 0x4121;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-02) from revision 0x411c up to 0x4121;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-03) from revision 0x411c up to 0x4121;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode from revision 0x411c
        up to 0x4121;
      - Update of 06-be-00/0x11 (ADL-N A0) microcode from revision 0x12 up
        to 0x17;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-02) from revision 0x32 up to 0x35;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-02) from revision 0x32 up to 0x35;
      - Update of 06-bf-02/0x07 (ADL C0) microcode from revision 0x32 up
        to 0x35;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-bf-02)
        from revision 0x32 up to 0x35;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-05) from revision 0x32 up to 0x35;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-05) from revision 0x32 up to 0x35;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-bf-05)
        from revision 0x32 up to 0x35;
      - Update of 06-bf-05/0x07 (ADL C0) microcode from revision 0x32 up
        to 0x35.
    - Update Intel CPU microcode to microcode-20231009 release, addresses
      CVE-2023-23583:
      - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode (in
        intel-06-8c-01/intel-ucode/06-8c-01) from revision 0xac up to 0xb4;
      - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003a5
        up to 0xd0003b9;
      - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x1000230
        up to 0x1000268;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xbc
        up to 0xc2;
      - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x2c up
        to 0x34;
      - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x46 up
        to 0x4e;
      - Update of 06-8f-04/0x10 microcode from revision 0x2c000271 up to
        0x2c000290;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode from revision
        0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-04) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-04) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-04) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode from revision
        0x2c000271 up to 0x2c000290;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode from revision 0x2b0004b1
        up to 0x2b0004d0;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-05) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-06) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-06) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-06/0x10 microcode from revision 0x2c000271 up to
        0x2c000290;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode from revision 0x2b0004b1
        up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-06) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode from revision
        0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-08) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-08) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-08) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode from revision
        0x2c000271 up to 0x2c000290;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode from revision
        0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision
        0x2e up to 0x32;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-97-02) from revision 0x2e up to 0x32;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x2e up to 0x32;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x2e up to 0x32;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-97-05) from revision 0x2e up to 0x32;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x2e
        up to 0x32;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x2e up to 0x32;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x2e up to 0x32;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision
        0x42c up to 0x430;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in
        intel-ucode/06-9a-03) from revision 0x42c up to 0x430;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in
        intel-ucode/06-9a-04) from revision 0x42c up to 0x430;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x42c
        up to 0x430;
      - Update of 06-9a-04/0x40 (AZB A0) microcode from revision 0x4 up
        to 0x5;
      - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x59 up
        to 0x5d;
      - Update of 06-b7-01/0x32 (RPL-S B0) microcode from revision 0x119 up
        to 0x11d;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode from revision
        0x4119 up to 0x411c;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-02) from revision 0x4119 up to 0x411c;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-03) from revision 0x4119 up to 0x411c;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode from revision 0x4119
        up to 0x411c;
      - Update of 06-be-00/0x11 (ADL-N A0) microcode from revision 0x11 up
        to 0x12;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-02) from revision 0x2e up to 0x32;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-02) from revision 0x2e up to 0x32;
      - Update of 06-bf-02/0x07 (ADL C0) microcode from revision 0x2e up
        to 0x32;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-bf-02)
        from revision 0x2e up to 0x32;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-05) from revision 0x2e up to 0x32;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-05) from revision 0x2e up to 0x32;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-bf-05)
        from revision 0x2e up to 0x32;
      - Update of 06-bf-05/0x07 (ADL C0) microcode from revision 0x2e up
        to 0x32.
    - Update Intel CPU microcode to microcode-20230808 release, addresses
      CVE-2022-40982, CVE-2022-41804, CVE-2023-23908 (#2213124, #2223992, #2230677,
        - Update of 06-55-04/0xb7 (SKX-D/SP/W/X H0/M0/M1/U0) microcode (in
        intel-06-55-04/intel-ucode/06-55-04) from revision 0x2006f05 up
        to 0x2007006;
      - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode (in
        intel-06-8c-01/intel-ucode/06-8c-01) from revision 0xaa up to 0xac;
      - Update of 06-8e-09/0xc0 (KBL-U/U 2+3e/Y H0/J1) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xf2 up
        to 0xf4;
      - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xf2 up
        to 0xf4;
      - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0a) from revision 0xf2 up
        to 0xf4;
      - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0b) from revision 0xf2 up
        to 0xf4;
      - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0)
        microcode (in intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0c) from
        revision 0xf6 up to 0xf8;
      - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-09) from revision 0xf2 up
        to 0xf4;
      - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0a) from revision 0xf2 up
        to 0xf4;
      - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0b) from revision 0xf2 up
        to 0xf4;
      - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0c) from revision 0xf2 up
        to 0xf4;
      - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0d) from revision 0xf8 up
        to 0xfa;
      - Update of 06-55-03/0x97 (SKX-SP B1) microcode from revision 0x1000171
        up to 0x1000181;
      - Update of 06-55-06/0xbf (CLX-SP B0) microcode from revision 0x4003501
        up to 0x4003604;
      - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision
        0x5003501 up to 0x5003604;
      - Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002601
        up to 0x7002703;
      - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd000390
        up to 0xd0003a5;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xba
        up to 0xbc;
      - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x2a up
        to 0x2c;
      - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x44 up
        to 0x46;
      - Update of 06-8f-04/0x10 microcode from revision 0x2c0001d1 up to
        0x2c000271;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode from revision
        0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-04) from revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-04) from
        revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-04) from revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) from
        revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode from revision
        0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode from revision 0x2b000461
        up to 0x2b0004b1;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-05) from
        revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-06) from
        revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-06) from revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-06/0x10 microcode from revision 0x2c0001d1 up to
        0x2c000271;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode from revision 0x2b000461
        up to 0x2b0004b1;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-06) from revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode from revision
        0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-08) from
        revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-08) from revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-08) from
        revision 0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b000461 up to 0x2b0004b1;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode from revision
        0x2c0001d1 up to 0x2c000271;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode from revision
        0x2b000461 up to 0x2b0004b1;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision
        0x2c up to 0x2e;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-97-02) from revision 0x2c up to 0x2e;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x2c up to 0x2e;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x2c up to 0x2e;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-97-05) from revision 0x2c up to 0x2e;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x2c
        up to 0x2e;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x2c up to 0x2e;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x2c up to 0x2e;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision
        0x42a up to 0x42c;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in
        intel-ucode/06-9a-03) from revision 0x42a up to 0x42c;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in
        intel-ucode/06-9a-04) from revision 0x42a up to 0x42c;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x42a
        up to 0x42c;
      - Update of 06-a5-02/0x20 (CML-H R1) microcode from revision 0xf6 up
        to 0xf8;
      - Update of 06-a5-03/0x22 (CML-S 6+2 G1) microcode from revision 0xf6
        up to 0xf8;
      - Update of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode from revision 0xf6
        up to 0xf8;
      - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from revision 0xf6
        up to 0xf8;
      - Update of 06-a6-01/0x80 (CML-U 6+2 v2 K1) microcode from revision
        0xf6 up to 0xf8;
      - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x58 up
        to 0x59;
      - Update of 06-b7-01/0x32 (RPL-S B0) microcode from revision 0x113 up
        to 0x119;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-02) from revision 0x2c up to 0x2e;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-02) from revision 0x2c up to 0x2e;
      - Update of 06-bf-02/0x07 (ADL C0) microcode from revision 0x2c up
        to 0x2e;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-bf-02)
        from revision 0x2c up to 0x2e;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-05) from revision 0x2c up to 0x2e;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-05) from revision 0x2c up to 0x2e;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-bf-05)
        from revision 0x2c up to 0x2e;
      - Update of 06-bf-05/0x07 (ADL C0) microcode from revision 0x2c up
        to 0x2e;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode from revision
        0x4112 up to 0x4119 (old pf 0xc0);
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-02) from revision 0x4112 up to 0x4119 (old pf 0xc0);
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-03) from revision 0x4112 up to 0x4119 (old pf 0xc0);
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode from revision 0x4112
        up to 0x4119 (old pf 0xc0);
      - Update of 06-be-00/0x11 (ADL-N A0) microcode from revision 0x10 up
        to 0x11 (old pf 0x1).

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-9401.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected microcode_ctl package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38575");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:5:baseos_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:microcode_ctl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'microcode_ctl-20240910-1.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'microcode_ctl');
}
