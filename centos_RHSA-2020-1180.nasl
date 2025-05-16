#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:1180 and 
# CentOS Errata and Security Advisory 2020:1180 respectively.
#

include('compat.inc');

if (description)
{
  script_id(135354);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2017-1000476",
    "CVE-2017-11166",
    "CVE-2017-12805",
    "CVE-2017-12806",
    "CVE-2017-18251",
    "CVE-2017-18252",
    "CVE-2017-18254",
    "CVE-2017-18271",
    "CVE-2017-18273",
    "CVE-2018-10177",
    "CVE-2018-10804",
    "CVE-2018-10805",
    "CVE-2018-11656",
    "CVE-2018-12599",
    "CVE-2018-12600",
    "CVE-2018-13153",
    "CVE-2018-14434",
    "CVE-2018-14435",
    "CVE-2018-14436",
    "CVE-2018-14437",
    "CVE-2018-15607",
    "CVE-2018-16328",
    "CVE-2018-16640",
    "CVE-2018-16642",
    "CVE-2018-16643",
    "CVE-2018-16644",
    "CVE-2018-16645",
    "CVE-2018-16749",
    "CVE-2018-16750",
    "CVE-2018-17966",
    "CVE-2018-17967",
    "CVE-2018-18016",
    "CVE-2018-18024",
    "CVE-2018-18544",
    "CVE-2018-20467",
    "CVE-2018-8804",
    "CVE-2018-9133",
    "CVE-2019-10131",
    "CVE-2019-10650",
    "CVE-2019-11470",
    "CVE-2019-11472",
    "CVE-2019-11597",
    "CVE-2019-11598",
    "CVE-2019-12974",
    "CVE-2019-12975",
    "CVE-2019-12976",
    "CVE-2019-12978",
    "CVE-2019-12979",
    "CVE-2019-13133",
    "CVE-2019-13134",
    "CVE-2019-13135",
    "CVE-2019-13295",
    "CVE-2019-13297",
    "CVE-2019-13300",
    "CVE-2019-13301",
    "CVE-2019-13304",
    "CVE-2019-13305",
    "CVE-2019-13306",
    "CVE-2019-13307",
    "CVE-2019-13309",
    "CVE-2019-13310",
    "CVE-2019-13311",
    "CVE-2019-13454",
    "CVE-2019-14980",
    "CVE-2019-14981",
    "CVE-2019-15139",
    "CVE-2019-15140",
    "CVE-2019-15141",
    "CVE-2019-16708",
    "CVE-2019-16709",
    "CVE-2019-16710",
    "CVE-2019-16711",
    "CVE-2019-16712",
    "CVE-2019-16713",
    "CVE-2019-17540",
    "CVE-2019-17541",
    "CVE-2019-19948",
    "CVE-2019-19949",
    "CVE-2019-7175",
    "CVE-2019-7397",
    "CVE-2019-7398",
    "CVE-2019-9956"
  );
  script_xref(name:"RHSA", value:"2020:1180");

  script_name(english:"CentOS 7 : ImageMagick (RHSA-2020:1180)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:1180 advisory.

  - ImageMagick 7.0.7-12 Q16, a CPU exhaustion vulnerability was found in the function ReadDDSInfo in
    coders/dds.c, which allows attackers to cause a denial of service. (CVE-2017-1000476)

  - The ReadXWDImage function in coders\xwd.c in ImageMagick 7.0.5-6 has a memory leak vulnerability that can
    cause memory exhaustion via a crafted length (number of color-map entries) field in the header of an XWD
    file. (CVE-2017-11166)

  - In ImageMagick 7.0.6-6, a memory exhaustion vulnerability was found in the function ReadTIFFImage, which
    allows attackers to cause a denial of service. (CVE-2017-12805)

  - In ImageMagick 7.0.6-6, a memory exhaustion vulnerability was found in the function format8BIM, which
    allows attackers to cause a denial of service. (CVE-2017-12806)

  - An issue was discovered in ImageMagick 7.0.7. A memory leak vulnerability was found in the function
    ReadPCDImage in coders/pcd.c, which allow remote attackers to cause a denial of service via a crafted
    file. (CVE-2017-18251)

  - An issue was discovered in ImageMagick 7.0.7. The MogrifyImageList function in MagickWand/mogrify.c allows
    attackers to cause a denial of service (assertion failure and application exit in ReplaceImageInList) via
    a crafted file. (CVE-2017-18252)

  - An issue was discovered in ImageMagick 7.0.7. A memory leak vulnerability was found in the function
    WriteGIFImage in coders/gif.c, which allow remote attackers to cause a denial of service via a crafted
    file. (CVE-2017-18254)

  - In ImageMagick 7.0.7-16 Q16 x86_64 2017-12-22, an infinite loop vulnerability was found in the function
    ReadMIFFImage in coders/miff.c, which allows attackers to cause a denial of service (CPU exhaustion) via a
    crafted MIFF image file. (CVE-2017-18271)

  - In ImageMagick 7.0.7-16 Q16 x86_64 2017-12-22, an infinite loop vulnerability was found in the function
    ReadTXTImage in coders/txt.c, which allows attackers to cause a denial of service (CPU exhaustion) via a
    crafted image file that is mishandled in a GetImageIndexInList call. (CVE-2017-18273)

  - In ImageMagick 7.0.7-28, there is an infinite loop in the ReadOneMNGImage function of the coders/png.c
    file. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted mng
    file. (CVE-2018-10177)

  - ImageMagick version 7.0.7-28 contains a memory leak in WriteTIFFImage in coders/tiff.c. (CVE-2018-10804)

  - ImageMagick version 7.0.7-28 contains a memory leak in ReadYCBCRImage in coders/ycbcr.c. (CVE-2018-10805)

  - In ImageMagick 7.0.7-20 Q16 x86_64, a memory leak vulnerability was found in the function ReadDCMImage in
    coders/dcm.c, which allows attackers to cause a denial of service via a crafted DCM image file.
    (CVE-2018-11656)

  - In ImageMagick 7.0.8-3 Q16, ReadBMPImage and WriteBMPImage in coders/bmp.c allow attackers to cause an out
    of bounds write via a crafted file. (CVE-2018-12599)

  - In ImageMagick 7.0.8-3 Q16, ReadDIBImage and WriteDIBImage in coders/dib.c allow attackers to cause an out
    of bounds write via a crafted file. (CVE-2018-12600)

  - In ImageMagick 7.0.8-4, there is a memory leak in the XMagickCommand function in MagickCore/animate.c.
    (CVE-2018-13153)

  - ImageMagick 7.0.8-4 has a memory leak for a colormap in WriteMPCImage in coders/mpc.c. (CVE-2018-14434)

  - ImageMagick 7.0.8-4 has a memory leak in DecodeImage in coders/pcd.c. (CVE-2018-14435)

  - ImageMagick 7.0.8-4 has a memory leak in ReadMIFFImage in coders/miff.c. (CVE-2018-14436)

  - ImageMagick 7.0.8-4 has a memory leak in parse8BIM in coders/meta.c. (CVE-2018-14437)

  - In ImageMagick 7.0.8-11 Q16, a tiny input file 0x50 0x36 0x36 0x36 0x36 0x4c 0x36 0x38 0x36 0x36 0x36 0x36
    0x36 0x36 0x1f 0x35 0x50 0x00 can result in a hang of several minutes during which CPU and memory
    resources are consumed until ultimately an attempted large memory allocation fails. Remote attackers could
    leverage this vulnerability to cause a denial of service via a crafted file. (CVE-2018-15607)

  - In ImageMagick before 7.0.8-8, a NULL pointer dereference exists in the CheckEventLogging function in
    MagickCore/log.c. (CVE-2018-16328)

  - ImageMagick 7.0.8-5 has a memory leak vulnerability in the function ReadOneJNGImage in coders/png.c.
    (CVE-2018-16640)

  - The function InsertRow in coders/cut.c in ImageMagick 7.0.7-37 allows remote attackers to cause a denial
    of service via a crafted image file due to an out-of-bounds write. (CVE-2018-16642)

  - The functions ReadDCMImage in coders/dcm.c, ReadPWPImage in coders/pwp.c, ReadCALSImage in coders/cals.c,
    and ReadPICTImage in coders/pict.c in ImageMagick 7.0.8-4 do not check the return value of the fputc
    function, which allows remote attackers to cause a denial of service via a crafted image file.
    (CVE-2018-16643)

  - There is a missing check for length in the functions ReadDCMImage of coders/dcm.c and ReadPICTImage of
    coders/pict.c in ImageMagick 7.0.8-11, which allows remote attackers to cause a denial of service via a
    crafted image. (CVE-2018-16644)

  - There is an excessive memory allocation issue in the functions ReadBMPImage of coders/bmp.c and
    ReadDIBImage of coders/dib.c in ImageMagick 7.0.8-11, which allows remote attackers to cause a denial of
    service via a crafted image file. (CVE-2018-16645)

  - In ImageMagick 7.0.7-29 and earlier, a missing NULL check in ReadOneJNGImage in coders/png.c allows an
    attacker to cause a denial of service (WriteBlob assertion failure and application exit) via a crafted
    file. (CVE-2018-16749)

  - In ImageMagick 7.0.7-29 and earlier, a memory leak in the formatIPTCfromBuffer function in coders/meta.c
    was found. (CVE-2018-16750)

  - ImageMagick 7.0.7-28 has a memory leak vulnerability in WritePDBImage in coders/pdb.c. (CVE-2018-17966)

  - ImageMagick 7.0.7-28 has a memory leak vulnerability in ReadBGRImage in coders/bgr.c. (CVE-2018-17967)

  - ImageMagick 7.0.7-28 has a memory leak vulnerability in WritePCXImage in coders/pcx.c. (CVE-2018-18016)

  - In ImageMagick 7.0.8-13 Q16, there is an infinite loop in the ReadBMPImage function of the coders/bmp.c
    file. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted bmp
    file. (CVE-2018-18024)

  - There is a memory leak in the function WriteMSLImage of coders/msl.c in ImageMagick 7.0.8-13 Q16, and the
    function ProcessMSLScript of coders/msl.c in GraphicsMagick before 1.3.31. (CVE-2018-18544)

  - In coders/bmp.c in ImageMagick before 7.0.8-16, an input file can result in an infinite loop and hang,
    with high CPU and memory consumption. Remote attackers could leverage this vulnerability to cause a denial
    of service via a crafted file. (CVE-2018-20467)

  - WriteEPTImage in coders/ept.c in ImageMagick 7.0.7-25 Q16 allows remote attackers to cause a denial of
    service (MagickCore/memory.c double free and application crash) or possibly have unspecified other impact
    via a crafted file. (CVE-2018-8804)

  - ImageMagick 7.0.7-26 Q16 has excessive iteration in the DecodeLabImage and EncodeLabImage functions
    (coders/tiff.c), which results in a hang (tens of minutes) with a tiny PoC file. Remote attackers could
    leverage this vulnerability to cause a denial of service via a crafted tiff file. (CVE-2018-9133)

  - An off-by-one read vulnerability was discovered in ImageMagick before version 7.0.7-28 in the
    formatIPTCfromBuffer function in coders/meta.c. A local attacker may use this flaw to read beyond the end
    of the buffer or to crash the program. (CVE-2019-10131)

  - In ImageMagick 7.0.8-36 Q16, there is a heap-based buffer over-read in the function WriteTIFFImage of
    coders/tiff.c, which allows an attacker to cause a denial of service or information disclosure via a
    crafted image file. (CVE-2019-10650)

  - The cineon parsing component in ImageMagick 7.0.8-26 Q16 allows attackers to cause a denial-of-service
    (uncontrolled resource consumption) by crafting a Cineon image with an incorrect claimed image size. This
    occurs because ReadCINImage in coders/cin.c lacks a check for insufficient image data in a file.
    (CVE-2019-11470)

  - ReadXWDImage in coders/xwd.c in the XWD image parsing component of ImageMagick 7.0.8-41 Q16 allows
    attackers to cause a denial-of-service (divide-by-zero error) by crafting an XWD image file in which the
    header indicates neither LSB first nor MSB first. (CVE-2019-11472)

  - In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer over-read in the function WriteTIFFImage of
    coders/tiff.c, which allows an attacker to cause a denial of service or possibly information disclosure
    via a crafted image file. (CVE-2019-11597)

  - In ImageMagick 7.0.8-40 Q16, there is a heap-based buffer over-read in the function WritePNMImage of
    coders/pnm.c, which allows an attacker to cause a denial of service or possibly information disclosure via
    a crafted image file. This is related to SetGrayscaleImage in MagickCore/quantize.c. (CVE-2019-11598)

  - A NULL pointer dereference in the function ReadPANGOImage in coders/pango.c and the function ReadVIDImage
    in coders/vid.c in ImageMagick 7.0.8-34 allows remote attackers to cause a denial of service via a crafted
    image. (CVE-2019-12974)

  - ImageMagick 7.0.8-34 has a memory leak vulnerability in the WriteDPXImage function in coders/dpx.c.
    (CVE-2019-12975)

  - ImageMagick 7.0.8-34 has a memory leak in the ReadPCLImage function in coders/pcl.c. (CVE-2019-12976)

  - ImageMagick 7.0.8-34 has a use of uninitialized value vulnerability in the ReadPANGOImage function in
    coders/pango.c. (CVE-2019-12978)

  - ImageMagick 7.0.8-34 has a use of uninitialized value vulnerability in the SyncImageSettings function in
    MagickCore/image.c. This is related to AcquireImage in magick/image.c. (CVE-2019-12979)

  - ImageMagick before 7.0.8-50 has a memory leak vulnerability in the function ReadBMPImage in coders/bmp.c.
    (CVE-2019-13133)

  - ImageMagick before 7.0.8-50 has a memory leak vulnerability in the function ReadVIFFImage in
    coders/viff.c. (CVE-2019-13134)

  - ImageMagick before 7.0.8-50 has a use of uninitialized value vulnerability in the function ReadCUTImage
    in coders/cut.c. (CVE-2019-13135)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer over-read at MagickCore/threshold.c in
    AdaptiveThresholdImage because a width of zero is mishandled. (CVE-2019-13295)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer over-read at MagickCore/threshold.c in
    AdaptiveThresholdImage because a height of zero is mishandled. (CVE-2019-13297)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer overflow at MagickCore/statistic.c in EvaluateImages
    because of mishandling columns. (CVE-2019-13300)

  - ImageMagick 7.0.8-50 Q16 has memory leaks in AcquireMagickMemory because of an AnnotateImage error.
    (CVE-2019-13301)

  - ImageMagick 7.0.8-50 Q16 has a stack-based buffer overflow at coders/pnm.c in WritePNMImage because of a
    misplaced assignment. (CVE-2019-13304)

  - ImageMagick 7.0.8-50 Q16 has a stack-based buffer overflow at coders/pnm.c in WritePNMImage because of a
    misplaced strncpy and an off-by-one error. (CVE-2019-13305)

  - ImageMagick 7.0.8-50 Q16 has a stack-based buffer overflow at coders/pnm.c in WritePNMImage because of
    off-by-one errors. (CVE-2019-13306)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer overflow at MagickCore/statistic.c in EvaluateImages
    because of mishandling rows. (CVE-2019-13307)

  - ImageMagick 7.0.8-50 Q16 has memory leaks at AcquireMagickMemory because of mishandling the NoSuchImage
    error in CLIListOperatorImages in MagickWand/operation.c. (CVE-2019-13309)

  - ImageMagick 7.0.8-50 Q16 has memory leaks at AcquireMagickMemory because of an error in
    MagickWand/mogrify.c. (CVE-2019-13310)

  - ImageMagick 7.0.8-50 Q16 has memory leaks at AcquireMagickMemory because of a wand/mogrify.c error.
    (CVE-2019-13311)

  - ImageMagick 7.0.8-54 Q16 allows Division by Zero in RemoveDuplicateLayers in MagickCore/layer.c.
    (CVE-2019-13454)

  - In ImageMagick 7.x before 7.0.8-42 and 6.x before 6.9.10-42, there is a use after free vulnerability in
    the UnmapBlob function that allows an attacker to cause a denial of service by sending a crafted file.
    (CVE-2019-14980)

  - In ImageMagick 7.x before 7.0.8-41 and 6.x before 6.9.10-41, there is a divide-by-zero vulnerability in
    the MeanShiftImage function. It allows an attacker to cause a denial of service by sending a crafted file.
    (CVE-2019-14981)

  - The XWD image (X Window System window dumping file) parsing component in ImageMagick 7.0.8-41 Q16 allows
    attackers to cause a denial-of-service (application crash resulting from an out-of-bounds Read) in
    ReadXWDImage in coders/xwd.c by crafting a corrupted XWD image file, a different vulnerability than
    CVE-2019-11472. (CVE-2019-15139)

  - coders/mat.c in ImageMagick 7.0.8-43 Q16 allows remote attackers to cause a denial of service (use-after-
    free and application crash) or possibly have unspecified other impact by crafting a Matlab image file that
    is mishandled in ReadImage in MagickCore/constitute.c. (CVE-2019-15140)

  - WriteTIFFImage in coders/tiff.c in ImageMagick 7.0.8-43 Q16 allows attackers to cause a denial-of-service
    (application crash resulting from a heap-based buffer over-read) via a crafted TIFF image file, related to
    TIFFRewriteDirectory, TIFFWriteDirectory, TIFFWriteDirectorySec, and TIFFWriteDirectoryTagColormap in
    tif_dirwrite.c of LibTIFF. NOTE: this occurs because of an incomplete fix for CVE-2019-11597.
    (CVE-2019-15141)

  - ImageMagick 7.0.8-35 has a memory leak in magick/xwindow.c, related to XCreateImage. (CVE-2019-16708)

  - ImageMagick 7.0.8-35 has a memory leak in coders/dps.c, as demonstrated by XCreateImage. (CVE-2019-16709)

  - ImageMagick 7.0.8-35 has a memory leak in coders/dot.c, as demonstrated by AcquireMagickMemory in
    MagickCore/memory.c. (CVE-2019-16710)

  - ImageMagick 7.0.8-40 has a memory leak in Huffman2DEncodeImage in coders/ps2.c. (CVE-2019-16711)

  - ImageMagick 7.0.8-43 has a memory leak in Huffman2DEncodeImage in coders/ps3.c, as demonstrated by
    WritePS3Image. (CVE-2019-16712)

  - ImageMagick 7.0.8-43 has a memory leak in coders/dot.c, as demonstrated by PingImage in
    MagickCore/constitute.c. (CVE-2019-16713)

  - ImageMagick before 7.0.8-54 has a heap-based buffer overflow in ReadPSInfo in coders/ps.c.
    (CVE-2019-17540)

  - ImageMagick before 7.0.8-55 has a use-after-free in DestroyStringInfo in MagickCore/string.c because the
    error manager is mishandled in coders/jpeg.c. (CVE-2019-17541)

  - In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer overflow in the function WriteSGIImage of
    coders/sgi.c. (CVE-2019-19948)

  - In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer over-read in the function WritePNGImage of
    coders/png.c, related to Magick_png_write_raw_profile and LocaleNCompare. (CVE-2019-19949)

  - In ImageMagick before 7.0.8-25, some memory leaks exist in DecodeImage in coders/pcd.c. (CVE-2019-7175)

  - In ImageMagick before 7.0.8-25 and GraphicsMagick through 1.3.31, several memory leaks exist in
    WritePDFImage in coders/pdf.c. (CVE-2019-7397)

  - In ImageMagick before 7.0.8-25, a memory leak exists in WriteDIBImage in coders/dib.c. (CVE-2019-7398)

  - In ImageMagick 7.0.8-35 Q16, there is a stack-based buffer overflow in the function PopHexPixel of
    coders/ps.c, which allows an attacker to cause a denial of service or code execution via a crafted image
    file. (CVE-2019-9956)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1180");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19948");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autotrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autotrace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:inkscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:inkscape-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:inkscape-view");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'autotrace-0.31.1-38.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autotrace-0.31.1-38.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autotrace-devel-0.31.1-38.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'autotrace-devel-0.31.1-38.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'emacs-24.3-23.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-24.3-23.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-common-24.3-23.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-common-24.3-23.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-el-24.3-23.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-el-24.3-23.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-filesystem-24.3-23.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-filesystem-24.3-23.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-nox-24.3-23.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-nox-24.3-23.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-terminal-24.3-23.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'emacs-terminal-24.3-23.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ImageMagick-6.9.10.68-3.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-6.9.10.68-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.10.68-3.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.10.68-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.10.68-3.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.10.68-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.10.68-3.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.10.68-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.10.68-3.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.10.68-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.10.68-3.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.10.68-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'inkscape-0.92.2-3.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'inkscape-0.92.2-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'inkscape-docs-0.92.2-3.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'inkscape-docs-0.92.2-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'inkscape-view-0.92.2-3.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'inkscape-view-0.92.2-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc');
}
