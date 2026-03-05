---
title: "Bypassing NTFS ACLs and File Locks via Direct Device Object I/Os From Kernel Mode"
date: 2026-03-05  00:00:00 -0500
categories: [research]
tags: [BYOVD]
image:
  path: /assets/img/posts/Bypassing-NTFS-ACLs/Header.png
  alt: Bypassing NTFS ACLs and File Locks via Direct Device Object I/Os From Kernel Mode
---

## Introduction
I recently began exploring kernel-mode drivers for Bring Your Own Vulnerable Driver (BYOVD) attacks during network testing. I found that many data forensics tools often export functions that can be leveraged for exploitation, like `ZwOpenSection`, `MmMapIoSpace`, & `ZwTerminateProcess`. A particular driver I identified used `IoBuildSynchronousFsdRequest` and `IofCallDriver` to read files from disk.sys bypassing NTFS protections. Unfortunately, the driver is not cross-signed by Microsoft, mitigating a lot of the impact. *I will update this post with the name of the driver once it is properly disclosed to the vendor*

## Initial Analysis
To start analysing the program, I used the [Driver Buddy Revolutions Plugin](https://plugins.hex-rays.com/jsacco/driverbuddyrevolutionsida) for IDA and found that various IOCTL's are missing privilege gates. This would allow low-privilege users use the IOCTLs if the driver was already installed. Next, I used my [IDA MCP](https://github.com/mrexodia/ida-pro-mcp) setup with Claude and have the agent decompile, rename functions, and add comments where necessary to speed up the process.

After all of this was done, I was able to quickly pull out the device name (`\Device\addriver`) and see what IOCTLs call certain functions. Various vulnerable functions can be called from IOCTLs, but for this post, we will focus on those that will help with reading files, bypassing NTFS restrictions (e.g., `0x8000E004`, `0x8000E000`).

## Finding The Vulnerability
The handler for IOCTL `0x8000E000` (renamed by Claude to IoctlReadDiskSectors) processes a 112‑byte input buffer supplied by the caller.

Early in the function, the driver verifies the input size:

```
if (v6 && *(_DWORD *)(a2 + 16) == 112)
```

*(a2 + 16) corresponds to InputBufferLength, confirming that the driver expects a fixed‑size 112‑byte structure.

The first 100 bytes of the buffer are validated as a NULL‑terminated string:

```
do {
    if (*v9 == 0)
        break;
} while (v8 < 0x64);
```

This indicates that the beginning of the buffer contains a device name.

Further down, two additional fields are read directly from the buffer:

```
v10 = *(_DWORD *)(v6 + 100);
v19 = *(_QWORD *)(v6 + 104);
```
These offsets reveal the remaining structure fields:

`+0x64` (100) → sector count

`+0x68` (104) → starting LBA

This is later passed to the function `IoBuildSynchronousFsdRequest` using `IRP_MJ_READ`, allowing for arbitrary read of disk sectors from user mode.

```
v16 = IoBuildSynchronousFsdRequest(
    3u,                                          // IRP_MJ_READ (major function code = read)
    *(PDEVICE_OBJECT *)((char *)v11 + 241),     // Target device object (selected disk) 
    (PVOID)(v6 + i * *(_DWORD *)((char *)v11 + 117)), // Output buffer for this sector read
    *(_DWORD *)((char *)v11 + 117),             // Length of the read = sector size
    &Timeout,                                   // Byte offset on disk for this read
                                                //   -> Timeout.QuadPart = sector_size * (StartLba + i)
                                                //   -> StartLba = user input from v6 + 104
    &Event,                                     // Event used to wait for completion
    &IoStatusBlock                              // IO_STATUS_BLOCK that will receive status info
);
```

Based on this, the IOCTL input buffer for our POC can be crafted like:

```
struct ReadSectorsInput
{
    char     DiskName[100];
    uint32_t SectorCount;
    uint64_t StartLba;
};
```

