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
The IOCTL handler `0x8000E000` executes a function (renamed by Claude to IoctlReadDiskSectors)  that processes a 112‑byte input buffer supplied by the caller.

```c
case 0x8000E000:
      ProcessNotifyRoutine = IoctlReadDiskSectors(a2, p_MajorFunction, &v19);
```

Early in the function, the driver verifies the input size:

```c
if (v6 && *(_DWORD *)(a2 + 16) == 112)
```

`(a2 + 16)` corresponds to InputBufferLength, confirming that the driver expects a fixed‑size 112‑byte structure.

The first 100 (`0x64`) bytes of the buffer are validated as a NULL‑terminated string:

```c
do {
    if (*v9 == 0)
        break;
} while (v8 < 0x64);
```

This indicates that the beginning of the buffer contains a device name.

Further down, two additional fields are read directly from the buffer:

```c
v10 = *(_DWORD *)(v6 + 100);
v19 = *(_QWORD *)(v6 + 104);
```
These offsets reveal the remaining structure fields:

`+0x64` (100) → sector count

`+0x68` (104) → starting LBA

This is later passed to the function `IoBuildSynchronousFsdRequest` using `IRP_MJ_READ`, allowing for arbitrary read of disk sectors from user mode, effectively bypassing NTFS read restrictions entirely.

```c
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

```cpp
struct ReadSectorsInput
{
    char     DiskName[100];
    uint32_t SectorCount;
    uint64_t StartLba;
};
```

## Getting the Disk Name
Knowing that the disk name would need to be passed into the vulnerable function, I looked to enumerate the disk name at runtime. Thankfully, the driver already does this for us at IOCTL `0x8000E004`.

Looking at the implementation reveals that the driver maintains an internal linked list of disk records, which are populated by a helper function. The enumeration routine walks the Windows disk driver (`\Driver\Disk`) device chain and gathers metadata for each disk device object. Once enumeration has completed, IoctlEnumDiskDevices simply iterates over the linked list and copies each entry to the caller's output buffer.

The following code shows 0xE1 bytes (225 bytes) from the internal disk record  into the user-provided buffer. Because this copy occurs for each disk entry, we can infer that each disk record stored internally by the driver has a size of 225 bytes.

```c
memmove((void *)(v9 + v3), v8 + 2, 0xE1u);
```

Enumerating the function reveals where different pieces of information are written inside this structure. By tracking writes into the allocated record buffer, the layout of the structure can be reconstructed:

```cpp
struct DiskRecord
{
    char     DeviceName[100]; 
    uint8_t  IsDrDevice;
    uint32_t SectorSize;
    uint64_t TotalSectors;
    uint32_t AtaType;
    uint32_t PartitionType;
    uint32_t BusType;
    char     Model[41];
    uint8_t  _pad1[9];        // to reach offset 175
    char     Serial[36];
    uint8_t  _pad2[14];       // pad to 225 total
};
static_assert(sizeof(DiskRecord) == 225, "DiskRecord must be 225 bytes");
```

## Writing the Exploit
With all of the information on how to interact with the driver it was time to write the code.

