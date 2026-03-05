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
To start analysing the program, I used the [Driver Buddy Revolutions Plugin] (https://plugins.hex-rays.com/jsacco/driverbuddyrevolutionsida) for IDA and found that various IOCTL's are missing privilege gates. This would allow low-privilege users use the IOCTLs if the driver was already installed. Next, I used my [IDA MCP](https://github.com/mrexodia/ida-pro-mcp) setup with Claude and have the agent decompile, rename functions, and add comments where necessary to speed up the process.
