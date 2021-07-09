/*
 * lm4flash  - TI Stellaris Launchpad ICDI flasher
 * Copyright 2021 Lukas Sandström
 *
 * Based on the C program lm4flash by Peter Stuge and Fabio Utzig
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
use anyhow::{bail, Context, Result};
use once_cell::sync::OnceCell;
use rusb::{Device, GlobalContext};
use structopt::{clap::AppSettings, StructOpt};

use lm4flash::usb::{ICDI_PID, ICDI_VID, INTERFACE_NR};
use lm4flash::{IcdiDevice, FLASH_BLOCK_SIZE, FLASH_ERASE_SIZE};

const FP_CTRL: u32 = 0x3000000;
const DHCSR: u32 = 0xe000edf0;
const DID0: u32 = 0x400fe000;
const DID1: u32 = 0x400fe004;
const DC0: u32 = 0x400fe008;
const RCC: u32 = 0x400fe060;
const NVMSTAT: u32 = 0x400fe1a0;
const ROMCTL: u32 = 0x400fe0f0;
const FMA: u32 = 0x400fd000;

fn parse_hex(src: &str) -> Result<u32> {
    u32::from_str_radix(src, 16).context("Failed to parse hex number")
}

#[derive(Debug, StructOpt)]
#[structopt(name = "lm4flash", about = "A rewrite of lm4flash in Rust...", global_settings=&[AppSettings::ArgRequiredElseHelp])]
struct CommandLineOpts {
    /// Only erase the blocks which will be written.
    #[structopt(short = "E")]
    erase_used: bool,

    /// Write the binary at the given (hexadecimal) address.
    /// The address must be aligned to the flash erase size.
    #[structopt(short = "S", default_value = "0")]
    start_addr: u32,

    /// Enable verification after write
    #[structopt(short = "v")]
    verify: bool,

    /// Flash the device with this serial number
    #[structopt(short = "s", parse(try_from_str = parse_hex))]
    serial: Option<u32>,

    /// The binary file to be written to the flash
    bin_file: String,
}

static OPTS: OnceCell<CommandLineOpts> = OnceCell::new();

fn main() -> Result<()> {
    let opt = CommandLineOpts::from_args();

    if opt.start_addr % FLASH_ERASE_SIZE != 0 {
        bail!(
            "Address given to -S must be aligned to 0x{:x}",
            FLASH_ERASE_SIZE
        )
    }

    if OPTS.set(opt).is_err() {
        bail!("BUG: Command line opts already loaded.");
    }

    flasher_flash()
}

fn flasher_flash() -> Result<()> {
    let mut device = find_device()?.open().context("Failed to open device")?;
    device
        .claim_interface(INTERFACE_NR)
        .context("Failed to claim interface")?;

    let bin_file = &OPTS.get().unwrap().bin_file;
    let fw = std::fs::read(bin_file).context("Failed to read firmware file")?;
    write_firmware(device, fw.as_slice())
}

fn print_icdi_version(device: &mut impl IcdiDevice) -> Result<()> {
    let mut response = device.send_remote_command(b"version")?;
    response.decode_buffer();

    let hex_number = response
        .strip_prefix(b"+$")
        .context("ICDI version response error")?
        .split(|&c| c == b'#')
        .next()
        .context("Failed to find # in version")?;

    print!("IDCI version: ");
    for hex in hex_number.chunks_exact(2) {
        let x = u32::from_str_radix(
            std::str::from_utf8(hex).context("IDCI version hex slice not valid UTF-8")?,
            16,
        )
        .context("Version not hex number")?;
        print!("{}", x);
    }
    println!();
    Ok(())
}
fn write_firmware(mut dev: impl IcdiDevice, fw: &[u8]) -> Result<()> {
    print_icdi_version(&mut dev)?;
    dev.send_remote_command(b"debug clock \0")?;
    dev.send_string(b"qSupported")?;
    dev.send_string(b"?")?;
    dev.mem_write(FP_CTRL, 0x3000000)?;
    dev.mem_read(DID0)?;
    dev.mem_read(DID1)?;
    dev.send_string(b"?")?;
    dev.mem_read(DHCSR)?;
    dev.send_remote_command(b"debug sreset")?;
    dev.mem_read(DHCSR)?;
    dev.mem_read(ROMCTL)?;
    dev.mem_write(ROMCTL, 0)?;
    dev.mem_read(DHCSR)?;
    dev.mem_read(RCC)?;
    dev.mem_read(DID0)?;
    dev.mem_read(DID1)?;
    dev.mem_read(DC0)?;
    dev.mem_read(DID0)?;
    dev.mem_read(NVMSTAT)?;

    dev.mem_write(FMA, 0)?;
    dev.mem_read(DHCSR)?;

    let start_addr = OPTS.get().unwrap().start_addr;
    if OPTS.get().unwrap().erase_used {
        let mut addr = start_addr;
        let end: u32 = start_addr + fw.len() as u32;
        while addr < end {
            dev.flash_erase(addr, FLASH_ERASE_SIZE)?;
            addr += FLASH_ERASE_SIZE
        }
    } else {
        dev.flash_erase(0, 0)?;
    }

    dev.send_remote_command(b"debug creset")?;
    dev.mem_read(DHCSR)?;

    dev.mem_write(DHCSR, 0)?;

    dev.mem_read(ROMCTL)?;
    dev.mem_write(ROMCTL, 0)?;
    dev.mem_read(DHCSR)?;

    let mut address = start_addr;
    for block in fw.chunks(FLASH_BLOCK_SIZE as usize) {
        dev.flash_write(address, block)?;
        address += FLASH_BLOCK_SIZE;
    }

    if OPTS.get().unwrap().verify {
        let mut address = start_addr;
        for block in fw.chunks(FLASH_BLOCK_SIZE as usize) {
            if let Err(e) = dev.flash_verify(address, block) {
                println!("{:#?}", e);
                break;
            }
            address += FLASH_BLOCK_SIZE;
        }
    };
    dev.send_remote_command(b"set vectorcatch 0")?;
    dev.send_remote_command(b"debug disable")?;

    dev.mem_write(FP_CTRL, 0x3000000)?;
    dev.send_remote_command(b"debug hreset")?;
    dev.send_remote_command(b"set vectorcatch 0")?;
    dev.send_remote_command(b"debug disable")?;

    Ok(())
}

fn find_device() -> Result<Device<GlobalContext>> {
    let mut found_device = None;
    let serial_target = OPTS.get().unwrap().serial;

    for device in rusb::devices()
        .context("Failed to enumerate USB devices.")?
        .iter()
    {
        let descr = device
            .device_descriptor()
            .context("Failed to get device descriptor")?;
        if descr.vendor_id() != ICDI_VID || descr.product_id() != ICDI_PID {
            continue;
        }

        let serial = device
            .open()
            .context("Unable to open USB device")?
            .read_string_descriptor_ascii(
                descr
                    .serial_number_string_index()
                    .context("Failed to get index of device serial number descriptor")?,
            )
            .context("Unable to get device serial number")?;
        println!("Found ICDI device with serial: {}", serial);
        if serial_target.is_some() && parse_hex(&serial).ok() != serial_target {
            continue;
        }
        if found_device.is_some() {
            if serial_target.is_none() {
                bail!("Found multiple ICDI devices")
            } else {
                bail!("Found ICDI serial number collision!")
            }
        }
        found_device = Some(device);
    }
    if let Some(device) = found_device {
        Ok(device)
    } else {
        bail!("No target device found.")
    }
}
