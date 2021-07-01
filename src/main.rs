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
use rusb::{Device, DeviceHandle, GlobalContext, UsbContext};
use std::convert::TryInto;
use std::io::Write;
use std::time::Duration;
use structopt::{clap::AppSettings, StructOpt};

const FLASH_BLOCK_SIZE: u32 = 512;
const FLASH_ERASE_SIZE: u32 = 1024;

const BUF_SIZE: usize = (64 + 2 * FLASH_BLOCK_SIZE) as usize;

const ICDI_VID: u16 = 0x1cbe;
const ICDI_PID: u16 = 0x00fd;

const INTERFACE_NR: u8 = 0x02;
const ENDPOINT_IN: u8 = 0x83;
const ENDPOINT_OUT: u8 = 0x02;

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

fn print_icdi_version(device: &mut DeviceHandle<GlobalContext>) -> Result<()> {
    let mut response = device.send_command(b"version")?;
    response.decode_buffer();
    if &response.data[..2] != b"+$" {
        bail!("ICDI version response error")
    }
    let hex_number = response.data[2..]
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
fn write_firmware(mut dev: DeviceHandle<GlobalContext>, fw: &[u8]) -> Result<()> {
    print_icdi_version(&mut dev)?;
    dev.send_command(b"debug clock \0")?;
    dev.send_string(b"qSupported")?;
    dev.send_string(b"?")?;
    dev.mem_write(FP_CTRL, 0x3000000)?;
    dev.mem_read(DID0)?;
    dev.mem_read(DID1)?;
    dev.send_string(b"?")?;
    dev.mem_read(DHCSR)?;
    dev.send_command(b"debug sreset")?;
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

    dev.send_command(b"debug creset")?;
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
    dev.send_command(b"set vectorcatch 0")?;
    dev.send_command(b"debug disable")?;

    dev.mem_write(FP_CTRL, 0x3000000)?;
    dev.send_command(b"debug hreset")?;
    dev.send_command(b"set vectorcatch 0")?;
    dev.send_command(b"debug disable")?;

    Ok(())
}

#[derive(Clone, Debug)]
struct ReceiveBuffer {
    data: Box<[u8]>,
    len: usize,
    decoded: bool,
}

impl ReceiveBuffer {
    fn new() -> Self {
        Self {
            data: vec![0u8; BUF_SIZE].into_boxed_slice(),
            len: 0,
            decoded: false,
        }
    }

    fn from_bulk_receive<C: UsbContext>(device: &mut DeviceHandle<C>) -> Result<Self> {
        let mut buf = Self::new();
        let mut len = 0;
        while len < 3 || buf.data[len - 3] != b'#' {
            let slice = &mut buf.data[len..];
            if slice.is_empty() {
                bail!("Buffer couldn't hold the full response.")
            }
            len += device
                .read_bulk(ENDPOINT_IN, slice, Duration::default())
                .context("Error receiving data")?;
        }
        buf.len = len;
        Ok(buf)
    }

    pub fn decode_buffer(&mut self) {
        if self.decoded {
            return;
        }
        let mut write = 0;
        let mut read = 0;
        while read < self.len {
            let decoded = if self.data[read] == b'}' {
                read += 1;
                self.data[read] ^ 0x20
            } else {
                self.data[read]
            };
            self.data[write] = decoded;
            write += 1;
            read += 1;
        }
        self.len = write;
        self.decoded = true;
    }
    pub fn has_ack(&self) -> bool {
        self.len > 0 && self.data[0] == b'+'
    }
}

trait IcdiDevice {
    // These are macros in the C original
    fn send_command(&mut self, cmd: &[u8]) -> Result<ReceiveBuffer> {
        self.send_u8_hex(b"qRcmd,", cmd)
    }
    fn send_string(&mut self, str: &[u8]) -> Result<ReceiveBuffer> {
        self.send_u8_hex(str, b"")
    }
    fn mem_write(&mut self, address: u32, value: u32) -> Result<ReceiveBuffer> {
        self.send_u32_u32(b"X", address, b",4:", value, b"")
    }
    fn mem_read(&mut self, address: u32) -> Result<u32> {
        let buf = self.send_u32(b"x", address, b",4")?;
        if buf.len <= 8 {
            bail!(
                "Not enough data received in mem_read from address {}.",
                address
            )
        }
        Ok(u32::from_le_bytes((&buf.data[5..9]).try_into().unwrap()))
    }
    fn flash_erase(&mut self, start: u32, len: u32) -> Result<ReceiveBuffer> {
        self.send_u32_u32(b"vFlashErase:", start, b",", len, b"")
    }
    fn flash_write(&mut self, address: u32, bytes: &[u8]) -> Result<ReceiveBuffer> {
        let mut prefix = [b'.'; b"vFlashWrite:12345678:".len()];
        write!(&mut prefix[..], "vFlashWrite:{:08x}:", address)?;
        let mut buf = Vec::with_capacity(bytes.len() * 3 / 2);
        for byte in bytes {
            if b"#$}".contains(byte) {
                buf.push(b'}');
                buf.push(*byte ^ 0x20)
            } else {
                buf.push(*byte)
            };
        }
        self.send_u8_binary(&prefix[..], buf.as_slice())
    }
    fn flash_verify(&mut self, address: u32, block: &[u8]) -> Result<()> {
        let mut x = self.send_u32_u32(b"x", address, b",", block.len() as u32, b"")?;
        x.decode_buffer();
        if &x
            .data
            .strip_prefix(b"+$OK:")
            .context("Bad flash verify response")?[..block.len()]
            != block
        {
            bail!("Flash verification failed.")
        }
        Ok(())
    }

    // Helper functions
    fn send_u8_hex(&mut self, prefix: &[u8], bytes: &[u8]) -> Result<ReceiveBuffer> {
        let mut buf = Vec::with_capacity(1 + prefix.len() + bytes.len() + 4);
        buf.push(b'$');
        buf.extend_from_slice(prefix);
        for byte in bytes {
            write!(&mut buf, "{:02x}", byte)?;
        }
        self.checksum_and_send(buf)
    }
    fn send_u8_binary(&mut self, prefix: &[u8], bytes: &[u8]) -> Result<ReceiveBuffer> {
        let mut buf = Vec::with_capacity(1 + prefix.len() + bytes.len() + 3);
        buf.push(b'$');
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(bytes);
        self.checksum_and_send(buf)
    }

    fn send_u32(&mut self, prefix: &[u8], value: u32, suffix: &[u8]) -> Result<ReceiveBuffer> {
        let mut buf = Vec::with_capacity(BUF_SIZE);
        buf.push(b'$');
        buf.extend_from_slice(prefix);
        write!(&mut buf, "{:08x}", value)?;
        buf.extend_from_slice(suffix);
        self.checksum_and_send(buf)
    }

    fn send_u32_u32(
        &mut self,
        prefix: &[u8],
        val1: u32,
        infix: &[u8],
        val2: u32,
        suffix: &[u8],
    ) -> Result<ReceiveBuffer> {
        let mut buf = Vec::with_capacity(prefix.len() + infix.len() + suffix.len() + 1 + 8 + 2 + 3);
        buf.push(b'$');
        buf.extend_from_slice(prefix);
        write!(&mut buf, "{:08x}", val1)?;
        buf.extend_from_slice(infix);
        write!(&mut buf, "{:08x}", val2)?;
        buf.extend_from_slice(suffix);
        self.checksum_and_send(buf)
    }

    /// Pushes 3 extra bytes to the end of the buffer
    fn checksum_and_send(&mut self, data: Vec<u8>) -> Result<ReceiveBuffer>;
    fn send(&mut self, data: &[u8]) -> Result<()>;
}

impl<CTX: rusb::UsbContext> IcdiDevice for DeviceHandle<CTX> {
    fn checksum_and_send(&mut self, mut data: Vec<u8>) -> Result<ReceiveBuffer> {
        let checksum = data
            .iter()
            .skip(1)
            .fold(0u8, |acc, &byte| acc.wrapping_add(byte));
        write!(&mut data, "#{:02x}", checksum)?;
        self.send(&data)?;
        ReceiveBuffer::from_bulk_receive(self)
    }

    fn send(&mut self, data: &[u8]) -> Result<()> {
        self.write_bulk(ENDPOINT_OUT, data, std::time::Duration::from_secs(0))
            .context("Error transmitting data")
            .and_then(|transmitted| {
                if transmitted == data.len() {
                    Ok(())
                } else {
                    bail!("Error while transmitting. The complete buffer wasn't sent.")
                }
            })
    }
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
