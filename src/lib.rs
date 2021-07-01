use std::convert::TryInto;
use std::io::Write;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rusb::{DeviceHandle, UsbContext};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;

const ENDPOINT_IN: u8 = 0x83;
const ENDPOINT_OUT: u8 = 0x02;

pub const FLASH_BLOCK_SIZE: u32 = 512;
pub const FLASH_ERASE_SIZE: u32 = 1024;
const BUF_SIZE: usize = (64 + 2 * FLASH_BLOCK_SIZE) as usize;

#[derive(Clone)]
pub struct ReceiveBuffer {
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

    pub fn from_bulk_receive<C: UsbContext>(device: &mut DeviceHandle<C>) -> Result<Self> {
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

impl Debug for ReceiveBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self[..])
    }
}

impl Deref for ReceiveBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[0..self.len]
    }
}

pub trait IcdiDevice {
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
