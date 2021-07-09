use crate::IcdiDevice;
use crate::{Context, Result};

use hex::FromHex;
use std::str::FromStr;

pub fn read_icdi_version(device: &mut impl IcdiDevice) -> Result<u32> {
    let mut response = device.send_remote_command(b"version")?;
    response.decode_buffer();

    let hex = response.get_payload()?;
    let x = Vec::<u8>::from_hex(hex).context("From hex failed")?;

    let ver_str = std::str::from_utf8(&x).context("hex utf8 err")?.trim();

    u32::from_str(ver_str).with_context(|| format!("From str failed {}", ver_str))
}
