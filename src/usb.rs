use anyhow::{Context, Result};
use rusb::{Device, DeviceHandle, GlobalContext};

pub const ICDI_VID: u16 = 0x1cbe;
pub const ICDI_PID: u16 = 0x00fd;

pub const INTERFACE_NR: u8 = 0x02;

pub type UsbDevice = Device<GlobalContext>;

pub fn get_device_list() -> Result<Vec<(u32, UsbDevice)>> {
    let mut icdi_devices = Vec::new();

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
        icdi_devices.push((
            u32::from_str_radix(&serial, 16).context("Failed to parse device serial number")?,
            device,
        ));
    }
    Ok(icdi_devices)
}

pub fn open_device(device: &Device<GlobalContext>) -> Result<DeviceHandle<GlobalContext>> {
    let mut dev = device.open().context("USB ICDI device open failed")?;
    dev.claim_interface(INTERFACE_NR)
        .context("Claim interface failed")?;
    Ok(dev)
}
