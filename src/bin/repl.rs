use anyhow::{bail, Context, Result};
use hex::FromHex;
use lm4flash::icdi_cmd::read_icdi_version;
use lm4flash::usb::{get_device_list, open_device, UsbDevice};
use lm4flash::IcdiDevice;
use rusb::{DeviceHandle, GlobalContext};
use rustyline::Editor;

use std::io::Write;
use std::str::FromStr;

fn handle_line(ps: &mut ProgState, line: String) -> Result<()> {
    if line == "quit" {
        bail!("Quitting")
    }
    let mut split = line.splitn(2, ' ');
    let cmd = split.next();
    let args = split.next().map(str::trim);

    if cmd.is_none() {
        return Ok(());
    }
    match cmd.unwrap() {
        "hello" => {
            println!("Hello you")
        }
        "connect" => {
            connect_to_device(ps, args)?;
        }
        "disconnect" => {
            if let Some(dev) = ps.dev.take() {
                std::mem::drop(dev);
                println!("Disconnected from ICDI device.")
            }
        }
        "dbgclock" => {
            let clk = args
                .map(|s| u8::from_str(s).context("clk arg not int"))
                .context("Missing int arg in range [0-4]")??;
            let mut cmd = Vec::from(&b"debug clock "[..]);
            write!(cmd, "{:02x}", clk).unwrap();
            let buf = ps.get_dev()?.send_remote_command(&cmd)?;
            println!("-> {}", buf.payload_str()?);
        }
        "list_devices" => {
            let devs = get_device_list()?;
            println!("Found the following ICDI devices");
            devs.iter()
                .enumerate()
                .for_each(|(idx, (serial, _dev))| println!("  [{}] S/N: {:08x}", idx, serial));
            ps.dev_list = Some(devs);
        }
        "icdi_ver" => {
            println!(
                "ICDI interface version: {}",
                read_icdi_version(ps.dev.as_mut().context("Not connected")?)?
            )
        }

        "cmd" => {
            let dev = ps.get_dev()?;
            let buf = dev.send_string(args.context("Missing arg")?.as_bytes())?;
            if buf.check_cmd_result().is_err() {
                println!("cmd returned error {:?}", &buf)
            }
            println!("-> {}", buf.payload_str()?);
        }
        "rcmd" => {
            let args = args.context("rcmd need command")?;
            let mut dev = ps.get_dev()?;
            let ret = dev.send_remote_command(args.as_bytes())?;
            ret.check_cmd_result()?;
            let payload = ret.get_payload()?;
            if let Ok(hex_decode) = Vec::<u8>::from_hex(payload) {
                if let Ok(str) = std::str::from_utf8(&hex_decode) {
                    println!("-> {}", str);
                } else {
                    println!("-> {:?})", hex_decode);
                }
            } else if let Ok(str) = std::str::from_utf8(payload) {
                println!("-> {}", str);
            } else {
                println!("-> {:?}", payload);
            }
        }
        cmd => println!("Unknown command: {}", cmd),
    }

    ps.rl.add_history_entry(line);
    Ok(())
}

fn connect_to_device(ps: &mut ProgState, args: Option<&str>) -> Result<()> {
    let dev_idx = args
        .context("Bad conn idx")
        .map(usize::from_str)
        .context("Bad idx")??;
    if ps.dev_list.is_none() {
        ps.dev_list = get_device_list()?.into();
    }
    let dl = ps.dev_list.as_deref_mut().unwrap();
    let dev = &dl.get(dev_idx).context("Bad dev idx")?.1;
    let dev = open_device(dev)?;
    ps.dev = Some(dev);
    println!("Connected to {:08x}", dl[dev_idx].0);
    Ok(())
}

struct ProgState {
    rl: Editor<()>,
    dev: Option<DeviceHandle<GlobalContext>>,
    dev_list: Option<Vec<(u32, UsbDevice)>>,
}

impl ProgState {
    fn get_dev(&mut self) -> Result<&mut DeviceHandle<GlobalContext>> {
        self.dev.as_mut().context("Not connected")
    }
}

fn main() -> Result<()> {
    let mut ps = ProgState {
        rl: rustyline::Editor::<()>::new(),
        dev: None,
        dev_list: None,
    };
    loop {
        match ps.rl.readline(">> ") {
            Ok(line) => {
                let _ = handle_line(&mut ps, line).map_err(|e| println!("Error: {:#?}", e));
            }
            Err(e) => {
                println!("Readline error {:?}", e);
                break;
            }
        }
    }
    Ok(())
}
