mod approval;
mod capture;
mod capture_protocol;
mod cursor;
#[cfg(feature = "development")]
mod development;
mod installation;
mod pipe;
mod security;
mod service;
mod win;
use win::*;

fn service_name() -> Result<String> {
    Ok(installation::Installation::current()?.name)
}
fn pipe_name() -> Result<String> {
    Ok(installation::Installation::current()?.pipe())
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        #[cfg(feature = "development")]
        Some("--check-client") if args.len() == 2 => {
            approval::Approval::for_client(args[1].parse::<u32>().map_err(|_| error())?)?;
            println!("ready");
            Ok(())
        }
        Some("--service") => service::run(),
        Some("--worker") if args.len() == 2 => service::worker(&args[1]),
        Some("--install") if args.len() == 2 => {
            let pid = args[1].parse::<u32>().map_err(|_| error())?;
            approval::install(pid)
        }
        Some("--uninstall") => approval::remove(),
        Some("--elevate-install") if args.len() == 2 => {
            let pid = args[1].parse::<u32>().map_err(|_| error())?;
            let (_approval, _main) = approval::Approval::for_client(pid)?;
            service::elevate(&format!("--install {pid}"))
        }
        Some("--elevate-uninstall") => service::elevate("--uninstall"),
        Some("--status") => {
            println!(
                "{}",
                if service::installed_pid().is_ok() {
                    if installation::Installation::current()?
                        .payload_is_current(&std::env::current_exe()?)?
                    {
                        "ready"
                    } else {
                        "updateRequired"
                    }
                } else {
                    "missing"
                }
            );
            Ok(())
        }
        _ => denied(),
    }
}
fn main() {
    if run().is_err() {
        println!("error");
        std::process::exit(1);
    }
}
