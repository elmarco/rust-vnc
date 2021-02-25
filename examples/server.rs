use std::error::Error;
use std::net::TcpListener;
use std::{thread, time};

use vnc::{server::*, PixelFormat, Rect, Server};

fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:5999").unwrap();
    for stream in listener.incoming() {
        let (mut server, _share) = Server::from_tcp_stream(
            stream?,
            640,
            480,
            PixelFormat::rgb8888(),
            "rust-vnc example".into(),
        )?;
        let mut last_update: Option<time::Instant> = None;
        loop {
            match server.read_event()? {
                Event::FramebufferUpdateRequest { .. } => {
                    if let Some(last_update) = last_update {
                        if last_update.elapsed().as_millis() < 100 {
                            continue;
                        }
                    }
                    last_update = Some(time::Instant::now());
                    let mut fbu = FramebufferUpdate::new(&PixelFormat::rgb8888());
                    let pixel_data = vec![128; 8 * 8 * 4];
                    let rect = Rect {
                        left: 0,
                        top: 0,
                        width: 8,
                        height: 8,
                    };
                    fbu.add_raw_pixels(rect, &pixel_data);
                    server.send(&fbu)?;
                }
                event => {
                    dbg!(event);
                }
            }
        }
    }
    Ok(())
}
