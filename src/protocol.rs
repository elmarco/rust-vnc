use crate::{Error, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{ErrorKind as IoErrorKind, Read, Write};

pub trait Message {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
    where
        Self: Sized;
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()>;
}

impl Message for Vec<u8> {
    fn read_from<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
        let length = reader.read_u32::<BigEndian>()?;
        let mut buffer = vec![0; length as usize];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let length = self.len() as u32; // TODO: check?
        writer.write_u32::<BigEndian>(length)?;
        writer.write_all(&self)?;
        Ok(())
    }
}

/* All strings in VNC are either ASCII or Latin-1, both of which
are embedded in Unicode. */
impl Message for String {
    fn read_from<R: Read>(reader: &mut R) -> Result<String> {
        let length = reader.read_u32::<BigEndian>()?;
        let mut string = vec![0; length as usize];
        reader.read_exact(&mut string)?;
        Ok(string.iter().map(|c| *c as char).collect())
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let length = self.len() as u32; // TODO: check?
        writer.write_u32::<BigEndian>(length)?;
        writer.write_all(&self.chars().map(|c| c as u8).collect::<Vec<u8>>())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Rfb33,
    Rfb37,
    Rfb38,
}

impl Message for Version {
    fn read_from<R: Read>(reader: &mut R) -> Result<Version> {
        let mut buf = [0; 12];
        reader.read_exact(&mut buf)?;
        match &buf {
            b"RFB 003.003\n" => Ok(Version::Rfb33),
            b"RFB 003.007\n" => Ok(Version::Rfb37),
            b"RFB 003.008\n" => Ok(Version::Rfb38),
            // Apple remote desktop
            b"RFB 003.889\n" => Ok(Version::Rfb38),
            _ => Err(Error::Unexpected("protocol version")),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Version::Rfb33 => writer.write_all(b"RFB 003.003\n"),
            Version::Rfb37 => writer.write_all(b"RFB 003.007\n"),
            Version::Rfb38 => writer.write_all(b"RFB 003.008\n"),
        }?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityType {
    Unknown(u8),
    // core spec
    Invalid,
    None,
    VncAuthentication,
    // extensions
    AppleRemoteDesktop,
}

impl Message for SecurityType {
    fn read_from<R: Read>(reader: &mut R) -> Result<SecurityType> {
        let security_type = reader.read_u8()?;
        match security_type {
            0 => Ok(SecurityType::Invalid),
            1 => Ok(SecurityType::None),
            2 => Ok(SecurityType::VncAuthentication),
            30 => Ok(SecurityType::AppleRemoteDesktop),
            n => Ok(SecurityType::Unknown(n)),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let security_type = match self {
            SecurityType::Invalid => 0,
            SecurityType::None => 1,
            SecurityType::VncAuthentication => 2,
            SecurityType::AppleRemoteDesktop => 30,
            SecurityType::Unknown(n) => *n,
        };
        writer.write_u8(security_type)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SecurityTypes(pub Vec<SecurityType>);

impl Message for SecurityTypes {
    fn read_from<R: Read>(reader: &mut R) -> Result<SecurityTypes> {
        let count = reader.read_u8()?;
        let mut security_types = Vec::new();
        for _ in 0..count {
            security_types.push(SecurityType::read_from(reader)?)
        }
        Ok(SecurityTypes(security_types))
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let count = self.0.len() as u8; // TODO: check?
        writer.write_u8(count)?;
        for security_type in &self.0 {
            security_type.write_to(writer)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityResult {
    Succeeded,
    Failed,
}

impl Message for SecurityResult {
    fn read_from<R: Read>(reader: &mut R) -> Result<SecurityResult> {
        let result = reader.read_u32::<BigEndian>()?;
        match result {
            0 => Ok(SecurityResult::Succeeded),
            1 => Ok(SecurityResult::Failed),
            _ => Err(Error::Unexpected("security result")),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let result = match self {
            SecurityResult::Succeeded => 0,
            SecurityResult::Failed => 1,
        };
        writer.write_u32::<BigEndian>(result)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct AppleAuthHandshake {
    pub generator: u16,
    pub prime: Vec<u8>,
    pub peer_key: Vec<u8>,
}

impl Message for AppleAuthHandshake {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let generator = reader.read_u16::<BigEndian>()?;
        let key_length = reader.read_u16::<BigEndian>()?;

        let mut prime = vec![0; key_length as usize];
        reader.read_exact(&mut prime)?;

        let mut peer_key = vec![0; key_length as usize];
        reader.read_exact(&mut peer_key)?;

        Ok(AppleAuthHandshake {
            generator,
            prime,
            peer_key,
        })
    }

    fn write_to<W: Write>(&self, _writer: &mut W) -> Result<()> {
        unreachable!()
    }
}

#[allow(dead_code)]
pub struct AppleAuthResponse {
    pub ciphertext: [u8; 128],
    pub pub_key: Vec<u8>,
}

impl Message for AppleAuthResponse {
    fn read_from<R: Read>(_reader: &mut R) -> Result<Self> {
        unreachable!()
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.ciphertext)?;
        writer.write_all(&self.pub_key)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ClientInit {
    pub shared: bool,
}

impl Message for ClientInit {
    fn read_from<R: Read>(reader: &mut R) -> Result<ClientInit> {
        Ok(ClientInit {
            shared: reader.read_u8()? != 0,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(if self.shared { 1 } else { 0 })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl Message for PixelFormat {
    fn read_from<R: Read>(reader: &mut R) -> Result<PixelFormat> {
        let pixel_format = PixelFormat {
            bits_per_pixel: reader.read_u8()?,
            depth: reader.read_u8()?,
            big_endian: reader.read_u8()? != 0,
            true_colour: reader.read_u8()? != 0,
            red_max: reader.read_u16::<BigEndian>()?,
            green_max: reader.read_u16::<BigEndian>()?,
            blue_max: reader.read_u16::<BigEndian>()?,
            red_shift: reader.read_u8()?,
            green_shift: reader.read_u8()?,
            blue_shift: reader.read_u8()?,
        };
        reader.read_exact(&mut [0u8; 3])?;
        Ok(pixel_format)
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.bits_per_pixel)?;
        writer.write_u8(self.depth)?;
        writer.write_u8(if self.big_endian { 1 } else { 0 })?;
        writer.write_u8(if self.true_colour { 1 } else { 0 })?;
        writer.write_u16::<BigEndian>(self.red_max)?;
        writer.write_u16::<BigEndian>(self.green_max)?;
        writer.write_u16::<BigEndian>(self.blue_max)?;
        writer.write_u8(self.red_shift)?;
        writer.write_u8(self.green_shift)?;
        writer.write_u8(self.blue_shift)?;
        writer.write_all(&[0u8; 3])?;
        Ok(())
    }
}

impl PixelFormat {
    /// Creates RGB pixel format with 4 bytes per pixel and 3 bytes of depth.
    pub fn rgb8888() -> Self {
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: true,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
        }
    }
}

#[derive(Debug)]
pub struct ServerInit {
    pub framebuffer_width: u16,
    pub framebuffer_height: u16,
    pub pixel_format: PixelFormat,
    pub name: String,
}

impl Message for ServerInit {
    fn read_from<R: Read>(reader: &mut R) -> Result<ServerInit> {
        Ok(ServerInit {
            framebuffer_width: reader.read_u16::<BigEndian>()?,
            framebuffer_height: reader.read_u16::<BigEndian>()?,
            pixel_format: PixelFormat::read_from(reader)?,
            name: String::read_from(reader)?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.framebuffer_width)?;
        writer.write_u16::<BigEndian>(self.framebuffer_height)?;
        PixelFormat::write_to(&self.pixel_format, writer)?;
        String::write_to(&self.name, writer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CopyRect {
    pub src_x_position: u16,
    pub src_y_position: u16,
}

impl Message for CopyRect {
    fn read_from<R: Read>(reader: &mut R) -> Result<CopyRect> {
        Ok(CopyRect {
            src_x_position: reader.read_u16::<BigEndian>()?,
            src_y_position: reader.read_u16::<BigEndian>()?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.src_x_position)?;
        writer.write_u16::<BigEndian>(self.src_y_position)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Unknown(i32),
    // core spec
    Raw,
    CopyRect,
    Rre,
    CoRre,
    Hextile,
    Zlib,
    Tight,
    ZlibHex,
    Zrle,
    Jpeg(i32),
    DesktopSize,
    LastRect,
    PointerPosition,
    RichCursor,
    XCursor,
    CompressionLevel(i32),
    PointerMotion,
    ExtendedKeyEvent,
    Audio,
    TightPng,
    Led,
    Gii,
    DesktopName,
    ExtendedDesktopSize,
    Xvp,
    Fence,
    ContinuousUpdate,
    CursorWithAlpha,
    JpegFineGrained(i32),
    JpegSubSampling(i32),
    VmwareCursor,
    VmwareCursorState,
    VmwareCursorPosition,
    VmwareKeyRepeat,
    VmwareLed,
    VmwareDisplayMode,
    VmwareVMState,
    ExtendedClipboard,
}

impl Message for Encoding {
    fn read_from<R: Read>(reader: &mut R) -> Result<Encoding> {
        let encoding = reader.read_i32::<BigEndian>()?;
        match encoding {
            0 => Ok(Encoding::Raw),
            1 => Ok(Encoding::CopyRect),
            2 => Ok(Encoding::Rre),
            4 => Ok(Encoding::CoRre),
            5 => Ok(Encoding::Hextile),
            6 => Ok(Encoding::Zlib),
            7 => Ok(Encoding::Tight),
            8 => Ok(Encoding::ZlibHex),
            16 => Ok(Encoding::Zrle),
            -32..=-23 => Ok(Encoding::Jpeg(encoding)),
            -223 => Ok(Encoding::DesktopSize),
            -224 => Ok(Encoding::LastRect),
            -232 => Ok(Encoding::PointerPosition),
            -239 => Ok(Encoding::RichCursor),
            -240 => Ok(Encoding::XCursor),
            -256..=-247 => Ok(Encoding::CompressionLevel(encoding)),
            -257 => Ok(Encoding::PointerMotion),
            -258 => Ok(Encoding::ExtendedKeyEvent),
            -259 => Ok(Encoding::Audio),
            -260 => Ok(Encoding::TightPng),
            -261 => Ok(Encoding::Led),
            -305 => Ok(Encoding::Gii),
            -307 => Ok(Encoding::DesktopName),
            -308 => Ok(Encoding::ExtendedDesktopSize),
            -309 => Ok(Encoding::Xvp),
            -312 => Ok(Encoding::Fence),
            -313 => Ok(Encoding::ContinuousUpdate),
            -314 => Ok(Encoding::CursorWithAlpha),
            -512..=-412 => Ok(Encoding::JpegFineGrained(encoding)),
            -768..=-763 => Ok(Encoding::JpegSubSampling(encoding)),
            0x574d5664 => Ok(Encoding::VmwareCursor),
            0x574d5665 => Ok(Encoding::VmwareCursorState),
            0x574d5666 => Ok(Encoding::VmwareCursorPosition),
            0x574d5667 => Ok(Encoding::VmwareKeyRepeat),
            0x574d5668 => Ok(Encoding::VmwareLed),
            0x574d5669 => Ok(Encoding::VmwareDisplayMode),
            0x574d566a => Ok(Encoding::VmwareVMState),
            -1063131698 => Ok(Encoding::ExtendedClipboard), // 0xc0a1e5ce
            n => Ok(Encoding::Unknown(n)),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let encoding = match self {
            Encoding::Raw => 0,
            Encoding::CopyRect => 1,
            Encoding::Rre => 2,
            Encoding::CoRre => 4,
            Encoding::Hextile => 5,
            Encoding::Zlib => 6,
            Encoding::Tight => 7,
            Encoding::ZlibHex => 8,
            Encoding::Zrle => 16,
            Encoding::Jpeg(n) => *n,
            Encoding::DesktopSize => -223,
            Encoding::LastRect => -224,
            Encoding::PointerPosition => -232,
            Encoding::RichCursor => -239,
            Encoding::PointerMotion => -257,
            Encoding::ExtendedKeyEvent => -258,
            Encoding::Audio => -259,
            Encoding::TightPng => -260,
            Encoding::Led => -261,
            Encoding::XCursor => -240,
            Encoding::CompressionLevel(n) => *n,
            Encoding::Gii => -305,
            Encoding::DesktopName => -307,
            Encoding::ExtendedDesktopSize => -308,
            Encoding::Xvp => -309,
            Encoding::Fence => -312,
            Encoding::ContinuousUpdate => -313,
            Encoding::CursorWithAlpha => -314,
            Encoding::JpegFineGrained(n) => *n,
            Encoding::JpegSubSampling(n) => *n,
            Encoding::VmwareCursor => 0x574d5664,
            Encoding::VmwareCursorState => 0x574d5665,
            Encoding::VmwareCursorPosition => 0x574d5666,
            Encoding::VmwareKeyRepeat => 0x574d5667,
            Encoding::VmwareLed => 0x574d5668,
            Encoding::VmwareDisplayMode => 0x574d5669,
            Encoding::VmwareVMState => 0x574d566a,
            Encoding::ExtendedClipboard => -1063131698, // 0xc0a1e5ce
            Encoding::Unknown(n) => *n,
        };
        writer.write_i32::<BigEndian>(encoding)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum C2S {
    // core spec
    SetPixelFormat(PixelFormat),
    SetEncodings(Vec<Encoding>),
    FramebufferUpdateRequest {
        incremental: bool,
        x_position: u16,
        y_position: u16,
        width: u16,
        height: u16,
    },
    KeyEvent {
        down: bool,
        key: u32,
    },
    PointerEvent {
        button_mask: u8,
        x_position: u16,
        y_position: u16,
    },
    CutText(String),
    // extensions
    ExtendedKeyEvent {
        down: bool,
        keysym: u32,
        keycode: u32,
    },
}

impl Message for C2S {
    fn read_from<R: Read>(reader: &mut R) -> Result<C2S> {
        let message_type = match reader.read_u8() {
            Err(ref e) if e.kind() == IoErrorKind::UnexpectedEof => {
                return Err(Error::Disconnected)
            }
            result => result?,
        };
        match message_type {
            0 => {
                reader.read_exact(&mut [0u8; 3])?;
                Ok(C2S::SetPixelFormat(PixelFormat::read_from(reader)?))
            }
            2 => {
                reader.read_exact(&mut [0u8; 1])?;
                let count = reader.read_u16::<BigEndian>()?;
                let mut encodings = Vec::new();
                for _ in 0..count {
                    encodings.push(Encoding::read_from(reader)?);
                }
                Ok(C2S::SetEncodings(encodings))
            }
            3 => Ok(C2S::FramebufferUpdateRequest {
                incremental: reader.read_u8()? != 0,
                x_position: reader.read_u16::<BigEndian>()?,
                y_position: reader.read_u16::<BigEndian>()?,
                width: reader.read_u16::<BigEndian>()?,
                height: reader.read_u16::<BigEndian>()?,
            }),
            4 => {
                let down = reader.read_u8()? != 0;
                reader.read_exact(&mut [0u8; 2])?;
                let key = reader.read_u32::<BigEndian>()?;
                Ok(C2S::KeyEvent { down, key })
            }
            5 => Ok(C2S::PointerEvent {
                button_mask: reader.read_u8()?,
                x_position: reader.read_u16::<BigEndian>()?,
                y_position: reader.read_u16::<BigEndian>()?,
            }),
            6 => {
                reader.read_exact(&mut [0u8; 3])?;
                Ok(C2S::CutText(String::read_from(reader)?))
            }
            255 => {
                let submessage_type = reader.read_u8()?;
                match submessage_type {
                    0 => {
                        let down = reader.read_u16::<BigEndian>()? != 0;
                        let keysym = reader.read_u32::<BigEndian>()?;
                        let keycode = reader.read_u32::<BigEndian>()?;
                        Ok(C2S::ExtendedKeyEvent {
                            down,
                            keysym,
                            keycode,
                        })
                    }
                    _ => Err(Error::Unexpected("client to server QEMU submessage type")),
                }
            }
            _ => Err(Error::Unexpected("client to server message type")),
        }
    }
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            C2S::SetPixelFormat(ref pixel_format) => {
                writer.write_u8(0)?;
                writer.write_all(&[0u8; 3])?;
                PixelFormat::write_to(pixel_format, writer)?;
            }
            C2S::SetEncodings(ref encodings) => {
                writer.write_u8(2)?;
                writer.write_all(&[0u8; 1])?;
                writer.write_u16::<BigEndian>(encodings.len() as u16)?; // TODO: check?
                for encoding in encodings {
                    Encoding::write_to(encoding, writer)?;
                }
            }
            C2S::FramebufferUpdateRequest {
                incremental,
                x_position,
                y_position,
                width,
                height,
            } => {
                writer.write_u8(3)?;
                writer.write_u8(if *incremental { 1 } else { 0 })?;
                writer.write_u16::<BigEndian>(*x_position)?;
                writer.write_u16::<BigEndian>(*y_position)?;
                writer.write_u16::<BigEndian>(*width)?;
                writer.write_u16::<BigEndian>(*height)?;
            }
            C2S::KeyEvent { down, key } => {
                writer.write_u8(4)?;
                writer.write_u8(if *down { 1 } else { 0 })?;
                writer.write_all(&[0u8; 2])?;
                writer.write_u32::<BigEndian>(*key)?;
            }
            C2S::PointerEvent {
                button_mask,
                x_position,
                y_position,
            } => {
                writer.write_u8(5)?;
                writer.write_u8(*button_mask)?;
                writer.write_u16::<BigEndian>(*x_position)?;
                writer.write_u16::<BigEndian>(*y_position)?;
            }
            C2S::CutText(ref text) => {
                String::write_to(text, writer)?;
            }
            C2S::ExtendedKeyEvent {
                down,
                keysym,
                keycode,
            } => {
                writer.write_u8(255)?;
                writer.write_u8(0)?;
                writer.write_u16::<BigEndian>(if *down { 1 } else { 0 })?;
                writer.write_u32::<BigEndian>(*keysym)?;
                writer.write_u32::<BigEndian>(*keycode)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Rectangle {
    pub x_position: u16,
    pub y_position: u16,
    pub width: u16,
    pub height: u16,
    pub encoding: Encoding,
}

impl Message for Rectangle {
    fn read_from<R: Read>(reader: &mut R) -> Result<Rectangle> {
        Ok(Rectangle {
            x_position: reader.read_u16::<BigEndian>()?,
            y_position: reader.read_u16::<BigEndian>()?,
            width: reader.read_u16::<BigEndian>()?,
            height: reader.read_u16::<BigEndian>()?,
            encoding: Encoding::read_from(reader)?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.x_position)?;
        writer.write_u16::<BigEndian>(self.y_position)?;
        writer.write_u16::<BigEndian>(self.width)?;
        writer.write_u16::<BigEndian>(self.height)?;
        Encoding::write_to(&self.encoding, writer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Colour {
    pub red: u16,
    pub green: u16,
    pub blue: u16,
}

impl Message for Colour {
    fn read_from<R: Read>(reader: &mut R) -> Result<Colour> {
        Ok(Colour {
            red: reader.read_u16::<BigEndian>()?,
            green: reader.read_u16::<BigEndian>()?,
            blue: reader.read_u16::<BigEndian>()?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.red)?;
        writer.write_u16::<BigEndian>(self.green)?;
        writer.write_u16::<BigEndian>(self.blue)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum S2C {
    // core spec
    FramebufferUpdate {
        count: u16,
        /* Vec<Rectangle> has to be read out manually */
    },
    SetColourMapEntries {
        first_colour: u16,
        colours: Vec<Colour>,
    },
    Bell,
    CutText(String),
    // extensions
}

impl Message for S2C {
    fn read_from<R: Read>(reader: &mut R) -> Result<S2C> {
        let message_type = match reader.read_u8() {
            Err(ref e) if e.kind() == IoErrorKind::UnexpectedEof => {
                return Err(Error::Disconnected)
            }
            result => result?,
        };
        match message_type {
            0 => {
                reader.read_exact(&mut [0u8; 1])?;
                Ok(S2C::FramebufferUpdate {
                    count: reader.read_u16::<BigEndian>()?,
                })
            }
            1 => {
                reader.read_exact(&mut [0u8; 1])?;
                let first_colour = reader.read_u16::<BigEndian>()?;
                let count = reader.read_u16::<BigEndian>()?;
                let mut colours = Vec::new();
                for _ in 0..count {
                    colours.push(Colour::read_from(reader)?);
                }
                Ok(S2C::SetColourMapEntries {
                    first_colour,
                    colours,
                })
            }
            2 => Ok(S2C::Bell),
            3 => {
                reader.read_exact(&mut [0u8; 3])?;
                Ok(S2C::CutText(String::read_from(reader)?))
            }
            _ => Err(Error::Unexpected("server to client message type")),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            S2C::FramebufferUpdate { count } => {
                writer.write_u8(0)?;
                writer.write_all(&[0u8; 1])?;
                writer.write_u16::<BigEndian>(*count)?;
            }
            S2C::SetColourMapEntries {
                first_colour,
                ref colours,
            } => {
                writer.write_u8(1)?;
                writer.write_all(&[0u8; 1])?;
                writer.write_u16::<BigEndian>(*first_colour)?;
                for colour in colours {
                    Colour::write_to(colour, writer)?;
                }
            }
            S2C::Bell => {
                writer.write_u8(2)?;
            }
            S2C::CutText(ref text) => {
                writer.write_u8(3)?;
                writer.write_all(&[0u8; 3])?;
                String::write_to(text, writer)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Rect {
    pub left: u16,
    pub top: u16,
    pub width: u16,
    pub height: u16,
}

impl Rect {
    /// Constructs new `Rect`.
    pub fn new(left: u16, top: u16, width: u16, height: u16) -> Self {
        Self {
            left,
            top,
            width,
            height,
        }
    }

    /// Constructs new zero-sized `Rect` placed at (0, 0).
    pub fn empty() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

impl Message for Rect {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            left: reader.read_u16::<BigEndian>()?,
            top: reader.read_u16::<BigEndian>()?,
            width: reader.read_u16::<BigEndian>()?,
            height: reader.read_u16::<BigEndian>()?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.left)?;
        writer.write_u16::<BigEndian>(self.top)?;
        writer.write_u16::<BigEndian>(self.width)?;
        writer.write_u16::<BigEndian>(self.height)?;
        Ok(())
    }
}
