use std::{net::TcpStream, io::{self, Read, Write}};
use ecies::{PublicKey};
use libsecp256k1::{PublicKeyFormat, Signature};

use self::message_types::SECRETKEY;


pub const HEARTBEAT_MESSAGE:&str = "P2PEM"; //P2PEM in UTF-8.
pub const MIN_TEST_SIZE: usize = 1024;
pub const MAX_TEST_SIZE: usize = 65535;

pub mod message_types {
    pub const INTRO:u16 = 0;
    pub const PUBLICKEY:u16 = 1;
    pub const TEST:u16 = 2;
    pub const VALIDATION:u16 = 3;
    pub const CONFIRMATION:u16 = 4;
    pub const CAPPRIMER:u16 = 5;
    pub const CAPABILITY:u16 = 6;
    pub const SECRETKEY:u16 = 7;
}

pub enum MessageError {
    CorruptMessageError,
    IOError
}

pub trait WrapMessageError<T> {
    fn wrap_me(self) -> Result<T, MessageError>;
}

impl<T> WrapMessageError<T> for io::Result<T> {
    fn wrap_me(self) -> Result<T, MessageError> {
        match self {
            Ok(dat) => Ok(dat),
            Err(_) => Err(MessageError::IOError),
        }
    }
}

pub trait Messageable {
    fn get_header_id(&self) -> u16;
    fn write_out(&self, stream: &mut TcpStream) -> Result<(), MessageError>;
    fn read_into(stream: &mut TcpStream) -> Result<Self, MessageError> where Self: Sized;
}

pub fn write_all<T>(message: T, stream: &mut TcpStream) -> Result<(), MessageError> where T: Messageable{
    let header_bytes = message.get_header_id().to_be_bytes();
    stream.write(&header_bytes).wrap_me()?;
    message.write_out(stream)?;

    Ok(())
}

pub struct IntroMessage;

impl Messageable for IntroMessage {
    fn get_header_id(&self) -> u16 {
        message_types::INTRO
    }

    #[warn(unused_must_use)] //This does not do anything maybe it will in the future but Rust is still working this one out. https://github.com/rust-lang/rust/issues/55506 https://github.com/rust-lang/rust/issues/67387
    fn write_out(&self, stream:&mut TcpStream) -> Result<(), MessageError>{
        stream.write(HEARTBEAT_MESSAGE.as_bytes()).wrap_me()?;
        Ok(())
    }

    #[warn(unused_must_use)] //Same goes for here.
    fn read_into(stream: &mut TcpStream) -> Result<Self, MessageError> where Self: Sized {
        let mut p2pem_buffer = [0u8; 5];
        stream.read_exact(&mut p2pem_buffer).wrap_me()?;
        if p2pem_buffer == HEARTBEAT_MESSAGE.as_bytes() {
            Ok(IntroMessage)
        } else {
            Err(MessageError::CorruptMessageError)
        }
    }
}

pub struct KeyMessage {
    pub key: PublicKey
}

impl Messageable for KeyMessage {
    fn get_header_id(&self) -> u16 {
        message_types::PUBLICKEY
    }

    fn write_out(&self, stream:&mut TcpStream) -> Result<(), MessageError> {
        let serkey = self.key.serialize();
        let length = (serkey.len() as u16).to_be_bytes();
        stream.write(&length).wrap_me()?;
        stream.write(&serkey).wrap_me()?;
        Ok(())
    }

    fn read_into(stream: &mut TcpStream) -> Result<Self, MessageError> where Self: Sized {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).wrap_me()?;
        let length = u16::from_be_bytes(length) as usize; //a 65k key is the worst it can be come on.
        if length > 128 {
            return Err(MessageError::CorruptMessageError);
        }

        let mut serkey = vec![0u8; length];
        stream.read_exact(&mut serkey).wrap_me()?;

        let possible_pk = PublicKey::parse_slice(&serkey, Some(PublicKeyFormat::Full)); //Unknown format.
        
        match possible_pk {
            Ok(key) => {
                return Ok(
                    KeyMessage {
                        key
                    }
                )
            },
            Err(_) => Err(MessageError::CorruptMessageError),
        }
    }    
}

pub struct TestMessage {
    data: Vec<u8>,
    is_validation: Option<bool>
}

impl TestMessage { //Also includes validation messages
    pub fn new(data: Vec<u8>, is_validation: bool) -> Self {
        TestMessage { data, is_validation: Some(is_validation) }
    }

    pub fn get_test_data(&self)-> &[u8] {
        return &self.data;
    }
}

impl Messageable for TestMessage {
    fn get_header_id(&self) -> u16 {
        if let Some(is_validation) = self.is_validation {
            if is_validation {
                return message_types::VALIDATION;
            } else {
                return message_types::TEST;
            }
        }

        panic!("Validation flag not set on TestMessage. This should not be possible since you shouldn't try to resend this packet anyway!");
    }

    fn write_out(&self, stream:&mut TcpStream) -> Result<(), MessageError> {
        let length = (self.data.len() as u16).to_be_bytes();
        stream.write(&length).wrap_me()?;
        stream.write(&self.data).wrap_me()?;
        Ok(())
    }

    fn read_into(stream: &mut TcpStream) -> Result<Self, MessageError> where Self: Sized {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).wrap_me()?;
        let length = u16::from_be_bytes(length) as usize;
        if length < MIN_TEST_SIZE || length > MAX_TEST_SIZE {
            return Err(MessageError::CorruptMessageError);
        }

        let mut data = vec![0u8; length];
        stream.read_exact(&mut data).wrap_me()?;

        Ok(
            TestMessage{
                data,
                is_validation: None //We don't know if it a validation message or not here.
            }
        )
    }    
}

pub struct ConfirmationMessage;

impl Messageable for ConfirmationMessage {
    fn get_header_id(&self) -> u16 {
        message_types::CONFIRMATION
    }

    fn write_out(&self, _:&mut TcpStream) -> Result<(), MessageError> {
        Ok(())
    }

    fn read_into(_: &mut TcpStream) -> Result<Self, MessageError> where Self: Sized {
        Ok(ConfirmationMessage)
    }
}

pub struct CapabilityPrimer {
    pub no_capabilities: u16
}

impl Messageable for CapabilityPrimer {
    fn get_header_id(&self) -> u16 {
        message_types::CAPPRIMER
    }

    fn write_out(&self, stream:&mut TcpStream) -> Result<(), MessageError> {
        let number = self.no_capabilities.to_be_bytes();
        stream.write(&number).wrap_me()?;
        Ok(())
    }

    fn read_into(stream: &mut TcpStream) -> Result<Self, MessageError> where Self: Sized {
        let mut number = [0u8; 2];
        stream.read_exact(&mut number).wrap_me()?;
        let number = u16::from_be_bytes(number);

        Ok(CapabilityPrimer{
            no_capabilities: number
        })
    }
}

pub struct Capability {
    pub name: String
}

impl Messageable for Capability {
    fn get_header_id(&self) -> u16 {
        message_types::CAPABILITY
    }

    fn write_out(&self, stream:&mut TcpStream) -> Result<(), MessageError> {
        if self.name.len() > 255 {
            panic!("The capability length is over 255 bytes. Why is it so long? What on earth are you doing?");
        }

        let length = self.name.len() as u8;
        stream.write(&[length]).wrap_me()?;
        stream.write(self.name.as_bytes()).wrap_me()?;
        Ok(())
    }

    fn read_into(stream: &mut TcpStream) -> Result<Self, MessageError> where Self: Sized {
        let mut length = [0u8];
        stream.read_exact(&mut length).wrap_me()?;
        let mut possible_name = vec![0u8; length[0] as usize];
        stream.read_exact(&mut possible_name).wrap_me()?;
        let possible_name = String::from_utf8(possible_name);

        match possible_name {
            Ok(name) => {
                return Ok(Capability {
                    name
                });
            },
            Err(_) => Err(MessageError::CorruptMessageError),
        }
    }
}

pub struct SecretKeyMessage { //Only the Key and IV are encrypted.
    pub keyiv: Vec<u8>, //Key and IV.
    pub signature: Signature,
}

impl Messageable for SecretKeyMessage {
    fn get_header_id(&self) -> u16 {
        SECRETKEY
    }

    fn write_out(&self, stream: &mut TcpStream) -> Result<(), MessageError> {

        stream.write(&(self.keyiv.len() as u16).to_be_bytes()).wrap_me()?; //Send length
        stream.write(&self.keyiv).wrap_me()?; //Send Key and Iv
        
        let signature_bytes = self.signature.serialize();
        stream.write(&(signature_bytes.len() as u16).to_be_bytes()).wrap_me()?;
        stream.write(&signature_bytes).wrap_me()?;
        
        Ok(())
    }

    fn read_into(stream: &mut TcpStream) -> Result<Self, MessageError> where Self: Sized {
        let mut keyiv_len = [0u8; 2];
        stream.read_exact(&mut keyiv_len).wrap_me()?;
        let keyiv_len = u16::from_be_bytes(keyiv_len) as usize;
        let mut keyiv = vec![0u8; keyiv_len];
        stream.read_exact(&mut keyiv).wrap_me()?;

        let mut sig_len = [0u8; 2];
        stream.read_exact(&mut sig_len).wrap_me()?;
        let sig_len = u16::from_be_bytes(sig_len) as usize;
        let mut sig = vec![0u8; sig_len];
        stream.read_exact(&mut sig).wrap_me()?;
        let sig = Signature::parse_standard_slice(&sig);

        match sig {
            Ok(signature) => Ok(Self {
                keyiv,
                signature
            }),
            Err(_) => Err(MessageError::CorruptMessageError),
        }
    }
}
