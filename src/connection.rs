use std::{net::TcpStream, io::{Read, self, Write}, cmp::min};
use ecies::{utils::generate_keypair, SecretKey, PublicKey, encrypt, decrypt};
use openssl::{sha::{sha256}, symm::{Cipher, Crypter}, error::ErrorStack};
use rand::{RngCore, prelude::ThreadRng, Rng};
use libsecp256k1::{sign, verify};
use crate::{message::{Messageable, IntroMessage, message_types, KeyMessage, TestMessage, ConfirmationMessage, MessageError, CapabilityPrimer, Capability, SecretKeyMessage, MessageRequest, WrapMessageError, MessageResponse, MessageChunk}};
type KeyPair = (SecretKey, PublicKey);

//Encryption Capabilities. At the moment I am only supporting one algorithm for each task.
const PKCRYPT_ALGO: &str = "secp256k1";
const SKCRYPT_ALGO: &str = "aes-256-ctr"; 
const HASHING_ALGO: &str = "sha256";

//Messaging Capabilities. 
const SUPPORTED_MSG: [&str; 1] = ["text"];
const MAX_CHUNK_SIZE:usize = 65535;
pub struct Connection {
    conn: TcpStream,
    encrypter: Crypter,
    decrypter: Crypter,
    msg_capabilities: Vec<String>
}

#[derive(Debug)]
pub enum NegotiationError{
    IOError,
    WrongMessageType,
    CorruptMessage,
    CryptoError,
    FailedTest,
    IncompatibleCapabilities,
}

#[derive(Debug)]
pub enum SessionMsgError {
    NotCapable, //We don't have the capability.
    Rejected, //Other side rejected the msg.
    IOError,
    CorruptMessageError,
}

impl Connection {
    pub fn negotiate(conn: TcpStream, incoming: bool) -> Result<Self, NegotiationError>{
        let kp = generate_keypair();

        if incoming {
            Self::negotiate_bob(conn, kp)
        } else {
            Self::negotiate_alice(conn, kp)
        }
    }

    fn negotiate_bob(mut conn: TcpStream, kp: KeyPair) -> Result<Self, NegotiationError>{
        let mut rng = rand::thread_rng();

        IntroMessage{}.write_all(&mut conn).wrap_neg()?; //Send intro message first

        read_header_expect_type(&mut conn, message_types::INTRO).wrap_neg()?; //Read intro header
        IntroMessage::read_into(&mut conn).wrap_neg()?;

        send_capabilities(&mut conn, get_capabilities())?;

        let chosen_capabilities = read_capabilities(&mut conn)?;
        let msgc = get_msg_capabilities(chosen_capabilities)?;

        let alice_pk = read_public_key(&mut conn)?;
    
        send_public_key(&mut conn, kp.1)?;

        complete_test(&mut conn, kp.0)?;

        perform_test(&mut conn, &mut rng, alice_pk)?;

        let (aes_key, iv) = read_aes_key(&mut conn, &kp.0, &alice_pk)?;

        let (encrypter, decrypter) = create_crypters(&aes_key, &iv)?;

        ConfirmationMessage.write_all(&mut conn).wrap_neg()?; //Send confirmation back.

        
        Ok(Self{
            conn,
            encrypter,
            decrypter,
            msg_capabilities: msgc
        })
    }

    fn negotiate_alice(mut conn: TcpStream, kp: KeyPair) -> Result<Self, NegotiationError> {
        let mut rng = rand::thread_rng();

        read_header_expect_type(&mut conn, message_types::INTRO).wrap_neg()?; //Read intro header
        IntroMessage::read_into(&mut conn).wrap_neg()?;

        IntroMessage{}.write_all(&mut conn).wrap_neg()?; //Send intro back

        let bob_capabilities = read_capabilities(&mut conn)?;
        let msg_caps = get_msg_capabilities(bob_capabilities)?;

        let mut using_capabilities = msg_caps.clone();
        using_capabilities.push(String::from(PKCRYPT_ALGO));
        using_capabilities.push(String::from(SKCRYPT_ALGO));
        using_capabilities.push(String::from(HASHING_ALGO));

        send_capabilities(&mut conn, using_capabilities)?; //Send capabilities back to bob.

        send_public_key(&mut conn, kp.1)?;

        let bob_pk = read_public_key(&mut conn)?;

        perform_test(&mut conn, &mut rng, bob_pk)?;

        complete_test(&mut conn, kp.0)?;

        let aes_key:[u8; 32] = rng.gen();
        let iv:[u8; 16] = rng.gen();

        send_aes_key(&mut conn, &bob_pk, &kp.0, &aes_key, &iv)?;
        
        let (encrypter, decrypter) = create_crypters(&aes_key, &iv)?;

        read_header_expect_type(&mut conn, message_types::CONFIRMATION).wrap_neg()?; //Expect confirmation.
        ConfirmationMessage::read_into(&mut conn).wrap_neg()?; //Read anyway even though this does nothing.

        Ok(Self{
            conn,
            encrypter,
            decrypter,
            msg_capabilities: msg_caps
        })
    }

    pub fn has_msg_capability(&self, capability: &str) -> bool {
        for cap in &self.msg_capabilities {
            if *cap == *capability {
                return true;
            }
        }

        false
    }

    pub fn send_message(&mut self, capability: &str, data: &[u8]) -> Result<(), SessionMsgError> {
        let req = MessageRequest{
            typ: String::from(capability),
            length: data.len() as u64
        };

        req.write_all(self).wrap_sme()?;
        
        read_header_expect_type(self, message_types::MSGRES).wrap_sme()?;
        let res = MessageResponse::read_into(self).wrap_sme()?;
        if !res.ok() { //Message was rejected.
            return Err(SessionMsgError::Rejected);
        }

        let mut rem_dat = &data[..]; //Create a slice of the remaining data to send with a mutable index so that I can reduce the size of it.
        
        while rem_dat.len() > 0 {
            let write_amount: usize = min(rem_dat.len(), MAX_CHUNK_SIZE); //Amount to write, capped at the CHUNK size.

            let mut chunk_recieved = false;
            while !chunk_recieved {
                let chunk_msg = MessageChunk{
                    data: Some(rem_dat[..write_amount].to_vec())
                };

                chunk_msg.write_all(self).wrap_sme()?; //Send the chunk

                read_header_expect_type(self, message_types::MSGACK).wrap_sme()?; //Wait for acknowledgement
                let ack = MessageResponse::read_into(self).wrap_sme()?;

                chunk_recieved = ack.ok();
            }

            rem_dat = &rem_dat[write_amount..];
        }

        Ok(())
    }

    pub fn read_next_msg_request(&mut self) -> Result<MessageRequest, SessionMsgError>{
        read_header_expect_type(self, message_types::MSGREQ).wrap_sme()?; //Wait for request header
        MessageRequest::read_into(self).wrap_sme() //Return message request
    }

    pub fn reply_to_request(&mut self, accept: bool) -> Result<(), SessionMsgError> {
        MessageResponse::new(accept, false).write_all(self).wrap_sme()
    }

    pub fn read_payload(&mut self, data: &mut [u8]) -> Result<(), SessionMsgError> {
        let mut rem_dat = data;

        while rem_dat.len() > 0 {
            read_header_expect_type(self, message_types::MSGCHNK).wrap_sme()?;
            let mut data:Option<Vec<u8>> = None;

            while let None = data {
                let chunk = MessageChunk::read_into(self).wrap_sme()?;
                data = chunk.data;

                match data {
                    Some(_) => {
                        MessageResponse::new(true, true).write_all(self).wrap_sme()?;
                    },
                    None => {
                        MessageResponse::new(true, true).write_all(self).wrap_sme()?;
                    },
                }
            }
            let data = data.unwrap();

            
            let data_len = data.len();
            if data_len > rem_dat.len(){ //Throw an error if the data has overflowed.
                return Err(SessionMsgError::CorruptMessageError);
            }

            rem_dat[..data_len].copy_from_slice(&data); //this could panic idk im so tired TODO: Make sure this definitely wont panic

            rem_dat = &mut rem_dat[data_len..];
        }

        Ok(())
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut encrypted = vec![0u8; buf.len()];
        let bytes_encrypted = self.encrypter.update(buf, &mut encrypted)?;

        self.conn.write(&encrypted[..bytes_encrypted])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.conn.flush()
    }
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut encrypted = vec![0u8; buf.len()];
        let bytes_read = self.conn.read(&mut encrypted)?;

        let bytes_decrypted = self.decrypter.update(&encrypted[..bytes_read], buf)?;

        Ok(bytes_decrypted)
    }
}

fn create_crypters(key: &[u8; 32], iv: &[u8; 16]) -> Result<(Crypter, Crypter), NegotiationError>{
    let mut encrypter = Crypter::new(
        Cipher::aes_256_ctr(),
        openssl::symm::Mode::Encrypt,
        key,
        Some(iv)
    ).wrap_neg()?;

    let mut decrypter = Crypter::new(
        Cipher::aes_256_ctr(),
        openssl::symm::Mode::Decrypt,
        key,
        Some(iv)
    ).wrap_neg()?;
    
    encrypter.pad(false);
    decrypter.pad(false);

    Ok((encrypter, decrypter))
}

fn read_type<T: Read>(conn: &mut T) -> io::Result<u16> { //Makes the connection read data and modify the state machine.
    let mut typ_bytes = [0u8; 2];
    conn.read_exact(&mut typ_bytes)?;
    let typ:u16 = u16::from_be_bytes(typ_bytes);
    Ok(typ)
}

#[must_use]
fn read_header_expect_type<T: Read>(conn: &mut T, typ: u16) -> Result<() ,MessageError> { //Returns the length or the error.
    let actual_type = read_type(conn).wrap_me()?;
    if actual_type == typ {
        Ok(())
    } else {
        Err(MessageError::WrongMessageType)
    }
}

fn send_public_key(conn: &mut TcpStream, pk: PublicKey) -> Result<(), NegotiationError> {
    KeyMessage { //Send public key
        key: pk
    }.write_all(conn).wrap_neg()
}

fn read_public_key(conn: &mut TcpStream) -> Result<PublicKey, NegotiationError> {
    read_header_expect_type(conn, message_types::PUBLICKEY).wrap_neg()?;
    let pk = KeyMessage::read_into(conn).wrap_neg()?.key;
    return Ok(pk);
}

fn perform_test(conn: &mut TcpStream, rng:&mut ThreadRng, their_pk: PublicKey) -> Result<(), NegotiationError> {
    let mut test_data = [0u8; 1028];
    rng.fill_bytes(&mut test_data);
    let encrypted_test_data = encrypt(&their_pk.serialize(), &test_data).wrap_neg()?;
    
    TestMessage::new(encrypted_test_data, false).write_all(conn).wrap_neg()?;

    read_header_expect_type(conn, message_types::VALIDATION).wrap_neg()?;
    let test_result = TestMessage::read_into(conn).wrap_neg()?;

    if test_result.get_test_data() == test_data {
        ConfirmationMessage.write_all(conn).wrap_neg()?;
        return Ok(());
    } else {
        return Err(NegotiationError::FailedTest);
    }
}

pub fn complete_test(conn: &mut TcpStream, sk: SecretKey) -> Result<(), NegotiationError> {
    read_header_expect_type(conn, message_types::TEST).wrap_neg()?;
    let test = TestMessage::read_into(conn).wrap_neg()?;

    let decrypted_test = decrypt(&sk.serialize(), test.get_test_data()).wrap_neg()?;

    TestMessage::new(decrypted_test, true).write_all(conn).wrap_neg()?;

    read_header_expect_type(conn, message_types::CONFIRMATION).wrap_neg()?; 
    ConfirmationMessage::read_into(conn).wrap_neg()?; //This 

    Ok(())
}

fn get_capabilities() -> Vec<String>{ //Returns all capabilities of my implementation.
    let mut capability_strrefs = Vec::from(SUPPORTED_MSG);
    capability_strrefs.push(PKCRYPT_ALGO);
    capability_strrefs.push(SKCRYPT_ALGO);
    capability_strrefs.push(HASHING_ALGO);
    let mut caps = Vec::<String>::with_capacity(capability_strrefs.len());
    for strref in capability_strrefs {
        caps.push(String::from(strref));
    }

    caps
}

fn get_msg_capabilities(caps: Vec<String>) -> Result<Vec<String>, NegotiationError> { //Returns pk algorithm, sk algorithm and messaging capabilities in that order.
    let mut msg_caps: Vec<String> = Vec::new();

    if !caps.contains(&String::from(PKCRYPT_ALGO)) || !caps.contains(&String::from(SKCRYPT_ALGO)) || !caps.contains(&String::from(HASHING_ALGO)) {
        return Err(NegotiationError::IncompatibleCapabilities);
    }

    for capability in caps {
        if SUPPORTED_MSG.contains(&&capability[..]) {
            msg_caps.push(capability);
        }
    }
    if msg_caps.len() == 0 {
        return Err(NegotiationError::IncompatibleCapabilities);
    }

    return Ok(msg_caps);
}

fn send_capabilities(conn: &mut TcpStream, caps: Vec<String>) -> Result<(), NegotiationError> {
    CapabilityPrimer{
        no_capabilities: caps.len() as u16 //risky.
    }.write_all(conn).wrap_neg()?; //Send primer msg.

    for cap in caps {
        Capability {
            name: cap
        }.write_all(conn).wrap_neg()?;
    }

    Ok(())
}

fn read_capabilities(conn: &mut TcpStream) -> Result<Vec<String>, NegotiationError>{
    read_header_expect_type(conn, message_types::CAPPRIMER).wrap_neg()?;
    let cap_count = CapabilityPrimer::read_into(conn).wrap_neg()?.no_capabilities;
    
    let mut capabilities = Vec::<String>::with_capacity(cap_count as usize);
    for _ in 0..cap_count {
        read_header_expect_type(conn, message_types::CAPABILITY).wrap_neg()?;
        let cap = Capability::read_into(conn).wrap_neg()?.name;
        capabilities.push(cap);
    }

    Ok(capabilities)
}

fn send_aes_key(conn: &mut TcpStream, other_pk: &PublicKey, my_sk: &SecretKey, aes_key: &[u8; 32], iv: &[u8; 16]) -> Result<(), NegotiationError> {
    let mut plain_keyiv = [0u8; 48];
    plain_keyiv[..32].copy_from_slice(aes_key);
    plain_keyiv[32..].copy_from_slice(iv);
    
    let hashed = sha256(&plain_keyiv);

    let (signature, _) = sign(&libsecp256k1::Message::parse(&hashed), my_sk);

    let keyiv = encrypt(&other_pk.serialize(), &plain_keyiv).wrap_neg()?;

    let msg = SecretKeyMessage{
        keyiv,
        signature
    };

    msg.write_all(conn).wrap_neg()?;

    Ok(())
}

fn read_aes_key(conn: &mut TcpStream, my_sk: &SecretKey, other_pk: &PublicKey) -> Result<([u8; 32], [u8; 16]), NegotiationError> {
    read_header_expect_type(conn, message_types::SECRETKEY).wrap_neg()?;
    let skm = SecretKeyMessage::read_into(conn).wrap_neg()?;
    let keyiv = decrypt(&my_sk.serialize(), &skm.keyiv).wrap_neg()?;
    
    let keyiv_hash = sha256(&keyiv);

    if verify(&libsecp256k1::Message::parse(&keyiv_hash), &skm.signature, &other_pk) {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];

        key.copy_from_slice(&keyiv[..32]);
        iv.copy_from_slice(&keyiv[32..]);

        return Ok((key, iv));
    } else {
        return Err(NegotiationError::CryptoError);
    }
}

trait WrapNegotiationError<T> {
    fn wrap_neg(self) -> Result<T, NegotiationError>;
}

impl<T> WrapNegotiationError<T> for io::Result<T> {
    fn wrap_neg(self) -> Result<T, NegotiationError> {
        match self {
            Ok(res) => Ok(res),
            Err(_) => Err(NegotiationError::IOError),
        }
    }
}

impl<T> WrapNegotiationError<T> for Result<T, MessageError> {
    fn wrap_neg(self) -> Result<T, NegotiationError> {
        match self {
            Ok(res) => Ok(res),
            Err(err) => {
                match err {
                    MessageError::CorruptMessageError => {
                        Err(NegotiationError::CorruptMessage)
                    },
                    MessageError::IOError => {
                        Err(NegotiationError::IOError)
                    },
                    MessageError::WrongMessageType => Err(NegotiationError::WrongMessageType),
                }
            },
        }
    }
}

impl<T> WrapNegotiationError<T> for Result<T, libsecp256k1::Error> {
    fn wrap_neg(self) -> Result<T, NegotiationError> {
        match self {
            Ok(res) => Ok(res),
            Err(_) => Err(NegotiationError::CryptoError),
        }
    }
}

impl WrapNegotiationError<Crypter> for Result<Crypter, ErrorStack> {
    fn wrap_neg(self) -> Result<Crypter, NegotiationError> {
        match self {
            Ok(crypter) => Ok(crypter),
            Err(_) => Err(NegotiationError::CryptoError),
        }
    }
}


trait WrapSMError<T>{
    fn wrap_sme(self) -> Result<T, SessionMsgError>;
}

impl<T> WrapSMError<T> for Result<T, MessageError> {
    fn wrap_sme(self) -> Result<T, SessionMsgError> {
        match self {
            Ok(res) => Ok(res),
            Err(err) => {
                match err {
                    MessageError::CorruptMessageError => Err(SessionMsgError::CorruptMessageError),
                    MessageError::IOError => Err(SessionMsgError::IOError),
                    MessageError::WrongMessageType => Err(SessionMsgError::CorruptMessageError),
                }
            },
        }
    }
}