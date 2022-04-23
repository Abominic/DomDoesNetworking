use std::{net::TcpStream, io::{Read, self}};
use ecies::{utils::generate_keypair, SecretKey, PublicKey, encrypt, decrypt};
use openssl::{sha::{sha256}, symm::{Cipher, Crypter}, error::ErrorStack};
use rand::{RngCore, prelude::ThreadRng, Rng};
use libsecp256k1::{sign, verify};
use crate::{message::{Messageable, IntroMessage, message_types::{self, CONFIRMATION}, KeyMessage, TestMessage, ConfirmationMessage, MessageError, CapabilityPrimer, Capability, write_all, SecretKeyMessage}};
type KeyPair = (SecretKey, PublicKey);

//Encryption Capabilities. In order of increasing priority. One from each to be picked.
const SUPPORTED_PKCRYPT: [&str; 1] = ["secp256k1"]; //This is unofficial. One will be picked.
const SUPPORTED_SKCRYPT:[&str; 1] = ["aes-256-ctr"]; 
//Messaging Capabilities. 
const SUPPORTED_MSG: [&str; 1] = ["text"];
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
    IncompatibleCapabilities
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

        write_all(IntroMessage, &mut conn).wrap_io()?; //Send intro message first

        read_header_expect_type(&mut conn, message_types::INTRO)?; //Read intro header
        IntroMessage::read_into(&mut conn).wrap_io()?;

        send_capabilities(&mut conn, get_capabilities())?;

        let chosen_capabilities = read_capabilities(&mut conn)?;
        let (_, _, msgc) = prune_capabilities(chosen_capabilities)?;

        let alice_pk = read_public_key(&mut conn)?;
    
        send_public_key(&mut conn, kp.1)?;

        complete_test(&mut conn, kp.0)?;

        perform_test(&mut conn, &mut rng, alice_pk)?;

        let (aes_key, iv) = read_aes_key(&mut conn, &kp.0, &alice_pk)?;

        let (encrypter, decrypter) = create_crypters(&aes_key, &iv)?;

        write_all(ConfirmationMessage, &mut conn).wrap_io()?; //Send confirmation back.

        Ok(Self{
            conn,
            encrypter,
            decrypter,
            msg_capabilities: msgc
        })
    }

    fn negotiate_alice(mut conn: TcpStream, kp: KeyPair) -> Result<Self, NegotiationError> {
        let mut rng = rand::thread_rng();

        read_header_expect_type(&mut conn, message_types::INTRO)?; //Read intro header
        IntroMessage::read_into(&mut conn).wrap_io()?;

        write_all(IntroMessage, &mut conn).wrap_io()?; //Send intro back

        let bob_capabilities = read_capabilities(&mut conn)?;
        let (pkc, skc, msgc) = prune_capabilities(bob_capabilities)?;

        let mut using_capabilities = msgc.clone();
        using_capabilities.push(pkc);
        using_capabilities.push(skc);

        send_capabilities(&mut conn, using_capabilities)?; //Send capabilities back to bob.

        send_public_key(&mut conn, kp.1)?;

        let bob_pk = read_public_key(&mut conn)?;

        perform_test(&mut conn, &mut rng, bob_pk)?;

        complete_test(&mut conn, kp.0)?;

        let aes_key:[u8; 32] = rng.gen();
        let iv:[u8; 16] = rng.gen();

        send_aes_key(&mut conn, &bob_pk, &kp.0, &aes_key, &iv)?;
        
        let (encrypter, decrypter) = create_crypters(&aes_key, &iv)?;

        read_header_expect_type(&mut conn, CONFIRMATION)?; //Expect confirmation.
        ConfirmationMessage::read_into(&mut conn).wrap_io()?; //Read anyway even though this does nothing.

        Ok(Self{
            conn,
            encrypter,
            decrypter,
            msg_capabilities: msgc
        })
    }
}

fn create_crypters(key: &[u8; 32], iv: &[u8; 16]) -> Result<(Crypter, Crypter), NegotiationError>{
    let encrypter = Crypter::new(
        Cipher::aes_256_ctr(),
        openssl::symm::Mode::Encrypt,
        key,
        Some(iv)
    ).wrap_io()?;

    let decrypter = Crypter::new(
        Cipher::aes_256_ctr(),
        openssl::symm::Mode::Decrypt,
        key,
        Some(iv)
    ).wrap_io()?;

    Ok((encrypter, decrypter))
}

fn read_type(conn: &mut TcpStream) -> io::Result<u16> { //Makes the connection read data and modify the state machine.
    let mut typ_bytes = [0u8; 2];
    conn.read_exact(&mut typ_bytes)?;
    let typ:u16 = u16::from_be_bytes(typ_bytes);
    Ok(typ)
}

#[must_use]
fn read_header_expect_type(conn: &mut TcpStream, typ: u16) -> Result<() ,NegotiationError> { //Returns the length or the error.
    let actual_type = read_type(conn).wrap_io()?;
    if actual_type == typ {
        Ok(())
    } else {
        Err(NegotiationError::WrongMessageType)
    }
}

fn send_public_key(conn: &mut TcpStream, pk: PublicKey) -> Result<(), NegotiationError> {
    write_all(KeyMessage { //Send public key
        key: pk
    }, conn).wrap_io()
}

fn read_public_key(conn: &mut TcpStream) -> Result<PublicKey, NegotiationError> {
    read_header_expect_type(conn, message_types::PUBLICKEY)?;
    let pk = KeyMessage::read_into(conn).wrap_io()?.key;
    return Ok(pk);
}

fn perform_test(conn: &mut TcpStream, rng:&mut ThreadRng, their_pk: PublicKey) -> Result<(), NegotiationError> {
    let mut test_data = [0u8; 1028];
    rng.fill_bytes(&mut test_data);
    let encrypted_test_data = encrypt(&their_pk.serialize(), &test_data).wrap_io()?;
    
    write_all(TestMessage::new(encrypted_test_data, false), conn).wrap_io()?;

    read_header_expect_type(conn, message_types::VALIDATION)?;
    let test_result = TestMessage::read_into(conn).wrap_io()?;

    if test_result.get_test_data() == test_data {
        write_all(ConfirmationMessage, conn).wrap_io()?;
        return Ok(());
    } else {
        return Err(NegotiationError::FailedTest);
    }
}

pub fn complete_test(conn: &mut TcpStream, sk: SecretKey) -> Result<(), NegotiationError> {
    read_header_expect_type(conn, message_types::TEST)?;
    let test = TestMessage::read_into(conn).wrap_io()?;

    let decrypted_test = decrypt(&sk.serialize(), test.get_test_data()).wrap_io()?;

    write_all(TestMessage::new(decrypted_test, true), conn).wrap_io()?;

    read_header_expect_type(conn, message_types::CONFIRMATION)?; 
    ConfirmationMessage::read_into(conn).wrap_io()?; //This 

    Ok(())
}

fn get_capabilities() -> Vec<String>{ //Returns all capabilities of my implementation.
    let capability_strrefs = [SUPPORTED_PKCRYPT, SUPPORTED_SKCRYPT, SUPPORTED_MSG].concat();
    let mut caps = Vec::<String>::with_capacity(capability_strrefs.len());
    for strref in capability_strrefs {
        caps.push(String::from(strref));
    }

    caps
}

fn prune_capabilities(caps: Vec<String>) -> Result<(String, String, Vec<String>), NegotiationError> { //Returns pk algorithm, sk algorithm and messaging capabilities in that order.
    let mut pk_algo:Option<String> = None;
    let mut sk_algo:Option<String> = None;
    let mut msg_caps: Vec<String> = Vec::new();

    for pkc in SUPPORTED_PKCRYPT {
        let pkc_string = String::from(pkc);
        if caps.contains(&pkc_string) {
            pk_algo = Some(pkc_string);
        }
    } 

    for skc in SUPPORTED_SKCRYPT {
        let skc_string = String::from(skc);
        if caps.contains(&skc_string) {
            sk_algo = Some(skc_string);
        }
    }

    for capability in caps {
        if SUPPORTED_MSG.contains(&&capability[..]) {
            msg_caps.push(capability);
        }
    }

    //Rust doesnt (yet?) support if let chains.
    if let None = pk_algo {
        return Err(NegotiationError::IncompatibleCapabilities);
    } else if let None = sk_algo {
        return Err(NegotiationError::IncompatibleCapabilities);
    }
    if msg_caps.len() == 0 {
        return Err(NegotiationError::IncompatibleCapabilities);
    }

    return Ok((pk_algo.unwrap(), sk_algo.unwrap(), msg_caps));
}

fn send_capabilities(conn: &mut TcpStream, caps: Vec<String>) -> Result<(), NegotiationError> {
    write_all(CapabilityPrimer{
        no_capabilities: caps.len() as u16 //risky.
    }, conn).wrap_io()?; //Send primer msg.

    for cap in caps {
        write_all(Capability {
            name: cap
        }, conn).wrap_io()?;
    }

    Ok(())
}

fn read_capabilities(conn: &mut TcpStream) -> Result<Vec<String>, NegotiationError>{
    read_header_expect_type(conn, message_types::CAPPRIMER)?;
    let cap_count = CapabilityPrimer::read_into(conn).wrap_io()?.no_capabilities;
    
    let mut capabilities = Vec::<String>::with_capacity(cap_count as usize);
    for _ in 0..cap_count {
        read_header_expect_type(conn, message_types::CAPABILITY)?;
        let cap = Capability::read_into(conn).wrap_io()?.name;
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

    let keyiv = encrypt(&other_pk.serialize(), &plain_keyiv).wrap_io()?;

    let msg = SecretKeyMessage{
        keyiv,
        signature
    };

    write_all(msg, conn).wrap_io()?;

    Ok(())
}

fn read_aes_key(conn: &mut TcpStream, my_sk: &SecretKey, other_pk: &PublicKey) -> Result<([u8; 32], [u8; 16]), NegotiationError> {
    read_header_expect_type(conn, message_types::SECRETKEY)?;
    let skm = SecretKeyMessage::read_into(conn).wrap_io()?;
    let keyiv = decrypt(&my_sk.serialize(), &skm.keyiv).wrap_io()?;
    
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
    fn wrap_io(self) -> Result<T, NegotiationError>;
}

impl<T> WrapNegotiationError<T> for io::Result<T> {
    fn wrap_io(self) -> Result<T, NegotiationError> {
        match self {
            Ok(res) => Ok(res),
            Err(_) => Err(NegotiationError::IOError),
        }
    }
}

impl<T> WrapNegotiationError<T> for Result<T, MessageError> {
    fn wrap_io(self) -> Result<T, NegotiationError> {
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
                }
            },
        }
    }
}

impl<T> WrapNegotiationError<T> for Result<T, libsecp256k1::Error> {
    fn wrap_io(self) -> Result<T, NegotiationError> {
        match self {
            Ok(res) => Ok(res),
            Err(_) => Err(NegotiationError::CryptoError),
        }
    }
}

impl WrapNegotiationError<Crypter> for Result<Crypter, ErrorStack> {
    fn wrap_io(self) -> Result<Crypter, NegotiationError> {
        match self {
            Ok(crypter) => Ok(crypter),
            Err(_) => Err(NegotiationError::CryptoError),
        }
    }
}