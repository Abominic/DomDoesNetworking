use chrono::{Local, DateTime};
use crate::connection::{Connection, SessionMsgError, TEXT_ALGO, CUSTOM_ALGO, WrapSMError};

pub struct Session {
    pub conn: Connection
}

impl Session {
    pub fn new(conn: Connection) -> Self {
        Self{
            conn
        }
    }

    pub fn send_text_msg(&mut self, msg: &str) -> Result<(), SessionMsgError> {
        if !self.conn.has_msg_capability(TEXT_ALGO) {
            return Err(SessionMsgError::NotCapable);
        }

        self.conn.send_message(TEXT_ALGO, msg.as_bytes())?;

        Ok(())
    }

    pub fn send_date_message(&mut self) -> Result<(), SessionMsgError> {
        if !self.conn.has_msg_capability(CUSTOM_ALGO) {
            return Err(SessionMsgError::NotCapable);
        }

        let time = Local::now();

        println!("Time: {:?}", time.to_rfc2822());

        self.conn.send_message(CUSTOM_ALGO, time.to_rfc3339().as_bytes())?;

        Ok(())
    }

    pub fn get_next_message(&mut self) -> Result<String, SessionMsgError> {
        let req = self.conn.read_next_msg_request()?;
        if !self.conn.has_msg_capability(&req.typ){ //Reject the message.
            self.conn.reply_to_request(false)?;
            return Err(SessionMsgError::Rejected);
        }

        self.conn.reply_to_request(true)?;
        
        if req.typ == TEXT_ALGO {
            let mut text = vec![0u8; req.length as usize];
            self.conn.read_payload(&mut text)?;
            let text = String::from_utf8(text);

            return match text {
                Ok(text) => {
                    Ok(text)
                },
                Err(_) => Err(SessionMsgError::CorruptMessageError),
            };
        } else if req.typ == CUSTOM_ALGO { //Date time.
            let mut time_string = vec![0u8; req.length as usize];
            self.conn.read_payload(&mut time_string)?;
            let time_string = String::from_utf8(time_string).wrap_sme()?;
            let time_string = DateTime::parse_from_rfc3339(&time_string);
            
            return match time_string {
                Ok(time_string) => {
                    let output = format!("My time is {}!", time_string.to_rfc2822()); //TODO: print timezone.
                    Ok(output)
                },
                Err(_) => Err(SessionMsgError::CorruptMessageError)
            }
        } else {
            panic!("Somehow I accepted a message that I never bothered to write code to handle but still wrote the capability in anyway.");
        }
    }
}