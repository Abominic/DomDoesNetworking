use crate::connection::{Connection, SessionMsgError, TEXT_ALGO};

pub struct Session {
    conn: Connection
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
        } else {
            panic!("Somehow I accepted a message that I never bothered to write code to handle but still wrote the capability in anyway.");
        }
    }
}