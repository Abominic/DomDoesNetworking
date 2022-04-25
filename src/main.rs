use std::{net::{TcpListener, TcpStream}, thread::spawn};
use connection::Connection;
use session::Session;

mod message;
mod connection;
mod session;

const PORT:u16 = 30522;

/*
TODOS: Most important first.
 - Make the app actually usable
 - Make keys persistent (both mine and others').
 - Perhaps improve reading and writing making a function that writes the length then the data and a function that reads that information back beacuse I've written the same code like 1000 times.
 - Make message types an enum (this would be but i cba).
 - Make chunk sending not use .to_vec() which copies data and uses loads of RAM for large chunks.
 - MAYBE fix the horrific error system I have in place or let other people know how messy it is.
 */
fn main() {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", PORT)).unwrap();
    let listening_thread = spawn(move || {listen(listener)});
    let conn = Connection::negotiate(TcpStream::connect("127.0.0.1:30522").unwrap(), false).unwrap(); //For testing purposes only.
    let mut session = Session::new(conn);
    session.send_text_msg("Hello There!").unwrap();
    listening_thread.join().unwrap();
}

fn listen(listener: TcpListener){
    for conn in listener.incoming() {
        let conn = Connection::negotiate(conn.unwrap(), true).unwrap();
        let mut session = Session::new(conn);
        session.handle_next_message().unwrap();
        break; //TEMPORARY TODO REMOVE.
    }
}
