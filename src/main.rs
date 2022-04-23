use std::{net::{TcpListener, TcpStream}, thread::spawn};
use connection::Connection;

mod message;
mod connection;

const PORT:u16 = 30522;

/*
TODOS:
 - Refactor message class so that repeated type conversions are all put into one function.
*/
fn main() {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", PORT)).unwrap();
    let listening_thread = spawn(move || {listen(listener)});
    let conn = Connection::negotiate(TcpStream::connect("127.0.0.1:30522").unwrap(), false).unwrap(); //For testing purposes only.

    

    listening_thread.join().unwrap();
}

fn listen(listener: TcpListener){
    for conn in listener.incoming() {
        Connection::negotiate(conn.unwrap(), true).unwrap();
        break; //TEMPORARY TODO REMOVE.
    }
}